"""
Unit tests for the three validation gates:

  - AdversarialValidator (skills/adversarial_validation.py)
  - CapabilityLedger     (skills/capability_ledger.py)
  - ShipDisciplineGate   (skills/ship_gate.py)

All three are dependency-light (stdlib only) and deterministic, so these tests
run without API keys, network, or the heavy model SDKs. Async paths are driven
through asyncio.run so the file works under plain pytest and standalone.
"""

import asyncio
import json
import tempfile

from skills.adversarial_validation import AdversarialValidator
from skills.capability_ledger import CapabilityLedger
from skills.ship_gate import ShipDisciplineGate, ProgramProfile


# ── Fakes ────────────────────────────────────────────────────────

class FakeClient:
    """Minimal stand-in for models.ModelClient used by the adversarial gate."""

    def __init__(self, reply, providers=("deepseek", "glm")):
        self._reply = reply
        self._providers = list(providers)
        self.calls = 0
        self.last_model = None

    async def generate(self, prompt, model=None, system_prompt=None, temperature=0.1):
        self.calls += 1
        self.last_model = model
        if callable(self._reply):
            return self._reply(prompt, model)
        return self._reply

    def get_available_models(self):
        return [{"provider": p, "model": p, "name": p} for p in self._providers]


def _sqli(**over):
    f = {
        "type": "sqli",
        "severity": "high",
        "confidence": 0.7,
        "url": "http://target.test/item?id=1",
        "param": "id",
        "evidence": "SQL syntax error near '1''",
    }
    f.update(over)
    return f


# ── AdversarialValidator ─────────────────────────────────────────

def test_adversarial_mock_is_passthrough():
    v = AdversarialValidator(mock=True)
    survivors, refuted = asyncio.run(v.challenge_batch([_sqli()]))
    assert len(survivors) == 1 and refuted == []
    assert survivors[0]["adversarial"]["verdict"] == "skipped"


def test_adversarial_confident_refutation_drops_finding():
    reply = json.dumps({"verdict": "not_real", "confidence": 0.9,
                        "benign_explanation": "reflected but HTML-escaped"})
    v = AdversarialValidator(model_client=FakeClient(reply), mock=False, min_refute_confidence=0.7)
    survivors, refuted = asyncio.run(v.challenge_batch([_sqli()]))
    assert survivors == [] and len(refuted) == 1
    assert refuted[0]["adversarial"]["verdict"] == "refuted"
    assert refuted[0]["false_positive_risk"] == "high"


def test_adversarial_low_confidence_refutation_is_kept():
    reply = json.dumps({"verdict": "not_real", "confidence": 0.5})
    v = AdversarialValidator(model_client=FakeClient(reply), mock=False, min_refute_confidence=0.7)
    survivors, refuted = asyncio.run(v.challenge_batch([_sqli()]))
    assert len(survivors) == 1 and refuted == []
    assert survivors[0]["adversarial"]["verdict"] == "uncertain"


def test_adversarial_real_verdict_survives_and_boosts_confidence():
    reply = json.dumps({"verdict": "real", "confidence": 0.8})
    v = AdversarialValidator(model_client=FakeClient(reply), mock=False)
    survivors, refuted = asyncio.run(v.challenge_batch([_sqli(confidence=0.6)]))
    assert len(survivors) == 1 and refuted == []
    assert survivors[0]["adversarial"]["verdict"] == "survived"
    assert survivors[0]["confidence"] > 0.6  # survived → boosted


def test_adversarial_unparseable_reply_fails_open():
    v = AdversarialValidator(model_client=FakeClient("sure, looks exploitable to me"), mock=False)
    survivors, refuted = asyncio.run(v.challenge_batch([_sqli()]))
    assert len(survivors) == 1 and refuted == []
    assert survivors[0]["adversarial"]["verdict"] == "uncertain"


def test_adversarial_skips_informational_class_without_calling_model():
    client = FakeClient("should not be called")
    v = AdversarialValidator(model_client=client, mock=False)
    survivors, refuted = asyncio.run(v.challenge_batch([{"type": "waf_detected", "severity": "info"}]))
    assert len(survivors) == 1 and refuted == []
    assert survivors[0]["adversarial"]["verdict"] == "skipped"
    assert client.calls == 0


def test_adversarial_picks_a_different_family_than_the_author():
    # sqli is authored by the 'minimax' family; disprover must differ.
    client = FakeClient(json.dumps({"verdict": "real", "confidence": 0.8}),
                        providers=("deepseek", "glm"))
    v = AdversarialValidator(model_client=client, mock=False)
    asyncio.run(v.challenge(_sqli()))
    assert client.last_model == "deepseek"

    # idor is authored by 'deepseek'; with deepseek+glm available it must pick glm.
    client2 = FakeClient(json.dumps({"verdict": "real", "confidence": 0.8}),
                         providers=("deepseek", "glm"))
    v2 = AdversarialValidator(model_client=client2, mock=False)
    asyncio.run(v2.challenge(_sqli(type="idor")))
    assert client2.last_model == "glm"


# ── CapabilityLedger ─────────────────────────────────────────────

def test_ledger_clean_when_all_executed():
    led = CapabilityLedger()
    led.record("xss", status="executed", probes_ok=3)
    led.record("sqli", status="executed", probes_ok=2)
    audit = led.audit()
    assert audit.clean and not led.blocked()
    assert audit.executed == 2 and audit.errored == 0


def test_ledger_blocked_on_errored_capability():
    led = CapabilityLedger()
    led.record("ssrf", error="RuntimeError: boom")   # derives errored
    led.record("xss", status="executed", probes_ok=1)
    assert led.blocked() is True
    audit = led.audit()
    assert "ssrf" in audit.debt and not audit.clean
    assert "ssrf" in led.coverage_warning()


def test_ledger_status_derivation_from_telemetry():
    led = CapabilityLedger()
    led.record_from_telemetry({
        "a": {"probed_urls": 5, "probes_ok": 0, "probes_failed": 5},  # every probe failed -> errored
        "b": {"probed_urls": 0},                                       # nothing to test -> empty
        "c": {"probed_urls": 3, "probes_ok": 3, "findings": 1},        # real coverage -> executed
    })
    audit = led.audit()
    assert "a" in audit.debt          # errored
    assert "b" in audit.gaps          # soft gap
    assert audit.executed == 1        # c
    assert led.blocked() is True      # a is hard debt


def test_ledger_empty_is_gap_not_debt():
    led = CapabilityLedger()
    led.record_from_telemetry({"b": {"probed_urls": 0}})
    audit = led.audit()
    assert audit.clean and not led.blocked()
    assert audit.gaps == ["b"]


def test_ledger_skipped_is_not_debt():
    led = CapabilityLedger()
    led.skip("cloud_metadata", note="scope disallows")
    led.record("xss", status="executed", probes_ok=1)
    audit = led.audit()
    assert audit.clean and audit.skipped == 1


def test_ledger_declared_but_never_recorded_is_debt():
    led = CapabilityLedger()
    led.expect("phantom")           # scheduled, no record ever arrived
    audit = led.audit()
    assert "phantom" in audit.debt and led.blocked()


# ── ShipDisciplineGate ───────────────────────────────────────────

def test_ship_reports_high_severity():
    gate = ShipDisciplineGate(platform="hackerone", persist=False)
    ship, held = gate.filter_batch([_sqli(severity="high")], "target.test")
    assert len(ship) == 1 and held == []
    assert ship[0]["ship"]["bucket"] == "report"


def test_ship_below_program_floor_is_informational():
    # immunefi accepts high+ only.
    gate = ShipDisciplineGate(platform="immunefi", persist=False)
    ship, held = gate.filter_batch([_sqli(severity="medium")], "target.test")
    assert ship == [] and len(held) == 1
    assert held[0]["ship"]["bucket"] == "informational"


def test_ship_out_of_scope_class_is_informational():
    gate = ShipDisciplineGate(platform="hackerone", persist=False)  # open_redirect OOS
    f = {"type": "open_redirect", "severity": "high", "confidence": 0.8,
         "url": "http://target.test/go?next=x", "param": "next"}
    ship, held = gate.filter_batch([f], "target.test")
    assert ship == [] and held[0]["ship"]["bucket"] == "informational"
    assert any("out of scope" in r for r in held[0]["ship"]["reasons"])


def test_ship_informational_class_is_held():
    gate = ShipDisciplineGate(platform="generic", persist=False)
    ship, held = gate.filter_batch([{"type": "waf_detected", "severity": "info", "url": "http://t/"}], "t")
    assert ship == [] and held[0]["ship"]["bucket"] == "informational"


def test_ship_duplicate_within_run():
    gate = ShipDisciplineGate(platform="generic", persist=False)
    ship, held = gate.filter_batch([_sqli(), _sqli()], "target.test")
    assert len(ship) == 1 and len(held) == 1
    assert held[0]["ship"]["bucket"] == "duplicate"


def test_ship_duplicate_across_runs_via_persistent_ledger():
    with tempfile.TemporaryDirectory() as d:
        g1 = ShipDisciplineGate(platform="generic", ledger_dir=d, persist=True)
        ship1, _ = g1.filter_batch([_sqli()], "target.test")
        assert len(ship1) == 1

        g2 = ShipDisciplineGate(platform="generic", ledger_dir=d, persist=True)
        ship2, held2 = g2.filter_batch([_sqli()], "target.test")
        assert ship2 == [] and held2[0]["ship"]["bucket"] == "duplicate"


def test_ship_custom_profile_override():
    profile = ProgramProfile("strict", min_severity="critical")
    gate = ShipDisciplineGate(profile=profile, persist=False)
    ship, held = gate.filter_batch([_sqli(severity="high")], "target.test")
    assert ship == [] and held[0]["ship"]["bucket"] == "informational"


# ── Standalone runner (no pytest required) ───────────────────────

if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        try:
            fn()
            print(f"  PASS  {fn.__name__}")
            passed += 1
        except Exception as e:  # noqa: BLE001
            print(f"  FAIL  {fn.__name__}: {e!r}")
    print(f"\n{passed}/{len(fns)} passed")
