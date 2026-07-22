"""
Adversarial Validation, cross-model disprove pass.

Every other gate in the pipeline *confirms* a finding: the quality gate checks
evidence consistency, the verifier re-tests the mechanism, and the validate skill
asks a single model "is this real?" (and on timeout it passes anyway). All of
that is confirmation bias baked into one model's opinion.

This module inverts the burden of proof. It hands each finding to a *different*
model than the one that produced it and instructs that model to REFUTE it, to
find the benign explanation, the missing precondition, the reason the PoC does
not actually prove impact. A finding survives only if the refutation fails.

    finding --> challenge(different model, "prove this is NOT exploitable")
              --> survived   (refutation failed)      -> keep
              --> refuted    (confident benign explanation) -> drop
              --> uncertain  (model unsure / unavailable)   -> keep + flag

Why cross-model matters: a model asked to confirm its own class of output agrees
with itself. A model from a different family, asked to attack the claim, catches
"reflected but HTML-escaped", "200 but that is the login page", "id changed but
the data is public", and "SSRF to an allow-listed host", the exact false
positives that get a report thrown back by a triager.

The gate fails OPEN: transport/parse errors never silently delete a finding, they
mark it `uncertain` so a human still sees it. Only a *confident* refutation drops
a finding.
"""

import asyncio
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# Findings of these classes are meta/informational, they carry no exploit claim
# to refute, so they bypass the adversarial pass untouched.
NON_CHALLENGEABLE_TYPES = {
    "attack chain",
    "attack_strategy_recommendation",
    "waf_detected",
}

# Severities that do not warrant a paid disprove round-trip. Informational
# findings pass through; only low+ get challenged.
CHALLENGEABLE_SEVERITIES = {"low", "medium", "high", "critical"}

# vuln_class -> the provider family most likely to have authored the finding
# during hunting (see models.ModelClient.get_task_model). The disprover is
# chosen from a *different* family than this.
_AUTHOR_PROVIDER = {
    "idor": "deepseek", "ssrf": "glm", "xss": "glm", "sqli": "minimax",
    "rce": "deepseek", "command_injection": "deepseek", "ssti": "glm",
    "lfi": "glm", "path_traversal": "deepseek", "nosqli": "glm",
    "graphql": "glm", "jwt": "glm", "auth_bypass": "deepseek",
    "open_redirect": "glm", "deserialization": "glm", "race_condition": "glm",
}

# Preference order when picking a disprover, reasoning-capable families first.
_DISPROVER_PREFERENCE = ["deepseek", "featherless", "kimi", "qwen", "minimax", "glm"]

_SYSTEM_PROMPT = (
    "You are a skeptical senior bug-bounty triager. Your only job is to REJECT "
    "weak reports before they waste a program's time. For the finding you are "
    "shown, actively look for the benign explanation: input reflected but "
    "encoded/escaped, a 200 that is really an error or login page, an id that "
    "changed but returns public data, a redirect to an allow-listed host, an "
    "SSRF that never leaves the app's own trust boundary, a 'confirmed' payload "
    "that was never actually sent. Assume the reporter is over-claiming until "
    "the evidence forces you to concede. Answer only with the requested JSON."
)


@dataclass
class Challenge:
    """Outcome of one adversarial disprove round for a single finding."""
    verdict: str = "uncertain"          # survived | refuted | uncertain | skipped
    disprover_model: str = ""
    confidence: float = 0.0             # disprover's confidence in ITS verdict
    benign_explanation: str = ""
    exploitability_holes: List[str] = field(default_factory=list)
    recommended_extra_proof: str = ""
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "disprover_model": self.disprover_model,
            "confidence": round(self.confidence, 2),
            "benign_explanation": self.benign_explanation,
            "exploitability_holes": self.exploitability_holes,
            "recommended_extra_proof": self.recommended_extra_proof,
            "error": self.error,
        }


class AdversarialValidator:
    """
    Cross-model disprove gate. Keep survivors, drop confident refutations.

    Args:
        model_client: a client exposing async ``generate(prompt, model=...)`` and
            ``get_available_models()`` (models.ModelClient or MockModelClient).
        mock: when True the gate is a pass-through (used by --mock runs).
        min_refute_confidence: a refutation only drops a finding when the
            disprover's confidence is at least this high.
        timeout: per-finding disprove timeout in seconds.
    """

    def __init__(
        self,
        model_client: Any = None,
        mock: bool = False,
        min_refute_confidence: float = 0.7,
        timeout: int = 20,
    ):
        self.model_client = model_client
        self.mock = mock or model_client is None
        self.min_refute_confidence = min_refute_confidence
        self.timeout = timeout
        self.stats = {"challenged": 0, "survived": 0, "refuted": 0, "uncertain": 0, "skipped": 0}
        self._available_providers: Optional[List[str]] = None

    # ── Public API ───────────────────────────────────────────────

    async def challenge_batch(
        self, findings: List[Dict[str, Any]]
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Run the disprove pass over a batch.

        Returns (survivors, refuted). Survivors keep their order and are annotated
        with an ``adversarial`` block; refuted findings are annotated too so the
        caller can log why they were dropped.
        """
        if not findings:
            return [], []

        results = await asyncio.gather(
            *(self.challenge(f) for f in findings), return_exceptions=True
        )

        survivors: List[Dict[str, Any]] = []
        refuted: List[Dict[str, Any]] = []
        for original, result in zip(findings, results):
            if isinstance(result, Exception):
                # A crash in the gate must never delete a finding.
                original["adversarial"] = Challenge(
                    verdict="uncertain", error=repr(result)
                ).to_dict()
                self.stats["uncertain"] += 1
                survivors.append(original)
                continue
            if result["adversarial"]["verdict"] == "refuted":
                refuted.append(result)
            else:
                survivors.append(result)
        return survivors, refuted

    async def challenge(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Disprove a single finding; return it annotated with an ``adversarial`` block."""
        if self._should_skip(finding):
            finding["adversarial"] = Challenge(verdict="skipped").to_dict()
            self.stats["skipped"] += 1
            return finding

        self.stats["challenged"] += 1
        disprover = self._pick_disprover(finding)
        challenge = await self._run_disprove(finding, disprover)

        # Apply the verdict to the finding's own confidence so downstream
        # severity/report logic sees the adversarial signal.
        base_conf = float(finding.get("confidence", 0.5) or 0.5)
        if challenge.verdict == "survived":
            finding["confidence"] = min(0.98, base_conf + 0.15)
            self.stats["survived"] += 1
        elif challenge.verdict == "refuted":
            finding["confidence"] = max(0.05, base_conf - 0.4)
            finding["false_positive_risk"] = "high"
            self.stats["refuted"] += 1
        else:
            self.stats["uncertain"] += 1

        finding["adversarial"] = challenge.to_dict()
        return finding

    def get_stats(self) -> dict:
        return dict(self.stats)

    # ── Disprove round ───────────────────────────────────────────

    async def _run_disprove(self, finding: Dict[str, Any], disprover: str) -> Challenge:
        if self.mock:
            return Challenge(verdict="skipped", disprover_model="mock")

        prompt = self._build_prompt(finding)
        try:
            raw = await asyncio.wait_for(
                self.model_client.generate(
                    prompt,
                    model=disprover,
                    system_prompt=_SYSTEM_PROMPT,
                    temperature=0.4,  # diverge from the low-temp confirmation pass
                ),
                timeout=self.timeout,
            )
        except asyncio.TimeoutError:
            return Challenge(verdict="uncertain", disprover_model=disprover, error="disprove timeout")
        except Exception as e:  # noqa: BLE001, never let a transport error drop a finding
            return Challenge(verdict="uncertain", disprover_model=disprover, error=repr(e))

        return self._parse_verdict(raw, disprover)

    def _build_prompt(self, finding: Dict[str, Any]) -> str:
        vuln = finding.get("type", finding.get("vuln_class", "unknown"))
        evidence = {
            "type": vuln,
            "severity": finding.get("severity", ""),
            "url": finding.get("url", finding.get("endpoint", "")),
            "parameter": finding.get("param", finding.get("parameter", "")),
            "payload": finding.get("payload", finding.get("payload_used", "")),
            "description": finding.get("description", ""),
            "evidence": _truncate(finding.get("evidence", ""), 1200),
            "http_request": _truncate(finding.get("http_request", ""), 1200),
            "http_response": _truncate(finding.get("http_response", ""), 1600),
            "verification": finding.get("verification", {}),
        }
        return (
            "Try to REFUTE the security finding below. Assume it is a false "
            "positive and look for the benign explanation. Only concede it is real "
            "if the evidence leaves no benign reading.\n\n"
            f"FINDING:\n{json.dumps(evidence, indent=2, default=str)}\n\n"
            "Return STRICT JSON, nothing else:\n"
            "{\n"
            '  "verdict": "real" | "not_real" | "uncertain",\n'
            '  "confidence": 0.0-1.0,   // your confidence in the verdict above\n'
            '  "benign_explanation": "the most likely non-vulnerable reading, or empty",\n'
            '  "exploitability_holes": ["missing precondition or proof gap", ...],\n'
            '  "recommended_extra_proof": "the single request/observation that would settle it"\n'
            "}"
        )

    def _parse_verdict(self, raw: str, disprover: str) -> Challenge:
        data = _extract_json(raw)
        if not isinstance(data, dict):
            # Unparseable disprover output must not silently drop the finding.
            return Challenge(verdict="uncertain", disprover_model=disprover, error="unparseable verdict")

        model_verdict = str(data.get("verdict", "uncertain")).strip().lower()
        try:
            confidence = float(data.get("confidence", 0.0))
        except (TypeError, ValueError):
            confidence = 0.0
        confidence = max(0.0, min(1.0, confidence))

        holes = data.get("exploitability_holes", []) or []
        if isinstance(holes, str):
            holes = [holes]

        challenge = Challenge(
            disprover_model=disprover,
            confidence=confidence,
            benign_explanation=str(data.get("benign_explanation", "") or ""),
            exploitability_holes=[str(h) for h in holes][:8],
            recommended_extra_proof=str(data.get("recommended_extra_proof", "") or ""),
        )

        # Map the disprover's verdict to a gate outcome. A drop requires the
        # disprover to be *confidently* sure the finding is not real.
        if model_verdict in ("not_real", "false_positive", "no", "refuted"):
            challenge.verdict = "refuted" if confidence >= self.min_refute_confidence else "uncertain"
        elif model_verdict in ("real", "valid", "yes", "confirmed"):
            challenge.verdict = "survived"
        else:
            challenge.verdict = "uncertain"
        return challenge

    # ── Disprover selection ──────────────────────────────────────

    def _pick_disprover(self, finding: Dict[str, Any]) -> str:
        """Pick a model from a different family than the one that likely authored it."""
        author = self._author_provider(finding)
        available = self._providers()

        for provider in _DISPROVER_PREFERENCE:
            if provider != author and provider in available:
                return provider
        # No cross-family option configured, fall back to any available model.
        # Same family is still adversarial: opposite stance, higher temperature.
        for provider in _DISPROVER_PREFERENCE:
            if provider in available:
                return provider
        return "featherless"

    def _author_provider(self, finding: Dict[str, Any]) -> str:
        vuln = str(finding.get("type", finding.get("vuln_class", ""))).lower()
        for key, provider in _AUTHOR_PROVIDER.items():
            if key in vuln:
                return provider
        return "glm"

    def _providers(self) -> List[str]:
        if self._available_providers is not None:
            return self._available_providers
        providers: List[str] = []
        try:
            for m in self.model_client.get_available_models():
                p = m.get("provider")
                if p and p not in providers:
                    providers.append(p)
        except Exception:  # noqa: BLE001
            providers = []
        self._available_providers = providers
        return providers

    # ── Helpers ──────────────────────────────────────────────────

    def _should_skip(self, finding: Dict[str, Any]) -> bool:
        vuln = str(finding.get("type", finding.get("vuln_class", ""))).lower()
        if vuln in NON_CHALLENGEABLE_TYPES:
            return True
        severity = str(finding.get("severity", "")).lower()
        if severity and severity not in CHALLENGEABLE_SEVERITIES:
            return True
        return False


def _truncate(value: Any, limit: int) -> str:
    text = value if isinstance(value, str) else str(value)
    return text if len(text) <= limit else text[:limit] + "…[truncated]"


def _extract_json(raw: str) -> Optional[dict]:
    """Best-effort JSON extraction from a model reply (handles code fences/prose)."""
    if not raw or not isinstance(raw, str):
        return None
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        pass
    # Strip ```json fences and retry.
    fenced = re.sub(r"^```(?:json)?|```$", "", raw.strip(), flags=re.MULTILINE).strip()
    try:
        return json.loads(fenced)
    except (json.JSONDecodeError, ValueError):
        pass
    # Grab the first balanced-looking object.
    match = re.search(r"\{.*\}", fenced, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except (json.JSONDecodeError, ValueError):
            return None
    return None
