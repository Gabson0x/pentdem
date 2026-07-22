"""
Capability Execution Ledger, coverage you can prove, not coverage you claim.

The hunt fans 15+ vuln classes and 8 advanced skills out with
``asyncio.gather(..., return_exceptions=True)``. When one of those coroutines
raises, the gather loop does ``if isinstance(result, Exception): continue``, the
whole capability vanishes with no trace. The advanced-skill runner is worse: it
wraps every skill in ``except Exception: return []``. So a run where the SSRF
hunter crashed on its first request and a run where SSRF was genuinely tested and
found nothing produce the *identical* output: zero SSRF findings.

That means a "clean, no criticals" verdict can silently be "half the hunters
never actually ran." The engine reports completeness it did not earn.

This ledger fixes that by recording, per capability, evidence *recomputed from
what actually happened*, was it attempted, how many URLs it probed, how many
probes returned vs errored, whether the coroutine raised, never a boolean the
phase set about itself. ``audit()`` then classifies each capability:

    executed, attempted and at least one probe completed        (real coverage)
    empty, attempted but had nothing to probe (no candidate URLs) (soft gap)
    errored, the coroutine raised, or every probe failed        (HARD debt)
    skipped, deliberately not run (out of mode / scope)          (not debt)

If any expected capability is ``errored`` (or was never recorded at all), the
run carries **coverage debt** and ``blocked()`` is True. The pipeline surfaces
that on the result and in the report so a no-findings outcome is never mistaken
for a thorough one.
"""

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# Recomputed-evidence outcomes.
EXECUTED = "executed"
EMPTY = "empty"
ERRORED = "errored"
SKIPPED = "skipped"

# Categories a capability can belong to (for grouping in the report).
CAT_HUNT = "hunt"
CAT_ADVANCED = "advanced"
CAT_PHASE = "phase"


@dataclass
class CapabilityRecord:
    """One capability's execution evidence, computed from run telemetry."""
    name: str
    category: str = CAT_HUNT
    status: str = EXECUTED
    probed_urls: int = 0        # candidate targets the capability actually had
    probes_ok: int = 0          # probes that returned a response
    probes_failed: int = 0      # probes that raised
    findings: int = 0
    error: str = ""
    duration_ms: int = 0
    note: str = ""

    @property
    def is_debt(self) -> bool:
        """Hard coverage debt: a capability that was supposed to run but didn't."""
        return self.status == ERRORED

    @property
    def is_gap(self) -> bool:
        """Soft coverage gap: attempted but had nothing to work with."""
        return self.status == EMPTY

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "category": self.category,
            "status": self.status,
            "probed_urls": self.probed_urls,
            "probes_ok": self.probes_ok,
            "probes_failed": self.probes_failed,
            "findings": self.findings,
            "error": self.error[:300],
            "duration_ms": self.duration_ms,
            "note": self.note,
        }


@dataclass
class LedgerAudit:
    """Result of auditing the ledger against everything that was scheduled."""
    total: int = 0
    executed: int = 0
    empty: int = 0
    errored: int = 0
    skipped: int = 0
    debt: List[str] = field(default_factory=list)     # capabilities that did not run
    gaps: List[str] = field(default_factory=list)     # capabilities with nothing to probe
    coverage_ratio: float = 1.0                        # executed / (expected to run)

    @property
    def clean(self) -> bool:
        return not self.debt

    def to_dict(self) -> dict:
        return {
            "total": self.total,
            "executed": self.executed,
            "empty": self.empty,
            "errored": self.errored,
            "skipped": self.skipped,
            "debt": self.debt,
            "gaps": self.gaps,
            "coverage_ratio": round(self.coverage_ratio, 3),
            "clean": self.clean,
        }


class CapabilityLedger:
    """
    Records capability execution evidence and blocks the clean verdict on debt.

    Recording a capability *is* declaring it was scheduled, so a capability that
    the pipeline meant to run but never recorded shows up as missing debt via
    ``expect()``. Callers record every capability they schedule (including the
    ones that errored or were skipped); the audit does the rest.
    """

    def __init__(self):
        self._records: Dict[str, CapabilityRecord] = {}
        self._expected: set[str] = set()

    # ── Recording ────────────────────────────────────────────────

    def expect(self, name: str) -> None:
        """Declare a capability as scheduled. If it is never recorded, it is debt."""
        self._expected.add(name)

    def record(
        self,
        name: str,
        category: str = CAT_HUNT,
        *,
        status: Optional[str] = None,
        probed_urls: int = 0,
        probes_ok: int = 0,
        probes_failed: int = 0,
        findings: int = 0,
        error: str = "",
        duration_ms: int = 0,
        note: str = "",
    ) -> CapabilityRecord:
        """
        Record a capability's outcome from recomputed telemetry.

        If ``status`` is not given it is derived from the evidence, which is the
        whole point, the caller reports *what happened*, not a self-assessed
        pass/fail:

            error present ......................... errored
            probed_urls == 0 ...................... empty  (nothing to test)
            probes_ok == 0 and probes_failed > 0 .. errored (every probe failed)
            otherwise ............................. executed
        """
        self._expected.add(name)
        if status is None:
            if error:
                status = ERRORED
            elif probed_urls == 0 and probes_ok == 0 and probes_failed == 0:
                status = EMPTY
            elif probes_ok == 0 and probes_failed > 0:
                status = ERRORED
            else:
                status = EXECUTED
        rec = CapabilityRecord(
            name=name,
            category=category,
            status=status,
            probed_urls=probed_urls,
            probes_ok=probes_ok,
            probes_failed=probes_failed,
            findings=findings,
            error=error,
            duration_ms=duration_ms,
            note=note,
        )
        self._records[name] = rec
        return rec

    def record_from_telemetry(self, telemetry: Dict[str, dict], category: str = CAT_HUNT) -> None:
        """
        Bulk-record from a ``{capability: {...evidence}}`` map produced by a runner.

        Recognised evidence keys: probed_urls, probes_ok, probes_failed, findings,
        error, duration_ms, note, status.
        """
        for name, ev in (telemetry or {}).items():
            self.record(
                name,
                category,
                status=ev.get("status"),
                probed_urls=int(ev.get("probed_urls", 0) or 0),
                probes_ok=int(ev.get("probes_ok", 0) or 0),
                probes_failed=int(ev.get("probes_failed", 0) or 0),
                findings=int(ev.get("findings", 0) or 0),
                error=str(ev.get("error", "") or ""),
                duration_ms=int(ev.get("duration_ms", 0) or 0),
                note=str(ev.get("note", "") or ""),
            )

    def skip(self, name: str, note: str = "") -> None:
        """Record a capability that was deliberately not run (out of mode/scope)."""
        self.record(name, status=SKIPPED, note=note)

    # ── Audit ────────────────────────────────────────────────────

    def audit(self) -> LedgerAudit:
        """Classify every scheduled capability and compute coverage debt."""
        audit = LedgerAudit()
        audit.total = len(self._expected)

        expected_to_run = 0
        for name in sorted(self._expected):
            rec = self._records.get(name)
            if rec is None:
                # Scheduled but never recorded, it vanished. Hardest debt.
                audit.errored += 1
                audit.debt.append(name)
                expected_to_run += 1
                continue
            if rec.status == EXECUTED:
                audit.executed += 1
                expected_to_run += 1
            elif rec.status == EMPTY:
                audit.empty += 1
                audit.gaps.append(name)
                expected_to_run += 1
            elif rec.status == ERRORED:
                audit.errored += 1
                audit.debt.append(name)
                expected_to_run += 1
            elif rec.status == SKIPPED:
                audit.skipped += 1

        audit.coverage_ratio = (audit.executed / expected_to_run) if expected_to_run else 1.0
        return audit

    def blocked(self) -> bool:
        """True when hard coverage debt exists, the clean verdict is not earned."""
        return not self.audit().clean

    def coverage_warning(self) -> str:
        """Human-readable banner for the report when the verdict is blocked."""
        audit = self.audit()
        if audit.clean:
            return ""
        classes = ", ".join(audit.debt)
        return (
            f"COVERAGE INCOMPLETE, {len(audit.debt)} scheduled "
            f"capabilit{'y' if len(audit.debt) == 1 else 'ies'} did not execute "
            f"({classes}). A no-findings or low-severity result is NOT authoritative "
            f"for this run: re-run the failed capabilities before trusting coverage."
        )

    # ── Serialization ────────────────────────────────────────────

    def records(self) -> List[CapabilityRecord]:
        return list(self._records.values())

    def to_dict(self) -> dict:
        audit = self.audit()
        return {
            "audit": audit.to_dict(),
            "coverage_warning": self.coverage_warning(),
            "capabilities": [r.to_dict() for r in self._records.values()],
        }


class _Timer:
    """Tiny context manager for millisecond timing of a capability."""

    def __init__(self):
        self.ms = 0
        self._start = 0.0

    def __enter__(self):
        self._start = time.monotonic()
        return self

    def __exit__(self, *exc):
        self.ms = int((time.monotonic() - self._start) * 1000)
        return False
