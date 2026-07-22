"""
Ship-Discipline Gate, is this finding worth sending to *this* program?

The quality gate answers "is the evidence real?" and the adversarial gate
answers "does it survive a disprove attempt?". Neither asks the question a
triager asks first: **should this even be in the report for this program?**

A real, reproducible open-redirect is still a rejected report on a program that
marks open-redirect out of scope. A genuine but informational WAF-detected note
pads a report and lowers the reporter's signal score. A finding already submitted
last week is a duplicate. Sending those does measurable harm, triager time,
signal/reputation, and sometimes a platform strike.

This gate takes each finding that is already believed real and decides its
*bucket*:

    report, meets the program's severity floor, in-scope class, novel
    informational, below floor, informational class, or out-of-scope-by-class
    duplicate, signature already reported for this target in a prior run

Only ``report`` findings go into the vulnerability section; the rest are kept in
the result for the dashboard/diagnostics but never padded into the headline
count. A small persistent ledger (one JSON file per target) remembers what has
already been shipped so repeat runs stop re-reporting the same thing.

Everything here is deterministic (no model calls), so it runs unchanged under
--mock.
"""

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse


# Severity rank for threshold comparisons.
_SEVERITY_RANK = {"info": 0, "informational": 0, "none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Meta/informational classes that are never a standalone vulnerability report.
_INFORMATIONAL_CLASSES = {
    "waf_detected",
    "attack_strategy_recommendation",
    "info",
    "banner",
    "tech_fingerprint",
}


@dataclass
class ProgramProfile:
    """What a given platform/program will accept."""
    name: str = "generic"
    min_severity: str = "low"                       # severity floor for the report
    oos_classes: set = field(default_factory=set)   # classes out of scope by policy
    min_confidence: float = 0.3                     # below this, treat as informational

    def floor_rank(self) -> int:
        return _SEVERITY_RANK.get(self.min_severity.lower(), 1)


# Sensible, conservative defaults. These are floors, not opinions about a specific
# program's scope, a run can override via ShipDisciplineGate(profile=...).
_PROFILES: Dict[str, ProgramProfile] = {
    "generic": ProgramProfile("generic", min_severity="low"),
    # Public platforms tend to down-rank or exclude the noisy classes below by
    # default; teams can still opt them back in with a custom profile.
    "hackerone": ProgramProfile("hackerone", min_severity="low", oos_classes={"open_redirect"}),
    "bugcrowd": ProgramProfile("bugcrowd", min_severity="low", oos_classes={"open_redirect"}),
    "intigriti": ProgramProfile("intigriti", min_severity="low"),
    "immunefi": ProgramProfile("immunefi", min_severity="high"),  # smart-contract: high+ only
    "github": ProgramProfile("github", min_severity="medium"),
}


@dataclass
class ShipDecision:
    """Where a single finding lands and why."""
    bucket: str = "report"                 # report | informational | duplicate
    program_fit: float = 1.0               # 0-1
    reasons: List[str] = field(default_factory=list)

    @property
    def shippable(self) -> bool:
        return self.bucket == "report"

    def to_dict(self) -> dict:
        return {"bucket": self.bucket, "program_fit": round(self.program_fit, 2), "reasons": self.reasons}


class ShipDisciplineGate:
    """
    Program-fit gate. Deterministic; safe to run in mock mode.

    Args:
        platform: platform name used to pick a default profile.
        profile: explicit ProgramProfile override (wins over ``platform``).
        ledger_dir: directory for the per-target "already reported" ledger.
        persist: when False, the duplicate ledger is not read or written (useful
            for tests and one-shot runs).
    """

    def __init__(
        self,
        platform: str = "generic",
        profile: Optional[ProgramProfile] = None,
        ledger_dir: str = ".ship_ledger",
        persist: bool = True,
    ):
        self.profile = profile or _PROFILES.get((platform or "generic").lower(), _PROFILES["generic"])
        self.ledger_dir = ledger_dir
        self.persist = persist
        self.stats = {"report": 0, "informational": 0, "duplicate": 0}
        self._seen_this_run: set = set()

    # ── Public API ───────────────────────────────────────────────

    def filter_batch(
        self, findings: List[Dict[str, Any]], target: str
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Split a batch into (shippable, held_back).

        ``shippable`` are the report-worthy findings; ``held_back`` are the
        informational + duplicate ones, each annotated with a ``ship`` block.
        The already-reported ledger is updated with the shippable signatures.
        """
        prior = self._load_prior(target)
        shippable: List[Dict[str, Any]] = []
        held_back: List[Dict[str, Any]] = []
        newly_reported: List[str] = []

        for finding in findings:
            decision = self._evaluate(finding, prior)
            finding["ship"] = decision.to_dict()
            self.stats[decision.bucket] = self.stats.get(decision.bucket, 0) + 1
            if decision.shippable:
                shippable.append(finding)
                newly_reported.append(self._signature(finding))
            else:
                held_back.append(finding)

        if newly_reported:
            self._save_reported(target, prior, newly_reported)
        return shippable, held_back

    def get_stats(self) -> dict:
        return dict(self.stats)

    # ── Evaluation ───────────────────────────────────────────────

    def _evaluate(self, finding: Dict[str, Any], prior: set) -> ShipDecision:
        decision = ShipDecision()
        vuln = str(finding.get("type", finding.get("vuln_class", ""))).lower()
        severity = str(finding.get("severity", finding.get("cvss_severity", "info"))).lower()
        try:
            confidence = float(finding.get("confidence", 0.5) or 0.5)
        except (TypeError, ValueError):
            confidence = 0.5

        sig = self._signature(finding)

        # 1) Duplicate, reported for this target before, or already this run.
        if sig in prior or sig in self._seen_this_run:
            decision.bucket = "duplicate"
            decision.program_fit = 0.0
            decision.reasons.append("Already reported for this target in a prior run")
            return decision
        self._seen_this_run.add(sig)

        # 2) Informational class, never a standalone vuln report.
        if vuln in _INFORMATIONAL_CLASSES:
            decision.bucket = "informational"
            decision.program_fit = 0.2
            decision.reasons.append(f"Informational class '{vuln}', context, not a vulnerability")
            return decision

        # 3) Out of scope by program policy.
        if vuln in self.profile.oos_classes:
            decision.bucket = "informational"
            decision.program_fit = 0.3
            decision.reasons.append(f"Class '{vuln}' is out of scope for program '{self.profile.name}'")
            return decision

        # 4) Below the program's severity floor.
        sev_rank = _SEVERITY_RANK.get(severity, 0)
        if sev_rank < self.profile.floor_rank():
            decision.bucket = "informational"
            decision.program_fit = 0.4
            decision.reasons.append(
                f"Severity '{severity or 'unknown'}' is below the '{self.profile.min_severity}' "
                f"floor for program '{self.profile.name}'"
            )
            return decision

        # 5) Confidence too low to burn triager time on.
        if confidence < self.profile.min_confidence:
            decision.bucket = "informational"
            decision.program_fit = 0.4
            decision.reasons.append(
                f"Confidence {confidence:.2f} below floor {self.profile.min_confidence:.2f}"
            )
            return decision

        # Shippable.
        decision.bucket = "report"
        decision.program_fit = round(min(1.0, 0.5 + 0.1 * sev_rank + 0.2 * confidence), 2)
        decision.reasons.append(
            f"Meets '{self.profile.name}' bar: severity '{severity}', confidence {confidence:.2f}"
        )
        return decision

    # ── Persistent already-reported ledger ───────────────────────

    def _ledger_path(self, target: str) -> Path:
        safe = target.replace("/", "_").replace(":", "_")
        return Path(self.ledger_dir) / f"{safe}.json"

    def _load_prior(self, target: str) -> set:
        if not self.persist:
            return set()
        path = self._ledger_path(target)
        try:
            if path.exists():
                data = json.loads(path.read_text(encoding="utf-8"))
                return set(data.get("reported", []))
        except Exception:  # noqa: BLE001, a corrupt ledger must not block a run
            pass
        return set()

    def _save_reported(self, target: str, prior: set, new_sigs: List[str]) -> None:
        if not self.persist:
            return
        path = self._ledger_path(target)
        try:
            os.makedirs(path.parent, exist_ok=True)
            merged = sorted(prior.union(new_sigs))
            path.write_text(json.dumps({"target": target, "reported": merged}, indent=2), encoding="utf-8")
        except Exception:  # noqa: BLE001, persistence is best-effort
            pass

    def _signature(self, finding: Dict[str, Any]) -> str:
        url = finding.get("url", finding.get("endpoint", ""))
        vuln = str(finding.get("type", finding.get("vuln_class", "")))
        param = finding.get("param", finding.get("parameter", ""))
        try:
            parsed = urlparse(url)
            base = f"{parsed.netloc}{parsed.path}"
        except Exception:  # noqa: BLE001
            base = url
        return f"{vuln.lower()}:{base}:{param}"
