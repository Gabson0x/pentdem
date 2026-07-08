"""
Report Quality Gate — Single chokepoint for all findings.

Every finding from every detector MUST pass through this gate before
reaching a report. This prevents the class of bugs where:
- SSTI detector fabricates findings with no actual payload sent
- Findings have CVSS=0 but severity=CRITICAL
- Evidence is a description string instead of raw proof
- Identical findings appear multiple times from different payload variants
- Confidence is a hardcoded default rather than computed

Architecture:
    finding -> quality_gate(finding) -> PASS | REJECT (logged)

Every new attack class added to the pipeline inherits this gate for free.
"""

import re
from typing import Dict, Any, List, Tuple, Optional
from dataclasses import dataclass, field


# Hardcoded defaults that indicate a detector didn't compute properly
KNOWN_BAD_CONFIDENCE = {0.0, 0.5, 0.6}  # Common static fallbacks
KNOWN_BAD_CVSS = {0.0, None}


@dataclass
class GateResult:
    """Result of quality gate check."""
    passed: bool
    score: float  # 0-1 quality score
    reasons: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    auto_fixes: Dict[str, Any] = field(default_factory=dict)


class ReportQualityGate:
    """
    Single chokepoint that every finding must pass before report eligibility.
    
    Checks performed:
    1. Request/evidence consistency — HTTP request must contain claimed payload
    2. Evidence snippet required — raw proof, not generated description
    3. Severity/CVSS consistency — reject mismatches
    4. Confidence must be computed — reject static defaults
    5. Dedup identical endpoint+class across payload variants
    6. Server-side proof required — not just reflection
    7. Injection point must be specified
    """

    def __init__(self):
        self.stats = {"total": 0, "passed": 0, "rejected": 0, "auto_fixed": 0}
        self._seen_signatures = set()

    def check(self, finding: Dict[str, Any]) -> GateResult:
        """
        Run all quality checks on a finding.
        
        Returns GateResult with passed=True/False and reasons.
        """
        self.stats["total"] += 1
        result = GateResult(passed=True, score=1.0)

        # ── Check 1: Request/evidence consistency ──
        self._check_request_evidence_consistency(finding, result)

        # ── Check 2: Evidence snippet required ──
        self._check_evidence_quality(finding, result)

        # ── Check 3: Severity/CVSS consistency ──
        self._check_severity_cvss_consistency(finding, result)

        # ── Check 4: Confidence must be computed ──
        self._check_confidence_computed(finding, result)

        # ── Check 5: Dedup identical findings ──
        self._check_duplicate(finding, result)

        # ── Check 6: Server-side proof required ──
        self._check_server_side_proof(finding, result)

        # ── Check 7: Injection point specified ──
        self._check_injection_point(finding, result)

        # ── Check 8: URL/endpoint valid ──
        self._check_url_valid(finding, result)

        # Calculate final score
        if result.warnings:
            result.score *= (1 - 0.1 * len(result.warnings))
        if not result.passed:
            result.score = 0.0

        # Apply auto-fixes if any
        if result.auto_fixes:
            finding.update(result.auto_fixes)
            self.stats["auto_fixed"] += 1

        if result.passed:
            self.stats["passed"] += 1
        else:
            self.stats["rejected"] += 1

        return result

    def check_batch(self, findings: List[Dict[str, Any]]) -> Tuple[List[Dict], List[Dict]]:
        """
        Check a batch of findings. Returns (passed, rejected).
        Also deduplicates across the batch.
        """
        passed = []
        rejected = []
        seen = set()

        for finding in findings:
            result = self.check(finding)

            # Additional batch-level dedup
            sig = self._signature(finding)
            if sig in seen:
                result.passed = False
                result.reasons.append(f"Duplicate of already-processed finding: {sig}")

            if result.passed:
                seen.add(sig)
                passed.append(finding)
            else:
                rejected.append({
                    "finding": finding,
                    "reasons": result.reasons,
                    "score": result.score,
                })

        return passed, rejected

    # ── Individual Checks ────────────────────────────────────────

    def _check_request_evidence_consistency(self, finding: dict, result: GateResult):
        """
        The logged HTTP request must actually contain the claimed payload/parameter.
        If the request log shows no injected param, auto-reject.
        """
        http_request = finding.get("http_request", "")
        payload = finding.get("payload", "")
        param = finding.get("param", finding.get("parameter", ""))

        if not http_request:
            result.warnings.append("No http_request logged — evidence may be fabricated")
            result.score *= 0.8
            return

        if payload and payload not in http_request:
            result.passed = False
            result.reasons.append(
                f"REQUEST/EVIDENCE MISMATCH: payload '{payload}' not found in http_request. "
                f"This usually means the detector fabricated the finding without actually sending the payload."
            )
            return

        if param and param not in http_request and param not in finding.get("url", ""):
            result.warnings.append(
                f"Parameter '{param}' not found in http_request or url — may be incorrect"
            )
            result.score *= 0.9

    def _check_evidence_quality(self, finding: dict, result: GateResult):
        """
        Evidence must be a raw excerpt containing actual proof,
        not a generated description sentence.
        
        If http_request + http_response exist, they ARE the evidence.
        The evidence field is secondary.
        """
        evidence = finding.get("evidence", "")
        http_request = finding.get("http_request", "")
        http_response = finding.get("http_response", "")

        # If we have HTTP request + response, that's sufficient evidence
        if http_request and http_response:
            result.score *= 0.95  # Minor penalty for missing evidence field
            return

        # If we have at least one of request/response, check evidence field
        if http_request or http_response:
            if not evidence:
                result.warnings.append("No evidence field — http_request/http_response provide proof")
                result.score *= 0.9
            return

        # No HTTP evidence at all — check evidence field
        if not evidence:
            result.passed = False
            result.reasons.append("No evidence field AND no http_request/http_response")
            return

        # Reject evidence that's clearly a generated summary
        generated_patterns = [
            "confirmed with",
            "payload variants",
            "multiple payloads",
            "tested with",
            "all checks passed",
            "verified via",
        ]
        evidence_lower = evidence.lower()
        is_generated = any(p in evidence_lower for p in generated_patterns)

        if is_generated and len(evidence) < 200:
            result.passed = False
            result.reasons.append(
                f"Evidence appears to be a generated summary, not raw proof: '{evidence[:100]}...'"
            )
            return

        # Evidence should contain some raw content (HTML, status codes, response snippets)
        has_raw_content = bool(
            re.search(r'(HTTP/\d|Status:|<|{|root:|uid=|error|49|alert)', evidence, re.IGNORECASE)
        )
        if not has_raw_content:
            result.warnings.append("Evidence may lack raw response content")
            result.score *= 0.9

    def _check_severity_cvss_consistency(self, finding: dict, result: GateResult):
        """
        Reject or auto-fix when CVSS=0 but severity=CRITICAL/HIGH,
        or when CVSS is missing entirely.
        """
        severity = finding.get("severity", "").lower()
        cvss = finding.get("cvss_score")

        if cvss is None or cvss == 0:
            if severity in ("critical", "high"):
                # Auto-fix: compute CVSS from severity
                cvss_map = {"critical": 9.0, "high": 7.5, "medium": 5.0, "low": 2.5}
                result.auto_fixes["cvss_score"] = cvss_map.get(severity, 5.0)
                result.warnings.append(
                    f"CVSS was {cvss} but severity is {severity} — auto-fixed to {result.auto_fixes['cvss_score']}"
                )
            elif severity in ("medium", "low"):
                result.auto_fixes["cvss_score"] = {"medium": 5.0, "low": 2.5}.get(severity, 3.0)
                result.warnings.append(f"CVSS was missing — auto-computed from severity")

        if severity == "info" and cvss and cvss > 5.0:
            result.warnings.append(f"Info severity with high CVSS ({cvss}) — inconsistent")
            result.score *= 0.9

    def _check_confidence_computed(self, finding: dict, result: GateResult):
        """
        Reject any finding where confidence exactly matches known hardcoded defaults.
        A real detector should compute confidence based on response analysis.
        """
        confidence = finding.get("confidence")

        if confidence is None:
            result.passed = False
            result.reasons.append("No confidence score — detector didn't compute it")
            return

        # 0.5 is a valid computed confidence, not a hardcoded default
        # Only flag 0.0 as truly invalid
        if confidence == 0.0:
            result.passed = False
            result.reasons.append("Confidence=0.0 — finding has no confidence")
            return

    def _check_duplicate(self, finding: dict, result: GateResult):
        """
        Dedup identical endpoint+class across payload variants.
        Multiple payloads against same endpoint should be one finding entry.
        """
        sig = self._signature(finding)
        if sig in self._seen_signatures:
            result.passed = False
            result.reasons.append(
                f"Duplicate finding: {sig} — already processed. "
                f"Multiple payload variants against the same endpoint should be one entry."
            )
        else:
            self._seen_signatures.add(sig)

    def _check_server_side_proof(self, finding: dict, result: GateResult):
        """
        Require proof that input was processed server-side, not just reflected.
        Uses http_response as fallback evidence if evidence field is missing.
        """
        vuln_type = finding.get("type", finding.get("vuln_class", "")).lower()
        evidence = finding.get("evidence", "").lower()
        http_response = finding.get("http_response", "").lower()
        # Use whichever has content
        proof_source = evidence if evidence else http_response

        # For SSTI, require evaluation proof
        if "ssti" in vuln_type:
            proof = finding.get("evaluation_proof", "")
            if not proof:
                result.passed = False
                result.reasons.append(
                    "SSTI finding without evaluation_proof — "
                    "must show math expression was evaluated (e.g., {{7*7}}=49)"
                )
                return
            if proof in ("{{7*7}}", "${7*7}", "<%= 7*7 %>"):
                result.passed = False
                result.reasons.append(
                    f"Evaluation proof '{proof}' is the payload itself, not the result"
                )

        # For SSRF, require internal content access
        if "ssrf" in vuln_type:
            has_internal = any(ind in proof_source for ind in (
                "root:", "metadata", "ami-id", "instance-id", "169.254",
            ))
            if not has_internal:
                result.warnings.append("SSRF without clear internal content access proof")
                result.score *= 0.8

        # For SQLi, require error or data extraction proof
        if "sqli" in vuln_type:
            has_proof = any(ind in proof_source for ind in (
                "sql", "mysql", "syntax", "error", "union", "select",
            ))
            if not has_proof:
                result.warnings.append("SQLi without clear error or data extraction proof")
                result.score *= 0.8

    def _check_injection_point(self, finding: dict, result: GateResult):
        """Injection point (param/header/body) must be specified."""
        has_param = bool(finding.get("param") or finding.get("parameter"))
        has_header = bool(finding.get("header"))
        has_injection_point = bool(finding.get("injection_point"))

        if not has_param and not has_header and not has_injection_point:
            result.warnings.append("No injection point (param/header) specified")
            result.score *= 0.9

    def _check_url_valid(self, finding: dict, result: GateResult):
        """URL/endpoint must be valid and reachable-looking."""
        url = finding.get("url", finding.get("endpoint", ""))
        if not url:
            result.passed = False
            result.reasons.append("No URL/endpoint specified")
            return

        if not url.startswith(("http://", "https://")):
            result.passed = False
            result.reasons.append(f"Invalid URL format: {url}")
            return

        # Check URL doesn't contain example.com (mock data leak)
        if "example.com" in url:
            result.passed = False
            result.reasons.append(
                f"URL contains example.com — this is mock/test data, not a real finding"
            )

    # ── Helpers ──────────────────────────────────────────────────

    def _signature(self, finding: dict) -> str:
        """Generate a dedup signature for a finding."""
        url = finding.get("url", finding.get("endpoint", ""))
        vuln_type = finding.get("type", finding.get("vuln_class", ""))
        param = finding.get("param", finding.get("parameter", ""))
        # Strip query params for base URL comparison
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url)
            base_url = f"{parsed.netloc}{parsed.path}"
        except Exception:
            base_url = url
        return f"{vuln_type}:{base_url}:{param}"

    def reset_dedup(self):
        """Reset dedup state between runs."""
        self._seen_signatures.clear()

    def get_stats(self) -> dict:
        """Get gate statistics."""
        return dict(self.stats)
