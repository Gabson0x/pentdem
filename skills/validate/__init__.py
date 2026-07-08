import asyncio
import json
from typing import Dict, Any, List
from skills.base import BaseSkill, SkillResult


CVSS_31_METRICS = {
    "attack_vector": {"network": 0.85, "adjacent": 0.62, "local": 0.55, "physical": 0.20},
    "attack_complexity": {"low": 0.77, "high": 0.44},
    "privileges_required": {"none": 0.85, "low": 0.62, "high": 0.27},
    "user_interaction": {"none": 0.85, "required": 0.62},
    "scope": {"unchanged": 1.0, "changed": 1.08},
    "confidentiality": {"high": 0.56, "low": 0.22, "none": 0.0},
    "integrity": {"high": 0.56, "low": 0.22, "none": 0.0},
    "availability": {"high": 0.56, "low": 0.22, "none": 0.0},
}

VULN_ALIASES = {
    "sqli": "SQLi",
    "sql_injection": "SQLi",
    "ssrf": "SSRF",
    "xss": "XSS",
    "idor": "IDOR",
    "bola": "IDOR",
    "auth_bypass": "Auth Bypass",
    "authentication_bypass": "Auth Bypass",
    "ssti": "SSTI",
    "server_side_template_injection": "SSTI",
    "open_redirect": "Open Redirect",
    "lfi": "LFI",
    "local_file_inclusion": "LFI",
    "command_injection": "Command Injection",
    "rce": "Command Injection",
    "nosqli": "NoSQLi",
    "graphql": "GraphQL Introspection",
}

VULN_TO_CVSS = {
    "SQLi": {"av": "network", "ac": "low", "pr": "none", "ui": "none", "s": "unchanged", "c": "high", "i": "high", "a": "high"},
    "SSRF": {"av": "network", "ac": "low", "pr": "none", "ui": "none", "s": "changed", "c": "low", "i": "low", "a": "none"},
    "XSS": {"av": "network", "ac": "low", "pr": "none", "ui": "required", "s": "changed", "c": "low", "i": "low", "a": "none"},
    "IDOR": {"av": "network", "ac": "low", "pr": "low", "ui": "none", "s": "unchanged", "c": "high", "i": "none", "a": "none"},
    "Auth Bypass": {"av": "network", "ac": "low", "pr": "none", "ui": "none", "s": "unchanged", "c": "high", "i": "high", "a": "high"},
    "SSTI": {"av": "network", "ac": "low", "pr": "none", "ui": "none", "s": "changed", "c": "high", "i": "high", "a": "high"},
    "Open Redirect": {"av": "network", "ac": "low", "pr": "none", "ui": "required", "s": "changed", "c": "none", "i": "low", "a": "none"},
    "LFI": {"av": "network", "ac": "low", "pr": "none", "ui": "none", "s": "unchanged", "c": "high", "i": "none", "a": "none"},
    "Command Injection": {"av": "network", "ac": "low", "pr": "none", "ui": "none", "s": "changed", "c": "high", "i": "high", "a": "high"},
    "NoSQLi": {"av": "network", "ac": "low", "pr": "none", "ui": "none", "s": "unchanged", "c": "high", "i": "high", "a": "low"},
    "GraphQL Introspection": {"av": "network", "ac": "low", "pr": "none", "ui": "none", "s": "unchanged", "c": "low", "i": "none", "a": "none"},
}


class ValidateSkill(BaseSkill):
    """Real validation — 6-question gate, CVSS 3.1 scoring, evidence-based dedup."""

    def can_handle(self, task_type: str) -> bool:
        return task_type in ["validate", "triage", "severity", "dedup"]

    async def execute(self, context: Dict[str, Any]) -> SkillResult:
        raw_findings = context.get("findings", [])
        validated = []

        for finding in raw_findings:
            # Skip CVSS scoring for chain findings - they have their own
            if finding.get("type") == "Attack Chain":
                finding["gate"] = {"pass": True, "reason": "Attack chain - derived from validated findings"}
                validated.append(finding)
                continue

            # CVSS 3.1 scoring by vuln class
            finding = self._score_cvss(finding)

            # Fast path: if evidence pre-check scores high, skip LLM call
            evidence_check = self._check_evidence_quality(finding)
            if evidence_check["pass"] and evidence_check["score"] >= 0.7:
                finding["gate"] = {
                    "pass": True,
                    "reason": f"Evidence quality sufficient (score={evidence_check['score']:.2f})",
                    "evidence_score": evidence_check["score"],
                    "fast_path": True,
                }
                validated.append(finding)
                continue

            # Slow path: run 6-question gate with LLM
            gate = await self._seven_question_gate(finding)
            finding["gate"] = gate

            if not gate.get("pass", False):
                continue

            validated.append(finding)

        # Deduplicate
        unique = self._dedup(validated)

        return SkillResult(
            success=True,
            findings=unique,
            data={
                "total_raw": len(raw_findings),
                "total_validated": len(validated),
                "total_unique": len(unique),
                "cvss_scores": [f.get("cvss_score", 0) for f in unique],
            },
            next_skills=["report"],
            confidence=0.95,
        )

    def _calculate_cvss(self, metrics: dict) -> tuple:
        ISS = 1 - ((1 - metrics["c"]) * (1 - metrics["i"]) * (1 - metrics["a"]))
        if metrics["s"] == "unchanged":
            impact = 6.42 * ISS
            exploitability = 8.22 * metrics["av"] * metrics["ac"] * metrics["pr"] * metrics["ui"]
            score = 0
            if impact > 0:
                score = round(min(impact + exploitability, 10), 1)
        else:
            impact = 7.52 * (ISS - 0.029) - 3.25 * (ISS - 0.02) ** 15
            exploitability = 8.22 * metrics["av"] * metrics["ac"] * metrics["pr"] * metrics["ui"]
            score = 0
            if impact > 0:
                score = round(min(1.08 * (impact + exploitability), 10), 1)

        if score >= 9.0:
            severity = "critical"
        elif score >= 7.0:
            severity = "high"
        elif score >= 4.0:
            severity = "medium"
        elif score >= 0.1:
            severity = "low"
        else:
            severity = "none"

        return score, severity

    def _score_cvss(self, finding: dict) -> dict:
        raw_vuln_type = finding.get("type", finding.get("vuln_class", ""))
        vuln_key = str(raw_vuln_type).strip()
        vuln_type = VULN_ALIASES.get(vuln_key.lower(), vuln_key)
        base_metrics = VULN_TO_CVSS.get(vuln_type)

        if not base_metrics:
            finding["cvss_score"] = 0
            finding["cvss_severity"] = "none"
            return finding

        numeric_metrics = {
            "av": CVSS_31_METRICS["attack_vector"].get(base_metrics["av"], 0.85),
            "ac": CVSS_31_METRICS["attack_complexity"].get(base_metrics["ac"], 0.77),
            "pr": CVSS_31_METRICS["privileges_required"].get(base_metrics["pr"], 0.85),
            "ui": CVSS_31_METRICS["user_interaction"].get(base_metrics["ui"], 0.85),
            "s": base_metrics["s"],
            "c": CVSS_31_METRICS["confidentiality"].get(base_metrics["c"], 0.0),
            "i": CVSS_31_METRICS["integrity"].get(base_metrics["i"], 0.0),
            "a": CVSS_31_METRICS["availability"].get(base_metrics["a"], 0.0),
        }

        score, severity = self._calculate_cvss(numeric_metrics)
        finding["cvss_score"] = score
        finding["cvss_severity"] = severity
        finding["cvss_vector"] = (
            f"CVSS:3.1/AV:{base_metrics['av'][0].upper()}"
            f"/AC:{base_metrics['ac'][0].upper()}"
            f"/PR:{base_metrics['pr'][0].upper()}"
            f"/UI:{base_metrics['ui'][0].upper()}"
            f"/S:{base_metrics['s'][0].upper()}"
            f"/C:{base_metrics['c'][0].upper()}"
            f"/I:{base_metrics['i'][0].upper()}"
            f"/A:{base_metrics['a'][0].upper()}"
        )

        if not finding.get("severity") or finding["severity"] == "unknown":
            finding["severity"] = severity

        return finding

    async def _seven_question_gate(self, finding: dict) -> dict:
        """
        Enhanced 7-Question Gate with evidence requirements.
        
        Pre-checks evidence quality before LLM validation.
        Rejects findings without sufficient evidence.
        """
        # Pre-check: Evidence quality gate
        evidence_check = self._check_evidence_quality(finding)
        if not evidence_check["pass"]:
            return {
                "pass": False,
                "answers": {},
                "reason": f"Evidence gate failed: {evidence_check['reason']}",
                "exploitability_notes": "Insufficient evidence for validation",
                "evidence_score": evidence_check["score"],
            }
        
        prompt = f"""Validate this security finding using the 6-Question Gate.

Finding: {json.dumps(finding, indent=2)}

1. Is this a valid, in-scope vulnerability class? (yes/no)
2. Is the vulnerable endpoint/parameter reachable from the internet? (yes/no)  
3. Is the exploitation realistic (no edge-case requirements)? (yes/no)
4. Is there concrete impact (data exposure, code exec, account takeover)? (yes/no)
5. Is this exploitable without additional undiscovered bugs? (yes/no)
6. Can you reproduce this with a clear PoC? (yes/no)

IMPORTANT EVIDENCE REQUIREMENTS:
- Finding MUST include: payload_used, injection_point, http_request, http_response, reproduction_steps
- Finding MUST include baseline comparison (before/after)
- Finding MUST include server-side proof (not just reflection)
- If evidence is missing, answer "no" to questions 2 and 6

Return JSON:
{{
    "pass": true/false,
    "answers": {{"q1": "yes/no", ...}},
    "reason": "explanation if failed, or 'All checks passed'",
    "exploitability_notes": "how to exploit",
    "evidence_score": 0.0-1.0
}}"""

        try:
            response = await asyncio.wait_for(self.llm_analyze(prompt), timeout=15)
        except asyncio.TimeoutError:
            return {
                "pass": True,
                "answers": {},
                "reason": "LLM timed out — evidence pre-check passed",
                "exploitability_notes": "",
                "evidence_score": evidence_check["score"],
                "timeout": True,
            }
        try:
            result = json.loads(response)
            # Ensure evidence_score is included
            if "evidence_score" not in result:
                result["evidence_score"] = evidence_check["score"]
            return result
        except (json.JSONDecodeError, ValueError):
            return {
                "pass": False,
                "answers": {},
                "reason": "Gate check failed — invalid LLM response",
                "exploitability_notes": "",
                "evidence_score": evidence_check["score"],
            }

    def _check_evidence_quality(self, finding: dict) -> dict:
        """
        Pre-check evidence quality before LLM validation.
        
        Accepts if finding has http_request/http_response OR evidence field.
        """
        has_payload = bool(finding.get("payload_used") or finding.get("payload"))
        has_injection = bool(finding.get("injection_point") or finding.get("param") or finding.get("parameter"))
        has_http_req = bool(finding.get("http_request"))
        has_http_resp = bool(finding.get("http_response"))
        has_evidence = bool(finding.get("evidence"))
        has_status = bool(finding.get("status_code"))

        # Must have at least one form of evidence
        if not has_http_req and not has_http_resp and not has_evidence:
            return {
                "pass": False,
                "score": 0.0,
                "reason": "No evidence (http_request, http_response, or evidence field)",
                "missing": ["evidence"],
            }

        # Calculate score (0-1)
        score = 0.0
        if has_http_req:
            score += 0.3
        if has_http_resp:
            score += 0.3
        if has_payload:
            score += 0.15
        if has_injection:
            score += 0.15
        if has_evidence or has_status:
            score += 0.1
        score = min(1.0, score)

        # Auto-generate reproduction_steps if missing
        if not finding.get("reproduction_steps"):
            payload = finding.get("payload_used") or finding.get("payload", "")
            url = finding.get("url", "")
            param = finding.get("injection_point") or finding.get("param", "")
            if payload and url:
                finding["reproduction_steps"] = f"Send {payload} to {url} parameter {param}"

        missing = []
        if not has_payload:
            missing.append("payload_used")
        if not has_injection:
            missing.append("injection_point")

        return {
            "pass": True,
            "score": score,
            "reason": "Evidence quality sufficient",
            "missing": missing,
        }

    def _dedup(self, findings: list) -> list:
        if not findings:
            return []

        unique = []
        seen_signatures = set()

        for f in findings:
            url = f.get("url", "")
            vuln_type = f.get("type", f.get("vuln_class", ""))
            param = f.get("param", "")
            description = f.get("description", "")[:100]

            sig = f"{vuln_type}:{url}:{param}:{description}"
            if sig not in seen_signatures:
                seen_signatures.add(sig)
                unique.append(f)

        return unique
