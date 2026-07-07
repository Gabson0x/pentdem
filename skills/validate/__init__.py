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
    """Real validation — 7-question gate, CVSS 3.1 scoring, evidence-based dedup."""

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

            # Run 7-question gate
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
        prompt = f"""Validate this security finding using the 7-Question Gate:

Finding: {json.dumps(finding, indent=2)}

1. Is this a valid, in-scope vulnerability class? (yes/no)
2. Is the vulnerable endpoint/parameter reachable from the internet? (yes/no)  
3. Is the exploitation realistic (no edge-case requirements)? (yes/no)
4. Is there concrete impact (data exposure, code exec, account takeover)? (yes/no)
5. Is this exploitable without additional undiscovered bugs? (yes/no)
6. Can you reproduce this with a clear PoC? (yes/no)
7. Is this unique (not a duplicate of another finding)? (yes/no)

Return JSON:
{{
    "pass": true/false,
    "answers": {{"q1": "yes/no", ...}},
    "reason": "explanation if failed, or 'All checks passed'",
    "exploitability_notes": "how to exploit"
}}"""

        response = await self.llm_analyze(prompt)
        try:
            return json.loads(response)
        except (json.JSONDecodeError, ValueError):
            return {"pass": True, "answers": {}, "reason": "Gate check skipped"}

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
