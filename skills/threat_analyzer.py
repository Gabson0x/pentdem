"""
Threat Analyzer - Dynamic exploit analysis for any tool output.

Takes raw findings from ANY tool (Nuclei, Nmap, Nikto, ffuf, etc.)
and studies them to determine if they're real, exploitable vulnerabilities.

No hardcoded vuln classes — just analyze the evidence and decide.
"""

import json
import re
from dataclasses import dataclass, field
from typing import Optional
from skills.osint_collector import RawToolFinding


@dataclass
class AnalyzedThreat:
    """A threat that has been analyzed and scored."""
    title: str = ""
    severity: str = "info"
    cvss_score: float = 0.0
    cvss_vector: str = ""
    confidence: float = 0.0
    is_valid: bool = False
    is_exploitable: bool = False
    target: str = ""
    endpoint: str = ""
    parameter: str = ""
    cve_id: str = ""
    description: str = ""
    exploit_scenario: str = ""
    impact: str = ""
    remediation: str = ""
    evidence: str = ""
    poc: str = ""
    source_tool: str = ""
    detection_method: str = ""
    false_positive_reasons: list = field(default_factory=list)
    confirmation_checks: list = field(default_factory=list)
    tags: list = field(default_factory=list)
    mitre_attack_id: str = ""
    mitre_tactic: str = ""
    raw_data: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "confidence": self.confidence,
            "is_valid": self.is_valid,
            "is_exploitable": self.is_exploitable,
            "target": self.target,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "cve_id": self.cve_id,
            "description": self.description,
            "exploit_scenario": self.exploit_scenario,
            "impact": self.impact,
            "remediation": self.remediation,
            "evidence": self.evidence,
            "poc": self.poc,
            "source_tool": self.source_tool,
            "detection_method": self.detection_method,
            "false_positive_reasons": self.false_positive_reasons,
            "confirmation_checks": self.confirmation_checks,
            "tags": self.tags,
            "mitre_attack_id": self.mitre_attack_id,
            "mitre_tactic": self.mitre_tactic,
        }


# False positive heuristics
FP_PATTERNS = [
    # Version-only detection without exploit proof
    r"version\s+[\d.]+.*(?:vulnerable|affected)",
    r"detected\s+(?:version|server)\s+[\d.]+",
    # Generic banner matches
    r"server\s+banner\s+disclosure",
    r"header\s+(?:missing|present)",
    r"cookie\s+(?:missing|no\s+httponly|no\s+secure)",
    # Informational findings
    r"information\s+disclosure",
    r"debug\s+(?:mode|enabled)",
    r"verbose\s+error",
]

# Confirmation patterns (stronger evidence)
CONFIRM_PATTERNS = [
    # Direct evidence of exploitation
    r"exploit(?:ed|able|ation)",
    r"confirmed\s+vulnerability",
    r"successfully\s+(?:executed|exploited|injected)",
    r"command\s+(?:executed|injection)",
    r"data\s+(?:exfiltrated|extracted|dumped)",
    # Specific proof
    r"root@|uid=\d|whoami",
    r"password\s*[:=]\s*\S+",
    r"token\s*[:=]\s*\S+",
    r"secret\s*[:=]\s*\S+",
]


class ThreatAnalyzer:
    """
    Analyzes any tool output and determines if findings are real.

    Flow:
    1. Receive raw findings from OSINT collector
    2. For each finding, analyze evidence and context
    3. Check for false positive patterns
    4. Check for confirmation patterns
    5. Score confidence
    6. Generate exploit scenario if valid
    7. Return analyzed threats

    No hardcoded vuln classes — just evidence-based analysis.
    """

    def __init__(self, llm_callback=None):
        self.llm_callback = llm_callback

    async def analyze(self, raw_findings: list[RawToolFinding], target: str = "") -> list[AnalyzedThreat]:
        """Analyze all raw findings and return validated threats."""
        analyzed = []

        for finding in raw_findings:
            if not finding.is_potential_threat:
                # Still analyze info findings — they might be interesting
                if finding.severity in ("critical", "high", "medium"):
                    result = await self._analyze_single(finding, target)
                    if result and result.is_valid:
                        analyzed.append(result)
            else:
                result = await self._analyze_single(finding, target)
                if result:
                    analyzed.append(result)

        # Sort by severity then confidence
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        analyzed.sort(key=lambda x: (severity_order.get(x.severity, 4), -x.confidence))

        return analyzed

    async def _analyze_single(self, finding: RawToolFinding, target: str) -> Optional[AnalyzedThreat]:
        """Analyze a single raw finding."""
        # Build analysis prompt for LLM
        analysis = AnalyzedThreat(
            title=finding.title or finding.template_name,
            severity=finding.severity,
            target=finding.target or target,
            endpoint=finding.matched_at or finding.endpoint,
            parameter=finding.parameter,
            cve_id=finding.cve_id,
            evidence=finding.evidence or finding.raw_line,
            source_tool=finding.source_tool,
            cvss_score=finding.cvss_score,
            raw_data=finding.raw_data,
            tags=finding.tags,
        )

        # Step 1: Check for false positive patterns
        fp_reasons = self._check_false_positive_patterns(finding)
        analysis.false_positive_reasons = fp_reasons

        # Step 2: Check for confirmation patterns
        confirm_checks = self._check_confirmation_patterns(finding)
        analysis.confirmation_checks = confirm_checks

        # Step 3: Calculate confidence
        base_confidence = finding.confidence
        if fp_reasons:
            base_confidence *= 0.3  # Reduce if FP patterns detected
        if confirm_checks:
            base_confidence = min(1.0, base_confidence + 0.3 * len(confirm_checks))

        # Step 4: Determine validity
        analysis.confidence = base_confidence
        analysis.is_valid = base_confidence > 0.4 and len(fp_reasons) < 2
        analysis.is_exploitable = base_confidence > 0.6 and len(confirm_checks) > 0

        # Step 5: If we have CVE, enrich with CVE data
        if finding.cve_id:
            analysis.cve_id = finding.cve_id
            analysis.description = finding.raw_data.get("description", "")
            analysis.remediation = finding.raw_data.get("remediation", "")
            if finding.cvss_score > 0:
                analysis.cvss_score = finding.cvss_score

        # Step 6: Generate description if missing
        if not analysis.description:
            analysis.description = self._generate_description(finding)

        # Step 7: Generate impact
        analysis.impact = self._assess_impact(finding, analysis)

        # Step 8: Generate remediation
        if not analysis.remediation:
            analysis.remediation = self._suggest_remediation(finding)

        # Step 9: Generate exploit scenario if exploitable
        if analysis.is_exploitable:
            analysis.exploit_scenario = self._build_exploit_scenario(finding, analysis)

        # Step 10: Map to MITRE ATT&CK
        analysis.mitre_attack_id, analysis.mitre_tactic = self._map_to_mitre(finding, analysis)

        # Step 11: Generate PoC
        analysis.poc = self._generate_poc(finding, analysis)

        return analysis

    def _check_false_positive_patterns(self, finding: RawToolFinding) -> list[str]:
        """Check for patterns that indicate false positives."""
        reasons = []
        text = f"{finding.title} {finding.raw_line} {finding.evidence}".lower()

        for pattern in FP_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                reasons.append(f"Matches FP pattern: {pattern[:50]}")

        # Version-only detection
        if finding.source_tool == "nuclei" and not finding.evidence:
            if any(w in finding.template_id.lower() for w in ["version", "detect", "fingerprint"]):
                reasons.append("Version-only detection without exploit proof")

        # Header/cookie findings (often informational)
        if any(w in text for w in ["header", "cookie", "metadata", "banner"]):
            reasons.append("Header/metadata finding — often informational")

        return reasons

    def _check_confirmation_patterns(self, finding: RawToolFinding) -> list[str]:
        """Check for patterns that confirm the vulnerability."""
        checks = []
        text = f"{finding.title} {finding.raw_line} {finding.evidence}".lower()

        for pattern in CONFIRM_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                checks.append(f"Confirmed by: {pattern[:50]}")

        # CVE with high CVSS
        if finding.cve_id and finding.cvss_score >= 7.0:
            checks.append(f"High CVSS CVE: {finding.cve_id} ({finding.cvss_score})")

        # Direct exploit evidence
        if finding.evidence and any(w in finding.evidence.lower() for w in ["root@", "uid=", "whoami", "password"]):
            checks.append("Direct command execution evidence")

        return checks

    def _generate_description(self, finding: RawToolFinding) -> str:
        """Generate a description from available evidence."""
        parts = []

        if finding.source_tool:
            parts.append(f"Detected by {finding.source_tool}")

        if finding.template_name:
            parts.append(f"Template: {finding.template_name}")

        if finding.cve_id:
            parts.append(f"CVE: {finding.cve_id}")

        if finding.matched_at:
            parts.append(f"Found at: {finding.matched_at}")

        if finding.service:
            parts.append(f"Service: {finding.service} {finding.version}")

        if finding.evidence:
            parts.append(f"Evidence: {finding.evidence[:200]}")

        return ". ".join(parts) if parts else finding.title

    def _assess_impact(self, finding: RawToolFinding, analysis: AnalyzedThreat) -> str:
        """Assess business impact of the finding."""
        severity = analysis.severity
        cve = analysis.cve_id

        if severity == "critical":
            if cve:
                return f"Critical vulnerability ({cve}) could lead to full system compromise"
            return "Critical severity finding could lead to full system compromise"
        elif severity == "high":
            if cve:
                return f"High severity vulnerability ({cve}) could lead to significant data exposure"
            return "High severity finding could lead to data exposure or unauthorized access"
        elif severity == "medium":
            return "Medium severity finding could provide information useful for further attacks"
        else:
            return "Low severity finding — limited direct impact"

    def _suggest_remediation(self, finding: RawToolFinding) -> str:
        """Suggest remediation based on finding type."""
        text = f"{finding.title} {finding.template_name}".lower()

        if "xss" in text:
            return "Implement input sanitization and output encoding. Use Content-Security-Policy headers."
        elif "sqli" in text or "sql" in text:
            return "Use parameterized queries. Implement input validation. Apply least-privilege database permissions."
        elif "ssrf" in text:
            return "Validate and allowlist URLs. Block internal IP ranges. Use a dedicated fetch service."
        elif "rce" in text or "command" in text:
            return "Avoid shell execution with user input. Use parameterized APIs. Implement input validation."
        elif "idor" in text or "authorization" in text:
            return "Implement proper authorization checks on every resource access. Use indirect object references."
        elif "ssti" in text or "template" in text:
            return "Use sandboxed template engines. Avoid rendering user input in templates."
        elif "path" in text or "traversal" in text:
            return "Validate file paths against an allowlist. Use chroot or containerization."
        elif "lfi" in text or "include" in text:
            return "Validate and sanitize file include paths. Use allowlists for includable files."
        elif finding.cve_id:
            return f"Apply patches for {finding.cve_id}. Check vendor advisory for remediation steps."
        else:
            return "Review the finding and apply appropriate security controls."

    def _build_exploit_scenario(self, finding: RawToolFinding, analysis: AnalyzedThreat) -> str:
        """Build an exploit scenario for confirmed findings."""
        scenario = f"## Exploit Scenario\n\n"
        scenario += f"**Target:** {analysis.target}\n"
        if analysis.endpoint:
            scenario += f"**Endpoint:** {analysis.endpoint}\n"
        if analysis.cve_id:
            scenario += f"**CVE:** {analysis.cve_id}\n"

        scenario += f"\n### Steps to Exploit:\n"
        scenario += f"1. Identify the vulnerable endpoint: `{analysis.endpoint or analysis.target}`\n"

        if analysis.evidence:
            scenario += f"2. Observe the evidence: `{analysis.evidence[:200]}`\n"

        if analysis.cve_id:
            scenario += f"3. Research {analysis.cve_id} for public exploits\n"
            scenario += f"4. Craft payload based on CVE details\n"
            scenario += f"5. Execute against target\n"
        else:
            scenario += f"2. Craft appropriate payload\n"
            scenario += f"3. Execute against target\n"

        scenario += f"\n### Impact:\n{analysis.impact}\n"

        return scenario

    def _map_to_mitre(self, finding: RawToolFinding, analysis: AnalyzedThreat) -> tuple[str, str]:
        """Map finding to MITRE ATT&CK."""
        text = f"{finding.title} {finding.template_name} {finding.evidence}".lower()

        mappings = [
            (r"xss|cross.site", "T1189", "drive-by-compromise"),
            (r"sqli|sql.inject", "T1190", "exploit-public-facing-application"),
            (r"ssrf|server.side.request", "T1552", "unsecured-credentials"),
            (r"rce|remote.code|command.inject", "T1059", "command-and-scripting-interpreter"),
            (r"idor|insecure.direct", "T1068", "exploitation-for-privilege-escalation"),
            (r"auth.*bypass|authentication", "T1078", "valid-accounts"),
            (r"ssti|template.inject", "T1059", "command-and-scripting-interpreter"),
            (r"path.*traversal|directory.*traversal|lfi", "T1083", "file-and-directory-discovery"),
            (r"file.*inclusion", "T1005", "data-from-local-system"),
            (r"deserializ", "T1059", "command-and-scripting-interpreter"),
            (r"open.*redirect", "T1566", "phishing"),
            (r"jwt|token", "T1539", "steal-web-session-cookie"),
            (r"graphql", "T1592", "gather-victim-host-information"),
            (r"information.*disclosure|verbose", "T1082", "system-information-discovery"),
            (r"version.*detect|fingerprint", "T1592", "gather-victim-host-information"),
        ]

        for pattern, technique_id, tactic in mappings:
            if re.search(pattern, text):
                return technique_id, tactic

        return "T1190", "exploit-public-facing-application"

    def _generate_poc(self, finding: RawToolFinding, analysis: AnalyzedThreat) -> str:
        """Generate a non-destructive PoC."""
        endpoint = analysis.endpoint or analysis.target

        if not endpoint:
            return "No PoC generated — no endpoint available"

        if finding.cve_id:
            return f"""# PoC for {finding.cve_id}
# Non-destructive verification only
curl -sS -I "{endpoint}"
# Check for vulnerable version in headers/response
# Compare against known vulnerable version ranges for {finding.cve_id}
"""

        text = f"{finding.title} {finding.template_name}".lower()
        if "xss" in text:
            return f"""# XSS PoC — non-destructive canary
curl -sS "{endpoint}?q=PENTESTAI_POC_$(date +%s)"
# Verify canary string reflects in response without encoding
"""
        elif "sqli" in text:
            return f"""# SQLi PoC — time-based (non-destructive)
time curl -sS "{endpoint}?id=1'%20OR%20SLEEP(3)--"
# Compare response time: baseline vs injected
# If delay matches SLEEP duration, SQLi is confirmed
"""
        elif "ssrf" in text:
            return f"""# SSRF PoC — out-of-band (use collaborator)
curl -sS "{endpoint}?url=https://YOUR-COLLABORATOR/ssrf-test"
# Monitor collaborator for incoming request
"""
        elif "idor" in text:
            return f"""# IDOR PoC — access another user's resource
# Use two test accounts
curl -sS -H "Authorization: Bearer TEST_USER_A_TOKEN" "{endpoint}"
curl -sS -H "Authorization: Bearer TEST_USER_B_TOKEN" "{endpoint}"
# If B can access A's resource, IDOR confirmed
"""
        else:
            return f"""# Generic PoC
curl -sS -I "{endpoint}"
# Analyze response for vulnerability indicators
"""

    def get_summary(self, threats: list[AnalyzedThreat]) -> dict:
        """Get summary of analyzed threats."""
        valid = sum(1 for t in threats if t.is_valid)
        exploitable = sum(1 for t in threats if t.is_exploitable)
        by_severity = {}
        for t in threats:
            by_severity[t.severity] = by_severity.get(t.severity, 0) + 1

        return {
            "total_analyzed": len(threats),
            "valid_findings": valid,
            "exploitable": exploitable,
            "by_severity": by_severity,
            "avg_confidence": sum(t.confidence for t in threats) / max(len(threats), 1),
        }
