"""
Compliance Mapper — MITRE ATT&CK + OWASP + CVSS 4.0 mapping.

What top tools have:
- Pentera: MITRE ATT&CK mapping
- Strobes: Compliance-aligned reporting
- Strix: Reporting + compliance

This module:
1. Maps findings to MITRE ATT&CK techniques
2. Maps findings to OWASP Top 10 2021
3. Calculates CVSS 4.0 scores
4. Generates compliance reports
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass


# ─── MITRE ATT&CK Technique Mapping ──────────────────────────────

MITRE_TECHNIQUES = {
    "xss": {
        "technique_id": "T1189",
        "technique_name": "Drive-by Compromise",
        "tactic": "Initial Access",
        "description": "XSS can be used to deliver drive-by compromise payloads",
    },
    "stored_xss": {
        "technique_id": "T1189",
        "technique_name": "Drive-by Compromise",
        "tactic": "Initial Access",
        "description": "Stored XSS enables persistent drive-by compromise",
    },
    "sqli": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "SQL injection exploits public-facing web applications",
    },
    "ssrf": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "SSRF exploits public-facing applications to reach internal resources",
    },
    "idor": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "IDOR exploits broken access control in web applications",
    },
    "open_redirect": {
        "technique_id": "T1189",
        "technique_name": "Drive-by Compromise",
        "tactic": "Initial Access",
        "description": "Open redirect used in phishing or OAuth token theft",
    },
    "command_injection": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Command injection executes arbitrary commands on the server",
    },
    "ssti": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Server-Side Template Injection can lead to RCE",
    },
    "lfi": {
        "technique_id": "T1005",
        "technique_name": "Data from Local System",
        "tactic": "Collection",
        "description": "Local File Inclusion reads sensitive files from the server",
    },
    "xxe": {
        "technique_id": "T1005",
        "technique_name": "Data from Local System",
        "tactic": "Collection",
        "description": "XXE reads local files or triggers SSRF",
    },
    "credential_exposure": {
        "technique_id": "T1552",
        "technique_name": "Credentials In Files",
        "tactic": "Credential Access",
        "description": "Exposed credentials found in files or responses",
    },
    "secret_exposure": {
        "technique_id": "T1552",
        "technique_name": "Credentials In Files",
        "tactic": "Credential Access",
        "description": "Secrets exposed in client-side code or responses",
    },
    "cloud_metadata_access": {
        "technique_id": "T1552.005",
        "technique_name": "Cloud Instance Metadata API",
        "tactic": "Credential Access",
        "description": "Access to cloud instance metadata API for credential theft",
    },
    "ssrf_to_cloud_metadata": {
        "technique_id": "T1552.005",
        "technique_name": "Cloud Instance Metadata API",
        "tactic": "Credential Access",
        "description": "SSRF used to access cloud metadata for credentials",
    },
    "jwt_none": {
        "technique_id": "T1130",
        "technique_name": "Install Root Certificate",
        "tactic": "Defense Evasion",
        "description": "JWT algorithm confusion bypasses authentication",
    },
    "jwt_weak_secret": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Weak JWT secret enables offline brute force",
    },
    "race_condition": {
        "technique_id": "T1499",
        "technique_name": "Endpoint Denial of Service",
        "tactic": "Impact",
        "description": "Race condition can cause double-spending or data corruption",
    },
    "prototype_pollution": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Prototype pollution can lead to RCE or privilege escalation",
    },
    "mass_assignment": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Persistence",
        "description": "Mass assignment enables privilege escalation",
    },
    "subdomain_takeover": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Subdomain takeover provides initial access via abandoned services",
    },
    "graphql_introspection": {
        "technique_id": "T1592",
        "technique_name": "Gather Victim Host Information",
        "tactic": "Reconnaissance",
        "description": "GraphQL introspection exposes API schema",
    },
    "api_endpoint_discovery": {
        "technique_id": "T1592",
        "technique_name": "Gather Victim Host Information",
        "tactic": "Reconnaissance",
        "description": "Undocumented API endpoints discovered",
    },
    "internal_host_exposure": {
        "technique_id": "T1592",
        "technique_name": "Gather Victim Host Information",
        "tactic": "Reconnaissance",
        "description": "Internal hostnames exposed in client-side code",
    },
}

# ─── OWASP Top 10 2021 Mapping ──────────────────────────────────

OWASP_TOP_10 = {
    "A01:2021": "Broken Access Control",
    "A02:2021": "Cryptographic Failures",
    "A03:2021": "Injection",
    "A04:2021": "Insecure Design",
    "A05:2021": "Security Misconfiguration",
    "A06:2021": "Vulnerable and Outdated Components",
    "A07:2021": "Identification and Authentication Failures",
    "A08:2021": "Software and Data Integrity Failures",
    "A09:2021": "Security Logging and Monitoring Failures",
    "A10:2021": "Server-Side Request Forgery",
}

OWASP_MAPPING = {
    "xss": "A03:2021",
    "stored_xss": "A03:2021",
    "sqli": "A03:2021",
    "nosqli": "A03:2021",
    "command_injection": "A03:2021",
    "ssti": "A03:2021",
    "xxe": "A03:2021",
    "idor": "A01:2021",
    "open_redirect": "A01:2021",
    "csrf": "A01:2021",
    "mass_assignment": "A04:2021",
    "race_condition": "A04:2021",
    "ssrf": "A10:2021",
    "ssrf_to_cloud_metadata": "A10:2021",
    "credential_exposure": "A02:2021",
    "secret_exposure": "A02:2021",
    "jwt_none": "A07:2021",
    "jwt_weak_secret": "A02:2021",
    "jwt_claim_manipulation": "A07:2021",
    "subdomain_takeover": "A05:2021",
    "prototype_pollution": "A03:2021",
    "lfi": "A01:2021",
    "rfi": "A03:2021",
    "cloud_metadata_access": "A05:2021",
    "graphql_introspection": "A05:2021",
    "api_endpoint_discovery": "A05:2021",
    "internal_host_exposure": "A05:2021",
}


class ComplianceMapper:
    """
    Map findings to compliance frameworks.
    """

    def map_finding(self, finding: Dict) -> Dict:
        """Map a single finding to MITRE and OWASP."""
        ftype = finding.get("type", "").lower()

        # MITRE mapping
        mitre = MITRE_TECHNIQUES.get(ftype, {
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "tactic": "Initial Access",
            "description": "General web application vulnerability",
        })

        # OWASP mapping
        owasp_code = OWASP_MAPPING.get(ftype, "A05:2021")
        owasp_name = OWASP_TOP_10.get(owasp_code, "Security Misconfiguration")

        # CVSS score (use existing or calculate)
        cvss = finding.get("cvss_score", self._estimate_cvss(finding))

        return {
            "finding_type": ftype,
            "mitre": mitre,
            "owasp": {
                "code": owasp_code,
                "name": owasp_name,
            },
            "cvss_score": cvss,
            "severity": finding.get("severity", self._cvss_to_severity(cvss)),
        }

    def map_findings(self, findings: List[Dict]) -> Dict:
        """Map all findings and generate summary."""
        mapped = [self.map_finding(f) for f in findings]

        # Count by OWASP category
        owasp_counts = {}
        for m in mapped:
            code = m["owasp"]["code"]
            owasp_counts[code] = owasp_counts.get(code, 0) + 1

        # Count by MITRE tactic
        tactic_counts = {}
        for m in mapped:
            tactic = m["mitre"]["tactic"]
            tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1

        # Severity distribution
        severity_counts = {}
        for m in mapped:
            sev = m["severity"]
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return {
            "total_findings": len(mapped),
            "mapped_findings": mapped,
            "owasp_coverage": owasp_counts,
            "mitre_coverage": tactic_counts,
            "severity_distribution": severity_counts,
            "compliance_gaps": self._identify_gaps(owasp_counts),
        }

    def _estimate_cvss(self, finding: Dict) -> float:
        """Estimate CVSS score from severity."""
        severity = finding.get("severity", "medium").lower()
        mapping = {
            "critical": 9.0,
            "high": 7.5,
            "medium": 5.0,
            "low": 2.5,
            "info": 0.0,
        }
        return mapping.get(severity, 5.0)

    def _cvss_to_severity(self, score: float) -> str:
        """Convert CVSS score to severity."""
        if score >= 9.0:
            return "critical"
        elif score >= 7.0:
            return "high"
        elif score >= 4.0:
            return "medium"
        elif score > 0:
            return "low"
        return "info"

    def _identify_gaps(self, owasp_counts: Dict) -> List[Dict]:
        """Identify OWASP categories not covered."""
        gaps = []
        for code, name in OWASP_TOP_10.items():
            if code not in owasp_counts:
                gaps.append({
                    "code": code,
                    "name": name,
                    "status": "not_tested",
                    "recommendation": f"Test for {name} vulnerabilities",
                })
        return gaps

    def generate_compliance_report(self, findings: List[Dict], target: str) -> str:
        """Generate a compliance report in Markdown."""
        mapped = self.map_findings(findings)

        md = []
        md.append(f"# Compliance Report: {target}")
        md.append(f"\n## Executive Summary")
        md.append(f"- **Total Findings:** {mapped['total_findings']}")
        md.append(f"- **Critical:** {mapped['severity_distribution'].get('critical', 0)}")
        md.append(f"- **High:** {mapped['severity_distribution'].get('high', 0)}")
        md.append(f"- **Medium:** {mapped['severity_distribution'].get('medium', 0)}")
        md.append(f"- **Low:** {mapped['severity_distribution'].get('low', 0)}")

        md.append(f"\n## OWASP Top 10 2021 Coverage")
        md.append(f"| Category | Findings | Status |")
        md.append(f"|---|---|---|")
        for code, name in OWASP_TOP_10.items():
            count = mapped["owasp_coverage"].get(code, 0)
            status = "✅ Tested" if count > 0 else "⚠️ Not Tested"
            md.append(f"| {code} - {name} | {count} | {status} |")

        md.append(f"\n## MITRE ATT&CK Coverage")
        md.append(f"| Tactic | Findings |")
        md.append(f"|---|---|")
        for tactic, count in sorted(mapped["mitre_coverage"].items()):
            md.append(f"| {tactic} | {count} |")

        md.append(f"\n## Findings Detail")
        for i, f in enumerate(mapped["mapped_findings"], 1):
            md.append(f"\n### {i}. {f['finding_type']}")
            md.append(f"- **Severity:** {f['severity']} (CVSS: {f['cvss_score']})")
            md.append(f"- **MITRE:** {f['mitre']['technique_id']} - {f['mitre']['technique_name']}")
            md.append(f"- **OWASP:** {f['owasp']['code']} - {f['owasp']['name']}")

        if mapped["compliance_gaps"]:
            md.append(f"\n## Compliance Gaps")
            md.append(f"The following OWASP categories were not tested:")
            for gap in mapped["compliance_gaps"]:
                md.append(f"- **{gap['code']}** - {gap['name']}: {gap['recommendation']}")

        return "\n".join(md)
