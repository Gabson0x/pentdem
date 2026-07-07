import json
from typing import Dict, Any, List
from skills.base import BaseSkill, SkillResult


PLATFORM_TEMPLATES = {
    "hackerone": {
        "title": "Security Vulnerability Report",
        "sections": ["Summary", "Vulnerability Details", "Steps to Reproduce", "Impact", "Proof of Concept", "Remediation"],
        "format": "markdown",
    },
    "bugcrowd": {
        "title": "Bug Bounty Submission",
        "sections": ["Vulnerability Type", "Target", "Description", "Steps to Reproduce", "Impact", "Proof of Concept", "Suggested Fix"],
        "format": "markdown",
    },
    "intigriti": {
        "title": "Security Finding Report",
        "sections": ["Title", "Weakness Type", "Affected Endpoint", "Description", "Reproduction Steps", "Business Impact", "Mitigation"],
        "format": "markdown",
    },
    "immunefi": {
        "title": "Smart Contract / Web3 Vulnerability Report",
        "sections": ["Summary", "Vulnerability Class", "Affected Contract/Endpoint", "Description", "Exploit Scenario", "Impact", "Proof of Concept", "Recommendation"],
        "format": "markdown",
    },
    "github": {
        "title": "Security Advisory",
        "sections": ["Package/Repository", "Vulnerability Type", "Description", "Steps to Reproduce", "Impact", "Suggested Fix"],
        "format": "markdown",
    },
}


class ReportSkill(BaseSkill):
    """Professional report generation with platform-specific templates and POC embedding."""

    def can_handle(self, task_type: str) -> bool:
        return task_type in ["report", "hackerone", "bugcrowd", "intigriti", "immunefi"]

    async def execute(self, context: Dict[str, Any]) -> SkillResult:
        findings = context.get("findings", [])
        target = context.get("target", "")
        platform = context.get("platform", "hackerone")
        chains = context.get("chains", [])

        report = await self._generate_report(findings, target, platform, chains)

        cvss_scores = [f.get("cvss_score", 0) for f in findings if f.get("cvss_score")]

        data = {
            "report": report,
            "platform": platform,
            "target": target,
            "finding_count": len(findings),
            "chain_count": len(chains),
            "highest_cvss": max(cvss_scores) if cvss_scores else 0,
        }

        return SkillResult(
            success=True,
            findings=findings,
            data=data,
            next_skills=["memory"],
            confidence=0.95,
        )

    async def _generate_report(self, findings: list, target: str, platform: str, chains: list) -> str:
        template = PLATFORM_TEMPLATES.get(platform, PLATFORM_TEMPLATES["hackerone"])
        platform_name = platform.replace("_", " ").title()

        report = f"# {template['title']}\n\n"
        report += f"**Target:** {target}\n"
        report += f"**Platform:** {platform_name}\n"
        report += f"**Date:** _(generated)_\n"
        report += f"**Total Findings:** {len(findings)}\n"
        report += f"**Chains Identified:** {len(chains)}\n\n"

        if not findings:
            report += "## Summary\nNo actionable vulnerabilities were identified during this scan.\n"
            return report

        overall_score = max((f.get("cvss_score", 0) for f in findings), default=0)
        overall_sev = "critical" if overall_score >= 9 else "high" if overall_score >= 7 else "medium" if overall_score >= 4 else "low"

        report += f"**Overall CVSS Score:** {overall_score} ({overall_sev.upper()})\n\n"

        # Executive summary
        vuln_summary = {}
        for f in findings:
            vt = f.get("type", "Unknown")
            vuln_summary[vt] = vuln_summary.get(vt, 0) + 1
        report += "## Summary\n"
        report += f"Security assessment of **{target}** identified **{len(findings)}** vulnerabilities:\n\n"
        for vt, count in sorted(vuln_summary.items(), key=lambda x: -x[1]):
            report += f"- **{vt}** — {count} instance(s)\n"
        report += "\n---\n\n"

        # Finding details
        for i, finding in enumerate(findings, 1):
            report += f"## Finding {i}: {finding.get('type', 'Unknown')}\n\n"
            report += f"**Severity:** {finding.get('severity', 'medium').upper()}\n"
            report += f"**CVSS Score:** {finding.get('cvss_score', 'N/A')}\n"
            report += f"**CVSS Vector:** {finding.get('cvss_vector', 'N/A')}\n"
            report += f"**URL:** `{finding.get('url', 'N/A')}`\n"
            if finding.get("param"):
                report += f"**Parameter:** `{finding['param']}`\n"
            if finding.get("payload"):
                report += f"**Payload:** `{finding['payload']}`\n"
            report += f"**Confidence:** {finding.get('confidence', 0.5)*100:.0f}%\n\n"

            report += "### Description\n"
            report += f"{finding.get('description', 'No description available.')}\n\n"

            report += "### Steps to Reproduce\n"
            steps = [
                f"1. Navigate to `{finding.get('url', 'N/A')}`",
                f"2. Manipulate the `{finding.get('param', 'request')}` parameter" if finding.get("param") else "2. Craft a malicious request",
            ]
            if finding.get("payload"):
                steps.append(f"3. Inject: `{finding['payload']}`")
            if finding.get("evidence"):
                steps.append(f"4. Observe: `{finding['evidence'][:200]}`")
            steps.append(f"5. Confirm the vulnerability manifests as described")
            for step in steps:
                report += f"{step}\n"
            report += "\n"

            report += "### Impact\n"
            report += f"{self._impact_description(finding)}\n\n"

            report += "### Evidence\n"
            if finding.get("evidence"):
                report += f"```\n{finding['evidence'][:1000]}\n```\n\n"
            else:
                report += "Evidence captured during testing.\n\n"

            report += "### Remediation\n"
            report += f"{self._remediation(finding)}\n\n"
            report += "---\n\n"

        # Attack chains section
        if chains:
            report += "## Attack Chains\n\n"
            report += "The following multi-step attack chains were identified:\n\n"
            for chain in chains:
                report += f"### {chain.get('chain_name', 'Attack Chain')}\n"
                report += f"**Severity:** {chain.get('computed_severity', 'high').upper()}\n"
                report += f"**Impact:** {chain.get('chain_impact', '')}\n\n"
                report += "**Steps:**\n"
                for step in chain.get("steps_to_reproduce", []):
                    report += f"- {step}\n"
                if chain.get("exploit_scenario"):
                    report += f"\n{chain['exploit_scenario']}\n"
                report += "\n---\n\n"

        report += "## Conclusion\n\n"
        report += f"This assessment of **{target}** revealed **{len(findings)}** vulnerabilities "
        report += f"across **{len(vuln_summary)}** vulnerability classes with "
        report += f"**{len(chains)}** exploitable attack chains. "
        report += f"The highest severity finding scored **{overall_score}** ({overall_sev.upper()}) on CVSS 3.1.\n"

        return report

    def _impact_description(self, finding: dict) -> str:
        vuln_type = finding.get("type", "")
        impacts = {
            "SQLi": "An attacker can execute arbitrary SQL queries, potentially extracting, modifying, or deleting database contents. This can lead to complete data breach, authentication bypass, and in some cases remote code execution.",
            "SSRF": "An attacker can make requests to internal systems, cloud metadata endpoints, and other protected resources. This can lead to cloud credential theft, internal network scanning, and lateral movement.",
            "XSS": "An attacker can execute arbitrary JavaScript in the context of the victim's browser, leading to session hijacking, credential theft, phishing attacks, and account takeover.",
            "IDOR": "An attacker can access or modify resources belonging to other users by manipulating identifiers. This can lead to mass data exposure, privilege escalation, and unauthorized actions.",
            "Auth Bypass": "An attacker can bypass authentication controls and access protected resources without valid credentials.",
            "SSTI": "An attacker can execute arbitrary code on the server by injecting template expressions, leading to full server compromise.",
            "Open Redirect": "An attacker can redirect users to malicious sites, enabling phishing attacks and OAuth token theft.",
            "LFI": "An attacker can read arbitrary files on the server, including source code, configuration files, and credentials.",
            "Command Injection": "An attacker can execute arbitrary system commands on the server, leading to complete server takeover.",
            "NoSQLi": "An attacker can bypass authentication or extract data from NoSQL databases through injection attacks.",
            "GraphQL Introspection": "An attacker can discover the complete GraphQL schema, including undocumented fields and mutations, enabling further attacks.",
        }
        return impacts.get(vuln_type, "This vulnerability can be exploited by an attacker to compromise the security of the application.")

    def _remediation(self, finding: dict) -> str:
        vuln_type = finding.get("type", "")
        remediations = {
            "SQLi": "Use parameterized queries / prepared statements. Apply input validation and output encoding. Use a WAF as a defense-in-depth layer. Limit database privileges per application user.",
            "SSRF": "Implement an allowlist of permitted URLs. Block access to private IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16). Disable redirect following. Use a URL parser that rejects IP-based hosts.",
            "XSS": "Implement Content Security Policy (CSP) headers. Encode all user-supplied data before rendering. Use context-aware output encoding. Validate input against an allowlist.",
            "IDOR": "Implement proper authorization checks on every access to resources. Use UUIDs or non-predictable identifiers. Never rely on user-supplied IDs without ownership verification.",
            "Auth Bypass": "Evaluate all authentication checks server-side. Do not rely on headers or cookies for access control decisions. Implement RBAC with proper session validation.",
            "SSTI": "Avoid using template engines with user input. If necessary, use sandboxed template environments. Sanitize and validate template expressions.",
            "Open Redirect": "Use an allowlist of permitted redirect destinations. Validate the redirect URL against the allowlist. Avoid user-controlled redirect parameters.",
            "LFI": "Use an allowlist of permitted files. Avoid passing user input to file inclusion functions. Use a mapping layer between user input and actual file paths.",
            "Command Injection": "Avoid passing user input to system commands. If necessary, use an allowlist of permitted commands and arguments. Use secure APIs instead of shell execution.",
            "NoSQLi": "Sanitize and validate user input before using in NoSQL queries. Use parameterized queries where supported. Avoid string concatenation in query building.",
            "GraphQL Introspection": "Disable GraphQL introspection in production. Implement query depth limiting and rate limiting. Use authentication on all GraphQL endpoints.",
        }
        return remediations.get(vuln_type, "Apply standard security controls: input validation, output encoding, proper authentication and authorization, and defense in depth.")
