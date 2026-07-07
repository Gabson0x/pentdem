import json
from typing import Dict, Any, List
from skills.base import BaseSkill, SkillResult


class ChainSkill(BaseSkill):
    """Chain builder — finds A→B→C attack paths from discovered vulnerabilities."""

    CHAIN_TEMPLATES = [
        {
            "name": "SSRF → Cloud Metadata → Credentials",
            "path": ["SSRF", "Cloud Metadata", "Credentials Exfiltration"],
            "impact": "Full cloud account compromise via metadata service",
            "severity": "critical",
        },
        {
            "name": "Open Redirect → OAuth Token Theft",
            "path": ["Open Redirect", "OAuth Flow Hijack", "Account Takeover"],
            "impact": "Steal OAuth tokens via redirect chain, full account takeover",
            "severity": "critical",
        },
        {
            "name": "IDOR → Admin Privilege Escalation",
            "path": ["IDOR", "Privilege Escalation", "Admin Access"],
            "impact": "Access admin-level resources via IDOR chain",
            "severity": "high",
        },
        {
            "name": "XSS → Session Hijacking → ATO",
            "path": ["XSS", "Session Theft", "Account Takeover"],
            "impact": "Steal session cookies via XSS, full account takeover",
            "severity": "critical",
        },
        {
            "name": "SQLi → Database Dump → Sensitive Data",
            "path": ["SQLi", "Data Exfiltration", "Credential Theft"],
            "impact": "Extract all database contents via SQL injection",
            "severity": "critical",
        },
        {
            "name": "SSTI → RCE → Full Server Compromise",
            "path": ["SSTI", "Remote Code Execution", "Server Takeover"],
            "impact": "Shell access via template injection",
            "severity": "critical",
        },
        {
            "name": "LFI → Log Poisoning → RCE",
            "path": ["LFI", "Log Poisoning", "Remote Code Execution"],
            "impact": "Write PHP to logs, include via LFI, execute code",
            "severity": "critical",
        },
        {
            "name": "Auth Bypass → IDOR → Mass Data Exposure",
            "path": ["Auth Bypass", "IDOR", "Mass Data Exposure"],
            "impact": "Bypass auth then enumerate all user data via IDOR",
            "severity": "critical",
        },
        {
            "name": "NoSQLi → Auth Bypass → Admin Panel Access",
            "path": ["NoSQLi", "Auth Bypass", "Admin Access"],
            "impact": "Bypass authentication via NoSQL injection",
            "severity": "high",
        },
        {
            "name": "GraphQL Introspection → Field Abuse → Data Leak",
            "path": ["GraphQL Introspection", "Query Abuse", "Data Leak"],
            "impact": "Extract hidden fields and relationships via introspection",
            "severity": "high",
        },
        {
            "name": "CORS Misconfig → API Abuse → Data Theft",
            "path": ["CORS Misconfig", "Cross-Origin API Abuse", "Data Theft"],
            "impact": "Exfiltrate API data via cross-origin requests",
            "severity": "high",
        },
        {
            "name": "Command Injection → Reverse Shell → Pivot",
            "path": ["Command Injection", "Reverse Shell", "Internal Network Pivot"],
            "impact": "Full RCE, then pivot to internal services",
            "severity": "critical",
        },
    ]

    def can_handle(self, task_type: str) -> bool:
        return task_type in ["chain", "chain_builder"]

    def _compute_business_impact(self, finding_types: list) -> str:
        has_critical = any(
            f.get("severity", "").lower() in ("critical", "high") or
            f.get("type", "") in ("SQLi", "SSRF", "SSTI", "Command Injection", "Auth Bypass")
            for f in finding_types
        )
        if has_critical:
            return "Complete system compromise possible"
        if any(f.get("severity", "").lower() == "high" for f in finding_types):
            return "Significant data exposure"
        return "Limited impact, but chaining increases severity"

    def _calculate_chain_scores(self, chain: dict, findings: list) -> dict:
        """
        5-dimension chain scoring model (0-100 each):
        - Reach: How far does the chain go? (user -> root -> domain admin -> crown jewels)
        - Reliability: How many steps are confirmed vs speculative?
        - Stealth: Overall OPSEC profile of the chain
        - Speed: Total estimated execution time (higher = faster)
        - Impact: Business impact at the final step
        """
        num_steps = len(chain.get("path", []))
        num_findings = len(findings)

        # Reach: more steps + critical vulns = higher reach
        critical_count = sum(1 for f in findings if f.get("severity", "").lower() == "critical")
        high_count = sum(1 for f in findings if f.get("severity", "").lower() == "high")
        reach = min(100, (num_steps * 15) + (critical_count * 20) + (high_count * 10))

        # Reliability: ratio of findings with evidence
        confirmed = sum(1 for f in findings if f.get("evidence") or f.get("confidence", 0) > 0.7)
        reliability = int((confirmed / max(num_findings, 1)) * 100)

        # Stealth: more steps = more detection opportunities = lower stealth
        stealth = max(10, 100 - (num_steps * 15))

        # Speed: fewer steps = faster execution
        speed = max(20, 100 - (num_steps * 12))

        # Impact: based on chain severity and finding types
        impact_types = {"SSRF": 90, "SQLi": 85, "RCE": 100, "SSTI": 95, "Command Injection": 100,
                        "Auth Bypass": 80, "IDOR": 60, "XSS": 50, "NoSQLi": 70}
        max_impact = 30  # base
        for f in findings:
            ft = f.get("type", f.get("vuln_class", ""))
            if ft in impact_types:
                max_impact = max(max_impact, impact_types[ft])
        impact = min(100, max_impact + (critical_count * 5))

        return {
            "reach": reach,
            "reliability": reliability,
            "stealth": stealth,
            "speed": speed,
            "impact": impact,
        }

    def _compute_chain_severity(self, findings: list) -> str:
        severities = [f.get("severity", "low").lower() for f in findings]
        if any(s == "critical" for s in severities):
            return "critical"
        if any(s == "high" for s in severities):
            return "high"
        if any(s == "medium" for s in severities):
            return "medium"
        return "low"

    def _merge_findings(self, chain: dict, matched_findings: list) -> dict:
        merged_vulns = []
        for f in matched_findings:
            merged_vulns.append({
                "type": f.get("type", f.get("vuln_class", "Unknown")),
                "url": f.get("url", ""),
                "param": f.get("param", ""),
                "severity": f.get("severity", "medium"),
                "description": f.get("description", ""),
                "evidence": f.get("evidence", ""),
            })

        scores = self._calculate_chain_scores(chain, matched_findings)
        total_score = int(
            scores["reach"] * 0.30
            + scores["reliability"] * 0.25
            + scores["stealth"] * 0.20
            + scores["speed"] * 0.15
            + scores["impact"] * 0.10
        )

        return {
            "type": "Attack Chain",
            "vuln_class": "Chain",
            "chain_name": chain["name"],
            "chain_path": chain["path"],
            "base_severity": chain["severity"],
            "severity": self._compute_chain_severity(matched_findings),
            "computed_severity": self._compute_chain_severity(matched_findings),
            "vulnerabilities": merged_vulns,
            "chain_impact": chain["impact"],
            "exploit_scenario": self._build_exploit_scenario(chain, matched_findings),
            "steps_to_reproduce": self._build_steps(chain, merged_vulns),
            "total_vulns_in_chain": len(merged_vulns),
            "confidence": min(len(matched_findings) / 3, 1.0),
            "cvss_score": 9.8 if self._compute_chain_severity(matched_findings) == "critical" else 8.2 if self._compute_chain_severity(matched_findings) == "high" else 5.5,
            "cvss_severity": self._compute_chain_severity(matched_findings).upper(),
            "scores": scores,
            "total_score": total_score,
        }

    async def execute(self, context: Dict[str, Any]) -> SkillResult:
        findings = context.get("findings", [])
        target = context.get("target", "")

        data = {"chains": [], "total_chains": 0}

        if not findings:
            return SkillResult(success=True, findings=[], data=data, next_skills=["validate"], confidence=1.0)

        finding_types = set()
        for f in findings:
            ft = f.get("type", f.get("vuln_class", ""))
            if ft:
                finding_types.add(ft)

        matched_chains = []
        for chain in self.CHAIN_TEMPLATES:
            chain_types = set(chain["path"])
            overlap = finding_types & chain_types
            if overlap:
                matched_findings = [
                    f for f in findings
                    if f.get("type", f.get("vuln_class", "")) in chain_types
                ]
                if matched_findings:
                    matched_chains.append(self._merge_findings(chain, matched_findings))

        if matched_chains:
            data["chains"] = matched_chains
            data["total_chains"] = len(matched_chains)

            # If we have chains, run LLM to find novel chains not in templates
            if len(matched_chains) >= 2:
                novel_chains = await self._find_novel_chains(target, findings, matched_chains)
                if novel_chains:
                    data["novel_chains"] = novel_chains

        return SkillResult(
            success=True,
            findings=matched_chains,
            data=data,
            next_skills=["validate"],
            confidence=min(len(matched_chains) / 3, 1.0) if matched_chains else 1.0,
        )

    def _build_exploit_scenario(self, chain: dict, findings: list) -> str:
        scenario = f"## {chain['name']}\n\n"
        scenario += f"**Impact:** {chain['impact']}\n\n"
        scenario += "### Attack Flow:\n"
        for i, step in enumerate(chain["path"], 1):
            matching = [f for f in findings if f.get("type", f.get("vuln_class", "")) in step]
            if matching:
                evidence = matching[0].get("evidence", "")[:200]
                scenario += f"{i}. **{step}** — Found: {matching[0].get('description', '')}\n"
                if evidence:
                    scenario += f"   Evidence: `{evidence}`\n"
            else:
                scenario += f"{i}. **{step}** (potential — not yet confirmed)\n"
        return scenario

    def _build_steps(self, chain: dict, vulns: list) -> list:
        steps = []
        for i, (step, vuln) in enumerate(zip(chain["path"], vulns), 1):
            step_text = f"Step {i}: {step}"
            if vuln.get("url"):
                step_text += f" — `{vuln['url']}`"
            steps.append(step_text)
        steps.append(f"Step {len(chain['path'])+1}: Attain {chain['impact']}")
        return steps

    async def _find_novel_chains(self, target: str, findings: list, existing_chains: list) -> list:
        prompt = f"""Given these vulnerabilities found on {target}:

Findings: {json.dumps(findings, indent=2)[:3000]}
Existing chains: {json.dumps(existing_chains, indent=2)[:2000]}

Are there any novel attack chains (A→B→C combinations) NOT covered by the existing chains?

Return JSON:
[{{"chain_name": "...", "path": ["Step1", "Step2"], "impact": "...", "exploit_scenario": "..."}}]
or [] if none."""

        response = await self.llm_analyze(prompt)
        try:
            chains = json.loads(response)
            return chains if isinstance(chains, list) else []
        except (json.JSONDecodeError, ValueError):
            return []
