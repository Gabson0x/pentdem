"""
Report Writer - Generates standalone MD reports in per-target folders.

Structure:
  reports/
    netflix/
      Netflix_Security_Report_2026-07-07.md
      findings/
        finding_001_SSQL_Injection.md
        finding_002_XSS.md
      evidence/
        nuclei_output.json
        nmap_output.xml
    bugcrowd_target/
      ...

Each report is standalone — can be read, shared, or submitted as-is.
"""

import os
import json
from datetime import datetime
from pathlib import Path
from typing import Optional


class ReportWriter:
    """
    Generates standalone security reports organized by target.

    Each target gets its own folder under reports/.
    Each finding gets its own file for granular sharing.
    The main report links to all findings.
    """

    def __init__(self, base_dir: str = "reports"):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _sanitize_target(self, target: str) -> str:
        """Make target safe for use as folder name."""
        safe = target.replace("https://", "").replace("http://", "")
        safe = safe.replace("/", "_").replace(":", "_").replace("?", "_").replace("&", "_")
        safe = safe.replace(" ", "_").strip("_.")
        return safe[:60]

    def _get_target_dir(self, target: str) -> Path:
        """Get or create the target-specific directory."""
        safe = self._sanitize_target(target)
        target_dir = self.base_dir / safe
        target_dir.mkdir(parents=True, exist_ok=True)
        (target_dir / "findings").mkdir(exist_ok=True)
        (target_dir / "evidence").mkdir(exist_ok=True)
        return target_dir

    def write_finding(self, target: str, finding: dict, index: int) -> str:
        """Write a single finding as a standalone MD file."""
        target_dir = self._get_target_dir(target)
        findings_dir = target_dir / "findings"

        title = finding.get("title", finding.get("type", finding.get("vuln_class", "Unknown Finding")))
        if isinstance(title, str) and title in ("Attack Chain", "Chain", ""):
            title = finding.get("chain_name", finding.get("vuln_class", "Unknown"))
        safe_title = "".join(c if c.isalnum() or c in " -_" else "" for c in str(title))[:50]
        filename = f"finding_{index:03d}_{safe_title.replace(' ', '_')}.md"
        filepath = findings_dir / filename

        sev = finding.get("severity", "info").upper()
        cvss = finding.get("cvss_score", "N/A")
        confidence = finding.get("confidence", 0)
        endpoint = finding.get("endpoint", finding.get("url", ""))
        param = finding.get("parameter", finding.get("param", ""))
        cve = finding.get("cve_id", "")
        description = finding.get("description", "")
        impact = finding.get("impact", "")
        remediation = finding.get("remediation", "")
        evidence = finding.get("evidence", "")
        poc = finding.get("poc", finding.get("poc_script", ""))
        source = finding.get("source_tool", finding.get("source", ""))
        mitre_id = finding.get("mitre_attack_id", "")
        mitre_tactic = finding.get("mitre_tactic", "")
        exploit_scenario = finding.get("exploit_scenario", "")
        tags = finding.get("tags", [])

        content = f"""# {title}

**Severity:** {sev} | **CVSS:** {cvss} | **Confidence:** {confidence*100:.0f}%
**Target:** {target}
**Endpoint:** `{endpoint}`
**Parameter:** `{param}`
**Source:** {source}
**Date:** {datetime.now().strftime("%Y-%m-%d")}

---

## Description

{description or "No description available."}

"""
        if cve:
            content += f"""## CVE Details

**CVE ID:** {cve}
**CVSS Score:** {cvss}

"""
        if mitre_id:
            content += f"""## MITRE ATT&CK

**Technique:** {mitre_id}
**Tactic:** {mitre_tactic}

"""
        if impact:
            content += f"""## Impact

{impact}

"""
        if exploit_scenario:
            content += f"""## Exploit Scenario

{exploit_scenario}

"""
        if evidence:
            content += f"""## Evidence

```
{evidence}
```

"""
        if poc:
            content += f"""## Proof of Concept

```bash
{poc}
```

"""
        # Reference screenshots if available
        screenshots = finding.get("screenshots", [])
        if screenshots:
            content += f"""## Screenshots

"""
            for ss in screenshots:
                if isinstance(ss, dict):
                    ss_path = ss.get("filename", ss.get("file", ""))
                    ss_desc = ss.get("description", ss.get("finding_type", "evidence"))
                else:
                    ss_path = str(ss)
                    ss_desc = "evidence"
                # Use relative path from findings/ to screenshots/
                content += f"![{ss_desc}](../screenshots/{os.path.basename(ss_path)})\n\n"
            content += "\n"

        if remediation:
            content += f"""## Remediation

{remediation}

"""
        if tags:
            content += f"""## Tags

{', '.join(tags)}

"""
        content += f"""---

*Report generated by AI Pentest Daemon on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}*
"""

        filepath.write_text(content, encoding="utf-8")
        return str(filepath)

    def filter_reportable(self, findings: list[dict]) -> list[dict]:
        """Filter findings to only include CONFIRMED verdicts (no false positives)."""
        from skills.waf_bypass import is_reportable
        reportable = []
        for f in findings:
            if is_reportable(f):
                reportable.append(f)
        return reportable

    def write_main_report(
        self,
        target: str,
        findings: list[dict],
        chains: list[dict],
        tool_outputs: list[dict] = None,
        metadata: dict = None,
    ) -> str:
        """Write the main standalone report for a target."""
        target_dir = self._get_target_dir(target)
        safe = self._sanitize_target(target)
        date_str = datetime.now().strftime("%Y-%m-%d")

        # Filter to only CONFIRMED findings (is_reportable gate)
        findings = self.filter_reportable(findings)

        filename = f"{safe.title()}_Security_Report_{date_str}.md"
        filepath = target_dir / filename

        # Separate individual findings from chains
        individual = [f for f in findings if f.get("type") != "Attack Chain"]
        chain_findings = [f for f in findings if f.get("type") == "Attack Chain"]
        # Also include chains passed directly
        all_chains = chain_findings + chains

        # Severity counts
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in individual:
            sev = f.get("severity", "info").upper()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        overall_severity = "LOW"
        for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if sev_counts.get(s, 0) > 0:
                overall_severity = s
                break

        max_cvss = max([f.get("cvss_score", 0) for f in individual] or [0])

        content = f"""# Security Assessment Report

**Target:** {target}
**Date:** {date_str}
**Assessor:** AI Pentest Daemon v3.0
**Report Version:** 1.0

---

## Executive Summary

This report presents the findings of an automated security assessment of **{target}**.

| Metric | Value |
|--------|-------|
| Overall Risk | **{overall_severity}** |
| Max CVSS Score | {max_cvss} |
| Total Findings | {len(individual)} |
| Attack Chains | {len(all_chains)} |
| Critical | {sev_counts.get("CRITICAL", 0)} |
| High | {sev_counts.get("HIGH", 0)} |
| Medium | {sev_counts.get("MEDIUM", 0)} |
| Low | {sev_counts.get("LOW", 0)} |

"""
        if sev_counts.get("CRITICAL", 0) > 0:
            content += """**⚠️ CRITICAL vulnerabilities were identified that require immediate attention.**

"""
        elif sev_counts.get("HIGH", 0) > 0:
            content += """**⚠️ HIGH severity vulnerabilities were identified that should be remediated promptly.**

"""

        # Findings summary table
        if individual:
            content += """## Findings Summary

| # | Finding | Severity | CVSS | Confidence | Endpoint | MITRE |
|---|---------|----------|------|------------|----------|-------|
"""
            for i, f in enumerate(individual, 1):
                title = f.get("title", f.get("type", "Unknown"))[:40]
                sev = f.get("severity", "info").upper()
                cvss = f.get("cvss_score", "N/A")
                conf = f.get("confidence", 0)
                ep = f.get("endpoint", f.get("url", ""))[:30]
                mitre = f.get("mitre_attack_id", "")
                content += f"| {i} | {title} | {sev} | {cvss} | {conf*100:.0f}% | `{ep}` | {mitre} |\n"
            content += "\n"

        # Detailed findings
        if individual:
            content += """## Detailed Findings

"""
            for i, f in enumerate(individual, 1):
                sev = f.get("severity", "info").upper()
                content += f"""### {i}. {f.get('title', f.get('type', 'Unknown'))}

**Severity:** {sev} | **CVSS:** {f.get('cvss_score', 'N/A')} | **Confidence:** {f.get('confidence', 0)*100:.0f}%
**Endpoint:** `{f.get('endpoint', f.get('url', ''))}`
**Parameter:** `{f.get('parameter', f.get('param', ''))}`
**Source:** {f.get('source_tool', f.get('source', 'N/A'))}
"""
                if f.get("cve_id"):
                    content += f"**CVE:** {f['cve_id']}\n"
                if f.get("mitre_attack_id"):
                    content += f"**MITRE ATT&CK:** {f['mitre_attack_id']} ({f.get('mitre_tactic', '')})\n"

                content += f"""
#### Description

{f.get('description', 'No description available.')}

"""
                if f.get("impact"):
                    content += f"""#### Impact

{f['impact']}

"""
                if f.get("evidence"):
                    content += f"""#### Evidence

```
{f['evidence'][:500]}
```

"""
                if f.get("poc") or f.get("poc_script"):
                    content += f"""#### Proof of Concept

```bash
{f.get('poc', f.get('poc_script', 'N/A'))}
```

"""
                if f.get("remediation"):
                    content += f"""#### Remediation

{f['remediation']}

"""
                content += "---\n\n"

        # Attack chains
        if all_chains:
            content += """## Attack Chains

"""
            for i, chain in enumerate(all_chains, 1):
                chain_name = chain.get("chain_name", chain.get("name", f"Chain {i}"))
                severity = chain.get("computed_severity", chain.get("severity", "HIGH")).upper()
                impact = chain.get("chain_impact", chain.get("impact", ""))
                total_score = chain.get("total_score", 0)
                scores = chain.get("scores", {})

                content += f"""### Chain {i}: {chain_name}

**Severity:** {severity} | **Score:** {total_score}/100
"""
                if scores:
                    content += f"""**Scores:** Reach: {scores.get('reach', 0)} | Reliability: {scores.get('reliability', 0)} | Stealth: {scores.get('stealth', 0)} | Speed: {scores.get('speed', 0)} | Impact: {scores.get('impact', 0)}
"""
                content += f"""
**Impact:** {impact}

**Steps:**
"""
                steps = chain.get("steps_to_reproduce", chain.get("steps", []))
                for step in steps:
                    if isinstance(step, dict):
                        content += f"- {step.get('type', '?')} — `{step.get('target', '')}`\n"
                    else:
                        content += f"- {step}\n"
                content += "\n---\n\n"

        # Tool outputs
        if tool_outputs:
            content += """## Tool Outputs

"""
            for tool in tool_outputs:
                content += f"""### {tool.get('tool', 'Unknown')}

**File:** `{tool.get('file', 'N/A')}`
**Summary:** {tool.get('summary', 'N/A')}

"""
                if tool.get("findings_count"):
                    content += f"**Findings:** {tool['findings_count']}\n\n"

        # Methodology
        content += """## Methodology

This assessment was conducted using the following methodology:

1. **Reconnaissance** — Subdomain enumeration, live host discovery, technology fingerprinting
2. **OSINT Collection** — Tool output parsing (Nuclei, Nmap, Nikto, ffuf, etc.)
3. **Threat Analysis** — Dynamic analysis of all tool outputs to identify and validate vulnerabilities
4. **Exploit Validation** — PoC generation and confidence scoring for each finding
5. **Chain Analysis** — Multi-step attack path identification and scoring
6. **Reporting** — Standalone findings with evidence, impact, and remediation

### Tools Used

- Subfinder (subdomain enumeration)
- httpx (live host detection)
- Katana (URL crawling)
- Nuclei (vulnerability scanning)
- Custom threat analysis engine

---

*Report generated by AI Pentest Daemon v3.0 on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}*
"""

        filepath.write_text(content, encoding="utf-8")

        # Also save a JSON summary
        summary_path = target_dir / "summary.json"
        summary = {
            "target": target,
            "date": date_str,
            "overall_severity": overall_severity,
            "max_cvss": max_cvss,
            "total_findings": len(individual),
            "total_chains": len(all_chains),
            "severity_counts": sev_counts,
            "finding_files": [self.write_finding(target, f, i+1) for i, f in enumerate(individual)],
        }
        summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

        return str(filepath)

    def save_tool_output(self, target: str, tool_name: str, content: str, extension: str = "txt") -> str:
        """Save raw tool output to the evidence folder."""
        target_dir = self._get_target_dir(target)
        evidence_dir = target_dir / "evidence"

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_tool = "".join(c if c.isalnum() else "_" for c in tool_name)
        filename = f"{safe_tool}_{ts}.{extension}"
        filepath = evidence_dir / filename

        filepath.write_text(content, encoding="utf-8")
        return str(filepath)

    def list_reports(self) -> list[dict]:
        """List all target reports."""
        reports = []
        for target_dir in self.base_dir.iterdir():
            if target_dir.is_dir():
                md_files = list(target_dir.glob("*.md"))
                json_files = list(target_dir.glob("summary.json"))
                if md_files or json_files:
                    reports.append({
                        "target": target_dir.name,
                        "dir": str(target_dir),
                        "reports": [str(f) for f in md_files],
                        "has_summary": len(json_files) > 0,
                    })
        return reports
