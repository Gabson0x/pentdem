"""
OSINT Collector - Gathers intel from any security tool output.

Parses output from Nuclei, Nmap, Nikto, ffuf, subfinder, httpx, katana,
and any other tool. Normalizes everything into a standard finding format
that the threat analyzer can evaluate.

This replaces the hardcoded 15-vuln-class approach with dynamic threat
analysis that can handle ANY tool output.
"""

import json
import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class RawToolFinding:
    """A normalized finding from ANY security tool."""
    source_tool: str = ""
    source_file: str = ""
    raw_line: str = ""
    title: str = ""
    severity: str = "info"
    target: str = ""
    endpoint: str = ""
    parameter: str = ""
    evidence: str = ""
    cve_id: str = ""
    cvss_score: float = 0.0
    template_id: str = ""       # Nuclei template ID
    template_name: str = ""     # Nuclei template name
    matched_at: str = ""        # Where it was found
    ip_address: str = ""
    port: int = 0
    protocol: str = ""
    service: str = ""
    version: str = ""
    os_info: str = ""
    tags: list = field(default_factory=list)
    raw_data: dict = field(default_factory=dict)
    is_potential_threat: bool = False
    confidence: float = 0.0

    def to_dict(self) -> dict:
        """Convert to dict for pipeline consumption."""
        return {
            "source_tool": self.source_tool,
            "title": self.title,
            "severity": self.severity,
            "target": self.target,
            "endpoint": self.endpoint or self.matched_at,
            "parameter": self.parameter,
            "evidence": self.evidence or self.raw_line,
            "cve_id": self.cve_id,
            "cvss_score": self.cvss_score,
            "template_id": self.template_id,
            "template_name": self.template_name,
            "tags": self.tags,
            "confidence": self.confidence,
            "is_potential_threat": self.is_potential_threat,
            "raw_data": self.raw_data,
        }


class OSINTCollector:
    """
    Collects and normalizes output from any security tool.
    No hardcoded vuln classes — just parse, normalize, and feed to threat analyzer.
    """

    def parse_nuclei_output(self, output: str, target: str = "") -> list[RawToolFinding]:
        """Parse Nuclei JSON or text output into normalized findings."""
        findings = []

        # Try JSON lines first
        for line in output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue

            # Try JSON parse
            try:
                data = json.loads(line)
                findings.append(self._parse_nuclei_json(data, target))
                continue
            except json.JSONDecodeError:
                pass

            # Fallback: text format like "[template-id] [severity] [template-name] [matched-at]"
            match = re.match(
                r'\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]',
                line
            )
            if match:
                findings.append(RawToolFinding(
                    source_tool="nuclei",
                    template_id=match.group(1),
                    severity=match.group(2).lower(),
                    template_name=match.group(3),
                    matched_at=match.group(4),
                    target=target,
                    is_potential_threat=match.group(2).lower() in ("critical", "high", "medium"),
                ))
            elif line.startswith("[") and "] [" in line:
                # Simple nuclei output
                findings.append(RawToolFinding(
                    source_tool="nuclei",
                    raw_line=line,
                    title=line,
                    severity="info",
                    target=target,
                ))

        return findings

    def _parse_nuclei_json(self, data: dict, target: str) -> RawToolFinding:
        """Parse a single Nuclei JSON result."""
        template_id = data.get("template-id", data.get("templateID", ""))
        info = data.get("info", {})
        severity = info.get("severity", "info").lower()
        matched = data.get("matched-at", data.get("matched", ""))
        host = data.get("host", target)

        # Extract CVE if present
        classification = info.get("classification", {})
        cve_id = classification.get("cve-id", "")
        if isinstance(cve_id, list):
            cve_id = cve_id[0] if cve_id else ""

        # Extract CVSS
        cvss = classification.get("cvss-score", 0)
        if isinstance(cvss, str):
            try:
                cvss = float(cvss)
            except ValueError:
                cvss = 0

        # Build description from info
        description = info.get("description", "")
        remediation = info.get("remediation", "")
        reference = info.get("reference", [])
        if isinstance(reference, list):
            reference = reference[:3]

        return RawToolFinding(
            source_tool="nuclei",
            template_id=template_id,
            template_name=info.get("name", template_id),
            severity=severity,
            matched_at=matched,
            target=host,
            cve_id=cve_id,
            cvss_score=cvss,
            evidence=data.get("extracted-results", data.get("matcher-name", "")),
            tags=info.get("tags", "").split(",") if isinstance(info.get("tags", ""), str) else info.get("tags", []),
            is_potential_threat=severity in ("critical", "high", "medium"),
            raw_data={
                "description": description,
                "remediation": remediation,
                "references": reference,
                "matcher_name": data.get("matcher-name", ""),
                "type": data.get("type", ""),
            },
        )

    def parse_nmap_output(self, output: str, target: str = "") -> list[RawToolFinding]:
        """Parse Nmap output into normalized findings."""
        findings = []

        # Parse XML or text output
        for line in output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue

            # Port line: 80/tcp open http Apache/2.4.41
            port_match = re.match(r'(\d+)/(tcp|udp)\s+(open|filtered)\s+(\S+)\s*(.*)', line)
            if port_match:
                port = int(port_match.group(1))
                proto = port_match.group(2)
                state = port_match.group(3)
                service = port_match.group(4)
                version_info = port_match.group(5).strip()

                severity = "info"
                if service in ("http", "https"):
                    severity = "info"
                elif service in ("mysql", "postgresql", "ms-sql-s", "oracle"):
                    severity = "info"
                elif service in ("ftp", "telnet", "rlogin"):
                    severity = "medium"
                elif service in ("ssh",):
                    severity = "info"

                findings.append(RawToolFinding(
                    source_tool="nmap",
                    target=target,
                    port=port,
                    protocol=proto,
                    service=service,
                    version=version_info,
                    title=f"{service} port {port} open",
                    severity=severity,
                    evidence=line,
                    is_potential_threat=False,
                    confidence=0.5,
                ))

            # Vulnerability script output
            elif "VULNERABLE" in line.upper() or "CVE-" in line.upper():
                cve_match = re.search(r'CVE-\d{4}-\d+', line)
                findings.append(RawToolFinding(
                    source_tool="nmap",
                    target=target,
                    title=line[:200],
                    severity="high",
                    evidence=line,
                    cve_id=cve_match.group(0) if cve_match else "",
                    is_potential_threat=True,
                    confidence=0.7,
                ))

        return findings

    def parse_nikto_output(self, output: str, target: str = "") -> list[RawToolFinding]:
        """Parse Nikto output into normalized findings."""
        findings = []

        for line in output.strip().split("\n"):
            line = line.strip()
            if not line or line.startswith("-") or line.startswith("+"):
                continue

            # Nikto lines often start with + OSVDB-xxxx
            osvdb_match = re.match(r'\+\s+(?:OSVDB-\d+:\s+)?(.+)', line)
            if osvdb_match:
                detail = osvdb_match.group(1)

                severity = "info"
                if any(w in detail.lower() for w in ("xss", "injection", "rce", "command", "upload")):
                    severity = "high"
                elif any(w in detail.lower() for w in ("directory", "file", "config", "backup", "default")):
                    severity = "medium"

                findings.append(RawToolFinding(
                    source_tool="nikto",
                    target=target,
                    title=detail[:200],
                    severity=severity,
                    evidence=line,
                    is_potential_threat=severity in ("high", "medium"),
                    confidence=0.5,
                ))

        return findings

    def parse_ffuf_output(self, output: str, target: str = "") -> list[RawToolFinding]:
        """Parse ffuf JSON output into normalized findings."""
        findings = []

        try:
            data = json.loads(output)
            results = data.get("results", [])
            for r in results:
                status = r.get("status", 0)
                url = r.get("url", "")
                size = r.get("length", 0)

                severity = "info"
                # Interesting status codes or paths
                if status == 200 and any(w in url.lower() for w in ("/admin", "/config", "/backup", "/.env", "/debug")):
                    severity = "medium"
                elif status == 403:
                    severity = "info"
                elif status == 500:
                    severity = "medium"

                findings.append(RawToolFinding(
                    source_tool="ffuf",
                    target=target,
                    endpoint=url,
                    title=f"Discovered: {url} [{status}]",
                    severity=severity,
                    evidence=f"Status: {status}, Size: {size}",
                    is_potential_threat=severity == "medium",
                    confidence=0.4,
                ))
        except json.JSONDecodeError:
            # Text output
            for line in output.strip().split("\n"):
                if line.strip():
                    findings.append(RawToolFinding(
                        source_tool="ffuf",
                        target=target,
                        title=line[:200],
                        severity="info",
                        evidence=line,
                    ))

        return findings

    def parse_generic_output(self, output: str, tool_name: str, target: str = "") -> list[RawToolFinding]:
        """
        Generic parser for ANY tool output.
        Looks for patterns that indicate vulnerabilities:
        - CVE IDs
        - Severity keywords
        - HTTP status codes
        - IP addresses
        - Error messages
        """
        findings = []

        for line in output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue

            severity = "info"
            is_threat = False

            # CVE pattern
            cve_match = re.search(r'CVE-\d{4}-\d+', line)
            if cve_match:
                severity = "high"
                is_threat = True

            # Vulnerability keywords
            vuln_keywords = [
                "vulnerable", "exploit", "injection", "xss", "ssrf", "sqli",
                "rce", "remote code", "command injection", "path traversal",
                "directory traversal", "file inclusion", "buffer overflow",
                "sql injection", "cross-site", "authentication bypass",
                "privilege escalation", "information disclosure",
            ]
            if any(kw in line.lower() for kw in vuln_keywords):
                severity = "high"
                is_threat = True

            # Warning/error patterns
            if any(w in line.lower() for w in ["warning:", "error:", "critical:", "fatal:"]):
                severity = "medium"
                is_threat = True

            # HTTP patterns
            http_match = re.search(r'HTTP/\d\.\d\s+(\d{3})', line)
            if http_match:
                code = int(http_match.group(1))
                if code >= 500:
                    severity = "medium"
                    is_threat = True
                elif code == 403:
                    severity = "info"

            findings.append(RawToolFinding(
                source_tool=tool_name,
                target=target,
                title=line[:200],
                severity=severity,
                evidence=line,
                cve_id=cve_match.group(0) if cve_match else "",
                is_potential_threat=is_threat,
                confidence=0.3 if is_threat else 0.1,
            ))

        return findings

    def collect_from_file(self, filepath: str, tool_name: str = "", target: str = "") -> list[RawToolFinding]:
        """Auto-detect tool type and parse file."""
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except FileNotFoundError:
            return []

        # Auto-detect tool from filename or content
        if not tool_name:
            fname = filepath.lower()
            if "nuclei" in fname:
                tool_name = "nuclei"
            elif "nmap" in fname:
                tool_name = "nmap"
            elif "nikto" in fname:
                tool_name = "nikto"
            elif "ffuf" in fname:
                tool_name = "ffuf"
            else:
                tool_name = "unknown"

        # Parse based on tool
        if tool_name == "nuclei":
            return self.parse_nuclei_output(content, target)
        elif tool_name == "nmap":
            return self.parse_nmap_output(content, target)
        elif tool_name == "nikto":
            return self.parse_nikto_output(content, target)
        elif tool_name == "ffuf":
            return self.parse_ffuf_output(content, target)
        else:
            return self.parse_generic_output(content, tool_name, target)

    def collect_from_dict(self, data: dict, tool_name: str = "", target: str = "") -> list[RawToolFinding]:
        """Parse structured data (e.g., from API response)."""
        if isinstance(data, list):
            findings = []
            for item in data:
                if isinstance(item, dict):
                    findings.append(RawToolFinding(
                        source_tool=tool_name,
                        target=target,
                        title=item.get("title", item.get("name", "")),
                        severity=item.get("severity", "info"),
                        endpoint=item.get("endpoint", item.get("url", "")),
                        evidence=item.get("evidence", item.get("description", "")),
                        cve_id=item.get("cve_id", item.get("cve", "")),
                        raw_data=item,
                        is_potential_threat=item.get("severity", "").lower() in ("critical", "high", "medium"),
                    ))
            return findings
        elif isinstance(data, dict):
            return [RawToolFinding(
                source_tool=tool_name,
                target=target,
                title=data.get("title", data.get("name", "")),
                severity=data.get("severity", "info"),
                endpoint=data.get("endpoint", data.get("url", "")),
                evidence=data.get("evidence", data.get("description", "")),
                cve_id=data.get("cve_id", data.get("cve", "")),
                raw_data=data,
                is_potential_threat=data.get("severity", "").lower() in ("critical", "high", "medium"),
            )]
        return []

    def summarize(self, findings: list[RawToolFinding]) -> dict:
        """Summarize all collected findings."""
        by_tool = {}
        by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        threats = 0

        for f in findings:
            by_tool[f.source_tool] = by_tool.get(f.source_tool, 0) + 1
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
            if f.is_potential_threat:
                threats += 1

        return {
            "total_findings": len(findings),
            "potential_threats": threats,
            "by_tool": by_tool,
            "by_severity": by_severity,
        }
