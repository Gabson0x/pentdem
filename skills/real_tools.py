"""
Real Tool Grounding — wraps actual security tools (not mocks).

What top tools have:
- XBOW: Deterministic validation with real exploitation
- NodeZero: Real credential attacks, lateral movement
- Pentera: Real ransomware simulation
- Strix: Tool-grounded execution (nmap, ffuf, sqlmap)

This module:
1. Runs real tools (local or Docker-isolated)
2. Parses tool output into structured findings
3. Validates findings with evidence
4. Chains tool results for multi-step attacks
"""

import asyncio
import json
import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass


@dataclass
class ToolResult:
    tool: str
    success: bool
    raw_output: str
    parsed_findings: List[Dict]
    duration: float
    errors: str = ""


class RealToolRunner:
    """
    Run real security tools and parse their output.
    """

    def __init__(self, use_docker: bool = False):
        self.use_docker = use_docker
        self._docker_isolator = None

        if use_docker:
            try:
                from skills.docker_isolation import DockerIsolator
                self._docker_isolator = DockerIsolator()
            except ImportError:
                self.use_docker = False

    # ─── Nmap ──────────────────────────────────────────────────────

    async def run_nmap(self, target: str, ports: str = "1-1000", scripts: str = "default") -> ToolResult:
        """Run nmap and parse results."""
        args = ["-sV", "-sC", "-p", ports, "-oX", "-", "--open"]

        if self.use_docker and self._docker_isolator:
            result = await self._docker_isolator.run_nmap(target, ports, scripts)
        else:
            result = await self._run_local("nmap", args + [target])

        parsed = self._parse_nmap_output(result.get("output", ""))

        return ToolResult(
            tool="nmap",
            success=result.get("success", False),
            raw_output=result.get("output", ""),
            parsed_findings=parsed,
            duration=result.get("duration", 0),
            errors=result.get("errors", ""),
        )

    def _parse_nmap_output(self, output: str) -> List[Dict]:
        """Parse nmap XML/text output into findings."""
        findings = []

        # Parse open ports
        port_pattern = r'(\d+)/(\w+)\s+(open)\s+([\w\-/\.]+)(?:\s+(.*))?'
        for match in re.finditer(port_pattern, output):
            port, protocol, state, service, version = match.groups()

            finding = {
                "type": "service_discovery",
                "port": int(port),
                "protocol": protocol,
                "service": service,
                "version": version.strip() if version else "",
                "severity": "info",
                "description": f"Open port {port}/{protocol} running {service} {version or ''}",
            }

            # Flag risky services
            risky_services = {
                "ftp": "medium", "telnet": "high", "mysql": "medium",
                "mssql": "medium", "rdp": "high", "vnc": "high",
                "smb": "medium", "snmp": "medium", "smtp": "info",
            }
            if service.lower() in risky_services:
                finding["severity"] = risky_services[service.lower()]
                finding["description"] += f" (potentially risky: {service})"

            findings.append(finding)

        # Parse script output for vulnerabilities
        script_pattern = r'\|_(.+?):\s*(.+)'
        for match in re.finditer(script_pattern, output):
            script_name, result = match.groups()
            if any(v in result.lower() for v in ["vuln", "vulnerable", "exploit", "cve"]):
                findings.append({
                    "type": "nmap_script_finding",
                    "script": script_name,
                    "result": result,
                    "severity": "medium",
                    "description": f"Nmap script {script_name}: {result}",
                })

        return findings

    # ─── SQLMap ────────────────────────────────────────────────────

    async def run_sqlmap(self, url: str, param: str = "", level: int = 1, risk: int = 1) -> ToolResult:
        """Run sqlmap and parse results."""
        args = ["-u", url, "--level", str(level), "--risk", str(risk), "--batch", "--output-dir=/tmp/sqlmap"]

        if param:
            args.extend(["-p", param])

        if self.use_docker and self._docker_isolator:
            result = await self._docker_isolator.run_sqlmap(url, param, level, risk)
        else:
            result = await self._run_local("sqlmap", args)

        parsed = self._parse_sqlmap_output(result.get("output", ""))

        return ToolResult(
            tool="sqlmap",
            success=result.get("success", False),
            raw_output=result.get("output", ""),
            parsed_findings=parsed,
            duration=result.get("duration", 0),
            errors=result.get("errors", ""),
        )

    def _parse_sqlmap_output(self, output: str) -> List[Dict]:
        """Parse sqlmap output into findings."""
        findings = []

        # Check for injection points
        if "is vulnerable" in output.lower() or "injectable" in output.lower():
            # Extract injection type
            type_pattern = r'Type:\s*(.+)'
            types = re.findall(type_pattern, output)

            param_pattern = r'Parameter:\s*(\w+)'
            params = re.findall(param_pattern, output)

            payload_pattern = r'Payload:\s*(.+)'
            payloads = re.findall(payload_pattern, output)

            for i, inj_type in enumerate(types):
                findings.append({
                    "type": "sqli",
                    "injection_type": inj_type.strip(),
                    "parameter": params[i] if i < len(params) else "unknown",
                    "payload": payloads[i] if i < len(payloads) else "",
                    "severity": "critical",
                    "confidence": 0.95,
                    "description": f"SQL injection: {inj_type.strip()}",
                    "evidence": output[:500],
                })

        # Check for databases
        db_pattern = r'databases?\s*\[(\d+)\]:\s*\[(.+?)\]'
        for match in re.finditer(db_pattern, output):
            count, databases = match.groups()
            findings.append({
                "type": "database_enumeration",
                "databases": databases.split(", "),
                "severity": "high",
                "description": f"Enumerated {count} databases: {databases}",
            })

        # Check for table dumps
        if "table" in output.lower() and "entries" in output.lower():
            findings.append({
                "type": "data_extraction",
                "severity": "critical",
                "description": "SQLMap extracted table data",
                "evidence": output[:1000],
            })

        return findings

    # ─── Nuclei ────────────────────────────────────────────────────

    async def run_nuclei(self, url: str, templates: str = "", severity: str = "") -> ToolResult:
        """Run nuclei and parse results."""
        args = ["-u", url, "-json", "-silent"]

        if templates:
            args.extend(["-t", templates])
        if severity:
            args.extend(["-severity", severity])

        if self.use_docker and self._docker_isolator:
            result = await self._docker_isolator.run_nuclei(url, templates, severity)
        else:
            result = await self._run_local("nuclei", args)

        parsed = self._parse_nuclei_output(result.get("output", ""))

        return ToolResult(
            tool="nuclei",
            success=result.get("success", False),
            raw_output=result.get("output", ""),
            parsed_findings=parsed,
            duration=result.get("duration", 0),
            errors=result.get("errors", ""),
        )

    def _parse_nuclei_output(self, output: str) -> List[Dict]:
        """Parse nuclei JSON output into findings."""
        findings = []

        for line in output.strip().split("\n"):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
                findings.append({
                    "type": item.get("type", "nuclei_finding"),
                    "template": item.get("template-id", ""),
                    "severity": item.get("info", {}).get("severity", "info"),
                    "url": item.get("matched-at", ""),
                    "description": item.get("info", {}).get("name", ""),
                    "matcher_name": item.get("matcher-name", ""),
                    "curl_command": item.get("curl-command", ""),
                    "extracted_results": item.get("extracted-results", []),
                    "evidence": item.get("matcher-name", ""),
                })
            except json.JSONDecodeError:
                # Non-JSON line, might be text output
                if "[critical]" in line.lower() or "[high]" in line.lower():
                    findings.append({
                        "type": "nuclei_text_finding",
                        "severity": "high" if "[high]" in line.lower() else "critical",
                        "description": line.strip(),
                    })

        return findings

    # ─── FFUF ──────────────────────────────────────────────────────

    async def run_ffuf(self, url: str, wordlist: str = "", extensions: str = "") -> ToolResult:
        """Run ffuf directory fuzzer."""
        args = ["-u", url + "/FUZZ", "-o", "/dev/stdout", "-json", "-mc", "200,201,301,302,403"]

        if wordlist:
            args.extend(["-w", wordlist])
        else:
            args.extend(["-w", "/usr/share/wordlists/dirb/common.txt"])

        if extensions:
            args.extend(["-e", extensions])

        if self.use_docker and self._docker_isolator:
            result = await self._docker_isolator.run_ffuf(url, wordlist, extensions)
        else:
            result = await self._run_local("ffuf", args)

        parsed = self._parse_ffuf_output(result.get("output", ""))

        return ToolResult(
            tool="ffuf",
            success=result.get("success", False),
            raw_output=result.get("output", ""),
            parsed_findings=parsed,
            duration=result.get("duration", 0),
            errors=result.get("errors", ""),
        )

    def _parse_ffuf_output(self, output: str) -> List[Dict]:
        """Parse ffuf JSON output."""
        findings = []

        for line in output.strip().split("\n"):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
                if item.get("status") in (200, 201, 301, 302, 403):
                    findings.append({
                        "type": "directory_discovery",
                        "url": item.get("url", ""),
                        "status": item.get("status"),
                        "size": item.get("length", 0),
                        "words": item.get("words", 0),
                        "severity": "info",
                        "description": f"Discovered: {item.get('input', {}).get('FUZZ', '')} (HTTP {item.get('status')})",
                    })
            except json.JSONDecodeError:
                continue

        return findings

    # ─── Subfinder ─────────────────────────────────────────────────

    async def run_subfinder(self, domain: str) -> ToolResult:
        """Run subfinder for subdomain enumeration."""
        args = ["-d", domain, "-silent"]

        if self.use_docker and self._docker_isolator:
            result = await self._docker_isolator.run_subfinder(domain)
        else:
            result = await self._run_local("subfinder", args)

        subdomains = [
            line.strip()
            for line in result.get("output", "").split("\n")
            if line.strip() and not line.startswith("[")
        ]

        parsed = [
            {"type": "subdomain", "subdomain": sub, "severity": "info"}
            for sub in subdomains
        ]

        return ToolResult(
            tool="subfinder",
            success=result.get("success", False),
            raw_output=result.get("output", ""),
            parsed_findings=parsed,
            duration=result.get("duration", 0),
            errors=result.get("errors", ""),
        )

    # ─── HTTPX ─────────────────────────────────────────────────────

    async def run_httpx(self, targets: List[str]) -> ToolResult:
        """Run httpx for live host detection."""
        args = ["-json", "-silent", "-status-code", "-title", "-tech-detect"]

        if self.use_docker and self._docker_isolator:
            # Write targets to temp file
            import tempfile
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
                f.write("\n".join(targets))
                tmpfile = f.name
            result = await self._docker_isolator.run_httpx(tmpfile)
        else:
            input_data = "\n".join(targets).encode()
            proc = await asyncio.create_subprocess_exec(
                "httpx", *args,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(input=input_data), timeout=120)
            result = {
                "success": proc.returncode == 0,
                "output": stdout.decode(errors="ignore"),
                "errors": stderr.decode(errors="ignore"),
                "duration": 0,
            }

        parsed = self._parse_httpx_output(result.get("output", ""))

        return ToolResult(
            tool="httpx",
            success=result.get("success", False),
            raw_output=result.get("output", ""),
            parsed_findings=parsed,
            duration=result.get("duration", 0),
            errors=result.get("errors", ""),
        )

    def _parse_httpx_output(self, output: str) -> List[Dict]:
        """Parse httpx JSON output."""
        findings = []
        for line in output.strip().split("\n"):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
                findings.append({
                    "type": "live_host",
                    "url": item.get("url", ""),
                    "status_code": item.get("status_code", 0),
                    "title": item.get("title", ""),
                    "tech": item.get("tech", []),
                    "severity": "info",
                    "description": f"Live host: {item.get('url', '')} (HTTP {item.get('status_code', 0)})",
                })
            except json.JSONDecodeError:
                continue
        return findings

    # ─── Generic Local Runner ──────────────────────────────────────

    async def _run_local(self, tool: str, args: List[str], timeout: int = 300) -> Dict:
        """Run tool locally."""
        cmd = [tool] + args
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return {
                "success": proc.returncode == 0,
                "output": stdout.decode(errors="ignore"),
                "errors": stderr.decode(errors="ignore"),
                "duration": 0,
            }
        except asyncio.TimeoutError:
            return {"success": False, "output": "", "errors": f"Timeout after {timeout}s", "duration": timeout}
        except FileNotFoundError:
            return {"success": False, "output": "", "errors": f"Tool '{tool}' not found", "duration": 0}
        except Exception as e:
            return {"success": False, "output": "", "errors": str(e), "duration": 0}

    # ─── Multi-Tool Orchestration ──────────────────────────────────

    async def full_scan(self, target: str, urls: List[str] = None) -> Dict[str, ToolResult]:
        """Run a full scan with multiple tools."""
        results = {}

        # Phase 1: Recon
        results["subfinder"] = await self.run_subfinder(target)
        results["nmap"] = await self.run_nmap(target)

        # Phase 2: Live host detection
        subdomains = [
            f.get("subdomain", "")
            for f in results["subfinder"].parsed_findings
            if f.get("subdomain")
        ]
        if subdomains:
            results["httpx"] = await self.run_httpx(subdomains[:20])

        # Phase 3: Web scanning
        live_urls = urls or [f"https://{target}"]
        for url in live_urls[:5]:
            results[f"nuclei_{url}"] = await self.run_nuclei(url)
            results[f"ffuf_{url}"] = await self.run_ffuf(url)

        return results
