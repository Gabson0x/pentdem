"""
Autonomous Pentest Agent — AI-driven security testing with tool orchestration.

The agent:
1. Receives a target
2. Plans which tools to use based on target characteristics
3. Executes tools and parses outputs
4. Analyzes results with LLM to identify vulnerabilities
5. Learns from each tool's output to refine next steps
6. Chains findings across tools for full attack paths

This is the main orchestrator that ties all tools together.
"""

import asyncio
import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

from tools import ToolExecutor
from tools.catalog import TOOLS_CATALOG, ToolCategory, get_tools_by_category, get_tool


class AgentPhase(Enum):
    RECON = "recon"
    SCAN = "scan"
    FUZZ = "fuzz"
    EXPLOIT = "exploit"
    CHAIN = "chain"
    REPORT = "report"


@dataclass
class AgentState:
    """Tracks the agent's current state and learned knowledge."""
    target: str
    phase: AgentPhase = AgentPhase.RECON
    subdomains: List[str] = field(default_factory=list)
    live_hosts: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    findings: List[Dict] = field(default_factory=list)
    tool_outputs: Dict[str, str] = field(default_factory=dict)
    learned_patterns: List[str] = field(default_factory=list)
    waf_detected: Optional[str] = None
    retry_count: int = 0
    max_retries: int = 3


class AutonomousAgent:
    """
    AI-driven pentest agent that uses tools and learns from outputs.

    Workflow:
    1. Recon: subfinder → httpx → katana → nuclei (discovery)
    2. Scan: nuclei → nmap → nikto (vulnerability detection)
    3. Fuzz: ffuf → dirsearch (hidden content)
    4. Exploit: sqlmap → dalfox → tplmap (validation)
    5. Chain: LLM analyzes all findings for attack paths
    6. Report: Generate professional bug bounty reports
    """

    def __init__(self, mock: bool = False, model_client=None):
        self.mock = mock
        self.tools = ToolExecutor(mock=mock)
        self.model = model_client
        self.state: Optional[AgentState] = None
        self._progress_callback = None

    def set_progress_callback(self, callback):
        """Set callback for progress updates."""
        self._progress_callback = callback

    async def _emit(self, phase: str, message: str, progress: float = 0):
        """Emit progress update."""
        if self._progress_callback:
            await self._progress_callback(phase, message, progress)

    # ═══════════════════════════════════════════════════════════════
    # MAIN EXECUTION LOOP
    # ═══════════════════════════════════════════════════════════════

    async def run(self, target: str) -> Dict[str, Any]:
        """
        Run the full autonomous pentest workflow.

        Returns comprehensive results with findings, chains, and evidence.
        """
        self.state = AgentState(target=target)
        results = {
            "target": target,
            "phases": {},
            "findings": [],
            "chains": [],
            "tool_outputs": {},
            "summary": {},
        }

        # Phase 1: Reconnaissance
        await self._emit("recon", f"Starting reconnaissance on {target}", 0.1)
        recon_results = await self._phase_recon(target)
        results["phases"]["recon"] = recon_results
        results["tool_outputs"].update(self.state.tool_outputs)

        # Phase 2: Vulnerability Scanning
        await self._emit("scan", "Running vulnerability scans", 0.3)
        scan_results = await self._phase_scan(target)
        results["phases"]["scan"] = scan_results
        results["tool_outputs"].update(self.state.tool_outputs)

        # Phase 3: Directory/API Fuzzing
        await self._emit("fuzz", "Fuzzing for hidden content", 0.5)
        fuzz_results = await self._phase_fuzz(target)
        results["phases"]["fuzz"] = fuzz_results
        results["tool_outputs"].update(self.state.tool_outputs)

        # Phase 4: Exploitation
        await self._emit("exploit", "Validating vulnerabilities", 0.7)
        exploit_results = await self._phase_exploit(target)
        results["phases"]["exploit"] = exploit_results
        results["findings"] = self.state.findings

        # Phase 5: Chain Analysis
        await self._emit("chain", "Analyzing attack chains", 0.85)
        chain_results = await self._phase_chain(target)
        results["chains"] = chain_results

        # Phase 6: Report Generation
        await self._emit("report", "Generating report", 0.95)
        results["summary"] = self._generate_summary(results)

        return results

    # ═══════════════════════════════════════════════════════════════
    # PHASE 1: RECONNAISSANCE
    # ═══════════════════════════════════════════════════════════════

    async def _phase_recon(self, target: str) -> Dict:
        """Reconnaissance: subdomain enum, live hosts, URL discovery."""
        recon_tools = get_tools_by_category(ToolCategory.RECON)
        results = {"subdomains": [], "live_hosts": [], "urls": [], "technologies": []}

        # Step 1: Subdomain enumeration (parallel)
        await self._emit("recon", "Enumerating subdomains...", 0.15)
        subfinder_result = await self.tools.run("subfinder", ["-d", target, "-silent"])
        if subfinder_result["success"]:
            subs = [s.strip() for s in subfinder_result["stdout"].strip().split("\n") if s.strip()]
            results["subdomains"] = subs
            self.state.subdomains = subs
            self.state.tool_outputs["subfinder"] = subfinder_result["stdout"]
            await self._emit("recon", f"Found {len(subs)} subdomains", 0.2)

        # Step 2: Live host detection
        if results["subdomains"]:
            await self._emit("recon", "Checking live hosts...", 0.25)
            # Write subdomains to temp file
            subs_file = f"/tmp/{target}_subs.txt"
            with open(subs_file, "w") as f:
                f.write("\n".join(results["subdomains"]))

            httpx_result = await self.tools.run("httpx", [
                "-l", subs_file, "-silent", "-status-code", "-title", "-tech-detect", "-json"
            ])
            if httpx_result["success"]:
                live_hosts = []
                technologies = []
                for line in httpx_result["stdout"].strip().split("\n"):
                    if not line.strip():
                        continue
                    try:
                        import json
                        entry = json.loads(line)
                        url = entry.get("url", entry.get("host", ""))
                        if url:
                            live_hosts.append(url)
                        tech = entry.get("tech", [])
                        if tech:
                            technologies.extend(tech)
                    except Exception:
                        # Fallback: text parsing
                        parts = line.split()
                        if parts:
                            live_hosts.append(parts[0])
                results["live_hosts"] = live_hosts
                results["technologies"] = technologies
                self.state.live_hosts = live_hosts
                self.state.technologies = technologies
                self.state.tool_outputs["httpx"] = httpx_result["stdout"]
                await self._emit("recon", f"Found {len(live_hosts)} live hosts", 0.3)

        # Step 3: URL discovery (parallel)
        await self._emit("recon", "Discovering URLs...", 0.35)
        katana_result = await self.tools.run("katana", [
            "-u", f"https://{target}", "-d", "3", "-silent", "-jc", "-kf",
            "-timeout", "10",
        ], timeout=20)
        if katana_result["success"]:
            urls = [u.strip() for u in katana_result["stdout"].strip().split("\n") if u.strip()]
            results["urls"] = urls
            self.state.urls = urls
            self.state.tool_outputs["katana"] = katana_result["stdout"]

        # Step 4: LLM analysis of recon data (with timeout)
        if self.model and results:
            await self._emit("recon", "Analyzing recon data with AI...", 0.4)
            try:
                analysis = await asyncio.wait_for(self._llm_analyze_recon(results), timeout=15)
            except asyncio.TimeoutError:
                analysis = {"recommendations": [], "interesting_findings": []}
            results["ai_analysis"] = analysis
            if analysis.get("interesting_findings"):
                self.state.learned_patterns.extend(analysis["interesting_findings"])

        return results

    # ═══════════════════════════════════════════════════════════════
    # PHASE 2: VULNERABILITY SCANNING
    # ═══════════════════════════════════════════════════════════════

    async def _phase_scan(self, target: str) -> Dict:
        """Vulnerability scanning with Nuclei, Nmap, Nikto."""
        results = {"nuclei": [], "nmap": [], "nikto": []}

        # Mock mode: return mock findings directly
        if self.mock:
            mock_nuclei = [
                {"template-id": "spring-actuator", "info": {"name": "Spring Actuator", "severity": "critical"}, "matched-at": f"https://{target}/actuator"},
                {"template-id": "cors-misconfig", "info": {"name": "CORS Misconfiguration", "severity": "high"}, "matched-at": f"https://{target}/api/v1/users"},
                {"template-id": "debug-mode", "info": {"name": "Debug Mode Enabled", "severity": "medium"}, "matched-at": f"https://{target}/debug"},
            ]
            results["nuclei"] = mock_nuclei
            for finding in mock_nuclei:
                self.state.findings.append({
                    "type": "nuclei",
                    "template": finding.get("template-id", ""),
                    "severity": finding.get("info", {}).get("severity", "info"),
                    "url": finding.get("matched-at", ""),
                    "name": finding.get("info", {}).get("name", ""),
                })
            return results

        # Step 1: Nuclei scan (most important)
        await self._emit("scan", "Running Nuclei templates...", 0.4)
        nuclei_input = f"/tmp/{target}_live.txt"
        with open(nuclei_input, "w") as f:
            f.write("\n".join(self.state.live_hosts or [target]))

        nuclei_result = await self.tools.run("nuclei", [
            "-l", nuclei_input,
            "-severity", "critical,high,medium",
            "-json",
        ])
        if nuclei_result["success"]:
            self.state.tool_outputs["nuclei"] = nuclei_result["stdout"]
            # Parse nuclei JSON output
            for line in nuclei_result["stdout"].strip().split("\n"):
                if line.strip():
                    try:
                        finding = json.loads(line)
                        results["nuclei"].append(finding)
                        # Add to state findings
                        self.state.findings.append({
                            "type": "nuclei",
                            "template": finding.get("template-id", ""),
                            "severity": finding.get("info", {}).get("severity", "info"),
                            "url": finding.get("matched-at", ""),
                            "name": finding.get("info", {}).get("name", ""),
                            "description": finding.get("info", {}).get("description", ""),
                        })
                    except json.JSONDecodeError:
                        pass
            await self._emit("scan", f"Nuclei found {len(results['nuclei'])} issues", 0.5)

        # Step 2: Nmap scan
        await self._emit("scan", "Running Nmap scan...", 0.55)
        nmap_result = await self.tools.run("nmap", [
            "-sV", "-sC", "-oX", f"/tmp/{target}_nmap.xml", target
        ])
        if nmap_result["success"]:
            self.state.tool_outputs["nmap"] = nmap_result["stdout"]
            # Parse nmap output for open ports
            for line in nmap_result["stdout"].split("\n"):
                if "/tcp" in line and "open" in line:
                    results["nmap"].append({"port_info": line.strip()})

        # Step 3: LLM analysis of scan results
        if self.model and results:
            await self._emit("scan", "Analyzing scan results with AI...", 0.6)
            analysis = await self._llm_analyze_scan(results)
            results["ai_analysis"] = analysis

        return results

    # ═══════════════════════════════════════════════════════════════
    # PHASE 3: DIRECTORY/API FUZZING
    # ═══════════════════════════════════════════════════════════════

    async def _phase_fuzz(self, target: str) -> Dict:
        """Directory and API fuzzing with ffuf."""
        results = {"directories": [], "parameters": []}

        # Step 1: Directory fuzzing
        await self._emit("fuzz", "Fuzzing directories...", 0.6)
        ffuf_result = await self.tools.run("ffuf", [
            "-u", f"https://{target}/FUZZ",
            "-w", "/usr/share/wordlists/dirb/common.txt",
            "-mc", "200,301,302,403",
            "-o", f"/tmp/{target}_ffuf.json",
            "-of", "json",
        ])
        if ffuf_result["success"]:
            self.state.tool_outputs["ffuf"] = ffuf_result["stdout"]
            # Parse ffuf JSON
            try:
                ffuf_data = json.loads(ffuf_result["stdout"])
                results["directories"] = ffuf_data.get("results", [])
            except json.JSONDecodeError:
                pass
            await self._emit("fuzz", f"Found {len(results['directories'])} directories", 0.65)

        # Step 2: Parameter discovery
        await self._emit("fuzz", "Discovering hidden parameters...", 0.7)
        # Use arjun for parameter discovery
        arjun_result = await self.tools.run("python3", [
            "-m", "arjun",
            "-u", f"https://{target}",
            "-oJ", f"/tmp/{target}_params.json",
        ])
        if arjun_result["success"]:
            self.state.tool_outputs["arjun"] = arjun_result["stdout"]
            try:
                params_data = json.loads(arjun_result["stdout"])
                results["parameters"] = params_data.get("parameters", [])
            except (json.JSONDecodeError, KeyError):
                pass

        # Step 3: LLM analysis of fuzz results
        if self.model and results:
            await self._emit("fuzz", "Analyzing fuzz results with AI...", 0.75)
            analysis = await self._llm_analyze_fuzz(results)
            results["ai_analysis"] = analysis

        return results

    # ═══════════════════════════════════════════════════════════════
    # PHASE 4: EXPLOITATION
    # ═══════════════════════════════════════════════════════════════

    async def _phase_exploit(self, target: str) -> Dict:
        """Exploit and validate vulnerabilities."""
        results = {"sql_injection": [], "xss": [], "ssti": [], "command_injection": []}

        # Mock mode: return mock findings directly
        if self.mock:
            mock_findings = [
                {"type": "sql_injection", "url": f"https://{target}/v1/users?id=1", "severity": "critical", "evidence": "SQL injection confirmed via error-based technique", "confidence": 0.9, "cvss_score": 9.8},
                {"type": "xss", "url": f"https://{target}/search?q=test", "severity": "high", "evidence": "Reflected XSS in search parameter", "confidence": 0.85, "cvss_score": 6.1},
                {"type": "ssti", "url": f"https://{target}/page?name=test", "severity": "critical", "evidence": "SSTI confirmed - math expression evaluated", "confidence": 0.9, "cvss_score": 9.8},
            ]
            for f in mock_findings:
                self.state.findings.append(f)
            results["sql_injection"] = [f for f in mock_findings if f["type"] == "sql_injection"]
            results["xss"] = [f for f in mock_findings if f["type"] == "xss"]
            results["ssti"] = [f for f in mock_findings if f["type"] == "ssti"]
            return results

        # Step 1: SQL Injection testing
        if self.state.urls:
            await self._emit("exploit", "Testing for SQL injection...", 0.75)
            # Find URLs with parameters
            param_urls = [u for u in self.state.urls if "?" in u]
            for url in param_urls[:5]:  # Test top 5
                sqli_result = await self.tools.run("python3", [
                    "-m", "sqlmap",
                    "-u", url,
                    "--batch",
                    "--level", "2",
                    "--risk", "1",
                ])
                if sqli_result["success"] and "injection" in sqli_result["stdout"].lower():
                    from urllib.parse import urlparse, parse_qs
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query)
                    param_name = list(params.keys())[0] if params else "id"
                    results["sql_injection"].append({
                        "url": url,
                        "evidence": sqli_result["stdout"][:500],
                    })
                    self.state.findings.append({
                        "type": "sql_injection",
                        "vuln_class": "sqli",
                        "url": url,
                        "param": param_name,
                        "payload": "' OR '1'='1",
                        "severity": "critical",
                        "confidence": 0.8,
                        "evidence": sqli_result["stdout"][:200],
                        "http_request": f"GET {parsed.path}?{parsed.query} HTTP/1.1\nHost: {parsed.netloc}",
                        "http_response": sqli_result["stdout"][:1000],
                        "reproduction_steps": f"Send SQLi payload to {url} parameter {param_name}",
                    })

        # Step 2: XSS testing
        await self._emit("exploit", "Testing for XSS...", 0.8)
        for url in (self.state.urls or [])[:5]:
            xss_result = await self.tools.run("dalfox", ["url", url, "--silence"])
            if xss_result["success"] and "xss" in xss_result["stdout"].lower():
                from urllib.parse import urlparse, parse_qs
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                param_name = list(params.keys())[0] if params else "q"
                results["xss"].append({
                    "url": url,
                    "evidence": xss_result["stdout"][:500],
                })
                self.state.findings.append({
                    "type": "xss",
                    "vuln_class": "xss",
                    "url": url,
                    "param": param_name,
                    "payload": "<script>alert(1)</script>",
                    "severity": "medium",
                    "confidence": 0.7,
                    "evidence": xss_result["stdout"][:200],
                    "http_request": f"GET {parsed.path}?{parsed.query} HTTP/1.1\nHost: {parsed.netloc}",
                    "http_response": xss_result["stdout"][:1000],
                    "reproduction_steps": f"Send XSS payload to {url} parameter {param_name}",
                })

        # Step 3: SSTI testing (using WAF bypass engine)
        await self._emit("exploit", "Testing for SSTI...", 0.82)
        from skills.waf_bypass import WAFBypassEngine, BypassVerdict

        async def request_fn(url, method="GET", headers=None):
            result = await self.tools.run("curl", ["-s", "-L", url])
            return {
                "status": 200 if result["success"] else 0,
                "headers": {},
                "body": result.get("stdout", ""),
            }

        ssti_engine = WAFBypassEngine(request_fn)
        for url in (self.state.urls or [])[:5]:
            verdict = await ssti_engine.attempt_bypass_with_llm(url, "test", "{{7*7}}")
            if verdict.verdict == BypassVerdict.CONFIRMED:
                from urllib.parse import urlparse, parse_qs
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                param_name = list(params.keys())[0] if params else "test"
                results["ssti"].append({
                    "url": url,
                    "verdict": verdict.verdict.value,
                    "proof": verdict.evaluation_proof,
                    "technique": verdict.technique_used,
                })
                self.state.findings.append({
                    "type": "ssti",
                    "vuln_class": "ssti",
                    "url": url,
                    "param": param_name,
                    "payload": "{{7*7}}",
                    "severity": "critical",
                    "confidence": 0.9,
                    "evidence": verdict.evidence,
                    "evaluation_proof": verdict.evaluation_proof,
                    "http_request": f"GET {parsed.path}?{parsed.query}={{7*7}} HTTP/1.1\nHost: {parsed.netloc}",
                    "http_response": verdict.evidence[:1000] if verdict.evidence else "",
                    "reproduction_steps": f"Send SSTI payload {{{{7*7}}}} to {url} parameter {param_name}",
                })

        # Step 4: LLM analysis of exploit results
        if self.model and results:
            await self._emit("exploit", "Analyzing exploit results with AI...", 0.85)
            analysis = await self._llm_analyze_exploit(results)
            results["ai_analysis"] = analysis

        return results

    # ═══════════════════════════════════════════════════════════════
    # PHASE 5: CHAIN ANALYSIS
    # ═══════════════════════════════════════════════════════════════

    async def _phase_chain(self, target: str) -> List[Dict]:
        """Analyze findings for attack chains."""
        if not self.model or not self.state.findings:
            return []

        prompt = f"""Analyze these security findings for {target} and identify attack chains.

FINDINGS:
{json.dumps(self.state.findings[:20], indent=2)}

LEARNED PATTERNS:
{json.dumps(self.state.learned_patterns[:10], indent=2)}

TASK:
1. Identify multi-step attack chains (e.g., open redirect → XSS → session hijack)
2. Score each chain: reachability, reliability, stealth, speed, impact (0-20 each)
3. Only include chains with total score > 60

Return JSON array of chains:
[
  {{
    "chain_name": "Name",
    "steps": ["step1", "step2"],
    "total_score": 75,
    "scores": {{"reach": 18, "reliability": 15, "stealth": 12, "speed": 15, "impact": 15}},
    "impact": "Description of full impact"
  }}
]"""

        try:
            response = await self.model.generate(prompt, model="glm")
            json_match = response.find("[")
            if json_match >= 0:
                chains = json.loads(response[json_match:])
                return chains[:5]  # Top 5 chains
        except Exception:
            pass

        return []

    # ═══════════════════════════════════════════════════════════════
    # LLM ANALYSIS METHODS
    # ═══════════════════════════════════════════════════════════════

    async def _llm_analyze_recon(self, recon_data: dict) -> dict:
        """Use LLM to analyze reconnaissance data."""
        if not self.model:
            return {}

        prompt = f"""Analyze this reconnaissance data for security testing:

Subdomains ({len(recon_data.get('subdomains', []))}):
{json.dumps(recon_data.get('subdomains', [])[:10])}

Live hosts ({len(recon_data.get('live_hosts', []))}):
{json.dumps(recon_data.get('live_hosts', [])[:10])}

Technologies:
{json.dumps(recon_data.get('technologies', [])[:5])}

URLs ({len(recon_data.get('urls', []))}):
{json.dumps(recon_data.get('urls', [])[:10])}

TASK:
1. Identify interesting endpoints for security testing
2. Identify potential technology-specific vulnerabilities
3. Suggest which tools to run next
4. Estimate attack surface size

Return JSON:
{{
  "interesting_findings": ["finding1", "finding2"],
  "tech_vulnerabilities": ["vuln1", "vuln2"],
  "recommended_tools": ["tool1", "tool2"],
  "attack_surface": "small|medium|large"
}}"""

        try:
            response = await self.model.generate(prompt, model="glm")
            json_match = response.find("{")
            if json_match >= 0:
                return json.loads(response[json_match:])
        except Exception:
            pass
        return {}

    async def _llm_analyze_scan(self, scan_data: dict) -> dict:
        """Use LLM to analyze vulnerability scan results."""
        if not self.model:
            return {}

        prompt = f"""Analyze these vulnerability scan results:

Nuclei findings ({len(scan_data.get('nuclei', []))}):
{json.dumps(scan_data.get('nuclei', [])[:5], indent=2)}

Nmap results:
{json.dumps(scan_data.get('nmap', [])[:5], indent=2)}

TASK:
1. Prioritize findings by exploitability
2. Identify false positives
3. Suggest exploitation approach for each finding
4. Identify any patterns across findings

Return JSON:
{{
  "prioritized_findings": ["finding1", "finding2"],
  "false_positives": ["fp1"],
  "exploitation_approaches": {{"finding1": "approach"}},
  "patterns": ["pattern1"]
}}"""

        try:
            response = await self.model.generate(prompt, model="glm")
            json_match = response.find("{")
            if json_match >= 0:
                return json.loads(response[json_match:])
        except Exception:
            pass
        return {}

    async def _llm_analyze_fuzz(self, fuzz_data: dict) -> dict:
        """Use LLM to analyze fuzzing results."""
        if not self.model:
            return {}

        prompt = f"""Analyze these fuzzing results:

Directories found ({len(fuzz_data.get('directories', []))}):
{json.dumps(fuzz_data.get('directories', [])[:10])}

Parameters found ({len(fuzz_data.get('parameters', []))}):
{json.dumps(fuzz_data.get('parameters', [])[:10])}

TASK:
1. Identify hidden admin panels or sensitive endpoints
2. Identify parameters worth testing for injection
3. Identify API endpoints
4. Suggest next steps

Return JSON:
{{
  "admin_panels": ["/admin", "/dashboard"],
  "injection_params": ["param1", "param2"],
  "api_endpoints": ["/api/v1/users"],
  "next_steps": ["step1", "step2"]
}}"""

        try:
            response = await self.model.generate(prompt, model="glm")
            json_match = response.find("{")
            if json_match >= 0:
                return json.loads(response[json_match:])
        except Exception:
            pass
        return {}

    async def _llm_analyze_exploit(self, exploit_data: dict) -> dict:
        """Use LLM to analyze exploitation results."""
        if not self.model:
            return {}

        prompt = f"""Analyze these exploitation results:

SQL Injection ({len(exploit_data.get('sql_injection', []))}):
{json.dumps(exploit_data.get('sql_injection', [])[:3])}

XSS ({len(exploit_data.get('xss', []))}):
{json.dumps(exploit_data.get('xss', [])[:3])}

SSTI ({len(exploit_data.get('ssti', []))}):
{json.dumps(exploit_data.get('ssti', [])[:3])}

TASK:
1. Validate each finding (true positive vs false positive)
2. Assess actual impact
3. Generate proof of concept for each
4. Suggest remediation

Return JSON:
{{
  "validated_findings": [{{"type": "sqli", "url": "...", "impact": "...", "poc": "..."}}],
  "false_positives": [{{"type": "xss", "url": "...", "reason": "..."}}],
  "remediation": {{"sqli": "Use parameterized queries"}}
}}"""

        try:
            response = await self.model.generate(prompt, model="glm")
            json_match = response.find("{")
            if json_match >= 0:
                return json.loads(response[json_match:])
        except Exception:
            pass
        return {}

    # ═══════════════════════════════════════════════════════════════
    # SUMMARY GENERATION
    # ═══════════════════════════════════════════════════════════════

    def _generate_summary(self, results: dict) -> dict:
        """Generate summary of all results."""
        all_findings = results.get("findings", [])
        chains = results.get("chains", [])

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in all_findings:
            sev = f.get("severity", "info").lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return {
            "total_findings": len(all_findings),
            "severity_counts": severity_counts,
            "total_chains": len(chains),
            "tools_used": list(results.get("tool_outputs", {}).keys()),
            "phases_completed": list(results.get("phases", {}).keys()),
        }


# ═══════════════════════════════════════════════════════════════════
# CLI ENTRY POINT
# ═══════════════════════════════════════════════════════════════════

async def main():
    """Run the agent from CLI."""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m agents.autonomous <target> [--mock]")
        sys.exit(1)

    target = sys.argv[1]
    mock = "--mock" in sys.argv

    print(f"[*] Target: {target}")
    print(f"[*] Mock mode: {mock}")

    agent = AutonomousAgent(mock=mock)

    async def progress(phase, message, progress):
        bar_len = 40
        filled = int(bar_len * progress)
        bar = "=" * filled + "-" * (bar_len - filled)
        print(f"\r[{bar}] {progress*100:.0f}% - {phase}: {message}", end="", flush=True)

    agent.set_progress_callback(progress)
    results = await agent.run(target)

    print("\n\n[+] Results:")
    print(json.dumps(results["summary"], indent=2))

    if results["findings"]:
        print(f"\n[+] Findings ({len(results['findings'])}):")
        for f in results["findings"][:10]:
            print(f"  - [{f.get('severity', '?').upper()}] {f.get('type', '?')} @ {f.get('url', '?')}")

    if results["chains"]:
        print(f"\n[+] Attack Chains ({len(results['chains'])}):")
        for c in results["chains"][:5]:
            print(f"  - {c.get('chain_name', '?')} (Score: {c.get('total_score', 0)})")


if __name__ == "__main__":
    asyncio.run(main())
