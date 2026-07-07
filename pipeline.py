"""
Swarm Orchestrator - Parallel agent deployment for autonomous pentesting.

Delegates to specialist agents, coordinates handoffs, tracks progress.
Inspired by the Bug-Bounty-Agents swarm-orchestrator pattern.

v4.0: Merged AutonomousAgent as primary execution engine.
     Reports stored in per-target folders (reports/{domain}/).
"""

import asyncio
import json
import os
import time
from enum import Enum
from pathlib import Path
from typing import Dict, Any, List, Optional

from models_data import (
    SourceType, EngagementType, AgentPhase, RiskTier, OPSECLevel,
    Finding, AttackChain, AgentStatus, EngagementState,
)
from skills.scope_guard import ScopeGuard, ScopeDeclaration, OPSECLevel as ScopeOPSEC
from skills.evidence import EvidenceHandler
from skills.mitre_mapper import MITREMapper
from skills.osint_collector import OSINTCollector, RawToolFinding
from skills.threat_analyzer import ThreatAnalyzer
from skills.report_writer import ReportWriter
from skills.screenshot import ScreenshotCapture
from skills.recon import ReconSkill
from skills.hunt import HuntSkill
from skills.chain import ChainSkill
from skills.knowledge import KnowledgeSkill
from skills.validate import ValidateSkill
from skills.report import ReportSkill
from skills.memory import MemorySkill
from adaptive_engine import AdaptiveEngine
from verifier import Verifier
from concurrent_hunt import ConcurrentHuntRunner
from rate_limiter import RateLimiter
from models import ModelClient
from agents.autonomous import AutonomousAgent
from tools import ToolExecutor


class PentestPipeline:
    """
    Swarm orchestrator with AutonomousAgent as primary execution engine.

    Architecture:
    - AutonomousAgent runs the 6-phase workflow (recon→scan→fuzz→exploit→chain→report)
    - Legacy pipeline skills run in parallel for additional coverage
    - Validation kills false positives before report generation
    - Every finding gets OPSEC tagging, evidence preservation, MITRE ATT&CK mapping
    """

    # 15 vuln classes our agents cover
    ALL_VULN_TYPES = [
        "idor", "ssrf", "xss", "sqli", "auth_bypass", "ssti",
        "open_redirect", "lfi", "command_injection", "nosqli",
        "graphql", "jwt", "deserialization", "path_traversal",
        "race_condition",
    ]

    # Agent registry with phase and risk tier
    AGENT_REGISTRY = {
        "recon-advisor":      {"phase": "recon", "risk": "safe"},
        "web-hunter":         {"phase": "hunting", "risk": "active"},
        "ssrf-hunter":        {"phase": "hunting", "risk": "active"},
        "api-security":       {"phase": "hunting", "risk": "active"},
        "graphql-hunter":     {"phase": "hunting", "risk": "active"},
        "bizlogic-hunter":    {"phase": "hunting", "risk": "active"},
        "poc-validator":      {"phase": "validation", "risk": "active"},
        "exploit-chainer":    {"phase": "chaining", "risk": "active"},
        "report-generator":   {"phase": "reporting", "risk": "safe"},
        "autonomous-agent":   {"phase": "hunting", "risk": "active"},
    }

    def __init__(self, config: Dict = None):
        self.config = config or {}
        mock = self.config.get("mock_mode", False)

        # Infrastructure (scope_guard before skills)
        self.scope_guard: Optional[ScopeGuard] = None
        self.evidence: Optional[EvidenceHandler] = None
        self.mitre = MITREMapper()
        self.osint = OSINTCollector()
        self.threat_analyzer = ThreatAnalyzer()
        self.report_writer = ReportWriter()
        self.screencap = ScreenshotCapture()

        # Tools executor (shared with autonomous agent)
        self.tools = ToolExecutor(mock=mock)

        # Autonomous agent (primary engine)
        try:
            self.model_client = ModelClient()
        except Exception:
            self.model_client = None
        self.agent = AutonomousAgent(mock=mock, model_client=self.model_client)

        self.skills = {
            "learn": KnowledgeSkill(mock=mock),
            "recon": ReconSkill(mock=mock),
            "hunt": HuntSkill(mock=mock, scope_guard=self.scope_guard),
            "chain": ChainSkill(mock=mock),
            "validate": ValidateSkill(mock=mock),
            "report": ReportSkill(mock=mock),
            "memory": MemorySkill(),
        }

        # Shorthand
        self.memory = self.skills["memory"]

        # Model client for adaptive engine
        try:
            self.models = ModelClient()
        except Exception:
            self.models = None

        # State
        self.state = EngagementState(mock=mock)
        self._progress_callbacks = []
        self._agent_statuses: Dict[str, AgentStatus] = {}

    def on_progress(self, callback):
        self._progress_callbacks.append(callback)

    async def _emit_progress(self, stage: str, status: str, progress: float, data: dict = None):
        event = {"stage": stage, "status": status, "progress": progress, "data": data, "timestamp": time.time()}
        for cb in self._progress_callbacks:
            try:
                if asyncio.iscoroutinefunction(cb):
                    await cb(event)
                else:
                    cb(event)
            except Exception:
                pass

    def _update_agent(self, name: str, status: str, progress: float = 0, findings: int = 0, error: str = None):
        if name not in self._agent_statuses:
            self._agent_statuses[name] = AgentStatus(name=name, phase=self.AGENT_REGISTRY.get(name, {}).get("phase", "unknown"))
        agent = self._agent_statuses[name]
        agent.status = status
        agent.progress = progress
        agent.findings_count = findings
        if error:
            agent.error = error

    def _analyze_tool_outputs(self, target: str) -> list:
        """
        Analyze any pre-existing tool output files in the evidence directory.
        Looks for Nuclei, Nmap, Nikto, ffuf output files and parses them.
        """
        import glob
        evidence_dir = Path(f"evidence/{target.replace('/', '_')}")
        if not evidence_dir.exists():
            return []

        all_findings = []
        tool_files = {
            "nuclei": ["*.json", "*.txt", "*.ndjson"],
            "nmap": ["*.xml", "*.txt"],
            "nikto": ["*.txt"],
            "ffuf": ["*.json"],
        }

        for tool_name, extensions in tool_files.items():
            for ext in extensions:
                for filepath in evidence_dir.glob(f"{tool_name}*{ext}"):
                    raw_findings = self.osint.collect_from_file(str(filepath), tool_name, target)
                    all_findings.extend(raw_findings)

        # Also check for any generic output files
        for filepath in evidence_dir.glob("*"):
            if filepath.is_file() and not any(
                filepath.name.startswith(t) for t in tool_files.keys()
            ):
                raw_findings = self.osint.collect_from_file(str(filepath), "unknown", target)
                all_findings.extend(raw_findings)

        return all_findings

    async def _validate_scope(self, target: str) -> bool:
        """Validate target is in scope before any agent execution."""
        decl = ScopeDeclaration(
            domains=[target],
            engagement_type="bug_bounty",
            allow_internal_probing=False,
            allow_cloud_metadata=False,
            rate_limit_rps=50,
        )
        self.scope_guard = ScopeGuard(decl)

        # Update hunt skill with scope guard
        self.skills["hunt"].explorer.scope_guard = self.scope_guard
        self.skills["hunt"].session_bypass.scope_guard = self.scope_guard

        validation = self.scope_guard.validate_target(target, ScopeOPSEC.MODERATE)
        if not validation.in_scope:
            await self._emit_progress("scope", "failed", 0, {"error": validation.reason})
            return False
        return True

    async def _phase_recon(self, target: str, mode: str) -> dict:
        """Phase 1: Reconnaissance — parallel workstreams."""
        await self._emit_progress("recon", "running", 0.05, {
            "message": f"Enumerating subdomains for {target}..."
        })

        # Run recon in parallel (subfinder, httpx, katana all run concurrently inside ReconSkill)
        recon_result = await self.skills["recon"].execute({
            "target": target,
            "mode": mode,
        })

        # Save evidence
        if self.evidence and recon_result.data:
            self.evidence.save_json_evidence(
                "recon-advisor", "recon", target, recon_result.data,
                opsec_level=OPSECLevel.QUIET,
            )

        subdomains = len(recon_result.data.get("subdomains", []))
        live_hosts = len(recon_result.data.get("live_hosts", []))
        urls = len(recon_result.data.get("urls", []))

        await self._emit_progress("recon", "completed", 0.25, {
            "findings": f"{subdomains} subdomains, {live_hosts} live hosts, {urls} URLs",
            "message": f"Found {subdomains} subdomains, {live_hosts} live hosts, {urls} URLs to test"
        })
        return recon_result.data

    async def _phase_learn(self, target: str, tech_hints: str) -> dict:
        """Phase 1.5: Knowledge injection from disclosed reports."""
        await self._emit_progress("learn", "running", 0.26)

        knowledge_tasks = await asyncio.gather(
            self.skills["learn"].execute({
                "action": "query",
                "tech": tech_hints,
                "limit": 5,
            }),
            self.skills["learn"].execute({
                "action": "inject",
                "target": target,
                "vuln_type": ",".join(self.ALL_VULN_TYPES),
                "tech_hints": tech_hints,
            }),
            return_exceptions=True,
        )

        knowledge_data = {"known_patterns": [], "relevant_reports": []}
        for kt in knowledge_tasks:
            if isinstance(kt, Exception):
                continue
            if kt.data.get("reports"):
                knowledge_data["relevant_reports"] = kt.data["reports"]
            if kt.data.get("knowledge"):
                knowledge_data["known_patterns"] = kt.data["knowledge"]

        await self._emit_progress("learn", "completed", 0.28, {
            "patterns": len(knowledge_data["known_patterns"]),
            "reports": len(knowledge_data["relevant_reports"]),
        })
        return knowledge_data

    async def _phase_hunt(
        self,
        target: str,
        mode: str,
        recon_data: dict,
        knowledge_data: dict,
    ) -> List[Finding]:
        """
        Phase 2: Concurrent vulnerability hunting.

        Architecture:
        - 15 vuln classes run in parallel via asyncio.gather
        - Shared RateLimiter (token bucket) caps total requests/sec
        - URL scoring per class (no LLM) selects top 5 URLs
        - Fast-fail 4s timeout with single retry
        - Verification loops confirm findings before counting
        """
        all_urls = recon_data.get("urls", [])
        tech_stack = recon_data.get("analysis", {}).get("tech_stack", [])
        tech_key = tech_stack[0] if tech_stack else "generic"

        # ── Step 1: Select vuln classes based on mode ──
        vuln_types = self.ALL_VULN_TYPES.copy()
        if mode == "quick":
            vuln_types = vuln_types[:6]
        elif mode == "targeted":
            vuln_types = ["idor", "ssrf", "xss", "sqli"]

        # ── Step 2: Load strategy memory to reorder classes ──
        historical_order = await self.memory.get_adaptive_vuln_order(tech_key)
        if historical_order:
            ordered = [v for v in historical_order if v in vuln_types]
            remaining = [v for v in vuln_types if v not in ordered]
            vuln_types = ordered + remaining

        await self._emit_progress("hunt", "running", 0.30, {
            "message": f"Testing {len(vuln_types)} vuln classes across {len(all_urls)} URLs..."
        })

        # ── Step 3: Run all classes concurrently ──
        tools = self.skills["hunt"].tools
        runner = ConcurrentHuntRunner(tools=tools, mock=self.config.get("mock_mode", False))

        all_findings = await runner.run_all_classes(
            urls=all_urls,
            target=target,
            vuln_classes=vuln_types,
            knowledge=knowledge_data.get("known_patterns", []),
            tech_hints=", ".join(tech_stack),
        )

        await self._emit_progress("hunt", "running", 0.45, {
            "message": f"Found {len(all_findings)} potential findings, verifying with canary tests..."
        })

        # ── Step 4: Map MITRE ATT&CK ──
        for f in all_findings:
            f = self.mitre.map_finding(f)
            f["source"] = "concurrent-hunt"
            f["noise_level"] = "active"

        # ── Step 5: Verify findings with confirmation loops ──
        verifier = Verifier(tools=tools)
        verified_findings = await verifier.verify_batch(all_findings)

        # Filter to verified/likely_verified only
        confirmed_findings = [
            f for f in verified_findings
            if f.get("verification", {}).get("status") in ("verified", "likely_verified")
        ]

        # ── Step 6: Record strategy success for cross-run learning ──
        for f in confirmed_findings:
            vt = f.get("type", f.get("vuln_class", ""))
            confidence = f.get("confidence", 0.5)
            strategy = f.get("bypass_technique", f.get("hypothesis", "standard"))

            await self.memory.record_strategy(
                tech_key, vt, strategy, success=True, confidence=confidence
            )

        await self._emit_progress("hunt", "completed", 0.55, {"findings": len(confirmed_findings)})
        return confirmed_findings

    async def _phase_chain(self, target: str, findings: List) -> List[dict]:
        """Phase 3: Attack chain analysis — exploit-chainer agent."""
        # Only build chains from verified findings
        verified = [
            f for f in findings
            if isinstance(f, dict)
            and f.get("verification", {}).get("status") in ("verified", "likely_verified", None)
        ]

        await self._emit_progress("chain", "running", 0.60, {
            "message": f"Chaining {len(verified)} verified findings into attack paths..."
        })

        if not verified:
            await self._emit_progress("chain", "completed", 0.70, {"chains": 0})
            return []

        chain_result = await self.skills["chain"].execute({
            "target": target,
            "findings": verified,
        })

        chains = []
        for chain in chain_result.findings:
            if isinstance(chain, dict):
                chain_data = chain
            elif hasattr(chain, "to_dict"):
                chain_data = chain.to_dict()
            else:
                continue

            # Enrich with MITRE ATT&CK
            vuln_classes = [step.get("type", "") for step in chain_data.get("steps", [])]
            chain_data["mitre_techniques"] = self.mitre.get_techniques_for_chain(vuln_classes)

            # Save evidence
            if self.evidence:
                self.evidence.save_json_evidence(
                    "exploit-chainer", "chain", target, chain_data,
                    opsec_level=OPSECLevel.MODERATE,
                )

            chains.append(chain_data)

        await self._emit_progress("chain", "completed", 0.70, {"chains": len(chains)})
        return chains

    async def _phase_validate(self, findings: List, chains: List) -> List:
        """Phase 4: Validation — poc-validator kills false positives."""
        await self._emit_progress("validate", "running", 0.75, {
            "message": f"Running 7-Question Gate on {len(findings)} findings..."
        })

        validate_result = await self.skills["validate"].execute({
            "findings": findings + chains,
        })

        validated = validate_result.findings
        await self._emit_progress("validate", "completed", 0.85, {"validated": len(validated)})
        return validated

    async def _phase_screenshot(self, target: str, findings: List) -> List:
        """Phase 4.5: Screenshot capture — capture evidence of top findings."""
        await self._emit_progress("screenshot", "running", 0.87, {
            "message": f"Capturing evidence cards for {len(findings)} findings..."
        })

        # Skip screenshots in mock mode (Playwright not needed)
        if self.state.mock:
            await self._emit_progress("screenshot", "completed", 0.89, {"screenshots": 0})
            return findings

        # Capture screenshots for critical/high findings
        screenshot_findings = [
            f for f in findings
            if isinstance(f, dict)
            and f.get("severity", "").lower() in ("critical", "high")
            and f.get("endpoint", f.get("url", ""))
        ][:5]  # Limit to top 5

        for finding in screenshot_findings:
            endpoint = finding.get("endpoint", finding.get("url", ""))
            vuln_type = finding.get("type", finding.get("vuln_class", "poc"))
            poc = finding.get("poc", finding.get("poc_script", ""))
            evidence = finding.get("evidence", "")

            # Capture PoC evidence card (shows exploit command, request, response, analysis)
            ss_path = await self.screencap.capture_poc(target, finding)
            if ss_path:
                finding.setdefault("screenshots", []).append({
                    "file": ss_path,
                    "filename": os.path.basename(ss_path),
                    "description": f"{vuln_type} evidence card",
                    "finding_type": vuln_type,
                })

            # If it's a Nuclei finding, capture a formatted card
            if finding.get("template_id"):
                ss_path = await self.screencap.capture_nuclei(
                    target,
                    finding.get("template_id", ""),
                    finding.get("template_name", finding.get("template_id", "")),
                    endpoint,
                    finding.get("severity", "info"),
                    evidence,
                    finding.get("description", ""),
                )
                if ss_path:
                    finding.setdefault("screenshots", []).append({
                        "file": ss_path,
                        "filename": os.path.basename(ss_path),
                        "description": f"Nuclei: {finding.get('template_id', '')}",
                        "finding_type": "nuclei",
                    })

        await self._emit_progress("screenshot", "completed", 0.89, {"screenshots": len(screenshot_findings)})
        return findings

    async def _phase_report(
        self,
        target: str,
        platform: str,
        findings: List,
        chains: List,
        tool_outputs: List[dict] = None,
    ) -> dict:
        """Phase 5: Report generation — standalone MD reports in per-target folders."""
        await self._emit_progress("report", "running", 0.90, {
            "message": f"Writing {platform} report for {len(findings)} findings..."
        })

        if not findings and not chains:
            await self._emit_progress("report", "completed", 0.95)
            return {"report": None, "report_dir": None}

        # Write standalone MD report in per-target folder
        report_path = self.report_writer.write_main_report(
            target=target,
            findings=[f if isinstance(f, dict) else (f.to_dict() if hasattr(f, 'to_dict') else f) for f in findings],
            chains=[c if isinstance(c, dict) else (c.to_dict() if hasattr(c, 'to_dict') else c) for c in chains],
            tool_outputs=tool_outputs,
        )

        # Also keep legacy report text for display
        report_result = await self.skills["report"].execute({
            "findings": findings,
            "chains": chains,
            "target": target,
            "platform": platform,
        })

        await self._emit_progress("report", "completed", 0.95, {
            "message": f"Report saved to {report_path}"
        })
        return {
            **report_result.data,
            "report_path": report_path,
            "report_dir": str(self.report_writer._get_target_dir(target)),
        }

    async def _phase_memory(self, results: dict, findings: List, target: str):
        """Phase 6: Memory — save and learn from this engagement."""
        await self._emit_progress("memory", "running", 0.97, {
            "message": f"Saving {len(findings)} findings to memory for future hunts..."
        })

        await self.skills["memory"].execute({
            "action": "save",
            "session_data": results,
        })

        if findings:
            await self.skills["memory"].execute({
                "action": "pattern",
                "findings": findings,
                "target": target,
            })

        await self._emit_progress("memory", "completed", 1.0)

    async def run(
        self,
        target: str,
        mode: str = "full",
        platform: str = "hackerone",
        source_type: str = "url",
        engagement_type: str = "bug_bounty",
        engine: str = "agent",
    ) -> Dict:
        """
        Execute the full pentest pipeline.

        Args:
            target: Domain, IP, or URL to test
            mode: full, quick, or targeted
            platform: hackerone, bugcrowd, intigriti, immunefi, github
            source_type: url (black-box) or repo (white-box) or hybrid
            engagement_type: bug_bounty, pentest, source_audit, pr_review
            engine: agent (autonomous), pipeline (legacy), or hybrid (both)
        """
        results = {
            "target": target,
            "mode": mode,
            "platform": platform,
            "source_type": source_type,
            "engagement_type": engagement_type,
            "engine": engine,
            "stages": {},
            "findings": [],
            "chains": [],
            "report": None,
            "agents": {},
            "evidence": {},
            "metrics": {"started_at": time.time(), "completed_at": None, "duration": 0},
        }

        # Initialize evidence handler
        self.evidence = EvidenceHandler(
            base_dir=f"evidence/{target.replace('/', '_')}",
            engagement_id=f"{target}_{int(time.time())}",
        )

        # Initialize engagement state
        self.state = EngagementState(
            target=target,
            source_type=source_type,
            engagement_type=engagement_type,
            platform=platform,
            mock=self.config.get("mock_mode", False),
        )

        await self._emit_progress("init", "running", 0.0, {"engine": engine})

        # Scope validation
        if not await self._validate_scope(target):
            results["error"] = "Target out of scope"
            return results

        # ═══════════════════════════════════════════════════════════
        # ENGINE: agent (primary) — uses AutonomousAgent
        # ═══════════════════════════════════════════════════════════
        if engine in ("agent", "hybrid"):
            await self._emit_progress("agent", "running", 0.01, {
                "message": f"Starting autonomous agent on {target}..."
            })

            # Connect agent progress to pipeline
            async def agent_progress(phase, message, progress):
                await self._emit_progress(phase, "running", progress, {"message": message})
            self.agent.set_progress_callback(agent_progress)

            # Run autonomous agent
            agent_results = await self.agent.run(target)

            # Merge agent results into pipeline results
            results["stages"]["agent_recon"] = agent_results.get("phases", {}).get("recon", {})
            results["stages"]["agent_scan"] = agent_results.get("phases", {}).get("scan", {})
            results["stages"]["agent_fuzz"] = agent_results.get("phases", {}).get("fuzz", {})
            results["stages"]["agent_exploit"] = agent_results.get("phases", {}).get("exploit", {})

            # Convert agent findings to pipeline format
            for f in agent_results.get("findings", []):
                finding = Finding(
                    vuln_class=f.get("type", "unknown"),
                    endpoint=f.get("url", ""),
                    parameter=f.get("param", ""),
                    severity=f.get("severity", "info"),
                    confidence=f.get("confidence", 0.5),
                    cvss_score=f.get("cvss_score", 0),
                    evidence=f.get("evidence", ""),
                    description=f.get("description", ""),
                    source_tool=f.get("source_tool", "autonomous-agent"),
                )
                results["findings"].append(finding)

            # Convert agent chains
            for c in agent_results.get("chains", []):
                chain = AttackChain(
                    chain_name=c.get("chain_name", ""),
                    steps=c.get("steps", []),
                    total_score=c.get("total_score", 0),
                    scores=c.get("scores", {}),
                    chain_impact=c.get("impact", ""),
                )
                results["chains"].append(chain)

            await self._emit_progress("agent", "completed", 0.5, {
                "findings": len(agent_results.get("findings", [])),
                "chains": len(agent_results.get("chains", [])),
            })

        # ═══════════════════════════════════════════════════════════
        # ENGINE: pipeline (legacy) — uses skills directly
        # ═══════════════════════════════════════════════════════════
        if engine in ("pipeline", "hybrid"):
            # Phase 1: Recon
            recon_data = await self._phase_recon(target, mode)
            results["stages"]["recon"] = recon_data

            # Phase 1.5: Knowledge
            tech_hints = ", ".join(recon_data.get("analysis", {}).get("tech_stack", []))
            knowledge_data = await self._phase_learn(target, tech_hints)
            results["stages"]["learn"] = {
                "patterns_loaded": len(knowledge_data["known_patterns"]),
                "reports_loaded": len(knowledge_data["relevant_reports"]),
            }

            # Phase 2: Hunt (parallel agents)
            findings = await self._phase_hunt(target, mode, recon_data, knowledge_data)
            results["findings"].extend(findings)

        # ═══════════════════════════════════════════════════════════
        # COMMON: Validation, Chain, Report (for both engines)
        # ═══════════════════════════════════════════════════════════

        # Analyze any pre-existing tool outputs
        tool_outputs = []
        tool_findings = self._analyze_tool_outputs(target)
        if tool_findings:
            for tf in tool_findings:
                if hasattr(tf, 'to_dict'):
                    results["findings"].append(tf.to_dict())
                elif isinstance(tf, dict):
                    results["findings"].append(tf)
            tool_outputs = [{"tool": "external", "findings_count": len(tool_findings)}]

        # Phase 3: Chain analysis
        chains = await self._phase_chain(target, results["findings"])
        results["chains"].extend(chains)

        # Phase 4: Validate
        validated = await self._phase_validate(results["findings"], results["chains"])

        # Phase 4.5: Screenshot
        validated = await self._phase_screenshot(target, validated)

        # Phase 5: Report
        report_data = await self._phase_report(target, platform, validated, results["chains"], tool_outputs)
        results["stages"]["report"] = report_data
        results["report"] = report_data.get("report")
        results["report_path"] = report_data.get("report_path")
        results["report_dir"] = report_data.get("report_dir")

        # Phase 6: Memory
        results["findings"] = [f if isinstance(f, dict) else (f.to_dict() if hasattr(f, 'to_dict') else f) for f in validated]
        results["chains"] = [c if isinstance(c, dict) else (c.to_dict() if hasattr(c, 'to_dict') else c) for c in results["chains"]]
        await self._phase_memory(results, results["findings"], target)

        # Collect agent statuses
        results["agents"] = {k: v.to_dict() for k, v in self._agent_statuses.items()}

        # Collect evidence summary
        if self.evidence:
            results["evidence"] = self.evidence.get_summary()

        results["metrics"]["completed_at"] = time.time()
        results["metrics"]["duration"] = round(
            results["metrics"]["completed_at"] - results["metrics"]["started_at"], 2
        )

        return results


pipeline = PentestPipeline()
