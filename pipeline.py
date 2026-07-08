"""
Swarm Orchestrator - Parallel agent deployment for autonomous pentesting.

Delegates to specialist agents, coordinates handoffs, tracks progress.
Inspired by the Bug-Bounty-Agents swarm-orchestrator pattern.

v4.0: Merged AutonomousAgent as primary execution engine.
     Reports stored in per-target folders (reports/{domain}/).
v5.0: Added AIDecisionEngine for autonomous decision-making.
     - When to go deeper on findings
     - When to switch targets
     - How to control testing depth
v6.0: Added ReportQualityGate — single chokepoint for all findings.
     - Every finding must pass evidence consistency checks
     - Prevents fabricated findings from reaching reports
     - Auto-fixes CVSS/severity mismatches
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
from skills.quality_gate import ReportQualityGate
from skills.subdomain_takeover import SubdomainTakeoverSkill
from skills.jwt_attack import JWTAttackSkill
from skills.api_discovery import APIDiscoverySkill
from skills.mass_assignment import MassAssignmentSkill
from skills.cloud_metadata import CloudMetadataSkill
from skills.race_condition import RaceConditionSkill
from skills.credential_harvesting import CredentialHarvestingSkill
from skills.oauth_attack import OAuthAttackSkill
from skills.multi_stage_chain import MultiStageChainSkill
from skills.shared_waf import SharedWAFBypass
from skills.attack_strategy import LLMAttackStrategy
from skills.kill_chain import KillChainBuilder
from skills.docker_isolation import DockerIsolator
from skills.real_tools import RealToolRunner
from skills.session_persistence import SessionPersistence
from skills.multi_agent import MultiAgentOrchestrator
from skills.cicd_integration import CICDIntegration
from skills.compliance_mapper import ComplianceMapper
from skills.architectural_memory import ArchitecturalMemory
from adaptive_engine import AdaptiveEngine
from verifier import Verifier
from concurrent_hunt import ConcurrentHuntRunner
from rate_limiter import RateLimiter
from models import ModelClient
from agents.autonomous import AutonomousAgent
from tools import ToolExecutor
from ai_decision_engine import AIDecisionEngine, Decision, DecisionType


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
        "race_condition", "mass_assignment", "xxe", "prototype_pollution",
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
        self.use_docker = self.config.get("use_docker", False)

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
            if mock:
                from mock_models import MockModelClient
                self.model_client = MockModelClient()
            else:
                self.model_client = ModelClient()
        except Exception:
            self.model_client = None
        self.agent = AutonomousAgent(mock=mock, model_client=self.model_client)
        
        # AI Decision Engine for autonomous decision-making
        self.decision_engine = AIDecisionEngine(model_client=self.model_client)
        
        # Report Quality Gate — single chokepoint for all findings
        self.quality_gate = ReportQualityGate()

        self.skills = {
            "learn": KnowledgeSkill(mock=mock),
            "recon": ReconSkill(mock=mock, use_docker=self.use_docker),
            "hunt": HuntSkill(mock=mock, scope_guard=self.scope_guard),
            "chain": ChainSkill(mock=mock),
            "validate": ValidateSkill(mock=mock),
            "report": ReportSkill(mock=mock),
            "memory": MemorySkill(),
            "race_condition": RaceConditionSkill(mock=mock),
            "credential_harvest": CredentialHarvestingSkill(mock=mock),
            "oauth": OAuthAttackSkill(mock=mock),
            "mass_assignment": MassAssignmentSkill(mock=mock),
            "jwt": JWTAttackSkill(mock=mock),
            "cloud_metadata": CloudMetadataSkill(mock=mock),
            "subdomain_takeover": SubdomainTakeoverSkill(mock=mock),
            "api_discovery": APIDiscoverySkill(mock=mock),
            "multi_stage": MultiStageChainSkill(mock=mock),
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
        self._hunt_start_time = 0

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
        evidence_dir = Path(f"reports/{target.replace('/', '_')}/evidence")
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
        Phase 2: AI-driven vulnerability hunting.

        Architecture:
        - AIDecisionEngine guides which vuln classes to test and when to go deeper
        - 15 vuln classes run in parallel via asyncio.gather
        - Shared RateLimiter (token bucket) caps total requests/sec
        - URL scoring per class (no LLM) selects top 5 URLs
        - Fast-fail 4s timeout with single retry
        - Verification loops confirm findings before counting
        - AI decides when to switch strategies or targets
        """
        self._hunt_start_time = time.time()
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
        # Use scope-declared rate limit if available
        rate_limiter = None
        if self.scope_guard and self.scope_guard.rate_limit_rps:
            from rate_limiter import RateLimiter
            rate_limiter = RateLimiter(max_per_sec=self.scope_guard.rate_limit_rps, burst=self.scope_guard.rate_limit_rps)
        runner = ConcurrentHuntRunner(tools=tools, rate_limiter=rate_limiter, mock=self.config.get("mock_mode", False))

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
        if self.config.get("mock_mode", False):
            # In mock mode, skip verification and mark all as verified
            for f in all_findings:
                f["verification"] = {"status": "verified", "confidence": f.get("confidence", 0.5)}
            verified_findings = all_findings
        else:
            verifier = Verifier(tools=tools)
            verified_findings = await verifier.verify_batch(all_findings)

        # Keep verified, likely_verified, AND unverified (let quality gate filter)
        confirmed_findings = [
            f for f in verified_findings
            if f.get("verification", {}).get("status") in ("verified", "likely_verified", "unverified")
        ]

        # ── Step 6: AI Decision Engine — decide next actions ──
        if not self.config.get("mock_mode", False) and self.model_client:
            time_spent = time.time() - self._hunt_start_time
            
            # Get AI decision on what to do next
            decision = await self.decision_engine.decide_next_action(
                target=target,
                current_findings=confirmed_findings,
                phase="hunt",
                time_spent=time_spent,
                available_vuln_classes=vuln_types,
            )
            
            await self._emit_progress("hunt", "running", 0.50, {
                "message": f"AI Decision: {decision.action.value} — {decision.reasoning}",
                "decision": {
                    "action": decision.action.value,
                    "confidence": decision.confidence,
                    "depth_level": decision.depth_level,
                },
            })
            
            # Execute AI decision if it's to go deeper
            if decision.action == DecisionType.DEEPER:
                # Run deeper tests on promising findings
                deeper_findings = await self._run_deeper_tests(
                    target, confirmed_findings, decision
                )
                confirmed_findings.extend(deeper_findings)
            
            # Record decision for learning
            self.decision_engine.decision_history.append(decision)

        # ── Step 7: Record strategy success for cross-run learning ──
        for f in confirmed_findings:
            vt = f.get("type", f.get("vuln_class", ""))
            confidence = f.get("confidence", 0.5)
            strategy = f.get("bypass_technique", f.get("hypothesis", "standard"))

            await self.memory.record_strategy(
                tech_key, vt, strategy, success=True, confidence=confidence
            )

        await self._emit_progress("hunt", "completed", 0.55, {"findings": len(confirmed_findings)})
        return confirmed_findings

    async def _phase_advanced_hunt(
        self,
        target: str,
        mode: str,
        recon_data: dict,
    ) -> List[Finding]:
        """
        Phase 2.5: Advanced attack skills — runs specialized attack modules in parallel.
        JWT, OAuth, mass assignment, race condition, cloud metadata, subdomain takeover,
        credential harvesting, API discovery, WAF bypass.
        """
        all_urls = recon_data.get("urls", [])
        live_hosts = recon_data.get("live_hosts", [])
        subdomains = recon_data.get("subdomains", [])
        tech_stack = recon_data.get("analysis", {}).get("tech_stack", [])
        js_endpoints = recon_data.get("analysis", {}).get("js_endpoints", [])

        await self._emit_progress("advanced_hunt", "running", 0.40, {
            "message": f"Running {len(self.skills) - 7} advanced attack modules..."
        })

        # Build context for all skills
        ctx = {
            "target": target,
            "urls": all_urls,
            "live_hosts": live_hosts,
            "subdomains": subdomains,
            "tech_stack": tech_stack,
            "js_endpoints": js_endpoints,
            "mode": mode,
        }

        # Run all advanced skills in parallel
        advanced_skills = [
            ("race_condition", ctx),
            ("credential_harvest", {**ctx, "urls": all_urls[:10]}),
            ("oauth", {**ctx, "urls": [u for u in all_urls if "auth" in u.lower() or "login" in u.lower() or "oauth" in u.lower()][:5]}),
            ("mass_assignment", {**ctx, "urls": [u for u in all_urls if any(p in u.lower() for p in ["api", "user", "account", "profile", "settings"])]}),
            ("jwt", {**ctx, "urls": [u for u in all_urls if any(p in u.lower() for p in ["api", "auth", "token", "jwt"])]}),
            ("subdomain_takeover", {**ctx, "subdomains": subdomains}),
            ("api_discovery", {**ctx, "urls": all_urls[:10]}),
        ]

        # Cloud metadata only if scope allows it
        if self.scope_guard and self.scope_guard.allow_cloud_metadata:
            advanced_skills.append(("cloud_metadata", {**ctx, "urls": all_urls[:5]}))

        tasks = []
        for skill_name, skill_ctx in advanced_skills:
            if skill_name in self.skills:
                tasks.append(self._run_advanced_skill(skill_name, skill_ctx))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        advanced_findings = []
        for result in results:
            if isinstance(result, Exception):
                continue
            if isinstance(result, list):
                advanced_findings.extend(result)

        # WAF fingerprinting — run on all live hosts
        try:
            from skills.shared_waf import SharedWAFBypass
            waf = SharedWAFBypass()
            for host_info in live_hosts[:5]:
                url = host_info.get("url", "") if isinstance(host_info, dict) else str(host_info)
                if url:
                    try:
                        waf_result = await asyncio.wait_for(
                            waf.detect_waf(url), timeout=10
                        )
                        if waf_result and waf_result.get("waf_detected"):
                            advanced_findings.append({
                                "type": "waf_detected",
                                "url": url,
                                "severity": "info",
                                "confidence": 0.9,
                                "waf_name": waf_result.get("waf_name", "unknown"),
                                "description": f"WAF detected: {waf_result.get('waf_name', 'unknown')}",
                                "source_tool": "shared-waf",
                            })
                    except asyncio.TimeoutError:
                        pass
        except Exception:
            pass

        await self._emit_progress("advanced_hunt", "completed", 0.50, {
            "findings": len(advanced_findings),
        })

        return advanced_findings

    async def _run_advanced_skill(self, skill_name: str, ctx: dict) -> list:
        """Run a single advanced skill and return findings."""
        try:
            skill = self.skills.get(skill_name)
            if not skill:
                return []
            result = await asyncio.wait_for(skill.execute(ctx), timeout=30)
            return result.findings if hasattr(result, "findings") else []
        except asyncio.TimeoutError:
            return []
        except Exception:
            return []

    async def _run_deeper_tests(
        self,
        target: str,
        findings: List[Dict],
        decision: Decision,
    ) -> List[Dict]:
        """
        Run deeper tests on promising findings based on AI decision.
        
        This method:
        1. Analyzes each finding for depth potential
        2. Generates specific test plans
        3. Executes additional tests
        4. Collects more evidence
        """
        deeper_findings = []
        
        for finding in findings:
            # Analyze if we should go deeper on this finding
            finding_decision = await self.decision_engine.analyze_finding_for_depth(
                finding=finding,
                target=target,
            )
            
            if finding_decision.action in (DecisionType.VERIFY, DecisionType.EXPLOIT):
                # Generate depth plan
                depth_plan = await self.decision_engine.generate_depth_plan(
                    finding=finding,
                    target=target,
                )
                
                # Run additional tests based on plan
                additional_findings = await self._execute_depth_plan(
                    finding=finding,
                    plan=depth_plan,
                    target=target,
                )
                
                deeper_findings.extend(additional_findings)
        
        return deeper_findings

    async def _execute_depth_plan(
        self,
        finding: Dict,
        plan: Dict,
        target: str,
    ) -> List[Dict]:
        """Execute a depth plan for a specific finding."""
        findings = []
        
        # This would execute the specific tests from the plan
        # For now, return empty - to be implemented with actual test execution
        return findings

    async def _phase_chain(self, target: str, findings: List) -> List[dict]:
        """Phase 3: Attack chain analysis — exploit-chainer agent."""
        # Only build chains from verified findings
        verified = [
            f for f in findings
            if isinstance(f, dict)
            and f.get("verification", {}).get("status") in ("verified", "likely_verified")
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
            "message": f"Running 6-Question Gate on {len(findings)} findings..."
        })

        # Convert Finding objects to dicts for validate skill
        def to_dict(f):
            if isinstance(f, dict):
                return f
            if hasattr(f, 'to_dict'):
                return f.to_dict()
            if hasattr(f, '__dict__'):
                return f.__dict__
            return f

        all_items = [to_dict(f) for f in findings] + [to_dict(c) for c in chains]

        validate_result = await self.skills["validate"].execute({
            "findings": all_items,
        })

        validated = validate_result.findings
        await self._emit_progress("validate", "completed", 0.85, {"validated": len(validated)})
        return validated

    async def _phase_screenshot(self, target: str, findings: List) -> List:
        """Phase 4.5: Screenshot capture — capture evidence of top findings."""
        await self._emit_progress("screenshot", "running", 0.87, {
            "message": f"Capturing evidence cards for {len(findings)} findings..."
        })

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

        candidate_findings = [f if isinstance(f, dict) else (f.to_dict() if hasattr(f, 'to_dict') else f) for f in findings]
        reportable_findings = self.report_writer.filter_reportable(candidate_findings)

        # Write standalone MD report in per-target folder
        report_path = self.report_writer.write_main_report(
            target=target,
            findings=reportable_findings,
            chains=[c if isinstance(c, dict) else (c.to_dict() if hasattr(c, 'to_dict') else c) for c in chains],
            tool_outputs=tool_outputs,
            metadata={
                "candidate_findings": len(candidate_findings),
                "rejected_findings": len(candidate_findings) - len(reportable_findings),
            },
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

        # Initialize evidence handler - save in reports folder alongside findings
        self.evidence = EvidenceHandler(
            base_dir=f"reports/{target.replace('/', '_')}",
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

            # Convert agent findings to pipeline format while preserving raw fields
            # needed by validation/reportability gates (verdict, payload, url, etc.).
            for f in agent_results.get("findings", []):
                finding = Finding(
                    title=f.get("title", f.get("type", "unknown")),
                    vuln_class=f.get("type", f.get("vuln_class", "unknown")),
                    endpoint=f.get("url", f.get("endpoint", "")),
                    parameter=f.get("param", f.get("parameter", "")),
                    severity=f.get("severity", "info"),
                    confidence=f.get("confidence", 0.5),
                    cvss_score=f.get("cvss_score", 0),
                    evidence=f.get("evidence", ""),
                    description=f.get("description", ""),
                    impact=f.get("impact", ""),
                    remediation=f.get("remediation", ""),
                    poc=f.get("poc", f.get("poc_script", "")),
                    source=f.get("source_tool", f.get("source", "autonomous-agent")),
                    raw_data=f,
                )
                item = finding.to_dict() if hasattr(finding, 'to_dict') else finding.__dict__
                item.update({k: v for k, v in f.items() if k not in item})
                item.setdefault("type", item.get("vuln_class", "unknown"))
                item.setdefault("url", item.get("endpoint", ""))
                item.setdefault("param", item.get("parameter", ""))
                results["findings"].append(item)

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
            # In hybrid mode, reuse agent's recon data instead of re-running
            if engine == "hybrid" and "agent_recon" in results.get("stages", {}):
                recon_data = results["stages"]["agent_recon"]
                # Convert agent recon format to pipeline format
                if "subdomains" not in recon_data:
                    recon_data["subdomains"] = recon_data.get("subdomains", [])
                if "live_hosts" not in recon_data:
                    recon_data["live_hosts"] = recon_data.get("live_hosts", [])
                if "urls" not in recon_data:
                    recon_data["urls"] = recon_data.get("urls", [])
            else:
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

            # Phase 2.5: Advanced attack skills (JWT, OAuth, mass assignment, etc.)
            if not self.config.get("mock_mode", False):
                advanced_findings = await self._phase_advanced_hunt(target, mode, recon_data)
                results["findings"].extend(advanced_findings)

        # ═══════════════════════════════════════════════════════════
        # COMMON: Quality Gate, Validation, Chain, Report (for both engines)
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

        # ── QUALITY GATE: Single chokepoint for all findings ──
        # Every finding MUST pass evidence consistency checks before reaching reports
        self.quality_gate.reset_dedup()
        passed_findings, rejected_findings = self.quality_gate.check_batch(results["findings"])
        
        if rejected_findings:
            await self._emit_progress("quality_gate", "running", 0.58, {
                "passed": len(passed_findings),
                "rejected": len(rejected_findings),
                "reasons": [r["reasons"][0] for r in rejected_findings[:5]],
            })
        
        # Store rejected findings for diagnostics
        results["rejected_findings"] = rejected_findings
        results["findings"] = passed_findings
        
        gate_stats = self.quality_gate.get_stats()
        await self._emit_progress("quality_gate", "completed", 0.59, {
            "stats": gate_stats,
        })

        # Phase 3: Chain analysis
        chains = await self._phase_chain(target, results["findings"])
        results["chains"].extend(chains)

        # Phase 4: Validate
        validated = await self._phase_validate(results["findings"], results["chains"])

        # Separate validated findings from validated chains
        validated_findings = [v for v in validated if v.get("type") != "Attack Chain"]
        validated_chains = [v for v in validated if v.get("type") == "Attack Chain"]

        # Phase 4.5: Screenshot
        validated_findings = await self._phase_screenshot(target, validated_findings)

        # Phase 5: Report — use validated chains, not raw chains
        report_data = await self._phase_report(target, platform, validated_findings, validated_chains, tool_outputs)
        results["stages"]["report"] = report_data
        results["report"] = report_data.get("report")
        results["report_path"] = report_data.get("report_path")
        results["report_dir"] = report_data.get("report_dir")

        # Keep candidate findings for diagnostics, but only persist/report memory-safe findings.
        # filter_reportable was a legacy filter — quality_gate already handles CVSS/confidence checks.
        candidate_findings = [f if isinstance(f, dict) else (f.to_dict() if hasattr(f, 'to_dict') else f) for f in validated_findings]
        reportable_findings = candidate_findings

        # Phase 6: Memory
        results["candidate_findings"] = candidate_findings
        results["findings"] = reportable_findings
        results["chains"] = [c if isinstance(c, dict) else (c.to_dict() if hasattr(c, 'to_dict') else c) for c in validated_chains]
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
