"""
AI Decision Engine — Autonomous brain for the pentest agent.

This module makes the agent truly autonomous by:
1. Deciding when to go deeper on a finding
2. Knowing when to switch targets
3. Controlling testing depth based on progress
4. Making strategic decisions about next steps
"""

import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum


class DecisionType(Enum):
    DEEPER = "deeper"           # Dig deeper on current finding
    SWITCH_VULN = "switch_vuln" # Switch to different vuln class
    SWITCH_TARGET = "switch_target"  # Move to new target
    EXPLOIT = "exploit"         # Attempt exploitation
    VERIFY = "verify"           # Verify finding
    REPORT = "report"           # Generate report
    STOP = "stop"               # Stop testing


@dataclass
class Decision:
    """A decision made by the AI engine."""
    action: DecisionType
    reasoning: str
    confidence: float
    target: Optional[str] = None
    vuln_class: Optional[str] = None
    depth_level: int = 1  # 1=basic, 2=intermediate, 3=advanced, 4=expert
    evidence_required: List[str] = field(default_factory=list)
    next_steps: List[str] = field(default_factory=list)


@dataclass
class TargetProfile:
    """Profile of a target being tested."""
    target: str
    technologies: List[str] = field(default_factory=list)
    attack_surface: str = "unknown"  # small, medium, large
    findings_count: int = 0
    verified_count: int = 0
    false_positive_count: int = 0
    testing_depth: int = 1
    time_spent_seconds: float = 0
    last_activity: str = ""
    promising_leads: List[str] = field(default_factory=list)
    dead_ends: List[str] = field(default_factory=list)


class AIDecisionEngine:
    """
    Autonomous decision engine that guides the pentest agent.
    
    Responsibilities:
    1. Analyze current state and decide next action
    2. Determine when to dig deeper vs move on
    3. Manage target prioritization and switching
    4. Control testing depth based on progress
    5. Ensure findings have sufficient evidence
    """

    # Time limits (seconds)
    MAX_TIME_PER_TARGET = 1800  # 30 minutes
    MAX_TIME_PER_VULN_CLASS = 300  # 5 minutes
    MAX_TIME_ON_FINDING = 120  # 2 minutes

    # Thresholds
    MIN_FINDINGS_FOR_DEEPER = 3
    FALSE_POSITIVE_THRESHOLD = 0.5  # If >50% are FP, switch strategy
    EVIDENCE_THRESHOLD = 0.7  # Minimum evidence score to keep finding

    def __init__(self, model_client=None):
        self.model = model_client
        self.target_profiles: Dict[str, TargetProfile] = {}
        self.decision_history: List[Decision] = []
        self.current_vuln_class = None
        self.vuln_class_start_time = 0

    def get_or_create_profile(self, target: str) -> TargetProfile:
        """Get or create a target profile."""
        if target not in self.target_profiles:
            self.target_profiles[target] = TargetProfile(target=target)
        return self.target_profiles[target]

    async def decide_next_action(
        self,
        target: str,
        current_findings: List[Dict],
        phase: str,
        time_spent: float,
        available_vuln_classes: List[str],
    ) -> Decision:
        """
        Core decision method — analyzes state and decides next action.
        
        This is the autonomous brain that decides:
        - Should we dig deeper on this finding?
        - Should we switch to a different vuln class?
        - Should we move to a completely new target?
        - Do we have enough evidence to report?
        """
        profile = self.get_or_create_profile(target)
        profile.time_spent_seconds = time_spent
        profile.findings_count = len(current_findings)
        
        # Calculate metrics
        verified = [f for f in current_findings if f.get("verification", {}).get("status") in ("verified", "likely_verified")]
        false_positives = [f for f in current_findings if f.get("verification", {}).get("status") == "false_positive"]
        profile.verified_count = len(verified)
        profile.false_positive_count = len(false_positives)
        
        # Check for time-based switches
        if time_spent > self.MAX_TIME_PER_TARGET:
            return Decision(
                action=DecisionType.REPORT,
                reasoning=f"Time limit reached ({time_spent:.0f}s > {self.MAX_TIME_PER_TARGET}s). Generating report with current findings.",
                confidence=0.9,
                next_steps=["generate_report"],
            )
        
        # Check if we should stop (no progress)
        if len(current_findings) == 0 and time_spent > 60:
            return Decision(
                action=DecisionType.SWITCH_TARGET,
                reasoning="No findings after 60s of testing. Target may be well-defended or out of scope.",
                confidence=0.7,
                next_steps=["try_different_approach", "switch_target"],
            )
        
        # Check false positive rate
        if len(current_findings) > 5:
            fp_rate = len(false_positives) / len(current_findings)
            if fp_rate > self.FALSE_POSITIVE_THRESHOLD:
                return Decision(
                    action=DecisionType.SWITCH_VULN,
                    reasoning=f"High false positive rate ({fp_rate:.0%}). Switching vulnerability class.",
                    confidence=0.8,
                    next_steps=["change_strategy", "try_different_payloads"],
                )
        
        # Analyze promising leads
        promising = [f for f in current_findings if f.get("confidence", 0) > 0.7 and f.get("evidence")]
        if promising:
            # We have promising findings — go deeper
            best_finding = max(promising, key=lambda f: f.get("confidence", 0))
            return Decision(
                action=DecisionType.DEEPER,
                reasoning=f"Found promising lead: {best_finding.get('type', 'unknown')} with {best_finding.get('confidence', 0):.0%} confidence. Going deeper.",
                confidence=0.85,
                vuln_class=best_finding.get("type"),
                depth_level=min(profile.testing_depth + 1, 4),
                evidence_required=[
                    "http_request",
                    "http_response",
                    "payload_used",
                    "injection_point",
                    "baseline_comparison",
                    "reproduction_steps",
                ],
                next_steps=[
                    "verify_finding",
                    "collect_evidence",
                    "generate_poc",
                    "test_variations",
                ],
            )
        
        # No promising leads — try different approach
        if profile.testing_depth < 3:
            profile.testing_depth += 1
            return Decision(
                action=DecisionType.SWITCH_VULN,
                reasoning=f"No promising leads at depth {profile.testing_depth}. Increasing depth and trying different vuln class.",
                confidence=0.7,
                depth_level=profile.testing_depth,
                next_steps=["try_bypass_techniques", "creative_payloads"],
            )
        
        # Exhausted current approach — switch target or report
        if len(available_vuln_classes) > 1:
            return Decision(
                action=DecisionType.SWITCH_VULN,
                reasoning="Exhausted current approach. Switching to remaining vuln classes.",
                confidence=0.6,
                next_steps=["try_remaining_vuln_classes"],
            )
        
        return Decision(
            action=DecisionType.REPORT,
            reasoning="All vuln classes tested. Generating final report.",
            confidence=0.8,
            next_steps=["generate_report"],
        )

    async def analyze_finding_for_depth(
        self,
        finding: Dict,
        target: str,
    ) -> Decision:
        """
        Analyze a specific finding to decide if we should go deeper.
        
        Returns a decision with:
        - Whether to dig deeper
        - What evidence to collect
        - What verification steps to take
        """
        vuln_type = finding.get("type", finding.get("vuln_class", ""))
        confidence = finding.get("confidence", 0)
        has_evidence = bool(finding.get("evidence"))
        
        # High confidence + evidence = verify and exploit
        if confidence > 0.8 and has_evidence:
            return Decision(
                action=DecisionType.VERIFY,
                reasoning=f"High confidence ({confidence:.0%}) finding with evidence. Verifying.",
                confidence=0.9,
                vuln_class=vuln_type,
                evidence_required=[
                    "verification_request",
                    "verification_response",
                    "payload_confirmation",
                ],
                next_steps=[
                    "send_verification_payload",
                    "compare_with_baseline",
                    "document_evidence",
                ],
            )
        
        # Medium confidence — collect more evidence
        if confidence > 0.5:
            return Decision(
                action=DecisionType.DEEPER,
                reasoning=f"Medium confidence ({confidence:.0%}). Collecting more evidence before verification.",
                confidence=0.7,
                vuln_class=vuln_type,
                evidence_required=[
                    "http_request",
                    "http_response",
                    "payload_used",
                    "injection_point",
                ],
                next_steps=[
                    "send_additional_payloads",
                    "test_variations",
                    "collect_response_data",
                ],
            )
        
        # Low confidence — try to confirm or dismiss
        return Decision(
            action=DecisionType.EXPLOIT,
            reasoning=f"Low confidence ({confidence:.0%}). Attempting exploitation to confirm or dismiss.",
            confidence=0.5,
            vuln_class=vuln_type,
            evidence_required=[
                "exploit_attempt",
                "server_response",
                "impact_demonstration",
            ],
            next_steps=[
                "attempt_exploitation",
                "test_edge_cases",
                "document_results",
            ],
        )

    async def decide_target_switch(
        self,
        current_target: str,
        discovered_targets: List[str],
        current_findings: List[Dict],
    ) -> Optional[Decision]:
        """
        Decide if we should switch to a different target.
        
        Considers:
        - Time spent on current target
        - Findings quality
        - Discovered targets with higher potential
        """
        profile = self.get_or_create_profile(current_target)
        
        # Don't switch if we have promising findings
        promising = [f for f in current_findings if f.get("confidence", 0) > 0.7]
        if promising:
            return None
        
        # Don't switch if we haven't spent enough time
        if profile.time_spent_seconds < 120:  # At least 2 minutes
            return None
        
        # Check for better targets
        if discovered_targets:
            # Score each target
            scored_targets = []
            for t in discovered_targets:
                if t == current_target:
                    continue
                t_profile = self.get_or_create_profile(t)
                score = self._score_target_potential(t, t_profile)
                scored_targets.append((score, t))
            
            scored_targets.sort(reverse=True)
            
            if scored_targets:
                best_score, best_target = scored_targets[0]
                current_score = self._score_target_potential(current_target, profile)
                
                # Switch if new target is significantly better
                if best_score > current_score * 1.5:
                    return Decision(
                        action=DecisionType.SWITCH_TARGET,
                        reasoning=f"Target {best_target} has higher potential (score {best_score:.2f} vs {current_score:.2f}).",
                        confidence=0.75,
                        target=best_target,
                        next_steps=["run_recon", "prioritize_endpoints"],
                    )
        
        return None

    def _score_target_potential(self, target: str, profile: TargetProfile) -> float:
        """Score a target's potential (0-1)."""
        score = 0.5  # Base score
        
        # Boost for technology diversity
        if len(profile.technologies) > 3:
            score += 0.1
        
        # Boost for large attack surface
        if profile.attack_surface == "large":
            score += 0.15
        elif profile.attack_surface == "medium":
            score += 0.1
        
        # Penalize for time spent
        if profile.time_spent_seconds > 300:
            score -= 0.2
        
        # Penalize for high false positive rate
        if profile.findings_count > 0:
            fp_rate = profile.false_positive_count / profile.findings_count
            score -= fp_rate * 0.3
        
        # Boost for promising leads
        if profile.promising_leads:
            score += 0.1 * len(profile.promising_leads)
        
        return max(0, min(1, score))

    async def generate_depth_plan(
        self,
        finding: Dict,
        target: str,
    ) -> Dict:
        """
        Generate a detailed plan for testing a finding at depth.
        
        Returns:
        - Specific payloads to try
        - Verification steps
        - Evidence to collect
        - Success criteria
        """
        vuln_type = finding.get("type", finding.get("vuln_class", ""))
        url = finding.get("url", "")
        param = finding.get("param", "")
        
        # Use LLM to generate depth plan if available
        if self.model:
            prompt = f"""Generate a detailed testing plan for this security finding:

Finding: {json.dumps(finding, indent=2)}
Target: {target}

Return JSON with:
{{
    "payloads": ["payload1", "payload2"],
    "verification_steps": ["step1", "step2"],
    "evidence_to_collect": ["evidence1", "evidence2"],
    "success_criteria": "what confirms this is a real vulnerability",
    "false_positive_indicators": "what would indicate this is a false positive",
    "estimated_time_seconds": 60
}}"""
            
            try:
                response = await self.model.generate(prompt, model="glm")
                return json.loads(response)
            except Exception:
                pass
        
        # Fallback to template-based plan
        return self._get_template_plan(vuln_type, url, param)

    def _get_template_plan(self, vuln_type: str, url: str, param: str) -> Dict:
        """Get a template-based testing plan."""
        templates = {
            "sqli": {
                "payloads": [
                    "' OR '1'='1",
                    "' UNION SELECT NULL--",
                    "1' AND SLEEP(5)--",
                    "' OR 1=1 LIMIT 1--",
                ],
                "verification_steps": [
                    "Send baseline request",
                    "Send payload request",
                    "Compare responses",
                    "Check for SQL errors",
                    "Test with UNION-based payload",
                ],
                "evidence_to_collect": [
                    "baseline_response",
                    "payload_response",
                    "error_messages",
                    "response_time_differences",
                ],
                "success_criteria": "SQL error messages or data exfiltration",
                "false_positive_indicators": "Generic error page, WAF block",
            },
            "xss": {
                "payloads": [
                    "<script>alert(1)</script>",
                    "<img src=x onerror=alert(1)>",
                    "javascript:alert(1)",
                    "<svg onload=alert(1)>",
                ],
                "verification_steps": [
                    "Send payload in parameter",
                    "Check if payload reflects",
                    "Verify no HTML encoding",
                    "Test in different contexts",
                ],
                "evidence_to_collect": [
                    "reflected_payload",
                    "html_context",
                    "encoding_status",
                ],
                "success_criteria": "Payload reflects unescaped in HTML",
                "false_positive_indicators": "Payload encoded, CSP blocks execution",
            },
            "ssti": {
                "payloads": [
                    "{{7*7}}",
                    "${7*7}",
                    "<%= 7*7 %>",
                    "{{config}}",
                ],
                "verification_steps": [
                    "Send math expression payload",
                    "Check for '49' in response",
                    "Verify expression was evaluated (not echoed)",
                    "Test with different template syntax",
                ],
                "evidence_to_collect": [
                    "evaluated_result",
                    "response_context",
                    "baseline_comparison",
                ],
                "success_criteria": "Math expression evaluated to 49",
                "false_positive_indicators": "Payload echoed back, no evaluation",
            },
            "ssrf": {
                "payloads": [
                    "http://127.0.0.1",
                    "http://169.254.169.254/latest/meta-data/",
                    "http://[::1]",
                    "http://0177.0.0.1",
                ],
                "verification_steps": [
                    "Send internal URL payload",
                    "Check for internal content",
                    "Test with AWS metadata",
                    "Test with different protocols",
                ],
                "evidence_to_collect": [
                    "internal_content",
                    "metadata_access",
                    "response_data",
                ],
                "success_criteria": "Internal content or metadata accessible",
                "false_positive_indicators": "Connection timeout, access denied",
            },
        }
        
        base_plan = templates.get(vuln_type, {
            "payloads": ["test_payload"],
            "verification_steps": ["send_payload", "check_response"],
            "evidence_to_collect": ["request", "response"],
            "success_criteria": "Positive confirmation",
            "false_positive_indicators": "No response or error",
        })
        
        base_plan["estimated_time_seconds"] = 60
        return base_plan

    def get_decision_summary(self) -> Dict:
        """Get summary of all decisions made."""
        return {
            "total_decisions": len(self.decision_history),
            "decisions_by_type": {},
            "targets_visited": list(self.target_profiles.keys()),
            "avg_confidence": sum(d.confidence for d in self.decision_history) / max(len(self.decision_history), 1),
        }
