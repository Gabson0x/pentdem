"""
LLM-Guided Attack Strategy — Brain that reads early signals and re-prioritizes.

Instead of running all 15 vuln classes uniformly everywhere, this module:
1. Reads early response signals (error phrasing, stack traces, timing, headers)
2. Uses LLM to analyze what the target is running
3. Re-prioritizes which classes to escalate on a given endpoint
4. Decides when to stop a class and switch to another

This is the "hands vs brain" upgrade — the brain sees patterns the hands miss.
"""

import json
import time
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field


@dataclass
class SignalSnapshot:
    """Early signals from initial probing of an endpoint."""
    url: str
    status: int
    response_time_ms: float
    body_size: int
    headers: Dict[str, str]
    body_snippet: str  # First 1000 chars
    error_patterns: List[str] = field(default_factory=list)
    tech_hints: List[str] = field(default_factory=list)


@dataclass
class AttackPlan:
    """AI-generated attack plan for a set of endpoints."""
    priority_classes: List[str]  # Ordered by priority
    skip_classes: List[str]      # Classes unlikely to work
    escalation_targets: List[Dict]  # Specific endpoints to go deeper on
    reasoning: str
    confidence: float
    estimated_time_seconds: int


# Signal patterns that indicate specific vuln classes
SIGNAL_PATTERNS = {
    "sql_errors": {
        "patterns": ["sql", "mysql", "syntax", "unclosed", "quotation", "odbc",
                     "postgresql", "ORA-", "SQLite", "MariaDB", "mysql_fetch"],
        "vuln_class": "sqli",
        "boost": 3,
    },
    "php_errors": {
        "patterns": ["warning:", "fatal error:", "notice:", "parse error",
                     "php_", "on line", "in /var/www", "stack trace"],
        "vuln_class": "lfi",
        "boost": 2,
    },
    "template_errors": {
        "patterns": ["template", "jinja", "twig", "freemarker", "velocity",
                     "mustache", "pug", "ejs", "undefined variable"],
        "vuln_class": "ssti",
        "boost": 3,
    },
    "json_api": {
        "patterns": ["application/json", "api", "graphql", "mutation", "query"],
        "vuln_class": "nosqli",
        "boost": 1,
    },
    "xml_input": {
        "patterns": ["xml", "soap", "feed", "import", "parse"],
        "vuln_class": "xxe",
        "boost": 2,
    },
    "file_operations": {
        "patterns": ["file", "path", "include", "require", "upload", "download"],
        "vuln_class": "lfi",
        "boost": 2,
    },
    "url_params": {
        "patterns": ["url", "redirect", "next", "return", "goto", "fetch"],
        "vuln_class": "ssrf",
        "boost": 2,
    },
    "admin_panels": {
        "patterns": ["admin", "dashboard", "panel", "manage", "console"],
        "vuln_class": "auth_bypass",
        "boost": 2,
    },
    "auth_endpoints": {
        "patterns": ["login", "signin", "auth", "token", "session", "cookie"],
        "vuln_class": "auth_bypass",
        "boost": 2,
    },
    "numeric_ids": {
        "patterns": ["id=", "user_id", "uid", "account", "profile", "order"],
        "vuln_class": "idor",
        "boost": 2,
    },
    "slow_response": {
        "patterns": [],  # Detected by timing, not body
        "vuln_class": "sqli",
        "boost": 1,  # Time-based blind SQLi
    },
    "large_response": {
        "patterns": [],  # Detected by body size
        "vuln_class": "idor",
        "boost": 1,  # Data-rich endpoints
    },
}


class LLMAttackStrategy:
    """
    AI-guided attack strategy that reads signals and decides what to test.
    
    Flow:
    1. Probe endpoints with lightweight requests
    2. Collect signal snapshots
    3. LLM analyzes signals and generates attack plan
    4. Execute plan with prioritized vuln classes
    5. Re-evaluate after initial results
    """

    def __init__(self, model_client=None):
        self.model = model_client
        self.signal_history: List[SignalSnapshot] = []
        self.attack_plans: List[AttackPlan] = []

    def collect_signals(self, url: str, response: Dict) -> SignalSnapshot:
        """
        Collect early signals from a response.
        This is lightweight — just reads what's already there.
        """
        status = response.get("status", 0)
        body = response.get("body", "")
        headers = response.get("headers", {})
        response_time = response.get("response_time_ms", 0)

        # Detect error patterns
        error_patterns = []
        body_lower = body.lower()
        for signal_name, signal_info in SIGNAL_PATTERNS.items():
            for pattern in signal_info["patterns"]:
                if pattern.lower() in body_lower:
                    error_patterns.append(signal_name)
                    break

        # Detect tech hints from headers
        tech_hints = []
        server = headers.get("server", "").lower()
        powered_by = headers.get("x-powered-by", "").lower()
        if "nginx" in server:
            tech_hints.append("nginx")
        if "apache" in server:
            tech_hints.append("apache")
        if "express" in powered_by or "node" in powered_by:
            tech_hints.append("node.js")
        if "php" in powered_by:
            tech_hints.append("php")
        if "python" in powered_by or "gunicorn" in server:
            tech_hints.append("python")
        if "asp.net" in powered_by:
            tech_hints.append("asp.net")

        # Check for specific indicators
        if response_time > 3000:
            error_patterns.append("slow_response")
        if len(body) > 50000:
            error_patterns.append("large_response")

        snapshot = SignalSnapshot(
            url=url,
            status=status,
            response_time_ms=response_time,
            body_size=len(body),
            headers=headers,
            body_snippet=body[:1000],
            error_patterns=error_patterns,
            tech_hints=tech_hints,
        )

        self.signal_history.append(snapshot)
        return snapshot

    def analyze_signals(self, signals: List[SignalSnapshot]) -> Dict[str, int]:
        """
        Analyze collected signals and score each vuln class.
        Returns {vuln_class: score} sorted by priority.
        """
        scores = {}
        for signal in signals:
            for pattern_name in signal.error_patterns:
                pattern_info = SIGNAL_PATTERNS.get(pattern_name, {})
                vuln_class = pattern_info.get("vuln_class")
                if vuln_class:
                    scores[vuln_class] = scores.get(vuln_class, 0) + pattern_info.get("boost", 1)

        # Sort by score
        return dict(sorted(scores.items(), key=lambda x: x[1], reverse=True))

    async def generate_attack_plan(
        self,
        signals: List[SignalSnapshot],
        available_classes: List[str],
        tech_stack: List[str] = None,
    ) -> AttackPlan:
        """
        Use LLM to generate an attack plan based on signals.
        Falls back to rule-based analysis if no LLM available.
        """
        if not self.model:
            return self._rule_based_plan(signals, available_classes)

        # Build context for LLM
        signal_summary = []
        for s in signals[:10]:  # Limit to 10 endpoints
            signal_summary.append({
                "url": s.url,
                "status": s.status,
                "response_time_ms": s.response_time_ms,
                "body_size": s.body_size,
                "error_patterns": s.error_patterns[:5],
                "tech_hints": s.tech_hints,
            })

        prompt = f"""Analyze these response signals from a web application and generate an attack plan.

Target signals:
{json.dumps(signal_summary, indent=2)}

Available vulnerability classes: {available_classes}
Detected tech stack: {tech_stack or []}

Based on the signals, determine:
1. Which vulnerability classes are most likely to succeed (priority order)
2. Which classes can be skipped (unlikely to work)
3. Which specific endpoints warrant deeper investigation
4. Reasoning for your decisions

Return JSON:
{{
    "priority_classes": ["class1", "class2", ...],
    "skip_classes": ["class3", ...],
    "escalation_targets": [{{"url": "...", "reason": "...", "vuln_class": "..."}}],
    "reasoning": "why you chose this order",
    "confidence": 0.0-1.0,
    "estimated_time_seconds": 300
}}"""

        try:
            response = await self.model.generate(prompt, model="glm")
            plan_data = json.loads(response)
            return AttackPlan(
                priority_classes=plan_data.get("priority_classes", available_classes),
                skip_classes=plan_data.get("skip_classes", []),
                escalation_targets=plan_data.get("escalation_targets", []),
                reasoning=plan_data.get("reasoning", ""),
                confidence=plan_data.get("confidence", 0.7),
                estimated_time_seconds=plan_data.get("estimated_time_seconds", 300),
            )
        except Exception:
            return self._rule_based_plan(signals, available_classes)

    def _rule_based_plan(
        self,
        signals: List[SignalSnapshot],
        available_classes: List[str],
    ) -> AttackPlan:
        """Fallback rule-based attack plan when LLM is unavailable."""
        scores = self.analyze_signals(signals)

        # Priority classes from signal analysis
        priority = [vc for vc in scores.keys() if vc in available_classes]
        # Add remaining classes not detected but available
        for vc in available_classes:
            if vc not in priority:
                priority.append(vc)

        # Skip classes with zero signal
        skip = [vc for vc in available_classes if vc not in priority and vc not in scores]

        # Find escalation targets (endpoints with most signals)
        escalation = []
        for signal in signals:
            if len(signal.error_patterns) >= 2:
                escalation.append({
                    "url": signal.url,
                    "reason": f"Multiple signals: {', '.join(signal.error_patterns[:3])}",
                    "vuln_class": scores.get(signal.error_patterns[0], "unknown")
                        if signal.error_patterns else "unknown",
                })

        return AttackPlan(
            priority_classes=priority[:8],
            skip_classes=skip[:4],
            escalation_targets=escalation[:5],
            reasoning=f"Rule-based: {len(scores)} signals detected, prioritizing {len(priority)} classes",
            confidence=0.6,
            estimated_time_seconds=300,
        )

    def re_evaluate_after_results(
        self,
        initial_plan: AttackPlan,
        findings: List[Dict],
        time_spent: float,
    ) -> AttackPlan:
        """
        Re-evaluate the attack plan based on actual findings.
        If a class is producing results, escalate it.
        If a class is producing nothing, deprioritize it.
        """
        # Count findings per class
        class_counts = {}
        for f in findings:
            vc = f.get("type", f.get("vuln_class", ""))
            class_counts[vc] = class_counts.get(vc, 0) + 1

        # Boost classes that are producing findings
        new_priority = list(initial_plan.priority_classes)
        for vc, count in class_counts.items():
            if count > 0 and vc in new_priority:
                # Move to front
                new_priority.remove(vc)
                new_priority.insert(0, vc)

        # Deprioritize classes with no findings after significant time
        if time_spent > 120:  # After 2 minutes
            for vc in new_priority:
                if class_counts.get(vc, 0) == 0:
                    new_priority.remove(vc)
                    new_priority.append(vc)

        return AttackPlan(
            priority_classes=new_priority,
            skip_classes=initial_plan.skip_classes,
            escalation_targets=initial_plan.escalation_targets,
            reasoning=f"Re-evaluated after {time_spent:.0f}s: {class_counts}",
            confidence=min(1.0, initial_plan.confidence + 0.1),
            estimated_time_seconds=max(60, initial_plan.estimated_time_seconds - int(time_spent)),
        )
