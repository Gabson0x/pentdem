import asyncio
from typing import Dict, Any


class MockModelClient:
    """Mock client for testing without API keys. Returns structured responses."""

    async def generate(self, prompt: str, model: str = "mock",
                       system_prompt: str = None, temperature: float = 0.1) -> str:
        p = prompt.lower()

        # Recon analysis
        if "analyze this recon data" in p:
            return json_dumps({
                "tech_stack": ["nginx", "React", "Node.js"],
                "highest_risk_endpoints": ["https://api.example.com/v1/users", "https://admin.example.com/login"],
                "recommended_tests": ["idor", "ssrf", "xss", "sqli"],
                "attack_vectors": ["auth_bypass", "api_misconfig"],
                "notes": "Multiple API endpoints found, prioritize IDOR and auth testing",
            })
        # JS analysis
        if "extract api endpoints, secrets" in p:
            return json_dumps({
                "endpoints": ["/api/v1/users", "/api/v1/admin", "/graphql"],
                "secrets": ["pk_test_xxxxx", "aws_key_xxxxx"],
                "interesting_patterns": ["internal_admin_panel", "debug_mode_enabled"],
            })
        # IDOR analysis
        if "analyze this potential idor" in p:
            return json_dumps({"is_vulnerable": True, "description": "IDOR confirmed - different user data accessible", "confidence": 0.85})
        # SQLi analysis
        if "analyze this potential sql injection" in p:
            return json_dumps({"is_vulnerable": True, "description": "SQL error message confirms injection", "confidence": 0.9})
        # 7-question gate
        if "7-question gate" in p or "validate this security finding" in p:
            return json_dumps({
                "pass": True,
                "answers": {"q1": "yes", "q2": "yes", "q3": "yes", "q4": "yes", "q5": "yes", "q6": "yes", "q7": "yes"},
                "reason": "All checks passed",
                "exploitability_notes": "Directly exploitable via URL manipulation",
            })
        # Pattern learning
        if "extract attack patterns" in p:
            return json_dumps({
                "patterns": [
                    {"vuln_type": "IDOR", "url_pattern": "/api/v1/users/{id}", "param_pattern": "id", "technique": "ID enumeration"},
                    {"vuln_type": "SSRF", "url_pattern": "/fetch?url=", "param_pattern": "url", "technique": "Internal URL probing"},
                ]
            })
        # Knowledge/report parsing
        if "parse this hackerone disclosed report" in p:
            return json_dumps({
                "report_id": "123456",
                "title": "Stored XSS in user profile",
                "vulnerability_class": "XSS",
                "severity": "high",
                "cvss_score": 6.1,
                "target_tech": "React, Node.js",
                "attack_vector": "XSS via unsanitized display name field",
                "endpoint_pattern": "/api/v1/users/profile",
                "parameter": "display_name",
                "payload": "<img src=x onerror=alert(document.cookie)>",
                "impact": "Account takeover",
                "remediation": "DOMPurify sanitization",
            })
        # Novel chains
        if "novel attack chains" in p:
            return json_dumps([])
        # Report generation
        if "generate" in p and ("report" in p or "hackerone" in p or "bugcrowd" in p):
            return None  # handled by the report generation logic
        # Vuln type analysis (hunt skill)
        if "analyze these urls for" in p or "idor vulnerability" in p or "ssrf vulnerability" in p:
            return "[]"
        # Subdomains
        if "subdomain" in p:
            return '["api.example.com", "dev.example.com", "admin.example.com"]'
        # Live hosts
        if "live" in p or "host" in p:
            return '[{"host": "api.example.com", "status": "alive", "ports": [80, 443]}]'
        # Crawl
        if "crawl" in p:
            return '["https://api.example.com/v1/users", "https://dev.example.com/admin"]'
        # Default
        return "Mock response for testing."

    def get_available_models(self) -> list:
        return [{"provider": "mock", "model": "mock", "name": "Mock Model (Testing)"}]


def json_dumps(obj: Any) -> str:
    import json
    return json.dumps(obj)


mock_client = MockModelClient()
