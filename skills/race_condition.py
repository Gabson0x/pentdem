"""
Race Condition Detection — concurrent request harness.

Strategy:
1. Send N concurrent requests to same endpoint
2. Compare responses for:
   - Duplicate resource creation
   - Inconsistent balances/counts
   - TOCTOU vulnerabilities
   - Double-spending
3. Proof = response differences or duplicate resources
"""

import asyncio
import json
import time
from typing import Dict, List, Any
from skills.base import BaseSkill, SkillResult


# Sensitive endpoints prone to race conditions
SENSITIVE_ENDPOINTS = [
    "/api/transfer", "/api/pay", "/api/checkout", "/api/purchase",
    "/api/withdraw", "/api/deposit", "/api/redeem", "/api/coupon",
    "/api/vote", "/api/like", "/api/claim", "/api/reward",
    "/api/refund", "/api/subscribe", "/api/register", "/api/order",
]


class RaceConditionSkill(BaseSkill):
    """
    Detect race conditions via concurrent request testing.
    """

    def can_handle(self, task_type: str) -> bool:
        return task_type in ["race_condition", "race", "concurrent", "toctou"]

    async def execute(self, context: Dict[str, Any]) -> SkillResult:
        urls = context.get("urls", [])
        target = context.get("target", "")
        
        findings = []
        
        # Test discovered endpoints
        test_urls = urls[:5] + [f"https://{target}{ep}" for ep in SENSITIVE_ENDPOINTS]
        
        for url in test_urls[:10]:
            race_findings = await self._test_race_condition(url)
            findings.extend(race_findings)

        return SkillResult(
            success=True,
            findings=findings,
            data={"urls_tested": len(test_urls), "race_findings": len(findings)},
            next_skills=["validate"],
            confidence=min(len(findings) / 2, 1.0) if findings else 0.0,
        )

    async def _test_race_condition(self, url: str) -> List[Dict]:
        """Test for race condition on a URL."""
        findings = []
        
        # Step 1: Send N concurrent requests
        concurrent_count = 10
        start_time = time.time()
        
        tasks = [self._send_request(url) for _ in range(concurrent_count)]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        elapsed = time.time() - start_time
        
        # Filter successful responses
        valid_responses = [r for r in responses if isinstance(r, dict) and r.get("body")]
        
        if len(valid_responses) < 3:
            return findings
        
        # Step 2: Analyze responses for race condition evidence
        
        # Check for duplicate resources
        ids = set()
        for resp in valid_responses:
            body = resp.get("body", "")
            # Look for IDs in response
            import re
            id_patterns = [
                r'"id"\s*:\s*(\d+)',
                r'"order_id"\s*:\s*"[^"]*"',
                r'"transaction_id"\s*:\s*"[^"]*"',
                r'"request_id"\s*:\s*"[^"]*"',
            ]
            for pattern in id_patterns:
                match = re.search(pattern, body)
                if match:
                    resource_id = match.group(1) if match.lastindex else match.group(0)
                    if resource_id in ids:
                        findings.append({
                            "type": "race_condition_duplicate",
                            "url": url,
                            "severity": "critical",
                            "confidence": 0.9,
                            "cvss_score": 9.0,
                            "evidence": f"Duplicate resource created: {resource_id}",
                            "payload": f"{concurrent_count} concurrent requests",
                            "param": "Request Timing",
                            "description": "Race condition — duplicate resource created from concurrent requests",
                            "source_tool": "race-condition",
                        })
                    ids.add(resource_id)
        
        # Check for inconsistent responses (different balances, counts)
        status_codes = [r.get("status", 0) for r in valid_responses]
        if len(set(status_codes)) > 1:
            findings.append({
                "type": "race_condition_inconsistent",
                "url": url,
                "severity": "high",
                "confidence": 0.75,
                "cvss_score": 7.0,
                "evidence": f"Inconsistent responses: {dict((s, status_codes.count(s)) for s in set(status_codes))}",
                "payload": f"{concurrent_count} concurrent requests in {elapsed:.2f}s",
                "param": "Request Timing",
                "description": "Race condition — inconsistent response codes from concurrent requests",
                "source_tool": "race-condition",
            })
        
        # Check for response time anomalies (TOCTOU indicator)
        response_times = [r.get("time", 0) for r in valid_responses if r.get("time")]
        if response_times:
            avg_time = sum(response_times) / len(response_times)
            max_time = max(response_times)
            if max_time > avg_time * 3:  # One request took 3x longer
                findings.append({
                    "type": "race_condition_timing",
                    "url": url,
                    "severity": "medium",
                    "confidence": 0.6,
                    "cvss_score": 5.0,
                    "evidence": f"Response time anomaly: avg={avg_time:.2f}s, max={max_time:.2f}s",
                    "payload": f"{concurrent_count} concurrent requests in {elapsed:.2f}s",
                    "param": "Request Timing",
                    "description": "Possible TOCTOU — timing anomaly suggests serialization issue",
                    "source_tool": "race-condition",
                })
        
        # Check for body differences (value manipulation)
        bodies = [r.get("body", "") for r in valid_responses]
        unique_bodies = set(bodies)
        if len(unique_bodies) > 1 and len(valid_responses) > 5:
            # Different responses to same request = race condition
            findings.append({
                "type": "race_condition_value_manipulation",
                "url": url,
                "severity": "critical",
                "confidence": 0.85,
                "cvss_score": 8.5,
                "evidence": f"{len(unique_bodies)} different responses to {concurrent_count} identical requests",
                "payload": f"{concurrent_count} concurrent requests",
                "param": "Request Timing",
                "description": "Race condition — different responses suggest value manipulation possible",
                "source_tool": "race-condition",
            })
        
        return findings

    async def _send_request(self, url: str) -> Dict:
        """Send a single request and measure time."""
        try:
            start = time.time()
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "-i", "--max-time", "10",
                "-X", "POST",
                "-H", "Content-Type: application/json",
                "-d", "{}",
                url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            elapsed = time.time() - start
            
            response = stdout.decode(errors="ignore")
            
            import re
            status_match = re.search(r'HTTP/[\d.]+\s+(\d+)', response)
            status = int(status_match.group(1)) if status_match else 0
            
            return {"status": status, "body": response, "time": elapsed}
        except Exception:
            return {}
