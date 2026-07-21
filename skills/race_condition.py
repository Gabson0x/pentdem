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


class RaceConditionSkill(BaseSkill):
    """
    Detect race conditions via concurrent request testing.
    Only tests URLs that actually exist (2xx/3xx baseline).
    """

    def can_handle(self, task_type: str) -> bool:
        return task_type in ["race_condition", "race", "concurrent", "toctou"]

    async def execute(self, context: Dict[str, Any]) -> SkillResult:
        urls = context.get("urls", [])
        
        findings = []
        
        # Only test real discovered URLs — no synthetic financial endpoints
        for url in urls[:5]:
            if not await self._endpoint_exists(url):
                continue
            race_findings = await self._test_race_condition(url)
            findings.extend(race_findings)

        return SkillResult(
            success=True,
            findings=findings,
            data={"urls_tested": len(urls[:5]), "race_findings": len(findings)},
            next_skills=["validate"],
            confidence=min(len(findings) / 2, 1.0) if findings else 0.0,
        )

    async def _endpoint_exists(self, url: str) -> bool:
        """Quick check if endpoint returns 2xx before doing heavy concurrent testing."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                "--max-time", "5", url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            code = int(stdout.decode(errors="ignore").strip())
            return 200 <= code < 300
        except Exception:
            return False

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
        
        # Guard: only flag findings when ALL responses are 2xx
        all_2xx = all(200 <= r.get("status", 0) < 300 for r in valid_responses)
        if not all_2xx:
            return findings
        
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
        
        # Check for response time anomalies (TOCTOU indicator)
        response_times = [r.get("time", 0) for r in valid_responses if r.get("time")]
        if response_times:
            avg_time = sum(response_times) / len(response_times)
            max_time = max(response_times)
            if max_time > avg_time * 5 and max_time > 2.0:
                findings.append({
                    "type": "race_condition_timing",
                    "url": url,
                    "severity": "low",
                    "confidence": 0.4,
                    "cvss_score": 3.0,
                    "evidence": f"Response time anomaly: avg={avg_time:.2f}s, max={max_time:.2f}s",
                    "payload": f"{concurrent_count} concurrent requests in {elapsed:.2f}s",
                    "param": "Request Timing",
                    "description": "Possible TOCTOU — timing anomaly suggests serialization issue",
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
