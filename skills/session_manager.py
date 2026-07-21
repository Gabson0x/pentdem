"""
Session Manager — Shared cookie jar, token store, and credential management.

Every HTTP request in the system currently has zero session state. The
SessionManager provides a thread-safe, async cookie jar and token store
that all concurrent requests share.

Architecture:
    SessionManager is NOT a BaseSkill — it is a shared state object,
    like RateLimiter. It is constructor-injected wherever needed.

Usage:
    session = SessionManager()
    await session.load_from_env()
    cookie_hdrs = await session.get_curl_header("https://target.com/api")
    # cookie_hdrs = ["-H", "Cookie: PHPSESSID=abc123"]
    await session.update_from_response(url, raw_curl_stdout)
"""

import asyncio
import os
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse


class CookieJar:
    """Domain-scoped cookie storage with async thread safety."""

    def __init__(self):
        self._cookies: Dict[str, Dict[str, str]] = {}  # domain -> {name: value}
        self._lock = asyncio.Lock()

    async def set_cookie(self, domain: str, name: str, value: str,
                         path: str = "/", max_age: Optional[int] = None):
        async with self._lock:
            if domain not in self._cookies:
                self._cookies[domain] = {}
            self._cookies[domain][name] = value

    async def set_cookies_from_response(self, url: str, raw_headers: str):
        """Parse Set-Cookie headers from raw curl -i output and store them."""
        domain = urlparse(url).hostname or ""
        if not domain:
            return
        for match in re.finditer(
            r'[Ss]et-[Cc]ookie:\s*([^=]+)=([^;\s]+)',
            raw_headers
        ):
            name = match.group(1).strip()
            value = match.group(2).strip()
            await self.set_cookie(domain, name, value)

    async def get_cookie_header(self, url: str) -> str:
        """Return cookie string 'name1=value1; name2=value2' for the URL's domain."""
        domain = urlparse(url).hostname or ""
        async with self._lock:
            cookies = self._cookies.get(domain, {})
            if not cookies:
                return ""
            return "; ".join(f"{k}={v}" for k, v in cookies.items())

    async def get_all_cookies(self) -> Dict[str, Dict[str, str]]:
        async with self._lock:
            return {k: dict(v) for k, v in self._cookies.items()}

    @property
    def cookie_count(self) -> int:
        return sum(len(c) for c in self._cookies.values())

    async def clear(self):
        async with self._lock:
            self._cookies.clear()


class SessionManager:
    """
    Shared session state for the entire scan.

    Loads credentials from environment variables and provides them
    as curl-compatible header arguments. Also parses Set-Cookie from
    responses to maintain session state across requests.
    """

    def __init__(self):
        self.cookie_jar = CookieJar()
        self._auth_token: Optional[str] = None
        self._api_key: Optional[str] = None
        self._raw_cookie: Optional[str] = None
        self._username: Optional[str] = None
        self._password: Optional[str] = None
        self._is_authenticated: bool = False
        self._auth_type: Optional[str] = None
        self._lock = asyncio.Lock()

    # ── Loading ────────────────────────────────────────────────

    async def load_from_env(self):
        """Load credentials from environment variables."""
        self._username = os.environ.get("PENTDEM_USERNAME")
        self._password = os.environ.get("PENTDEM_PASSWORD")
        self._auth_token = os.environ.get("PENTDEM_SESSION_TOKEN")
        self._api_key = os.environ.get("PENTDEM_API_KEY")
        self._raw_cookie = os.environ.get("PENTDEM_COOKIE")

        if self._raw_cookie:
            self._is_authenticated = True
            self._auth_type = "raw_cookie"

        if self._auth_token:
            self._is_authenticated = True
            self._auth_type = self._auth_type or "token"

        if self._api_key:
            self._is_authenticated = True
            self._auth_type = self._auth_type or "api_key"

    # ── Curl header injection ──────────────────────────────────

    async def get_curl_header(self, url: str) -> List[str]:
        """
        Build curl -H arguments for authentication.
        Returns list like ["-H", "Cookie: PHPSESSID=abc", "-H", "Authorization: Bearer xyz"]
        or empty list if nothing is configured.
        """
        headers: List[str] = []

        # Session cookies from jar
        jar_header = await self.cookie_jar.get_cookie_header(url)
        if jar_header:
            headers.extend(["-H", f"Cookie: {jar_header}"])

        # Raw cookie as fallback
        if self._raw_cookie and not jar_header:
            headers.extend(["-H", f"Cookie: {self._raw_cookie}"])

        # Bearer token
        if self._auth_token:
            headers.extend(["-H", f"Authorization: Bearer {self._auth_token}"])

        # API key
        if self._api_key:
            headers.extend(["-H", f"X-API-Key: {self._api_key}"])

        return headers

    # ── Response parsing ───────────────────────────────────────

    async def update_from_response(self, url: str, raw_stdout: str):
        """Parse Set-Cookie headers from curl -i output and store them."""
        await self.cookie_jar.set_cookies_from_response(url, raw_stdout)
        # If we got new cookies, we're authenticated
        if self.cookie_jar.cookie_count > 0:
            await self.mark_authenticated("session")

    # ── State management ───────────────────────────────────────

    async def mark_authenticated(self, auth_type: str = "session"):
        async with self._lock:
            self._is_authenticated = True
            self._auth_type = self._auth_type or auth_type

    async def is_authenticated(self) -> bool:
        async with self._lock:
            return self._is_authenticated

    # ── Credential access ──────────────────────────────────────

    async def get_credentials(self) -> Tuple[Optional[str], Optional[str]]:
        return self._username, self._password

    async def set_credentials_from_prompt(self, username: str, password: str):
        async with self._lock:
            self._username = username
            self._password = password

    def has_config_credentials(self) -> bool:
        return bool(self._username and self._password)

    def get_auth_summary(self) -> dict:
        return {
            "authenticated": self._is_authenticated,
            "auth_type": self._auth_type,
            "has_credentials": self.has_config_credentials(),
            "has_api_key": bool(self._api_key),
            "has_token": bool(self._auth_token),
            "has_raw_cookie": bool(self._raw_cookie),
            "cookie_domains": list(self.cookie_jar._cookies.keys()),
        }
