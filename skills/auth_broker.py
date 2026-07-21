"""
Auth Broker — Orchestrates authentication for a scan target.

Detects login/register/auth pages, attempts credential-based login
or temp-email auto-registration, and manages session state.

Workflow:
    1. Scan recon-discovered URLs for auth pages
    2. If login form found:
       a. Try config credentials (PENTDEM_USERNAME/PENTDEM_PASSWORD)
       b. If no config creds, prompt user interactively (TTY only)
       c. Submit form, extract session cookies
    3. If no credentials and registration form found:
       a. Auto-create temp email via TempEmail
       b. Fill registration form, submit
       c. Wait for verification email, follow link
    4. Mark SessionManager as authenticated

Inherits from BaseSkill — wired into pipeline as a standard skill.

Usage:
    broker = AuthBrokerSkill(session_manager, tools, mock=False)
    result = await broker.execute({"target": "example.com", "urls": [...]})
"""

import asyncio
import re
import sys
import urllib.parse
from typing import Dict, Any, List, Optional

from skills.base import BaseSkill, SkillResult
from skills.auth_detect import (
    AuthDetectionSkill, AuthDetectionResult,
    AUTH_TYPE_LOGIN, AUTH_TYPE_REGISTER, AUTH_TYPE_MFA,
    AUTH_TYPE_OAUTH, AUTH_TYPE_403_WALL, AUTH_TYPE_401_WALL,
    AUTH_TYPE_CAPTCHA, AUTH_TYPE_RATE_LIMIT,
)
from skills.session_manager import SessionManager


class AuthBrokerSkill(BaseSkill):
    """
    Orchestrates the auth flow for a scan target.

    Detects auth pages, attempts login with config creds or interactive
    prompt, falls back to temp email auto-registration.
    """

    COMMON_AUTH_PATHS = [
        "/login", "/signin", "/auth/login", "/user/login",
        "/admin/login", "/wp-login.php", "/administrator",
        "/register", "/signup", "/create-account", "/join",
        "/forgot-password", "/reset-password",
    ]

    def __init__(self, session_manager: SessionManager, tools,
                 mock: bool = False):
        super().__init__(mock)
        self.session = session_manager
        self.tools = tools
        self.detector = AuthDetectionSkill()
        self._temp_email = None  # Lazy init
        self._login_attempts = 0
        self._max_login_attempts = 3

    def can_handle(self, task_type: str) -> bool:
        return task_type in ("auth", "login", "authentication")

    async def execute(self, context: Dict[str, Any]) -> SkillResult:
        """
        Execute auth broker for a target.

        Context keys:
            target: str — target domain/URL
            urls: List[str] — URLs discovered during recon
        """
        target = context.get("target", "")
        urls = context.get("urls", [])

        if not urls:
            base = self._normalize_base(target)
            urls = [f"{base}{p}" for p in self.COMMON_AUTH_PATHS]

        data = {
            "target": target,
            "auth_status": "unknown",
            "authenticated": False,
            "auth_type": None,
            "detected_pages": [],
            "login_attempted": False,
            "registration_attempted": False,
        }

        # Step 1: Already authenticated via env config?
        if await self.session.is_authenticated():
            data.update({
                "auth_status": "already_authenticated",
                "authenticated": True,
                "auth_type": self.session._auth_type,
            })
            return SkillResult(
                success=True,
                findings=[{
                    "type": "auth_status",
                    "severity": "info",
                    "description": f"Already authenticated via {self.session._auth_type}",
                    "confidence": 1.0,
                }],
                data=data,
                next_skills=["hunt"],
                confidence=1.0,
            )

        # Step 2: Scan URLs for auth pages
        auth_pages = await self._scan_for_auth_pages(urls)
        data["detected_pages"] = [
            {"url": r.url, "type": r.auth_type, "confidence": r.confidence,
             "form_action": r.form_action}
            for r in auth_pages
        ]

        if not auth_pages:
            data["auth_status"] = "no_auth_detected"
            return SkillResult(
                success=True, findings=[], data=data,
                next_skills=["hunt"], confidence=0.5,
            )

        # Step 3: Try login forms
        login_pages = [r for r in auth_pages if r.auth_type == AUTH_TYPE_LOGIN]
        for page in login_pages:
            if self._login_attempts >= self._max_login_attempts:
                break
            success = await self._handle_login(page)
            if success:
                await self.session.mark_authenticated("session")
                data.update({
                    "auth_status": "login_successful",
                    "authenticated": True,
                    "login_attempted": True,
                    "auth_type": "session",
                })
                return SkillResult(
                    success=True,
                    findings=[{
                        "type": "auth_success",
                        "severity": "info",
                        "url": page.url,
                        "description": f"Logged in via {page.form_action or page.url}",
                        "confidence": 1.0,
                    }],
                    data=data, next_skills=["hunt"], confidence=1.0,
                )

        # Step 4: No login success — try auto-registration with temp email
        register_pages = [r for r in auth_pages if r.auth_type == AUTH_TYPE_REGISTER]
        for page in register_pages:
            success = await self._handle_register(page, target)
            if success:
                await self.session.mark_authenticated("session")
                data.update({
                    "auth_status": "registration_successful",
                    "authenticated": True,
                    "registration_attempted": True,
                    "auth_type": "session",
                })
                return SkillResult(
                    success=True,
                    findings=[{
                        "type": "auth_auto_registered",
                        "severity": "info",
                        "url": page.url,
                        "description": "Auto-registered with temp email",
                        "confidence": 1.0,
                    }],
                    data=data, next_skills=["hunt"], confidence=1.0,
                )

        # Step 5: Report what we found
        data["auth_status"] = self._summarize_status(auth_pages)
        return SkillResult(
            success=await self.session.is_authenticated(),
            findings=[], data=data,
            next_skills=["hunt"],
            confidence=0.3 if not await self.session.is_authenticated() else 1.0,
        )

    # ── Auth page scanning ─────────────────────────────────────

    async def _scan_for_auth_pages(self, urls: List[str]) -> List[AuthDetectionResult]:
        """Fetch each URL and run auth detection on the response."""
        results = []

        async def _check_one(url):
            try:
                resp = await self._fetch_url(url)
                if not resp or not resp.get("stdout"):
                    return None
                raw = resp["stdout"]
                status = self._extract_status(raw)
                body = self._extract_body(raw)
                headers = self._extract_headers(raw)

                detection = await self.detector.detect(url, status, body, headers)
                if detection.confidence >= 0.5:
                    return detection
            except Exception:
                pass
            return None

        tasks = [_check_one(u) for u in urls[:20]]  # Cap at 20 URLs
        raw_results = await asyncio.gather(*tasks)
        for r in raw_results:
            if r is not None:
                results.append(r)

        return results

    # ── Login handling ─────────────────────────────────────────

    async def _handle_login(self, page: AuthDetectionResult) -> bool:
        """Attempt to log in via the detected form."""
        username, password = await self.session.get_credentials()

        # Try interactive prompt if no config creds AND we have a TTY
        if (not username or not password) and sys.stdin.isatty():
            prompted = await self._prompt_credentials()
            if prompted:
                username, password = prompted
                await self.session.set_credentials_from_prompt(username, password)

        if not username or not password:
            return False

        self._login_attempts += 1
        return await self._submit_form(page, username, password)

    async def _submit_form(self, page: AuthDetectionResult,
                           username: str, password: str) -> bool:
        """Submit login form and capture session cookies."""
        action_url = page.form_action or page.url

        form_data = {}
        if page.csrf_field:
            form_data[page.csrf_field] = page.csrf_value or ""
        username_field = page.username_field or "email"
        form_data[username_field] = username
        password_field = page.password_field or "password"
        form_data[password_field] = password
        form_data.update(page.extra_fields)

        encoded = urllib.parse.urlencode(form_data)

        cmd = ["curl", "-s", "-i", "-L", "--max-time", "15",
               "-X", "POST", "--data", encoded,
               "-H", "Content-Type: application/x-www-form-urlencoded"]

        # Attach existing cookies
        cookie_hdr = await self.session.cookie_jar.get_cookie_header(action_url)
        if cookie_hdr:
            cmd.extend(["-H", f"Cookie: {cookie_hdr}"])

        cmd.append(action_url)

        result = await self.tools.run("curl", cmd[1:])
        stdout = result.get("stdout", "")

        # Parse Set-Cookie
        await self.session.update_from_response(action_url, stdout)

        # Success if we got cookies
        return bool(await self.session.cookie_jar.get_cookie_header(action_url))

    async def _prompt_credentials(self) -> Optional[tuple]:
        """Interactive credential prompt via stdin."""
        print("\n[PENTDEM AUTH] Login page detected. Enter credentials (blank to skip):")
        try:
            username = input("  Username/Email: ").strip()
            if not username:
                return None
            import getpass
            password = getpass.getpass("  Password: ").strip()
            if not password:
                return None
            return (username, password)
        except (EOFError, KeyboardInterrupt):
            return None

    # ── Registration handling ──────────────────────────────────

    async def _handle_register(self, page: AuthDetectionResult,
                               target: str) -> bool:
        """Auto-register using temp email + generated password."""
        try:
            from skills.temp_email import TempEmail
            if self._temp_email is None:
                self._temp_email = TempEmail()

            temp_account = await self._temp_email.create()
            if not temp_account:
                return False

            email = temp_account["email"]
            password = TempEmail._random_password()

            # Submit registration form
            action_url = page.form_action or page.url
            form_data = {}

            if page.csrf_field:
                form_data[page.csrf_field] = page.csrf_value or ""

            email_field = page.username_field or "email"
            form_data[email_field] = email
            password_field = page.password_field or "password"
            form_data[password_field] = password

            # Try common confirm-password fields
            form_data["password_confirmation"] = password
            form_data["password_confirm"] = password
            form_data["confirm_password"] = password

            form_data.update(page.extra_fields)

            encoded = urllib.parse.urlencode(form_data)
            cmd = ["curl", "-s", "-i", "-L", "--max-time", "15",
                   "-X", "POST", "--data", encoded,
                   "-H", "Content-Type: application/x-www-form-urlencoded"]
            cmd.append(action_url)

            result = await self.tools.run("curl", cmd[1:])
            stdout = result.get("stdout", "")
            await self.session.update_from_response(action_url, stdout)

            # Wait for verification email
            try:
                verify_email = await self._temp_email.wait_for_email(
                    temp_account, timeout=60, check_interval=5,
                    subject_filter="verify",
                )
                if verify_email:
                    verify_link = await self._extract_verification_link(temp_account, verify_email)
                    if verify_link:
                        await self._fetch_url(verify_link)
            except Exception:
                pass  # Some sites don't require verification

            # Store credentials
            await self.session.set_credentials_from_prompt(email, password)
            return True

        except Exception:
            return False

    async def _extract_verification_link(self, account: dict,
                                          email: dict) -> Optional[str]:
        """Extract verification URL from an email."""
        body = await self._fetch_email_body(account, email)
        if not body:
            return None

        # Try href in anchor tags
        match = re.search(
            r'href=["\'](https?://[^"\']*(?:verify|confirm|activate|validate)[^"\']*)["\']',
            body, re.IGNORECASE,
        )
        if match:
            return match.group(1)

        # Fallback: bare URL
        match = re.search(
            r'(https?://[^\s<>"\']*(?:verify|confirm|activate|validate)[^\s<>"\']*)',
            body, re.IGNORECASE,
        )
        return match.group(1) if match else None

    async def _fetch_email_body(self, account: dict,
                                 email: dict) -> Optional[str]:
        """Fetch full body of an email from temp email provider."""
        if account.get("provider") == "mail.tm":
            try:
                import aiohttp
                async with aiohttp.ClientSession() as session:
                    headers = {"Authorization": f"Bearer {account.get('token', '')}"}
                    async with session.get(
                        f"https://api.mail.tm/messages/{email.get('id', '')}",
                        headers=headers,
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            # mail.tm returns text/html as lists of strings
                            html = data.get("html", [])
                            text = data.get("text", [])
                            body = (html[0] if html else "") or (text[0] if text else "")
                            return body if body else None
            except Exception:
                pass
        return None

    # ── HTTP helpers ───────────────────────────────────────────

    async def _fetch_url(self, url: str, timeout: int = 10) -> Optional[dict]:
        """Fetch a URL via curl with session cookies."""
        cmd = ["curl", "-s", "-i", "-L", "--max-time", str(timeout)]
        cookie_hdr = await self.session.cookie_jar.get_cookie_header(url)
        if cookie_hdr:
            cmd.extend(["-H", f"Cookie: {cookie_hdr}"])
        cmd.append(url)

        result = await self.tools.run("curl", cmd[1:])
        if result.get("stdout"):
            await self.session.update_from_response(url, result["stdout"])
            return result
        return None

    def _extract_status(self, raw: str) -> int:
        match = re.search(r"HTTP/[\d.]+\s+(\d+)", raw)
        return int(match.group(1)) if match else 0

    def _extract_body(self, raw: str) -> str:
        parts = raw.split("\r\n\r\n", 1)
        if len(parts) < 2:
            parts = raw.split("\n\n", 1)
        return parts[1] if len(parts) > 1 else ""

    def _extract_headers(self, raw: str) -> dict:
        parts = raw.split("\r\n\r\n", 1)
        header_raw = parts[0] if parts else ""
        headers = {}
        for line in header_raw.split("\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        return headers

    def _normalize_base(self, target: str) -> str:
        if not target.startswith("http"):
            target = f"https://{target}"
        from urllib.parse import urlparse
        parsed = urlparse(target)
        return f"{parsed.scheme}://{parsed.netloc}"

    def _summarize_status(self, pages: List[AuthDetectionResult]) -> str:
        types = set(p.auth_type for p in pages)
        if AUTH_TYPE_CAPTCHA in types:
            return "captcha_detected"
        if AUTH_TYPE_OAUTH in types:
            return "oauth_detected"
        if AUTH_TYPE_403_WALL in types or AUTH_TYPE_401_WALL in types:
            return "auth_wall_detected"
        if AUTH_TYPE_LOGIN in types:
            return "login_page_detected_no_credentials"
        return "auth_page_detected"

    async def cleanup(self):
        if self._temp_email:
            try:
                await self._temp_email.close()
            except Exception:
                pass
