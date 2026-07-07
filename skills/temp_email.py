"""
Temp Email — Disposable email for IDOR and auth testing.

Creates temporary email addresses to:
1. Register accounts on target
2. Test IDOR on email-related endpoints
3. Verify email verification bypass
4. Test multi-account scenarios

Providers: mail.tm (free API), guerrillamail, tempmail.plus
"""

import asyncio
import hashlib
import json
import random
import string
import time
from typing import Optional, Dict, List
from urllib.parse import urlparse

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False


class TempEmail:
    """
    Disposable email manager for security testing.

    Usage:
        temp = TempEmail()
        account = await temp.create()
        # account = {"email": "xyz@domain.com", "token": "...", "provider": "mail.tm"}
        emails = await temp.fetch_inbox(account)
    """

    def __init__(self):
        self._session = None
        self._accounts = []

    async def _get_session(self):
        if self._session is None or self._session.closed:
            if HAS_AIOHTTP:
                self._session = aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=15)
                )
            else:
                return None
        return self._session

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()
        self._session = None

    # ─── Mail.TM (Primary — free, no auth) ───────────────────────

    async def _mailtm_create(self) -> Optional[Dict]:
        """Create email via mail.tm free API."""
        session = await self._get_session()
        if not session:
            return None

        try:
            # Get available domains
            async with session.get("https://api.mail.tm/domains") as resp:
                if resp.status != 200:
                    return None
                data = await resp.json()
                domains = [d["domain"] for d in data.get("hydra:member", [])]
                if not domains:
                    return None

            domain = random.choice(domains)
            username = self._random_username()
            email = f"{username}@{domain}"
            password = self._random_password()

            # Create account
            async with session.post(
                "https://api.mail.tm/accounts",
                json={"address": email, "password": password},
            ) as resp:
                if resp.status not in (200, 201):
                    return None
                account_data = await resp.json()

            # Get auth token
            async with session.post(
                "https://api.mail.tm/token",
                json={"address": email, "password": password},
            ) as resp:
                if resp.status != 200:
                    return None
                token_data = await resp.json()

            account = {
                "email": email,
                "password": password,
                "token": token_data.get("token", ""),
                "provider": "mail.tm",
                "account_id": account_data.get("id", ""),
                "created_at": time.time(),
            }
            self._accounts.append(account)
            return account

        except Exception as e:
            return None

    async def _mailtm_fetch(self, account: Dict) -> List[Dict]:
        """Fetch emails from mail.tm inbox."""
        session = await self._get_session()
        if not session or not account.get("token"):
            return []

        try:
            headers = {"Authorization": f"Bearer {account['token']}"}
            async with session.get(
                "https://api.mail.tm/messages",
                headers=headers,
            ) as resp:
                if resp.status != 200:
                    return []
                data = await resp.json()

            emails = []
            for msg in data.get("hydra:member", []):
                emails.append({
                    "id": msg.get("id", ""),
                    "from": msg.get("from", {}).get("address", ""),
                    "subject": msg.get("subject", ""),
                    "preview": msg.get("intro", ""),
                    "created_at": msg.get("createdAt", ""),
                })
            return emails

        except Exception:
            return []

    # ─── GuerrillaMail (Fallback) ───────────────────────────────

    async def _guerrillamail_create(self) -> Optional[Dict]:
        """Create email via GuerrillaMail."""
        session = await self._get_session()
        if not session:
            return None

        try:
            # Get a session token
            async with session.get(
                "https://api.guerrillamail.com/ajax.php?f=get_email_address"
            ) as resp:
                if resp.status != 200:
                    return None
                data = await resp.json()

            email = data.get("email_addr", "")
            token = data.get("sid_token", "")

            if not email:
                return None

            account = {
                "email": email,
                "token": token,
                "provider": "guerrillamail",
                "created_at": time.time(),
            }
            self._accounts.append(account)
            return account

        except Exception:
            return None

    async def _guerrillamail_fetch(self, account: Dict) -> List[Dict]:
        """Fetch emails from GuerrillaMail."""
        session = await self._get_session()
        if not session or not account.get("token"):
            return []

        try:
            url = f"https://api.guerrillamail.com/ajax.php?f=check_email&seq=0&sid_token={account['token']}"
            async with session.get(url) as resp:
                if resp.status != 200:
                    return []
                data = await resp.json()

            emails = []
            for msg in data.get("list", []):
                emails.append({
                    "id": msg.get("mail_id", ""),
                    "from": msg.get("mail_from", ""),
                    "subject": msg.get("mail_subject", ""),
                    "preview": msg.get("mail_excerpt", ""),
                    "created_at": msg.get("mail_timestamp", ""),
                })
            return emails

        except Exception:
            return []

    # ─── Public API ──────────────────────────────────────────────

    async def create(self, provider: str = "auto") -> Optional[Dict]:
        """
        Create a temporary email account.

        Args:
            provider: "mail.tm", "guerrillamail", or "auto" (try both)

        Returns:
            {"email": "...", "token": "...", "provider": "...", ...} or None
        """
        if provider in ("auto", "mail.tm"):
            account = await self._mailtm_create()
            if account:
                return account

        if provider in ("auto", "guerrillamail"):
            account = await self._guerrillamail_create()
            if account:
                return account

        return None

    async def fetch_inbox(self, account: Dict) -> List[Dict]:
        """Fetch all emails in the inbox."""
        provider = account.get("provider", "mail.tm")

        if provider == "mail.tm":
            return await self._mailtm_fetch(account)
        elif provider == "guerrillamail":
            return await self._guerrillamail_fetch(account)
        return []

    async def wait_for_email(
        self,
        account: Dict,
        timeout: int = 60,
        check_interval: int = 3,
        subject_filter: str = None,
    ) -> Optional[Dict]:
        """
        Wait for an email to arrive.

        Args:
            account: The temp email account dict
            timeout: Max seconds to wait
            check_interval: Seconds between checks
            subject_filter: Only return emails containing this in subject

        Returns:
            First matching email dict, or None on timeout
        """
        start = time.time()
        while time.time() - start < timeout:
            emails = await self.fetch_inbox(account)
            for email in emails:
                if subject_filter:
                    if subject_filter.lower() in email.get("subject", "").lower():
                        return email
                else:
                    return email
            await asyncio.sleep(check_interval)
        return None

    async def create_multiple(self, count: int, provider: str = "auto") -> List[Dict]:
        """Create multiple temp email accounts for multi-user IDOR testing."""
        accounts = []
        for _ in range(count):
            account = await self.create(provider)
            if account:
                accounts.append(account)
            await asyncio.sleep(0.5)  # Rate limit
        return accounts

    def get_all_accounts(self) -> List[Dict]:
        """Get all created accounts."""
        return list(self._accounts)

    # ─── Helpers ─────────────────────────────────────────────────

    @staticmethod
    def _random_username(length: int = 10) -> str:
        chars = string.ascii_lowercase + string.digits
        return "".join(random.choices(chars, k=length))

    @staticmethod
    def _random_password(length: int = 16) -> str:
        chars = string.ascii_letters + string.digits + "!@#$%"
        return "".join(random.choices(chars, k=length))

    @staticmethod
    def generate_test_emails(target: str, count: int = 5) -> List[str]:
        """
        Generate test email addresses for a target domain.
        These are NOT real — just for testing parameter injection.
        """
        emails = []
        for i in range(count):
            username = f"test{i+1}"
            emails.append(f"{username}@{target}")
        return emails


# ─── IDOR Email Testing Helper ──────────────────────────────────

class EmailIDORTester:
    """
    Helper for email-based IDOR testing.

    Workflow:
    1. Create N temp emails
    2. Register accounts on target with each email
    3. Test if user A can access user B's data via:
       - Changing email parameter
       - Changing user ID
       - Changing session/token
    """

    def __init__(self):
        self.temp_email = TempEmail()
        self.accounts = []

    async def setup(self, count: int = 3) -> List[Dict]:
        """Create temp emails for testing."""
        self.accounts = await self.temp_email.create_multiple(count)
        return self.accounts

    def get_idor_payloads(self) -> List[Dict]:
        """
        Generate IDOR test payloads based on created accounts.
        Returns payloads to try against email-related endpoints.
        """
        payloads = []

        for i, acc in enumerate(self.accounts):
            email = acc["email"]

            # Test: change email parameter
            payloads.append({
                "type": "email_idor",
                "original_email": email,
                "test_emails": [a["email"] for a in self.accounts if a["email"] != email],
                "params": ["email", "user_email", "mail", "e", "account"],
                "description": f"IDOR via email parameter manipulation",
            })

            # Test: change user ID (if numeric)
            payloads.append({
                "type": "user_id_idor",
                "test_ids": ["1", "2", "0", "-1", "99999"],
                "params": ["user_id", "uid", "id", "account_id"],
                "description": f"IDOR via user ID enumeration",
            })

        return payloads

    async def cleanup(self):
        """Clean up temp email accounts."""
        await self.temp_email.close()


# ─── Convenience Function ───────────────────────────────────────

async def create_temp_email(provider: str = "auto") -> Optional[Dict]:
    """Quick create a temp email."""
    temp = TempEmail()
    account = await temp.create(provider)
    await temp.close()
    return account


async def test_email_idor(target: str, endpoint: str, count: int = 3) -> Dict:
    """
    Quick IDOR test using temp emails.

    Creates temp emails, then tests if the endpoint leaks data
    when email parameters are manipulated.
    """
    tester = EmailIDORTester()
    accounts = await tester.setup(count)

    results = {
        "target": target,
        "endpoint": endpoint,
        "emails_created": len(accounts),
        "payloads": tester.get_idor_payloads(),
        "accounts": [{"email": a["email"], "provider": a["provider"]} for a in accounts],
    }

    await tester.cleanup()
    return results
