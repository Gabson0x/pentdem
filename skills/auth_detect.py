"""
Auth Detection — Scan HTTP responses for authentication-related pages.

Detects login forms, registration forms, MFA pages, OAuth/SSO redirects,
auth walls (401/403), captcha challenges, and rate limits.

Does NOT inherit from BaseSkill — it is a utility class used by
AuthBrokerSkill. It focuses purely on detection, not execution.

Usage:
    detector = AuthDetectionSkill()
    result = await detector.detect(url, status_code, body, headers)
    if result.auth_type == "login":
        print(f"Login form at {result.form_action}, user field: {result.username_field}")
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin


# ── Auth type constants ───────────────────────────────────────────

AUTH_TYPE_LOGIN = "login"
AUTH_TYPE_REGISTER = "register"
AUTH_TYPE_MFA = "mfa"
AUTH_TYPE_OAUTH = "oauth"
AUTH_TYPE_SSO = "sso"
AUTH_TYPE_403_WALL = "auth_wall_403"
AUTH_TYPE_401_WALL = "auth_wall_401"
AUTH_TYPE_CAPTCHA = "captcha"
AUTH_TYPE_RATE_LIMIT = "rate_limit"
AUTH_TYPE_UNKNOWN = "unknown"


@dataclass
class AuthDetectionResult:
    """Result of scanning a URL for auth content."""
    url: str
    auth_type: str = AUTH_TYPE_UNKNOWN
    confidence: float = 0.0

    # Form fields (for login/register forms)
    form_action: Optional[str] = None
    form_method: str = "POST"
    username_field: Optional[str] = None
    password_field: Optional[str] = None
    csrf_field: Optional[str] = None
    csrf_value: Optional[str] = None
    extra_fields: Dict[str, str] = field(default_factory=dict)

    # OAuth/SSO details
    oauth_provider: Optional[str] = None
    oauth_redirect_url: Optional[str] = None

    # Status codes
    status_code: int = 0

    # Evidence
    evidence: str = ""
    matched_patterns: List[str] = field(default_factory=list)


class AuthDetectionSkill:
    """
    Scans HTTP responses for authentication-related pages.

    Recognizes:
    - Login forms (password input + submit button + login text)
    - Registration forms (password + email + register text)
    - MFA/2FA forms (code/otp/token input)
    - OAuth/SSO redirects (Google, GitHub, Microsoft, etc.)
    - Auth walls (HTTP 401/403)
    - Captcha challenges (reCAPTCHA, hCaptcha, Turnstile)
    - Rate limiting (HTTP 429)
    """

    # ── Pattern dictionaries ────────────────────────────────────
    # Each entry is (regex_string, weight, tag)

    LOGIN_PATTERNS = [
        (r'<form[^>]*>', 0.1, "form_tag"),
        (r'input[^>]*type=["\']password["\']', 0.5, "password_input"),
        (r'input[^>]*type=["\']email["\']', 0.3, "email_input"),
        (r'input[^>]*name=["\'](?:login|signin|username|user)["\']', 0.4, "login_field"),
        (r'<button[^>]*type=["\']submit["\'][^>]*>[^<]*(?:log\s*in|sign\s*in|login|signin)', 0.2, "login_button"),
        (r'(?:login|signin|sign\s+in)', 0.1, "login_text"),
    ]

    REGISTER_PATTERNS = [
        (r'input[^>]*type=["\']password["\']', 0.3, "password_on_register"),
        (r'input[^>]*type=["\']email["\']', 0.3, "email_on_register"),
        (r'<button[^>]*type=["\']submit["\'][^>]*>[^<]*(?:register|sign\s*up|create|join)', 0.3, "register_button"),
        (r'(?:register|sign\s*up|signup|create\s*account)', 0.15, "register_text"),
    ]

    MFA_PATTERNS = [
        (r'input[^>]*(?:type=["\'](?:text|number)["\']|name=["\'](?:code|otp|token|mfa|2fa|totp))', 0.4, "mfa_input"),
        (r'(?:two.factor|multi.factor|2fa|mfa|authenticator|verification\s*code)', 0.35, "mfa_text"),
    ]

    OAUTH_PATTERNS = [
        (r'href=["\'][^"\']*(?:accounts\.google\.com|login\.microsoftonline|github\.com/login/oauth|facebook\.com/v[\d.]+/dialog|appleid\.apple\.com)', 0.5, "oauth_url"),
        (r'(?:sign\s*in\s*with\s*(?:google|github|microsoft|facebook|apple|twitter))', 0.4, "oauth_text"),
    ]

    AUTH_WALL_PATTERNS = [
        (r'(?:access\s*denied|access\s*forbidden|unauthorized)', 0.3, "denied_text"),
        (r'(?:please\s*log\s*in|please\s*authenticate|you\s*must\s*be\s*logged)', 0.4, "please_login"),
    ]

    CAPTCHA_PATTERNS = [
        (r'(?:recaptcha|hcaptcha|turnstile|g-recaptcha|cf-turnstile)', 0.5, "captcha_script"),
        (r'(?:captcha|challenge|security\s*check)', 0.3, "captcha_text"),
    ]

    # ── OAuth provider detection ────────────────────────────────

    OAUTH_PROVIDERS = {
        "google":    r'accounts\.google\.com',
        "github":    r'github\.com/login/oauth',
        "microsoft": r'login\.microsoftonline\.com',
        "facebook":  r'facebook\.com/[\w.]+/dialog',
        "apple":     r'appleid\.apple\.com',
        "twitter":   r'twitter\.com/i/oauth',
        "linkedin":  r'linkedin\.com/oauth',
    }

    # ── CSRF token extraction ───────────────────────────────────

    CSRF_PATTERNS = [
        (r'input[^>]*name=["\']([^"\']*(?:csrf|token|nonce|_token|authenticity_token)[^"\']*)["\'][^>]*value=["\']([^"\']*)["\']', "csrf_named"),
        (r'meta[^>]*name=["\']csrf-token["\'][^>]*content=["\']([^"\']*)["\']', "csrf_meta"),
        (r'<script[^>]*>[^<]*csrf[^=]*=\s*["\']([^"\']+)["\']', "csrf_js_var"),
    ]

    def __init__(self):
        # Pre-compile all patterns
        self._compiled = {}
        for cat_name, patterns in [
            ("login", self.LOGIN_PATTERNS),
            ("register", self.REGISTER_PATTERNS),
            ("mfa", self.MFA_PATTERNS),
            ("oauth", self.OAUTH_PATTERNS),
            ("captcha", self.CAPTCHA_PATTERNS),
        ]:
            self._compiled[cat_name] = [
                (re.compile(p, re.IGNORECASE), w, t) for p, w, t in patterns
            ]

    async def detect(self, url: str, status_code: int, body: str,
                     headers: Dict[str, str] = None) -> AuthDetectionResult:
        """
        Run detection on a response and return structured results.
        """
        result = AuthDetectionResult(url=url, status_code=status_code)
        headers = headers or {}

        # 1. Check HTTP-level auth walls first
        if status_code == 429:
            result.auth_type = AUTH_TYPE_RATE_LIMIT
            result.confidence = 0.95
            result.evidence = "HTTP 429 Too Many Requests"
            result.matched_patterns.append("http_429")
            return result

        if status_code == 403:
            result.auth_type = AUTH_TYPE_403_WALL
            result.confidence = 0.7
            result.evidence = "HTTP 403 Forbidden"
            result.matched_patterns.append("http_403")
        elif status_code == 401:
            result.auth_type = AUTH_TYPE_401_WALL
            result.confidence = 0.9
            result.evidence = "HTTP 401 Unauthorized"
            result.matched_patterns.append("http_401")

        # 2. Scan body for auth patterns
        if not body or len(body) < 50:
            return result

        category_scores = {}
        category_patterns = {}
        category_hits = {}

        for cat_name, patterns in self._compiled.items():
            total = 0.0
            matched = []
            for pattern, weight, tag in patterns:
                if pattern.search(body):
                    total += weight
                    matched.append(tag)
            category_scores[cat_name] = total
            category_patterns[cat_name] = matched

        # 3. Determine the highest-confidence auth type
        if category_scores:
            best_cat = max(category_scores, key=category_scores.get)
            best_score = category_scores[best_cat]

            if best_score >= 0.5:
                result.matched_patterns.extend(category_patterns[best_cat])
                result.confidence = min(best_score, 1.0)

                if best_cat == "login":
                    result.auth_type = AUTH_TYPE_LOGIN
                    await self._extract_form_details(body, url, result)
                elif best_cat == "register":
                    result.auth_type = AUTH_TYPE_REGISTER
                    await self._extract_form_details(body, url, result)
                elif best_cat == "mfa":
                    result.auth_type = AUTH_TYPE_MFA
                elif best_cat == "oauth":
                    result.auth_type = AUTH_TYPE_OAUTH
                    result.oauth_provider = self._detect_oauth_provider(body)
                elif best_cat == "captcha":
                    result.auth_type = AUTH_TYPE_CAPTCHA

        # 4. Also check auth wall patterns on the body (for 403 pages with login forms)
        if result.auth_type in (AUTH_TYPE_403_WALL, AUTH_TYPE_401_WALL, AUTH_TYPE_UNKNOWN):
            for pattern in [
                r'(?:access\s*denied|access\s*forbidden|unauthorized)',
                r'(?:please\s*log\s*in|please\s*authenticate)',
            ]:
                if re.search(pattern, body, re.IGNORECASE):
                    # Wall + login form = probably a login page behind the wall
                    pass  # Keep current detection

        # 5. Extract CSRF token
        result.csrf_field, result.csrf_value = self._extract_csrf(body)

        if result.evidence:
            pass  # Already set from HTTP check
        elif result.matched_patterns:
            result.evidence = f"Matched: {', '.join(result.matched_patterns[:5])}"
        else:
            result.evidence = "No patterns matched"

        return result

    # ── Form extraction ────────────────────────────────────────

    async def _extract_form_details(self, body: str, base_url: str,
                                     result: AuthDetectionResult):
        """Extract form action, method, and input field names from HTML."""
        # Extract form tag with action and method
        form_match = re.search(
            r'<form[^>]*action=["\']([^"\']*)["\'][^>]*method=["\'](get|post)["\']',
            body, re.IGNORECASE,
        )
        if not form_match:
            form_match = re.search(
                r'<form[^>]*method=["\'](get|post)["\'][^>]*action=["\']([^"\']*)["\']',
                body, re.IGNORECASE,
            )
        if form_match:
            action = form_match.group(1) or form_match.group(2) or ""
            method = form_match.group(2) if form_match.lastindex and form_match.lastindex >= 2 else "POST"
            if action:
                result.form_action = urljoin(base_url, action)
            result.form_method = method.upper() if method else "POST"

        # Extract input fields
        for input_match in re.finditer(
            r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>',
            body, re.IGNORECASE,
        ):
            name = input_match.group(1)
            html = input_match.group(0)

            type_match = re.search(r'type=["\'](\w+)["\']', html, re.IGNORECASE)
            input_type = type_match.group(1).lower() if type_match else "text"

            if input_type in ("email", "text"):
                if not result.username_field:
                    result.username_field = name
            elif input_type == "password":
                if not result.password_field:
                    result.password_field = name
            elif input_type == "hidden":
                val_match = re.search(r'value=["\']([^"\']*)["\']', html)
                result.extra_fields[name] = val_match.group(1) if val_match else ""

    # ── CSRF extraction ────────────────────────────────────────

    def _extract_csrf(self, body: str) -> Tuple[Optional[str], Optional[str]]:
        """Extract CSRF token name and value from body."""
        for pattern, tag in self.CSRF_PATTERNS:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                if tag == "csrf_meta":
                    return ("_csrf_token", match.group(1))
                elif tag == "csrf_named":
                    return (match.group(1), match.group(2))
                elif tag == "csrf_js_var":
                    return ("csrf_token", match.group(1))
        return (None, None)

    # ── OAuth detection ────────────────────────────────────────

    def _detect_oauth_provider(self, body: str) -> Optional[str]:
        """Detect which OAuth provider is being used."""
        for provider, pattern in self.OAUTH_PROVIDERS.items():
            if re.search(pattern, body, re.IGNORECASE):
                return provider
        return None
