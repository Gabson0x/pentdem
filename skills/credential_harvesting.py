"""
Credential Harvesting — extract-only, never auto-use.

Extracts credentials, tokens, API keys from:
1. Response bodies (HTML, JSON, JS)
2. HTTP headers (Set-Cookie, Authorization)
3. HTML comments
4. JavaScript variables
5. Configuration files

Strategy: Extract → Report → Human decides.
"""

import re
from typing import Dict, List, Any, Set
from skills.base import BaseSkill, SkillResult


# Credential patterns (type, regex, severity)
CREDENTIAL_PATTERNS = [
    # API Keys
    ("API Key", r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']([^"\']{8,})["\']', "high"),
    ("API Key", r'(?i)x-api-key\s*[:=]\s*["\']([^"\']{8,})["\']', "high"),
    
    # Tokens
    ("Bearer Token", r'(?i)bearer\s+(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)', "high"),
    ("Access Token", r'(?i)(access[_-]?token)\s*[:=]\s*["\']([^"\']{8,})["\']', "high"),
    ("Auth Token", r'(?i)(auth[_-]?token)\s*[:=]\s*["\']([^"\']{8,})["\']', "high"),
    ("Session Token", r'(?i)(session[_-]?token)\s*[:=]\s*["\']([^"\']{8,})["\']', "medium"),
    
    # Cloud
    ("AWS Access Key", r'(?i)(AKIA[0-9A-Z]{16})', "critical"),
    ("AWS Secret Key", r'(?i)(aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*["\']([A-Za-z0-9/+=]{40})["\']', "critical"),
    ("GCP Key", r'(?i)(-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----)', "critical"),
    
    # GitHub
    ("GitHub Token", r'(?i)(ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36})', "critical"),
    ("GitHub OAuth", r'(?i)(github[_-]?oauth[_-]?token)\s*[:=]\s*["\']([^"\']{8,})["\']', "high"),
    
    # Slack
    ("Slack Token", r'(?i)(xox[baprs]-[A-Za-z0-9-]+)', "critical"),
    
    # Database
    ("Database URL", r'(?i)(mysql|postgres|postgresql|mongodb|redis)://[^"\']+', "critical"),
    ("Connection String", r'(?i)(connection[_-]?string|conn[_-]?str)\s*[:=]\s*["\']([^"\']{10,})["\']', "critical"),
    
    # Generic Secrets
    ("Secret", r'(?i)(secret[_-]?key|client[_-]?secret)\s*[:=]\s*["\']([^"\']{8,})["\']', "high"),
    ("Password", r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']([^"\']{4,})["\']', "high"),
    
    # JWT
    ("JWT Token", r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', "high"),
    
    # Private Keys
    ("Private Key", r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----', "critical"),
    
    # Webhook URLs
    ("Webhook URL", r'(?i)(https?://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+)', "critical"),
    
    # Hardcoded Credentials
    ("Hardcoded Password", r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{4,})["\']', "high"),
    ("Hardcoded Token", r'(?i)(?:token|secret)\s*[:=]\s*["\']([A-Za-z0-9+/=_-]{20,})["\']', "high"),
]


class CredentialHarvestingSkill(BaseSkill):
    """
    Extract credentials from responses — report only, never auto-use.
    """

    def can_handle(self, task_type: str) -> bool:
        return task_type in ["credential_harvesting", "credentials", "secrets", "harvest"]

    async def execute(self, context: Dict[str, Any]) -> SkillResult:
        urls = context.get("urls", [])
        response_bodies = context.get("response_bodies", [])
        
        findings = []
        seen_credentials = set()
        
        # Harvest from URLs
        for url in urls[:10]:
            body = await self._fetch_url(url)
            if body:
                creds = self._extract_credentials(body, url)
                for cred in creds:
                    cred_hash = f"{cred['type']}:{cred['value'][:20]}"
                    if cred_hash not in seen_credentials:
                        seen_credentials.add(cred_hash)
                        findings.append(cred)
        
        # Harvest from provided response bodies
        for body in response_bodies:
            creds = self._extract_credentials(body, "response_body")
            for cred in creds:
                cred_hash = f"{cred['type']}:{cred['value'][:20]}"
                if cred_hash not in seen_credentials:
                    seen_credentials.add(cred_hash)
                    findings.append(cred)
        
        # Check HTML comments specifically
        for url in urls[:5]:
            body = await self._fetch_url(url)
            if body:
                comment_creds = self._extract_from_comments(body, url)
                for cred in comment_creds:
                    cred_hash = f"{cred['type']}:{cred['value'][:20]}"
                    if cred_hash not in seen_credentials:
                        seen_credentials.add(cred_hash)
                        findings.append(cred)

        return SkillResult(
            success=True,
            findings=findings,
            data={"urls_scanned": len(urls), "credentials_found": len(findings)},
            next_skills=["validate"],
            confidence=min(len(findings) / 2, 1.0) if findings else 0.0,
        )

    async def _fetch_url(self, url: str) -> str:
        """Fetch URL content."""
        try:
            import asyncio
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "-L", "--max-time", "10",
                url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            return stdout.decode(errors="ignore")
        except Exception:
            return ""

    def _extract_credentials(self, body: str, source: str) -> List[Dict]:
        """Extract credentials from body content."""
        findings = []
        
        for cred_type, pattern, severity in CREDENTIAL_PATTERNS:
            matches = re.finditer(pattern, body)
            for match in matches:
                value = match.group(0)
                
                # Skip common false positives
                if self._is_false_positive(value, cred_type):
                    continue
                
                findings.append({
                    "type": "credential_exposure",
                    "url": source,
                    "severity": severity,
                    "confidence": 0.85,
                    "cvss_score": self._severity_to_cvss(severity),
                    "evidence": f"{cred_type} found: {value[:30]}...",
                    "payload": value,
                    "param": "Response Body",
                    "description": f"Exposed {cred_type} in HTTP response",
                    "source_tool": "credential-harvesting",
                    "warning": "EXTRACT ONLY — do not auto-use. Requires human verification.",
                })
        
        return findings

    def _extract_from_comments(self, body: str, source: str) -> List[Dict]:
        """Extract credentials from HTML comments."""
        findings = []
        
        # Extract HTML comments
        comments = re.findall(r'<!--(.*?)-->', body, re.DOTALL)
        for comment in comments:
            # Check for credentials in comments
            creds = self._extract_credentials(comment, f"{source} (HTML comment)")
            findings.extend(creds)
        
        return findings

    def _is_false_positive(self, value: str, cred_type: str) -> bool:
        """Check for common false positives."""
        false_positives = [
            "example", "test", "placeholder", "xxx", "your-",
            "changeme", "replace", "insert", "dummy", "sample",
            "fake", "mock", "debug", "todo", "fixme",
        ]
        value_lower = value.lower()
        return any(fp in value_lower for fp in false_positives)

    def _severity_to_cvss(self, severity: str) -> float:
        """Convert severity to CVSS score."""
        mapping = {
            "critical": 9.0,
            "high": 7.5,
            "medium": 5.0,
            "low": 2.5,
        }
        return mapping.get(severity, 5.0)
