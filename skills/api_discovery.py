"""
API Discovery via JavaScript Analysis — extract endpoints, secrets, hidden params.

Approach:
1. Fetch JS files linked from target pages
2. Regex extract: URLs, endpoints, API keys, tokens, internal hosts
3. Map authentication patterns (Bearer, API key, cookie names)
4. Identify hidden parameters and undocumented endpoints
"""

import asyncio
import re
from typing import Dict, List, Any, Set
from skills.base import BaseSkill, SkillResult


# Regex patterns for secret detection
SECRET_PATTERNS = [
    (r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']([^"\']{8,})["\']', "API Key"),
    (r'(?i)(secret[_-]?key|client_secret)\s*[:=]\s*["\']([^"\']{8,})["\']', "Secret Key"),
    (r'(?i)(access[_-]?token|auth[_-]?token)\s*[:=]\s*["\']([^"\']{8,})["\']', "Token"),
    (r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']([^"\']{4,})["\']', "Password"),
    (r'(?i)(aws[_-]?access[_-]?key[_-]?id)\s*[:=]\s*["\']([A-Z0-9]{20})["\']', "AWS Access Key"),
    (r'(?i)(aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*["\']([A-Za-z0-9/+=]{40})["\']', "AWS Secret Key"),
    (r'(?i)(ghp_[A-Za-z0-9]{36})', "GitHub Token"),
    (r'(?i)(sk-[A-Za-z0-9]{32,})', "OpenAI Key"),
    (r'(?i)(xox[baprs]-[A-Za-z0-9-]+)', "Slack Token"),
    (r'(?i)private[_-]?key\s*[:=]\s*["\']((?:-----BEGIN)?[A-Z ]+PRIVATE KEY)', "Private Key"),
]

# Patterns for endpoint discovery
ENDPOINT_PATTERNS = [
    r'["\'](/api/[^"\']{3,})["\']',
    r'["\'](/v[0-9]+/[^"\']{3,})["\']',
    r'["\'](/graphql[^"\']{0,30})["\']',
    r'["\'](/rest/[^"\']{3,})["\']',
    r'["\'](/internal/[^"\']{3,})["\']',
    r'["\'](/admin/[^"\']{3,})["\']',
    r'["\'](/debug/[^"\']{3,})["\']',
    r'["\'](/\.env[^"\']{0,10})["\']',
    r'["\'](/wp-json/[^"\']{3,})["\']',
    r'["\'](/graphql\?query=[^"\']{5,})["\']',
    r'fetch\s*\(\s*["\']([^"\']+)["\']',
    r'\.get\s*\(\s*["\']([^"\']+)["\']',
    r'\.post\s*\(\s*["\']([^"\']+)["\']',
    r'\.put\s*\(\s*["\']([^"\']+)["\']',
    r'\.delete\s*\(\s*["\']([^"\']+)["\']',
    r'url\s*[:=]\s*["\']([^"\']+)["\']',
    r'endpoint\s*[:=]\s*["\']([^"\']+)["\']',
    r'baseURL\s*[:=]\s*["\']([^"\']+)["\']',
    r'BASE_URL\s*[:=]\s*["\']([^"\']+)["\']',
]

# Internal host patterns
HOST_PATTERNS = [
    r'["\']https?://([a-z0-9.-]+\.(internal|local|corp|intra|private))["\']',
    r'["\']https?://(10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)["\']',
    r'["\']https?://(localhost|127\.0\.0\.1|0\.0\.0\.0)(?::\d+)?["\']',
]

# GraphQL introspection
GRAPHQL_INTROSPECT = '{"query":"{ __schema { queryType { name } mutationType { name } types { name kind fields { name type { name kind } } } } }"}'


class APIDiscoverySkill(BaseSkill):
    """
    Discover hidden APIs and secrets via JavaScript analysis.
    """

    def can_handle(self, task_type: str) -> bool:
        return task_type in ["api_discovery", "api", "js_analysis", "recon"]

    async def execute(self, context: Dict[str, Any]) -> SkillResult:
        target = context.get("target", "")
        urls = context.get("urls", [])
        
        findings = []
        
        # Step 1: Discover JS files from target pages
        js_urls = set()
        for url in urls[:5]:
            discovered = await self._discover_js_files(url)
            js_urls.update(discovered)
        
        # Add common JS paths
        for path in ["/static/js/", "/assets/js/", "/dist/", "/build/", "/public/"]:
            js_urls.add(f"https://{target}{path}")
        
        # Step 2: Analyze JS files
        all_secrets = set()
        all_endpoints = set()
        all_hosts = set()
        
        for js_url in list(js_urls)[:10]:
            content = await self._fetch_js(js_url)
            if not content:
                continue
            
            secrets = self._extract_secrets(content)
            endpoints = self._extract_endpoints(content)
            hosts = self._extract_hosts(content)
            
            for secret_type, secret_value in secrets:
                if secret_value not in all_secrets:
                    all_secrets.add(secret_value)
                    findings.append({
                        "type": "secret_exposure",
                        "url": js_url,
                        "severity": "high",
                        "confidence": 0.85,
                        "cvss_score": 7.5,
                        "evidence": f"{secret_type} found: {secret_value[:20]}...",
                        "payload": secret_value,
                        "param": "JavaScript Analysis",
                        "description": f"Exposed {secret_type} in JavaScript file",
                        "source_tool": "api-discovery",
                    })
            
            all_endpoints.update(endpoints)
            all_hosts.update(hosts)
        
        # Step 3: Test discovered endpoints
        for endpoint in list(all_endpoints)[:15]:
            if endpoint.startswith("/"):
                test_url = f"https://{target}{endpoint}"
            else:
                test_url = endpoint
            
            endpoint_finding = await self._test_endpoint(test_url)
            if endpoint_finding:
                findings.append(endpoint_finding)
        
        # Step 4: Test internal hosts (SSRF potential)
        for host in list(all_hosts)[:5]:
            findings.append({
                "type": "internal_host_exposure",
                "url": f"JS analysis of {target}",
                "severity": "medium",
                "confidence": 0.7,
                "cvss_score": 5.0,
                "evidence": f"Internal host referenced in JS: {host}",
                "payload": host,
                "param": "JavaScript Analysis",
                "description": f"Internal hostname/IP exposed in client-side JavaScript",
                "source_tool": "api-discovery",
            })
        
        # Step 5: Check for GraphQL introspection
        for url in urls[:5]:
            graphql_finding = await self._test_graphql(url)
            if graphql_finding:
                findings.append(graphql_finding)

        return SkillResult(
            success=True,
            findings=findings,
            data={
                "js_files_scanned": len(js_urls),
                "endpoints_found": len(all_endpoints),
                "secrets_found": len(all_secrets),
                "internal_hosts": len(all_hosts),
            },
            next_skills=["validate"],
            confidence=min(len(findings) / 5, 1.0) if findings else 0.0,
        )

    async def _discover_js_files(self, url: str) -> Set[str]:
        """Discover JavaScript files linked from a page."""
        js_files = set()
        try:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "-L", "--max-time", "10",
                url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            html = stdout.decode(errors="ignore")
            
            # Extract JS sources from script tags
            patterns = [
                r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']',
                r'<script[^>]+src=([^\s>]+\.js)',
                r'import\s+.*from\s+["\']([^"\']+\.js)["\']',
                r'loadScript\s*\(\s*["\']([^"\']+\.js)["\']',
            ]
            
            from urllib.parse import urljoin
            for pattern in patterns:
                for match in re.finditer(pattern, html):
                    js_url = urljoin(url, match.group(1))
                    js_files.add(js_url)
        except Exception:
            pass
        
        return js_files

    async def _fetch_js(self, url: str) -> str:
        """Fetch JavaScript file content."""
        try:
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

    def _extract_secrets(self, content: str) -> List[tuple]:
        """Extract secrets from JS content."""
        secrets = []
        for pattern, secret_type in SECRET_PATTERNS:
            for match in re.finditer(pattern, content):
                secrets.append((secret_type, match.group(0)))
        return secrets

    def _extract_endpoints(self, content: str) -> Set[str]:
        """Extract API endpoints from JS content."""
        endpoints = set()
        for pattern in ENDPOINT_PATTERNS:
            for match in re.finditer(pattern, content):
                endpoint = match.group(1)
                if len(endpoint) > 3 and not endpoint.endswith(('.png', '.jpg', '.gif', '.svg', '.css')):
                    endpoints.add(endpoint)
        return endpoints

    def _extract_hosts(self, content: str) -> Set[str]:
        """Extract internal hostnames from JS content."""
        hosts = set()
        for pattern in HOST_PATTERNS:
            for match in re.finditer(pattern, content):
                hosts.add(match.group(0))
        return hosts

    async def _test_endpoint(self, url: str) -> Dict[str, Any]:
        """Test a discovered endpoint."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "-i", "--max-time", "10", url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            response = stdout.decode(errors="ignore")
            
            import re
            status_match = re.search(r'HTTP/[\d.]+\s+(\d+)', response)
            status = int(status_match.group(1)) if status_match else 0
            
            if status not in (404, 0, 502, 503):
                # Check if response contains sensitive data
                body = response.lower()
                sensitive = any(x in body for x in ['password', 'secret', 'token', 'key', 'credential'])
                
                severity = "high" if sensitive and status == 200 else "info"
                if status == 200 and sensitive:
                    severity = "high"
                elif status == 200:
                    severity = "info"
                elif status in (401, 403):
                    severity = "info"  # Auth required, endpoint exists
                else:
                    return {}
                
                return {
                    "type": "api_endpoint_discovery",
                    "url": url,
                    "severity": severity,
                    "confidence": 0.8,
                    "cvss_score": 7.0 if severity == "high" else 0.0,
                    "evidence": f"HTTP {status} — {len(response)} bytes",
                    "payload": f"GET {url}",
                    "param": "URL",
                    "description": f"Undocumented API endpoint discovered (HTTP {status})",
                    "source_tool": "api-discovery",
                }
        except Exception:
            pass
        return {}

    async def _test_graphql(self, url: str) -> Dict[str, Any]:
        """Test for GraphQL introspection."""
        try:
            # Try common GraphQL paths
            for path in ["/graphql", "/api/graphql", "/v1/graphql", "/gql"]:
                graphql_url = url.rstrip("/") + path
                proc = await asyncio.create_subprocess_exec(
                    "curl", "-s", "-X", "POST",
                    "-H", "Content-Type: application/json",
                    "-d", GRAPHQL_INTROSPECT,
                    "--max-time", "10",
                    graphql_url,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate()
                response = stdout.decode(errors="ignore")
                
                if '"data"' in response and '"__schema"' in response:
                    return {
                        "type": "graphql_introspection",
                        "url": graphql_url,
                        "severity": "medium",
                        "confidence": 0.95,
                        "cvss_score": 5.0,
                        "evidence": "GraphQL introspection query returned schema",
                        "payload": GRAPHQL_INTROSPECT,
                        "param": "POST Body",
                        "description": "GraphQL introspection enabled — full API schema exposed",
                        "source_tool": "api-discovery",
                    }
        except Exception:
            pass
        return {}
