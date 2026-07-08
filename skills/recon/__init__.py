import asyncio
import json
import re
import sqlite3
from typing import Dict, Any, List
from urllib.parse import urlparse, parse_qs
from skills.base import BaseSkill, SkillResult
from tools import ToolExecutor
from adaptive_wordlist_engine import (
    ReconContext,
    build_adaptive_wordlist,
    init_memory_db,
    record_hit,
    write_wordlist,
)


class ReconSkill(BaseSkill):
    """Adaptive recon skill — context-aware, memory-backed, multi-model."""

    def __init__(self, mock: bool = False, use_docker: bool = False):
        super().__init__(mock)
        self.tools = ToolExecutor(mock=mock)
        self.use_docker = use_docker
        self._docker = None
        self._wl_conn = None

        if use_docker:
            try:
                from skills.docker_isolation import DockerIsolator
                self._docker = DockerIsolator()
            except Exception:
                self.use_docker = False

    def _get_wl_conn(self):
        if self._wl_conn is None:
            self._wl_conn = init_memory_db()
        return self._wl_conn

    def can_handle(self, task_type: str) -> bool:
        return task_type in ["recon", "subdomain_enum", "live_hosts", "url_crawl", "js_analysis"]

    async def execute(self, context: Dict[str, Any]) -> SkillResult:
        target = self._clean_target(context.get("target", ""))
        mode = context.get("mode", "full")

        if self.mock:
            return self._mock_response(target)

        data = {}
        findings = []
        import time, logging
        log = logging.getLogger("recon")
        t_start = time.time()

        # Phase 1: Subdomain enumeration + URL crawling in parallel
        log.info(f"[{target}] Phase 1: subdomain enumeration")
        subdomain_task = self._enumerate_subdomains(target)
        crawl_task = self._crawl_public_sources(target) if mode == "full" else None

        subdomains = await subdomain_task
        data["subdomains"] = subdomains
        data["subdomains_raw"] = subdomains
        log.info(f"[{target}] Phase 1 complete: {len(subdomains)} subdomains ({time.time()-t_start:.1f}s)")

        if crawl_task:
            public_urls = await crawl_task
            data["public_urls"] = public_urls
        else:
            public_urls = []

        # Phase 2: Live host detection
        t_phase2 = time.time()
        log.info(f"[{target}] Phase 2: live host detection")
        all_hosts = list(set(subdomains + [target]))
        live_hosts = await self._detect_live_hosts(all_hosts)
        data["live_hosts"] = live_hosts

        live_urls = [h.get("url", f"https://{h['host']}") for h in live_hosts if h.get("alive")]
        log.info(f"[{target}] Phase 2 complete: {len(live_urls)} live hosts ({time.time()-t_phase2:.1f}s)")

        # Phase 3: Deep crawling + directory fuzzing (parallelized across hosts)
        deep_urls = []
        fuzzed = []
        if mode == "full" and live_urls:
            t_phase3 = time.time()
            log.info(f"[{target}] Phase 3: crawling + fuzzing {len(live_urls)} hosts")
            # Parallelize across hosts: each host gets its own katana + ffuf tasks
            host_tasks = []
            for url in live_urls[:5]:  # cap at 5 hosts
                host_tasks.append(self._crawl_deep_single(url))
                host_tasks.append(self._fuzz_single_host(url))
            results = await asyncio.gather(*host_tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, Exception):
                    continue
                if isinstance(r, dict):
                    deep_urls.extend(r.get("deep", []))
                    fuzzed.extend(r.get("fuzz", []))
                elif isinstance(r, list):
                    deep_urls.extend(r)
            log.info(f"[{target}] Phase 3 complete: {len(deep_urls)} crawled + {len(fuzzed)} fuzzed ({time.time()-t_phase3:.1f}s)")

        all_urls = list(set(public_urls + deep_urls + fuzzed))
        data["urls"] = all_urls

        # Phase 4: Extract attack surface
        surface = self._extract_attack_surface(all_urls, target)
        data["attack_surface"] = surface

        # Phase 5: JS endpoint discovery
        js_files = [u for u in all_urls if u.endswith((".js", ".jsx", ".ts", ".tsx"))]
        js_endpoints = []
        if js_files:
            js_endpoints = await self._analyze_js_endpoints(js_files)
            data["js_endpoints"] = js_endpoints

        # Phase 6: Build adaptive wordlist for this target
        tech_stack = self._extract_tech_stack(live_hosts)
        data["tech_stack"] = tech_stack

        wl_conn = self._get_wl_conn()
        ctx = ReconContext(
            domain=target,
            tech_stack=tech_stack,
            discovered_paths=[u.replace(f"https://{target}", "").rstrip("/") or "/" for u in all_urls[:50]],
            js_endpoints=[e for endpoints in js_endpoints if isinstance(endpoints, dict) for e in endpoints.get("endpoints", [])],
            server_headers=self._extract_server_headers(live_hosts),
        )

        def _llm_call(prompt):
            """Synchronous LLM call for wordlist generation."""
            try:
                import httpx as req
                api_key = __import__("os").getenv("GLM_API_KEY", "")
                if api_key and not api_key.startswith("your_"):
                    resp = req.post(
                        "https://open.bigmodel.cn/api/paas/v4/chat/completions",
                        headers={"Authorization": f"Bearer {api_key}"},
                        json={
                            "model": "glm-4-flash",
                            "messages": [{"role": "user", "content": prompt}],
                            "temperature": 0.1,
                            "max_tokens": 1000,
                        },
                        timeout=10,
                    )
                    return resp.json()["choices"][0]["message"]["content"]
            except Exception:
                pass
            return "[]"

        wordlist = build_adaptive_wordlist(ctx, _llm_call, conn=wl_conn)
        data["adaptive_wordlist"] = wordlist
        data["wordlist_size"] = len(wordlist)

        # Record current paths for future learning
        for path in ctx.discovered_paths:
            record_hit(wl_conn, path, ",".join(sorted(tech_stack)), 200)

        # Phase 7: LLM analysis (with timeout)
        log.info(f"[{target}] Phase 7: LLM analysis")
        try:
            analysis = await asyncio.wait_for(self._analyze_target(target, data), timeout=15)
        except asyncio.TimeoutError:
            analysis = {"raw": "LLM analysis timed out", "parsed": False}
        data["analysis"] = analysis

        log.info(f"[{target}] Recon complete: {len(all_urls)} URLs, {len(findings)} findings ({time.time()-t_start:.1f}s)")

        return SkillResult(
            success=True,
            findings=findings,
            data=data,
            next_skills=["hunt"],
            confidence=0.9,
        )

    def _mock_response(self, target: str) -> SkillResult:
        return SkillResult(
            success=True,
            findings=[],
            data={
                "subdomains_raw": [f"api.{target}", f"admin.{target}", f"cdn.{target}", f"www.{target}"],
                "live_hosts": [
                    {"host": f"www.{target}", "url": f"https://www.{target}", "status": 200, "alive": True, "tech": ["Nginx", "PHP"]},
                    {"host": f"api.{target}", "url": f"https://api.{target}", "status": 200, "alive": True, "tech": ["Node.js", "Express"]},
                ],
                "urls": [f"https://www.{target}", f"https://api.{target}/v1/users", f"https://api.{target}/admin", f"https://api.{target}/graphql"],
                "attack_surface": {
                    "total_urls": 4,
                    "api_endpoints": [f"https://api.{target}/v1/users", f"https://api.{target}/graphql"],
                    "admin_panels": [f"https://api.{target}/admin"],
                    "unique_params": ["id", "user_id", "q", "redirect", "url"],
                },
                "tech_stack": ["Nginx", "PHP", "Node.js", "Express"],
                "js_endpoints": [],
                "adaptive_wordlist": ["admin", "api", ".env", "login", "graphql", "users", "config"],
                "wordlist_size": 7,
            },
            next_skills=["hunt"],
            confidence=0.9,
        )

    def _extract_tech_stack(self, live_hosts: list) -> list:
        """Extract unique tech stack from live hosts."""
        tech = set()
        for host in live_hosts:
            for t in host.get("tech", []):
                tech.add(t)
        return sorted(tech)

    def _extract_server_headers(self, live_hosts: list) -> dict:
        """Extract server headers from live hosts."""
        headers = {}
        for host in live_hosts:
            if host.get("webserver"):
                headers["Server"] = host["webserver"]
            if host.get("tech"):
                headers["X-Technologies"] = ", ".join(host["tech"][:5])
        return headers

    # ─── Tool Wrappers ──────────────────────────────────────────

    async def _run_tool(self, tool: str, args: list, timeout: int = None) -> dict:
        """Run a tool via Docker if configured, else locally."""
        if self._docker and self.use_docker:
            try:
                if tool == "subfinder":
                    result = await self._docker.run_subfinder(args[1] if len(args) > 1 else "")
                    return {"success": result.get("success", False), "stdout": result.get("output", ""), "stderr": ""}
                elif tool == "nuclei":
                    result = await self._docker.run_nuclei(args[0] if args else "")
                    return {"success": result.get("success", False), "stdout": result.get("output", ""), "stderr": ""}
                elif tool == "ffuf":
                    result = await self._docker.run_ffuf(args[1] if len(args) > 1 else "", args[3] if len(args) > 3 else "")
                    return {"success": result.get("success", False), "stdout": result.get("output", ""), "stderr": ""}
                elif tool == "nmap":
                    result = await self._docker.run_nmap(args[0] if args else "")
                    return {"success": result.get("success", False), "stdout": result.get("output", ""), "stderr": ""}
            except Exception:
                pass  # Fall back to local
        return await self.tools.run(tool, args, timeout=timeout)

    async def _enumerate_subdomains(self, target: str) -> list:
        result = await self._run_tool("subfinder", ["-d", target, "-silent", "-timeout", "10"], timeout=15)
        if result["success"] and result["stdout"].strip():
            return [line.strip() for line in result["stdout"].splitlines() if line.strip()]
        return [target]

    async def _crawl_public_sources(self, target: str) -> list:
        result = await self.tools.run("curl", [
            "-s", f"https://crt.sh/?q=%25.{target}&output=json"
        ])
        urls = set()
        if result["success"] and result["stdout"].strip():
            try:
                entries = json.loads(result["stdout"])
                for e in entries:
                    name = e.get("name_value", "")
                    urls.add(f"https://{name}")
            except json.JSONDecodeError:
                pass

        if not urls:
            urls.add(f"https://{target}")
        return list(urls)

    async def _detect_live_hosts(self, hosts: list) -> list:
        if not hosts:
            return []

        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('\n'.join(hosts))
            tmp_path = f.name

        try:
            result = await self.tools.run("httpx", [
                "-l", tmp_path,
                "-silent",
                "-status-code",
                "-tech-detect",
                "-title",
                "-json",
                "-timeout", "10",
                "-retries", "1",
            ])
            if result["success"]:
                return self._parse_httpx_output(result["stdout"])
        finally:
            import os
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

        return [{"host": h, "alive": False} for h in hosts]

    def _parse_httpx_output(self, output: str) -> list:
        hosts = []
        for line in output.splitlines():
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
                hosts.append({
                    "host": entry.get("host", ""),
                    "url": entry.get("url", ""),
                    "status": entry.get("status_code", 0),
                    "title": entry.get("title", ""),
                    "tech": entry.get("tech", []),
                    "webserver": entry.get("webserver", ""),
                    "alive": entry.get("status_code", 0) > 0,
                    "content_type": entry.get("content_type", ""),
                })
            except json.JSONDecodeError:
                parts = line.split()
                if parts:
                    hosts.append({
                        "host": parts[-1] if len(parts) > 1 else parts[0],
                        "status": parts[0] if parts[0].isdigit() else 0,
                        "alive": False,
                    })
        return hosts

    _FUZZ_WORDLIST = "\n".join([
        "admin", "administrator", "login", "logout", "api", "api/v1", "api/v2",
        "dashboard", "portal", "console", "manage", "management",
        "uploads", "upload", "files", "assets", "static", "media",
        "test", "testing", "dev", "staging", "demo", "sandbox",
        "internal", "private", "secret", "hidden", "temp", "tmp",
        ".env", ".env.local", ".env.production",
        "config", "config.php", "config.json", "config.yml", "config.yaml",
        "settings.py", "settings.json", "web.config", "app.config",
        ".git", ".git/config", ".git/HEAD", ".gitignore",
        "robots.txt", "sitemap.xml", "crossdomain.xml",
        "server-status", "server-info", "phpinfo.php", "info.php",
        "swagger.json", "swagger-ui.html", "openapi.json", "graphql",
        "actuator", "actuator/health", "actuator/env",
        "debug", "trace", "elmah.axd",
        "wp-admin", "wp-content", "wp-includes", "wp-login.php",
        "wp-config.php", "wp-json", "xmlrpc.php",
    ])

    async def _crawl_deep_single(self, url: str) -> list:
        """Crawl a single URL with katana (15s timeout)."""
        try:
            result = await self._run_tool("katana", [
                "-u", url, "-d", "2", "-silent", "-jc", "-kf",
                "-timeout", "8",
            ], timeout=15)
            if result["success"] and result["stdout"].strip():
                return [u.strip() for u in result["stdout"].splitlines() if u.strip()]
        except Exception:
            pass
        return []

    async def _fuzz_single_host(self, url: str) -> list:
        """Fuzz a single host with ffuf (10s timeout)."""
        discovered = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(self._FUZZ_WORDLIST)
            tmp_path = f.name

        try:
            result = await self._run_tool("ffuf", [
                "-u", f"{base}/FUZZ",
                "-w", tmp_path,
                "-t", "20",
                "-mc", "200,204,301,302,307,401,403,405,500",
                "-s",
                "-timeout", "8",
            ], timeout=10)
            if result["success"] and result["stdout"].strip():
                for line in result["stdout"].splitlines():
                    if line.strip():
                        word = line.split()[0]
                        discovered.append(f"{base}/{word}")
        except Exception:
            pass
        finally:
            import os
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

        return discovered

    async def _crawl_deep(self, urls: list) -> list:
        """Legacy: crawl multiple URLs (kept for backward compat)."""
        if not urls:
            return []
        tasks = [self._crawl_deep_single(u) for u in urls[:3]]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        out = []
        for r in results:
            if isinstance(r, list):
                out.extend(r)
        return out

    async def _fuzz_directories(self, urls: list) -> list:
        """Legacy: fuzz multiple hosts (kept for backward compat)."""
        if not urls:
            return []
        tasks = [self._fuzz_single_host(u) for u in urls[:3]]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        out = []
        for r in results:
            if isinstance(r, list):
                out.extend(r)
        return out

    def _extract_attack_surface(self, urls: list, target: str) -> dict:
        endpoints = set()
        params = set()
        paths = set()
        api_endpoints = set()
        admin_panels = set()
        js_files = set()

        patterns = {
            "api": re.compile(r"/api/|/v\d+/|/graphql|/rest/"),
            "admin": re.compile(r"/admin|/dashboard|/manage|/wp-admin|/login"),
            "upload": re.compile(r"/upload|/file|/attach"),
        }

        for url in urls:
            parsed = urlparse(url)
            path = parsed.path
            if path:
                paths.add(path)

            if patterns["api"].search(path):
                api_endpoints.add(url)

            if patterns["admin"].search(path):
                admin_panels.add(url)

            if patterns["upload"].search(path):
                endpoints.add(("upload_endpoint", url))

            if url.endswith((".js", ".jsx", ".mjs")):
                js_files.add(url)

            if parsed.query:
                qs = parse_qs(parsed.query)
                for p in qs:
                    params.add(p)

        return {
            "total_urls": len(urls),
            "unique_paths": sorted(paths),
            "unique_params": sorted(params),
            "api_endpoints": sorted(api_endpoints),
            "admin_panels": sorted(admin_panels),
            "js_files": sorted(js_files),
            "endpoints": list(endpoints),
        }

    async def _analyze_target(self, target: str, data: dict) -> dict:
        live_summary = [
            {
                "url": h.get("url", ""),
                "status": h.get("status", 0),
                "tech": h.get("tech", []),
                "title": h.get("title", ""),
            }
            for h in data.get("live_hosts", [])
            if h.get("alive")
        ]

        surface = data.get("attack_surface", {})
        wordlist_preview = data.get("adaptive_wordlist", [])[:20]

        prompt = f"""Analyze this recon data for security testing prioritization:

Target: {target}
Tech Stack: {', '.join(data.get('tech_stack', []))}
Live Hosts: {json.dumps(live_summary[:10], indent=2)}
API Endpoints: {json.dumps(surface.get('api_endpoints', [])[:20], indent=2)}
Parameters Found: {json.dumps(surface.get('unique_params', [])[:30], indent=2)}
Admin Panels: {json.dumps(surface.get('admin_panels', [])[:10], indent=2)}
Adaptive Wordlist Preview: {json.dumps(wordlist_preview)}

Return a JSON object:
{{
    "tech_stack": ["list", "of", "technologies"],
    "highest_risk_endpoints": ["urls", "most", "interesting"],
    "recommended_tests": ["idor", "ssrf", "xss", ...],
    "attack_vectors": ["auth_bypass", "api_misconfig", ...],
    "notes": "strategic analysis of where to focus"
}}"""

        response = await self.llm_analyze(prompt)
        try:
            return json.loads(response) if response.strip().startswith("{") else {"raw": response}
        except (json.JSONDecodeError, ValueError):
            return {"raw": response[:500], "parsed": False}

    async def _analyze_js_endpoints(self, js_files: list) -> list:
        if not js_files:
            return []

        results = []
        for js_url in js_files[:5]:
            result = await self.tools.run("curl", ["-s", js_url])
            if result["success"]:
                content = result["stdout"][:10000]
                prompt = f"""Extract API endpoints, secrets, and interesting patterns from this JavaScript:

URL: {js_url}
Content:
{content}

Return JSON:
{{
    "endpoints": ["found endpoints"],
    "secrets": ["api keys, tokens, etc"],
    "interesting_patterns": ["internal paths, hidden features"]
}}"""
                analysis = await self.llm_analyze(prompt)
                try:
                    parsed = json.loads(analysis)
                    parsed["source"] = js_url
                    results.append(parsed)
                except (json.JSONDecodeError, ValueError):
                    results.append({"source": js_url, "raw": analysis[:500]})
        return results

    @staticmethod
    def _clean_target(target: str) -> str:
        target = target.strip().lower()
        target = re.sub(r"^https?://", "", target)
        target = re.sub(r"/.*$", "", target)
        return target
