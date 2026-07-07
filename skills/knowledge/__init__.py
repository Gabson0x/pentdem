import asyncio
import json
import os
import re
import sqlite3
from typing import Dict, Any, List, Optional
from datetime import datetime
from skills.base import BaseSkill, SkillResult
from tools import ToolExecutor


class KnowledgeSkill(BaseSkill):
    """Autonomous knowledge system — fetches disclosed reports, extracts patterns, feeds the hunt.

    Sources:
      - HackerOne Hacktivity (disclosed reports feed)
      - Individual disclosed report pages
      - Cached in SQLite for offline querying
    """

    SOURCES = {
        "hackerone": {
            "hacktivity": "https://hackerone.com/hacktivity?sort_type=latest_disclosable_activity&page=1&range=week",
            "report_base": "https://hackerone.com/reports/",
        },
    }

    VULN_CLASS_KEYWORDS = {
        "XSS": ["cross-site", "xss", "script", "stored xss", "reflected xss", "dom-based"],
        "SSRF": ["ssrf", "server-side request", "internal request", "metadata"],
        "SQLi": ["sql injection", "sqli", "mysql", "postgresql", "database"],
        "IDOR": ["idor", "insecure direct", "object reference", "access control", "authorization"],
        "Auth Bypass": ["auth bypass", "authentication bypass", "privilege escalation", "admin access"],
        "SSTI": ["ssti", "template injection", "server-side template", "jinja", "twig", "freemarker"],
        "Open Redirect": ["open redirect", "url redirect", "unvalidated redirect"],
        "LFI": ["lfi", "local file inclusion", "path traversal", "directory traversal"],
        "Command Injection": ["command injection", "rce", "remote code execution", "os command"],
        "NoSQLi": ["nosql", "mongodb injection", "mongo injection"],
        "GraphQL": ["graphql", "introspection", "graphql injection"],
        "CSRF": ["csrf", "cross-site request forgery", "request forgery"],
        "Race Condition": ["race condition", "time-of-check", "toctou"],
        "Business Logic": ["business logic", "logic flaw", "logic bug"],
        "File Upload": ["file upload", "unrestricted upload", "arbitrary file"],
        "Information Disclosure": ["information disclosure", "info leak", "data leak", "pii"],
    }

    def __init__(self, mock: bool = False):
        super().__init__(mock)
        self.tools = ToolExecutor(mock=mock)
        db_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
        os.makedirs(db_dir, exist_ok=True)
        self.db_path = os.path.join(db_dir, "pentest.db")
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.executescript("""
            CREATE TABLE IF NOT EXISTS disclosed_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT,
                report_id TEXT,
                title TEXT,
                vulnerability_class TEXT,
                severity TEXT,
                cvss_score REAL,
                target_tech TEXT,
                attack_vector TEXT,
                endpoint_pattern TEXT,
                parameter TEXT,
                payload TEXT,
                impact TEXT,
                remediation TEXT,
                url TEXT UNIQUE,
                fetched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS knowledge_tags (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id INTEGER,
                tag TEXT,
                FOREIGN KEY (report_id) REFERENCES disclosed_reports(id)
            );
            CREATE INDEX IF NOT EXISTS idx_reports_class ON disclosed_reports(vulnerability_class);
            CREATE INDEX IF NOT EXISTS idx_reports_tech ON disclosed_reports(target_tech);
            CREATE INDEX IF NOT EXISTS idx_tags ON knowledge_tags(tag);
        """)
        conn.commit()
        conn.close()

    def can_handle(self, task_type: str) -> bool:
        return task_type in [
            "knowledge", "learn", "fetch_reports", "query_knowledge",
            "search_disclosed", "update_knowledge",
        ]

    async def execute(self, context: Dict[str, Any]) -> SkillResult:
        action = context.get("action", "fetch")

        if action == "fetch":
            return await self._fetch_and_learn(context)
        elif action == "query":
            return await self._query_knowledge(context)
        elif action == "inject":
            return await self._inject_knowledge(context)
        elif action == "stats":
            return await self._knowledge_stats()
        elif action == "search":
            return await self._search_reports(context)

        return SkillResult(
            success=False, findings=[], data={"error": f"Unknown action: {action}"},
            next_skills=[], confidence=0.0,
        )

    # ─── Fetch & Parse ──────────────────────────────────────────────

    async def _fetch_and_learn(self, context: dict) -> SkillResult:
        """Fetch disclosed reports from all sources and store patterns."""
        sources = context.get("sources", ["hackerone"])
        limit = context.get("limit", 25)
        stats = {"fetched": 0, "parsed": 0, "new": 0, "errors": 0}

        if self.mock:
            mock_data = self._mock_query("", "", limit)
            for r in mock_data.data["reports"]:
                self._store_report(r)
                stats["fetched"] += 1
                stats["parsed"] += 1
                stats["new"] += 1
            return SkillResult(
                success=True,
                findings=[],
                data={
                    "action": "fetch_complete",
                    "stats": stats,
                    "total_reports": self._count_reports(),
                },
                next_skills=[],
                confidence=1.0,
            )

        for source in sources:
            if source == "hackerone":
                result = await self._fetch_hackerone_hacktivity(limit)
                stats["fetched"] += result.get("fetched", 0)
                stats["parsed"] += result.get("parsed", 0)
                stats["new"] += result.get("new", 0)
                stats["errors"] += result.get("errors", 0)

        return SkillResult(
            success=True,
            findings=[],
            data={
                "action": "fetch_complete",
                "stats": stats,
                "total_reports": self._count_reports(),
            },
            next_skills=[],
            confidence=1.0 if stats["errors"] == 0 else 0.8,
        )

    async def _fetch_hackerone_hacktivity(self, limit: int = 25) -> dict:
        """Fetch HackerOne hacktivity feed for disclosed reports."""
        stats = {"fetched": 0, "parsed": 0, "new": 0, "errors": 0}

        # Fetch hacktivity page
        url = self.SOURCES["hackerone"]["hacktivity"]
        result = await self.tools.run("curl", [
            "-s",
            "-H", "User-Agent: Mozilla/5.0 (compatible; AI-Pentest-Daemon/2.0; +https://github.com/ai-pentest-daemon)",
            "-H", "Accept: text/html,application/json",
            url,
        ])

        if not result.get("success"):
            stats["errors"] += 1
            return stats

        html = result.get("stdout", "")
        report_urls = self._extract_report_urls(html)

        for report_url in report_urls[:limit]:
            try:
                parsed = await self._fetch_and_parse_report(report_url)
                if parsed:
                    stats["parsed"] += 1
                    if self._store_report(parsed):
                        stats["new"] += 1
                stats["fetched"] += 1
            except Exception:
                stats["errors"] += 1

        return stats

    def _extract_report_urls(self, html: str) -> list:
        """Extract HackerOne report URLs from HTML."""
        urls = set()
        patterns = [
            r'href="https://hackerone\.com/reports/(\d+)"',
            r'/reports/(\d+)',
            r'href="https://hackerone\.com/reports/\d+',
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, html):
                rid = match.group(1) if match.lastindex else match.group(0)
                if rid.isdigit():
                    urls.add(f"https://hackerone.com/reports/{rid}")
                elif "hackerone.com/reports/" in rid:
                    urls.add(rid.split('"')[0] if '"' in rid else rid)

        return list(urls)

    async def _fetch_and_parse_report(self, report_url: str) -> Optional[dict]:
        """Fetch an individual disclosed report and parse it."""
        result = await self.tools.run("curl", [
            "-s",
            "-H", "User-Agent: Mozilla/5.0 (compatible; AI-Pentest-Daemon/2.0)",
            "-H", "Accept: text/html",
            report_url,
        ])

        if not result.get("success"):
            return None

        html = result.get("stdout", "")
        if not html or "Page not found" in html:
            return None

        return await self._parse_report_html(report_url, html)

    async def _parse_report_html(self, url: str, html: str) -> Optional[dict]:
        """Parse report HTML using LLM to extract structured data."""

        if self.mock:
            return self._mock_parsed_report(url)

        # Truncate to reduce token usage
        html_snippet = html[:8000]

        prompt = f"""Parse this HackerOne disclosed report and extract structured vulnerability data.

Report URL: {url}
HTML Content:
{html_snippet}

Return JSON with these fields (use null if not found):
{{
    "report_id": "the numeric ID from the URL",
    "title": "report title",
    "vulnerability_class": "one of: XSS, SSRF, SQLi, IDOR, Auth Bypass, SSTI, Open Redirect, LFI, Command Injection, NoSQLi, GraphQL, CSRF, Race Condition, Business Logic, File Upload, Information Disclosure, or Other",
    "severity": "critical/high/medium/low/none",
    "cvss_score": numeric score or null,
    "target_tech": "comma-separated tech stack if mentioned",
    "attack_vector": "how the attacker exploited this (1-2 sentences)",
    "endpoint_pattern": "the vulnerable URL pattern (e.g. /api/v1/users/{{id}})",
    "parameter": "the vulnerable parameter name, if applicable",
    "payload": "exact payload used, if shown in the report",
    "impact": "what the attacker achieved",
    "remediation": "how they fixed it, if mentioned"
}}"""

        response = await self.llm_analyze(prompt)
        try:
            parsed = json.loads(response)
            parsed["url"] = url
            parsed["source"] = "hackerone"
            return parsed
        except (json.JSONDecodeError, ValueError):
            return None

    def _mock_parsed_report(self, url: str) -> dict:
        """Return mock parsed reports for testing."""
        mock_reports = [
            {
                "report_id": "123456",
                "title": "Stored XSS in user profile name field",
                "vulnerability_class": "XSS",
                "severity": "high",
                "cvss_score": 6.1,
                "target_tech": "React, Node.js, MongoDB",
                "attack_vector": "Attacker submitted malicious script in the display name field which was rendered unsanitized in the admin panel",
                "endpoint_pattern": "/api/v1/users/profile",
                "parameter": "display_name",
                "payload": "<img src=x onerror=alert(document.cookie)>",
                "impact": "Account takeover of any admin user who views the profile",
                "remediation": "Implemented DOMPurify sanitization on user input before rendering",
                "url": url,
                "source": "hackerone",
            },
            {
                "report_id": "123457",
                "title": "IDOR allows viewing any user's private messages",
                "vulnerability_class": "IDOR",
                "severity": "high",
                "cvss_score": 6.5,
                "target_tech": "Ruby on Rails, PostgreSQL",
                "attack_vector": "Changed message_id parameter to enumerate other users' private messages",
                "endpoint_pattern": "/api/v1/messages/{message_id}",
                "parameter": "message_id",
                "payload": "Changed message_id from 1 to 2, 3, 4... via integer enumeration",
                "impact": "An attacker can read any user's private messages by iterating message IDs",
                "remediation": "Added ownership check before returning message data",
                "url": url,
                "source": "hackerone",
            },
            {
                "report_id": "123458",
                "title": "SSRF in PDF export feature leads to internal network scan",
                "vulnerability_class": "SSRF",
                "severity": "critical",
                "cvss_score": 8.6,
                "target_tech": "Python, Flask, wkhtmltopdf",
                "attack_vector": "The PDF export feature accepts a URL to render — attacker used it to probe internal network",
                "endpoint_pattern": "/api/v1/export/pdf?url={target_url}",
                "parameter": "url",
                "payload": "http://169.254.169.254/latest/meta-data/",
                "impact": "Access to cloud metadata service exposing AWS credentials",
                "remediation": "Added URL allowlist and blocked private IP ranges",
                "url": url,
                "source": "hackerone",
            },
            {
                "report_id": "123459",
                "title": "SQL injection in search endpoint",
                "vulnerability_class": "SQLi",
                "severity": "critical",
                "cvss_score": 9.8,
                "target_tech": "PHP, MySQL, Apache",
                "attack_vector": "Search query parameter was directly concatenated into SQL query without sanitization",
                "endpoint_pattern": "/search?q={query}",
                "parameter": "q",
                "payload": "' UNION SELECT username,password FROM users--",
                "impact": "An attacker can extract all user credentials from the database",
                "remediation": "Switched to parameterized prepared statements",
                "url": url,
                "source": "hackerone",
            },
            {
                "report_id": "123460",
                "title": "SSTI in email template leads to RCE",
                "vulnerability_class": "SSTI",
                "severity": "critical",
                "cvss_score": 9.8,
                "target_tech": "Python, Jinja2, Django",
                "attack_vector": "User-controlled name field was injected into email template rendered server-side",
                "endpoint_pattern": "/api/v1/send-invite",
                "parameter": "name",
                "payload": "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
                "impact": "Remote code execution on the email server",
                "remediation": "Switched to string formatting instead of template rendering for user input",
                "url": url,
                "source": "hackerone",
            },
            {
                "report_id": "123461",
                "title": "Open redirect in OAuth callback allows token theft",
                "vulnerability_class": "Open Redirect",
                "severity": "medium",
                "cvss_score": 4.3,
                "target_tech": "Node.js, Express, Passport.js",
                "attack_vector": "The redirect_uri parameter in OAuth flow was not validated, allowing redirection to attacker domain",
                "endpoint_pattern": "/auth/callback?redirect_uri={url}",
                "parameter": "redirect_uri",
                "payload": "https://evil.com/steal-token",
                "impact": "OAuth authorization code can be stolen via open redirect",
                "remediation": "Implemented redirect URI allowlist validation",
                "url": url,
                "source": "hackerone",
            },
            {
                "report_id": "123462",
                "title": "LFI via path traversal in file download",
                "vulnerability_class": "LFI",
                "severity": "high",
                "cvss_score": 7.5,
                "target_tech": "PHP, Linux, Apache",
                "attack_vector": "The file download endpoint did not sanitize path parameter allowing directory traversal",
                "endpoint_pattern": "/download?file={path}",
                "parameter": "file",
                "payload": "../../../etc/passwd",
                "impact": "An attacker can read any file on the server including configuration files with credentials",
                "remediation": "Implemented path canonicalization and restricted access to the uploads directory only",
                "url": url,
                "source": "hackerone",
            },
            {
                "report_id": "123463",
                "title": "Command injection in ping tool",
                "vulnerability_class": "Command Injection",
                "severity": "critical",
                "cvss_score": 9.8,
                "target_tech": "Python, Flask, Ubuntu",
                "attack_vector": "The ping tool passed user input directly to os.system() without sanitization",
                "endpoint_pattern": "/tools/ping?host={ip}",
                "parameter": "host",
                "payload": "127.0.0.1; id",
                "impact": "Remote code execution on the server",
                "remediation": "Replaced os.system() with subprocess and input validation",
                "url": url,
                "source": "hackerone",
            },
            {
                "report_id": "123464",
                "title": "Auth bypass via header injection",
                "vulnerability_class": "Auth Bypass",
                "severity": "critical",
                "cvss_score": 9.1,
                "target_tech": "Java, Spring Boot, Tomcat",
                "attack_vector": "The admin panel trusts X-Forwarded-For and X-Admin headers for authorization",
                "endpoint_pattern": "/admin/dashboard",
                "parameter": "X-Admin header",
                "payload": "X-Admin: true",
                "impact": "Anyone can access the admin panel by adding a simple HTTP header",
                "remediation": "Removed header-based authentication, implemented proper session-based auth",
                "url": url,
                "source": "hackerone",
            },
            {
                "report_id": "123465",
                "title": "GraphQL introspection reveals admin mutations",
                "vulnerability_class": "GraphQL",
                "severity": "medium",
                "cvss_score": 5.3,
                "target_tech": "Node.js, Apollo GraphQL, React",
                "attack_vector": "GraphQL endpoint had introspection enabled revealing all types and mutations including admin-only operations",
                "endpoint_pattern": "/graphql",
                "parameter": "query",
                "payload": "{__schema{types{name fields{name}}}}",
                "impact": "Attacker can discover and call undocumented admin mutations",
                "remediation": "Disabled introspection in production, implemented query depth limiting",
                "url": url,
                "source": "hackerone",
            },
            {
                "report_id": "123466",
                "title": "NoSQL injection bypasses login",
                "vulnerability_class": "NoSQLi",
                "severity": "high",
                "cvss_score": 9.3,
                "target_tech": "Node.js, MongoDB, Express",
                "attack_vector": "Login endpoint passed JSON body directly to MongoDB query without sanitization",
                "endpoint_pattern": "/api/v1/login",
                "parameter": "password",
                "payload": '{"$gt": ""}',
                "impact": "An attacker can bypass authentication by injecting MongoDB operators",
                "remediation": "Implemented input validation and type checking before database queries",
                "url": url,
                "source": "hackerone",
            },
        ]
        rid_match = re.search(r"/reports/(\d+)", url)
        rid = rid_match.group(1) if rid_match else "999999"

        for r in mock_reports:
            r["report_id"] = rid
            r["url"] = url
        return mock_reports[hash(rid) % len(mock_reports)]

    # ─── Storage ────────────────────────────────────────────────────

    def _store_report(self, report: dict) -> bool:
        """Store parsed report in SQLite, returns True if new."""
        if not report or not report.get("url"):
            return False

        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        try:
            c.execute(
                """INSERT OR IGNORE INTO disclosed_reports
                   (source, report_id, title, vulnerability_class, severity, cvss_score,
                    target_tech, attack_vector, endpoint_pattern, parameter, payload,
                    impact, remediation, url)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    report.get("source", "hackerone"),
                    report.get("report_id", ""),
                    report.get("title", "")[:500],
                    report.get("vulnerability_class", "Other"),
                    report.get("severity", "medium"),
                    report.get("cvss_score"),
                    report.get("target_tech", "")[:500],
                    report.get("attack_vector", "")[:2000],
                    report.get("endpoint_pattern", "")[:500],
                    report.get("parameter", "")[:200],
                    report.get("payload", "")[:2000],
                    report.get("impact", "")[:2000],
                    report.get("remediation", "")[:2000],
                    report.get("url", ""),
                ),
            )
            was_new = c.rowcount > 0
            conn.commit()
            return was_new
        except sqlite3.IntegrityError:
            return False
        finally:
            conn.close()

    # ─── Query ──────────────────────────────────────────────────────

    async def _query_knowledge(self, context: dict) -> SkillResult:
        """Query knowledge base for relevant reports."""
        vuln_class = context.get("vuln_class", "")
        tech = context.get("tech", "")
        endpoint = context.get("endpoint", "")
        limit = context.get("limit", 10)

        if self.mock:
            return self._mock_query(vuln_class, tech, limit)

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        conditions = []
        params = []

        if vuln_class:
            conditions.append("vulnerability_class = ?")
            params.append(vuln_class)
        if tech:
            conditions.append("(target_tech LIKE ? OR target_tech LIKE ?)")
            params.extend([f"%{tech}%", f"%{tech.lower()}%"])

        where = " AND ".join(conditions) if conditions else "1=1"

        c.execute(
            f"SELECT * FROM disclosed_reports WHERE {where} ORDER BY fetched_at DESC LIMIT ?",
            params + [limit],
        )
        reports = [dict(r) for r in c.fetchall()]
        conn.close()

        return SkillResult(
            success=True,
            findings=[],
            data={
                "reports": reports,
                "count": len(reports),
                "query": {"vuln_class": vuln_class, "tech": tech},
            },
            next_skills=[],
            confidence=1.0 if reports else 0.0,
        )

    def _mock_query(self, vuln_class: str, tech: str, limit: int) -> SkillResult:
        """Return mock knowledge for testing."""
        all_mock = [
            {"source": "hackerone", "report_id": "123456", "title": "Stored XSS in user profile name field", "vulnerability_class": "XSS", "severity": "high", "cvss_score": 6.1, "target_tech": "React, Node.js, MongoDB", "attack_vector": "XSS via unsanitized display name field", "endpoint_pattern": "/api/v1/users/profile", "parameter": "display_name", "payload": "<img src=x onerror=alert(document.cookie)>", "impact": "Account takeover of admin users", "remediation": "DOMPurify sanitization", "url": "https://hackerone.com/reports/123456"},
            {"source": "hackerone", "report_id": "123457", "title": "IDOR allows viewing any user's private messages", "vulnerability_class": "IDOR", "severity": "high", "cvss_score": 6.5, "target_tech": "Ruby on Rails, PostgreSQL", "attack_vector": "IDOR via message_id enumeration", "endpoint_pattern": "/api/v1/messages/{message_id}", "parameter": "message_id", "payload": "Integer ID enumeration (1,2,3...)", "impact": "Read any user's private messages", "remediation": "Ownership check on message access", "url": "https://hackerone.com/reports/123457"},
            {"source": "hackerone", "report_id": "123458", "title": "SSRF in PDF export leads to internal network scan", "vulnerability_class": "SSRF", "severity": "critical", "cvss_score": 8.6, "target_tech": "Python, Flask, wkhtmltopdf", "attack_vector": "SSRF via URL parameter in PDF export", "endpoint_pattern": "/api/v1/export/pdf?url={target_url}", "parameter": "url", "payload": "http://169.254.169.254/latest/meta-data/", "impact": "Cloud metadata credentials exposed", "remediation": "URL allowlist + private IP block", "url": "https://hackerone.com/reports/123458"},
            {"source": "hackerone", "report_id": "123459", "title": "SQL injection in search endpoint", "vulnerability_class": "SQLi", "severity": "critical", "cvss_score": 9.8, "target_tech": "PHP, MySQL, Apache", "attack_vector": "SQLi via search query parameter", "endpoint_pattern": "/search?q={query}", "parameter": "q", "payload": "' UNION SELECT username,password FROM users--", "impact": "Extract all user credentials", "remediation": "Parameterized prepared statements", "url": "https://hackerone.com/reports/123459"},
            {"source": "hackerone", "report_id": "123460", "title": "Auth bypass via admin header", "vulnerability_class": "Auth Bypass", "severity": "critical", "cvss_score": 9.1, "target_tech": "Java, Spring Boot, Tomcat", "attack_vector": "Auth bypass via X-Admin header", "endpoint_pattern": "/admin/dashboard", "parameter": "X-Admin", "payload": "X-Admin: true", "impact": "Anyone can access admin panel via header", "remediation": "Remove header-based auth", "url": "https://hackerone.com/reports/123460"},
            {"source": "hackerone", "report_id": "123461", "title": "SSTI in email template leads to RCE", "vulnerability_class": "SSTI", "severity": "critical", "cvss_score": 9.8, "target_tech": "Python, Jinja2, Django", "attack_vector": "SSTI via user name in email template", "endpoint_pattern": "/api/v1/send-invite", "parameter": "name", "payload": "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}", "impact": "Remote code execution on server", "remediation": "String formatting instead of template rendering", "url": "https://hackerone.com/reports/123461"},
            {"source": "hackerone", "report_id": "123462", "title": "Open redirect in OAuth callback", "vulnerability_class": "Open Redirect", "severity": "medium", "cvss_score": 4.3, "target_tech": "Node.js, Express, Passport.js", "attack_vector": "Open redirect via unvalidated redirect_uri", "endpoint_pattern": "/auth/callback?redirect_uri={url}", "parameter": "redirect_uri", "payload": "https://evil.com/steal-token", "impact": "OAuth token theft via redirect", "remediation": "Redirect URI allowlist", "url": "https://hackerone.com/reports/123462"},
            {"source": "hackerone", "report_id": "123463", "title": "LFI via path traversal in file download", "vulnerability_class": "LFI", "severity": "high", "cvss_score": 7.5, "target_tech": "PHP, Linux, Apache", "attack_vector": "LFI via directory traversal in file param", "endpoint_pattern": "/download?file={path}", "parameter": "file", "payload": "../../../etc/passwd", "impact": "Read any file on server", "remediation": "Path canonicalization + directory restriction", "url": "https://hackerone.com/reports/123463"},
            {"source": "hackerone", "report_id": "123464", "title": "Command injection in ping tool", "vulnerability_class": "Command Injection", "severity": "critical", "cvss_score": 9.8, "target_tech": "Python, Flask, Ubuntu", "attack_vector": "Command injection via os.system() call", "endpoint_pattern": "/tools/ping?host={ip}", "parameter": "host", "payload": "127.0.0.1; id", "impact": "Remote code execution", "remediation": "subprocess with input validation", "url": "https://hackerone.com/reports/123464"},
            {"source": "hackerone", "report_id": "123465", "title": "GraphQL introspection reveals admin mutations", "vulnerability_class": "GraphQL", "severity": "medium", "cvss_score": 5.3, "target_tech": "Node.js, Apollo GraphQL, React", "attack_vector": "GraphQL introspection enabled in production", "endpoint_pattern": "/graphql", "parameter": "query", "payload": "{__schema{types{name fields{name}}}}", "impact": "Discover hidden admin mutations", "remediation": "Disable introspection in production", "url": "https://hackerone.com/reports/123465"},
            {"source": "hackerone", "report_id": "123466", "title": "NoSQL injection bypasses login", "vulnerability_class": "NoSQLi", "severity": "high", "cvss_score": 9.3, "target_tech": "Node.js, MongoDB, Express", "attack_vector": "NoSQLi via JSON body to MongoDB query", "endpoint_pattern": "/api/v1/login", "parameter": "password", "payload": '{"$gt": ""}', "impact": "Authentication bypass", "remediation": "Input validation + type checking", "url": "https://hackerone.com/reports/123466"},
        ]

        filtered = all_mock
        if vuln_class:
            filtered = [r for r in filtered if r["vulnerability_class"].lower() == vuln_class.lower()]
        if tech:
            filtered = [r for r in filtered if tech.lower() in r["target_tech"].lower()]

        if not filtered:
            filtered = all_mock

        return SkillResult(
            success=True,
            findings=[],
            data={"reports": filtered[:limit], "count": len(filtered[:limit]),
                  "query": {"vuln_class": vuln_class, "tech": tech}},
            next_skills=[],
            confidence=1.0,
        )

    async def _search_reports(self, context: dict) -> SkillResult:
        """Full-text search across disclosed reports."""
        query = context.get("q", "")
        limit = context.get("limit", 10)

        if not query:
            return SkillResult(
                success=False, findings=[],
                data={"error": "No search query provided", "results": []},
                next_skills=[], confidence=0.0,
            )

        if self.mock:
            mock_data = self._mock_query("", "", 100)
            q = query.lower()
            results = [
                r for r in mock_data.data["reports"]
                if q in r.get("title", "").lower()
                or q in r.get("vulnerability_class", "").lower()
                or q in r.get("attack_vector", "").lower()
                or q in r.get("target_tech", "").lower()
                or q in r.get("payload", "").lower()
            ]
            return SkillResult(
                success=True,
                findings=[],
                data={"results": results[:limit], "count": len(results[:limit]), "query": query},
                next_skills=[], confidence=1.0,
            )

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        like = f"%{query}%"
        c.execute(
            """SELECT * FROM disclosed_reports
               WHERE title LIKE ? OR attack_vector LIKE ? OR payload LIKE ?
                  OR endpoint_pattern LIKE ? OR target_tech LIKE ? OR vulnerability_class LIKE ?
               ORDER BY fetched_at DESC LIMIT ?""",
            (like, like, like, like, like, like, limit),
        )
        results = [dict(r) for r in c.fetchall()]
        conn.close()

        return SkillResult(
            success=True,
            findings=[],
            data={"results": results, "count": len(results), "query": query},
            next_skills=[],
            confidence=1.0 if results else 0.0,
        )

    async def _knowledge_stats(self) -> SkillResult:
        """Get knowledge base statistics."""
        if self.mock:
            mock_data = self._mock_query("", "", 100)
            by_class = {}
            for r in mock_data.data["reports"]:
                cls = r.get("vulnerability_class", "Other")
                sev = r.get("severity", "low")
                if cls not in by_class:
                    by_class[cls] = {"vulnerability_class": cls, "count": 0, "max_severity": sev}
                by_class[cls]["count"] += 1
                sev_order = ["none", "low", "medium", "high", "critical"]
                if sev_order.index(sev) > sev_order.index(by_class[cls]["max_severity"]):
                    by_class[cls]["max_severity"] = sev
            return SkillResult(
                success=True,
                findings=[],
                data={
                    "total_reports": len(mock_data.data["reports"]),
                    "by_class": [v for _, v in sorted(by_class.items(), key=lambda x: -x[1]["count"])],
                    "by_source": [{"source": "hackerone", "count": len(mock_data.data["reports"])}],
                    "patterns_learned": 11,
                },
                next_skills=[],
                confidence=1.0,
            )

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        c.execute("SELECT COUNT(*) as total FROM disclosed_reports")
        total = c.fetchone()["total"]

        c.execute("""
            SELECT vulnerability_class, COUNT(*) as count, MAX(severity) as max_severity
            FROM disclosed_reports
            GROUP BY vulnerability_class
            ORDER BY count DESC
        """)
        by_class = [dict(r) for r in c.fetchall()]

        c.execute("""
            SELECT source, COUNT(*) as count
            FROM disclosed_reports
            GROUP BY source
        """)
        by_source = [dict(r) for r in c.fetchall()]

        c.execute("SELECT COUNT(*) as total FROM patterns")
        patterns_count = c.fetchone()["total"]

        conn.close()

        return SkillResult(
            success=True,
            findings=[],
            data={
                "total_reports": total,
                "by_class": by_class,
                "by_source": by_source,
                "patterns_learned": patterns_count,
            },
            next_skills=[],
            confidence=1.0,
        )

    def _count_reports(self) -> int:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM disclosed_reports")
        count = c.fetchone()[0]
        conn.close()
        return count

    # ─── Inject Knowledge Into Hunting ──────────────────────────────

    async def _inject_knowledge(self, context: dict) -> SkillResult:
        """Find relevant disclosed reports for the current target and return patterns."""
        target = context.get("target", "")
        vuln_type = context.get("vuln_type", "")
        endpoint = context.get("endpoint", "")
        tech_hints = context.get("tech_hints", "")

        if self.mock:
            mock_query = self._mock_query("", "", 10)
            return SkillResult(
                success=True,
                findings=[],
                data={
                    "knowledge": mock_query.data["reports"],
                    "count": len(mock_query.data["reports"]),
                    "injected_for": {"target": target, "vuln_type": vuln_type},
                },
                next_skills=["hunt"],
                confidence=1.0,
            )

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        relevant = []

        # By vulnerability class
        if vuln_type:
            classes = [c.strip() for c in vuln_type.split(",")]
            placeholders = ",".join("?" for _ in classes)
            c.execute(
                f"SELECT * FROM disclosed_reports WHERE vulnerability_class IN ({placeholders}) ORDER BY fetched_at DESC LIMIT 10",
                classes,
            )
            relevant.extend([dict(r) for r in c.fetchall()])

        # By tech stack similarity
        if tech_hints:
            for hint in tech_hints.split(","):
                hint = hint.strip()
                if hint:
                    c.execute(
                        "SELECT * FROM disclosed_reports WHERE target_tech LIKE ? ORDER BY fetched_at DESC LIMIT 3",
                        (f"%{hint}%",),
                    )
                    relevant.extend([dict(r) for r in c.fetchall()])

        # By endpoint similarity
        if endpoint:
            c.execute(
                "SELECT * FROM disclosed_reports WHERE endpoint_pattern LIKE ? ORDER BY fetched_at DESC LIMIT 3",
                (f"%{endpoint}%",),
            )
            relevant.extend([dict(r) for r in c.fetchall()])

        # If nothing found, return recent high-severity reports
        if not relevant:
            c.execute(
                "SELECT * FROM disclosed_reports WHERE severity IN ('critical', 'high') ORDER BY fetched_at DESC LIMIT 5"
            )
            relevant.extend([dict(r) for r in c.fetchall()])

        conn.close()

        # Deduplicate by URL
        seen = set()
        unique = []
        for r in relevant:
            if r["url"] not in seen:
                seen.add(r["url"])
                unique.append(r)

        return SkillResult(
            success=True,
            findings=[],
            data={
                "knowledge": unique,
                "count": len(unique),
                "injected_for": {"target": target, "vuln_type": vuln_type},
            },
            next_skills=["hunt"],
            confidence=min(len(unique) / 3, 1.0),
        )
