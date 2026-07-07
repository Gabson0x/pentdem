"""
Adaptive Wordlist Engine — Context-aware, memory-backed fuzzing wordlists.

Instead of a static list, this generates wordlists based on:
1. Target's actual tech stack (Laravel != WordPress != Django)
2. Already-discovered paths (inferred naming conventions)
3. JS-extracted endpoints (hidden API routes)
4. Cross-target memory (what worked on similar tech stacks before)
5. Pattern-based mutation (version guessing, sibling paths)

Tiered ranking: Learned > LLM-generated > Static baseline.

Usage:
    from adaptive_wordlist_engine import ReconContext, build_adaptive_wordlist, init_memory_db, record_hit, write_wordlist

    conn = init_memory_db()
    ctx = ReconContext(
        domain="example.com",
        tech_stack=["Laravel", "PHP", "Nginx"],
        discovered_paths=["/api/v1/users", "/admin/dashboard"],
        js_endpoints=["/api/v1/internal/audit"],
        server_headers={"Server": "nginx/1.18"},
    )
    wordlist = build_adaptive_wordlist(ctx, llm_call, conn=conn)
    write_wordlist(wordlist, "wordlist.txt")
"""

import json
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional


# ─── Data Structures ────────────────────────────────────────────

@dataclass
class ReconContext:
    """Everything the engine knows about a target after recon."""
    domain: str
    tech_stack: list[str] = field(default_factory=list)
    discovered_paths: list[str] = field(default_factory=list)
    js_endpoints: list[str] = field(default_factory=list)
    server_headers: dict[str, str] = field(default_factory=dict)
    version_hints: dict[str, str] = field(default_factory=dict)  # e.g. {"PHP": "8.2", "Laravel": "10.x"}


# ─── Memory DB ──────────────────────────────────────────────────

def init_memory_db(db_path: str | Path = "wordlist_memory.db") -> sqlite3.Connection:
    """
    Initialize the cross-target memory database.
    Stores what paths worked on which tech stacks.
    """
    conn = sqlite3.connect(str(db_path))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS learned_paths (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            path TEXT NOT NULL,
            tech_stack TEXT NOT NULL,  -- comma-separated, sorted
            hit_count INTEGER DEFAULT 1,
            status_code INTEGER DEFAULT 200,
            first_seen TEXT,
            last_seen TEXT,
            UNIQUE(path, tech_stack)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS path_patterns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pattern TEXT NOT NULL,  -- e.g. "/api/v{N}"
            tech_stack TEXT NOT NULL,
            hit_count INTEGER DEFAULT 1,
            UNIQUE(pattern, tech_stack)
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_learned_tech ON learned_paths(tech_stack)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_patterns_tech ON path_patterns(tech_stack)
    """)
    conn.commit()
    return conn


def record_hit(
    conn: sqlite3.Connection,
    path: str,
    tech_stack: str,
    status_code: int = 200,
) -> None:
    """Record a successful path hit for cross-target learning."""
    now = __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat()
    tech_key = ",".join(sorted(t.strip() for t in tech_stack.split(",") if t.strip()))

    conn.execute("""
        INSERT INTO learned_paths (path, tech_stack, hit_count, status_code, first_seen, last_seen)
        VALUES (?, ?, 1, ?, ?, ?)
        ON CONFLICT(path, tech_stack) DO UPDATE SET
            hit_count = hit_count + 1,
            last_seen = ?,
            status_code = ?
    """, (path, tech_key, status_code, now, now, now, status_code))

    # Also extract and record patterns
    pattern = _extract_pattern(path)
    if pattern:
        conn.execute("""
            INSERT INTO path_patterns (pattern, tech_stack, hit_count)
            VALUES (?, ?, 1)
            ON CONFLICT(pattern, tech_stack) DO UPDATE SET hit_count = hit_count + 1
        """, (pattern, tech_key))

    conn.commit()


def get_learned_paths(
    conn: sqlite3.Connection,
    tech_stack: list[str],
    limit: int = 50,
) -> list[str]:
    """Get paths that worked on similar tech stacks."""
    tech_key = ",".join(sorted(tech_stack))
    # Exact match first, then partial match
    rows = conn.execute("""
        SELECT path, hit_count FROM learned_paths
        WHERE tech_stack = ?
        ORDER BY hit_count DESC
        LIMIT ?
    """, (tech_key, limit)).fetchall()

    if len(rows) < limit:
        # Fallback: partial tech match
        partial_conditions = " OR ".join(f"tech_stack LIKE '%{t}%'" for t in tech_stack if len(t) > 2)
        if partial_conditions:
            rows += conn.execute(f"""
                SELECT path, hit_count FROM learned_paths
                WHERE {partial_conditions} AND tech_stack != ?
                ORDER BY hit_count DESC
                LIMIT ?
            """, (tech_key, limit - len(rows))).fetchall()

    return [r[0] for r in rows]


def get_learned_patterns(
    conn: sqlite3.Connection,
    tech_stack: list[str],
) -> list[str]:
    """Get path patterns (e.g. /api/v{N}) that worked on similar tech stacks."""
    tech_key = ",".join(sorted(tech_stack))
    rows = conn.execute("""
        SELECT pattern, hit_count FROM path_patterns
        WHERE tech_stack LIKE ?
        ORDER BY hit_count DESC
        LIMIT 20
    """, (f"%{tech_key[:20]}%",)).fetchall()
    return [r[0] for r in rows]


def _extract_pattern(path: str) -> Optional[str]:
    """
    Extract a pattern from a path for mutation.
    E.g. /api/v1/users -> /api/v{N}/users
         /api/v2/admin -> /api/v{N}/admin
    """
    # Version number pattern
    m = re.search(r"(/(?:api|v|version|ver)/)v?(\d+)(/.*)?$", path, re.IGNORECASE)
    if m:
        return f"{m.group(1)}{{N}}{m.group(3) or ''}"

    # Numeric ID pattern
    m = re.search(r"(/[^/]*/)(\d+)(/[^/]*)?$", path)
    if m:
        return f"{m.group(1)}{{ID}}{m.group(3) or ''}"

    return None


# ─── Static Baseline ────────────────────────────────────────────

STATIC_BASELINE = [
    # Common paths
    "admin", "administrator", "login", "logout", "api", "api/v1", "api/v2", "api/v3",
    "dashboard", "portal", "console", "manage", "management",
    "uploads", "upload", "files", "assets", "static", "media",
    "test", "testing", "dev", "staging", "demo", "sandbox",
    "internal", "private", "secret", "hidden", "temp", "tmp",
    "old", "backup", "backups", "archive", "bak",
    # Config and env
    ".env", ".env.local", ".env.production", ".env.backup",
    "config", "config.php", "config.json", "config.yml", "config.yaml",
    "settings.py", "settings.json", "web.config", "app.config",
    "docker-compose.yml", "Dockerfile", ".dockerignore",
    "appveyor.yml", ".travis.yml", "Jenkinsfile", ".gitlab-ci.yml",
    "package.json", "package-lock.json", "composer.json", "composer.lock",
    "requirements.txt", "Gemfile", "Gemfile.lock", "yarn.lock",
    # Version control
    ".git", ".git/config", ".git/HEAD", ".gitignore",
    ".svn", ".svn/entries", ".hg", ".bzr",
    # CMS specific
    "wp-admin", "wp-content", "wp-includes", "wp-login.php",
    "wp-config.php", "wp-json", "xmlrpc.php",
    "administrator", "joomla.xml", "sites/default",
    "typo3", "typo3conf",
    # Cloud and infra
    ".aws/credentials", ".ssh/id_rsa", ".ssh/authorized_keys",
    "kube-config", ".kube/config", "terraform.tfstate",
    "docker-compose.override.yml", ".npmrc", ".pypirc",
    # Info disclosure
    "robots.txt", "sitemap.xml", "crossdomain.xml", "clientaccesspolicy.xml",
    "server-status", "server-info", "phpinfo.php", "info.php",
    ".well-known/security.txt", "humans.txt",
    "swagger.json", "swagger-ui.html", "openapi.json", "graphql",
    "actuator", "actuator/health", "actuator/env",
    "debug", "trace", "elmah.axd",
]


# ─── Tech-Specific Overrides ────────────────────────────────────

TECH_SPECIFIC_PATHS = {
    "laravel": [
        ".env", "storage/logs/laravel.log", "storage/app/public",
        "vendor/phpunit/phpunit/src/Util/Filter.php",
        "telescope", "horizon", "aileron",
        "api/sanctum/csrf-cookie", "broadcasting/auth",
    ],
    "django": [
        "admin/", "static/admin/", "api/", "graphql",
        "django-admin/", "manage.py", "settings.py",
        "static/rest_framework/", "__debug__/",
        "media/", "staticfiles/",
    ],
    "wordpress": [
        "wp-admin/", "wp-content/uploads/", "wp-content/plugins/",
        "wp-content/themes/", "wp-includes/", "wp-json/wp/v2/",
        "xmlrpc.php", "wp-login.php", "readme.html",
        "license.txt", "wp-config.php.bak",
    ],
    "spring": [
        "actuator", "actuator/health", "actuator/env", "actuator/beans",
        "actuator/configprops", "actuator/mappings", "actuator/trace",
        "swagger-ui.html", "v2/api-docs", "hystrix",
    ],
    "node": [
        "package.json", ".env", ".env.local", "server.js", "app.js",
        "node_modules/", ".npmrc", "tsconfig.json", "webpack.config.js",
    ],
    "rails": [
        "rails/info", "rails/mailers", "rails/mailers/",
        "assets/config/manifest.js", ".env", "config/database.yml",
        "config/secrets.yml", "config/secrets.yml.enc",
    ],
    "php": [
        "phpinfo.php", "info.php", "test.php", "config.php",
        ".env", "composer.json", "composer.lock", "vendor/",
        "wp-config.php", "config/database.php",
    ],
    "nginx": [
        "server-status", "server-info", ".nginx/",
    ],
    "apache": [
        "server-status", "server-info", ".htaccess", ".htpasswd",
    ],
    "express": [
        ".env", "package.json", "app.js", "server.js",
        "routes/", "middleware/", "config/",
    ],
    "fastapi": [
        "docs", "redoc", "openapi.json", "swagger-ui.html",
        "api/v1/", "api/v2/", "health", "metrics",
    ],
    "next": [
        "_next/", "_next/data/", "api/", ".env", ".env.local",
        "next.config.js", "package.json",
    ],
}


# ─── Pattern Mutation ───────────────────────────────────────────

def mutate_paths(discovered_paths: list[str], learned_patterns: list[str]) -> list[str]:
    """
    Generate sibling guesses from discovered paths.
    /api/v1/users -> /api/v2/users, /api/v3/users, /api/legacy/users
    /admin/dashboard -> /admin/config, /admin/settings, /admin/users
    """
    mutations = []

    for path in discovered_paths:
        # Version mutations
        m = re.search(r"(/v)(\d+)(/.*)", path)
        if m:
            prefix, version, suffix = m.group(1), int(m.group(2)), m.group(3)
            for v in range(1, 6):
                if v != version:
                    mutations.append(f"{prefix}{v}{suffix}")
            mutations.append(f"{path.rsplit('/', 1)[0]}/legacy{suffix}")
            mutations.append(f"{path.rsplit('/', 1)[0]}/internal{suffix}")

        # Sibling path mutations
        parts = path.strip("/").split("/")
        if len(parts) >= 2:
            base = "/" + "/".join(parts[:-1])
            last = parts[-1]
            siblings = ["config", "settings", "users", "admin", "list", "search",
                        "export", "import", "backup", "logs", "status", "health",
                        "metrics", "debug", "test", "internal", "staging"]
            for sib in siblings:
                if sib != last:
                    mutations.append(f"{base}/{sib}")

    # Apply learned patterns
    for pattern in learned_patterns:
        # /api/v{N}/users -> /api/v1/users, /api/v2/users, etc.
        for i in range(1, 6):
            mutations.append(pattern.replace("{N}", str(i)))
            mutations.append(pattern.replace("{ID}", str(i)))

    return list(set(mutations))


# ─── LLM Generation ─────────────────────────────────────────────

def build_llm_prompt(ctx: ReconContext) -> str:
    """Build a prompt for the LLM to generate context-aware paths."""
    tech_str = ", ".join(ctx.tech_stack) if ctx.tech_stack else "unknown"
    version_str = ", ".join(f"{k}: {v}" for k, v in ctx.version_hints.items()) if ctx.version_hints else "not detected"
    paths_str = "\n".join(ctx.discovered_paths[:20]) if ctx.discovered_paths else "none yet"
    js_str = "\n".join(ctx.js_endpoints[:15]) if ctx.js_endpoints else "none"
    server_str = "\n".join(f"{k}: {v}" for k, v in ctx.server_headers.items()) if ctx.server_headers else "not captured"

    return f"""You are a security researcher generating a fuzzing wordlist for a specific target.

Target: {ctx.domain}
Tech Stack: {tech_str}
Versions: {version_str}
Server Headers:
{server_str}

Discovered Paths:
{paths_str}

JS-Extracted Endpoints:
{js_str}

Based on this context, generate 30-50 paths/files that a real developer on THIS SPECIFIC STACK would have created, deployed, or left behind. Think about:
- Framework-specific paths (not generic ones)
- Version-specific quirks
- Common developer mistakes on this stack
- Undocumented API routes
- Debug/test endpoints
- Config files specific to this framework
- Backup files that developers actually create

Return ONLY a JSON array of path strings. No explanation.
Example: ["/api/v1/health", "/.env", "/admin/debug"]
"""


# ─── Main Engine ────────────────────────────────────────────────

def build_adaptive_wordlist(
    ctx: ReconContext,
    llm_call: Callable[[str], str],
    base_static_list: list[str] = None,
    conn: Optional[sqlite3.Connection] = None,
    max_size: int = 200,
) -> list[str]:
    """
    Build a context-aware, memory-backed fuzzing wordlist.

    Priority order:
    1. Learned paths (from memory DB, same tech stack)
    2. LLM-generated paths (context-aware)
    3. Pattern mutations (from discovered paths)
    4. Tech-specific static paths
    5. Generic static baseline
    """
    seen = set()
    wordlist = []

    # Tier 1: Learned paths from memory
    if conn:
        tech_for_memory = ctx.tech_stack or []
        learned = get_learned_paths(conn, tech_for_memory, limit=30)
        for path in learned:
            if path not in seen:
                seen.add(path)
                wordlist.append(path)

    # Tier 2: LLM-generated paths (context-aware)
    try:
        prompt = build_llm_prompt(ctx)
        raw = llm_call(prompt)
        # Parse JSON array from response
        raw = raw.strip()
        if raw.startswith("["):
            generated = json.loads(raw)
        else:
            # Try to extract JSON array from response
            m = re.search(r"\[.*\]", raw, re.DOTALL)
            if m:
                generated = json.loads(m.group())
            else:
                generated = []

        for path in generated:
            if isinstance(path, str) and path.startswith("/") and path not in seen:
                seen.add(path)
                wordlist.append(path)
    except (json.JSONDecodeError, Exception):
        pass  # LLM failure is non-fatal

    # Tier 3: Pattern mutations from discovered paths
    if conn:
        learned_patterns = get_learned_patterns(conn, ctx.tech_stack or [])
    else:
        learned_patterns = []

    mutated = mutate_paths(ctx.discovered_paths + ctx.js_endpoints, learned_patterns)
    for path in mutated:
        if path not in seen:
            seen.add(path)
            wordlist.append(path)

    # Tier 4: Tech-specific static paths
    for tech in ctx.tech_stack:
        tech_lower = tech.lower()
        if tech_lower in TECH_SPECIFIC_PATHS:
            for path in TECH_SPECIFIC_PATHS[tech_lower]:
                if path not in seen:
                    seen.add(path)
                    wordlist.append(path)

    # Tier 5: Generic static baseline (fill remaining slots)
    static = base_static_list or STATIC_BASELINE
    for path in static:
        if path not in seen:
            seen.add(path)
            wordlist.append(path)
        if len(wordlist) >= max_size:
            break

    return wordlist[:max_size]


def write_wordlist(wordlist: list[str], output_path: str) -> None:
    """Write wordlist to a file, one path per line."""
    Path(output_path).write_text("\n".join(wordlist))


# ─── Convenience ────────────────────────────────────────────────

def quick_wordlist(
    domain: str,
    tech_stack: list[str],
    discovered_paths: list[str] = None,
    js_endpoints: list[str] = None,
    llm_call: Callable[[str], str] = None,
    db_path: str = "wordlist_memory.db",
) -> list[str]:
    """Quick helper to generate a wordlist without full pipeline setup."""
    conn = init_memory_db(db_path)
    ctx = ReconContext(
        domain=domain,
        tech_stack=tech_stack,
        discovered_paths=discovered_paths or [],
        js_endpoints=js_endpoints or [],
    )
    if llm_call is None:
        llm_call = lambda p: "[]"
    return build_adaptive_wordlist(ctx, llm_call, conn=conn)
