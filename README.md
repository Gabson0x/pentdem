# PENTDEM — Autonomous AI Pentesting Daemon

Autonomous AI-powered pentesting platform that deploys coordinated agents for reconnaissance, vulnerability discovery, proof-of-concept validation, kill-chain analysis, and compliance reporting.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         PIPELINE (pipeline.py)                          │
│              Orchestrator — coordinates agents, validates, reports       │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ENGINE: agent (default)           ENGINE: pipeline (legacy)            │
│  ┌───────────────────────────┐     ┌───────────────────────────┐       │
│  │  AutonomousAgent          │     │  Skills (recon, hunt,     │       │
│  │  - 34 security tools      │     │  chain, validate, etc.)   │       │
│  │  - LLM analysis           │     │  - Parallel vuln class    │       │
│  │  - WAF bypass engine      │     │    hunting                │       │
│  └───────────────────────────┘     └───────────────────────────┘       │
│                          │                                              │
│                     Merge findings                                      │
│                          ↓                                              │
│  ┌────────────────────────────────────────────────────────────────┐     │
│  │  Quality Gate → Kill Chain Builder → Compliance Mapper         │     │
│  │  → Report → Session Persistence → Dashboard                    │     │
│  └────────────────────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
# Clone
git clone <repo>
cd pentdem

# Install dependencies
pip install -r requirements.txt

# Copy environment file
cp .env.example .env

# Add API keys (all free tiers)
# - GLM: https://open.bigmodel.cn/
# - Featherless: https://featherless.ai/

# Run mock mode (no API calls)
python cli.py example.com full hackerone --mock

# ★ RECOMMENDED: Full scan with pipeline engine + Docker isolation
python cli.py example.com full hackerone --engine pipeline --docker

# Run with autonomous agent (simpler, less coverage)
python cli.py example.com full hackerone

# Run with both engines (slowest, most thorough)
python cli.py example.com full hackerone --engine hybrid
```

### ★ Recommended Command

```bash
python cli.py <target> full <platform> --engine pipeline --docker
```

**Why pipeline + docker is better than agent mode:**
- **15 vuln classes** run in parallel (agent runs 4 sequentially)
- **8 advanced attack skills** run in parallel (JWT, OAuth, mass assignment, race condition, cloud metadata, subdomain takeover, credential harvesting, API discovery)
- **WAF fingerprinting** runs on all live hosts automatically
- **Docker isolation** sandboxes dangerous tools (sqlmap, nuclei, nmap)
- **Quality gate** rejects weak findings before report
- **Kill-chain builder** chains findings into attack paths
- **Faster** — parallel execution vs sequential agent phases

## Pipeline Flow

### ★ Pipeline Engine (recommended)
```
recon → learn → hunt (15 vuln classes parallel)
  → advanced_hunt (8 attack skills parallel + WAF fingerprinting)
  → quality_gate → chain → validate → screenshot → report → memory
```

### Agent Engine (simpler)
```
recon → scan → fuzz → exploit → chain → quality_gate → validate → report
```

### Phase Details

| Phase | Description | Time |
|-------|-------------|------|
| **recon** | Subdomain enum, live hosts, URL discovery, JS analysis | ~30s |
| **learn** | Load disclosed reports, build knowledge base | ~5s |
| **hunt** | 15 vuln classes in parallel (IDOR, SSRF, XSS, SQLi, etc.) | ~60s |
| **advanced_hunt** | JWT, OAuth, mass assignment, race condition, cloud metadata, subdomain takeover, credential harvesting, API discovery, WAF bypass | ~30s |
| **quality_gate** | Evidence consistency check, dedup, reject weak findings | ~1s |
| **chain** | Chain findings into attack paths, MITRE ATT&CK mapping | ~5s |
| **validate** | 7-Question Gate, confirmation loops | ~10s |
| **report** | Generate Markdown report with CVSS scoring | ~5s |

## CLI Usage

```bash
# ★ RECOMMENDED: Full scan with all attack classes + Docker isolation
python cli.py <target> full <platform> --engine pipeline --docker

# Full scan (24 vuln classes, ~2min mock)
python cli.py <target> full <platform> [--mock] [--docker]

# Quick scan (top 6 vuln classes)
python cli.py <target> quick [--mock] [--docker]

# Targeted scan (core 4: IDOR, SSRF, XSS, SQLi)
python cli.py <target> targeted [--mock] [--docker]

# Engine selection
python cli.py <target> full hackerone --engine agent      # Autonomous agent (simpler)
python cli.py <target> full hackerone --engine pipeline   # ★ Pipeline (recommended)
python cli.py <target> full hackerone --engine hybrid     # Both engines (slowest)

# Docker isolation (sandboxed tool execution)
python cli.py <target> full hackerone --docker

# Source code analysis
python cli.py github.com/org/repo full github --source repo

# Standalone agent
python -m agents.autonomous <target> [--mock]

# Knowledge base
python cli.py knowledge fetch     # Fetch disclosed reports
python cli.py knowledge stats     # Show stats
python cli.py knowledge search <q>
```

## Engines

| Engine | How it works | Best for |
|--------|--------------|----------|
| **pipeline** ★ | 15 vuln classes parallel + 8 advanced skills + WAF + Docker | **Recommended** — maximum coverage, faster |
| **agent** | Uses 34 tools + LLM analyzes after each phase | Simpler, less coverage |
| **hybrid** | Runs agent for tools, pipeline for analysis | Double validation (slowest) |

★ **Pipeline engine is recommended** — it runs more attack classes in parallel, includes advanced hunt phase, and supports Docker isolation.

## Attack Classes (24)

### Core (15) — tested in parallel during hunt phase
IDOR, SSRF, XSS, SQLi, Auth Bypass, SSTI, Open Redirect, LFI, Command Injection, NoSQLi, GraphQL, JWT, Deserialization, Path Traversal, Race Condition

### Advanced (9) — tested in parallel during advanced hunt phase
Subdomain Takeover, JWT Attack Suite, API Discovery, Mass Assignment, Cloud Metadata, Race Conditions, Credential Harvesting, OAuth/OIDC, Multi-Stage Chains

## Key Features

### LLM-Guided Attack Strategy
Real AI decides what to test next based on response patterns:
- Analyzes status codes, response times, body sizes, error patterns
- Re-prioritizes vuln classes based on what's likely to succeed
- Adapts strategy mid-scan based on findings

### Multi-Stage Exploitation Chains
Pivots from initial finding to full attack path:
```
SQLi (entry) → Credential Extraction → Privilege Escalation → Full Compromise
```
Maps each path to MITRE ATT&CK techniques and OWASP Top 10 categories.

### Real-Time WAF Fingerprinting & Auto-Bypass
Detects and bypasses Web Application Firewalls:
- 9 WAF signatures (Cloudflare, Akamai, Incapsula, etc.)
- Auto-bypass techniques for each WAF type
- Shared across all skills via `SharedWAFBypass`

### Credential Harvesting from Responses
Extracts credentials, tokens, and secrets from HTTP responses:
- Regex patterns for API keys, tokens, passwords
- JWT token detection and analysis
- Hardcoded credential detection

### API Discovery via JavaScript Analysis
Discovers hidden endpoints, secrets, and tokens in JavaScript files:
- Endpoint extraction from JS code
- Secret/token detection
- Parameter discovery

### Mass Assignment / HTTP Parameter Pollution
Tests for mass assignment vulnerabilities:
- Parameter injection (admin, role, price, etc.)
- HPP (HTTP Parameter Pollution) testing
- Content-type manipulation

### JWT Attack Suite
Comprehensive JWT testing:
- Algorithm confusion (none, HS256→RS256)
- Key confusion attacks
- Header injection
- Token leakage detection

### OAuth/OIDC Attack Flows
Tests OAuth/OIDC implementations:
- redirect_uri manipulation
- State parameter bypass
- PKCE downgrade attacks
- Token leakage via referer

### Subdomain Takeover Detection
Detects subdomain takeover opportunities:
- CNAME record analysis
- Dangling DNS detection
- Service fingerprinting (GitHub Pages, Heroku, etc.)

### Cloud Metadata Exploitation
Tests for cloud metadata exposure:
- AWS IMDSv1/v2 endpoints
- GCP metadata server
- Azure Instance Metadata Service
- SSRF to cloud metadata pivoting

### Race Condition Detection
Detects race conditions via concurrent requests:
- Sends 10+ concurrent requests
- Detects TOCTOU (Time-of-Check Time-of-Use) bugs
- Identifies duplicate processing

### Report Quality Gate
Single chokepoint that rejects weak findings:
- Checks request/evidence consistency
- Validates evidence quality (raw proof, not generated)
- Deduplicates identical findings
- Rejects findings without server-side proof

### Docker Isolation
Runs dangerous tools in sandboxed containers:
- sqlmap, nuclei, nmap, ffuf, subfinder, httpx, dalfox, nikto, wfuzz
- Resource limits (CPU, memory, time)
- Network isolation
- Enable with `--docker` flag

### Real Tool Grounding
Actually runs real security tools:
- **nmap** — port scanning, service detection, script scanning
- **sqlmap** — SQL injection detection and exploitation
- **nuclei** — template-based vulnerability scanning
- **ffuf** — directory/file fuzzing
- **subfinder** — subdomain enumeration
- **httpx** — live host detection

### Session Persistence
Saves and loads scan state:
- Resume interrupted scans
- Compare findings across runs (detect new/fixed vulns)
- Track vulnerability trends over time
- Export to Markdown reports

### Multi-Agent Orchestrator
Runs parallel agents for faster testing:
- **Recon Agent** — subdomain enum, port scan, tech fingerprint
- **Explore Agent** — endpoint discovery, parameter analysis
- **Validate Agent** — confirm findings with PoC
- **Exploit Agent** — build kill chains

### CI/CD Integration
- GitHub Actions workflow generation
- GitLab CI pipeline generation
- Jira/GitHub issue creation
- Deployment gating based on severity

### Compliance Mapper
Maps findings to compliance frameworks:
- **MITRE ATT&CK** — 25+ technique mappings
- **OWASP Top 10 2021** — all 10 categories
- **CVSS 3.1** — dynamic scoring

### Web Dashboard
Real-time monitoring UI:
- Live findings browser with filtering
- Attack path visualization
- WebSocket updates
- Severity distribution charts

## File Structure

```
├── cli.py                    # CLI entry point (--docker, --engine, --mock)
├── main.py                   # Daemon entry point
├── server.py                 # FastAPI server
├── pipeline.py               # Swarm orchestrator (agent + pipeline engines)
├── adaptive_engine.py        # Mid-run test adaptation
├── concurrent_hunt.py        # Parallel hunt runner (with attack strategy)
├── ai_decision_engine.py     # Autonomous decisions (deeper/switch/stop)
├── rate_limiter.py           # Token bucket rate limiter
├── verifier.py               # Confirmation loops
├── models.py                 # Multi-model client (GLM, Featherless, Kimi, MiniMax)
├── agents/
│   ├── __init__.py           # Agent configs
│   ├── __main__.py           # python -m agents.autonomous
│   └── autonomous.py         # Autonomous agent (primary engine)
├── tools/
│   ├── __init__.py           # ToolExecutor (subprocess + mock)
│   ├── catalog.py            # 34 security tools catalog
│   └── payloads.py           # Real payload DB (11+ classes)
├── skills/
│   ├── recon/                # Subdomain enum, live hosts, URLs (Docker-aware)
│   ├── hunt/                 # 15 vuln class hunters (with EvidenceCollector)
│   ├── chain/                # Attack chain builder
│   ├── validate/             # 7-Question Gate (with evidence pre-check)
│   ├── report/               # Report generator
│   ├── report_writer.py      # Standalone MD reports
│   ├── memory/               # SQLite persistence + strategy memory
│   ├── knowledge/            # Disclosed report parser
│   ├── quality_gate.py       # Single chokepoint for all findings
│   ├── evidence_collector.py # Standardized evidence collection
│   ├── shared_waf.py         # Shared WAF fingerprinting & bypass
│   ├── attack_strategy.py    # LLM-guided attack prioritization
│   ├── kill_chain.py         # Kill-chain path builder (MITRE/OWASP)
│   ├── docker_isolation.py   # Sandboxed tool execution (9 containers)
│   ├── real_tools.py         # Real nmap/sqlmap/nuclei/ffuf execution
│   ├── session_persistence.py # Save/load scan state
│   ├── multi_agent.py        # Parallel explore/validate/exploit agents
│   ├── cicd_integration.py   # GitHub Actions, GitLab CI, Jira
│   ├── compliance_mapper.py  # MITRE ATT&CK + OWASP + CVSS
│   ├── architectural_memory.py # Learn target across runs
│   ├── web_dashboard.py      # Real-time monitoring UI
│   ├── waf_bypass.py         # WAF detection + bypass engine
│   ├── deep_exploration.py   # Never-stop-at-404 engine
│   ├── session_bypass.py     # Cookie swap, whitespace auth
│   ├── temp_email.py         # Disposable email for IDOR
│   ├── screenshot.py         # PoC evidence cards
│   ├── evidence.py           # Timestamped evidence files
│   ├── mitre_mapper.py       # ATT&CK technique mapping
│   ├── threat_analyzer.py    # FP detection, confidence scoring
│   ├── subdomain_takeover.py # CNAME/dangling detection
│   ├── jwt_attack.py         # JWT alg:none, key confusion, injection
│   ├── api_discovery.py      # JS endpoint/secret discovery
│   ├── mass_assignment.py    # Parameter injection + HPP
│   ├── cloud_metadata.py     # AWS/GCP/Azure metadata endpoints
│   ├── race_condition.py     # Concurrent request race detection
│   ├── credential_harvesting.py # Regex credential extraction
│   ├── oauth_attack.py       # OAuth redirect_uri, state, PKCE
│   └── multi_stage_chain.py  # Multi-step exploitation chains
├── reports/{target}/         # Per-target report folders
│   ├── Main_Report.md
│   ├── findings/
│   ├── screenshots/
│   └── evidence/
├── .sessions/                # Session persistence files
├── .memory/                  # Architectural memory files
└── data/
    ├── pentest.db            # SQLite (sessions, findings, patterns, strategies)
    └── wordlist_memory.db    # Cross-target wordlist memory
```

## Model Assignment

| Model | Use | Cost |
|-------|-----|------|
| GLM-4-Flash | Analysis, triage, WAF bypass, attack strategy | Free |
| Featherless.ai | Recon, reports, chain reasoning | Free |
| Kimi | Long context (JS analysis, disclosed reports) | Free |
| MiniMax | Tool orchestration, function calling | Free |

## Cost

Total: <$3/month (all free tiers)

## Roadmap

- [x] Docker deployment
- [x] CI/CD integration
- [x] Session persistence
- [x] Kill-chain path builder
- [x] Compliance mapping (MITRE/OWASP)
- [x] Web dashboard
- [x] Multi-agent orchestration
- [x] Docker isolation (`--docker` flag)
- [x] LLM-guided attack strategy
- [x] Multi-stage exploitation chains
- [x] WAF fingerprinting & auto-bypass
- [x] Credential harvesting
- [x] API discovery via JS analysis
- [x] Mass assignment / HPP
- [x] JWT attack suite
- [x] OAuth/OIDC attack flows
- [x] Subdomain takeover detection
- [x] Cloud metadata exploitation
- [x] Race condition detection
- [ ] Continuous monitoring / scheduled rescans
- [ ] Automated patch suggestions
- [ ] PR review / shift-left capability
- [ ] Multi-tenant support
