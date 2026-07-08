# PENTDEM — Autonomous AI Pentesting Daemon

Autonomous AI-powered pentesting platform that deploys coordinated agents for reconnaissance, vulnerability discovery, proof-of-concept validation, kill-chain analysis, and compliance reporting.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    PIPELINE (pipeline.py)                            │
│  Orchestrator — coordinates agents, validates, reports               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ENGINE: agent (default)        ENGINE: pipeline (legacy)           │
│  ┌─────────────────────────┐    ┌─────────────────────────┐        │
│  │  AutonomousAgent        │    │  Skills (recon, hunt,   │        │
│  │  - 34 security tools    │    │  chain, validate, etc.) │        │
│  │  - LLM analysis         │    │  - Parallel vuln class  │        │
│  │  - WAF bypass engine    │    │    hunting              │        │
│  └─────────────────────────┘    └─────────────────────────┘        │
│                         │                                           │
│                    Merge findings                                   │
│                         ↓                                           │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  Quality Gate → Kill Chain Builder → Compliance Mapper       │   │
│  │  → Report → Session Persistence → Dashboard                  │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
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

# Run with autonomous agent (default)
python cli.py example.com full hackerone

# Run with legacy pipeline
python cli.py example.com full hackerone --engine pipeline

# Run with both engines
python cli.py example.com full hackerone --engine hybrid

# Standalone agent
python -m agents.autonomous example.com --mock
```

## How It Runs (v6.0)

The process is **similar but enhanced**:

### Before (v3.0)
```
1. Recon → 2. Hunt (15 vuln classes) → 3. Validate → 4. Report
```

### Now (v6.0)
```
1. Recon → 2. Hunt (15 vuln classes + 9 attack classes) →
3. Kill Chain Builder (chains findings into attack paths) →
4. Quality Gate (rejects weak findings) →
5. Compliance Mapper (MITRE/OWASP/CVSS) →
6. Report → 7. Session Persistence → 8. Dashboard
```

**Key differences:**
- **24 attack classes** (was 15) — added JWT, OAuth, subdomain takeover, cloud metadata, race conditions, etc.
- **Kill-chain builder** — chains individual findings into full attack paths
- **Quality gate** — single chokepoint rejects weak findings before report
- **Session persistence** — saves scan state, can resume/compare across runs
- **Docker isolation** — runs dangerous tools (sqlmap, nuclei) in containers
- **Real tool grounding** — actually runs nmap/sqlmap/nuclei/ffuf (not mocks)
- **Web dashboard** — real-time monitoring UI

## CLI Usage

```bash
# Full scan (24 vuln classes, ~2min mock)
python cli.py <target> full <platform> [--mock]

# Quick scan (top 6 vuln classes)
python cli.py <target> quick [--mock]

# Targeted scan (core 4: IDOR, SSRF, XSS, SQLi)
python cli.py <target> targeted [--mock]

# Engine selection
python cli.py <target> full hackerone --engine agent      # Autonomous agent (default)
python cli.py <target> full hackerone --engine pipeline   # Legacy pipeline
python cli.py <target> full hackerone --engine hybrid     # Both engines

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
| **agent** | Uses 34 tools + LLM analyzes after each phase | Full automation, real tool execution |
| **pipeline** | Uses skills with parallel vuln class testing | Deep analysis, existing infrastructure |
| **hybrid** | Runs agent for tools, pipeline for analysis | Maximum coverage, double validation |

## Attack Classes (24)

### Core (15)
IDOR, SSRF, XSS, SQLi, Auth Bypass, SSTI, Open Redirect, LFI, Command Injection, NoSQLi, GraphQL, JWT, Deserialization, Path Traversal, Race Condition

### Phase 3 Additions (9)
Subdomain Takeover, JWT Attack Suite, API Discovery, Mass Assignment, Cloud Metadata, Race Conditions, Credential Harvesting, OAuth/OIDC, Multi-Stage Chains

## Key Features

### Kill-Chain Path Builder
Chains individual findings into full attack paths:
```
SQLi (entry) → Credential Extraction → Privilege Escalation → Full Compromise
```
Maps each path to MITRE ATT&CK techniques and OWASP Top 10 categories.

### Quality Gate
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
├── cli.py                    # CLI entry point
├── main.py                   # Daemon entry point
├── server.py                 # FastAPI server
├── pipeline.py               # Swarm orchestrator (merged with agent)
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
│   ├── recon/                # Subdomain enum, live hosts, URLs
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
│   ├── docker_isolation.py   # Sandboxed tool execution
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
│   └── threat_analyzer.py    # FP detection, confidence scoring
│   └── Phase 3 Attack Classes:
│       ├── subdomain_takeover.py
│       ├── jwt_attack.py
│       ├── api_discovery.py
│       ├── mass_assignment.py
│       ├── cloud_metadata.py
│       ├── race_condition.py
│       ├── credential_harvesting.py
│       ├── oauth_attack.py
│       └── multi_stage_chain.py
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
- [ ] Continuous monitoring / scheduled rescans
- [ ] Automated patch suggestions
- [ ] PR review / shift-left capability
- [ ] Multi-tenant support
