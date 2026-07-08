# PENTDEM — Autonomous AI Pentesting Daemon

Autonomous AI-powered pentesting platform that deploys coordinated agents for reconnaissance, vulnerability discovery, proof-of-concept validation, and attack chain analysis.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    PIPELINE (pipeline.py)                        │
│  Orchestrator — coordinates agents, validates, reports           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ENGINE: agent (default)        ENGINE: pipeline (legacy)       │
│  ┌─────────────────────────┐    ┌─────────────────────────┐    │
│  │  AutonomousAgent        │    │  Skills (recon, hunt,   │    │
│  │  - 34 security tools    │    │  chain, validate, etc.) │    │
│  │  - LLM analysis         │    │  - Parallel vuln class  │    │
│  │  - WAF bypass engine    │    │    hunting              │    │
│  └─────────────────────────┘    └─────────────────────────┘    │
│                         │                                       │
│                    Merge findings                               │
│                         ↓                                       │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  Common: Chain → Validate → Screenshot → Report → Memory│    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

## Features

### Autonomous Agent (Primary Engine)
- **6-Phase Workflow** — Recon → Scan → Fuzz → Exploit → Chain → Report
- **34 Integrated Tools** — Real security tools (not mocks)
- **LLM Analysis** — AI analyzes tool outputs after each phase
- **WAF Bypass Engine** — 10+ mutation techniques + LLM-generated payloads
- **Learning** — Agent learns patterns from each tool's output

### Tool Catalog (34 Tools)

| Category | Tools |
|----------|-------|
| **Recon** (9) | Subfinder, httpx, katana, dnsx, Amass, Chaos, assetfinder, waybackurls, gau |
| **Scanner** (7) | Nuclei, Nmap, Nikto, Acunetix, OWASP ZAP, Wapiti, Arachni |
| **Fuzzer** (5) | ffuf, wfuzz, dirsearch, gobuster, Feroxbuster |
| **Exploit** (7) | sqlmap, dalfox, SSRFmap, commix, tplmap, XSStrike, Arjun |
| **Util** (5) | curl, jq, qsreplace, interactsh-client, anew |
| **Report** (1) | Chaos-Plus-Plus |

**33 free**, 1 commercial (Acunetix - free limited 1 target)

### Vuln Classes (15)
IDOR, SSRF, XSS, SQLi, Auth Bypass, SSTI, Open Redirect, LFI, Command Injection, NoSQLi, GraphQL, JWT, Deserialization, Path Traversal, Race Condition

### WAF Bypass
- **Standard Techniques** — URL encode, double encode, HTML entity, Unicode, case mutation, null byte, comment injection, whitespace manipulation
- **Template Syntax Variants** — Jinja2, ERB, Freemarker, Twig, Mako, Smarty, Velocity
- **LLM-Generated Payloads** — When standard techniques fail, LLM generates WAF-specific bypass payloads
- **Evaluation Proof** — SSTI requires arithmetic proof (49 for 7*7), not just "not-403"

### Report Generation
- **Per-target folders** — reports/{domain}/ with standalone MD files
- **Platform templates** — HackerOne, Bugcrowd, Intigriti, Immunefi
- **is_reportable() gate** — Only CONFIRMED verdicts reach reports (no false positives)
- **MITRE ATT&CK** — 25+ technique mappings
- **CVSS 3.1** — Dynamic scoring based on context

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

# Run mock mode
python cli.py example.com full hackerone --mock

# Run with autonomous agent (default)
python cli.py example.com full hackerone

# Run with legacy pipeline
python cli.py example.com full hackerone --engine pipeline

# Run with both engines
python cli.py example.com full hackerone --engine hybrid
```

## CLI Usage

```bash
# Full scan with autonomous agent (default)
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
| **pipeline** | Uses 7 skills with parallel vuln class testing | Deep analysis, existing infrastructure |
| **hybrid** | Runs agent for tools, pipeline for analysis | Maximum coverage, double validation |

## Modes

| Mode | Classes | Time (mock) | Use Case |
|------|---------|-------------|----------|
| `quick` | 6 | ~7s | Fast recon, top vulns |
| `targeted` | 4 | ~10s | Core vulns only |
| `full` | 15 | ~1m | Complete audit |

## API Usage

```bash
# Start scan
curl -X POST http://localhost:8888/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "mode": "full", "engine": "agent"}'

# Check status
curl http://localhost:8888/status/{task_id}

# Get results
curl http://localhost:8888/results/{task_id}
```

## Model Assignment

| Model | Use | Cost |
|-------|-----|------|
| GLM-4-Flash | Analysis, triage, WAF bypass generation | Free |
| Featherless.ai | Recon, reports, chain reasoning | Free |
| Kimi | Long context (JS analysis, disclosed reports) | Free |
| MiniMax | Tool orchestration, function calling | Free |

## Cost

Total: <$3/month (all free tiers)

## File Structure

```
├── cli.py                    # CLI entry point
├── main.py                   # Daemon entry point
├── server.py                 # FastAPI server
├── pipeline.py               # Swarm orchestrator (merged with agent)
├── adaptive_engine.py        # Mid-run test adaptation
├── concurrent_hunt.py        # Parallel hunt runner
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
│   ├── recon/                # Tool execution (subfinder, httpx, katana, ffuf)
│   ├── hunt/                 # 15 vuln class hunters
│   ├── chain/                # Attack chain builder
│   ├── validate/             # False positive killer
│   ├── report/               # Report generator
│   ├── report_writer.py      # Standalone MD reports
│   ├── memory/               # SQLite persistence + strategy memory
│   ├── knowledge/            # Disclosed report parser
│   ├── waf_bypass.py         # WAF detection + bypass engine + LLM payloads
│   ├── deep_exploration.py   # Never-stop-at-404 engine
│   ├── session_bypass.py     # Cookie swap, whitespace auth
│   ├── temp_email.py         # Disposable email for IDOR
│   ├── screenshot.py         # PoC evidence cards
│   ├── evidence.py           # Timestamped evidence files
│   ├── mitre_mapper.py       # ATT&CK technique mapping
│   └── threat_analyzer.py    # FP detection, confidence scoring
├── reports/{target}/         # Per-target report folders
│   ├── Main_Report.md
│   ├── findings/
│   ├── screenshots/
│   └── evidence/
└── data/
    ├── pentest.db            # SQLite (sessions, findings, patterns, strategies)
    └── wordlist_memory.db    # Cross-target wordlist memory
```

## Roadmap

- [ ] Docker deployment
- [ ] CI/CD integration
- [ ] Continuous monitoring / scheduled rescans
- [ ] Automated patch suggestions
- [ ] PR review / shift-left capability
# pentdem
