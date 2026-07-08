# AI Pentest Daemon - Implementation Status

## ✅ Completed

### Core Structure
- `server.py` - FastAPI server with /scan, /status, /results, /health endpoints
- `pipeline.py` - Pipeline orchestrator with agent + pipeline engine support
- `models.py` - Multi-model client (GLM, Featherless, Kimi, MiniMax, DeepSeek, Qwen)
- `cli.py` - Command-line interface with engine selection
- `main.py` - Daemon entry point

### Autonomous Agent
- `agents/autonomous.py` - 6-phase autonomous agent (recon→scan→fuzz→exploit→chain→report)
- `agents/__main__.py` - `python -m agents.autonomous` support (fixed broken import)
- `tools/catalog.py` - 34 security tools catalog with install commands
- `tools/__init__.py` - ToolExecutor (subprocess + mock)

### LLM-Based Features
- `skills/waf_bypass.py` - WAF detection + 10 bypass techniques + LLM payload generation
- `skills/shared_waf.py` - Shared WAF module — fingerprint 9 WAFs (Cloudflare, Akamai, AWS WAF, Imperva, Sucuri, ModSecurity, Wordfence, Datadome, F5), `is_waf_blocked()`, `bypass_payload()` with encode/case/comment/null-byte/chunked/unicode variants
- `skills/attack_strategy.py` - LLM-guided attack prioritization — `SignalSnapshot`, `AttackPlan`, `analyze_signals()`, `generate_attack_plan()`, `re_evaluate_after_results()`
- SSTI evaluation proof (49 for 7*7), not just "not-403"
- Multiple template syntaxes (Jinja2, ERB, Freemarker, Twig, Mako, Smarty, Velocity)
- `is_reportable()` gate - Only CONFIRMED verdicts reach reports

### Quality & Evidence
- `skills/quality_gate.py` - ReportQualityGate — single chokepoint for all findings. Validates: request/evidence consistency, evidence quality, severity/CVSS consistency, confidence check, dedup, server-side proof, injection point, URL validity
- `skills/evidence_collector.py` - EvidenceCollector — standardizes evidence across all detectors. Required fields: payload_used, injection_point, http_request, http_response, baseline_comparison, reproduction_steps, server_side_proof, evidence_score (0-1)

### Decision Engine
- `ai_decision_engine.py` - AIDecisionEngine — autonomous decisions: deeper/switch_vuln/switch_target/exploit/verify/report/stop. Depth control (1-4 levels), time limits per target (30min) and per vuln class (5min)

### Skills
- `skills/base.py` - Base skill class with LLM fallback (fixed MockModelClient → _DummyModelClient chain)
- `skills/recon/` - Subdomain enum, live host detection, URL crawling
- `skills/hunt/` - IDOR, SSRF, XSS, SQLi testing (with EvidenceCollector integration)
- `skills/validate/` - 7-Question Gate triage, severity assessment, dedup (with evidence pre-check)
- `skills/report/` - Report generation for HackerOne, Bugcrowd, Intigriti, Immunefi
- `skills/report_writer.py` - Standalone MD reports with is_reportable() gate
- `skills/memory/` - Session storage, pattern learning
- `skills/knowledge/` - Pattern learning (integrated with attack strategy)

### Phase 3 Attack Classes (NEW)
- `skills/subdomain_takeover.py` - CNAME check + fingerprint 50+ vulnerable services (GitHub, Heroku, Shopify, Tumblr, WordPress, etc.)
- `skills/jwt_attack.py` - alg:none, key confusion (RS256→HS256), weak secret brute force, claim injection, token leakage detection
- `skills/api_discovery.py` - JS analysis — extract endpoints, secrets, internal hosts, GraphQL introspection
- `skills/mass_assignment.py` - Privilege escalation param injection, prototype pollution (__proto__), HTTP Parameter Pollution
- `skills/cloud_metadata.py` - SSRF→AWS/GCP/Azure/DigitalOcean/Kubernetes metadata endpoints, IAM credential extraction
- `skills/race_condition.py` - 10 concurrent requests, detect duplicate resources, timing anomalies, inconsistent responses
- `skills/credential_harvesting.py` - Extract-only (never auto-use) — API keys, tokens, private keys, DB URLs, webhook URLs
- `skills/oauth_attack.py` - Redirect URI manipulation, state parameter bypass, token leakage, OAuth discovery
- `skills/multi_stage_chain.py` - 5 chain types: SQLi→data, XSS→ATO, SSRF→cloud, IDOR→breach, redirect→OAuth theft

### Phase 4 Enterprise Features (NEW)
- `skills/kill_chain.py` - Kill-chain path builder — chains individual findings into full attack paths with MITRE/OWASP mapping
- `skills/docker_isolation.py` - Docker isolation for safe tool execution (sqlmap, nuclei, nmap, ffuf, subfinder, httpx, dalfox, nikto, wfuzz)
- `skills/real_tools.py` - Real tool grounding — actual nmap/sqlmap/nuclei/ffuf/subfinder/httpx execution with output parsing
- `skills/session_persistence.py` - Save/load scan state across runs, session diffing, markdown export
- `skills/multi_agent.py` - Multi-agent orchestrator — parallel recon/explore/validate/exploit agents
- `skills/cicd_integration.py` - CI/CD integration — GitHub Actions, GitLab CI, Jira/GitHub issue generation, deployment gating
- `skills/compliance_mapper.py` - Compliance mapping — MITRE ATT&CK + OWASP Top 10 2021 + CVSS scoring
- `skills/architectural_memory.py` - Architectural memory — learn target structure across runs, trend analysis, test suggestions
- `skills/web_dashboard.py` — Real-time web dashboard UI with WebSocket updates, findings browser, attack path visualization

### Deployment
- `Dockerfile` - Docker image definition
- `docker-compose.yml` - Docker Compose configuration
- `deploy.sh` - Deployment script
- `.env.example` - API key template

### Dependencies
- `requirements.txt` - All Python packages (updated for Python 3.14)

## 🔧 Engine System

### Available Engines

| Engine | Command | How it works |
|--------|---------|--------------|
| **agent** | `--engine agent` | Autonomous agent with 34 tools + LLM analysis |
| **pipeline** | `--engine pipeline` | Legacy skills-based parallel hunting |
| **hybrid** | `--engine hybrid` | Both engines for maximum coverage |

### Default Engine: agent

The autonomous agent is now the primary engine. It:
1. Runs 6 phases (recon→scan→fuzz→exploit→chain→report)
2. Uses real security tools (subfinder, httpx, nuclei, ffuf, sqlmap, etc.)
3. LLM analyzes tool outputs after each phase
4. WAF bypass engine triggers when blocked
5. Only CONFIRMED findings reach reports

## 🛠️ Tool Catalog (34 Tools)

### Reconnaissance (9)
- Subfinder - Passive subdomain enumeration
- httpx - Live host detection with fingerprinting
- katana - Web crawler with JS rendering
- dnsx - DNS resolution with multiple record types
- Amass - OWASP subdomain enumeration
- Chaos - ProjectDiscovery subdomain dataset
- assetfinder - Quick passive subdomain finder
- waybackurls - Historical URL discovery
- gau - URL discovery from multiple sources

### Scanners (7)
- Nuclei - Template-based vulnerability scanner (9000+ templates)
- Nmap - Network scanner with NSE scripts
- Nikto - Web server scanner
- Acunetix - Commercial scanner (free limited 1 target)
- OWASP ZAP - Full-featured web app scanner
- Wapiti - Web application vulnerability scanner
- Arachni - Modular web scanner

### Fuzzers (5)
- ffuf - Fast web fuzzer
- wfuzz - Web fuzzer with injection point control
- dirsearch - Directory/file brute-forcer
- gobuster - Directory/DNS/VHost brute-forcer
- Feroxbuster - Recursive content discovery (Rust)

### Exploitation (7)
- sqlmap - Automatic SQL injection
- dalfox - XSS scanner
- SSRFmap - SSRF exploitation
- commix - Command injection
- tplmap - Template injection + RCE
- XSStrike - Advanced XSS scanner
- Arjun - HTTP parameter discovery

### Utilities (5)
- curl - HTTP client
- jq - JSON processor
- qsreplace - Query string replacement
- interactsh-client - Out-of-band interaction server
- anew - Append unique lines (dedup)

## 🔑 API Keys Required

1. **GLM** - https://open.bigmodel.cn/ (working)
2. **Featherless.ai** - https://featherless.ai/ (working)
3. **Kimi/Moonshot** - https://platform.moonshot.cn/ (rate limited)
4. **MiniMax** - https://platform.minimaxi.com/ (key format TBD)
5. **DeepSeek** - https://platform.deepseek.com/ (no balance)
6. **Qwen** - https://dashscope.console.aliyun.com/ (optional)

## 🚀 Quick Start

```bash
# 1. Add API keys
cp .env.example .env
nano .env

# 2. Run with autonomous agent (default)
python cli.py example.com full hackerone

# 3. Run with legacy pipeline
python cli.py example.com full hackerone --engine pipeline

# 4. Run standalone agent
python -m agents.autonomous example.com --mock

# 5. Docker deployment
./deploy.sh
```

## 📊 Model Assignments

| Task | Model | Provider |
|------|-------|----------|
| WAF bypass generation | GLM-4-Flash | Zhipu |
| Recon analysis | GLM-4-Flash | Zhipu |
| Scan analysis | GLM-4-Flash | Zhipu |
| Chain reasoning | GLM-5.2 | Featherless |
| Report writing | Qwen3.6 | Featherless |
| Validation | GLM-5.2 | Featherless |
| Attack strategy | GLM-4-Flash | Zhipu |

## 📁 Architecture Overview

```
pipeline.py (orchestrator)
├── skills/recon/          # Subdomain enum, live hosts, URLs
├── skills/hunt/           # IDOR, SSRF, XSS, SQLi (with EvidenceCollector)
├── skills/validate/       # 7-Question Gate + evidence pre-check
├── skills/quality_gate.py # Single chokepoint for all findings
├── skills/chain.py        # Exploitation chains
├── skills/report/         # Report generation
├── skills/report_writer.py # MD reports with is_reportable()
├── skills/knowledge/      # Pattern learning
├── ai_decision_engine.py  # Autonomous decisions
├── concurrent_hunt.py     # Parallel hunting with attack strategy
├── skills/shared_waf.py   # WAF fingerprinting & bypass
├── skills/attack_strategy.py # LLM-guided prioritization
├── skills/kill_chain.py   # Kill-chain path builder (MITRE/OWASP)
├── skills/docker_isolation.py # Sandboxed tool execution
├── skills/real_tools.py   # Real nmap/sqlmap/nuclei/ffuf execution
├── skills/session_persistence.py # Save/load scan state
├── skills/multi_agent.py  # Parallel explore/validate/exploit agents
├── skills/cicd_integration.py # GitHub Actions, GitLab CI, Jira
├── skills/compliance_mapper.py # MITRE ATT&CK + OWASP + CVSS
├── skills/architectural_memory.py # Learn target across runs
├── skills/web_dashboard.py # Real-time monitoring UI
└── Phase 3 Attack Classes:
    ├── skills/subdomain_takeover.py
    ├── skills/jwt_attack.py
    ├── skills/api_discovery.py
    ├── skills/mass_assignment.py
    ├── skills/cloud_metadata.py
    ├── skills/race_condition.py
    ├── skills/credential_harvesting.py
    ├── skills/oauth_attack.py
    └── skills/multi_stage_chain.py
```

## 📝 Recent Changes

### v6.0 - Phase 4 Enterprise Features (NEW)
- Added Kill-Chain Path Builder — chains findings into full attack paths with MITRE/OWASP mapping
- Added Docker Isolation — sandboxed execution for 9 security tools (sqlmap, nuclei, nmap, ffuf, subfinder, httpx, dalfox, nikto, wfuzz)
- Added Real Tool Grounding — actual tool execution with output parsing
- Added Session Persistence — save/load scan state, session diffing, markdown export
- Added Multi-Agent Orchestrator — parallel recon/explore/validate/exploit agents
- Added CI/CD Integration — GitHub Actions, GitLab CI, Jira/GitHub issues, deployment gating
- Added Compliance Mapper — MITRE ATT&CK + OWASP Top 10 2021 + CVSS scoring
- Added Architectural Memory — learn target structure across runs, trend analysis, test suggestions
- Added Web Dashboard — real-time monitoring UI with WebSocket updates

### v5.0 - Phase 3 Attack Classes
- Added 9 new attack skills (subdomain takeover, JWT, API discovery, mass assignment, cloud metadata, race conditions, credential harvesting, OAuth, multi-stage chains)
- Added SharedWAFBypass — shared WAF module used by concurrent_hunt.py
- Added LLMAttackStrategy — post-finding re-prioritization in concurrent_hunt.py
- Updated pipeline.py to import all new skills
- Updated concurrent_hunt.py to use shared_waf and attack_strategy

### v4.1 - Quality & Evidence System
- Added ReportQualityGate — single chokepoint for all findings before report
- Added EvidenceCollector — standardized evidence collection across all detectors
- Added AIDecisionEngine — autonomous decisions (deeper/switch/stop)
- Fixed 7-Question Gate: removed None from chain builder filter
- Fixed agents/__main__.py: broken import from nonexistent main()
- Fixed skills/base.py: MockModelClient → _DummyModelClient fallback chain
- Improved 7-Question Gate with evidence pre-check

### v4.0 - Merged Agent + Pipeline
- Added `--engine` parameter (agent, pipeline, hybrid)
- Autonomous agent is now the default engine
- Pipeline runs agent first, then adds legacy skills analysis
- Both engines share validation, chain, and report phases

### v3.0 - WAF Bypass + LLM Analysis
- Added WAF detection (Cloudflare, Akamai, Sucuri, etc.)
- Added 10 bypass techniques (encoding, mutation, comments)
- Added LLM-generated WAF-specific bypass payloads
- Added SSTI evaluation proof requirement
- Added `is_reportable()` gate for reports

### v2.0 - Multi-Model + Tools
- Added 34 security tools catalog
- Added GLM and Featherless model support
- Added Kimi rate limiting with retry
- Added MiniMax OpenAI-compatible client

## ⏳ Next Steps

1. Integration testing with real targets
2. Deploy to Docker and test on server
3. Add continuous monitoring / scheduled rescans
4. Add CI/CD integration testing
5. Web dashboard deployment
