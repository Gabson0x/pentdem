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
- `agents/__main__.py` - `python -m agents.autonomous` support
- `tools/catalog.py` - 34 security tools catalog with install commands
- `tools/__init__.py` - ToolExecutor (subprocess + mock)

### LLM-Based Features
- `skills/waf_bypass.py` - WAF detection + 10 bypass techniques + LLM payload generation
- SSTI evaluation proof (49 for 7*7), not just "not-403"
- Multiple template syntaxes (Jinja2, ERB, Freemarker, Twig, Mako, Smarty, Velocity)
- `is_reportable()` gate - Only CONFIRMED verdicts reach reports

### Skills
- `skills/base.py` - Base skill class with LLM fallback
- `skills/recon/` - Subdomain enum, live host detection, URL crawling
- `skills/hunt/` - IDOR, SSRF, XSS, SQLi testing
- `skills/validate/` - 7-Question Gate triage, severity assessment, dedup
- `skills/report/` - Report generation for HackerOne, Bugcrowd, Intigriti, Immunefi
- `skills/report_writer.py` - Standalone MD reports with is_reportable() gate
- `skills/memory/` - Session storage, pattern learning

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

## 📝 Recent Changes

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

1. Fix MiniMax API key format
2. Deploy to Docker and test on server
3. Add continuous monitoring / scheduled rescans
4. Add CI/CD integration
