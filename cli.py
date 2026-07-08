#!/usr/bin/env python3
import asyncio
import sys
import json
import threading
import time
from pipeline import PentestPipeline


def color(s: str, code: str) -> str:
    codes = {"red": "31", "green": "32", "yellow": "33", "blue": "34", "magenta": "35", "cyan": "36", "bold": "1"}
    c = codes.get(code, "0")
    return f"\033[{c}m{s}\033[0m"


# ─── Loading Animation ──────────────────────────────────────────

class LoadingAnimation:
    """Simple 3-dot loading."""

    def __init__(self):
        self._stop = threading.Event()
        self._thread = None
        self._lock = threading.Lock()
        self._dots = 0

    def start(self):
        self._thread = threading.Thread(target=self._animate, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1)

    def set_stage(self, stage: str, status: str = "running"):
        pass

    def _animate(self):
        while not self._stop.is_set():
            self._dots = (self._dots + 1) % 4
            dots = "." * self._dots
            sys.stdout.write(f"\r  {dots:3s}")
            sys.stdout.flush()
            self._stop.wait(0.4)

    def done(self, stage: str):
        pass

    def print_final(self, results: dict):
        self.stop()
        sys.stdout.write("\r  \n")
        sys.stdout.flush()


async def main():
    if len(sys.argv) < 2:
        print(f"  {color('PENTDEM', 'bold')}")
        print(f"  {'=' * 50}")
        print()
        print(f"  {color('USAGE', 'yellow')}")
        print(f"    python cli.py <target> [mode] [platform] [--engine agent|pipeline|hybrid] [--mock]")
        print(f"    python cli.py knowledge <action> [options]")
        print()
        print(f"  {color('SCAN COMMANDS', 'yellow')}")
        print(f"    python cli.py example.com {color('full', 'cyan')} {color('hackerone', 'cyan')} [{color('--mock', 'cyan')}]")
        print(f"    python cli.py example.com {color('quick', 'cyan')}")
        print(f"    python cli.py https://github.com/org/repo {color('full', 'cyan')} --source repo")
        print()
        print(f"  {color('KNOWLEDGE COMMANDS', 'yellow')}")
        print(f"    python cli.py knowledge {color('fetch', 'cyan')}          Fetch disclosed reports & learn")
        print(f"    python cli.py knowledge {color('stats', 'cyan')}          Show knowledge base stats")
        print(f"    python cli.py knowledge {color('search', 'cyan')} <q>     Search disclosed reports")
        print(f"    python cli.py knowledge {color('query', 'cyan')} --class XSS  Query by vuln class")
        print()
        print(f"  {color('MODES', 'yellow')}")
        print(f"    {color('quick', 'cyan')}     Fast recon + top-6 vuln tests")
        print(f"    {color('full', 'cyan')}      Complete recon + all 15 vuln classes + chain detection")
        print(f"    {color('targeted', 'cyan')}  Minimal recon + core-4 vuln tests (idor, ssrf, xss, sqli)")
        print()
        print(f"  {color('ENGINES', 'yellow')}")
        print(f"    {color('agent', 'cyan')}     Autonomous AI agent (default) — tool-driven + LLM analysis")
        print(f"    {color('pipeline', 'cyan')}  Legacy pipeline — skills-based parallel hunting")
        print(f"    {color('hybrid', 'cyan')}    Both engines — agent for tools, pipeline for deep analysis")
        print()
        print(f"  {color('PLATFORMS', 'yellow')}")
        print(f"    {color('hackerone', 'cyan')}  HackerOne (default)")
        print(f"    {color('bugcrowd', 'cyan')}   Bugcrowd")
        print(f"    {color('intigriti', 'cyan')}  Intigriti")
        print(f"    {color('immunefi', 'cyan')}   Immunefi")
        print()
        print(f"  {color('SOURCE TYPE', 'yellow')}")
        print(f"    {color('url', 'cyan')}        Black-box web app testing (default)")
        print(f"    {color('repo', 'cyan')}       White-box source code analysis")
        print()
        print(f"  {color('OPTIONS', 'yellow')}")
        print(f"    {color('--mock', 'cyan')}     Mock mode (no real API/tool calls)")
        print(f"    {color('--source', 'cyan')}   Source type: url or repo")
        print(f"    {color('--engine', 'cyan')}   Execution engine: agent, pipeline, or hybrid")
        print()
        print(f"  {color('VULN CLASSES (15)', 'yellow')}")
        print(f"    IDOR, SSRF, XSS, SQLi, Auth Bypass, SSTI, Open Redirect")
        print(f"    LFI, Command Injection, NoSQLi, GraphQL, JWT")
        print(f"    Deserialization, Path Traversal, Race Condition")
        print()
        print(f"  {color('EXAMPLES', 'yellow')}")
        print(f"    python cli.py example.com full hackerone --mock")
        print(f"    python cli.py example.com quick --source url")
        print(f"    python cli.py github.com/org/repo full github --source repo")
        print(f"    python cli.py knowledge stats")
        sys.exit(1)

    # Knowledge commands
    if sys.argv[1] == "knowledge":
        mock_mode = "--mock" in sys.argv
        knowledge_args = [a for a in sys.argv[2:] if a != "--mock"]
        return await _handle_knowledge_command(knowledge_args, mock_mode)

    target = sys.argv[1]
    mode = sys.argv[2] if len(sys.argv) > 2 else "full"
    platform = sys.argv[3] if len(sys.argv) > 3 else "hackerone"
    mock_mode = "--mock" in sys.argv
    use_docker = "--docker" in sys.argv

    # Parse --source flag
    source_type = "url"
    if "--source" in sys.argv:
        src_idx = sys.argv.index("--source")
        if src_idx + 1 < len(sys.argv):
            source_type = sys.argv[src_idx + 1]

    # Parse --engine flag
    engine = "agent"  # Default to autonomous agent
    if "--engine" in sys.argv:
        eng_idx = sys.argv.index("--engine")
        if eng_idx + 1 < len(sys.argv):
            engine = sys.argv[eng_idx + 1]

    print()
    print(f"  {color('PENTDEM', 'bold')}")
    print(f"  {'=' * 50}")
    print(f"  {color('Target:', 'yellow')}    {target}")
    print(f"  {color('Mode:', 'yellow')}      {mode}")
    print(f"  {color('Platform:', 'yellow')}  {platform}")
    print(f"  {color('Source:', 'yellow')}    {source_type}")
    print(f"  {color('Engine:', 'yellow')}    {engine}")
    print(f"  {color('Docker:', 'yellow')}    {'Yes' if use_docker else 'No'}")
    print(f"  {color('Mock:', 'yellow')}      {'Yes' if mock_mode else 'No'}")
    print()

    pipeline = PentestPipeline(config={"mock_mode": mock_mode, "use_docker": use_docker})

    last_message = [None]

    def on_progress(event):
        msg = event.get("data", {}).get("message") if isinstance(event, dict) else None
        if msg and msg != last_message[0]:
            last_message[0] = msg
            print(f"  {color('.', 'blue')} {msg}")

    pipeline.on_progress(on_progress)

    try:
        results = await pipeline.run(target, mode=mode, platform=platform, source_type=source_type, engine=engine)
    except (KeyboardInterrupt, asyncio.CancelledError):
        print(f"\n  {color('Interrupted', 'yellow')}")
        sys.exit(130)
    except Exception as e:
        print(f"\n  {color(f'ERROR: {e}', 'red')}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    findings = results.get("findings", [])
    candidate_findings = results.get("candidate_findings", findings)
    chains = results.get("chains", [])
    report_text = results.get("report")
    metrics = results.get("metrics", {})

    print()
    print(f"  {color('╔══════════════════════════════════════════╗', 'green')}")
    print(f"  {color('║           SCAN COMPLETE                  ║', 'green')}")
    print(f"  {color('╚══════════════════════════════════════════╝', 'green')}")
    print()
    print(f"  {color('Target:', 'yellow')}  {target}")
    duration = metrics.get("duration", 0)
    print(f"  {color('Time:', 'yellow')}   {duration:.1f}s")
    print(f"  {color('Mode:', 'yellow')}   {mode}")

    # Show recon diagnostics (agent engine stores as agent_recon, pipeline as recon)
    recon_data = results.get("stages", {}).get("agent_recon", results.get("stages", {}).get("recon", {}))
    subdomains = len(recon_data.get("subdomains", []))
    live_hosts = len(recon_data.get("live_hosts", []))
    urls = len(recon_data.get("urls", []))
    print(f"  {color('Recon:', 'yellow')}  {subdomains} subdomains, {live_hosts} live hosts, {urls} URLs")

    individual_findings = [f for f in findings if f.get("type") != "Attack Chain"]
    individual_candidates = [f for f in candidate_findings if isinstance(f, dict) and f.get("type") != "Attack Chain"]
    rejected_count = max(0, len(individual_candidates) - len(individual_findings))
    print(f"  {color('Findings:', 'yellow')} {len(individual_findings)} reportable {'vulnerability' if len(individual_findings) == 1 else 'vulnerabilities'}")
    if rejected_count:
        print(f"  {color('Filtered:', 'yellow')} {rejected_count} non-reportable candidate(s)")
    print(f"  {color('Chains:', 'yellow')}  {len(chains)} {'attack chain' if len(chains) == 1 else 'attack chains'}")
    print()

    if individual_findings:
        print(f"  {color('FINDINGS', 'bold')}")
        print(f"  {color('─' * 50, 'blue')}")
        for i, f in enumerate(individual_findings, 1):
            sev = f.get("severity", "medium")
            sev_color = {"critical": "red", "high": "red", "medium": "yellow", "low": "blue"}.get(sev, "white")
            cvss = f.get("cvss_score", "N/A")
            confidence = f.get("confidence", 0.5)
            vuln_type = f.get("type", f.get("vuln_class", "Unknown"))
            url = f.get("url", f.get("endpoint", ""))[:60]
            param = f.get("param", f.get("parameter", ""))
            payload = f.get("payload", "")[:40]
            mitre_id = f.get("mitre_attack_id", "")
            noise = f.get("noise_level", "")
            source = f.get("source", "")

            print(f"  {i}. {color(vuln_type, 'bold')} [{color(sev.upper(), sev_color)}] CVSS:{cvss}")
            if url:
                print(f"     {color('URL:', 'cyan')} {url}")
            if param:
                print(f"     {color('Param:', 'cyan')} {param}")
            if payload:
                print(f"     {color('Payload:', 'cyan')} {payload}")
            if mitre_id:
                print(f"     {color('ATT&CK:', 'cyan')} {mitre_id}")
            if noise:
                print(f"     {color('OPSEC:', 'cyan')} {noise.upper()}")
            if source:
                print(f"     {color('Agent:', 'cyan')} {source}")
            print(f"     {color('Confidence:', 'cyan')} {confidence*100:.0f}%")
            desc = f.get("description", "")
            if desc:
                print(f"     {desc[:100]}")
            print()

    if chains:
        print(f"  {color('ATTACK CHAINS', 'bold')}")
        print(f"  {color('─' * 50, 'magenta')}")
        for chain in chains:
            sev = chain.get("computed_severity", chain.get("severity", "high"))
            sev_color = {"critical": "red", "high": "red", "medium": "yellow"}.get(sev, "white")
            total_score = chain.get("total_score", 0)
            scores = chain.get("scores", {})
            print(f"  🔗 {color(chain.get('chain_name', chain.get('name', 'Chain')), 'bold')} [{color(sev.upper(), sev_color)}] Score:{total_score}/100")
            if scores:
                print(f"     {color('Scores:', 'cyan')} Reach:{scores.get('reach',0)} Reliability:{scores.get('reliability',0)} Stealth:{scores.get('stealth',0)} Speed:{scores.get('speed',0)} Impact:{scores.get('impact',0)}")
            for step in chain.get("steps_to_reproduce", chain.get("steps", [])):
                if isinstance(step, dict):
                    print(f"     {step.get('type', '?')} — {step.get('target', '')}")
                else:
                    print(f"     {step}")
            print(f"     {color('Impact:', 'magenta')} {chain.get('chain_impact', chain.get('impact', ''))}")
            print()

    if report_text:
        print(f"  {color('REPORT PREVIEW', 'bold')}")
        print(f"  {color('─' * 50, 'blue')}")
        lines = report_text.strip().split("\n")
        for line in lines[:10]:
            print(f"  {line[:100]}")
        if len(lines) > 10:
            print(f"  {color('... (report truncated, total ' + str(len(lines)) + ' lines)', 'cyan')}")
        print()

    print(f"  {color('DONE', 'green')} — {len(individual_findings)} reportable findings, {rejected_count} filtered candidates, {len(chains)} chains in {duration:.1f}s")


async def _handle_knowledge_command(args: list, mock_mode: bool = False):
    """Handle knowledge subcommands."""
    from skills.knowledge import KnowledgeSkill

    skill = KnowledgeSkill(mock=mock_mode)
    action = args[0] if args else "stats"

    print(f"  {color('📚 KNOWLEDGE BASE', 'bold')}")
    print(f"  {color('─' * 50, 'blue')}")
    print()

    if action == "fetch":
        print(f"  Fetching disclosed reports...")
        result = await skill.execute({"action": "fetch", "sources": ["hackerone"], "limit": 25})
        stats = result.data.get("stats", {})
        print(f"  {color('Fetched:', 'yellow')}   {stats.get('fetched', 0)}")
        print(f"  {color('Parsed:', 'yellow')}    {stats.get('parsed', 0)}")
        print(f"  {color('New:', 'yellow')}       {stats.get('new', 0)}")
        print(f"  {color('Errors:', 'yellow')}    {stats.get('errors', 0)}")
        print(f"  {color('Total:', 'yellow')}     {result.data.get('total_reports', 0)}")

    elif action == "stats":
        result = await skill.execute({"action": "stats"})
        data = result.data
        print(f"  {color('Total Reports:', 'yellow')} {data.get('total_reports', 0)}")
        print(f"  {color('Patterns:', 'yellow')}      {data.get('patterns_learned', 0)}")
        print()
        print(f"  {color('BY VULNERABILITY CLASS:', 'bold')}")
        for entry in data.get("by_class", []):
            sev = entry.get("max_severity", "low")
            sev_color = {"critical": "red", "high": "red", "medium": "yellow", "low": "blue"}.get(sev, "white")
            print(f"    {entry['vulnerability_class']:25s} {color(str(entry['count']), 'cyan'):>5s}  [{color(sev.upper(), sev_color)}]")
        print()
        print(f"  {color('BY SOURCE:', 'bold')}")
        for entry in data.get("by_source", []):
            print(f"    {entry['source']:25s} {color(str(entry['count']), 'cyan')}")

    elif action == "search":
        query = " ".join(args[1:]) if len(args) > 1 else ""
        if not query:
            print(f"  {color('Usage:', 'yellow')} python cli.py knowledge search <query>")
            return
        print(f"  Searching for: {query}")
        print()
        result = await skill.execute({"action": "search", "q": query})
        for r in result.data.get("results", []):
            print(f"  {color(r.get('report_id', '?'), 'cyan')} {color(r.get('vulnerability_class', '?').upper(), 'yellow')} — {r.get('title', '')[:80]}")
            print(f"     {r.get('attack_vector', '')[:120]}")
            print()

    elif action == "query":
        vuln_class = ""
        tech = ""
        i = 1
        while i < len(args):
            if args[i] == "--class" and i + 1 < len(args):
                vuln_class = args[i + 1]
                i += 2
            elif args[i] == "--tech" and i + 1 < len(args):
                tech = args[i + 1]
                i += 2
            else:
                i += 1
        result = await skill.execute({
            "action": "query",
            "vuln_class": vuln_class,
            "tech": tech,
            "limit": 10,
        })
        reports = result.data.get("reports", [])
        print(f"  Found {len(reports)} reports matching class={vuln_class or '*'}, tech={tech or '*'}")
        print()
        for r in reports[:10]:
            sev_color = {"critical": "red", "high": "red", "medium": "yellow"}.get(r.get("severity", "").lower(), "white")
            print(f"  {color(r.get('report_id', '?'), 'cyan')} [{color(r.get('severity', '?').upper(), sev_color)}] {r.get('title', '')[:70]}")
            print(f"     Target: {r.get('target_tech', 'N/A')[:60]}")
            print(f"     Payload: {r.get('payload', 'N/A')[:80]}")
            print()

    else:
        print(f"  {color(f'Unknown knowledge action: {action}', 'red')}")
        print(f"  Use: fetch, stats, search, query")


if __name__ == "__main__":
    asyncio.run(main())
