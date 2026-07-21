#!/usr/bin/env python3
"""
PENTDEM — Autonomous AI Bug Hunting Engine
Single command. Full pipeline. Docker-isolated. AI-driven.

Usage:
    pentdem <target> [--mode full|quick|targeted] [--docker] [--mock]
    pentdem example.com
    pentdem example.com --mode quick --docker
    pentdem localhost:5000 --mode full
"""

import asyncio
import sys
import os
import time
import json
import shutil
import textwrap
from pathlib import Path


# ═══════════════════════════════════════════════════════════════════
# Terminal helpers
# ═══════════════════════════════════════════════════════════════════

def c(s: str, code: str) -> str:
    codes = {
        "r": "31", "g": "32", "y": "33", "b": "34", "m": "35", "c": "36",
        "w": "37", "R": "41", "G": "42", "bold": "1", "dim": "2",
        "ul": "4", "blink": "5", "rev": "7",
    }
    return f"\033[{codes.get(code, '0')}m{s}\033[0m"

def pad(s: str, n: int) -> str:
    return s.ljust(n)

def box(lines: list, border_color: str = "c") -> str:
    """Draw an ASCII box around lines."""
    width = max(len(l) for l in lines) + 4
    top = c("╔" + "═" * (width - 2) + "╗", border_color)
    mid = "\n".join(c("║", border_color) + f" {l:<{width-4}} " + c("║", border_color) for l in lines)
    bot = c("╚" + "═" * (width - 2) + "╝", border_color)
    return f"{top}\n{mid}\n{bot}"

def clear():
    os.system("clear 2>/dev/null || cls 2>/dev/null || printf '\\033c'")

# ═══════════════════════════════════════════════════════════════════
# Banners
# ═══════════════════════════════════════════════════════════════════

BANNER = r"""
██████╗ ███████╗███╗   ██╗████████╗██████╗ ███████╗███╗   ███╗
██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔══██╗██╔════╝████╗ ████║
██████╔╝█████╗  ██╔██╗ ██║   ██║   ██║  ██║█████╗  ██╔████╔██║
██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██║  ██║██╔══╝  ██║╚██╔╝██║
██║     ███████╗██║ ╚████║   ██║   ██████╔╝███████╗██║ ╚═╝ ██║
╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝     ╚═╝"""

BANNER_SMALL = r"""
╔══════════════════════════════════════════════════════╗
║         P E N T D E M   A I   E N G I N E            ║
╚══════════════════════════════════════════════════════╝"""

TAGLINES = [
    "The tool the NSA wishes it built.",
    "Autonomous offense. Human-grade reports.",
    "One command. Full kill chain. Zero false positives.",
    "Recon. Hunt. Exploit. Report. All at once.",
    "Your bug bounty career, automated.",
    "Built for hunters. Feared by defenders.",
    "The last pentest framework you'll ever need.",
    "Docker-isolated. AI-driven. Battle-tested.",
]

# ═══════════════════════════════════════════════════════════════════
# Progress spinners
# ═══════════════════════════════════════════════════════════════════

SPINNER = ["◐", "◓", "◑", "◒"]
BAR_CHARS = "█▉▊▋▌▍▎▏"


class LiveDisplay:
    """Terminal display manager — sections, spinners, progress bars."""

    def __init__(self):
        self.sections = {}  # id -> {label, status, detail, spinner_idx, start_time}
        self._order = []
        self._ai_log = []
        self._last_lines = 0

    def add_section(self, sid: str, label: str):
        self.sections[sid] = {
            "label": label, "status": "pending", "detail": "",
            "spinner_idx": 0, "start_time": time.time(),
        }
        self._order.append(sid)

    def update(self, sid: str, status: str = None, detail: str = None):
        if sid in self.sections:
            if status:
                self.sections[sid]["status"] = status
            if detail is not None:
                self.sections[sid]["detail"] = detail

    def ai_says(self, message: str):
        self._ai_log.append(message)

    def render(self) -> str:
        """Build the full display string."""
        out = []
        now = time.time()

        for sid in self._order:
            sec = self.sections[sid]
            label = sec["label"]
            status = sec["status"]
            detail = sec["detail"]
            elapsed = now - sec["start_time"]

            # Status icon
            if status == "running":
                icon = c(SPINNER[sec["spinner_idx"] % len(SPINNER)], "c")
                sec["spinner_idx"] += 1
            elif status == "done":
                icon = c("✓", "g")
            elif status == "failed":
                icon = c("✗", "r")
            elif status == "warn":
                icon = c("⚠", "y")
            elif status == "found":
                icon = c("◆", "m")
            else:
                icon = c("·", "dim")

            # Build line
            line = f"  {icon} {c(label, 'bold' if status == 'running' else '')}"
            if detail:
                line += f"  {c(detail, 'dim')}"
            if status == "running":
                line += f"  {c(f'{elapsed:.1f}s', 'dim')}"

            out.append(line)

        # AI log
        if self._ai_log:
            out.append("")
            out.append(f"  {c('▛', 'm')}{c('▀', 'm') * 50}{c('▜', 'm')}")
            out.append(f"  {c('AI DECISION ENGINE', 'm')}")
            for msg in self._ai_log[-3:]:
                wrapped = textwrap.fill(msg, width=60)
                for wline in wrapped.split("\n"):
                    out.append(f"  {c('│', 'm')} {c(wline, 'dim')}")
            out.append(f"  {c('▙', 'm')}{c('▄', 'm') * 50}{c('▟', 'm')}")

        return "\n".join(out)

    def clear(self):
        # Move cursor up and clear previous render
        if self._last_lines:
            sys.stdout.write(f"\033[{self._last_lines}A\033[J")
        self._last_lines = 0

    def flush(self):
        self.clear()
        rendered = self.render()
        self._last_lines = rendered.count("\n") + 1
        sys.stdout.write(rendered + "\n")
        sys.stdout.flush()


# ═══════════════════════════════════════════════════════════════════
# Docker check
# ═══════════════════════════════════════════════════════════════════

def check_docker() -> dict:
    """Check Docker availability and installed tools."""
    docker_ok = shutil.which("docker") is not None
    tools = {
        "subfinder": shutil.which("subfinder") is not None,
        "httpx": shutil.which("httpx") is not None,
        "katana": shutil.which("katana") is not None,
        "ffuf": shutil.which("ffuf") is not None,
        "nuclei": shutil.which("nuclei") is not None,
        "curl": shutil.which("curl") is not None,
    }
    return {
        "docker_available": docker_ok,
        "docker_running": _docker_running() if docker_ok else False,
        "tools": tools,
        "tools_count": sum(tools.values()),
    }


def _docker_running() -> bool:
    import subprocess
    try:
        subprocess.run(["docker", "info"], capture_output=True, timeout=3, check=False)
        return True
    except Exception:
        return False


# ═══════════════════════════════════════════════════════════════════
# Main engine
# ═══════════════════════════════════════════════════════════════════

async def run_engine(
    target: str,
    mode: str = "full",
    platform: str = "hackerone",
    source_type: str = "url",
    engine: str = "hybrid",
    use_docker: bool = False,
    mock: bool = False,
    display: LiveDisplay = None,
):
    """Run the full PENTDEM engine and return results."""
    from pipeline import PentestPipeline

    pipeline = PentestPipeline(config={
        "mock_mode": mock,
        "use_docker": use_docker,
    })

    last_stage = [None]
    hunt_start = [0]
    hunt_count = [0]

    def on_progress(event):
        if not isinstance(event, dict):
            return
        stage = event.get("stage", "")
        status = event.get("status", "")
        data = event.get("data", {})
        msg = data.get("message", "")

        # Map pipeline stages to display sections
        stage_map = {
            "init": "init",
            "scope": "init",
            "recon": "recon",
            "learn": "recon",
            "hunt": "hunt",
            "advanced_hunt": "advanced",
            "agent": "agent",
            "quality_gate": "verify",
            "chain": "chain",
            "validate": "verify",
            "screenshot": "report",
            "report": "report",
            "memory": "report",
        }

        sid = stage_map.get(stage, "hunt")

        if display:
            if status == "running":
                display.update(sid, status="running", detail=msg[:80] if msg else "")

                # Track hunt findings count
                if stage == "hunt" and "findings" in data:
                    hunt_count[0] = data["findings"]
                    if hunt_count[0] > 0:
                        display.update("hunt", detail=f"{hunt_count[0]} findings so far")

                # AI decision messages
                if stage == "hunt" and "decision" in data:
                    decision = data["decision"]
                    action = decision.get("action", "")
                    display.ai_says(f"Decision: {action} — {data.get('message', '')}")

            elif status == "completed":
                detail = ""
                if stage == "recon":
                    fdata = data.get("findings", data.get("message", ""))
                    detail = str(fdata)[:80]
                elif stage == "hunt":
                    detail = f"{data.get('findings', 0)} findings"
                elif stage == "advanced_hunt":
                    detail = f"{data.get('findings', 0)} advanced findings"
                elif stage == "validate":
                    detail = f"{data.get('validated', 0)} validated"
                elif stage == "report":
                    detail = data.get("message", "")[:80]
                display.update(sid, status="done", detail=detail)

    pipeline.on_progress(on_progress)

    # Initialize display sections
    if display:
        display.add_section("init", "INIT")
        display.add_section("recon", "RECON")
        display.add_section("hunt", "HUNT")
        display.add_section("advanced", "ADVANCED ATTACKS")
        display.add_section("verify", "VERIFY")
        display.add_section("chain", "CHAIN")
        display.add_section("report", "REPORT")
        display.update("init", status="running")

    t0 = time.time()

    try:
        results = await pipeline.run(
            target=target,
            mode=mode,
            platform=platform,
            source_type=source_type,
            engine=engine,
        )
    except Exception as e:
        if display:
            display.update("init", status="failed", detail=str(e)[:80])
            display.flush()
        raise

    elapsed = time.time() - t0

    if display:
        for sid in ["init", "recon", "hunt", "advanced", "verify", "chain", "report"]:
            if sid in display.sections and display.sections[sid]["status"] == "running":
                display.update(sid, status="done")

    return results, elapsed


# ═══════════════════════════════════════════════════════════════════
# Results display
# ═══════════════════════════════════════════════════════════════════

def print_results(results: dict, target: str, elapsed: float, docker_info: dict, use_docker: bool):
    """Print final results with the PENTDEM signature block."""
    findings = results.get("findings", [])
    individual = [f for f in findings if f.get("type") != "Attack Chain"]
    chains = results.get("chains", [])
    metrics = results.get("metrics", {})
    report_path = results.get("report_path", "")

    # Severity distribution
    sev_count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in individual:
        sev = f.get("severity", "info").lower()
        sev_count[sev] = sev_count.get(sev, 0) + 1

    print()
    print(f"  {c('▀' * 56, 'm')}")

    # Stat blocks
    stats = [
        f"  {c('TARGET', 'bold')}      {target}",
        f"  {c('DURATION', 'bold')}    {elapsed:.1f}s",
        f"  {c('MODE', 'bold')}        {results.get('mode', 'full')}",
        f"  {c('ENGINE', 'bold')}      {results.get('engine', 'hybrid')}",
        f"  {c('DOCKER', 'bold')}      {'YES' if use_docker else 'NO'}",
        "",
    ]

    # Findings bar
    if individual:
        bar_parts = []
        for sev, color in [("critical", "r"), ("high", "r"), ("medium", "y"), ("low", "b"), ("info", "dim")]:
            count = sev_count[sev]
            if count:
                bar_parts.append(c(f"{count} {sev.upper()}", color))
        stats.append(f"  {c('FINDINGS', 'bold')}    {', '.join(bar_parts)}")
    else:
        stats.append(f"  {c('FINDINGS', 'bold')}    {c('0 — no vulnerabilities found', 'g')}")

    if chains:
        stats.append(f"  {c('CHAINS', 'bold')}      {len(chains)} attack chains")

    if report_path:
        stats.append(f"  {c('REPORT', 'bold')}      {report_path}")

    for s in stats:
        print(s)

    # Individual findings
    if individual:
        print(f"\n  {c('▄' * 56, 'm')}")
        print(f"  {c('VULNERABILITY DETAIL', 'bold')}")
        print(f"  {c('─' * 56, 'dim')}")
        for i, f in enumerate(individual, 1):
            sev = f.get("severity", "medium").lower()
            sev_color = {"critical": "r", "high": "r", "medium": "y", "low": "b"}.get(sev, "w")
            vtype = f.get("type", f.get("vuln_class", "?")).upper()
            cvss = f.get("cvss_score", "?")
            conf = f.get("confidence", 0) * 100
            url = f.get("url", f.get("endpoint", ""))[:70]
            param = f.get("param", f.get("parameter", ""))
            payload = f.get("payload", "")[:50]
            evidence = f.get("evidence", "")[:120]
            verdict = ""
            if f.get("verification"):
                verdict = f["verification"].get("reason", f["verification"].get("status", ""))

            print(f"  {c(f'[{i}]', 'dim')} {c(vtype, 'bold')} {c(f'CVSS:{cvss}', sev_color)} {c(f'{conf:.0f}%', 'dim')} conf")
            if url:
                print(f"     {c('URL:', 'dim')} {url}")
            if param:
                print(f"     {c('Param:', 'dim')} {param}  {c('Payload:', 'dim')} {payload}")
            if evidence:
                print(f"     {c('Evidence:', 'dim')} {evidence}")
            if verdict:
                print(f"     {c('Verdict:', 'dim')} {verdict[:100]}")
            print()

    # Chains
    if chains:
        print(f"  {c('ATTACK CHAINS', 'bold')}")
        print(f"  {c('─' * 56, 'm')}")
        for chain in chains:
            name = chain.get("chain_name", chain.get("name", "Chain"))
            score = chain.get("total_score", 0)
            impact = chain.get("chain_impact", chain.get("impact", ""))
            print(f"  {c('◆', 'm')} {c(name, 'bold')}  {c(f'Score: {score}/100', 'y')}")
            if impact:
                print(f"     {c('Impact:', 'dim')} {impact[:100]}")
            for step in chain.get("steps", [])[:5]:
                if isinstance(step, dict):
                    print(f"     {c('↳', 'dim')} {step.get('type', '?')} → {step.get('target', '')}")
            print()

    # Signature block
    print(f"  {c('▀' * 56, 'm')}")
    print(f"  {c('PENTDEM ENGINE v1.5.0', 'bold')} — {c('Autonomous AI Bug Hunting', 'dim')}")
    print(f"  {c('Docker-isolated  |  AI-driven  |  Battle-tested', 'dim')}")
    print(f"  {c('Report generated at:', 'dim')} {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print()


# ═══════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════

async def main():
    # Parse args
    args = sys.argv[1:]

    if not args or "-h" in args or "--help" in args:
        print_help()
        return

    target = args[0]
    mode = "full"
    platform = "hackerone"
    source_type = "url"
    engine = "hybrid"
    use_docker = False
    mock = False

    i = 1
    while i < len(args):
        if args[i] == "--mode" and i + 1 < len(args):
            mode = args[i + 1]; i += 2
        elif args[i] == "--platform" and i + 1 < len(args):
            platform = args[i + 1]; i += 2
        elif args[i] == "--source" and i + 1 < len(args):
            source_type = args[i + 1]; i += 2
        elif args[i] == "--engine" and i + 1 < len(args):
            engine = args[i + 1]; i += 2
        elif args[i] == "--docker":
            use_docker = True; i += 1
        elif args[i] == "--mock":
            mock = True; i += 1
        else:
            i += 1

    # Auto-detect docker
    docker_info = check_docker()
    if use_docker and not docker_info["docker_available"]:
        print(f"\n  {c('WARNING: Docker requested but not available. Running locally.', 'y')}\n")
        use_docker = False

    # ── Splash screen ──
    clear()
    import random
    tagline = random.choice(TAGLINES)

    # Print banner
    print()
    for line in BANNER.split("\n"):
        print(f"  {c(line, 'm')}")
    print(f"  {c('AUTONOMOUS AI BUG HUNTING ENGINE v1.5.0', 'bold')}")
    print(f"  {c(tagline, 'dim')}")
    print()

    # Config box
    config_lines = [
        f"TARGET:    {target}",
        f"MODE:      {mode}",
        f"ENGINE:    {engine}",
        f"PLATFORM:  {platform}",
        f"DOCKER:    {'YES — isolated execution' if use_docker else 'NO — running locally'}",
        f"TOOLS:     {docker_info['tools_count']}/6 installed ({', '.join(k for k, v in docker_info['tools'].items() if v) or 'none'})",
        f"MOCK:      {'YES' if mock else 'NO'}",
        "",
        f"CLASSES:   18 vuln classes (IDOR, SSRF, XSS, SQLi, SSTI, LFI, ...)",
    ]
    print(box(config_lines, "c"))
    print()

    # Docker warning banner if not using it
    if not use_docker and not mock:
        print(f"  {c('╔══════════════════════════════════════════════════╗', 'y')}")
        print(f"  {c('║', 'y')}  {c('Docker not detected. Some tools may be unavailable.', 'y')}  {c('║', 'y')}")
        if docker_info["tools_count"] < 3:
            tc = docker_info["tools_count"]
            print(f"  {c('║', 'y')}  {c(f'Only {tc}/6 tools found. Run --docker for full coverage.', 'y')}  {c('║', 'y')}")
        print(f"  {c('╚══════════════════════════════════════════════════╝', 'y')}")
        print()

    print(f"  {c('Press Ctrl+C to abort', 'dim')}")
    print()

    # ── Run engine ──
    display = LiveDisplay()
    display.update("init", status="running", detail=f"Starting engine for {target}...")
    display.flush()

    # Animation loop
    animation_running = True

    async def animate():
        while animation_running:
            display.flush()
            await asyncio.sleep(0.15)

    anim_task = asyncio.create_task(animate())

    async def _stop_anim():
        nonlocal animation_running
        animation_running = False
        try:
            anim_task.cancel()
            await anim_task
        except (asyncio.CancelledError, Exception):
            pass

    try:
        results, elapsed = await run_engine(
            target=target,
            mode=mode,
            platform=platform,
            source_type=source_type,
            engine=engine,
            use_docker=use_docker,
            mock=mock,
            display=display,
        )
    except KeyboardInterrupt:
        await _stop_anim()
        display.clear()
        print(f"\n  {c('╔══════════════════════════════════════════════╗', 'y')}")
        print(f"  {c('║', 'y')}  {c('SCAN CANCELLED BY USER', 'y')}                     {c('║', 'y')}")
        print(f"  {c('╚══════════════════════════════════════════════╝', 'y')}")
        print()
        sys.exit(130)
    except Exception as e:
        await _stop_anim()
        display.clear()
        print(f"\n  {c(f'FATAL: {e}', 'r')}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    await _stop_anim()
    display.clear()

    # ── Results ──
    print_results(results, target, elapsed, docker_info, use_docker)


def print_help():
    print()
    print(f"  {c('PENTDEM', 'bold')} — Autonomous AI Bug Hunting Engine")
    print()
    print(f"  {c('USAGE', 'y')}")
    print(f"    pentdem <target> [options]")
    print()
    print(f"  {c('OPTIONS', 'y')}")
    print(f"    --mode     quick | full | targeted   (default: full)")
    print(f"    --platform hackerone | bugcrowd | intigriti | immunefi")
    print(f"    --engine   agent | pipeline | hybrid (default: hybrid)")
    print(f"    --source   url | repo               (default: url)")
    print(f"    --docker   Enable Docker-isolated execution")
    print(f"    --mock     Mock mode (no real API calls)")
    print()
    print(f"  {c('EXAMPLES', 'y')}")
    print(f"    pentdem example.com")
    print(f"    pentdem example.com --mode quick")
    print(f"    pentdem example.com --docker --mode full")
    print(f"    pentdem localhost:5000 --mode targeted")
    print(f"    pentdem api.example.com --engine agent")
    print()


def main_cli():
    """Entry point for console_scripts — wraps async main."""
    asyncio.run(main())


if __name__ == "__main__":
    main_cli()
