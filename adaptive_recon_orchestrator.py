"""
Adaptive Recon + Fuzzing Orchestrator
--------------------------------------
Ties the full loop together:
  subdomain enum -> live host probe -> tech fingerprint -> JS/endpoint extraction
      -> ReconContext built -> adaptive wordlist generated -> fuzzing executed
      -> hits fed back into memory -> noise filtered by cheap model
      -> diffed against last run -> only NEW findings surfaced

Design principles:
  - Real tools do real work (subfinder/httpx/katana/nuclei/ffuf)
  - Cheap models handle high-volume triage
  - Claude-tier only sees pre-filtered slice
  - Everything persists across runs so the pipeline gets smarter over time
"""

import json
import os
import shutil
import sqlite3
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from adaptive_wordlist_engine import (
    ReconContext,
    build_adaptive_wordlist,
    init_memory_db,
    record_hit,
    write_wordlist,
)

DB_PATH = Path("recon_memory.db")
WORKDIR = Path("recon_runs")


# ─── Tool Availability ─────────────────────────────────────────

REQUIRED_TOOLS = ["subfinder", "httpx", "katana", "nuclei", "ffuf"]


def check_tools() -> dict[str, bool]:
    return {tool: shutil.which(tool) is not None for tool in REQUIRED_TOOLS}


# ─── Persistent State ──────────────────────────────────────────

def init_recon_db(path: Path = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS assets (
            domain TEXT,
            subdomain TEXT,
            first_seen TEXT,
            last_seen TEXT,
            status_code INTEGER,
            tech_stack TEXT,
            PRIMARY KEY (domain, subdomain)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS runs (
            domain TEXT,
            run_time TEXT,
            new_assets INTEGER,
            new_findings INTEGER
        )
    """)
    conn.commit()
    return conn


def diff_against_history(conn: sqlite3.Connection, domain: str, current: list[str]) -> tuple[list[str], list[str]]:
    """Returns (new_subdomains, gone_subdomains) vs last known state."""
    known = {r[0] for r in conn.execute(
        "SELECT subdomain FROM assets WHERE domain = ?", (domain,)
    ).fetchall()}
    current_set = set(current)
    new = sorted(current_set - known)
    gone = sorted(known - current_set)

    now = datetime.now(timezone.utc).isoformat()
    for sub in current_set:
        conn.execute("""
            INSERT INTO assets (domain, subdomain, first_seen, last_seen)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(domain, subdomain) DO UPDATE SET last_seen = ?
        """, (domain, sub, now, now, now))
    conn.commit()
    return new, gone


# ─── Tool Wrappers ─────────────────────────────────────────────

def run_subfinder(domain: str, workdir: Path, timeout: int = 60) -> list[str]:
    out_file = workdir / "subdomains.txt"
    try:
        subprocess.run(
            ["subfinder", "-d", domain, "-silent", "-timeout", "30", "-o", str(out_file)],
            check=True, timeout=timeout, capture_output=True,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        pass
    return out_file.read_text().splitlines() if out_file.exists() else []


def run_httpx(subdomains: list[str], workdir: Path, timeout: int = 120) -> list[dict]:
    in_file = workdir / "subdomains.txt"
    out_file = workdir / "httpx_results.jsonl"
    in_file.write_text("\n".join(subdomains))
    try:
        subprocess.run(
            ["httpx", "-l", str(in_file), "-json", "-tech-detect", "-status-code",
             "-title", "-web-server", "-silent", "-timeout", "10", "-retries", "1",
             "-o", str(out_file)],
            check=True, timeout=timeout, capture_output=True,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        pass
    if not out_file.exists():
        return []
    results = []
    for line in out_file.read_text().splitlines():
        if line.strip():
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return results


def run_katana(target: str, workdir: Path, timeout: int = 60) -> list[str]:
    out_file = workdir / "katana_endpoints.txt"
    try:
        subprocess.run(
            ["katana", "-u", target, "-jc", "-silent", "-timeout", "10",
             "-o", str(out_file)],
            check=True, timeout=timeout, capture_output=True,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        pass
    return out_file.read_text().splitlines() if out_file.exists() else []


def run_nuclei(targets_file: Path, workdir: Path,
               severity: str = "medium,high,critical", timeout: int = 300) -> list[dict]:
    out_file = workdir / "nuclei_results.jsonl"
    try:
        subprocess.run(
            ["nuclei", "-l", str(targets_file), "-severity", severity,
             "-jsonl", "-silent", "-timeout", "10", "-retries", "1",
             "-o", str(out_file)],
            check=True, timeout=timeout, capture_output=True,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        pass
    if not out_file.exists():
        return []
    results = []
    for line in out_file.read_text().splitlines():
        if line.strip():
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return results


def run_ffuf(target: str, wordlist_path: Path, workdir: Path, timeout: int = 120) -> list[dict]:
    out_file = workdir / "ffuf_results.json"
    try:
        subprocess.run(
            ["ffuf", "-u", f"{target}/FUZZ", "-w", str(wordlist_path),
             "-mc", "200,204,301,302,307,401,403,405,500",
             "-of", "json", "-o", str(out_file),
             "-t", "20", "-rate", "20", "-timeout", "10", "-s"],
            check=True, timeout=timeout, capture_output=True,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        pass
    if not out_file.exists():
        return []
    try:
        return json.loads(out_file.read_text()).get("results", [])
    except json.JSONDecodeError:
        return []


# ─── Cheap-Model Triage Gate ───────────────────────────────────

TRIAGE_PROMPT = """You are triaging raw scanner output for false positives.
Given this finding, respond with ONLY a JSON object:
{{"verdict": "likely_real" | "likely_noise", "confidence": 0-100, "reason": "<one sentence>"}}

Finding:
{finding}
"""


def triage_finding(finding: dict, llm_call: Callable[[str], str]) -> dict:
    prompt = TRIAGE_PROMPT.format(finding=json.dumps(finding))
    raw = llm_call(prompt).strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"verdict": "likely_noise", "confidence": 0, "reason": "unparseable"}


def filter_findings(findings: list[dict], llm_call: Callable[[str], str],
                    min_confidence: int = 60) -> list[dict]:
    survivors = []
    for f in findings:
        verdict = triage_finding(f, llm_call)
        if verdict["verdict"] == "likely_real" and verdict["confidence"] >= min_confidence:
            f["_triage"] = verdict
            survivors.append(f)
    return survivors


# ─── Scope Enforcement ─────────────────────────────────────────

@dataclass
class ScopeConfig:
    in_scope_domains: list[str]
    out_of_scope: list[str] = field(default_factory=list)
    max_requests_per_sec: int = 20
    active_testing_allowed: bool = True


def is_in_scope(host: str, scope: ScopeConfig) -> bool:
    if any(host.endswith(bad) for bad in scope.out_of_scope):
        return False
    return any(host == d or host.endswith("." + d) for d in scope.in_scope_domains)


# ─── Full Pipeline ─────────────────────────────────────────────

def run_full_pipeline(
    domain: str,
    scope: ScopeConfig,
    llm_call: Callable[[str], str],
    workdir_base: Path = WORKDIR,
    run_active_fuzzing: bool = True,
) -> dict:
    """
    Full adaptive recon + fuzzing pipeline.

    Returns dict with:
      - new_subdomains, gone_subdomains (asset diffing)
      - live_hosts, js_endpoints_found (recon metrics)
      - triaged_nuclei_findings (filtered nuclei results)
      - triaged_fuzz_findings (per-host filtered fuzz results)
      - workdir (artifacts location)
    """
    tools = check_tools()
    missing = [t for t, ok in tools.items() if not ok]
    if missing:
        raise RuntimeError(f"Missing tools: {missing}")

    conn = init_recon_db()
    wl_conn = init_memory_db()
    workdir = workdir_base / domain / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    workdir.mkdir(parents=True, exist_ok=True)

    # --- Recon Phase ---
    all_subs = run_subfinder(domain, workdir)
    in_scope_subs = [s for s in all_subs if is_in_scope(s, scope)]
    new_subs, gone_subs = diff_against_history(conn, domain, in_scope_subs)

    httpx_results = run_httpx(in_scope_subs, workdir)
    live_hosts = [r for r in httpx_results if r.get("status_code")]

    # --- Fingerprint + Endpoint Extraction ---
    all_js_endpoints = []
    tech_by_host = {}
    for host in live_hosts:
        url = host.get("url", "")
        tech_by_host[url] = host.get("tech", [])
        try:
            js_eps = run_katana(url, workdir)
            all_js_endpoints.extend(js_eps)
        except Exception:
            continue

    # --- Vulnerability Scan (noisy, gets triaged) ---
    live_targets_file = workdir / "live_targets.txt"
    live_targets_file.write_text("\n".join(h.get("url", "") for h in live_hosts))
    raw_nuclei_findings = run_nuclei(live_targets_file, workdir) if live_hosts else []

    # --- Adaptive Fuzzing (per-host, tech-aware) ---
    fuzz_results = {}
    if run_active_fuzzing and scope.active_testing_allowed:
        for host in live_hosts:
            url = host.get("url", "")
            ctx = ReconContext(
                domain=url,
                tech_stack=tech_by_host.get(url, []),
                discovered_paths=[],
                js_endpoints=[e for e in all_js_endpoints if url in e],
                server_headers={"Server": host.get("webserver", "")},
            )
            wordlist = build_adaptive_wordlist(
                ctx, llm_call,
                conn=wl_conn,
            )
            wl_path = workdir / f"wordlist_{url.replace('://', '_').replace('/', '_')}.txt"
            write_wordlist(wordlist, str(wl_path))

            hits = run_ffuf(url, wl_path, workdir)
            fuzz_results[url] = hits
            for hit in hits:
                record_hit(wl_conn, hit.get("input", {}).get("FUZZ", ""),
                           ",".join(sorted(tech_by_host.get(url, []))),
                           hit.get("status", 0))

    # --- Triage Gate ---
    filtered_nuclei = filter_findings(raw_nuclei_findings, llm_call)
    filtered_fuzz = {
        url: filter_findings(hits, llm_call) for url, hits in fuzz_results.items()
    }

    conn.execute(
        "INSERT INTO runs (domain, run_time, new_assets, new_findings) VALUES (?, ?, ?, ?)",
        (domain, datetime.now(timezone.utc).isoformat(), len(new_subs),
         len(filtered_nuclei) + sum(len(v) for v in filtered_fuzz.values())),
    )
    conn.commit()

    return {
        "domain": domain,
        "new_subdomains": new_subs,
        "gone_subdomains": gone_subs,
        "live_hosts": len(live_hosts),
        "js_endpoints_found": len(all_js_endpoints),
        "raw_nuclei_findings": len(raw_nuclei_findings),
        "triaged_nuclei_findings": filtered_nuclei,
        "triaged_fuzz_findings": filtered_fuzz,
        "workdir": str(workdir),
    }
