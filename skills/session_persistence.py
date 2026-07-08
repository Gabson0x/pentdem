"""
Session Persistence — save/load scan state across runs.

What top tools have:
- Strobes: Architectural memory across runs
- PentestGPT: Session persistence
- Strix: Reproducible outputs

This module:
1. Saves full scan state (findings, decisions, chains) to disk
2. Loads previous scan state for resumption
3. Maintains architectural memory of target across runs
4. Tracks changes (new findings, fixed findings)
"""

import json
import os
import hashlib
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path


class SessionPersistence:
    """
    Save and load scan sessions across runs.
    """

    def __init__(self, session_dir: str = ".sessions"):
        self.session_dir = Path(session_dir)
        self.session_dir.mkdir(parents=True, exist_ok=True)
        self.current_session: Optional[Dict] = None

    def create_session(self, target: str) -> str:
        """Create a new scan session."""
        session_id = hashlib.md5(
            f"{target}_{datetime.now().isoformat()}".encode()
        ).hexdigest()[:12]

        self.current_session = {
            "session_id": session_id,
            "target": target,
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),
            "status": "running",
            "findings": [],
            "decisions": [],
            "attack_paths": [],
            "tool_results": {},
            "recon_data": {},
            "target_info": {},
            "kill_chain_graph": {},
            "stats": {
                "total_findings": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            },
        }

        self._save_session(session_id)
        return session_id

    def add_finding(self, finding: Dict):
        """Add a finding to the current session."""
        if not self.current_session:
            return

        self.current_session["findings"].append(finding)
        self.current_session["updated_at"] = datetime.now().isoformat()

        # Update stats
        severity = finding.get("severity", "info").lower()
        if severity in self.current_session["stats"]:
            self.current_session["stats"][severity] += 1
        self.current_session["stats"]["total_findings"] += 1

        self._save_session(self.current_session["session_id"])

    def add_findings(self, findings: List[Dict]):
        """Add multiple findings."""
        for finding in findings:
            self.add_finding(finding)

    def add_decision(self, decision: Dict):
        """Add an AI decision to the session."""
        if not self.current_session:
            return

        decision["timestamp"] = datetime.now().isoformat()
        self.current_session["decisions"].append(decision)
        self.current_session["updated_at"] = datetime.now().isoformat()
        self._save_session(self.current_session["session_id"])

    def add_attack_paths(self, paths: List[Dict]):
        """Add attack paths to the session."""
        if not self.current_session:
            return

        self.current_session["attack_paths"].extend(paths)
        self.current_session["updated_at"] = datetime.now().isoformat()
        self._save_session(self.current_session["session_id"])

    def add_tool_result(self, tool: str, result: Dict):
        """Add tool result to the session."""
        if not self.current_session:
            return

        self.current_session["tool_results"][tool] = result
        self.current_session["updated_at"] = datetime.now().isoformat()
        self._save_session(self.current_session["session_id"])

    def add_recon_data(self, key: str, data: Any):
        """Add reconnaissance data."""
        if not self.current_session:
            return

        self.current_session["recon_data"][key] = data
        self.current_session["updated_at"] = datetime.now().isoformat()
        self._save_session(self.current_session["session_id"])

    def update_target_info(self, info: Dict):
        """Update target information."""
        if not self.current_session:
            return

        self.current_session["target_info"].update(info)
        self.current_session["updated_at"] = datetime.now().isoformat()
        self._save_session(self.current_session["session_id"])

    def set_kill_chain_graph(self, graph: Dict):
        """Save the kill chain graph."""
        if not self.current_session:
            return

        self.current_session["kill_chain_graph"] = graph
        self.current_session["updated_at"] = datetime.now().isoformat()
        self._save_session(self.current_session["session_id"])

    def complete_session(self):
        """Mark session as completed."""
        if not self.current_session:
            return

        self.current_session["status"] = "completed"
        self.current_session["completed_at"] = datetime.now().isoformat()
        self.current_session["updated_at"] = datetime.now().isoformat()
        self._save_session(self.current_session["session_id"])

    def load_session(self, session_id: str) -> Optional[Dict]:
        """Load a previous session."""
        session_file = self.session_dir / f"{session_id}.json"
        if session_file.exists():
            with open(session_file) as f:
                self.current_session = json.load(f)
                return self.current_session
        return None

    def list_sessions(self, target: str = None) -> List[Dict]:
        """List all sessions, optionally filtered by target."""
        sessions = []
        for session_file in self.session_dir.glob("*.json"):
            try:
                with open(session_file) as f:
                    session = json.load(f)
                    if target is None or session.get("target") == target:
                        sessions.append({
                            "session_id": session.get("session_id"),
                            "target": session.get("target"),
                            "created_at": session.get("created_at"),
                            "status": session.get("status"),
                            "total_findings": session.get("stats", {}).get("total_findings", 0),
                        })
            except Exception:
                continue

        sessions.sort(key=lambda s: s.get("created_at", ""), reverse=True)
        return sessions

    def get_previous_findings(self, target: str) -> List[Dict]:
        """Get all findings from previous sessions for a target."""
        all_findings = []
        for session in self.list_sessions(target):
            if session.get("status") == "completed":
                loaded = self.load_session(session["session_id"])
                if loaded:
                    all_findings.extend(loaded.get("findings", []))
        return all_findings

    def diff_sessions(self, old_session_id: str, new_session_id: str) -> Dict:
        """Compare two sessions to find new/fixed findings."""
        old_session = self.load_session(old_session_id)
        new_session = self.load_session(new_session_id)

        if not old_session or not new_session:
            return {"error": "Session not found"}

        old_findings = {self._finding_hash(f) for f in old_session.get("findings", [])}
        new_findings = {self._finding_hash(f) for f in new_session.get("findings", [])}

        return {
            "new_findings": [
                f for f in new_session.get("findings", [])
                if self._finding_hash(f) not in old_findings
            ],
            "fixed_findings": [
                f for f in old_session.get("findings", [])
                if self._finding_hash(f) not in new_findings
            ],
            "old_total": len(old_findings),
            "new_total": len(new_findings),
        }

    def _finding_hash(self, finding: Dict) -> str:
        """Generate a hash for a finding for comparison."""
        key = f"{finding.get('type', '')}:{finding.get('url', '')}:{finding.get('param', '')}"
        return hashlib.md5(key.encode()).hexdigest()

    def _save_session(self, session_id: str):
        """Save session to disk."""
        if not self.current_session:
            return

        session_file = self.session_dir / f"{session_id}.json"
        with open(session_file, "w") as f:
            json.dump(self.current_session, f, indent=2, default=str)

    def export_session_markdown(self, session_id: str = None) -> str:
        """Export session as Markdown report."""
        session = self.current_session
        if session_id:
            session = self.load_session(session_id)

        if not session:
            return "No session loaded."

        md = []
        md.append(f"# Pentest Report: {session.get('target', 'Unknown')}")
        md.append(f"\n**Session ID:** {session.get('session_id', 'N/A')}")
        md.append(f"**Started:** {session.get('created_at', 'N/A')}")
        md.append(f"**Completed:** {session.get('completed_at', session.get('updated_at', 'N/A'))}")
        md.append(f"**Status:** {session.get('status', 'unknown')}")

        stats = session.get("stats", {})
        md.append(f"\n## Summary")
        md.append(f"- **Total Findings:** {stats.get('total_findings', 0)}")
        md.append(f"- **Critical:** {stats.get('critical', 0)}")
        md.append(f"- **High:** {stats.get('high', 0)}")
        md.append(f"- **Medium:** {stats.get('medium', 0)}")
        md.append(f"- **Low:** {stats.get('low', 0)}")
        md.append(f"- **Info:** {stats.get('info', 0)}")

        # Findings by severity
        findings = session.get("findings", [])
        for severity in ["critical", "high", "medium", "low", "info"]:
            severity_findings = [f for f in findings if f.get("severity", "").lower() == severity]
            if severity_findings:
                md.append(f"\n## {severity.upper()} Findings")
                for i, f in enumerate(severity_findings, 1):
                    md.append(f"\n### {i}. {f.get('type', 'Unknown')}")
                    md.append(f"- **URL:** {f.get('url', 'N/A')}")
                    md.append(f"- **Parameter:** {f.get('param', 'N/A')}")
                    md.append(f"- **Description:** {f.get('description', 'N/A')}")
                    if f.get("evidence"):
                        md.append(f"- **Evidence:** {f['evidence'][:200]}")
                    if f.get("payload"):
                        md.append(f"- **Payload:** `{f['payload'][:100]}`")

        # Attack paths
        paths = session.get("attack_paths", [])
        if paths:
            md.append(f"\n## Attack Paths")
            for path in paths[:5]:
                md.append(f"\n### Path: {path.get('impact', 'Unknown')}")
                md.append(f"- **Score:** {path.get('total_score', 0)}")
                md.append(f"- **Steps:** {len(path.get('nodes', []))}")
                if path.get("narrative"):
                    md.append(f"\n```\n{path['narrative']}\n```")

        # Decisions
        decisions = session.get("decisions", [])
        if decisions:
            md.append(f"\n## AI Decisions")
            for d in decisions[-10:]:
                md.append(f"- [{d.get('timestamp', '')}] {d.get('action', 'N/A')}: {d.get('reasoning', '')[:100]}")

        return "\n".join(md)
