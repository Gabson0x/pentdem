"""
Evidence Handler - Timestamped evidence preservation for all agents.

Every agent saves raw output to timestamped files following a consistent naming convention.
Provides audit trail and reproducibility for findings.
"""

import os
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from .scope_guard import OPSECLevel


class EvidenceHandler:
    """Manages evidence file creation and storage."""

    def __init__(self, base_dir: str = "evidence", engagement_id: str = ""):
        self.base_dir = Path(base_dir)
        self.engagement_id = engagement_id
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._index: list[dict] = []

    def _timestamp(self) -> str:
        """Generate timestamp string for filenames."""
        return datetime.now().strftime("%Y%m%d_%H%M%S")

    def _sanitize(self, target: str) -> str:
        """Sanitize target string for use in filenames."""
        return target.replace("/", "-").replace(":", "-").replace("?", "-").replace("&", "-").replace(" ", "_")[:50]

    def save_evidence(
        self,
        agent_name: str,
        vuln_type: str,
        target: str,
        content: str,
        extension: str = "txt",
        opsec_level: OPSECLevel = OPSECLevel.MODERATE,
        metadata: Optional[dict] = None,
    ) -> str:
        """Save evidence file and return the path."""
        ts = self._timestamp()
        safe_target = self._sanitize(target)
        filename = f"{vuln_type}_{safe_target}_{ts}.{extension}"

        # Create evidence subdirectory
        evidence_dir = self.base_dir / "evidence"
        evidence_dir.mkdir(parents=True, exist_ok=True)

        filepath = evidence_dir / filename

        filepath.write_text(content, encoding="utf-8")

        # Index entry
        entry = {
            "agent": agent_name,
            "vuln_type": vuln_type,
            "target": target,
            "file": str(filepath),
            "opsec_level": opsec_level.value,
            "timestamp": ts,
            "size_bytes": len(content.encode("utf-8")),
        }
        if metadata:
            entry["metadata"] = metadata
        self._index.append(entry)

        return str(filepath)

    def save_json_evidence(
        self,
        agent_name: str,
        vuln_type: str,
        target: str,
        data: dict,
        opsec_level: OPSECLevel = OPSECLevel.MODERATE,
    ) -> str:
        """Save JSON evidence file."""
        content = json.dumps(data, indent=2, default=str)
        return self.save_evidence(
            agent_name, vuln_type, target, content,
            extension="json", opsec_level=opsec_level, metadata={"format": "json"},
        )

    def save_http_evidence(
        self,
        agent_name: str,
        vuln_type: str,
        target: str,
        request: str,
        response: str,
        opsec_level: OPSECLevel = OPSECLevel.MODERATE,
    ) -> str:
        """Save HTTP request/response evidence."""
        content = f"=== REQUEST ===\n{request}\n\n=== RESPONSE ===\n{response}"
        return self.save_evidence(
            agent_name, vuln_type, target, content,
            extension="http", opsec_level=opsec_level,
            metadata={"format": "http_request_response"},
        )

    def save_poc_script(
        self,
        agent_name: str,
        vuln_type: str,
        target: str,
        script: str,
        opsec_level: OPSECLevel = OPSECLevel.LOUD,
    ) -> str:
        """Save PoC script (non-destructive by design)."""
        header = (
            "#!/bin/bash\n"
            f"# PoC: {vuln_type}\n"
            f"# Target: {target}\n"
            f"# Agent: {agent_name}\n"
            f"# Generated: {datetime.now().isoformat()}\n"
            f"# OPSEC: {opsec_level.value}\n"
            "# SAFETY: Non-destructive PoC - verify only, do not exploit\n\n"
            "set -euo pipefail\n\n"
        )
        return self.save_evidence(
            agent_name, f"poc_{vuln_type}", target, header + script,
            extension="sh", opsec_level=opsec_level,
            metadata={"type": "poc_script", "destructive": False},
        )

    def get_index(self) -> list[dict]:
        """Get all evidence entries."""
        return self._index.copy()

    def get_summary(self) -> dict:
        """Get evidence collection summary."""
        by_agent = {}
        by_opsec = {"quiet": 0, "moderate": 0, "loud": 0}
        total_bytes = 0

        for entry in self._index:
            agent = entry["agent"]
            by_agent[agent] = by_agent.get(agent, 0) + 1
            by_opsec[entry["opsec_level"]] = by_opsec.get(entry["opsec_level"], 0) + 1
            total_bytes += entry["size_bytes"]

        return {
            "total_files": len(self._index),
            "by_agent": by_agent,
            "by_opsec_level": by_opsec,
            "total_bytes": total_bytes,
            "directory": str(self.base_dir),
        }
