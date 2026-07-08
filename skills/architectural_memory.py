"""
Architectural Memory — learn target structure across runs.

What top tools have:
- Strobes: Architectural memory across runs
- RunSybil: Cloud-native persistent memory
- NodeZero: Attack path persistence

This module:
1. Remembers target structure (hosts, services, endpoints)
2. Tracks changes over time (new services, removed vulns)
3. Builds knowledge base of target's attack surface
4. Predicts future vulnerabilities based on patterns
"""

import json
import hashlib
from typing import Dict, List, Any, Optional, Set
from datetime import datetime
from pathlib import Path


class ArchitecturalMemory:
    """
    Learn and remember target architecture across scan runs.
    """

    def __init__(self, memory_dir: str = ".memory"):
        self.memory_dir = Path(memory_dir)
        self.memory_dir.mkdir(parents=True, exist_ok=True)
        self.target_memory: Dict[str, Any] = {}

    def load_target_memory(self, target: str) -> Dict:
        """Load memory for a specific target."""
        memory_file = self.memory_dir / f"{target.replace('.', '_')}.json"
        if memory_file.exists():
            with open(memory_file) as f:
                self.target_memory = json.load(f)
                return self.target_memory
        return self._init_target_memory(target)

    def save_target_memory(self, target: str):
        """Save target memory to disk."""
        memory_file = self.memory_dir / f"{target.replace('.', '_')}.json"
        self.target_memory["last_updated"] = datetime.now().isoformat()
        with open(memory_file, "w") as f:
            json.dump(self.target_memory, f, indent=2)

    def _init_target_memory(self, target: str) -> Dict:
        """Initialize empty memory for a target."""
        self.target_memory = {
            "target": target,
            "first_seen": datetime.now().isoformat(),
            "last_updated": datetime.now().isoformat(),
            "hosts": {},
            "services": {},
            "endpoints": {},
            "findings_history": [],
            "tech_stack": [],
            "waf_info": {},
            "auth_mechanisms": [],
            "attack_surface": {},
            "patterns": {},
            "scan_count": 0,
        }
        return self.target_memory

    def record_scan(self, target: str, findings: List[Dict], recon_data: Dict):
        """Record a scan's results into memory."""
        if not self.target_memory:
            self.load_target_memory(target)

        self.target_memory["scan_count"] += 1

        # Record findings
        for finding in findings:
            entry = {
                "finding_type": finding.get("type", ""),
                "url": finding.get("url", ""),
                "param": finding.get("param", ""),
                "severity": finding.get("severity", ""),
                "first_seen": finding.get("first_seen", datetime.now().isoformat()),
                "last_seen": datetime.now().isoformat(),
                "status": "open",
            }
            self.target_memory["findings_history"].append(entry)

        # Record hosts from recon
        if recon_data.get("hosts"):
            for host in recon_data["hosts"]:
                if host not in self.target_memory["hosts"]:
                    self.target_memory["hosts"][host] = {
                        "first_seen": datetime.now().isoformat(),
                        "status": "active",
                    }

        # Record services
        if recon_data.get("services"):
            for service, info in recon_data["services"].items():
                self.target_memory["services"][service] = info

        # Record tech stack
        if recon_data.get("tech_stack"):
            for tech in recon_data["tech_stack"]:
                if tech not in self.target_memory["tech_stack"]:
                    self.target_memory["tech_stack"].append(tech)

        # Identify patterns
        self._identify_patterns()

        self.save_target_memory(target)

    def _identify_patterns(self):
        """Identify patterns in findings history."""
        findings = self.target_memory["findings_history"]

        # Pattern: recurring vulnerability types
        type_counts = {}
        for f in findings:
            ftype = f.get("finding_type", "")
            type_counts[ftype] = type_counts.get(ftype, 0) + 1

        self.target_memory["patterns"]["recurring_vulns"] = {
            k: v for k, v in sorted(type_counts.items(), key=lambda x: -x[1])
        }

        # Pattern: most vulnerable endpoints
        url_counts = {}
        for f in findings:
            url = f.get("url", "")
            if url:
                url_counts[url] = url_counts.get(url, 0) + 1

        self.target_memory["patterns"]["hot_endpoints"] = {
            k: v for k, v in sorted(url_counts.items(), key=lambda x: -x[1])[:10]
        }

        # Pattern: most vulnerable parameters
        param_counts = {}
        for f in findings:
            param = f.get("param", "")
            if param:
                param_counts[param] = param_counts.get(param, 0) + 1

        self.target_memory["patterns"]["vulnerable_params"] = {
            k: v for k, v in sorted(param_counts.items(), key=lambda x: -x[1])[:10]
        }

    def get_vulnerability_trend(self, target: str) -> Dict:
        """Analyze vulnerability trends over time."""
        if not self.target_memory:
            self.load_target_memory(target)

        findings = self.target_memory["findings_history"]

        # Group by date
        daily_counts = {}
        for f in findings:
            date = f.get("first_seen", "")[:10]
            if date:
                daily_counts[date] = daily_counts.get(date, 0) + 1

        # Calculate trend
        dates = sorted(daily_counts.keys())
        if len(dates) >= 2:
            recent = daily_counts[dates[-1]]
            previous = daily_counts[dates[-2]]
            trend = "increasing" if recent > previous else "decreasing" if recent < previous else "stable"
        else:
            trend = "insufficient_data"

        return {
            "total_scans": self.target_memory["scan_count"],
            "total_findings": len(findings),
            "daily_counts": daily_counts,
            "trend": trend,
            "open_findings": sum(1 for f in findings if f.get("status") == "open"),
            "fixed_findings": sum(1 for f in findings if f.get("status") == "fixed"),
        }

    def suggest_next_tests(self, target: str) -> List[Dict]:
        """Suggest what to test next based on memory."""
        if not self.target_memory:
            self.load_target_memory(target)

        suggestions = []

        # Suggest: test untested OWASP categories
        tested_types = set(f.get("finding_type", "") for f in self.target_memory["findings_history"])

        all_vuln_types = {
            "xss", "sqli", "ssrf", "idor", "open_redirect", "csrf",
            "ssti", "lfi", "command_injection", "xxe", "race_condition",
            "jwt_none", "jwt_weak_secret", "mass_assignment", "prototype_pollution",
            "subdomain_takeover", "cloud_metadata_access",
        }

        untested = all_vuln_types - tested_types
        for vt in list(untested)[:5]:
            suggestions.append({
                "type": "untested_vuln_class",
                "vuln_class": vt,
                "reason": f"No {vt} findings in history — test this class",
                "priority": "medium",
            })

        # Suggest: retest fixed findings
        fixed = [f for f in self.target_memory["findings_history"] if f.get("status") == "fixed"]
        for f in fixed[:3]:
            suggestions.append({
                "type": "retest_fix",
                "finding": f,
                "reason": f"Previously fixed {f.get('finding_type', '')} — verify fix",
                "priority": "high",
            })

        # Suggest: deeper testing on hot endpoints
        hot_endpoints = self.target_memory.get("patterns", {}).get("hot_endpoints", {})
        for endpoint, count in list(hot_endpoints.items())[:3]:
            suggestions.append({
                "type": "deep_test_endpoint",
                "endpoint": endpoint,
                "reason": f"Endpoint has {count} historical findings — test deeper",
                "priority": "high",
            })

        return suggestions

    def get_target_summary(self, target: str) -> str:
        """Get human-readable target summary."""
        if not self.target_memory:
            self.load_target_memory(target)

        tm = self.target_memory
        summary = []
        summary.append(f"Target: {target}")
        summary.append(f"Scans: {tm.get('scan_count', 0)}")
        summary.append(f"Hosts: {len(tm.get('hosts', {}))}")
        summary.append(f"Services: {len(tm.get('services', {}))}")
        summary.append(f"Tech Stack: {', '.join(tm.get('tech_stack', [])[:5]) or 'Unknown'}")
        summary.append(f"Total Findings: {len(tm.get('findings_history', []))}")

        # Top vuln types
        patterns = tm.get("patterns", {})
        recurring = patterns.get("recurring_vulns", {})
        if recurring:
            top_vulns = list(recurring.keys())[:3]
            summary.append(f"Top Vulnerabilities: {', '.join(top_vulns)}")

        return "\n".join(summary)
