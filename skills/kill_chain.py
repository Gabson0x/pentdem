"""
Kill-Chain Path Builder — chains individual findings into full attack paths.

What top tools have that we're building:
- NodeZero: Chains misconfigurations into multi-step attack paths
- XBOW: Multi-agent exploration + validation
- Pentera: Full kill-chain simulation
- Strobes: Architectural memory across runs

This module:
1. Builds a graph of all findings and their relationships
2. Identifies chains (entry → pivot → escalation → objective)
3. Scores chains by impact and feasibility
4. Generates step-by-step attack narratives
5. Persists architectural memory across runs
"""

import json
import hashlib
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum


class NodeType(Enum):
    ENTRY = "entry"
    VULN = "vuln"
    PIVOT = "pivot"
    CREDENTIAL = "credential"
    PRIVILEGE = "privilege"
    OBJECTIVE = "objective"
    INFO = "info"


class EdgeType(Enum):
    REQUIRES = "requires"
    ENABLES = "enables"
    CHAINS_TO = "chains_to"
    ESCALATES_TO = "escalates_to"
    PIVOTS_VIA = "pivots_via"


@dataclass
class ChainNode:
    id: str
    node_type: NodeType
    finding: Dict[str, Any]
    labels: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __hash__(self):
        return hash(self.id)


@dataclass
class ChainEdge:
    source: str
    target: str
    edge_type: EdgeType
    confidence: float = 0.8
    description: str = ""


@dataclass
class AttackPath:
    path_id: str
    nodes: List[ChainNode]
    edges: List[ChainEdge]
    total_score: float
    impact: str
    narrative: str
    mitre_mapping: List[str] = field(default_factory=list)
    owasp_mapping: List[str] = field(default_factory=list)


# ─── Chain Rules: What connects to what ───────────────────────────

CHAIN_RULES = {
    # Entry points
    ("xss", "session_hijack"): {"confidence": 0.85, "description": "XSS steals session cookie → account takeover"},
    ("xss", "credential_theft"): {"confidence": 0.8, "description": "XSS steals credentials from DOM/localStorage"},
    ("xss", "admin_access"): {"confidence": 0.7, "description": "XSS on admin panel → admin session hijack"},

    ("sqli", "data_extraction"): {"confidence": 0.9, "description": "SQLi extracts user table → credential dump"},
    ("sqli", "privilege_escalation"): {"confidence": 0.75, "description": "SQLi modifies user role → admin access"},
    ("sqli", "rce"): {"confidence": 0.6, "description": "SQLi via LOAD_FILE/INTO OUTFILE → RCE"},

    ("ssrf", "cloud_metadata"): {"confidence": 0.9, "description": "SSRF accesses 169.254.169.254 → IAM credentials"},
    ("ssrf", "internal_network"): {"confidence": 0.85, "description": "SSRF pivots to internal services"},
    ("ssrf", "credential_theft"): {"confidence": 0.8, "description": "SSRF reads /etc/passwd or cloud credentials"},

    ("idor", "data_breach"): {"confidence": 0.9, "description": "IDOR accesses other users' data"},
    ("idor", "privilege_escalation"): {"confidence": 0.7, "description": "IDOR modifies admin resources"},

    ("open_redirect", "oauth_theft"): {"confidence": 0.85, "description": "Open redirect steals OAuth code/token"},
    ("open_redirect", "phishing"): {"confidence": 0.8, "description": "Open redirect enables credential phishing"},

    ("ssrf", "lateral_movement"): {"confidence": 0.75, "description": "SSRF pivots to internal services → lateral movement"},

    # Pivot chains
    ("credential_theft", "account_takeover"): {"confidence": 0.9, "description": "Stolen credentials → full account compromise"},
    ("credential_theft", "lateral_movement"): {"confidence": 0.8, "description": "Stolen creds → access other services"},
    ("credential_theft", "data_exfiltration"): {"confidence": 0.85, "description": "Stolen creds → data download"},

    ("admin_access", "rce"): {"confidence": 0.85, "description": "Admin panel → file upload/plugin install → RCE"},
    ("admin_access", "data_exfiltration"): {"confidence": 0.9, "description": "Admin access → full data export"},
    ("admin_access", "persistence"): {"confidence": 0.8, "description": "Admin access → create backdoor user"},

    ("cloud_metadata", "iam_credentials"): {"confidence": 0.9, "description": "Metadata endpoint → IAM role credentials"},
    ("iam_credentials", "lateral_movement"): {"confidence": 0.85, "description": "IAM creds → access other AWS services"},
    ("iam_credentials", "data_exfiltration"): {"confidence": 0.9, "description": "IAM creds → S3 bucket access → data theft"},

    ("internal_network", "database_access"): {"confidence": 0.8, "description": "Internal pivot → database server access"},
    ("internal_network", "domain_controller"): {"confidence": 0.7, "description": "Internal pivot → Active Directory access"},

    ("rce", "full_compromise"): {"confidence": 0.95, "description": "RCE → complete system takeover"},
    ("data_exfiltration", "full_compromise"): {"confidence": 0.85, "description": "Data theft → business impact"},
    ("persistence", "full_compromise"): {"confidence": 0.9, "description": "Backdoor → persistent access"},
}

# ─── Finding type classification ──────────────────────────────────

FINDING_TYPE_MAP = {
    "xss": NodeType.VULN,
    "reflected_xss": NodeType.VULN,
    "stored_xss": NodeType.VULN,
    "dom_xss": NodeType.VULN,
    "sqli": NodeType.VULN,
    "sql_injection": NodeType.VULN,
    "ssrf": NodeType.VULN,
    "idor": NodeType.VULN,
    "open_redirect": NodeType.VULN,
    "csrf": NodeType.VULN,
    "ssti": NodeType.VULN,
    "lfi": NodeType.VULN,
    "rfi": NodeType.VULN,
    "command_injection": NodeType.VULN,
    "xxe": NodeType.VULN,
    "race_condition": NodeType.VULN,
    "mass_assignment": NodeType.VULN,
    "jwt_none": NodeType.VULN,
    "jwt_weak_secret": NodeType.VULN,
    "subdomain_takeover": NodeType.VULN,
    "credential_exposure": NodeType.CREDENTIAL,
    "secret_exposure": NodeType.CREDENTIAL,
    "aws_credentials_exposed": NodeType.CREDENTIAL,
    "cloud_metadata_access": NodeType.CREDENTIAL,
    "ssrf_to_cloud_metadata": NodeType.VULN,
    "prototype_pollution": NodeType.VULN,
    "oauth_redirect_uri_manipulation": NodeType.VULN,
    "api_endpoint_discovery": NodeType.INFO,
    "graphql_introspection": NodeType.INFO,
    "internal_host_exposure": NodeType.INFO,
}


class KillChainBuilder:
    """
    Builds kill-chain attack paths from individual findings.
    """

    def __init__(self):
        self.nodes: Dict[str, ChainNode] = {}
        self.edges: List[ChainEdge] = []
        self.architectural_memory: Dict[str, Any] = {}
        self._node_counter = 0

    def build_from_findings(self, findings: List[Dict]) -> List[AttackPath]:
        """Build attack paths from a list of findings."""
        # Step 1: Convert findings to nodes
        for finding in findings:
            self._add_finding(finding)

        # Step 2: Build edges based on chain rules
        self._build_edges()

        # Step 3: Add inferred nodes (credentials, pivots, objectives)
        self._infer_nodes()

        # Step 4: Find all paths from entry to objective
        paths = self._find_paths()

        # Step 5: Score and rank paths
        scored_paths = self._score_paths(paths)

        # Step 6: Generate narratives
        for path in scored_paths:
            path.narrative = self._generate_narrative(path)
            path.mitre_mapping = self._map_mitre(path)
            path.owasp_mapping = self._map_owasp(path)

        return scored_paths

    def _add_finding(self, finding: Dict):
        """Convert a finding to a chain node."""
        ftype = finding.get("type", "").lower()
        node_type = FINDING_TYPE_MAP.get(ftype, NodeType.VULN)
        node_id = f"finding_{self._node_counter}"
        self._node_counter += 1

        node = ChainNode(
            id=node_id,
            node_type=node_type,
            finding=finding,
            labels=[ftype],
            metadata={
                "severity": finding.get("severity", "unknown"),
                "confidence": finding.get("confidence", 0.5),
                "url": finding.get("url", ""),
            },
        )
        self.nodes[node_id] = node

    def _build_edges(self):
        """Build edges between nodes based on chain rules."""
        node_list = list(self.nodes.values())

        for i, node_a in enumerate(node_list):
            for j, node_b in enumerate(node_list):
                if i >= j:
                    continue

                for label_a in node_a.labels:
                    for label_b in node_b.labels:
                        # Check both directions
                        key = (label_a, label_b)
                        reverse_key = (label_b, label_a)

                        if key in CHAIN_RULES:
                            rule = CHAIN_RULES[key]
                            edge = ChainEdge(
                                source=node_a.id,
                                target=node_b.id,
                                edge_type=EdgeType.CHAINS_TO,
                                confidence=rule["confidence"],
                                description=rule["description"],
                            )
                            self.edges.append(edge)

                        elif reverse_key in CHAIN_RULES:
                            rule = CHAIN_RULES[reverse_key]
                            edge = ChainEdge(
                                source=node_b.id,
                                target=node_a.id,
                                edge_type=EdgeType.CHAINS_TO,
                                confidence=rule["confidence"],
                                description=rule["description"],
                            )
                            self.edges.append(edge)

    def _infer_nodes(self):
        """Infer additional nodes from existing findings."""
        new_nodes = {}
        new_edges = []

        # If we have cloud_metadata, infer iam_credentials node
        for node_id, node in list(self.nodes.items()):
            if "cloud_metadata" in node.labels or "ssrf_to_cloud_metadata" in node.labels:
                iam_node = ChainNode(
                    id="inferred_iam",
                    node_type=NodeType.CREDENTIAL,
                    finding={"type": "iam_credentials", "severity": "critical"},
                    labels=["iam_credentials"],
                    metadata={"inferred": True},
                )
                new_nodes["inferred_iam"] = iam_node
                new_edges.append(ChainEdge(
                    source=node_id,
                    target="inferred_iam",
                    edge_type=EdgeType.ENABLES,
                    confidence=0.9,
                    description="Cloud metadata access yields IAM credentials",
                ))

            # If we have credential exposure, infer account_takeover
            if "credential_exposure" in node.labels or "secret_exposure" in node.labels:
                ato_id = f"inferred_ato_{node_id}"
                ato_node = ChainNode(
                    id=ato_id,
                    node_type=NodeType.OBJECTIVE,
                    finding={"type": "account_takeover", "severity": "critical"},
                    labels=["account_takeover", "full_compromise"],
                    metadata={"inferred": True},
                )
                new_nodes[ato_id] = ato_node
                new_edges.append(ChainEdge(
                    source=node_id,
                    target=ato_id,
                    edge_type=EdgeType.ESCALATES_TO,
                    confidence=0.85,
                    description="Exposed credentials enable account takeover",
                ))

        # Add new nodes and edges after iteration
        self.nodes.update(new_nodes)
        self.edges.extend(new_edges)

    def _find_paths(self) -> List[List[str]]:
        """Find all paths from entry/vuln nodes to objective nodes."""
        paths = []

        # Find all objective nodes
        objective_nodes = [
            nid for nid, node in self.nodes.items()
            if node.node_type == NodeType.OBJECTIVE
            or "full_compromise" in node.labels
            or "account_takeover" in node.labels
            or "data_exfiltration" in node.labels
            or "rce" in node.labels
        ]

        # If no objectives, create a synthetic one
        if not objective_nodes:
            obj = ChainNode(
                id="synthetic_objective",
                node_type=NodeType.OBJECTIVE,
                finding={"type": "full_compromise", "severity": "critical"},
                labels=["full_compromise"],
                metadata={"synthetic": True},
            )
            self.nodes["synthetic_objective"] = obj
            objective_nodes = ["synthetic_objective"]

            # Connect all high-severity findings to objective
            for nid, node in self.nodes.items():
                if node.node_type == NodeType.VULN:
                    sev = node.metadata.get("severity", "")
                    if sev in ("critical", "high"):
                        self.edges.append(ChainEdge(
                            source=nid,
                            target="synthetic_objective",
                            edge_type=EdgeType.ENABLES,
                            confidence=0.6,
                            description=f"High-severity finding enables compromise",
                        ))

        # BFS/DFS from each vuln/entry node to objectives
        vuln_nodes = [
            nid for nid, node in self.nodes.items()
            if node.node_type in (NodeType.VULN, NodeType.ENTRY, NodeType.CREDENTIAL)
        ]

        for start in vuln_nodes:
            for end in objective_nodes:
                found_paths = self._dfs(start, end, max_depth=5)
                paths.extend(found_paths)

        return paths

    def _dfs(self, start: str, end: str, max_depth: int, visited: Set[str] = None) -> List[List[str]]:
        """DFS to find paths between two nodes."""
        if visited is None:
            visited = set()

        if start == end:
            return [[start]]

        if max_depth <= 0 or start in visited:
            return []

        visited.add(start)
        paths = []

        # Find edges from start
        for edge in self.edges:
            if edge.source == start:
                sub_paths = self._dfs(edge.target, end, max_depth - 1, visited.copy())
                for sp in sub_paths:
                    paths.append([start] + sp)

        return paths

    def _score_paths(self, paths: List[List[str]]) -> List[AttackPath]:
        """Score and rank attack paths."""
        scored = []

        for path_nodes in paths:
            if len(path_nodes) < 2:
                continue

            # Calculate score based on:
            # 1. Path length (longer = more steps but more impact)
            # 2. Confidence of edges
            # 3. Severity of findings
            # 4. Whether it reaches a real objective

            total_confidence = 1.0
            max_severity = 0
            severity_map = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

            edges_in_path = []
            for i in range(len(path_nodes) - 1):
                for edge in self.edges:
                    if edge.source == path_nodes[i] and edge.target == path_nodes[i + 1]:
                        total_confidence *= edge.confidence
                        edges_in_path.append(edge)
                        break

            for nid in path_nodes:
                node = self.nodes.get(nid)
                if node:
                    sev = node.metadata.get("severity", "medium")
                    sev_score = severity_map.get(sev, 2)
                    max_severity = max(max_severity, sev_score)

            # Score formula
            path_score = (
                total_confidence * 40 +
                max_severity * 20 +
                min(len(path_nodes) * 5, 25) +
                (15 if any("rce" in self.nodes[nid].labels for nid in path_nodes if nid in self.nodes) else 0)
            )

            # Determine impact
            has_rce = any("rce" in self.nodes[nid].labels for nid in path_nodes if nid in self.nodes)
            has_data = any("data_exfiltration" in self.nodes[nid].labels or "data_breach" in self.nodes[nid].labels for nid in path_nodes if nid in self.nodes)
            has_ato = any("account_takeover" in self.nodes[nid].labels or "full_compromise" in self.nodes[nid].labels for nid in path_nodes if nid in self.nodes)

            if has_rce:
                impact = "CRITICAL - Remote Code Execution"
            elif has_ato:
                impact = "CRITICAL - Full System Compromise"
            elif has_data:
                impact = "HIGH - Data Breach"
            else:
                impact = "MEDIUM - Security Bypass"

            attack_path = AttackPath(
                path_id=hashlib.md5(json.dumps(path_nodes).encode()).hexdigest()[:12],
                nodes=[self.nodes[nid] for nid in path_nodes if nid in self.nodes],
                edges=edges_in_path,
                total_score=round(path_score, 2),
                impact=impact,
                narrative="",  # Generated later
            )
            scored.append(attack_path)

        # Sort by score descending
        scored.sort(key=lambda p: p.total_score, reverse=True)
        return scored

    def _generate_narrative(self, path: AttackPath) -> str:
        """Generate human-readable attack narrative."""
        if not path.nodes:
            return "No attack path found."

        steps = []
        for i, node in enumerate(path.nodes):
            ftype = node.labels[0] if node.labels else "unknown"
            url = node.metadata.get("url", "N/A")
            sev = node.metadata.get("severity", "unknown")

            if i == 0:
                steps.append(f"1. **Initial Access**: Attacker discovers {ftype.upper()} at {url} (severity: {sev})")
            elif i == len(path.nodes) - 1:
                steps.append(f"{i+1}. **Objective**: {node.finding.get('type', 'compromise').replace('_', ' ').title()}")
            else:
                edge_desc = ""
                if i < len(path.edges):
                    edge_desc = f" — {path.edges[i-1].description}" if i > 0 else ""
                steps.append(f"{i+1}. **Pivot**: {ftype.replace('_', ' ').title()}{edge_desc}")

        return "\n".join(steps)

    def _map_mitre(self, path: AttackPath) -> List[str]:
        """Map attack path to MITRE ATT&CK techniques."""
        techniques = []
        for node in path.nodes:
            labels = node.labels
            for label in labels:
                if "xss" in label:
                    techniques.append("T1189 - Drive-by Compromise")
                elif "sqli" in label:
                    techniques.append("T1190 - Exploit Public-Facing Application")
                elif "ssrf" in label:
                    techniques.append("T1190 - Exploit Public-Facing Application")
                    techniques.append("T1552 - Credentials In Files")
                elif "idor" in label:
                    techniques.append("T1190 - Exploit Public-Facing Application")
                elif "credential" in label or "secret" in label:
                    techniques.append("T1552 - Credentials In Files")
                elif "rce" in label:
                    techniques.append("T1059 - Command and Scripting Interpreter")
                elif "admin" in label:
                    techniques.append("T1078 - Valid Accounts")
                elif "lateral" in label:
                    techniques.append("T1021 - Remote Services")
                elif "data" in label and "exfil" in label:
                    techniques.append("T1041 - Exfiltration Over C2 Channel")
                elif "persistence" in label:
                    techniques.append("T1098 - Account Manipulation")
        return list(set(techniques))

    def _map_owasp(self, path: AttackPath) -> List[str]:
        """Map attack path to OWASP Top 10."""
        mappings = []
        for node in path.nodes:
            labels = node.labels
            for label in labels:
                if "xss" in label:
                    mappings.append("A03:2021 - Injection")
                elif "sqli" in label:
                    mappings.append("A03:2021 - Injection")
                elif "ssrf" in label:
                    mappings.append("A10:2021 - Server-Side Request Forgery")
                elif "idor" in label or "access" in label:
                    mappings.append("A01:2021 - Broken Access Control")
                elif "credential" in label or "auth" in label:
                    mappings.append("A07:2021 - Identification and Authentication Failures")
                elif "misconfig" in label or "cloud" in label:
                    mappings.append("A05:2021 - Security Misconfiguration")
                elif "xxe" in label:
                    mappings.append("A05:2021 - Security Misconfiguration")
        return list(set(mappings))

    def export_graph(self) -> Dict:
        """Export the full graph for visualization."""
        return {
            "nodes": [
                {
                    "id": n.id,
                    "type": n.node_type.value,
                    "labels": n.labels,
                    "finding_type": n.finding.get("type", ""),
                    "severity": n.metadata.get("severity", ""),
                    "url": n.metadata.get("url", ""),
                }
                for n in self.nodes.values()
            ],
            "edges": [
                {
                    "source": e.source,
                    "target": e.target,
                    "type": e.edge_type.value,
                    "confidence": e.confidence,
                    "description": e.description,
                }
                for e in self.edges
            ],
        }

    def save_memory(self, filepath: str):
        """Save architectural memory to disk."""
        memory = {
            "graph": self.export_graph(),
            "timestamp": datetime.now().isoformat(),
            "stats": {
                "total_nodes": len(self.nodes),
                "total_edges": len(self.edges),
                "total_findings": sum(1 for n in self.nodes.values() if n.node_type == NodeType.VULN),
            },
        }
        with open(filepath, "w") as f:
            json.dump(memory, f, indent=2)

    def load_memory(self, filepath: str):
        """Load architectural memory from disk."""
        try:
            with open(filepath) as f:
                self.architectural_memory = json.load(f)
        except FileNotFoundError:
            pass
