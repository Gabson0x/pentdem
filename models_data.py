"""
Data Models - Core types used across all agents and the swarm orchestrator.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class SourceType(Enum):
    """Target source type - determines testing methodology."""
    URL = "url"              # Black-box web app testing
    REPO = "repo"            # White-box source code analysis
    IP_RANGE = "ip_range"    # Network-level testing
    HYBRID = "hybrid"        # Both URL + repo


class EngagementType(Enum):
    """What kind of engagement this is."""
    BUG_BOUNTY = "bug_bounty"
    PENTEST = "pentest"
    RED_TEAM = "red_team"
    SOURCE_AUDIT = "source_audit"
    PR_REVIEW = "pr_review"
    CONTINUOUS = "continuous"


class AgentPhase(Enum):
    """Agent deployment phase."""
    PLANNING = "planning"
    RECON = "recon"
    HUNTING = "hunting"
    VALIDATION = "validation"
    CHAINING = "chaining"
    REPORTING = "reporting"


class RiskTier(Enum):
    """Operational risk of agent actions."""
    SAFE = "safe"            # Read-only/passive
    ACTIVE = "active"        # Touches target
    INTRUSIVE = "intrusive"  # Likely to alert/disrupt


class OPSECLevel(Enum):
    """Noise level for each command."""
    QUIET = "quiet"          # Passive, unlikely to trigger alerts
    MODERATE = "moderate"    # Active but common traffic
    LOUD = "loud"            # Likely to trigger IDS/IPS, WAF, or SOC


@dataclass
class Finding:
    """A confirmed vulnerability finding."""
    id: str = ""
    title: str = ""
    vuln_class: str = ""
    severity: str = "medium"  # critical, high, medium, low, info
    cvss_score: float = 0.0
    cvss_vector: str = ""
    confidence: float = 0.5
    target: str = ""
    endpoint: str = ""
    parameter: str = ""
    description: str = ""
    impact: str = ""
    remediation: str = ""
    evidence: str = ""
    poc: str = ""
    source: str = ""          # Which agent found it
    agent_phase: str = ""     # Which phase found it
    noise_level: str = "moderate"
    mitre_attack_id: str = ""
    mitre_tactic: str = ""
    mitre_technique: str = ""
    detection: str = ""
    tags: list = field(default_factory=list)
    chain_ids: list = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    dedup_signature: str = ""
    false_positive_risk: str = ""
    raw_data: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "vuln_class": self.vuln_class,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "confidence": self.confidence,
            "target": self.target,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "description": self.description,
            "impact": self.impact,
            "remediation": self.remediation,
            "evidence": self.evidence,
            "poc": self.poc,
            "source": self.source,
            "noise_level": self.noise_level,
            "mitre_attack_id": self.mitre_attack_id,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
            "detection": self.detection,
            "tags": self.tags,
            "chain_ids": self.chain_ids,
            "timestamp": self.timestamp,
            "dedup_signature": self.dedup_signature,
        }


@dataclass
class AttackChain:
    """A multi-step attack path chaining multiple findings."""
    id: str = ""
    name: str = ""
    severity: str = "medium"
    steps: list = field(default_factory=list)
    impact: str = ""
    confidence: float = 0.5
    # 5-dimension scoring
    score_reach: int = 0         # 0-100: How far does the chain go?
    score_reliability: int = 0   # 0-100: How many steps confirmed?
    score_stealth: int = 0       # 0-100: Overall OPSEC profile
    score_speed: int = 0         # 0-100: Total estimated execution time
    score_impact: int = 0        # 0-100: Business impact at final step
    total_score: int = 0         # Weighted composite
    mitre_techniques: list = field(default_factory=list)
    detection_points: list = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def calculate_total_score(self) -> int:
        """Calculate weighted composite score."""
        self.total_score = int(
            self.score_reach * 0.30
            + self.score_reliability * 0.25
            + self.score_stealth * 0.20
            + self.score_speed * 0.15
            + self.score_impact * 0.10
        )
        return self.total_score

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "severity": self.severity,
            "steps": self.steps,
            "impact": self.impact,
            "confidence": self.confidence,
            "total_score": self.total_score,
            "scores": {
                "reach": self.score_reach,
                "reliability": self.score_reliability,
                "stealth": self.score_stealth,
                "speed": self.score_speed,
                "impact": self.score_impact,
            },
            "mitre_techniques": self.mitre_techniques,
            "detection_points": self.detection_points,
            "timestamp": self.timestamp,
        }


@dataclass
class AgentStatus:
    """Status of a single agent in the swarm."""
    name: str
    phase: str
    status: str = "pending"  # pending, running, completed, failed, blocked
    progress: float = 0.0
    findings_count: int = 0
    error: Optional[str] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    opsec_level: str = "moderate"
    evidence_count: int = 0

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "phase": self.phase,
            "status": self.status,
            "progress": self.progress,
            "findings_count": self.findings_count,
            "error": self.error,
            "opsec_level": self.opsec_level,
            "evidence_count": self.evidence_count,
        }


@dataclass
class EngagementState:
    """Full state of the current engagement."""
    target: str = ""
    source_type: str = "url"
    engagement_type: str = "bug_bounty"
    platform: str = ""
    mock: bool = False
    agents: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)
    chains: list = field(default_factory=list)
    knowledge_data: dict = field(default_factory=dict)
    recon_data: dict = field(default_factory=dict)
    evidence_summary: dict = field(default_factory=dict)
    start_time: str = field(default_factory=lambda: datetime.now().isoformat())
    end_time: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "source_type": self.source_type,
            "engagement_type": self.engagement_type,
            "platform": self.platform,
            "mock": self.mock,
            "agents": {k: v.to_dict() for k, v in self.agents.items()},
            "findings_count": len(self.findings),
            "chains_count": len(self.chains),
            "evidence_summary": self.evidence_summary,
        }
