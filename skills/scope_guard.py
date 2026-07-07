"""
Scope Guard - Pre-execution validation for all agents.

Every agent must validate target scope before executing commands.
Prevents out-of-scope attacks and provides audit trail.
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from urllib.parse import urlparse


class ScopeType(Enum):
    DOMAIN = "domain"
    IP_RANGE = "ip_range"
    CIDR = "cidr"
    URL = "url"
    REPO = "repo"


class OPSECLevel(Enum):
    QUIET = "quiet"          # Passive, unlikely to trigger alerts
    MODERATE = "moderate"    # Active but common traffic
    LOUD = "loud"            # Likely to trigger IDS/IPS, WAF, or SOC


@dataclass
class ScopeDeclaration:
    """What the operator has authorized for testing."""
    engagement_type: str = ""          # web_app, api, full_scope, etc.
    domains: list[str] = field(default_factory=list)
    ip_ranges: list[str] = field(default_factory=list)
    cidrs: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    repos: list[str] = field(default_factory=list)
    allow_internal_probing: bool = False
    allow_cloud_metadata: bool = False
    rate_limit_rps: int = 50
    time_restrictions: str = ""
    excluded_targets: list[str] = field(default_factory=list)


@dataclass
class ScopeValidation:
    """Result of scope validation."""
    in_scope: bool
    reason: str
    noise_level: OPSECLevel
    requires_approval: bool = True


class ScopeGuard:
    """Validates every command against declared scope before execution."""

    def __init__(self, declaration: ScopeDeclaration):
        self.declaration = declaration
        self._scope_strings = self._build_scope_set()

    def _build_scope_set(self) -> set[str]:
        """Build normalized set of in-scope targets."""
        s = set()
        for d in self.declaration.domains:
            s.add(d.lower().lstrip("*.").rstrip("."))
        for url in self.declaration.urls:
            parsed = urlparse(url)
            s.add(parsed.hostname.lower() if parsed.hostname else "")
        for ip in self.declaration.ip_ranges:
            s.add(ip)
        for cidr in self.declaration.cidrs:
            s.add(cidr)
        for repo in self.declaration.repos:
            s.add(repo.lower())
        return s

    def _extract_host(self, target: str) -> str:
        """Extract hostname/IP from a target string."""
        if target.startswith(("http://", "https://")):
            parsed = urlparse(target)
            return (parsed.hostname or "").lower()
        return target.lower().strip()

    def _is_ip_in_range(self, ip: str, range_str: str) -> bool:
        """Check if IP is within a range (simplified)."""
        try:
            parts = list(map(int, ip.split(".")))
            if "-" in range_str:
                start, end = range_str.split("-")
                start_parts = list(map(int, start.strip().split(".")))
                end_parts = list(map(int, end.strip().split(".")))
                ip_int = (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
                start_int = (start_parts[0] << 24) + (start_parts[1] << 16) + (start_parts[2] << 8) + start_parts[3]
                end_int = (end_parts[0] << 24) + (end_parts[1] << 16) + (end_parts[2] << 8) + end_parts[3]
                return start_int <= ip_int <= end_int
        except (ValueError, IndexError):
            pass
        return False

    def _is_ip_in_cidr(self, ip: str, cidr: str) -> bool:
        """Check if IP is within CIDR range (simplified)."""
        try:
            ip_str, prefix = cidr.split("/")
            prefix = int(prefix)
            ip_parts = list(map(int, ip.split(".")))
            net_parts = list(map(int, ip_str.split(".")))
            ip_int = (ip_parts[0] << 24) + (ip_parts[1] << 16) + (ip_parts[2] << 8) + ip_parts[3]
            net_int = (net_parts[0] << 24) + (net_parts[1] << 16) + (net_parts[2] << 8) + net_parts[3]
            mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
            return (ip_int & mask) == (net_int & mask)
        except (ValueError, IndexError):
            pass
        return False

    def validate_target(self, target: str, noise_level: OPSECLevel = OPSECLevel.MODERATE) -> ScopeValidation:
        """Validate if a target is within declared scope."""
        host = self._extract_host(target)

        if not host:
            return ScopeValidation(False, "Empty target", noise_level)

        # Check exclusions
        for excluded in self.declaration.excluded_targets:
            if excluded.lower() in host:
                return ScopeValidation(False, f"Target matches exclusion: {excluded}", noise_level)

        # Check if in domain scope
        for domain in self._scope_strings:
            if host == domain or host.endswith("." + domain):
                return ScopeValidation(True, f"In scope (domain: {domain})", noise_level)

        # Check IP ranges
        for ip_range in self.declaration.ip_ranges:
            if self._is_ip_in_range(host, ip_range):
                return ScopeValidation(True, f"In scope (IP range: {ip_range})", noise_level)

        # Check CIDRs
        for cidr in self.declaration.cidrs:
            if self._is_ip_in_cidr(host, cidr):
                return ScopeValidation(True, f"In scope (CIDR: {cidr})", noise_level)

        # Check repo scope
        for repo in self.declaration.repos:
            if repo.lower() in host:
                return ScopeValidation(True, f"In scope (repo: {repo})", noise_level)

        return ScopeValidation(
            False,
            f"Target '{host}' not in any declared scope. "
            f"In-scope domains: {list(self.declaration.domains)}",
            noise_level,
        )

    def validate_command(self, command: str, noise_level: OPSECLevel) -> ScopeValidation:
        """Validate a command's targets against scope."""
        # Extract potential targets from command
        targets = []

        # URLs
        url_pattern = re.findall(r'https?://[^\s\'"]+', command)
        targets.extend(url_pattern)

        # IP addresses
        ip_pattern = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', command)
        targets.extend(ip_pattern)

        # Domain-like patterns
        domain_pattern = re.findall(r'\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}\b', command)
        targets.extend(domain_pattern)

        if not targets:
            return ScopeValidation(True, "No extractable targets in command", noise_level)

        # Validate each target
        for target in targets:
            result = self.validate_target(target, noise_level)
            if not result.in_scope:
                return ScopeValidation(
                    False,
                    f"Command contains out-of-scope target: {result.reason}",
                    noise_level,
                )

        return ScopeValidation(True, "All targets in scope", noise_level)

    def is_internal_target(self, target: str) -> bool:
        """Check if target is internal (RFC1918, link-local, etc.)."""
        host = self._extract_host(target)
        internal_patterns = [
            r'^10\.', r'^172\.(1[6-9]|2[0-9]|3[01])\.', r'^192\.168\.',
            r'^127\.', r'^169\.254\.', r'^0\.', r'localhost',
            r'^fc00:', r'^fe80:',
        ]
        return any(re.match(p, host) for p in internal_patterns)

    def requires_internal_approval(self, target: str) -> bool:
        """Check if internal probing requires explicit approval."""
        return (
            self.is_internal_target(target)
            and not self.declaration.allow_internal_probing
        )

    def requires_cloud_metadata_approval(self) -> bool:
        """Check if cloud metadata access requires explicit approval."""
        return not self.declaration.allow_cloud_metadata
