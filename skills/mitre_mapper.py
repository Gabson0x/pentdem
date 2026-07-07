"""
MITRE ATT&CK Mapper - Maps all techniques and findings to ATT&CK framework.

Every finding gets a technique ID, tactic classification, and detection guidance.
"""

from dataclasses import dataclass, field


@dataclass
class AttackTechnique:
    """A single ATT&CK technique."""
    technique_id: str        # e.g., "T1190"
    name: str                # e.g., "Exploit Public-Facing Application"
    tactic: str              # e.g., "initial-access"
    subtechnique: str = ""   # e.g., "T1190.001"
    description: str = ""
    detection: str = ""
    mitigation: str = ""


# Core web application attack techniques
TECHNIQUE_MAP: dict[str, AttackTechnique] = {
    # Reconnaissance
    "active_scanning": AttackTechnique(
        "T1595", "Active Scanning", "reconnaissance",
        description="Adversaries may execute active scanning to gather information",
        detection="Monitor for unusual scanning patterns in network logs",
    ),
    "subdomain_enum": AttackTechnique(
        "T1596", "Search Open Technical Databases", "reconnaissance",
        description="Subdomain enumeration via DNS, certificate transparency",
        detection="Monitor DNS query logs for bulk subdomain lookups",
    ),

    # Initial Access
    "exploit_public_facing": AttackTechnique(
        "T1190", "Exploit Public-Facing Application", "initial-access",
        description="Exploitation of a software vulnerability in an internet-facing application",
        detection="Deploy WAF rules, monitor for exploit signatures in HTTP traffic",
    ),
    "phishing": AttackTechnique(
        "T1566", "Phishing", "initial-access",
        description="Adversaries may send phishing messages to gain access",
        detection="Email gateway logs, user reporting, URL reputation checks",
    ),
    "valid_accounts": AttackTechnique(
        "T1078", "Valid Accounts", "initial-access",
        description="Use of legitimate credentials for initial access",
        detection="Monitor for anomalous login patterns, impossible travel",
    ),

    # Execution
    "command_injection": AttackTechnique(
        "T1059", "Command and Scripting Interpreter", "execution",
        description="Adversaries may abuse command-line interpreters to execute commands",
        detection="Monitor process creation, command-line arguments",
    ),
    "sql_injection": AttackTechnique(
        "T1190", "Exploit Public-Facing Application", "execution",
        subtechnique="T1190.001",
        description="SQL injection leading to code execution",
        detection="WAF SQL injection signatures, database query logging",
    ),
    "template_injection": AttackTechnique(
        "T1059", "Command and Scripting Interpreter", "execution",
        subtechnique="T1059.001",
        description="Server-Side Template Injection leading to code execution",
        detection="Monitor for template syntax in user input, error messages",
    ),
    "deserialization": AttackTechnique(
        "T1059", "Command and Scripting Interpreter", "execution",
        subtechnique="T1059.001",
        description="Insecure deserialization leading to code execution",
        detection="Monitor for serialized object patterns, unusual class loading",
    ),

    # Persistence
    "web_shell": AttackTechnique(
        "T1505.003", "Server Software Component: Web Shell", "persistence",
        description="Installation of a web shell on the target system",
        detection="File integrity monitoring, webshell scanners",
    ),

    # Privilege Escalation
    "idor": AttackTechnique(
        "T1068", "Exploitation for Privilege Escalation", "privilege-escalation",
        description="Insecure Direct Object Reference allowing access to unauthorized resources",
        detection="Monitor for rapid sequential ID access patterns",
    ),
    "auth_bypass": AttackTechnique(
        "T1078", "Valid Accounts", "privilege-escalation",
        subtechnique="T1078.001",
        description="Authentication bypass gaining unauthorized access",
        detection="Monitor for access to protected endpoints without valid session",
    ),
    "mass_assignment": AttackTechnique(
        "T1098", "Account Manipulation", "privilege-escalation",
        description="Mass assignment allowing privilege escalation",
        detection="Monitor for unexpected field values in API requests",
    ),

    # Credential Access
    "credential_dumping": AttackTechnique(
        "T1003", "OS Credential Dumping", "credential-access",
        description="Credential harvesting from various sources",
        detection="Monitor for access to credential stores, LSASS",
    ),
    "jwt_attack": AttackTechnique(
        "T1539", "Steal Web Session Cookie", "credential-access",
        description="JWT token manipulation or theft",
        detection="Monitor for JWT algorithm changes, invalid token patterns",
    ),

    # Lateral Movement
    "ssrf": AttackTechnique(
        "T1552", "Unsecured Credentials: Credentials in Files", "lateral-movement",
        description="Server-Side Request Forgery to access internal resources",
        detection="Monitor for outbound requests to internal IP ranges",
    ),
    "open_redirect": AttackTechnique(
        "T1566.002", "Phishing: Spearphishing Link", "initial-access",
        description="Open redirect used in phishing chains or OAuth theft",
        detection="Monitor for redirect chains to external domains",
    ),

    # Collection
    "xss_data_exfil": AttackTechnique(
        "T1005", "Data from Local System", "collection",
        description="XSS used to exfiltrate sensitive data from client",
        detection="Monitor for unusual outbound data transfers from web app",
    ),
    "path_traversal": AttackTechnique(
        "T1083", "File and Directory Discovery", "collection",
        subtechnique="T1083.001",
        description="Path traversal to access files outside intended directory",
        detection="Monitor for unusual file access patterns, directory traversal in URLs",
    ),
    "lfi": AttackTechnique(
        "T1005", "Data from Local System", "collection",
        description="Local File Inclusion to read server files",
        detection="Monitor for access to sensitive file paths (/etc/passwd, etc.)",
    ),
    "graphql_abuse": AttackTechnique(
        "T1530", "Data from Cloud Storage", "collection",
        description="GraphQL introspection or query abuse",
        detection="Monitor for introspection queries, nested query depth",
    ),

    # Impact
    "rce": AttackTechnique(
        "T1203", "Exploitation for Client Execution", "impact",
        description="Remote Code Execution on target system",
        detection="Monitor for process creation from web application, unusual commands",
    ),
    "dos": AttackTechnique(
        "T1499", "Endpoint Denial of Service", "impact",
        description="Denial of Service via resource exhaustion",
        detection="Monitor for traffic spikes, resource exhaustion patterns",
    ),
    "data_manipulation": AttackTechnique(
        "T1565", "Data Manipulation", "impact",
        description="Business logic abuse for data manipulation",
        detection="Monitor for unexpected state changes, transaction anomalies",
    ),

    # Defense Evasion
    "waf_bypass": AttackTechnique(
        "T1027", "Obfuscated Files or Information", "defense-evasion",
        description="WAF evasion via encoding/obfuscation",
        detection="Monitor for encoded payloads, unusual character sequences",
    ),

    # Discovery
    "graphql_introspection": AttackTechnique(
        "T1592", "Gather Victim Host Information", "discovery",
        description="GraphQL introspection to discover API schema",
        detection="Monitor for __schema introspection queries",
    ),
    "sensitive_info_disclosure": AttackTechnique(
        "T1082", "System Information Discovery", "discovery",
        description="Information disclosure via error messages, headers, debug endpoints",
        detection="Monitor for access to debug endpoints, verbose error responses",
    ),
}

# Mapping from vulnerability class to primary ATT&CK technique
VULN_CLASS_TO_TECHNIQUE: dict[str, str] = {
    "sql_injection": "sql_injection",
    "xss": "xss_data_exfil",
    "ssrf": "ssrf",
    "idor": "idor",
    "auth_bypass": "auth_bypass",
    "command_injection": "command_injection",
    "ssti": "template_injection",
    "open_redirect": "open_redirect",
    "path_traversal": "path_traversal",
    "lfi": "lfi",
    "nosql_injection": "sql_injection",
    "graphql_abuse": "graphql_abuse",
    "jwt_attack": "jwt_attack",
    "deserialization": "deserialization",
    "mass_assignment": "mass_assignment",
    "race_condition": "data_manipulation",
    "rce": "rce",
    "sensitive_info_disclosure": "sensitive_info_disclosure",
    "waf_bypass": "waf_bypass",
    "graphql_introspection": "graphql_introspection",
}


class MITREMapper:
    """Maps vulnerability findings to MITRE ATT&CK."""

    def __init__(self):
        self.techniques = TECHNIQUE_MAP
        self.vuln_map = VULN_CLASS_TO_TECHNIQUE

    def get_technique(self, vuln_class: str) -> AttackTechnique:
        """Get ATT&CK technique for a vulnerability class."""
        key = self.vuln_map.get(vuln_class.lower(), vuln_class)
        return self.techniques.get(key, AttackTechnique(
            "T1190", "Exploit Public-Facing Application", "initial-access",
            description="Generic web application exploit",
        ))

    def get_tactic(self, vuln_class: str) -> str:
        """Get ATT&CK tactic for a vulnerability class."""
        return self.get_technique(vuln_class).tactic

    def get_detection(self, vuln_class: str) -> str:
        """Get detection guidance for a vulnerability class."""
        return self.get_technique(vuln_class).detection

    def map_finding(self, finding: dict) -> dict:
        """Enrich a finding dict with ATT&CK data."""
        vuln_class = finding.get("type", finding.get("vuln_class", "unknown"))
        technique = self.get_technique(vuln_class)

        finding["mitre_attack"] = {
            "technique_id": technique.technique_id,
            "technique_name": technique.name,
            "tactic": technique.tactic,
            "subtechnique": technique.subtechnique,
            "description": technique.description,
            "detection": technique.detection,
        }
        finding["mitre_attack_id"] = technique.technique_id
        finding["mitre_tactic"] = technique.tactic

        return finding

    def get_techniques_for_chain(self, vuln_classes: list[str]) -> list[dict]:
        """Get ATT&CK techniques for an attack chain."""
        seen = set()
        result = []
        for vc in vuln_classes:
            technique = self.get_technique(vc)
            if technique.technique_id not in seen:
                seen.add(technique.technique_id)
                result.append({
                    "technique_id": technique.technique_id,
                    "name": technique.name,
                    "tactic": technique.tactic,
                })
        return result
