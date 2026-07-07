"""
Security Tools Catalog — Complete listing of all integrated tools.

Each tool entry includes:
- Name, owner, license, platforms
- Install command
- Usage pattern for the agent
- Output format
- Category (recon, scan, fuzz, exploit, report)
"""

from dataclasses import dataclass
from typing import List, Optional
from enum import Enum


class ToolCategory(Enum):
    RECON = "recon"
    SCANNER = "scanner"
    FUZZER = "fuzzer"
    EXPLOIT = "exploit"
    REPORT = "report"
    UTIL = "util"


class ToolLicense(Enum):
    FREE = "free"
    OPEN_SOURCE = "open_source"
    COMMERCIAL = "commercial"
    FREEMIUM = "freemium"


@dataclass
class ToolEntry:
    name: str
    owner: str
    license_type: ToolLicense
    platforms: List[str]
    category: ToolCategory
    install_cmd: str
    usage_pattern: str
    output_format: str
    note: str = ""
    api_key_required: bool = False
    binary_name: Optional[str] = None  # If different from name

    @property
    def binary(self) -> str:
        return self.binary_name or self.name.lower()


# ═══════════════════════════════════════════════════════════════════
# COMPLETE TOOLS CATALOG
# ═══════════════════════════════════════════════════════════════════

TOOLS_CATALOG: List[ToolEntry] = [

    # ─── RECONNAISSANCE ────────────────────────────────────────────

    ToolEntry(
        name="Subfinder",
        owner="ProjectDiscovery",
        license_type=ToolLicense.FREE,
        platforms=["Linux", "macOS", "Windows"],
        category=ToolCategory.RECON,
        install_cmd="go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        usage_pattern="subfinder -d {target} -silent",
        output_format="text (one subdomain per line)",
        note="Passive subdomain enumeration from 40+ sources",
    ),
    ToolEntry(
        name="httpx",
        owner="ProjectDiscovery",
        license_type=ToolLicense.FREE,
        platforms=["Linux", "macOS", "Windows"],
        category=ToolCategory.RECON,
        install_cmd="go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
        usage_pattern="httpx -l {input_file} -silent -status-code -title -tech-detect",
        output_format="text/json (URL, status, title, tech)",
        note="Live host detection with fingerprinting",
    ),
    ToolEntry(
        name="katana",
        owner="ProjectDiscovery",
        license_type=ToolLicense.FREE,
        platforms=["Linux", "macOS", "Windows"],
        category=ToolCategory.RECON,
        install_cmd="go install github.com/projectdiscovery/katana/cmd/katana@latest",
        usage_pattern="katana -u {url} -d 3 -silent",
        output_format="text (URLs)",
        note="Web crawler with JS rendering support",
    ),
    ToolEntry(
        name="dnsx",
        owner="ProjectDiscovery",
        license_type=ToolLicense.FREE,
        platforms=["Linux", "macOS", "Windows"],
        category=ToolCategory.RECON,
        install_cmd="go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
        usage_pattern="dnsx -l {input_file} -silent -A -AAAA -CNAME -MX",
        output_format="text (DNS records)",
        note="DNS resolution with multiple record types",
    ),
    ToolEntry(
        name="Amass",
        owner="OWASP",
        license_type=ToolLicense.FREE,
        platforms=["Linux", "macOS", "Windows"],
        category=ToolCategory.RECON,
        install_cmd="apt install amass OR go install github.com/owasp-amass/amass/v4/...@master",
        usage_pattern="amass enum -d {target} -o {output_file}",
        output_format="text (subdomains with scores)",
        note="OWASP subdomain enumeration with OSINT",
    ),
    ToolEntry(
        name="Chaos",
        owner="ProjectDiscovery",
        license_type=ToolLicense.FREE,
        platforms=["Linux", "macOS", "Windows"],
        category=ToolCategory.RECON,
        install_cmd="go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest",
        usage_pattern="chaos -d {target} -silent",
        output_format="text (subdomains)",
        note="ProjectDiscovery's subdomain dataset API",
        api_key_required=True,
    ),
    ToolEntry(
        name="assetfinder",
        owner="Tomnomnom",
        license_type=ToolLicense.FREE,
        platforms=["Linux", "macOS"],
        category=ToolCategory.RECON,
        install_cmd="go install github.com/tomnomnom/assetfinder@latest",
        usage_pattern="assetfinder --subs-only {target}",
        output_format="text (subdomains)",
        note="Quick passive subdomain finder",
    ),
    ToolEntry(
        name="waybackurls",
        owner="Tomnomnom",
        license_type=ToolLicense.FREE,
        platforms=["Linux", "macOS"],
        category=ToolCategory.RECON,
        install_cmd="go install github.com/tomnomnom/waybackurls@latest",
        usage_pattern="echo {target} | waybackurls",
        output_format="text (URLs from Wayback Machine)",
        note="Historical URL discovery",
    ),
    ToolEntry(
        name="gau",
        owner="corlerac",
        license_type=ToolLicense.FREE,
        platforms=["Linux", "macOS", "Windows"],
        category=ToolCategory.RECON,
        install_cmd="go install github.com/lc/gau/v2/cmd/gau@latest",
        usage_pattern="gau {target} --threads 5",
        output_format="text (URLs from multiple sources)",
        note="Fetches URLs from AlienVault OTX, Wayback, Common Crawl",
    ),
    ToolEntry(
        name="anew",
        owner="Tomnomnom",
        license_type=ToolLicense.FREE,
        platforms=["Linux", "macOS"],
        category=ToolCategory.UTIL,
        install_cmd="go install github.com/tomnomnom/anew@latest",
        usage_pattern="cat {file} | anew {output_file}",
        output_format="text (new lines only)",
        note="Append unique lines to file (dedup)",
    ),

    # ─── SCANNERS ──────────────────────────────────────────────────

    ToolEntry(
        name="Nuclei",
        owner="ProjectDiscovery",
        license_type=ToolLicense.FREE,
        platforms=["Linux", "macOS", "Windows"],
        category=ToolCategory.SCANNER,
        install_cmd="go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        usage_pattern="nuclei -l {input_file} -t ~/nuclei-templates/ -severity critical,high,medium",
        output_format="text/json (template-id, severity, URL, matched-at)",
        note="Template-based vulnerability scanner with 9000+ templates",
    ),
    ToolEntry(
        name="Nmap",
        owner="Nmap Project",
        license_type=ToolLicense.FREE,
        platforms=["Linux", "macOS", "Windows"],
        category=ToolCategory.SCANNER,
        install_cmd="apt install nmap OR brew install nmap",
        usage_pattern="nmap -sV -sC -oX {output_file} {target}",
        output_format="XML/text (ports, services, versions)",
        note="Network scanner with NSE scripts",
    ),
    ToolEntry(
        name="Nikto",
        owner="CIRT.net",
        license_type=ToolLicense.FREE,
        platforms=["Linux", "macOS", "Windows"],
        category=ToolCategory.SCANNER,
        install_cmd="apt install nikto OR git clone https://github.com/sullo/nikto",
        usage_pattern="nikto -h {target} -o {output_file} -Format json",
        output_format="text/json (vulnerabilities)",
        note="Web server scanner (outdated but useful)",
    ),
    ToolEntry(
        name="Acunetix",
        owner="Acunetix",
        license_type=ToolLicense.COMMERCIAL,
        platforms=["Windows", "Linux", "macOS"],
        category=ToolCategory.SCANNER,
        install_cmd="Download from https://www.acunetix.com/vulnerability-scanner/",
        usage_pattern="acunetix-cli scan --target {url} --profile {profile}",
        output_format="JSON/XML (detailed vulnerabilities with CVSS)",
        note="Free limited capability (1 target). Commercial for full. Excellent WAF detection.",
        api_key_required=True,
    ),
    ToolEntry(
        name="OWASP ZAP",
        owner="OWASP",
        license_type=ToolLicense.FREE,
        platforms=["Linux", "macOS", "Windows"],
        category=ToolCategory.SCANNER,
        install_cmd="apt install zaproxy OR download from https://www.zaproxy.org/",
        usage_pattern="zap-cli quick-scan -s all -r {target}",
        output_format="JSON/XML (vulnerabilities with evidence)",
        note="Full-featured web application scanner with API",
    ),
    ToolEntry(
        name="Wapiti",
        owner="Wapiti Project",
        license_type=ToolLicense.FREE,
        platforms=["Linux", "macOS", "Windows"],
        category=ToolCategory.SCANNER,
        install_cmd="pip install wapiti3",
        usage_pattern="wapiti -u {target} -f json -o {output_file}",
        output_format="JSON (vulnerabilities)",
        note="Web application vulnerability scanner",
    ),
    ToolEntry(
        name="Arachni",
        owner="Arachni",
        license_type=ToolLicense.FREE,
        platforms=["Linux", "macOS"],
        category=ToolCategory.SCANNER,
        install_cmd="gem install arachni",
        usage_pattern="arachni --report-save-path {output_file} {target}",
        output_format="YAML/JSON (comprehensive report)",
        note="Modular, high-performance web scanner",
    ),

    # ─── FUZZERS ───────────────────────────────────────────────────

    ToolEntry(
        name="ffuf",
        owner="ffuf",
        license_type=ToolLicense.FREE,
        platforms=["Linux", "macOS", "Windows"],
        category=ToolCategory.FUZZER,
        install_cmd="go install github.com/ffuf/ffuf/v2@latest",
        usage_pattern='ffuf -u "{target}/FUZZ" -w {wordlist} -mc 200,301,302,403',
        output_format="text/json (URL, status, size, words)",
        note="Fast web fuzzer for directory/API fuzzing",
    ),
    ToolEntry(
        name="wfuzz",
        owner="X-Mind",
        license_type=ToolLicense.FREE,
        platforms=["Linux", "macOS"],
        category=ToolCategory.FUZZER,
        install_cmd="pip install wfuzz",
        usage_pattern='wfuzz -c -z file,{wordlist} --hc 404 {target}/FUZZ',
        output_format="text (URL, status, size, words, lines)",
        note="Web fuzzer with injection point control",
    ),
    ToolEntry(
        name="dirsearch",
        owner="maurosoria",
        license_type=ToolLicense.FREE,
        platforms=["Linux", "macOS", "Windows"],
        category=ToolCategory.FUZZER,
        install_cmd="git clone https://github.com/maurosoria/dirsearch",
        usage_pattern="python3 dirsearch.py -u {target} -e php,html,js",
        output_format="text (URL, status, size)",
        note="Directory/file brute-forcer",
    ),
    ToolEntry(
        name="gobuster",
        owner="OJ Reeves",
        license_type=ToolLicense.FREE,
        platforms=["Linux", "macOS", "Windows"],
        category=ToolCategory.FUZZER,
        install_cmd="go install github.com/OJ/gobuster/v3@latest",
        usage_pattern="gobuster dir -u {target} -w {wordlist}",
        output_format="text (URL, status)",
        note="Directory/DNS/VHost brute-forcer",
    ),
    ToolEntry(
        name="Feroxbuster",
        owner="epi052",
        license_type=ToolLicense.FREE,
        platforms=["Linux", "macOS", "Windows"],
        category=ToolCategory.FUZZER,
        install_cmd="cargo install feroxbuster",
        usage_pattern="feroxbuster -u {target} -w {wordlist} --json",
        output_format="JSON (URLs with status, size, words)",
        note="Recursive content discovery tool (Rust)",
    ),

    # ─── EXPLOIT / INJECTION ───────────────────────────────────────

    ToolEntry(
        name="sqlmap",
        owner="sqlmap",
        license_type=ToolLicense.FREE,
        platforms=["Linux", "macOS", "Windows"],
        category=ToolCategory.EXPLOIT,
        install_cmd="apt install sqlmap OR git clone https://github.com/sqlmapproject/sqlmap",
        usage_pattern="python3 sqlmap.py -u {url} --batch --level 3 --risk 2",
        output_format="text (injection points, database info)",
        note="Automatic SQL injection tool",
    ),
    ToolEntry(
        name="dalfox",
        owner="hahwul",
        license_type=ToolLicense.FREE,
        platforms=["Linux", "macOS", "Windows"],
        category=ToolCategory.EXPLOIT,
        install_cmd="go install github.com/hahwul/dalfox/v2@latest",
        usage_pattern="dalfox url {url} --blind {callback}",
        output_format="text/json (XSS vectors)",
        note="XSS scanner and parameter analyzer",
    ),
    ToolEntry(
        name="SSRFmap",
        owner="sw33tLie",
        license_type=ToolLicense.FREE,
        platforms=["Linux", "macOS"],
        category=ToolCategory.EXPLOIT,
        install_cmd="git clone https://github.com/sw33tLie/ssrfmap",
        usage_pattern="python3 ssrfmap.py -r {request_file} -p {param} -m portscan",
        output_format="text (SSRF exploitation results)",
        note="SSRF exploitation tool",
    ),
    ToolEntry(
        name="commix",
        owner="commixproject",
        license_type=ToolLicense.FREE,
        platforms=["Linux", "macOS", "Windows"],
        category=ToolCategory.EXPLOIT,
        install_cmd="git clone https://github.com/commixproject/commix",
        usage_pattern="python3 commix.py --url={url} --param={param}",
        output_format="text (command injection results)",
        note="Automated command injection tool",
    ),
    ToolEntry(
        name="tplmap",
        owner="epinna",
        license_type=ToolLicense.FREE,
        platforms=["Linux", "macOS"],
        category=ToolCategory.EXPLOIT,
        install_cmd="git clone https://github.com/epinna/tplmap",
        usage_pattern="python3 tplmap.py -u {url} --level 5",
        output_format="text (template injection + RCE)",
        note="Server-side template injection detection and exploitation",
    ),
    ToolEntry(
        name="XSStrike",
        owner="s0md3v",
        license_type=ToolLicense.FREE,
        platforms=["Linux", "macOS"],
        category=ToolCategory.EXPLOIT,
        install_cmd="git clone https://github.com/s0md3v/XSStrike",
        usage_pattern="python3 xsstrike.py -u {url} --crawl",
        output_format="text (XSS payloads)",
        note="Advanced XSS scanner",
    ),
    ToolEntry(
        name="Arjun",
        owner="s0md3v",
        license_type=ToolLicense.FREE,
        platforms=["Linux", "macOS", "Windows"],
        category=ToolCategory.EXPLOIT,
        install_cmd="pip install arjun",
        usage_pattern="arjun -u {url} -oJ {output_file}",
        output_format="JSON (hidden parameters)",
        note="HTTP parameter discovery",
    ),

    # ─── UTILITIES ─────────────────────────────────────────────────

    ToolEntry(
        name="curl",
        owner="curl",
        license_type=ToolLicense.FREE,
        platforms=["Linux", "macOS", "Windows"],
        category=ToolCategory.UTIL,
        install_cmd="apt install curl OR brew install curl",
        usage_pattern='curl -s -o /dev/null -w "%{{http_code}}" {url}',
        output_format="text (HTTP response)",
        note="HTTP client for manual testing",
    ),
    ToolEntry(
        name="jq",
        owner="stedolan",
        license_type=ToolLicense.FREE,
        platforms=["Linux", "macOS", "Windows"],
        category=ToolCategory.UTIL,
        install_cmd="apt install jq OR brew install jq",
        usage_pattern='jq ".vulnerabilities[] | select(.severity==\"high\")"',
        output_format="text (filtered JSON)",
        note="JSON processor for parsing tool outputs",
    ),
    ToolEntry(
        name="qsreplace",
        owner="tomnomnom",
        license_type=ToolLicense.FREE,
        platforms=["Linux", "macOS"],
        category=ToolCategory.UTIL,
        install_cmd="go install github.com/tomnomnom/qsreplace@latest",
        usage_pattern='cat urls.txt | qsreplace "FUZZ"',
        output_format="text (URLs with replaced params)",
        note="Query string replacement for testing",
    ),
    ToolEntry(
        name="interactsh-client",
        owner="ProjectDiscovery",
        license_type=ToolLicense.FREE,
        platforms=["Linux", "macOS", "Windows"],
        category=ToolCategory.UTIL,
        install_cmd="go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest",
        usage_pattern="interactsh-client -silent",
        output_format="text (callback interactions)",
        note="Out-of-band interaction server (SSRF, blind XSS, etc.)",
    ),

    # ─── REPORTING ─────────────────────────────────────────────────

    ToolEntry(
        name="Chaos-Plus-Plus",
        owner="ProjectDiscovery",
        license_type=ToolLicense.FREE,
        platforms=["Linux", "macOS", "Windows"],
        category=ToolCategory.REPORT,
        install_cmd="go install github.com/projectdiscovery/chaos-plus-plus@latest",
        usage_pattern="echo {target} | chaos-plus-plus -stats",
        output_format="text (subdomain statistics)",
        note="Subdomain statistics for reporting",
    ),
]


# ═══════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════

def get_tools_by_category(category: ToolCategory) -> List[ToolEntry]:
    """Get all tools in a category."""
    return [t for t in TOOLS_CATALOG if t.category == category]


def get_free_tools() -> List[ToolEntry]:
    """Get all free/open-source tools."""
    return [t for t in TOOLS_CATALOG
            if t.license_type in (ToolLicense.FREE, ToolLicense.OPEN_SOURCE, ToolLicense.FREEMIUM)]


def get_tool(name: str) -> Optional[ToolEntry]:
    """Get a tool by name (case-insensitive)."""
    name_lower = name.lower()
    for t in TOOLS_CATALOG:
        if t.name.lower() == name_lower or t.binary == name_lower:
            return t
    return None


def get_install_commands() -> str:
    """Get all install commands for setup script."""
    lines = []
    for t in TOOLS_CATALOG:
        lines.append(f"# {t.name} ({t.license_type.value})")
        lines.append(t.install_cmd)
        lines.append("")
    return "\n".join(lines)


def check_tools_installed() -> dict:
    """Check which tools are installed on the system."""
    import shutil
    results = {}
    for t in TOOLS_CATALOG:
        results[t.name] = {
            "installed": shutil.which(t.binary) is not None,
            "binary": t.binary,
            "category": t.category.value,
            "license": t.license_type.value,
        }
    return results


def print_tools_table():
    """Print a formatted table of all tools."""
    print(f"\n{'='*100}")
    print(f"{'NAME':<20} {'OWNER':<20} {'LICENSE':<12} {'PLATFORMS':<30} {'CATEGORY':<12}")
    print(f"{'='*100}")
    for t in TOOLS_CATALOG:
        platforms = ", ".join(t.platforms[:2])
        if len(t.platforms) > 2:
            platforms += f" +{len(t.platforms)-2}"
        print(f"{t.name:<20} {t.owner:<20} {t.license_type.value:<12} {platforms:<30} {t.category.value:<12}")
    print(f"{'='*100}")
    print(f"Total tools: {len(TOOLS_CATALOG)}")
    print(f"Free tools: {len(get_free_tools())}")
    print(f"Categories: {len(set(t.category for t in TOOLS_CATALOG))}")
