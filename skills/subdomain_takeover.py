"""
Subdomain Takeover Detection — cheap, high-signal, near-zero false positive.

Checks CNAME records against known vulnerable services:
- GitHub Pages, Heroku, Shopify, Tumblr, WordPress.com, etc.
- If CNAME points to a service but the service isn't claimed → takeover
"""

import asyncio
import re
from typing import Dict, List, Any, Optional
from skills.base import BaseSkill, SkillResult


# Known vulnerable CNAME targets (service → fingerprint)
VULNERABLE_CNAME_TARGETS = {
    # Cloud hosting
    "github.io": {"service": "GitHub Pages", "verify": "There isn't a GitHub Pages site here"},
    "githubapp.com": {"service": "GitHub App", "verify": "apps/github"},
    "herokudns.com": {"service": "Heroku", "verify": "No such app"},
    "herokuapp.com": {"service": "Heroku", "verify": "No such app"},
    "herokuspace.com": {"service": "Heroku", "verify": "No such app"},
    "pantheonsite.io": {"service": "Pantheon", "verify": "404 error unknown site"},
    "ghost.io": {"service": "Ghost", "verify": "The thing you were looking for is no here"},
    "shopify.com": {"service": "Shopify", "verify": "Sorry, this shop is currently unavailable"},
    "squarespace.com": {"service": "Squarespace", "verify": "No Such Account"},
    "strikingly.com": {"service": "Strikingly", "verify": "But if you're looking for a website"},
    "tumblr.com": {"service": "Tumblr", "verify": "Whatever you were looking for"},
    "wordpress.com": {"service": "WordPress.com", "verify": "Do you want to register"},
    "zendesk.com": {"service": "Zendesk", "verify": "Help Center Closed"},
    "readme.io": {"service": "ReadMe", "verify": "Project doesn't exist"},
    "cargocollective.com": {"service": "Cargo", "verify": "If this is your website"},
    "feedpress.com": {"service": "FeedPress", "verify": "The feed hasn't been found"},
    "ghost.io": {"service": "Ghost", "verify": "The thing you were looking for"},
    "helpjuice.com": {"service": "Helpjuice", "verify": "We couldn't find the page"},
    "helpscoutdocs.com": {"service": "HelpScout", "verify": "No documentation was found"},
    "landingi.com": {"service": "Landingi", "verify": "It looks like you're lost"},
    "launchrock.com": {"service": "LaunchRock", "verify": "It looks like you may have taken a wrong turn somewhere"},
    "mashery.com": {"service": "Mashery", "verify": "Unrecognized domain"},
    "ngrok.io": {"service": "Ngrok", "verify": "Tunnel *.ngrok.io not found"},
    "pingdom.com": {"service": "Pingdom", "verify": "Sorry, couldn't find the status page"},
    "proposify.biz": {"service": "Proposify", "verify": "If you need immediate assistance"},
    "readme.io": {"service": "ReadMe", "verify": "Project doesn't exist"},
    "simplebooklet.com": {"service": "SimpleBooklet", "verify": "We can't find this"},
    "smartling.com": {"service": "Smartling", "verify": "Domain is not configured"},
    "statuspage.io": {"service": "Atlassian StatusPage", "verify": "Better StatusPage"},
    "surge.sh": {"service": "Surge.sh", "verify": "project not found"},
    "tave.com": {"service": "Tave", "verify": "Error: Domain not found"},
    "teamwork.com": {"service": "Teamwork", "verify": "Oops - We didn't find your site"},
    "thinkific.com": {"service": "Thinkific", "verify": "You may have typed the address incorrectly"},
    "tictail.com": {"service": "Tictail", "verify": "to start selling online"},
    "tumblr.com": {"service": "Tumblr", "verify": "Whatever you were looking for"},
    "uberflip.com": {"service": "Uberflip", "verify": "Blog not found"},
    "unbounce.com": {"service": "Unbounce", "verify": "The requested page / could not be found"},
    "uservoice.com": {"service": "UserVoice", "verify": "This UserVoice subdomain is currently available!"},
    "via.weebly.com": {"service": "Weebly", "verify": "Does this look right"},
    "webex.com": {"service": "Webex", "verify": "We couldn't find the Webex site"},
    "wishpond.com": {"service": "Wishpond", "verify": "https://www.wishpond.com/404?url"},
    "wishpond.com": {"service": "Wishpond", "verify": "looks like you've followed a broken link"},
    "wordpress.com": {"service": "WordPress.com", "verify": "Do you want to register"},
    "zendesk.com": {"service": "Zendesk", "verify": "Help Center Closed"},
    "worksites.net": {"service": "Worksites", "verify": "Hello! Sorry, but the website you"},
    "zoho.com": {"service": "Zoho", "verify": "This domain is configured as an alias"},
}


class SubdomainTakeoverSkill(BaseSkill):
    """
    Detect subdomain takeover vulnerabilities.
    
    Flow:
    1. Resolve CNAME for each subdomain
    2. Check if CNAME points to a known vulnerable service
    3. Verify the service isn't claimed (HTTP check)
    4. Report with proof
    """

    def can_handle(self, task_type: str) -> bool:
        return task_type in ["subdomain_takeover", "takeover", "subdomain"]

    async def execute(self, context: Dict[str, Any]) -> SkillResult:
        subdomains = context.get("subdomains", [])
        target = context.get("target", "")
        
        if not subdomains:
            # Generate common subdomains to check
            subdomains = self._generate_subdomains(target)

        findings = []
        
        for subdomain in subdomains:
            if not subdomain.endswith(target):
                subdomain = f"{subdomain}.{target}"
            
            # Resolve CNAME
            cname = await self._resolve_cname(subdomain)
            if not cname:
                continue
            
            # Check against vulnerable services
            vuln_service = self._check_vulnerable_cname(cname)
            if not vuln_service:
                continue
            
            # Verify takeover is possible
            takeover_proof = await self._verify_takeover(subdomain, vuln_service)
            if takeover_proof:
                findings.append({
                    "type": "subdomain_takeover",
                    "url": f"https://{subdomain}",
                    "severity": "high",
                    "confidence": 0.95,
                    "cvss_score": 7.5,
                    "evidence": takeover_proof,
                    "description": f"Subdomain takeover via {vuln_service['service']} — CNAME: {cname}",
                    "payload": f"CNAME {subdomain} -> {cname}",
                    "param": "CNAME",
                    "remediation": f"Remove DNS record or claim the {vuln_service['service']} service",
                    "source_tool": "subdomain-takeover",
                })

        return SkillResult(
            success=True,
            findings=findings,
            data={"subdomains_checked": len(subdomains), "cnames_found": len(findings)},
            next_skills=["validate"],
            confidence=min(len(findings) / 5, 1.0) if findings else 0.0,
        )

    def _generate_subdomains(self, target: str) -> List[str]:
        """Generate common subdomains to check."""
        prefixes = [
            "www", "api", "dev", "staging", "admin", "mail", "ftp",
            "webmail", "smtp", "pop", "ns1", "ns2", "dns", "cdn",
            "assets", "static", "media", "img", "images", "docs",
            "blog", "shop", "store", "app", "mobile", "beta",
            "test", "qa", "uat", "demo", "sandbox", "portal",
            "dashboard", "panel", "manage", "console", "status",
            "support", "help", "docs", "wiki", "git", "gitlab",
            "jenkins", "ci", "cd", "build", "deploy", "monitor",
            "grafana", "kibana", "elastic", "search", "db", "database",
            "redis", "mysql", "postgres", "mongo", "elastic",
        ]
        return [f"{p}.{target}" for p in prefixes]

    async def _resolve_cname(self, domain: str) -> Optional[str]:
        """Resolve CNAME record for a domain."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "dig", "+short", "CNAME", domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            cname = stdout.decode().strip().rstrip(".")
            if cname and cname != domain:
                return cname
        except Exception:
            pass
        
        # Fallback: try nslookup
        try:
            proc = await asyncio.create_subprocess_exec(
                "nslookup", "-type=CNAME", domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            output = stdout.decode()
            match = re.search(r"canonical name = (.+)", output, re.IGNORECASE)
            if match:
                return match.group(1).strip().rstrip(".")
        except Exception:
            pass
        
        return None

    def _check_vulnerable_cname(self, cname: str) -> Optional[Dict]:
        """Check if CNAME points to a known vulnerable service."""
        cname_lower = cname.lower()
        for target, info in VULNERABLE_CNAME_TARGETS.items():
            if target in cname_lower:
                return info
        return None

    async def _verify_takeover(self, subdomain: str, vuln_service: Dict) -> Optional[str]:
        """Verify that the service is actually unclaimed."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "-L", "--max-time", "10",
                f"https://{subdomain}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            body = stdout.decode().lower()
            
            verify_string = vuln_service.get("verify", "").lower()
            if verify_string and verify_string in body:
                return f"Service '{vuln_service['service']}' confirmed unclaimed: '{verify_string}' found in response"
        except Exception:
            pass
        
        return None
