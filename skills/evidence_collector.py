"""
Evidence Collector — Ensures all findings have sufficient evidence for validation.

Every finding must include:
1. Exact payload used
2. Injection point details
3. HTTP request sent
4. HTTP response received
5. Baseline comparison (before/after)
6. Reproduction steps
7. Evidence of server-side processing
"""

from typing import Dict, Any, Optional
from urllib.parse import urlparse, parse_qs, urlencode
import json


class EvidenceCollector:
    """
    Collects and validates evidence for security findings.
    
    Usage:
        collector = EvidenceCollector()
        finding = collector.enrich_finding(
            finding=raw_finding,
            url="https://target.com/api?id=1",
            param="id",
            payload="' OR '1'='1",
            baseline_response=baseline,
            exploit_response=exploit,
        )
    """

    REQUIRED_FIELDS = [
        "payload_used",
        "injection_point",
        "http_request",
        "http_response",
        "baseline_comparison",
        "reproduction_steps",
    ]

    def __init__(self):
        self.findings_enriched = 0
        self.findings_rejected = 0

    def enrich_finding(
        self,
        finding: Dict[str, Any],
        url: str,
        param: str,
        payload: str,
        baseline_response: Optional[Dict] = None,
        exploit_response: Optional[Dict] = None,
        evidence_context: str = "",
        server_side_proof: str = "",
    ) -> Dict[str, Any]:
        """
        Enrich a finding with complete evidence.
        
        Args:
            finding: Raw finding dict
            url: Full URL with parameter
            param: Parameter name being tested
            payload: Exact payload used
            baseline_response: Response without payload (for comparison)
            exploit_response: Response with payload
            evidence_context: Context around the evidence in response
            server_side_proof: Proof that input was processed server-side
        
        Returns:
            Enriched finding with all required evidence fields
        """
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        # Build HTTP request
        http_request = self._build_http_request(url, payload, param, query_params)
        
        # Build HTTP response
        http_response = self._build_http_response(exploit_response)
        
        # Build baseline comparison
        baseline_comparison = self._build_baseline_comparison(
            baseline_response, exploit_response
        )
        
        # Build reproduction steps
        reproduction_steps = self._build_reproduction_steps(
            url, param, payload, finding.get("type", "")
        )
        
        # Build injection point details
        injection_point = self._build_injection_point(param, query_params, url)
        
        # Enrich the finding
        finding.update({
            # Core evidence fields
            "payload_used": payload,
            "injection_point": injection_point,
            "http_request": http_request,
            "http_response": http_response,
            "baseline_comparison": baseline_comparison,
            "reproduction_steps": reproduction_steps,
            
            # Additional context
            "evidence_context": evidence_context,
            "server_side_proof": server_side_proof,
            "tested_url": url,
            
            # Evidence quality score
            "evidence_score": self._calculate_evidence_score(finding),
            
            # Verification metadata
            "verification": {
                "status": "unverified",
                "confidence": finding.get("confidence", 0.5),
                "evidence_collected": True,
                "evidence_fields": self.REQUIRED_FIELDS,
            },
        })
        
        self.findings_enriched += 1
        return finding

    def _build_http_request(
        self,
        url: str,
        payload: str,
        param: str,
        query_params: Dict,
    ) -> str:
        """Build a complete HTTP request string."""
        parsed = urlparse(url)
        
        # Build request line
        request_line = f"GET {parsed.path}"
        if parsed.query:
            request_line += f"?{parsed.query}"
        request_line += " HTTP/1.1"
        
        # Build headers
        headers = [
            request_line,
            f"Host: {parsed.netloc}",
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language: en-US,en;q=0.5",
            "Connection: close",
            "",
            f"[Payload injected in parameter: {param}]",
            f"[Payload: {payload}]",
        ]
        
        return "\r\n".join(headers)

    def _build_http_response(self, response: Optional[Dict]) -> str:
        """Build HTTP response string from response dict."""
        if not response:
            return "[No response captured]"
        
        status = response.get("status", 0)
        body = response.get("body", "")
        headers = response.get("headers", {})
        
        response_parts = [
            f"HTTP/1.1 {status}",
        ]
        
        for key, value in headers.items():
            response_parts.append(f"{key}: {value}")
        
        response_parts.append("")
        response_parts.append(body[:2000])  # Limit body size
        
        return "\r\n".join(response_parts)

    def _build_baseline_comparison(
        self,
        baseline: Optional[Dict],
        exploit: Optional[Dict],
    ) -> Dict:
        """Build baseline comparison showing before/after."""
        if not baseline or not exploit:
            return {
                "available": False,
                "reason": "Baseline or exploit response not captured",
            }
        
        baseline_body = baseline.get("body", "")
        exploit_body = exploit.get("body", "")
        
        return {
            "available": True,
            "baseline_status": baseline.get("status", 0),
            "exploit_status": exploit.get("status", 0),
            "baseline_size": len(baseline_body),
            "exploit_size": len(exploit_body),
            "size_diff": len(exploit_body) - len(baseline_body),
            "status_changed": baseline.get("status") != exploit.get("status"),
            "body_changed": baseline_body != exploit_body,
            "key_differences": self._find_key_differences(baseline_body, exploit_body),
        }

    def _find_key_differences(self, baseline: str, exploit: str) -> list:
        """Find key differences between baseline and exploit responses."""
        differences = []
        
        # Check for new error messages
        error_indicators = [
            "error", "exception", "warning", "sql", "mysql",
            "syntax", "root:", "uid=", "admin", "password",
        ]
        
        baseline_lower = baseline.lower()
        exploit_lower = exploit.lower()
        
        for indicator in error_indicators:
            if indicator in exploit_lower and indicator not in baseline_lower:
                differences.append(f"New '{indicator}' found in exploit response")
        
        # Check for size changes
        size_diff = len(exploit) - len(baseline)
        if abs(size_diff) > 100:
            differences.append(f"Response size changed by {size_diff} bytes")
        
        # Check for status code changes
        # (This would need status codes, which aren't in body strings)
        
        return differences

    def _build_reproduction_steps(
        self,
        url: str,
        param: str,
        payload: str,
        vuln_type: str,
    ) -> list:
        """Build clear reproduction steps."""
        parsed = urlparse(url)
        
        steps = [
            f"1. Navigate to: {parsed.scheme}://{parsed.netloc}{parsed.path}",
            f"2. Locate parameter: {param}",
            f"3. Inject payload: {payload}",
            f"4. Observe the response for: {self._get_expected_behavior(vuln_type)}",
            f"5. Verify the finding by: {self._get_verification_method(vuln_type)}",
        ]
        
        return steps

    def _get_expected_behavior(self, vuln_type: str) -> str:
        """Get expected behavior for vulnerability type."""
        behaviors = {
            "sqli": "SQL error messages or data extraction",
            "xss": "Payload reflected in HTML without encoding",
            "ssti": "Math expression evaluated (e.g., {{7*7}} = 49)",
            "ssrf": "Internal content or metadata accessible",
            "idor": "Different user data returned",
            "lfi": "File contents displayed",
            "command_injection": "Command output in response",
            "auth_bypass": "Access granted without proper authentication",
            "open_redirect": "Redirect to external URL",
            "nosqli": "NoSQL query results returned",
        }
        return behaviors.get(vuln_type, "Unexpected behavior confirming vulnerability")

    def _get_verification_method(self, vuln_type: str) -> str:
        """Get verification method for vulnerability type."""
        methods = {
            "sqli": "Using UNION-based or boolean-based confirmation",
            "xss": "Confirming payload executes in browser",
            "ssti": "Testing multiple math expressions",
            "ssrf": "Accessing internal metadata endpoints",
            "idor": "Comparing responses with different IDs",
            "lfi": "Reading known system files",
            "command_injection": "Executing canary commands",
            "auth_bypass": "Comparing authenticated vs unauthenticated",
            "open_redirect": "Following redirect chain",
            "nosqli": "Testing NoSQL operators",
        }
        return methods.get(vuln_type, "Additional testing required")

    def _build_injection_point(
        self,
        param: str,
        query_params: Dict,
        url: str,
    ) -> Dict:
        """Build detailed injection point information."""
        parsed = urlparse(url)
        
        # Determine injection location
        if "?" in url:
            location = "query_parameter"
        elif param.startswith("X-") or param.startswith("Authorization"):
            location = "header"
        elif param.startswith("Cookie"):
            location = "cookie"
        else:
            location = "body"
        
        return {
            "parameter": param,
            "location": location,
            "original_value": query_params.get(param, [""])[0],
            "full_url": url,
            "path": parsed.path,
            "host": parsed.netloc,
        }

    def _calculate_evidence_score(self, finding: Dict) -> float:
        """Calculate evidence quality score (0-1)."""
        score = 0.0
        max_score = len(self.REQUIRED_FIELDS)
        
        for field in self.REQUIRED_FIELDS:
            if finding.get(field):
                score += 1
        
        # Bonus for additional evidence
        if finding.get("server_side_proof"):
            score += 0.5
        if finding.get("baseline_comparison", {}).get("available"):
            score += 0.5
        
        return min(1.0, score / max_score)

    def validate_evidence(self, finding: Dict) -> Dict:
        """
        Validate that a finding has sufficient evidence.
        
        Returns:
            {
                "valid": bool,
                "score": float,
                "missing": list of missing fields,
                "warnings": list of warnings
            }
        """
        missing = []
        warnings = []
        
        for field in self.REQUIRED_FIELDS:
            if not finding.get(field):
                missing.append(field)
        
        # Check evidence quality
        score = finding.get("evidence_score", 0)
        
        if score < 0.5:
            warnings.append("Low evidence score — may be rejected by validators")
        
        if not finding.get("verification", {}).get("status"):
            warnings.append("No verification status — finding is unverified")
        
        if not finding.get("baseline_comparison", {}).get("available"):
            warnings.append("No baseline comparison — cannot confirm change")
        
        return {
            "valid": len(missing) == 0,
            "score": score,
            "missing": missing,
            "warnings": warnings,
        }

    def get_stats(self) -> Dict:
        """Get collection statistics."""
        return {
            "findings_enriched": self.findings_enriched,
            "findings_rejected": self.findings_rejected,
        }
