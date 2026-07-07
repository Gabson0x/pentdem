"""
Screenshot Capture — Evidence screenshots for PoC results.

Renders styled PoC evidence cards showing: exploit command, HTTP request/response,
analysis, and severity badge — NOT just a screenshot of the page.
"""

import asyncio
import hashlib
import json
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse


# ─── HTML Templates (use __VAR__ placeholders to avoid brace conflicts) ──

POC_CARD_HTML = """<!DOCTYPE html>
<html>
<head>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'SF Mono', 'Courier New', monospace;
    background: #0d1117;
    color: #c9d1d9;
    padding: 32px;
  }
  .card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 12px;
    padding: 28px;
    max-width: 900px;
    box-shadow: 0 8px 24px rgba(0,0,0,0.4);
  }
  .header {
    display: flex;
    align-items: center;
    gap: 14px;
    margin-bottom: 22px;
    padding-bottom: 16px;
    border-bottom: 1px solid #21262d;
  }
  .severity {
    padding: 5px 14px;
    border-radius: 6px;
    font-weight: 700;
    font-size: 13px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }
  .sev-critical { background: #da3633; color: #fff; }
  .sev-high { background: #d29922; color: #000; }
  .sev-medium { background: #9e6a03; color: #fff; }
  .sev-low { background: #388bfd; color: #fff; }
  .sev-info { background: #6e7681; color: #fff; }
  .vuln-type {
    font-size: 22px;
    font-weight: 700;
    color: #f0f6fc;
  }
  .meta {
    color: #8b949e;
    font-size: 13px;
    margin-bottom: 20px;
    line-height: 1.6;
  }
  .meta strong { color: #c9d1d9; }
  .section { margin-bottom: 18px; }
  .section-label {
    color: #58a6ff;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-bottom: 8px;
  }
  .code-block {
    background: #0d1117;
    border: 1px solid #21262d;
    border-radius: 8px;
    padding: 14px 16px;
    font-family: 'SF Mono', 'Fira Code', monospace;
    font-size: 13px;
    line-height: 1.5;
    white-space: pre-wrap;
    word-break: break-all;
    overflow-x: auto;
  }
  .cmd { border-left: 3px solid #da3633; }
  .req { border-left: 3px solid #d29922; }
  .res { border-left: 3px solid #3fb950; }
  .analysis { border-left: 3px solid #58a6ff; }
  .badge-row {
    display: flex;
    gap: 10px;
    margin-bottom: 18px;
    flex-wrap: wrap;
  }
  .badge {
    padding: 4px 10px;
    border-radius: 4px;
    font-size: 12px;
    font-weight: 600;
  }
  .badge-mitre { background: #1f6feb33; color: #58a6ff; border: 1px solid #1f6feb; }
  .badge-tool { background: #23862633; color: #3fb950; border: 1px solid #238626; }
  .badge-cvss { background: #da363333; color: #ff7b72; border: 1px solid #da3633; }
  .footer {
    margin-top: 20px;
    padding-top: 14px;
    border-top: 1px solid #21262d;
    color: #6e7681;
    font-size: 11px;
  }
</style>
</head>
<body>
<div class="card">
  <div class="header">
    <span class="severity sev-__SEV_CLASS__">__SEVERITY__</span>
    <span class="vuln-type">__VULN_TYPE__</span>
  </div>

  <div class="badge-row">
    <span class="badge badge-cvss">CVSS __CVSS__</span>
    <span class="badge badge-mitre">MITRE __MITRE__</span>
    <span class="badge badge-tool">via __SOURCE__</span>
  </div>

  <div class="meta">
    <strong>Target:</strong> __TARGET__<br>
    <strong>Endpoint:</strong> __ENDPOINT__<br>
    <strong>Parameter:</strong> __PARAMETER__
  </div>

  <div class="section">
    <div class="section-label">Exploit Command</div>
    <div class="code-block cmd">__POC__</div>
  </div>

  <div class="section">
    <div class="section-label">HTTP Request</div>
    <div class="code-block req">__HTTP_REQUEST__</div>
  </div>

  <div class="section">
    <div class="section-label">HTTP Response</div>
    <div class="code-block res">__HTTP_RESPONSE__</div>
  </div>

  <div class="section">
    <div class="section-label">Analysis</div>
    <div class="code-block analysis">__ANALYSIS__</div>
  </div>

  <div class="footer">
    AI Pentest Daemon v3.0 — __TIMESTAMP__
  </div>
</div>
</body>
</html>"""


NUCLEI_CARD_HTML = """<!DOCTYPE html>
<html>
<head>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, sans-serif; background: #0d1117; color: #c9d1d9; padding: 32px; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 28px; max-width: 900px; }
  .header { display: flex; align-items: center; gap: 14px; margin-bottom: 20px; padding-bottom: 16px; border-bottom: 1px solid #21262d; }
  .severity { padding: 5px 14px; border-radius: 6px; font-weight: 700; font-size: 13px; text-transform: uppercase; }
  .sev-critical { background: #da3633; color: #fff; }
  .sev-high { background: #d29922; color: #000; }
  .sev-medium { background: #9e6a03; color: #fff; }
  .vuln-type { font-size: 20px; font-weight: 700; color: #f0f6fc; }
  .section { margin-bottom: 16px; }
  .section-label { color: #58a6ff; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; }
  .code-block { background: #0d1117; border: 1px solid #21262d; border-radius: 8px; padding: 14px 16px; font-family: monospace; font-size: 13px; white-space: pre-wrap; }
  .match { border-left: 3px solid #3fb950; }
  .desc { border-left: 3px solid #58a6ff; }
  .footer { margin-top: 20px; padding-top: 14px; border-top: 1px solid #21262d; color: #6e7681; font-size: 11px; }
</style>
</head>
<body>
<div class="card">
  <div class="header">
    <span class="severity sev-__SEV_CLASS__">__SEVERITY__</span>
    <span class="vuln-type">__TEMPLATE_NAME__</span>
  </div>
  <div class="meta" style="color:#8b949e;font-size:13px;margin-bottom:18px">
    <strong>Template:</strong> __TEMPLATE_ID__ &nbsp;|&nbsp;
    <strong>Target:</strong> __TARGET__ &nbsp;|&nbsp;
    <strong>Matched:</strong> __MATCHED_AT__
  </div>
  <div class="section">
    <div class="section-label">Matched Evidence</div>
    <div class="code-block match">__EVIDENCE__</div>
  </div>
  <div class="section">
    <div class="section-label">Description</div>
    <div class="code-block desc">__DESCRIPTION__</div>
  </div>
  <div class="footer">AI Pentest Daemon v3.0 — __TIMESTAMP__</div>
</div>
</body>
</html>"""


# ─── Screenshot Engine ───────────────────────────────────────────

class ScreenshotCapture:
    """
    Captures evidence screenshots for security findings.

    Renders styled PoC evidence cards showing: exploit command, HTTP request/response,
    and analysis — the real proof, not a blank page.
    """

    def __init__(self, base_dir: str = "reports"):
        self.base_dir = Path(base_dir)
        self._browser = None
        self._context = None

    def _get_screenshot_dir(self, target: str) -> Path:
        safe = target.replace("https://", "").replace("http://", "")
        safe = safe.replace("/", "_").replace(":", "_").replace("?", "_")[:50]
        d = self.base_dir / safe / "screenshots"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _hash(self, s: str) -> str:
        return hashlib.md5(s.encode()).hexdigest()[:8]

    def _render_template(self, template: str, replacements: dict) -> str:
        """Replace __VAR__ placeholders with values."""
        result = template
        for key, value in replacements.items():
            placeholder = f"__{key}__"
            # Escape HTML in values
            safe_val = str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            result = result.replace(placeholder, safe_val)
        return result

    async def _get_browser(self):
        if self._browser is None:
            try:
                from playwright.async_api import async_playwright
                self._pw = await async_playwright().start()
                self._browser = await self._pw.chromium.launch(headless=True)
                self._context = await self._browser.new_context(
                    viewport={"width": 1000, "height": 800},
                )
            except Exception as e:
                print(f"  Warning: Playwright unavailable: {e}")
                return None
        return self._context

    async def close(self):
        if self._browser:
            await self._browser.close()
        if hasattr(self, '_pw') and self._pw:
            await self._pw.stop()
        self._browser = None
        self._context = None

    async def _render_html(self, html: str, filepath: Path) -> Optional[str]:
        """Render HTML to a PNG screenshot."""
        context = await self._get_browser()
        if not context:
            return None
        try:
            page = await context.new_page()
            await page.set_content(html, wait_until="networkidle")
            await page.wait_for_timeout(400)
            await page.screenshot(path=str(filepath), full_page=True)
            await page.close()
            return str(filepath)
        except Exception as e:
            try:
                await page.close()
            except Exception:
                pass
            return None

    async def capture_poc(
        self,
        target: str,
        finding: dict,
    ) -> Optional[str]:
        """
        Capture a PoC evidence card for a finding.
        Shows: exploit command, HTTP request/response, analysis, badges.
        """
        vuln_type = finding.get("type", finding.get("vuln_class", "Unknown"))
        severity = finding.get("severity", "info").upper()
        cvss = finding.get("cvss_score", "N/A")
        endpoint = finding.get("endpoint", finding.get("url", ""))
        parameter = finding.get("parameter", finding.get("param", ""))
        poc = finding.get("poc", finding.get("poc_script", finding.get("payload", "")))
        evidence = finding.get("evidence", "")
        source = finding.get("source_tool", finding.get("source", "pentest-daemon"))
        mitre = finding.get("mitre_attack_id", "N/A")
        description = finding.get("description", "")
        http_request = finding.get("http_request", "")
        http_response = finding.get("http_response", "")

        # Build actual HTTP request with payload injection if we have the tested URL
        if not http_request:
            tested_url = finding.get("tested_url", finding.get("mutated_url", endpoint))
            # Extract parameter name from finding
            param_name = parameter or "test"
            if tested_url:
                parsed = urlparse(tested_url.split()[0] if 'HTTP/1.1' in tested_url else tested_url)
                http_request = f"GET {tested_url} HTTP/1.1\nHost: {parsed.netloc or target}\nUser-Agent: Mozilla/5.0\nAccept: */*"
            elif endpoint and param_name:
                # Build request showing payload injection
                injected_url = f"{endpoint}?{param_name}={poc or 'PAYLOAD'}"
                parsed = urlparse(injected_url)
                http_request = f"GET {injected_url} HTTP/1.1\nHost: {parsed.netloc or target}\nUser-Agent: Mozilla/5.0\nAccept: */*"
            else:
                http_request = f"GET / HTTP/1.1\nHost: {target}\nUser-Agent: Mozilla/5.0\nAccept: */*"

        # Build actual HTTP response with real status and body context
        if not http_response:
            status_code = finding.get("status_code", "Unknown")
            # Use response_context if available (contains context around evaluation proof)
            response_context = finding.get("response_context", "")
            if response_context:
                http_response = f"HTTP/1.1 {status_code}\nContent-Type: text/html\n\n{response_context[:2000]}"
            elif evidence:
                http_response = f"HTTP/1.1 {status_code}\nContent-Type: text/html\n\n{evidence[:2000]}"
            else:
                http_response = "No response captured"
        analysis = description or "Analysis pending"

        sev_class = severity.lower().replace(" ", "-")

        html = self._render_template(POC_CARD_HTML, {
            "SEV_CLASS": sev_class,
            "SEVERITY": severity,
            "VULN_TYPE": vuln_type,
            "CVSS": cvss,
            "MITRE": mitre,
            "SOURCE": source,
            "TARGET": target,
            "ENDPOINT": endpoint,
            "PARAMETER": parameter,
            "POC": poc or "No PoC generated",
            "HTTP_REQUEST": http_request,
            "HTTP_RESPONSE": http_response,
            "ANALYSIS": analysis,
            "TIMESTAMP": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        })

        screenshot_dir = self._get_screenshot_dir(target)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{vuln_type}_{self._hash(endpoint)}_{ts}.png"
        filepath = screenshot_dir / filename

        return await self._render_html(html, filepath)

    async def capture_nuclei(
        self,
        target: str,
        template_id: str,
        template_name: str,
        matched_at: str,
        severity: str,
        evidence: str = "",
        description: str = "",
    ) -> Optional[str]:
        """Capture a Nuclei finding evidence card."""
        sev_class = severity.lower()
        html = self._render_template(NUCLEI_CARD_HTML, {
            "SEV_CLASS": sev_class,
            "SEVERITY": severity.upper(),
            "TEMPLATE_NAME": template_name or template_id,
            "TEMPLATE_ID": template_id,
            "TARGET": target,
            "MATCHED_AT": matched_at,
            "EVIDENCE": evidence or "No evidence captured",
            "DESCRIPTION": description or "No description",
            "TIMESTAMP": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        })

        screenshot_dir = self._get_screenshot_dir(target)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"nuclei_{self._hash(template_id)}_{ts}.png"
        filepath = screenshot_dir / filename

        return await self._render_html(html, filepath)

    async def capture_http(
        self,
        target: str,
        url: str,
        method: str,
        request_headers: dict,
        request_body: str,
        response_code: int,
        response_headers: dict,
        response_body: str,
        finding_type: str = "http",
    ) -> Optional[str]:
        """Capture an HTTP request/response evidence card."""
        req_headers = "\\n".join(f"{k}: {v}" for k, v in request_headers.items())
        res_headers = "\\n".join(f"{k}: {v}" for k, v in response_headers.items())

        html = self._render_template(POC_CARD_HTML, {
            "SEV_CLASS": "info",
            "SEVERITY": "EVIDENCE",
            "VULN_TYPE": f"{finding_type} Request",
            "CVSS": "N/A",
            "MITRE": "N/A",
            "SOURCE": "http-client",
            "TARGET": target,
            "ENDPOINT": url,
            "PARAMETER": "",
            "POC": f"{method} {url}",
            "HTTP_REQUEST": f"{method} {url} HTTP/1.1\\n{req_headers}\\n\\n{request_body[:1000]}",
            "HTTP_RESPONSE": f"HTTP/1.1 {response_code}\\n{res_headers}\\n\\n{response_body[:2000]}",
            "ANALYSIS": f"Status: {response_code}\\nResponse size: {len(response_body)} bytes",
            "TIMESTAMP": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        })

        screenshot_dir = self._get_screenshot_dir(target)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{finding_type}_{self._hash(url)}_{ts}.png"
        filepath = screenshot_dir / filename

        return await self._render_html(html, filepath)

    def get_screenshots(self, target: str) -> list[dict]:
        """List all screenshots for a target."""
        screenshot_dir = self._get_screenshot_dir(target)
        if not screenshot_dir.exists():
            return []
        screenshots = []
        for f in sorted(screenshot_dir.glob("*.png")):
            meta_file = f.with_suffix(".json")
            meta = {}
            if meta_file.exists():
                try:
                    meta = json.loads(meta_file.read_text())
                except Exception:
                    pass
            screenshots.append({"file": str(f), "filename": f.name, "size": f.stat().st_size, **meta})
        return screenshots
