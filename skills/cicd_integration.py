"""
CI/CD Integration — GitHub Actions, GitLab CI hooks.

What top tools have:
- Strix: CI/CD + reporting + continuous validation
- Strobes: Auto-ticketing + SLA tracking
- Escape: CI/CD pipeline integration

This module:
1. Generates GitHub Actions workflow files
2. Generates GitLab CI pipeline files
3. Gates deployments based on findings
4. Auto-creates Jira/GitHub issues for findings
"""

import json
from typing import Dict, List, Any, Optional


class CICDIntegration:
    """
    CI/CD integration for automated security gating.
    """

    def generate_github_actions(self, target: str, fail_on: str = "high") -> str:
        """Generate GitHub Actions workflow for security scanning."""
        return f"""name: AI Pentest Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 2 * * 1'  # Weekly Monday 2am

jobs:
  pentest:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install dependencies
        run: pip install -r requirements.txt

      - name: Run AI Pentest
        run: |
          python cli.py {target} full hackerone --engine agent --mock
        env:
          GLM_API_KEY: ${{{{ secrets.GLM_API_KEY }}}}
          FEATHERLESS_API_KEY: ${{{{ secrets.FEATHERLESS_API_KEY }}}}

      - name: Check findings severity
        run: |
          python -c "
          import json, sys
          results = json.load(open('results/latest.json'))
          critical = sum(1 for f in results.get('findings', []) if f.get('severity') == 'critical')
          high = sum(1 for f in results.get('findings', []) if f.get('severity') == 'high')
          fail_level = '{fail_on}'
          if fail_level == 'critical' and critical > 0:
              print(f'FAIL: {{critical}} critical findings')
              sys.exit(1)
          elif fail_level == 'high' and (critical + high) > 0:
              print(f'FAIL: {{critical}} critical, {{high}} high findings')
              sys.exit(1)
          print('PASS: No blocking findings')
          "

      - name: Upload results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: pentest-results
          path: results/
"""

    def generate_gitlab_ci(self, target: str, fail_on: str = "high") -> str:
        """Generate GitLab CI pipeline for security scanning."""
        return f"""stages:
  - security

pentest-scan:
  stage: security
  image: python:3.12
  script:
    - pip install -r requirements.txt
    - python cli.py {target} full hackerone --engine agent --mock
    - |
      python -c "
      import json, sys
      results = json.load(open('results/latest.json'))
      critical = sum(1 for f in results.get('findings', []) if f.get('severity') == 'critical')
      high = sum(1 for f in results.get('findings', []) if f.get('severity') == 'high')
      if '{fail_on}' == 'critical' and critical > 0:
          sys.exit(1)
      elif '{fail_on}' == 'high' and (critical + high) > 0:
          sys.exit(1)
      "
  artifacts:
    paths:
      - results/
    when: always
  rules:
    - if: $CI_PIPELINE_SOURCE == "push"
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_PIPELINE_SOURCE == "schedule"
"""

    def generate_jira_issue(self, finding: Dict) -> Dict:
        """Generate Jira issue payload for a finding."""
        severity_to_priority = {
            "critical": "Highest",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "info": "Lowest",
        }

        return {
            "fields": {
                "project": {"key": "SEC"},
                "summary": f"[SECURITY] {finding.get('type', 'Unknown')} at {finding.get('url', 'N/A')}",
                "description": (
                    f"*Security Finding*\n\n"
                    f"*Type:* {finding.get('type', 'Unknown')}\n"
                    f"*Severity:* {finding.get('severity', 'Unknown')}\n"
                    f"*URL:* {finding.get('url', 'N/A')}\n"
                    f"*Parameter:* {finding.get('param', 'N/A')}\n\n"
                    f"*Description:*\n{finding.get('description', 'N/A')}\n\n"
                    f"*Evidence:*\n{{code}}\n{finding.get('evidence', 'N/A')[:500]}\n{{code}}\n\n"
                    f"*Payload:*\n{{code}}\n{finding.get('payload', 'N/A')}\n{{code}}\n\n"
                    f"*Remediation:*\n{finding.get('remediation', 'Review and fix the vulnerability')}"
                ),
                "issuetype": {"name": "Bug"},
                "priority": {"name": severity_to_priority.get(finding.get("severity", "medium"), "Medium")},
                "labels": ["security", finding.get("type", "unknown"), "auto-detected"],
            }
        }

    def generate_github_issue(self, finding: Dict) -> Dict:
        """Generate GitHub issue payload."""
        severity_emoji = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
            "info": "⚪",
        }

        emoji = severity_emoji.get(finding.get("severity", ""), "⚪")

        return {
            "title": f"{emoji} Security: {finding.get('type', 'Unknown')} at {finding.get('url', 'N/A')}",
            "body": (
                f"## Security Finding\n\n"
                f"| Field | Value |\n|---|---|\n"
                f"| **Type** | {finding.get('type', 'Unknown')} |\n"
                f"| **Severity** | {finding.get('severity', 'Unknown')} |\n"
                f"| **URL** | {finding.get('url', 'N/A')} |\n"
                f"| **Parameter** | {finding.get('param', 'N/A')} |\n\n"
                f"### Description\n{finding.get('description', 'N/A')}\n\n"
                f"### Evidence\n```\n{finding.get('evidence', 'N/A')[:500]}\n```\n\n"
                f"### Payload\n```\n{finding.get('payload', 'N/A')}\n```\n\n"
                f"### Remediation\n{finding.get('remediation', 'Review and fix the vulnerability')}\n\n"
                f"---\n*Auto-generated by AI Pentest Daemon*"
            ),
            "labels": ["security", "auto-detected", finding.get("severity", "unknown")],
        }

    def gate_deployment(self, findings: List[Dict], gate_config: Dict = None) -> Dict:
        """Decide if deployment should proceed based on findings."""
        if gate_config is None:
            gate_config = {
                "block_on_critical": True,
                "block_on_high": False,
                "max_high": 5,
                "max_medium": 20,
            }

        critical = sum(1 for f in findings if f.get("severity") == "critical")
        high = sum(1 for f in findings if f.get("severity") == "high")
        medium = sum(1 for f in findings if f.get("severity") == "medium")

        should_block = False
        reasons = []

        if gate_config.get("block_on_critical") and critical > 0:
            should_block = True
            reasons.append(f"{critical} critical findings")

        if gate_config.get("block_on_high") and high > 0:
            should_block = True
            reasons.append(f"{high} high findings")
        elif high > gate_config.get("max_high", 5):
            should_block = True
            reasons.append(f"{high} high findings (max: {gate_config.get('max_high', 5)})")

        if medium > gate_config.get("max_medium", 20):
            should_block = True
            reasons.append(f"{medium} medium findings (max: {gate_config.get('max_medium', 20)})")

        return {
            "should_deploy": not should_block,
            "block_reasons": reasons,
            "stats": {
                "critical": critical,
                "high": high,
                "medium": medium,
                "total": len(findings),
            },
        }
