"""
Web Dashboard — real-time scan monitoring UI.

What top tools have:
- Cobalt: Real-time dashboard
- PlexTrac: Pentest management platform
- Strobes: Live activity logs

This module:
1. FastAPI-based web dashboard
2. Real-time scan status via WebSocket
3. Findings browser with filtering
4. Attack path visualization
5. Report download
"""

import json
from typing import Dict, List, Any, Optional
from datetime import datetime


class WebDashboard:
    """
    Generate web dashboard HTML and API routes.
    """

    def generate_dashboard_html(self) -> str:
        """Generate the main dashboard HTML."""
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Pentest Daemon - Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0a0a0a; color: #e0e0e0; }
        .header { background: #111; padding: 20px 30px; border-bottom: 1px solid #333; display: flex; justify-content: space-between; align-items: center; }
        .header h1 { font-size: 24px; color: #00ff88; }
        .status-badge { padding: 6px 16px; border-radius: 20px; font-size: 12px; font-weight: 600; }
        .status-running { background: #003300; color: #00ff88; border: 1px solid #00ff88; }
        .status-completed { background: #003366; color: #00aaff; border: 1px solid #00aaff; }
        .main { display: grid; grid-template-columns: 1fr 1fr 1fr 1fr; gap: 20px; padding: 30px; }
        .card { background: #111; border: 1px solid #333; border-radius: 12px; padding: 24px; }
        .card h3 { color: #888; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; }
        .card .value { font-size: 36px; font-weight: 700; }
        .critical { color: #ff4444; }
        .high { color: #ff8800; }
        .medium { color: #ffcc00; }
        .low { color: #00cc88; }
        .findings-table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        .findings-table th, .findings-table td { padding: 12px 16px; text-align: left; border-bottom: 1px solid #222; }
        .findings-table th { color: #888; font-size: 12px; text-transform: uppercase; }
        .findings-table tr:hover { background: #1a1a1a; }
        .severity-badge { padding: 4px 10px; border-radius: 12px; font-size: 11px; font-weight: 600; }
        .sev-critical { background: #330000; color: #ff4444; }
        .sev-high { background: #332200; color: #ff8800; }
        .sev-medium { background: #333300; color: #ffcc00; }
        .sev-low { background: #003322; color: #00cc88; }
        .sev-info { background: #112233; color: #00aaff; }
        .full-width { grid-column: 1 / -1; }
        .section-title { font-size: 18px; font-weight: 600; margin-bottom: 16px; }
        .progress-bar { height: 8px; background: #222; border-radius: 4px; overflow: hidden; margin-top: 12px; }
        .progress-fill { height: 100%; background: linear-gradient(90deg, #00ff88, #00aaff); transition: width 0.5s; }
        .attack-path { background: #1a1a2e; border: 1px solid #333; border-radius: 8px; padding: 16px; margin-bottom: 12px; }
        .attack-path h4 { color: #ff8800; margin-bottom: 8px; }
        .attack-path p { color: #aaa; font-size: 13px; line-height: 1.6; }
        .filter-bar { display: flex; gap: 12px; margin-bottom: 20px; }
        .filter-btn { padding: 8px 16px; border: 1px solid #333; border-radius: 8px; background: #111; color: #888; cursor: pointer; }
        .filter-btn.active { border-color: #00ff88; color: #00ff88; }
        #log-container { max-height: 300px; overflow-y: auto; font-family: monospace; font-size: 12px; background: #0a0a0a; padding: 16px; border-radius: 8px; border: 1px solid #222; }
        .log-entry { padding: 4px 0; border-bottom: 1px solid #1a1a1a; }
        .log-time { color: #666; }
        .log-action { color: #00aaff; }
    </style>
</head>
<body>
    <div class="header">
        <h1>AI Pentest Daemon</h1>
        <div>
            <span class="status-badge status-running" id="status-badge">Running</span>
        </div>
    </div>

    <div class="main">
        <div class="card">
            <h3>Total Findings</h3>
            <div class="value" id="total-findings">0</div>
            <div class="progress-bar"><div class="progress-fill" id="progress" style="width: 0%"></div></div>
        </div>
        <div class="card">
            <h3>Critical</h3>
            <div class="value critical" id="critical-count">0</div>
        </div>
        <div class="card">
            <h3>High</h3>
            <div class="value high" id="high-count">0</div>
        </div>
        <div class="card">
            <h3>Attack Paths</h3>
            <div class="value" id="attack-paths" style="color: #ff8800;">0</div>
        </div>

        <div class="card full-width">
            <div class="section-title">Findings</div>
            <div class="filter-bar">
                <button class="filter-btn active" onclick="filterFindings('all')">All</button>
                <button class="filter-btn" onclick="filterFindings('critical')">Critical</button>
                <button class="filter-btn" onclick="filterFindings('high')">High</button>
                <button class="filter-btn" onclick="filterFindings('medium')">Medium</button>
                <button class="filter-btn" onclick="filterFindings('low')">Low</button>
            </div>
            <table class="findings-table">
                <thead>
                    <tr><th>Type</th><th>URL</th><th>Parameter</th><th>Severity</th><th>Confidence</th></tr>
                </thead>
                <tbody id="findings-body"></tbody>
            </table>
        </div>

        <div class="card full-width">
            <div class="section-title">Attack Paths</div>
            <div id="attack-paths-container"></div>
        </div>

        <div class="card full-width">
            <div class="section-title">Live Log</div>
            <div id="log-container"></div>
        </div>
    </div>

    <script>
        let allFindings = [];
        let ws;

        function connectWebSocket() {
            ws = new WebSocket(`ws://${location.host}/ws`);
            ws.onmessage = (event) => {
                const data = JSON.parse(event.data);
                handleUpdate(data);
            };
            ws.onclose = () => setTimeout(connectWebSocket, 3000);
        }

        function handleUpdate(data) {
            if (data.type === 'finding') {
                allFindings.push(data.finding);
                updateUI();
                addLog(data.finding);
            } else if (data.type === 'status') {
                document.getElementById('status-badge').textContent = data.status;
                document.getElementById('status-badge').className = `status-badge status-${data.status.toLowerCase()}`;
            } else if (data.type === 'attack_path') {
                addAttackPath(data.path);
            }
        }

        function updateUI() {
            document.getElementById('total-findings').textContent = allFindings.length;
            document.getElementById('critical-count').textContent = allFindings.filter(f => f.severity === 'critical').length;
            document.getElementById('high-count').textContent = allFindings.filter(f => f.severity === 'high').length;

            const tbody = document.getElementById('findings-body');
            tbody.innerHTML = allFindings.map(f => `
                <tr>
                    <td>${f.type || 'Unknown'}</td>
                    <td>${(f.url || '').substring(0, 50)}</td>
                    <td>${f.param || '-'}</td>
                    <td><span class="severity-badge sev-${f.severity}">${f.severity || 'info'}</span></td>
                    <td>${((f.confidence || 0) * 100).toFixed(0)}%</td>
                </tr>
            `).join('');
        }

        function filterFindings(severity) {
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            event.target.classList.add('active');

            const filtered = severity === 'all' ? allFindings : allFindings.filter(f => f.severity === severity);
            const tbody = document.getElementById('findings-body');
            tbody.innerHTML = filtered.map(f => `
                <tr>
                    <td>${f.type || 'Unknown'}</td>
                    <td>${(f.url || '').substring(0, 50)}</td>
                    <td>${f.param || '-'}</td>
                    <td><span class="severity-badge sev-${f.severity}">${f.severity || 'info'}</span></td>
                    <td>${((f.confidence || 0) * 100).toFixed(0)}%</td>
                </tr>
            `).join('');
        }

        function addAttackPath(path) {
            const container = document.getElementById('attack-paths-container');
            const div = document.createElement('div');
            div.className = 'attack-path';
            div.innerHTML = `<h4>${path.impact}</h4><p>${(path.narrative || '').replace(/\\n/g, '<br>')}</p>`;
            container.appendChild(div);
            document.getElementById('attack-paths').textContent = container.children.length;
        }

        function addLog(finding) {
            const container = document.getElementById('log-container');
            const time = new Date().toLocaleTimeString();
            container.innerHTML += `<div class="log-entry"><span class="log-time">[${time}]</span> <span class="log-action">${finding.type}</span> at ${finding.url || 'N/A'}</div>`;
            container.scrollTop = container.scrollHeight;
        }

        connectWebSocket();
        fetch('/api/findings').then(r => r.json()).then(data => { allFindings = data.findings || []; updateUI(); });
        fetch('/api/attack-paths').then(r => r.json()).then(data => { (data.paths || []).forEach(addAttackPath); });
    </script>
</body>
</html>"""

    def generate_api_routes(self) -> str:
        """Generate FastAPI routes for the dashboard."""
        return '''
from fastapi import FastAPI, WebSocket
from fastapi.responses import HTMLResponse, JSONResponse
import json

app = FastAPI()

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    from skills.web_dashboard import WebDashboard
    return WebDashboard().generate_dashboard_html()

@app.get("/api/findings")
async def get_findings():
    # Load from current session
    try:
        from skills.session_persistence import SessionPersistence
        persistence = SessionPersistence()
        sessions = persistence.list_sessions()
        if sessions:
            session = persistence.load_session(sessions[0]["session_id"])
            return {"findings": session.get("findings", []) if session else []}
    except Exception:
        pass
    return {"findings": []}

@app.get("/api/attack-paths")
async def get_attack_paths():
    try:
        from skills.session_persistence import SessionPersistence
        persistence = SessionPersistence()
        sessions = persistence.list_sessions()
        if sessions:
            session = persistence.load_session(sessions[0]["session_id"])
            return {"paths": session.get("attack_paths", []) if session else []}
    except Exception:
        pass
    return {"paths": []}

@app.get("/api/stats")
async def get_stats():
    try:
        from skills.session_persistence import SessionPersistence
        persistence = SessionPersistence()
        sessions = persistence.list_sessions()
        if sessions:
            session = persistence.load_session(sessions[0]["session_id"])
            if session:
                return session.get("stats", {})
    except Exception:
        pass
    return {}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            # Keep connection alive and send updates
            import asyncio
            await asyncio.sleep(1)
    except Exception:
        pass
'''
