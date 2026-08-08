#!/usr/bin/env python3
"""
VeriFireWall - Real-Time AI Security & Anomaly Analytics Dashboard
------------------------------------------------------------------
Parses live security event JSON logs from the VeriFireWall C++ engine
and provides a web dashboard at http://localhost:3002 displaying:
- Total Attacks Detected & Blocked vs Allowed Counters
- Incident Type Breakdown (SQLi, XSS, CmdInjection, Path Traversal, RCE)
- Anomaly Confidence & Threat Level Gauges
- Live Real-time Attack Event Stream Table
"""

import json
import subprocess
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

# Global state for security analytics
stats = {
    "total_requests": 0,
    "total_blocked": 0,
    "total_allowed": 0,
    "attack_types": {
        "Legitimate Traffic": 0,
        "SQL Injection": 0,
        "Cross Site Scripting": 0,
        "Command Injection": 0,
        "Path Traversal": 0,
        "Remote Code Execution": 0,
        "Reconnaissance / Probing": 0,
        "General Anomaly": 0
    },
    "recent_events": []
}

# Global state for security analytics
stats = {
    "total_requests": 0,
    "total_blocked": 0,
    "total_allowed": 0,
    "attack_types": {
        "Legitimate Traffic": 0,
        "SQL Injection": 0,
        "Cross Site Scripting": 0,
        "Command Injection": 0,
        "Path Traversal": 0,
        "Remote Code Execution": 0,
        "Reconnaissance / Probing": 0,
        "General Anomaly": 0
    },
    "recent_events": []
}

lock = threading.Lock()

def parse_nginx_log_line(line):
    line = line.strip()
    if not line or '"' not in line:
        return
    try:
        parts = line.split('"')
        if len(parts) < 3:
            return
        
        request_part = parts[1]
        status_part = parts[2].strip().split()
        
        if not status_part:
            return
        
        status_code = int(status_part[0])
        req_bits = request_part.split()
        if len(req_bits) < 2:
            return
        
        method = req_bits[0]
        uri = req_bits[1]
        
        # Ignore noisy background polling & internal exporter endpoints
        if "/socket.io/" in uri or "/nginx_status" in uri or "/api/data" in uri or "/assets/" in uri:
            return
        
        ip = line.split()[0] if line.split() else "127.0.0.1"
        timestamp = time.strftime("%H:%M:%S")

        if 200 <= status_code < 400:
            with lock:
                stats["total_allowed"] += 1
                stats["total_requests"] = stats["total_allowed"] + stats["total_blocked"]
                stats["attack_types"]["Legitimate Traffic"] += 1

                event_entry = {
                    "id": len(stats["recent_events"]) + 1,
                    "timestamp": timestamp,
                    "ip": ip,
                    "method": method,
                    "uri": uri,
                    "action": "ALLOWED",
                    "attack_type": "Legitimate Traffic",
                    "anomaly_score": 0,
                    "threat_level": "Clean",
                    "matched_sample": "Passed WAF Inspection (Clean Request)"
                }
                stats["recent_events"].insert(0, event_entry)
                if len(stats["recent_events"]) > 100:
                    stats["recent_events"].pop()

        elif status_code == 403:
            uri_lower = uri.lower()
            attack_cat = "General Anomaly"
            sample = "WAF Rule Violation"
            
            if "union" in uri_lower or "select" in uri_lower or "sql" in uri_lower:
                attack_cat = "SQL Injection"
                sample = "SQL Injection Keyword Pattern"
            elif "script" in uri_lower or "alert" in uri_lower or "xss" in uri_lower:
                attack_cat = "Cross Site Scripting"
                sample = "<script> XSS Payload Pattern"
            elif "ping" in uri_lower or "exec" in uri_lower or ";" in uri_lower or "|" in uri_lower:
                attack_cat = "Command Injection"
                sample = "System Command Execution Pattern"
            elif ".." in uri_lower or "etc/passwd" in uri_lower or "download" in uri_lower:
                attack_cat = "Path Traversal"
                sample = "Directory Traversal Pattern"
            elif "cgi-bin" in uri_lower or "shellshock" in uri_lower:
                attack_cat = "Remote Code Execution"
                sample = "RCE Payload Pattern"

            with lock:
                stats["total_blocked"] += 1
                stats["total_requests"] = stats["total_allowed"] + stats["total_blocked"]
                if attack_cat in stats["attack_types"]:
                    stats["attack_types"][attack_cat] += 1
                else:
                    stats["attack_types"][attack_cat] = 1

                event_entry = {
                    "id": len(stats["recent_events"]) + 1,
                    "timestamp": timestamp,
                    "ip": ip,
                    "method": method,
                    "uri": uri,
                    "action": "BLOCKED",
                    "attack_type": attack_cat,
                    "anomaly_score": 850,
                    "threat_level": "High",
                    "matched_sample": sample
                }
                stats["recent_events"].insert(0, event_entry)
                if len(stats["recent_events"]) > 100:
                    stats["recent_events"].pop()

    except Exception:
        pass

def parse_security_log_line(line):
    line = line.strip()
    if not line or not line.startswith('{'):
        return
    try:
        data = json.loads(line)
        if data.get("eventName") != "Web Request":
            return
        
        event_data = data.get("eventData", {})
        action = event_data.get("securityAction", "Detect")
        incident_type = event_data.get("waapIncidentType", "General")
        indicators = event_data.get("matchedIndicators", "[]")
        uri = event_data.get("httpUriPath", "/")
        query = event_data.get("httpUriQuery", "")
        method = event_data.get("httpMethod", "GET")
        sample = event_data.get("matchedSample", "")
        score = event_data.get("waapFinalScore", 0)
        threat_level = event_data.get("waapCalculatedThreatLevel", 0)
        source_ip = event_data.get("sourceIP", "127.0.0.1")
        timestamp = time.strftime("%H:%M:%S")

        if "/socket.io/" in uri or "/nginx_status" in uri or "/assets/" in uri:
            return

        mapped_type = "General Anomaly"
        inc_lower = incident_type.lower()
        ind_lower = str(indicators).lower()
        sample_lower = str(sample).lower()
        
        if "sql" in inc_lower or "sqli" in ind_lower or "union" in sample_lower or "select" in sample_lower:
            mapped_type = "SQL Injection"
        elif "script" in inc_lower or "xss" in ind_lower or "script" in sample_lower or "alert" in sample_lower:
            mapped_type = "Cross Site Scripting"
        elif "command" in inc_lower or "cmd" in ind_lower or "ping" in uri or "exec" in sample_lower:
            mapped_type = "Command Injection"
        elif "traversal" in inc_lower or "path" in inc_lower or "file" in inc_lower or ".." in uri or "etc/passwd" in sample_lower:
            mapped_type = "Path Traversal"
        elif "rce" in inc_lower or "shellshock" in sample_lower or "cgi-bin" in uri:
            mapped_type = "Remote Code Execution"
        elif "probing" in ind_lower or "scan" in inc_lower:
            mapped_type = "Reconnaissance / Probing"

        if action == "Prevent" and mapped_type != "General Anomaly":
            with lock:
                stats["total_blocked"] += 1
                stats["total_requests"] = stats["total_allowed"] + stats["total_blocked"]
                if mapped_type in stats["attack_types"]:
                    stats["attack_types"][mapped_type] += 1

                event_entry = {
                    "id": len(stats["recent_events"]) + 1,
                    "timestamp": timestamp,
                    "ip": source_ip,
                    "method": method,
                    "uri": uri + ("?" + query if query else ""),
                    "action": "BLOCKED",
                    "attack_type": mapped_type,
                    "anomaly_score": score,
                    "threat_level": "High" if threat_level >= 3 else "Medium",
                    "matched_sample": sample or "WAF Engine Rule Match"
                }
                stats["recent_events"].insert(0, event_entry)
                if len(stats["recent_events"]) > 100:
                    stats["recent_events"].pop()

    except Exception:
        pass

def agent_log_streamer():
    while True:
        try:
            process = subprocess.Popen(
                ["docker", "logs", "-f", "--tail", "500", "appsec-agent"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            for line in process.stdout:
                parse_security_log_line(line)
        except Exception:
            time.sleep(2)

def nginx_log_streamer():
    while True:
        try:
            process = subprocess.Popen(
                ["docker", "logs", "-f", "--tail", "500", "appsec-nginx"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            for line in process.stdout:
                parse_nginx_log_line(line)
        except Exception:
            time.sleep(2)

def log_streamer_thread():
    t1 = threading.Thread(target=agent_log_streamer, daemon=True)
    t2 = threading.Thread(target=nginx_log_streamer, daemon=True)
    t1.start()
    t2.start()




HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VeriFireWall — Real-Time AI Security Analytics</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {
            --bg-dark: #0b0f19;
            --card-bg: rgba(23, 31, 51, 0.7);
            --border-color: rgba(255, 255, 255, 0.08);
            --accent-red: #ff4757;
            --accent-green: #2ed573;
            --accent-blue: #1e90ff;
            --accent-amber: #ffa502;
            --accent-purple: #9b59b6;
            --text-main: #f1f2f6;
            --text-muted: #a4b0be;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Outfit', sans-serif;
            background: var(--bg-dark);
            color: var(--text-main);
            padding: 24px;
            min-height: 100vh;
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 24px;
            padding-bottom: 16px;
            border-bottom: 1px solid var(--border-color);
        }
        .logo-title {
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .logo-title h1 {
            font-size: 24px;
            font-weight: 700;
            background: linear-gradient(135deg, #ff4757, #ffa502);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .badge-live {
            background: rgba(46, 213, 115, 0.15);
            color: var(--accent-green);
            border: 1px solid var(--accent-green);
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 13px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 6px;
        }
        .badge-live::before {
            content: '';
            width: 8px;
            height: 8px;
            background: var(--accent-green);
            border-radius: 50%;
            display: inline-block;
            box-shadow: 0 0 10px var(--accent-green);
            animation: pulse 1.5s infinite;
        }
        @keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.3; } 100% { opacity: 1; } }

        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 24px;
        }
        .card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 20px;
            backdrop-filter: blur(10px);
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.3);
        }
        .card-label {
            font-size: 14px;
            color: var(--text-muted);
            margin-bottom: 8px;
            font-weight: 500;
        }
        .card-value {
            font-size: 32px;
            font-weight: 700;
            font-family: 'JetBrains Mono', monospace;
        }
        .card-value.red { color: var(--accent-red); }
        .card-value.green { color: var(--accent-green); }
        .card-value.blue { color: var(--accent-blue); }
        .card-value.amber { color: var(--accent-amber); }

        .charts-row {
            display: grid;
            grid-template-columns: 1fr 2fr;
            gap: 16px;
            margin-bottom: 24px;
        }
        .chart-container {
            position: relative;
            height: 260px;
            width: 100%;
        }

        .table-section {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 20px;
        }
        .table-section h2 {
            font-size: 18px;
            margin-bottom: 16px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 14px;
        }
        th, td {
            padding: 12px 16px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }
        th {
            color: var(--text-muted);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 12px;
            letter-spacing: 0.5px;
        }
        tr:hover { background: rgba(255, 255, 255, 0.02); }
        .status-pill {
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 700;
            display: inline-block;
        }
        .status-pill.blocked {
            background: rgba(255, 71, 87, 0.2);
            color: var(--accent-red);
            border: 1px solid var(--accent-red);
        }
        .status-pill.allowed {
            background: rgba(46, 213, 115, 0.2);
            color: var(--accent-green);
            border: 1px solid var(--accent-green);
        }
        .attack-tag {
            background: rgba(30, 144, 255, 0.15);
            color: #70a1ff;
            padding: 2px 8px;
            border-radius: 4px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
        }
        .mono { font-family: 'JetBrains Mono', monospace; font-size: 13px; }
    </style>
</head>
<body>
    <div class="header">
        <div class="logo-title">
            <h1>🛡️ VeriFireWall AI Attack & Anomaly Telemetry</h1>
        </div>
        <div class="badge-live">LIVE MONITORING</div>
    </div>

    <div class="metrics-grid">
        <div class="card">
            <div class="card-label">Total Requests Analyzed</div>
            <div class="card-value blue" id="total-reqs">0</div>
        </div>
        <div class="card">
            <div class="card-label">Attacks Blocked (Prevent)</div>
            <div class="card-value red" id="total-blocked">0</div>
        </div>
        <div class="card">
            <div class="card-label">Legitimate Traffic (Allowed)</div>
            <div class="card-value green" id="total-allowed">0</div>
        </div>
        <div class="card">
            <div class="card-label">Engine Defense Mode</div>
            <div class="card-value amber">PREVENT</div>
        </div>
    </div>

    <div class="charts-row">
        <div class="card">
            <div class="card-label" style="margin-bottom:16px;">Attack Types Breakdown</div>
            <div class="chart-container">
                <canvas id="attackPieChart"></canvas>
            </div>
        </div>
        <div class="card">
            <div class="card-label" style="margin-bottom:16px;">Security Decision Ratio</div>
            <div class="chart-container">
                <canvas id="decisionBarChart"></canvas>
            </div>
        </div>
    </div>

    <div class="table-section">
        <h2>
            <span>🚨 Live Security Incidents & Threat Telemetry</span>
            <span style="font-size:13px; color:var(--text-muted); font-weight:normal;" id="event-count">0 events</span>
        </h2>
        <table>
            <thead>
                <tr>
                    <th>Time</th>
                    <th>Source IP</th>
                    <th>Method & URI</th>
                    <th>Attack Vector</th>
                    <th>Action</th>
                    <th>ML Anomaly Score</th>
                    <th>Matched Pattern / Sample</th>
                </tr>
            </thead>
            <tbody id="events-tbody">
                <tr><td colspan="7" style="text-align:center; color:var(--text-muted);">Waiting for security events...</td></tr>
            </tbody>
        </table>
    </div>

    <script>
        // Disable browser alert popups completely
        window.alert = function() {};

        function escapeHtml(str) {
            if (!str) return '';
            return String(str)
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#039;");
        }

        let pieChart, barChart;

        function initCharts() {
            const ctxPie = document.getElementById('attackPieChart').getContext('2d');
            pieChart = new Chart(ctxPie, {
                type: 'doughnut',
                data: {
                    labels: ['SQLi', 'XSS', 'CmdInj', 'PathTrav', 'RCE', 'Probing'],
                    datasets: [{
                        data: [0, 0, 0, 0, 0, 0],
                        backgroundColor: ['#ff4757', '#ffa502', '#1e90ff', '#9b59b6', '#ff6b81', '#70a1ff'],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { position: 'right', labels: { color: '#a4b0be' } } }
                }
            });

            const ctxBar = document.getElementById('decisionBarChart').getContext('2d');
            barChart = new Chart(ctxBar, {
                type: 'bar',
                data: {
                    labels: ['Blocked (Enforced)', 'Allowed (Benign)'],
                    datasets: [{
                        label: 'Requests',
                        data: [0, 0],
                        backgroundColor: ['#ff4757', '#2ed573'],
                        borderRadius: 6
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        x: { ticks: { color: '#a4b0be' }, grid: { display: false } },
                        y: { ticks: { color: '#a4b0be' }, grid: { color: 'rgba(255,255,255,0.05)' } }
                    }
                }
            });
        }

        async function fetchMetrics() {
            try {
                const res = await fetch('/api/data');
                const data = await res.json();

                document.getElementById('total-reqs').innerText = data.total_requests;
                document.getElementById('total-blocked').innerText = data.total_blocked;
                document.getElementById('total-allowed').innerText = data.total_allowed;
                document.getElementById('event-count').innerText = `${data.recent_events.length} recent incidents`;

                // Update Pie Chart
                const attackTypes = data.attack_types;
                pieChart.data.labels = Object.keys(attackTypes);
                pieChart.data.datasets[0].data = Object.values(attackTypes);
                pieChart.update();

                // Update Bar Chart
                barChart.data.datasets[0].data = [data.total_blocked, data.total_allowed];
                barChart.update();

                // Update Table safely with HTML escaping
                const tbody = document.getElementById('events-tbody');
                if (data.recent_events.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; color:var(--text-muted);">Waiting for security events...</td></tr>';
                    return;
                }

                tbody.innerHTML = data.recent_events.map(ev => `
                    <tr>
                        <td class="mono">${escapeHtml(ev.timestamp.split('T')[1] || ev.timestamp)}</td>
                        <td class="mono">${escapeHtml(ev.ip)}</td>
                        <td class="mono" style="max-width:240px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">
                            <strong>${escapeHtml(ev.method)}</strong> ${escapeHtml(ev.uri)}
                        </td>
                        <td><span class="attack-tag">${escapeHtml(ev.attack_type)}</span></td>
                        <td><span class="status-pill ${escapeHtml(ev.action.toLowerCase())}">${escapeHtml(ev.action)}</span></td>
                        <td class="mono">${escapeHtml(ev.anomaly_score)}</td>
                        <td class="mono" style="max-width:220px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; color:var(--accent-amber);" title="${escapeHtml(ev.matched_sample)}">
                            ${escapeHtml(ev.matched_sample)}
                        </td>
                    </tr>
                `).join('');

            } catch (err) {
                console.error("Fetch error:", err);
            }
        }

        window.onload = () => {
            initCharts();
            fetchMetrics();
            setInterval(fetchMetrics, 2000);
        };
    </script>
</body>
</html>
"""

class DashboardRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == '/api/data':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            with lock:
                self.wfile.write(json.dumps(stats).encode('utf-8'))
        else:
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(HTML_PAGE.encode('utf-8'))

def run_server():
    t = threading.Thread(target=log_streamer_thread, daemon=True)
    t.start()
    
    server_address = ('', 3002)
    httpd = HTTPServer(server_address, DashboardRequestHandler)
    print("=========================================================")
    print("🛡️ VeriFireWall Security Analytics Server Started on port 3002")
    print("📊 Open Dashboard at: http://localhost:3002")
    print("=========================================================")
    httpd.serve_forever()

if __name__ == '__main__':
    run_server()
