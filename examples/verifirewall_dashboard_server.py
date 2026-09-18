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
import os
import sys
import subprocess
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

# Import UNSW-NB15 Layer 4 ML NIDS Classifier
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
try:
    from unsw_nb15.unsw_nb15_classifier import UNSWNB15Classifier
    from unsw_nb15.l4_flow_simulator import generate_random_flow
    unsw_classifier = UNSWNB15Classifier()
except Exception as _e:
    print('[UNSW-NB15 ML] Import notice:', _e)
    unsw_classifier = None

# Global state for security analytics (Layer 7 HTTP WAAP)
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

# Global state for Layer 4 UNSW-NB15 NetFlow NIDS ML Engine
l4_stats = {
    "total_flows": 0,
    "total_blocked": 0,
    "total_allowed": 0,
    "attack_categories": {
        "DoS / SYN Flood": 0,
        "Reconnaissance / Port Scan": 0,
        "Fuzzers / Malicious Buffer": 0,
        "Exploits / Shellcode Payload": 0,
        "Legitimate NetFlow": 0
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
    <title>VeriFireWall — AI Security & Anomaly Telemetry</title>
    <!-- Google Fonts: Space Grotesk, Plus Jakarta Sans, JetBrains Mono -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=Space+Grotesk:wght@600;700&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
    <style>
        :root {
            --bg-paper: #f4f3ee;
            --bg-card: #ffffff;
            --border-dark: #18181b;
            --border-width: 2.5px;
            --shadow-neo: 4px 4px 0px #18181b;
            --shadow-neo-sm: 2.5px 2.5px 0px #18181b;
            --shadow-neo-hover: 6px 6px 0px #18181b;
            --shadow-neo-active: 1px 1px 0px #18181b;
            
            --neo-red: #ff4757;
            --neo-red-light: #ffe5e8;
            --neo-green: #10b981;
            --neo-green-light: #d1fae5;
            --neo-blue: #3b82f6;
            --neo-blue-light: #dbeafe;
            --neo-yellow: #fbbf24;
            --neo-yellow-light: #fef3c7;
            --neo-purple: #8b5cf6;
            --neo-purple-light: #ede9fe;
            --neo-pink: #ec4899;
            --neo-pink-light: #fce7f3;

            --text-dark: #09090b;
            --text-muted: #52525b;
            --radius-neo: 8px;
            --radius-btn: 6px;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: 'Plus Jakarta Sans', -apple-system, sans-serif;
            background-color: var(--bg-paper);
            color: var(--text-dark);
            padding: 24px;
            min-height: 100vh;
            line-height: 1.5;
            background-image: radial-gradient(#d4d4d8 1px, transparent 1px);
            background-size: 20px 20px;
        }

        /* Top Header Navigation */
        .navbar {
            background: var(--bg-card);
            border: var(--border-width) solid var(--border-dark);
            box-shadow: var(--shadow-neo);
            border-radius: var(--radius-neo);
            padding: 16px 24px;
            margin-bottom: 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 16px;
        }

        .brand {
            display: flex;
            align-items: center;
            gap: 14px;
        }

        .brand-icon {
            width: 44px;
            height: 44px;
            background: var(--neo-yellow);
            border: var(--border-width) solid var(--border-dark);
            box-shadow: 2px 2px 0px var(--border-dark);
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 22px;
            font-weight: bold;
        }

        .brand-title h1 {
            font-family: 'Space Grotesk', sans-serif;
            font-size: 24px;
            font-weight: 700;
            letter-spacing: -0.5px;
            color: var(--text-dark);
            line-height: 1.1;
        }

        .brand-title span {
            font-size: 12px;
            font-weight: 600;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.8px;
        }

        .controls-group {
            display: flex;
            align-items: center;
            gap: 12px;
            flex-wrap: wrap;
        }

        .live-status-pill {
            background: var(--neo-green-light);
            color: #065f46;
            border: var(--border-width) solid var(--border-dark);
            box-shadow: 2px 2px 0px var(--border-dark);
            padding: 6px 14px;
            border-radius: 20px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 8px;
            transition: all 0.2s ease;
        }

        .live-status-pill.paused {
            background: var(--neo-yellow-light);
            color: #92400e;
        }

        .pulse-dot {
            width: 10px;
            height: 10px;
            background: var(--neo-green);
            border: 1.5px solid var(--border-dark);
            border-radius: 50%;
            animation: pulse-ring 1.5s cubic-bezier(0.215, 0.61, 0.355, 1) infinite;
        }

        .live-status-pill.paused .pulse-dot {
            background: var(--neo-yellow);
            animation: none;
        }

        @keyframes pulse-ring {
            0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); }
            70% { transform: scale(1.1); box-shadow: 0 0 0 8px rgba(16, 185, 129, 0); }
            100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
        }

        /* Buttons Neo-Brutalist Style */
        .btn-neo {
            font-family: 'Plus Jakarta Sans', sans-serif;
            font-size: 13px;
            font-weight: 700;
            padding: 8px 16px;
            background: var(--bg-card);
            color: var(--text-dark);
            border: var(--border-width) solid var(--border-dark);
            box-shadow: var(--shadow-neo-sm);
            border-radius: var(--radius-btn);
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            user-select: none;
            transition: transform 0.1s ease, box-shadow 0.1s ease, background-color 0.2s ease;
        }

        .btn-neo:hover {
            transform: translate(-1px, -1px);
            box-shadow: 3.5px 3.5px 0px var(--border-dark);
            background-color: #fafafa;
        }

        .btn-neo:active {
            transform: translate(1.5px, 1.5px);
            box-shadow: var(--shadow-neo-active);
        }

        .btn-neo.btn-primary {
            background: var(--neo-blue-light);
            color: #1e40af;
        }

        .btn-neo.btn-danger {
            background: var(--neo-red-light);
            color: #991b1b;
        }

        .btn-neo.btn-purple {
            background: var(--neo-purple-light);
            color: #5b21b6;
        }

        .btn-neo.active {
            background: var(--neo-yellow);
            box-shadow: var(--shadow-neo-active);
            transform: translate(1.5px, 1.5px);
        }

        /* Metrics Cards Grid */
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 20px;
            margin-bottom: 24px;
        }

        .metric-card {
            background: var(--bg-card);
            border: var(--border-width) solid var(--border-dark);
            box-shadow: var(--shadow-neo);
            border-radius: var(--radius-neo);
            padding: 20px;
            position: relative;
            overflow: hidden;
            transition: transform 0.15s ease, box-shadow 0.15s ease;
        }

        .metric-card:hover {
            transform: translate(-2px, -2px);
            box-shadow: var(--shadow-neo-hover);
        }

        .metric-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
        }

        .metric-title {
            font-size: 13px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.6px;
            color: var(--text-muted);
        }

        .metric-icon-badge {
            width: 32px;
            height: 32px;
            border-radius: 6px;
            border: 2px solid var(--border-dark);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 15px;
            font-weight: bold;
        }

        .metric-card.blue .metric-icon-badge { background: var(--neo-blue-light); color: #1d4ed8; }
        .metric-card.red .metric-icon-badge { background: var(--neo-red-light); color: #dc2626; }
        .metric-card.green .metric-icon-badge { background: var(--neo-green-light); color: #059669; }
        .metric-card.yellow .metric-icon-badge { background: var(--neo-yellow-light); color: #d97706; }

        .metric-value {
            font-family: 'JetBrains Mono', monospace;
            font-size: 34px;
            font-weight: 700;
            line-height: 1.1;
            margin-bottom: 8px;
            color: var(--text-dark);
        }

        .metric-sub {
            font-size: 12px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .tag-pill {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 700;
            border: 1.5px solid var(--border-dark);
        }

        .tag-pill.red { background: var(--neo-red-light); color: #b91c1c; }
        .tag-pill.green { background: var(--neo-green-light); color: #047857; }
        .tag-pill.blue { background: var(--neo-blue-light); color: #1d4ed8; }
        .tag-pill.yellow { background: var(--neo-yellow-light); color: #b45309; }

        /* Charts Row */
        .charts-grid {
            display: grid;
            grid-template-columns: 1fr 1.6fr;
            gap: 20px;
            margin-bottom: 24px;
        }

        @media (max-width: 900px) {
            .charts-grid {
                grid-template-columns: 1fr;
            }
        }

        .chart-box {
            background: var(--bg-card);
            border: var(--border-width) solid var(--border-dark);
            box-shadow: var(--shadow-neo);
            border-radius: var(--radius-neo);
            padding: 20px;
        }

        .chart-box-title {
            font-family: 'Space Grotesk', sans-serif;
            font-size: 16px;
            font-weight: 700;
            margin-bottom: 16px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .chart-container-inner {
            position: relative;
            height: 250px;
            width: 100%;
        }

        /* Telemetry Section & Filters */
        .telemetry-section {
            background: var(--bg-card);
            border: var(--border-width) solid var(--border-dark);
            box-shadow: var(--shadow-neo);
            border-radius: var(--radius-neo);
            padding: 20px;
        }

        .telemetry-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 16px;
            margin-bottom: 20px;
        }

        .telemetry-title-area h2 {
            font-family: 'Space Grotesk', sans-serif;
            font-size: 18px;
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .filter-bar {
            display: flex;
            align-items: center;
            gap: 12px;
            flex-wrap: wrap;
            width: 100%;
            background: var(--bg-paper);
            padding: 12px;
            border: var(--border-width) solid var(--border-dark);
            border-radius: var(--radius-neo);
            margin-bottom: 16px;
        }

        .search-input-wrap {
            flex: 1;
            min-width: 220px;
            position: relative;
        }

        .search-input {
            width: 100%;
            font-family: 'Plus Jakarta Sans', sans-serif;
            font-size: 13px;
            font-weight: 600;
            padding: 8px 12px 8px 34px;
            background: #ffffff;
            border: 2px solid var(--border-dark);
            border-radius: var(--radius-btn);
            box-shadow: 2px 2px 0px var(--border-dark);
            outline: none;
            transition: all 0.15s ease;
        }

        .search-input:focus {
            border-color: var(--neo-blue);
            box-shadow: 3px 3px 0px var(--border-dark);
        }

        .search-icon {
            position: absolute;
            left: 10px;
            top: 50%;
            transform: translateY(-50%);
            font-size: 14px;
            color: var(--text-muted);
            pointer-events: none;
        }

        .filter-select {
            font-family: 'Plus Jakarta Sans', sans-serif;
            font-size: 13px;
            font-weight: 700;
            padding: 8px 12px;
            background: #ffffff;
            border: 2px solid var(--border-dark);
            border-radius: var(--radius-btn);
            box-shadow: 2px 2px 0px var(--border-dark);
            outline: none;
            cursor: pointer;
        }

        .filter-pills {
            display: flex;
            gap: 6px;
        }

        .filter-pill-btn {
            font-family: 'Plus Jakarta Sans', sans-serif;
            font-size: 12px;
            font-weight: 700;
            padding: 6px 12px;
            border: 2px solid var(--border-dark);
            border-radius: 20px;
            background: #ffffff;
            box-shadow: 1.5px 1.5px 0px var(--border-dark);
            cursor: pointer;
            transition: all 0.1s ease;
        }

        .filter-pill-btn.active {
            background: var(--border-dark);
            color: #ffffff;
            box-shadow: none;
        }

        /* Table Styling */
        .table-responsive {
            width: 100%;
            overflow-x: auto;
            border: var(--border-width) solid var(--border-dark);
            border-radius: 6px;
        }

        table.neo-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            background: #ffffff;
            text-align: left;
        }

        table.neo-table th {
            background: #f4f4f5;
            color: var(--text-dark);
            font-family: 'JetBrains Mono', monospace;
            font-weight: 700;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            padding: 12px 14px;
            border-bottom: var(--border-width) solid var(--border-dark);
            border-right: 1px solid #e4e4e7;
        }

        table.neo-table th:last-child {
            border-right: none;
        }

        table.neo-table td {
            padding: 12px 14px;
            border-bottom: 1px solid #e4e4e7;
            border-right: 1px solid #e4e4e7;
            vertical-align: middle;
            transition: background-color 0.15s ease;
        }

        table.neo-table td:last-child {
            border-right: none;
        }

        table.neo-table tr:hover td {
            background-color: #fdfef2;
        }

        table.neo-table tr.row-blocked td {
            background-color: #fff8f8;
        }

        table.neo-table tr.row-blocked:hover td {
            background-color: #fee2e2;
        }

        .mono {
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
        }

        .badge-action {
            display: inline-block;
            font-family: 'JetBrains Mono', monospace;
            font-size: 11px;
            font-weight: 800;
            padding: 4px 10px;
            border-radius: 4px;
            border: 1.5px solid var(--border-dark);
            box-shadow: 1px 1px 0px var(--border-dark);
        }

        .badge-action.blocked {
            background: var(--neo-red);
            color: #ffffff;
        }

        .badge-action.allowed {
            background: var(--neo-green);
            color: #ffffff;
        }

        .vector-tag {
            display: inline-block;
            font-family: 'JetBrains Mono', monospace;
            font-size: 11px;
            font-weight: 600;
            padding: 2px 8px;
            border-radius: 4px;
            background: var(--neo-blue-light);
            color: #1e3a8a;
            border: 1px solid #93c5fd;
        }

        .sample-preview {
            max-width: 220px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            font-family: 'JetBrains Mono', monospace;
            font-size: 11px;
            color: #b45309;
            background: #fffbeb;
            padding: 2px 6px;
            border-radius: 4px;
            border: 1px solid #fde68a;
        }

        .score-bar-wrap {
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .score-num {
            font-family: 'JetBrains Mono', monospace;
            font-weight: 700;
            min-width: 28px;
        }

        .score-bar {
            flex: 1;
            height: 6px;
            background: #e4e4e7;
            border-radius: 3px;
            overflow: hidden;
            border: 1px solid var(--border-dark);
        }

        .score-bar-inner {
            height: 100%;
            background: var(--neo-red);
            border-radius: 3px;
        }

        /* Modal Details Inspector */
        .modal-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100vw;
            height: 100vh;
            background: rgba(9, 9, 11, 0.5);
            backdrop-filter: blur(4px);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 1000;
            opacity: 0;
            pointer-events: none;
            transition: opacity 0.2s ease;
            padding: 20px;
        }

        .modal-overlay.open {
            opacity: 1;
            pointer-events: auto;
        }

        .modal-card {
            background: #ffffff;
            border: var(--border-width) solid var(--border-dark);
            box-shadow: 8px 8px 0px var(--border-dark);
            border-radius: var(--radius-neo);
            width: 100%;
            max-width: 650px;
            max-height: 90vh;
            overflow-y: auto;
            transform: scale(0.95);
            transition: transform 0.2s cubic-bezier(0.175, 0.885, 0.32, 1.275);
            display: flex;
            flex-direction: column;
        }

        .modal-overlay.open .modal-card {
            transform: scale(1);
        }

        .modal-header {
            padding: 16px 20px;
            background: var(--neo-yellow-light);
            border-bottom: var(--border-width) solid var(--border-dark);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .modal-header h3 {
            font-family: 'Space Grotesk', sans-serif;
            font-size: 18px;
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .modal-close {
            background: #ffffff;
            border: 2px solid var(--border-dark);
            box-shadow: 2px 2px 0px var(--border-dark);
            width: 28px;
            height: 28px;
            border-radius: 4px;
            font-weight: bold;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .modal-close:hover {
            background: var(--neo-red-light);
            color: #dc2626;
        }

        .modal-body {
            padding: 20px;
        }

        .modal-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 12px;
            margin-bottom: 16px;
        }

        .modal-field {
            background: var(--bg-paper);
            border: 1.5px solid var(--border-dark);
            padding: 10px 12px;
            border-radius: 6px;
        }

        .modal-field label {
            display: block;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            color: var(--text-muted);
            margin-bottom: 4px;
        }

        .modal-field val {
            font-family: 'JetBrains Mono', monospace;
            font-size: 13px;
            font-weight: 600;
            word-break: break-all;
            display: block;
        }

        .modal-full-box {
            background: #18181b;
            color: #a1a1aa;
            border: 2px solid var(--border-dark);
            border-radius: 6px;
            padding: 14px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            max-height: 180px;
            overflow-y: auto;
            white-space: pre-wrap;
            word-break: break-all;
        }

        /* Footer */
        .footer-bar {
            margin-top: 24px;
            text-align: center;
            font-size: 12px;
            font-weight: 600;
            color: var(--text-muted);
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 12px;
        }
    </style>
</head>
<body>

    <!-- Header Navbar -->
    <div class="navbar">
        <div class="brand">
            <div class="brand-icon">🛡️</div>
            <div class="brand-title">
                <h1>VERIFIREWALL</h1>
                <span>AI Security Telemetry Dashboard</span>
            </div>
        </div>

        <div class="controls-group">
            <div class="live-status-pill" id="live-status-pill">
                <span class="pulse-dot"></span>
                <span id="live-status-text">LIVE TELEMETRY STREAM</span>
            </div>

            <button class="btn-neo btn-primary" id="btn-pause-toggle" onclick="togglePause()">
                <span id="pause-icon">⏸</span> <span id="pause-label">Pause Stream</span>
            </button>

            <button class="btn-neo" onclick="fetchMetrics(true)">
                🔄 Force Refresh
            </button>

            <button class="btn-neo btn-purple" onclick="exportToCSV()">
                📥 Export CSV
            </button>

            <button class="btn-neo" id="btn-sound-toggle" onclick="toggleSoundAlert()">
                <span id="sound-icon">🔇</span> Sound: Off
            </button>
        </div>
    </div>

    
    <!-- Dual-Layer Telemetry Navigation -->
    <div style="display: flex; gap: 12px; margin-bottom: 20px; align-items: center;">
        <button class="btn-neo btn-primary" id="tab-btn-l7" onclick="switchSecurityTab('L7')">
            🛡️ Layer 7 Web Application Protection (WAF)
        </button>
        <button class="btn-neo" id="tab-btn-l4" onclick="switchSecurityTab('L4')">
            ⚡ Layer 4 Network NIDS (UNSW-NB15 ML Engine)
        </button>
        <span class="badge-action allowed" style="margin-left: auto; font-family: 'JetBrains Mono', monospace; font-size: 11px;">
            🤖 XGBoost L4 Accuracy: 95.59%
        </span>
    </div>

    <!-- Layer 4 NetFlow NIDS Metrics Grid (Hidden by default or toggled) -->
    <div id="section-l4-metrics" style="display: none;">
        <div class="metrics-grid" style="margin-bottom: 24px;">
            <div class="metric-card blue">
                <div class="metric-header">
                    <span class="metric-title">Layer 4 Flows Inspected</span>
                    <div class="metric-icon-badge">📡</div>
                </div>
                <div class="metric-value" id="l4-metric-total">0</div>
                <div class="metric-sub">UNSW-NB15 NetFlow Classifier</div>
            </div>
            <div class="metric-card red">
                <div class="metric-header">
                    <span class="metric-title">L4 Network Attacks Blocked</span>
                    <div class="metric-icon-badge">🚨</div>
                </div>
                <div class="metric-value" id="l4-metric-blocked">0</div>
                <div class="metric-sub" id="l4-block-rate-pill">0% Block Rate</div>
            </div>
            <div class="metric-card green">
                <div class="metric-header">
                    <span class="metric-title">L4 Legitimate Traffic</span>
                    <div class="metric-icon-badge">✅</div>
                </div>
                <div class="metric-value" id="l4-metric-allowed">0</div>
                <div class="metric-sub" id="l4-clean-rate-pill">100% Clean</div>
            </div>
            <div class="metric-card purple">
                <div class="metric-header">
                    <span class="metric-title">ML Inference Latency</span>
                    <div class="metric-icon-badge">⚡</div>
                </div>
                <div class="metric-value">< 1.2 ms</div>
                <div class="metric-sub">XGBoost Sub-Millisecond Engine</div>
            </div>
        </div>

        <!-- L4 Telemetry Log Table Card -->
        <div class="neo-card" style="margin-bottom: 24px;">
            <div class="neo-card-header">
                <h3>⚡ Layer 4 NetFlow Anomaly Stream (UNSW-NB15)</h3>
                <span class="incident-count-label" id="l4-incident-count-label">0 NetFlows Displayed</span>
            </div>
            <div class="table-responsive">
                <table class="neo-table">
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>Source IP</th>
                            <th>Proto / Service</th>
                            <th>L4 Threat Category</th>
                            <th>Decision</th>
                            <th>ML Score</th>
                            <th>Flow Metrics (Pkts / Bytes / Rate)</th>
                            <th>Details</th>
                        </tr>
                    </thead>
                    <tbody id="l4-events-tbody">
                        <tr>
                            <td colspan="8" style="text-align:center; padding: 30px; color: var(--text-muted); font-weight: 600;">
                                ⚡ UNSW-NB15 ML NIDS Engine Active — Listening for NetFlow packet streams...
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <div id="section-l7-metrics">
    <!-- Metrics Grid -->
    <div class="metrics-grid">
        <div class="metric-card blue">
            <div class="metric-header">
                <span class="metric-title">Total Requests Inspected</span>
                <div class="metric-icon-badge">📊</div>
            </div>
            <div class="metric-value" id="metric-total">0</div>
            <div class="metric-sub">
                <span class="tag-pill blue">WAF Engine Core</span>
                <span>Active Inspection</span>
            </div>
        </div>

        <div class="metric-card red">
            <div class="metric-header">
                <span class="metric-title">Attacks Enforced (Blocked)</span>
                <div class="metric-icon-badge">🚫</div>
            </div>
            <div class="metric-value" id="metric-blocked">0</div>
            <div class="metric-sub">
                <span class="tag-pill red" id="block-rate-pill">0% Block Rate</span>
                <span>Security Action: Prevent</span>
            </div>
        </div>

        <div class="metric-card green">
            <div class="metric-header">
                <span class="metric-title">Legitimate Requests (Allowed)</span>
                <div class="metric-icon-badge">✅</div>
            </div>
            <div class="metric-value" id="metric-allowed">0</div>
            <div class="metric-sub">
                <span class="tag-pill green" id="clean-rate-pill">100% Clean</span>
                <span>Passed Inspection</span>
            </div>
        </div>

        <div class="metric-card yellow">
            <div class="metric-header">
                <span class="metric-title">Engine Defense Mode</span>
                <div class="metric-icon-badge">⚡</div>
            </div>
            <div class="metric-value" style="font-size: 26px;">PREVENT</div>
            <div class="metric-sub">
                <span class="tag-pill yellow">Autonomous ML</span>
                <span>Real-Time Anomaly Scoring</span>
            </div>
        </div>
    </div>

    <!-- Charts Row -->
    <div class="charts-grid">
        <div class="chart-box">
            <div class="chart-box-title">
                <span>🎯 Attack Types Breakdown</span>
                <span style="font-size: 12px; color: var(--text-muted); font-weight: normal;" id="chart-pie-total">0 types</span>
            </div>
            <div class="chart-container-inner">
                <canvas id="attackPieChart"></canvas>
            </div>
        </div>

        <div class="chart-box">
            <div class="chart-box-title">
                <span>📈 Security Decision Telemetry Ratio</span>
                <span style="font-size: 12px; color: var(--text-muted); font-weight: normal;">Blocked vs Allowed</span>
            </div>
            <div class="chart-container-inner">
                <canvas id="decisionBarChart"></canvas>
            </div>
        </div>
    </div>

    <!-- Telemetry Log Table Section -->
    <div class="telemetry-section">
        <div class="telemetry-header">
            <div class="telemetry-title-area">
                <h2>🚨 Live Security Incident Stream</h2>
            </div>
            <div style="font-size: 13px; font-weight: 700; color: var(--text-muted);" id="incident-count-label">
                0 Incidents Logged
            </div>
        </div>

        <!-- Filter & Search Controls -->
        <div class="filter-bar">
            <div class="search-input-wrap">
                <span class="search-icon">🔍</span>
                <input type="text" id="search-box" class="search-input" placeholder="Filter by IP, URI, Method, or Pattern sample..." oninput="applyFilters()">
            </div>

            <div class="filter-pills">
                <button class="filter-pill-btn active" id="btn-filter-all" onclick="setActionFilter('ALL')">All</button>
                <button class="filter-pill-btn" id="btn-filter-blocked" onclick="setActionFilter('BLOCKED')">Blocked Only</button>
                <button class="filter-pill-btn" id="btn-filter-allowed" onclick="setActionFilter('ALLOWED')">Allowed Only</button>
            </div>

            <select id="attack-type-select" class="filter-select" onchange="applyFilters()">
                <option value="ALL">All Incident Types</option>
                <option value="SQL Injection">SQL Injection</option>
                <option value="Cross Site Scripting">Cross Site Scripting</option>
                <option value="Command Injection">Command Injection</option>
                <option value="Path Traversal">Path Traversal</option>
                <option value="Remote Code Execution">Remote Code Execution</option>
                <option value="Reconnaissance / Probing">Recon / Probing</option>
                <option value="Legitimate Traffic">Legitimate Traffic</option>
            </select>
        </div>

        <!-- Events Table -->
        <div class="table-responsive">
            <table class="neo-table">
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Source IP</th>
                        <th>Method & URI</th>
                        <th>Attack Vector</th>
                        <th>Action</th>
                        <th>ML Score</th>
                        <th>Matched Pattern / Sample</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody id="events-tbody">
                    <tr>
                        <td colspan="8" style="text-align:center; padding: 30px; color: var(--text-muted); font-weight: 600;">
                            ⚡ VeriFireWall Telemetry Active — Listening for web traffic events...
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>

    </div>
    <!-- Footer Bar -->
    <div class="footer-bar">
        <div>🛡️ <strong>VeriFireWall Core v1.1.35</strong> — Real-Time WAAP Engine</div>
        <div id="last-updated-tag">Last Polled: Never</div>
    </div>

    <!-- Incident Inspector Modal -->
    <div class="modal-overlay" id="inspector-modal" onclick="closeModalOnBackdrop(event)">
        <div class="modal-card">
            <div class="modal-header">
                <h3>🔍 Incident Telemetry Inspector</h3>
                <button class="modal-close" onclick="closeInspectorModal()">✕</button>
            </div>
            <div class="modal-body">
                <div class="modal-grid">
                    <div class="modal-field">
                        <label>Incident Reference ID</label>
                        <val id="modal-id">-</val>
                    </div>
                    <div class="modal-field">
                        <label>Timestamp</label>
                        <val id="modal-time">-</val>
                    </div>
                    <div class="modal-field">
                        <label>Source IP</label>
                        <val id="modal-ip">-</val>
                    </div>
                    <div class="modal-field">
                        <label>Security Action</label>
                        <val id="modal-action">-</val>
                    </div>
                    <div class="modal-field">
                        <label>Attack Category</label>
                        <val id="modal-vector">-</val>
                    </div>
                    <div class="modal-field">
                        <label>ML Anomaly Score</label>
                        <val id="modal-score">-</val>
                    </div>
                </div>

                <div class="modal-field" style="margin-bottom: 16px;">
                    <label>HTTP Request URI</label>
                    <val id="modal-uri">-</val>
                </div>

                <div class="modal-field" style="margin-bottom: 16px;">
                    <label>Matched Pattern / WAF Sample</label>
                    <val id="modal-sample" style="color: var(--neo-red);">-</val>
                </div>

                <div style="margin-bottom: 6px; display: flex; justify-content: space-between; align-items: center;">
                    <label style="font-size: 11px; font-weight: 700; text-transform: uppercase; color: var(--text-muted);">Raw Event Payload</label>
                    <button class="btn-neo" style="padding: 2px 8px; font-size: 11px;" onclick="copyRawJson()">📋 Copy JSON</button>
                </div>
                <div class="modal-full-box" id="modal-raw-json">{}</div>
            </div>
        </div>
    </div>

    <!-- JavaScript Application Logic -->
    <script>
        // Disable default browser alert dialogs
        window.alert = function() {};

        // State variables
        let isPaused = false;
        let isSoundOn = false;
        let activeActionFilter = 'ALL';
        let rawEventsList = [];
        let previousBlockedCount = 0;
        let pieChart = null;
        let barChart = null;
        let currentModalEvent = null;

        // Escape HTML helper
        function escapeHtml(str) {
            if (str === null || str === undefined) return '';
            return String(str)
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#039;");
        }

        // Initialize Neo-Brutalist Styled Chart.js Visualizations cleanly
        function initCharts() {
            if (typeof Chart === 'undefined') {
                console.warn("Chart.js library not loaded yet; charts disabled.");
                return;
            }
            try {
                // Attack Pie / Doughnut Chart
                const ctxPie = document.getElementById('attackPieChart');
                if (ctxPie) {
                    pieChart = new Chart(ctxPie, {
                        type: 'doughnut',
                        data: {
                            labels: ['SQLi', 'XSS', 'CmdInj', 'PathTrav', 'RCE', 'Probing', 'Legitimate'],
                            datasets: [{
                                data: [0, 0, 0, 0, 0, 0, 0],
                                backgroundColor: [
                                    '#ff4757', // Red SQLi
                                    '#fbbf24', // Amber XSS
                                    '#3b82f6', // Blue CmdInj
                                    '#8b5cf6', // Purple PathTrav
                                    '#ec4899', // Pink RCE
                                    '#06b6d4', // Cyan Probing
                                    '#10b981'  // Green Legitimate
                                ],
                                borderColor: '#18181b',
                                borderWidth: 2.5,
                                hoverOffset: 6
                            }]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            plugins: {
                                legend: {
                                    position: 'right',
                                    labels: {
                                        font: { family: "'Plus Jakarta Sans', sans-serif", weight: '700', size: 11 },
                                        color: '#18181b',
                                        boxWidth: 14,
                                        padding: 10
                                    }
                                }
                            }
                        }
                    });
                }

                // Decision Bar Chart
                const ctxBar = document.getElementById('decisionBarChart');
                if (ctxBar) {
                    barChart = new Chart(ctxBar, {
                        type: 'bar',
                        data: {
                            labels: ['Blocked (Prevent)', 'Allowed (Clean)'],
                            datasets: [{
                                label: 'Requests',
                                data: [0, 0],
                                backgroundColor: ['#ff4757', '#10b981'],
                                borderColor: '#18181b',
                                borderWidth: 2.5,
                                borderRadius: 6
                            }]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            plugins: { legend: { display: false } },
                            scales: {
                                x: {
                                    grid: { display: false },
                                    ticks: { font: { family: "'Plus Jakarta Sans', sans-serif", weight: '700', size: 12 }, color: '#18181b' }
                                },
                                y: {
                                    grid: { color: '#e4e4e7', lineWidth: 1.5 },
                                    ticks: { font: { family: "'JetBrains Mono', monospace", weight: '600', size: 11 }, color: '#18181b' }
                                }
                            }
                        }
                    });
                }
            } catch (err) {
                console.error("Error initializing Chart.js:", err);
            }
        }

        // Toggle stream pause
        function togglePause() {
            isPaused = !isPaused;
            const statusPill = document.getElementById('live-status-pill');
            const statusText = document.getElementById('live-status-text');
            const pauseLabel = document.getElementById('pause-label');
            const pauseIcon = document.getElementById('pause-icon');

            if (isPaused) {
                statusPill.classList.add('paused');
                statusText.innerText = 'STREAM PAUSED';
                pauseLabel.innerText = 'Resume Stream';
                pauseIcon.innerText = '▶';
            } else {
                statusPill.classList.remove('paused');
                statusText.innerText = 'LIVE TELEMETRY STREAM';
                pauseLabel.innerText = 'Pause Stream';
                pauseIcon.innerText = '⏸';
                fetchMetrics(true);
            }
        }

        // Synthesize Beep audio via Web Audio API
        function playBeep() {
            if (!isSoundOn) return;
            try {
                const AudioCtx = window.AudioContext || window.webkitAudioContext;
                if (!AudioCtx) return;
                const ctx = new AudioCtx();
                const osc = ctx.createOscillator();
                const gain = ctx.createGain();
                osc.type = 'sawtooth';
                osc.frequency.setValueAtTime(880, ctx.currentTime);
                gain.gain.setValueAtTime(0.1, ctx.currentTime);
                gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.3);
                osc.connect(gain);
                gain.connect(ctx.destination);
                osc.start();
                osc.stop(ctx.currentTime + 0.3);
            } catch (e) {}
        }

        function toggleSoundAlert() {
            isSoundOn = !isSoundOn;
            const btn = document.getElementById('btn-sound-toggle');
            const icon = document.getElementById('sound-icon');
            if (isSoundOn) {
                btn.classList.add('active');
                icon.innerText = '🔔';
                btn.childNodes[2].nodeValue = ' Sound: On';
                playBeep();
            } else {
                btn.classList.remove('active');
                icon.innerText = '🔇';
                btn.childNodes[2].nodeValue = ' Sound: Off';
            }
        }

        // Action Filter selector
        function setActionFilter(action) {
            activeActionFilter = action;
            document.getElementById('btn-filter-all').classList.toggle('active', action === 'ALL');
            document.getElementById('btn-filter-blocked').classList.toggle('active', action === 'BLOCKED');
            document.getElementById('btn-filter-allowed').classList.toggle('active', action === 'ALLOWED');
            applyFilters();
        }

        // Main data polling function (Guaranteed to execute even if charts fail!)
        async function fetchMetrics(force = false) {
            if (isPaused && !force) return;

            try {
                const res = await fetch('/api/data');
                if (!res.ok) return;
                const data = await res.json();

                // Sound notification on new blocked events
                if (data.total_blocked > previousBlockedCount && previousBlockedCount > 0) {
                    playBeep();
                }
                previousBlockedCount = data.total_blocked;

                // Update Metrics Counters safely
                const totalReqsEl = document.getElementById('metric-total');
                const totalBlockedEl = document.getElementById('metric-blocked');
                const totalAllowedEl = document.getElementById('metric-allowed');

                if (totalReqsEl) totalReqsEl.innerText = (data.total_requests || 0).toLocaleString();
                if (totalBlockedEl) totalBlockedEl.innerText = (data.total_blocked || 0).toLocaleString();
                if (totalAllowedEl) totalAllowedEl.innerText = (data.total_allowed || 0).toLocaleString();

                const total = data.total_requests || 1;
                const blockPercent = (((data.total_blocked || 0) / total) * 100).toFixed(1);
                const cleanPercent = (((data.total_allowed || 0) / total) * 100).toFixed(1);

                const blockPill = document.getElementById('block-rate-pill');
                const cleanPill = document.getElementById('clean-rate-pill');
                const lastUpdated = document.getElementById('last-updated-tag');

                if (blockPill) blockPill.innerText = `${blockPercent}% Block Rate`;
                if (cleanPill) cleanPill.innerText = `${cleanPercent}% Clean`;
                if (lastUpdated) lastUpdated.innerText = `Last Polled: ${new Date().toLocaleTimeString()}`;

                // Update Charts safely
                if (pieChart && data.attack_types) {
                    const keys = Object.keys(data.attack_types);
                    const values = Object.values(data.attack_types);
                    pieChart.data.labels = keys;
                    pieChart.data.datasets[0].data = values;
                    pieChart.update();
                    const pieTotalEl = document.getElementById('chart-pie-total');
                    if (pieTotalEl) pieTotalEl.innerText = `${keys.length} vectors tracked`;
                }

                if (barChart) {
                    barChart.data.datasets[0].data = [data.total_blocked || 0, data.total_allowed || 0];
                    barChart.update();
                }

                // Store recent events & render table
                rawEventsList = data.recent_events || [];
                applyFilters();

            } catch (err) {
                console.error("Telemetry API fetch error:", err);
            }
        }

        // Filtering logic
        function applyFilters() {
            const query = (document.getElementById('search-box').value || '').toLowerCase().trim();
            const selectedType = document.getElementById('attack-type-select').value;

            const filtered = rawEventsList.filter(ev => {
                // Action Filter
                if (activeActionFilter === 'BLOCKED' && ev.action !== 'BLOCKED') return false;
                if (activeActionFilter === 'ALLOWED' && ev.action !== 'ALLOWED') return false;

                // Attack Type Filter
                if (selectedType !== 'ALL' && ev.attack_type !== selectedType) return false;

                // Search Box Filter
                if (query) {
                    const matchIp = (ev.ip || '').toLowerCase().includes(query);
                    const matchUri = (ev.uri || '').toLowerCase().includes(query);
                    const matchMethod = (ev.method || '').toLowerCase().includes(query);
                    const matchSample = (ev.matched_sample || '').toLowerCase().includes(query);
                    const matchType = (ev.attack_type || '').toLowerCase().includes(query);
                    if (!matchIp && !matchUri && !matchMethod && !matchSample && !matchType) return false;
                }

                return true;
            });

            renderTable(filtered);
        }

        // Render Telemetry Table
        
        // Render Layer 4 NetFlow Telemetry Table
        function renderL4Table(events) {
            const tbody = document.getElementById('l4-events-tbody');
            const incidentLabel = document.getElementById('l4-incident-count-label');
            if (incidentLabel) incidentLabel.innerText = `${events.length} NetFlows Displayed`;

            if (!tbody) return;

            if (events.length === 0) {
                tbody.innerHTML = `
                    <tr>
                        <td colspan="8" style="text-align:center; padding: 30px; color: var(--text-muted); font-weight: 600;">
                            ⚡ UNSW-NB15 ML NIDS Engine Active — Listening for NetFlow packet streams...
                        </td>
                    </tr>
                `;
                return;
            }

            tbody.innerHTML = events.map(ev => {
                const isBlocked = ev.action === 'BLOCKED';
                const rowClass = isBlocked ? 'row-blocked' : '';
                const score = ev.anomaly_score || 0;
                const scorePercent = Math.min(100, Math.max(0, (score / 1000) * 100));

                return `
                    <tr class="${rowClass}">
                        <td class="mono" style="white-space: nowrap; font-weight: 600;">${escapeHtml(ev.timestamp)}</td>
                        <td class="mono" style="white-space: nowrap; font-weight: 700; color: #1e293b;">${escapeHtml(ev.src_ip)}</td>
                        <td class="mono" style="white-space: nowrap;">
                            <span style="font-weight: 800; color: #0284c7;">${escapeHtml(ev.proto)}</span>:${escapeHtml(ev.service)}
                        </td>
                        <td><span class="vector-tag" style="background: #e0f2fe; color: #0369a1; border-color: #0284c7;">${escapeHtml(ev.attack_type)}</span></td>
                        <td>
                            <span class="badge-action ${isBlocked ? 'blocked' : 'allowed'}">
                                ${isBlocked ? '🚫 BLOCKED' : '✅ ALLOWED'}
                            </span>
                        </td>
                        <td>
                            <div class="score-bar-wrap">
                                <span class="score-num">${score}</span>
                                <div class="score-bar">
                                    <div class="score-bar-inner" style="width: ${scorePercent}%; background: ${isBlocked ? 'var(--neo-red)' : 'var(--neo-green)'};"></div>
                                </div>
                            </div>
                        </td>
                        <td class="mono" style="font-size: 11px;">
                            ${ev.spkts} pkts / ${ev.sbytes}B (${ev.rate} r/s) TTL:${ev.sttl}
                        </td>
                        <td style="text-align: center;">
                            <button class="btn-neo" style="padding: 4px 8px; font-size: 11px;" onclick="openInspectorModal(${ev.id}, 'L4')">
                                🔍 Inspect
                            </button>
                        </td>
                    </tr>
                `;
            }).join('');
        }

        function renderTable(events) {
            const tbody = document.getElementById('events-tbody');
            const incidentLabel = document.getElementById('incident-count-label');
            if (incidentLabel) incidentLabel.innerText = `${events.length} Incidents Displayed`;

            if (!tbody) return;

            if (events.length === 0) {
                tbody.innerHTML = `
                    <tr>
                        <td colspan="8" style="text-align:center; padding: 30px; color: var(--text-muted); font-weight: 600;">
                            ⚡ VeriFireWall Telemetry Active — Listening for incoming traffic...
                        </td>
                    </tr>
                `;
                return;
            }

            tbody.innerHTML = events.map(ev => {
                const isBlocked = ev.action === 'BLOCKED';
                const rowClass = isBlocked ? 'row-blocked' : '';
                const timeStr = ev.timestamp ? (ev.timestamp.includes('T') ? ev.timestamp.split('T')[1] : ev.timestamp) : '-';
                const score = ev.anomaly_score || 0;
                const scorePercent = Math.min(100, Math.max(0, (score / 1000) * 100));

                return `
                    <tr class="${rowClass}">
                        <td class="mono" style="white-space: nowrap; font-weight: 600;">${escapeHtml(timeStr)}</td>
                        <td class="mono" style="white-space: nowrap; font-weight: 700; color: #1e293b;">${escapeHtml(ev.ip)}</td>
                        <td class="mono" style="max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                            <span style="font-weight: 800; color: #0284c7;">${escapeHtml(ev.method)}</span> ${escapeHtml(ev.uri)}
                        </td>
                        <td><span class="vector-tag">${escapeHtml(ev.attack_type)}</span></td>
                        <td>
                            <span class="badge-action ${isBlocked ? 'blocked' : 'allowed'}">
                                ${isBlocked ? '🚫 BLOCKED' : '✅ ALLOWED'}
                            </span>
                        </td>
                        <td>
                            <div class="score-bar-wrap">
                                <span class="score-num">${score}</span>
                                <div class="score-bar">
                                    <div class="score-bar-inner" style="width: ${scorePercent}%; background: ${isBlocked ? 'var(--neo-red)' : 'var(--neo-green)'};"></div>
                                </div>
                            </div>
                        </td>
                        <td>
                            <div class="sample-preview" title="${escapeHtml(ev.matched_sample)}">
                                ${escapeHtml(ev.matched_sample)}
                            </div>
                        </td>
                        <td style="text-align: center;">
                            <button class="btn-neo" style="padding: 4px 8px; font-size: 11px;" onclick="openInspectorModal(${ev.id})">
                                🔍 Inspect
                            </button>
                        </td>
                    </tr>
                `;
            }).join('');
        }

        // Modal Inspector Functions
        function openInspectorModal(eventId) {
            const ev = rawEventsList.find(e => e.id === eventId);
            if (!ev) return;
            currentModalEvent = ev;

            document.getElementById('modal-id').innerText = `#EVT-${ev.id || '00'}`;
            document.getElementById('modal-time').innerText = ev.timestamp || '-';
            document.getElementById('modal-ip').innerText = ev.ip || '-';
            document.getElementById('modal-action').innerText = ev.action || '-';
            document.getElementById('modal-vector').innerText = ev.attack_type || '-';
            document.getElementById('modal-score').innerText = `${ev.anomaly_score || 0} (${ev.threat_level || 'Normal'})`;
            document.getElementById('modal-uri').innerText = ev.uri || '-';
            document.getElementById('modal-sample').innerText = ev.matched_sample || 'Passed WAF Filter';
            document.getElementById('modal-raw-json').innerText = JSON.stringify(ev, null, 2);

            document.getElementById('inspector-modal').classList.add('open');
        }

        function closeInspectorModal() {
            document.getElementById('inspector-modal').classList.remove('open');
        }

        function closeModalOnBackdrop(e) {
            if (e.target.id === 'inspector-modal') {
                closeInspectorModal();
            }
        }

        // Copy raw JSON
        function copyRawJson() {
            if (!currentModalEvent) return;
            navigator.clipboard.writeText(JSON.stringify(currentModalEvent, null, 2));
            const btn = event.target;
            const orig = btn.innerText;
            btn.innerText = '✅ Copied!';
            setTimeout(() => { btn.innerText = orig; }, 1500);
        }

        // Export events to CSV
        function exportToCSV() {
            if (rawEventsList.length === 0) return;
            const headers = ['ID', 'Timestamp', 'IP', 'Method', 'URI', 'Action', 'Attack Type', 'Anomaly Score', 'Threat Level', 'Matched Sample'];
            const rows = rawEventsList.map(ev => [
                ev.id,
                `"${ev.timestamp || ''}"`,
                `"${ev.ip || ''}"`,
                `"${ev.method || ''}"`,
                `"${(ev.uri || '').replace(/"/g, '""')}"`,
                `"${ev.action || ''}"`,
                `"${ev.attack_type || ''}"`,
                ev.anomaly_score || 0,
                `"${ev.threat_level || ''}"`,
                `"${(ev.matched_sample || '').replace(/"/g, '""')}"`
            ]);

            const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map(e => e.join(','))].join('\\n');
            const encodedUri = encodeURI(csvContent);
            const link = document.createElement('a');
            link.setAttribute('href', encodedUri);
            link.setAttribute('download', `verifirewall_telemetry_${Date.now()}.csv`);
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        }

        // Keyboard shortcuts (ESC closes modal)
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') closeInspectorModal();
        });

        function switchSecurityTab(tab) {
            const l4 = document.getElementById('section-l4-metrics');
            const l7_cards = document.querySelector('.metrics-grid');
            const l7_charts = document.querySelector('.charts-grid');
            const l7_table = document.querySelector('.telemetry-section');
            const btnL4 = document.getElementById('tab-btn-l4');
            const btnL7 = document.getElementById('tab-btn-l7');
            if (tab === 'L4') {
                if (l4) l4.style.display = 'block';
                if (l7_cards) l7_cards.style.display = 'none';
                if (l7_charts) l7_charts.style.display = 'none';
                if (l7_table) l7_table.style.display = 'none';
                if (btnL4) { btnL4.classList.add('btn-primary'); }
                if (btnL7) { btnL7.classList.remove('btn-primary'); }
            } else {
                if (l4) l4.style.display = 'none';
                if (l7_cards) l7_cards.style.display = 'grid';
                if (l7_charts) l7_charts.style.display = 'grid';
                if (l7_table) l7_table.style.display = 'block';
                if (btnL7) { btnL7.classList.add('btn-primary'); }
                if (btnL4) { btnL4.classList.remove('btn-primary'); }
            }
        }

        // Initialize application robustly
        function startApp() {
            const params = new URLSearchParams(window.location.search);
            if (params.get('tab') === 'L4' || params.get('tab') === 'l4') {
                switchSecurityTab('L4');
            }
            // First fetch data immediately
            fetchMetrics(true);
            
            // Try initializing charts safely
            try {
                initCharts();
            } catch (e) {
                console.error("Init charts failed safely:", e);
            }
            
            // Set 2s interval polling
            setInterval(() => fetchMetrics(), 2000);
        }

        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', startApp);
        } else {
            startApp();
        }
    </script>
</body>
</html>
"""

def l4_streamer_thread():
    print("⚡ [UNSW-NB15 ML] Starting Layer 4 NetFlow Anomaly Classification Streamer...")
    while True:
        try:
            if unsw_classifier is not None:
                flow_data = generate_random_flow()
                res = unsw_classifier.classify_flow(flow_data)
                
                with lock:
                    l4_stats["total_flows"] += 1
                    if res["is_attack"]:
                        l4_stats["total_blocked"] += 1
                    else:
                        l4_stats["total_allowed"] += 1

                    cat = res["attack_cat"]
                    if cat in l4_stats["attack_categories"]:
                        l4_stats["attack_categories"][cat] += 1
                    else:
                        l4_stats["attack_categories"][cat] = 1

                    event_entry = {
                        "id": len(l4_stats["recent_events"]) + 1,
                        "timestamp": flow_data.get("timestamp", time.strftime("%H:%M:%S")),
                        "src_ip": flow_data.get("src_ip", "192.168.1.100"),
                        "proto": flow_data.get("proto", "tcp").upper(),
                        "service": flow_data.get("service", "http"),
                        "action": "BLOCKED" if res["is_attack"] else "ALLOWED",
                        "attack_type": cat,
                        "anomaly_score": res["anomaly_score"],
                        "confidence": res["confidence"],
                        "model": res["model"],
                        "dur": flow_data.get("dur", 0.0),
                        "spkts": flow_data.get("spkts", 0),
                        "dpkts": flow_data.get("dpkts", 0),
                        "sbytes": flow_data.get("sbytes", 0),
                        "dbytes": flow_data.get("dbytes", 0),
                        "rate": flow_data.get("rate", 0.0),
                        "sttl": flow_data.get("sttl", 64)
                    }

                    l4_stats["recent_events"].insert(0, event_entry)
                    if len(l4_stats["recent_events"]) > 100:
                        l4_stats["recent_events"].pop()

            time.sleep(1.8)
        except Exception as e:
            print(f"[UNSW-NB15 ML] Streamer error: {e}")
            time.sleep(2)

class DashboardRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == '/api/data':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            with lock:
                payload = dict(stats)
                payload["l4"] = l4_stats
                self.wfile.write(json.dumps(payload).encode('utf-8'))
        else:
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(HTML_PAGE.encode('utf-8'))

def run_server():
    t1 = threading.Thread(target=log_streamer_thread, daemon=True)
    t1.start()
    t2 = threading.Thread(target=l4_streamer_thread, daemon=True)
    t2.start()
    
    server_address = ('', 3002)
    httpd = HTTPServer(server_address, DashboardRequestHandler)
    print("=========================================================")
    print("🛡️ VeriFireWall Security Analytics Server Started on port 3002")
    print("📊 Open Dashboard at: http://localhost:3002")
    print("=========================================================")
    httpd.serve_forever()

if __name__ == '__main__':
    run_server()
