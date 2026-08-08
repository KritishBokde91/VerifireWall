#!/usr/bin/env python3
"""
VeriFireWall - Attack & Demonstration Traffic Generator
------------------------------------------------------
Simulates both legitimate web traffic and realistic cyber-attack vectors
against the VeriFireWall WAF proxy (http://localhost:80) so that real-time
metrics and security alerts populate in the Grafana Dashboard (http://localhost:3001).
"""

import sys
import time
import argparse
import random
import urllib.parse
import urllib.request
import urllib.error

TARGET_URL = "http://localhost:80"

BENIGN_ENDPOINTS = [
    "/",
    "/products",
    "/about",
    "/contact",
    "/api/v1/status",
    "/user/profile?id=102",
    "/search?category=electronics",
    "/cart?action=view"
]

ATTACK_PAYLOADS = [
    # SQL Injection
    {"path": "/rest/user/login", "param": "email", "payload": "' OR '1'='1' --", "type": "SQL Injection"},
    {"path": "/products/search", "param": "q", "payload": "1 UNION SELECT username, password FROM users--", "type": "SQL Injection"},
    
    # Cross-Site Scripting (XSS)
    {"path": "/comment", "param": "msg", "payload": "<script>alert('VeriFireWall XSS Test')</script>", "type": "Cross-Site Scripting"},
    {"path": "/profile", "param": "name", "payload": "<img src=x onerror=alert(document.cookie)>", "type": "Cross-Site Scripting"},
    
    # Remote Code Execution (RCE) / Command Injection
    {"path": "/api/tools/ping", "param": "host", "payload": "127.0.0.1; cat /etc/passwd", "type": "Command Injection"},
    {"path": "/cgi-bin/test", "param": "cmd", "payload": "() { :;}; echo Vulnerable: $(whoami)", "type": "Shellshock RCE"},
    
    # Local File Inclusion (LFI) / Path Traversal
    {"path": "/download", "param": "file", "payload": "../../../../etc/passwd", "type": "Path Traversal"},
    {"path": "/view", "param": "doc", "payload": "....//....//....//etc/shadow", "type": "Local File Inclusion"}
]

def send_request(url: str, post_data: bytes = None):
    req = urllib.request.Request(
        url,
        data=post_data,
        headers={
            "User-Agent": "VeriFireWall-Demo-Tester/1.0",
            "Accept": "text/html,application/xhtml+xml,application/json"
        }
    )
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            return resp.status, "ALLOWED (200 OK)"
    except urllib.error.HTTPError as e:
        if e.code == 403:
            return e.code, "BLOCKED (403 Forbidden - VeriFireWall Enforced)"
        return e.code, f"HTTP {e.code}"
    except Exception as e:
        return 0, f"Error: {e}"

def generate_benign():
    path = random.choice(BENIGN_ENDPOINTS)
    url = f"{TARGET_URL}{path}"
    status, result = send_request(url)
    print(f"   [BENIGN TRAFFIC]  {url[:50]:<50} => Status: {status} ({result})")

def generate_attack():
    attack = random.choice(ATTACK_PAYLOADS)
    encoded_param = urllib.parse.urlencode({attack["param"]: attack["payload"]})
    url = f"{TARGET_URL}{attack['path']}?{encoded_param}"
    status, result = send_request(url)
    print(f"   🔥 [ATTACK PROBE]   {attack['type']:<22} | URL: {url[:45]:<45} => Status: {status} ({result})")

def main():
    parser = argparse.ArgumentParser(description="VeriFireWall Attack Generator & Dashboard Feeder")
    parser.add_argument("--count", "-c", type=int, default=50, help="Number of test requests to send (default: 50)")
    parser.add_argument("--ratio", "-r", type=float, default=0.4, help="Ratio of attacks vs benign traffic (0.0 to 1.0, default: 0.4)")
    parser.add_argument("--continuous", action="store_true", help="Run continuously in a loop for live demo")
    args = parser.parse_args()

    print("=" * 75)
    print(" 🔥 VeriFireWall Attack Generator & Real-time Dashboard Feeder")
    print(f" 🎯 Target WAF Proxy: {TARGET_URL}")
    print(f" 📊 Visualizing in:  http://localhost:3001 (Grafana)")
    print("=" * 75)

    iteration = 0
    try:
        while True:
            iteration += 1
            if not args.continuous and iteration > args.count:
                break
                
            if random.random() < args.ratio:
                generate_attack()
            else:
                generate_benign()
                
            time.sleep(0.2) # smooth flow of traffic
    except KeyboardInterrupt:
        print("\nStopped traffic generation.")

    print("=" * 75)
    print(" ✅ Traffic generation complete. Check your Grafana dashboard at http://localhost:3001 !")
    print("=" * 75)

if __name__ == "__main__":
    main()
