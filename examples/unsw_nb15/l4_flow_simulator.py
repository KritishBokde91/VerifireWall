#!/usr/bin/env python3
"""
VeriFireWall - Layer 4 NetFlow Packet Stream Simulator
-------------------------------------------------------
Generates realistic Layer 4 TCP/UDP network flow statistics covering:
- Normal Legitimate NetFlow
- DoS / DDoS SYN Flood Attacks
- Automated Port Scanning & Reconnaissance
- Fuzzers & Malicious Buffer Payload Flows
- Shellcode / Exploit Intrusion Attempts
"""

import time
import random

L4_ATTACK_PATTERNS = [
    {
        "attack_cat": "DoS / SYN Flood",
        "dur": 0.000001, "spkts": 2, "dpkts": 0, "sbytes": 128, "dbytes": 0,
        "rate": 1000000.0, "sttl": 254, "dttl": 0, "proto": "tcp", "service": "None", "state": "INT",
        "src_ip": "192.168.1.105", "dst_port": 80
    },
    {
        "attack_cat": "Reconnaissance / Port Scan",
        "dur": 0.000012, "spkts": 1, "dpkts": 1, "sbytes": 64, "dbytes": 40,
        "rate": 83333.3, "sttl": 64, "dttl": 60, "proto": "tcp", "service": "dns", "state": "CON",
        "src_ip": "10.0.4.19", "dst_port": 53
    },
    {
        "attack_cat": "Fuzzers / Malicious Buffer",
        "dur": 0.54012, "spkts": 45, "dpkts": 32, "sbytes": 12400, "dbytes": 450,
        "rate": 142.5, "sttl": 254, "dttl": 252, "proto": "udp", "service": "None", "state": "INT",
        "src_ip": "172.16.0.44", "dst_port": 8080
    },
    {
        "attack_cat": "Exploits / Shellcode Payload",
        "dur": 0.08920, "spkts": 18, "dpkts": 14, "sbytes": 4500, "dbytes": 8900,
        "rate": 358.7, "sttl": 62, "dttl": 252, "proto": "tcp", "service": "http", "state": "FIN",
        "src_ip": "198.51.100.77", "dst_port": 80
    }
]

NORMAL_NETFLOW_PATTERNS = [
    {
        "attack_cat": "Legitimate NetFlow",
        "dur": 0.05120, "spkts": 10, "dpkts": 12, "sbytes": 850, "dbytes": 4200,
        "rate": 429.6, "sttl": 64, "dttl": 60, "proto": "tcp", "service": "http", "state": "FIN",
        "src_ip": "192.168.1.50", "dst_port": 80
    },
    {
        "attack_cat": "Legitimate NetFlow",
        "dur": 0.01240, "spkts": 4, "dpkts": 4, "sbytes": 320, "dbytes": 1200,
        "rate": 645.1, "sttl": 64, "dttl": 60, "proto": "udp", "service": "dns", "state": "CON",
        "src_ip": "192.168.1.55", "dst_port": 53
    }
]

def generate_random_flow():
    """Generates a random network flow packet dict (70% attack, 30% normal for simulation)."""
    is_attack = random.random() < 0.7
    if is_attack:
        base = random.choice(L4_ATTACK_PATTERNS).copy()
    else:
        base = random.choice(NORMAL_NETFLOW_PATTERNS).copy()

    # Add slight noise to numeric metrics
    base['dur'] = max(0.000001, round(base['dur'] * random.uniform(0.8, 1.2), 6))
    base['sbytes'] = max(40, int(base['sbytes'] * random.uniform(0.9, 1.1)))
    base['dbytes'] = max(0, int(base['dbytes'] * random.uniform(0.9, 1.1)))
    base['rate'] = round(base['rate'] * random.uniform(0.95, 1.05), 1)
    base['timestamp'] = time.strftime("%H:%M:%S")

    return base
