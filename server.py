#!/usr/bin/env python3
"""
Snort3 IDS Dashboard - Backend Server
Parses /var/log/snort/alert_fast.txt and serves live alerts via HTTP + SSE
Run: sudo python3 server.py
"""

import re
import json
import time
import threading
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from collections import defaultdict
from datetime import datetime
from urllib.parse import urlparse

ALERT_FILE = "/var/log/snort/alert_fast.txt"
HOST = "0.0.0.0"
PORT = 8888

# ── Alert regex for Snort3 alert_fast format ──────────────────────────────────
# Example line:
# 04/20-11:23:28.270374 [**] [1:1000001:1] "ICMP Ping Detected" [**] [Priority: 0] {ICMP} 172.29.60.170 -> 8.8.8.8
ALERT_RE = re.compile(
    r"(?P<timestamp>\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)"
    r"\s+\[\*\*\]\s+"
    r"\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+"
    r'"(?P<msg>[^"]+)"'
    r"\s+\[\*\*\]\s+"
    r"(?:\[Classification:\s*(?P<classification>[^\]]+)\]\s*)?"
    r"\[Priority:\s*(?P<priority>\d+)\]\s+"
    r"\{(?P<proto>[^}]+)\}\s+"
    r"(?P<src>[\d\.]+)(?::(?P<sport>\d+))?\s+->\s+"
    r"(?P<dst>[\d\.]+)(?::(?P<dport>\d+))?"
)

# ── Attack category mapping ───────────────────────────────────────────────────
CATEGORY_MAP = {
    "icmp": "Recon",
    "ping": "Recon",
    "scan": "Recon",
    "sweep": "Recon",
    "port_scan": "Recon",
    "ssh": "Brute Force",
    "ftp": "Brute Force",
    "telnet": "Brute Force",
    "http": "Web Attack",
    "sql": "Web Attack",
    "xss": "Web Attack",
    "shellcode": "Exploit",
    "overflow": "Exploit",
    "exploit": "Exploit",
    "malware": "Malware",
    "trojan": "Malware",
    "backdoor": "Malware",
    "dos": "DoS",
    "flood": "DoS",
    "syn": "DoS",
}

def categorize(msg):
    msg_lower = msg.lower()
    for keyword, category in CATEGORY_MAP.items():
        if keyword in msg_lower:
            return category
    return "Other"

def severity_from_priority(priority):
    p = int(priority)
    if p <= 1:
        return "critical"
    elif p == 2:
        return "high"
    elif p == 3:
        return "medium"
    else:
        return "low"

# ── Shared state ──────────────────────────────────────────────────────────────
state = {
    "alerts": [],          # last 500 alerts
    "total": 0,
    "src_ip_counts": defaultdict(int),
    "category_counts": defaultdict(int),
    "proto_counts": defaultdict(int),
    "severity_counts": defaultdict(int),
    "alerts_per_minute": [],   # list of {time, count}
    "last_minute_bucket": None,
    "last_minute_count": 0,
}
state_lock = threading.Lock()
sse_clients = []
sse_lock = threading.Lock()

def parse_line(line):
    line = line.strip()
    if not line:
        return None
    m = ALERT_RE.match(line)
    if not m:
        return None
    d = m.groupdict()
    category = categorize(d["msg"])
    severity = severity_from_priority(d.get("priority") or 4)
    return {
        "id": int(time.time() * 1000),
        "timestamp": d["timestamp"],
        "sid": f"{d['gid']}:{d['sid']}:{d['rev']}",
        "msg": d["msg"],
        "priority": int(d.get("priority") or 4),
        "severity": severity,
        "proto": d["proto"],
        "src": d["src"],
        "sport": d.get("sport") or "",
        "dst": d["dst"],
        "dport": d.get("dport") or "",
        "category": category,
        "classification": d.get("classification") or "",
        "raw": line,
    }

def update_state(alert):
    with state_lock:
        state["alerts"].insert(0, alert)
        if len(state["alerts"]) > 500:
            state["alerts"] = state["alerts"][:500]
        state["total"] += 1
        state["src_ip_counts"][alert["src"]] += 1
        state["category_counts"][alert["category"]] += 1
        state["proto_counts"][alert["proto"]] += 1
        state["severity_counts"][alert["severity"]] += 1

        now_min = datetime.now().strftime("%H:%M")
        if state["last_minute_bucket"] != now_min:
            if state["last_minute_bucket"] is not None:
                state["alerts_per_minute"].append({
                    "time": state["last_minute_bucket"],
                    "count": state["last_minute_count"]
                })
                if len(state["alerts_per_minute"]) > 20:
                    state["alerts_per_minute"] = state["alerts_per_minute"][-20:]
            state["last_minute_bucket"] = now_min
            state["last_minute_count"] = 1
        else:
            state["last_minute_count"] += 1

def broadcast_sse(alert):
    data = f"data: {json.dumps(alert)}\n\n"
    with sse_lock:
        dead = []
        for client in sse_clients:
            try:
                client.wfile.write(data.encode())
                client.wfile.flush()
            except Exception:
                dead.append(client)
        for c in dead:
            sse_clients.remove(c)

def tail_alerts():
    """Tail the Snort alert file and push new alerts."""
    print(f"[snort-dashboard] Watching {ALERT_FILE}")
    while not os.path.exists(ALERT_FILE):
        print(f"[snort-dashboard] Waiting for {ALERT_FILE} ...")
        time.sleep(2)

    with open(ALERT_FILE, "r") as f:
        # Read existing alerts on startup
        for line in f:
            alert = parse_line(line)
            if alert:
                update_state(alert)
        print(f"[snort-dashboard] Loaded {state['total']} existing alerts")

        # Now tail for new ones
        while True:
            line = f.readline()
            if line:
                alert = parse_line(line)
                if alert:
                    update_state(alert)
                    broadcast_sse(alert)
            else:
                time.sleep(0.2)

def get_stats():
    with state_lock:
        top_src = sorted(state["src_ip_counts"].items(), key=lambda x: x[1], reverse=True)[:10]
        top_cat = sorted(state["category_counts"].items(), key=lambda x: x[1], reverse=True)
        top_proto = sorted(state["proto_counts"].items(), key=lambda x: x[1], reverse=True)
        return {
            "total": state["total"],
            "top_src": [{"ip": k, "count": v} for k, v in top_src],
            "categories": [{"name": k, "count": v} for k, v in top_cat],
            "protocols": [{"name": k, "count": v} for k, v in top_proto],
            "severity": dict(state["severity_counts"]),
            "alerts_per_minute": state["alerts_per_minute"],
        }

# ── HTTP Handler ──────────────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # silence default logging

    def send_cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_cors()
        self.end_headers()

    def do_GET(self):
        path = urlparse(self.path).path

        if path == "/":
            self.serve_file("/home/harshraj1695/snort_project/index.html", "text/html")

        elif path == "/api/alerts":
            with state_lock:
                alerts = state["alerts"][:100]
            self.send_json(alerts)

        elif path == "/api/stats":
            self.send_json(get_stats())

        elif path == "/api/stream":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.send_cors()
            self.end_headers()
            with sse_lock:
                sse_clients.append(self)
            # Keep connection open
            try:
                while True:
                    time.sleep(1)
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
            except Exception:
                with sse_lock:
                    if self in sse_clients:
                        sse_clients.remove(self)

        else:
            self.send_response(404)
            self.end_headers()

    def serve_file(self, path, content_type):
        try:
            with open(path, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_cors()
            self.end_headers()
            self.wfile.write(content)
        except FileNotFoundError:
            self.send_response(404)
            self.end_headers()

    def send_json(self, data):
        body = json.dumps(data).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_cors()
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    # Start file tailer in background thread
    t = threading.Thread(target=tail_alerts, daemon=True)
    t.start()

    server = HTTPServer((HOST, PORT), Handler)
    print(f"[snort-dashboard] Dashboard running at http://localhost:{PORT}")
    print(f"[snort-dashboard] Open your browser at http://localhost:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[snort-dashboard] Stopped.")