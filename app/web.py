import json
import mimetypes
import os
from pathlib import Path
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from .alerts import parse_line
from .config import ALERT_FILE, HOST, INDEX_FILE, INTERFACE, PORT, RULES_FILE, STATIC_DIR
from .rules import (
    append_rule,
    build_rule,
    delete_rule_by_sid,
    list_rules,
    read_json_body,
    reload_hint,
)
from .state import DashboardState


STATE = DashboardState()
SSE_CLIENTS = []
SSE_LOCK = threading.Lock()


def broadcast_sse(alert):
    data = f"data: {json.dumps(alert)}\n\n"
    with SSE_LOCK:
        dead_clients = []
        for client in SSE_CLIENTS:
            try:
                client.wfile.write(data.encode())
                client.wfile.flush()
            except Exception:
                dead_clients.append(client)
        for client in dead_clients:
            SSE_CLIENTS.remove(client)


def tail_alerts():
    print(f"[snort-dashboard] Watching {ALERT_FILE}")
    while not os.path.exists(ALERT_FILE):
        print(f"[snort-dashboard] Waiting for {ALERT_FILE} ...")
        time.sleep(2)

    with open(ALERT_FILE, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            alert = parse_line(line)
            if alert:
                STATE.update(alert)
        print(f"[snort-dashboard] Loaded {STATE.data['total']} existing alerts")

        while True:
            line = handle.readline()
            if line:
                alert = parse_line(line)
                if alert:
                    STATE.update(alert)
                    broadcast_sse(alert)
            else:
                time.sleep(0.2)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def send_cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def send_json(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_cors()
        self.end_headers()
        self.wfile.write(body)

    def serve_file(self, path):
        try:
            with open(path, "rb") as handle:
                content = handle.read()
            content_type, _ = mimetypes.guess_type(path.name)
            self.send_response(200)
            self.send_header("Content-Type", content_type or "application/octet-stream")
            self.send_cors()
            self.end_headers()
            self.wfile.write(content)
        except FileNotFoundError:
            self.send_response(404)
            self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_cors()
        self.end_headers()

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/api/alerts/clear":
            STATE.clear()
            self.send_json({"ok": True, "message": "Detection history cleared."})
            return

        if path != "/api/rules":
            self.send_response(404)
            self.end_headers()
            return

        try:
            payload = read_json_body(self)
            if payload is None:
                raise ValueError("Request body is required")
            rule = build_rule(payload)
            append_rule(rule, RULES_FILE)
            self.send_json({"ok": True, "rule": rule, "message": reload_hint()}, status=201)
        except json.JSONDecodeError:
            self.send_json({"ok": False, "error": "Invalid JSON body"}, status=400)
        except ValueError as exc:
            self.send_json({"ok": False, "error": str(exc)}, status=400)
        except PermissionError:
            self.send_json(
                {
                    "ok": False,
                    "error": f"Permission denied writing to {RULES_FILE}. Run the dashboard with privileges that can update the rules file.",
                },
                status=500,
            )
        except Exception as exc:
            self.send_json({"ok": False, "error": f"Unable to save rule: {exc}"}, status=500)

    def do_DELETE(self):
        path = urlparse(self.path).path
        if not path.startswith("/api/rules/"):
            self.send_response(404)
            self.end_headers()
            return

        sid = path.rsplit("/", 1)[-1]
        try:
            removed_rule = delete_rule_by_sid(sid, RULES_FILE)
            self.send_json(
                {
                    "ok": True,
                    "message": f"Rule {sid} deleted. Reload or restart Snort for the change to take effect.",
                    "rule": removed_rule,
                }
            )
        except ValueError as exc:
            self.send_json({"ok": False, "error": str(exc)}, status=404)
        except PermissionError:
            self.send_json(
                {
                    "ok": False,
                    "error": f"Permission denied writing to {RULES_FILE}. Run the dashboard with privileges that can update the rules file.",
                },
                status=500,
            )
        except Exception as exc:
            self.send_json({"ok": False, "error": f"Unable to delete rule: {exc}"}, status=500)

    def do_GET(self):
        path = urlparse(self.path).path

        if path == "/":
            self.serve_file(INDEX_FILE)
            return

        if path.startswith("/static/"):
            relative_path = path.removeprefix("/static/")
            safe_path = (STATIC_DIR / relative_path).resolve()
            if STATIC_DIR.resolve() not in safe_path.parents and safe_path != STATIC_DIR.resolve():
                self.send_response(403)
                self.end_headers()
                return
            self.serve_file(safe_path)
            return

        if path == "/api/alerts":
            self.send_json(STATE.recent_alerts())
            return

        if path == "/api/stats":
            self.send_json(STATE.stats(INTERFACE, ALERT_FILE, RULES_FILE))
            return

        if path == "/api/rules":
            self.send_json({"rules": list_rules(RULES_FILE)})
            return

        if path == "/api/stream":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.send_cors()
            self.end_headers()
            with SSE_LOCK:
                SSE_CLIENTS.append(self)
            try:
                while True:
                    time.sleep(1)
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
            except Exception:
                with SSE_LOCK:
                    if self in SSE_CLIENTS:
                        SSE_CLIENTS.remove(self)
            return

        self.send_response(404)
        self.end_headers()


def main():
    tailer = threading.Thread(target=tail_alerts, daemon=True)
    tailer.start()

    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"[snort-dashboard] Dashboard running at http://localhost:{PORT}")
    print(f"[snort-dashboard] Open your browser at http://localhost:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[snort-dashboard] Stopped.")
