# Snort3 IDS Dashboard

A real-time intrusion detection dashboard for Snort3 using AFPacket. Parses Snort alert logs and displays them live in a web UI with attack categorization, source IP tracking, and severity filtering.

---

## Project Structure

```
snort_project/
├── app/
│   ├── alerts.py              # Snort alert parsing and categorization
│   ├── config.py              # Paths and environment-driven settings
│   ├── rules.py               # Rule validation and rule-file writes
│   ├── state.py               # In-memory dashboard aggregates
│   ├── web.py                 # HTTP server, SSE stream, static/template serving
│   ├── static/
│   │   ├── css/dashboard.css  # Dashboard styles
│   │   └── js/dashboard.js    # Dashboard client logic
│   └── templates/index.html   # Dashboard markup
├── server.py                  # Thin entrypoint for starting the app
└── README.md
```

---

## Prerequisites

- Snort3 installed at `/usr/local/snort/bin/snort`
- Snort config at `/usr/local/snort/etc/snort/snort.lua`
- Local rules at `/usr/local/snort/etc/snort/rules/local.rules`
- Python 3 (standard library only, no pip installs needed)
- Log directory: `/var/log/snort/`

---

## Setup

### 1. Make sure log directory exists

```bash
sudo mkdir -p /var/log/snort
```

### 2. Optional runtime configuration

The dashboard now supports environment variables instead of hardcoded paths:

```bash
export SNORT_ALERT_FILE=/var/log/snort/alert_fast.txt
export SNORT_INTERFACE=eth0
export SNORT_DASHBOARD_HOST=0.0.0.0
export SNORT_DASHBOARD_PORT=8888
```

---

## Running

You need **two terminals** running simultaneously.

### Terminal 1 — Start Snort3

```bash
sudo /usr/local/snort/bin/snort \
  --daq afpacket \
  -i eth0 \
  -c /usr/local/snort/etc/snort/snort.lua \
  -l /var/log/snort \
  -A alert_fast \
  --lua "alert_fast = { file = true }"
```

Expected output:
```
afpacket DAQ configured to passive.
Commencing packet processing
++ [0] eth0
```

### Terminal 2 — Start the Dashboard Server

```bash
sudo python3 ~/snort_project/server.py
```

Expected output:
```
[snort-dashboard] Watching /var/log/snort/alert_fast.txt
[snort-dashboard] Loaded X existing alerts
[snort-dashboard] Dashboard running at http://localhost:8888
```

If you exported custom environment variables with `sudo`, preserve them:

```bash
sudo --preserve-env=SNORT_ALERT_FILE,SNORT_INTERFACE,SNORT_DASHBOARD_HOST,SNORT_DASHBOARD_PORT python3 ~/snort_project/server.py
```

### Terminal 3 — Open the Dashboard

Open your browser at:
```
http://localhost:8888
```

---

## Generating Test Traffic

```bash
# Trigger ICMP rule
ping -c 5 8.8.8.8

# Trigger HTTP rule
curl http://example.com

# Watch raw alerts
sudo tail -f /var/log/snort/alert_fast.txt
```

---

## Local Rules

Rules file: `/usr/local/snort/etc/snort/rules/local.rules`

```
alert icmp any any -> any any (msg:"ICMP Ping Detected"; sid:1000001; rev:1;)
alert tcp any any -> any 22  (msg:"SSH Connection Attempt"; sid:1000002; rev:1;)
alert tcp any any -> any 80  (msg:"HTTP Traffic Detected"; sid:1000003; rev:1;)
```

To add a new rule, append to the file and restart Snort. No dashboard restart needed.

---

## Dashboard Features

| Feature | Description |
|---|---|
| Live alert feed | New alerts appear instantly via SSE (no page refresh) |
| Severity filter | Filter by critical / high / medium / low |
| Category filter | Auto-classifies alerts (Recon, Web Attack, Exploit, DoS, etc.) |
| Search | Filter by IP address or message keyword |
| Top Source IPs | Bar chart of most active attacking hosts |
| Attack categories | Breakdown by attack type |
| Alerts per minute | Sparkline chart showing traffic over time |
| Protocol breakdown | ICMP / TCP / UDP distribution |
| Live indicator | Green dot shows SSE connection status |

---

## API Endpoints

The server exposes these endpoints (useful for scripting or integration):

| Endpoint | Description |
|---|---|
| `GET /` | Serves the dashboard UI |
| `GET /api/alerts` | Last 100 alerts as JSON |
| `GET /api/stats` | Aggregated stats (top IPs, categories, severity counts) |
| `GET /api/stream` | SSE stream — push new alerts in real time |

Example:
```bash
curl http://localhost:8888/api/alerts | python3 -m json.tool
curl http://localhost:8888/api/stats  | python3 -m json.tool
```

---

## Alert Severity Mapping

Snort priority field maps to dashboard severity as follows:

| Snort Priority | Dashboard Severity |
|---|---|
| 1 | Critical |
| 2 | High |
| 3 | Medium |
| 4+ | Low |

---

## Troubleshooting

**`alert_fast.txt` not created**
Snort only creates the file after the first alert fires. Trigger one with `ping -c 3 8.8.8.8`.

**Browser shows "This page can't be found"**
Run the server from this project directory so it can serve the bundled template and static assets from `app/templates/` and `app/static/`.

**Permission denied on alert file**
Always run the server with `sudo` since the alert file is owned by root.

**Dashboard shows "Waiting for alerts"**
The SSE connection is working but no alerts have fired yet. Generate traffic with `ping` or `curl`.

**Port 8888 already in use**
```bash
sudo lsof -i :8888
sudo kill <PID>
```
