#!/usr/bin/env bash

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

SNORT_BIN="${SNORT_BIN:-/usr/local/snort/bin/snort}"
SNORT_CONF="${SNORT_CONF:-/usr/local/snort/etc/snort/snort.lua}"
SNORT_RULES="${SNORT_RULES:-/usr/local/snort/etc/snort/rules/local.rules}"
SNORT_LOG_DIR="${SNORT_LOG_DIR:-/var/log/snort}"
SNORT_INTERFACE="${SNORT_INTERFACE:-eth0}"

DASHBOARD_HOST="${SNORT_DASHBOARD_HOST:-0.0.0.0}"
DASHBOARD_PORT="${SNORT_DASHBOARD_PORT:-8888}"
DASHBOARD_ENTRY="${DASHBOARD_ENTRY:-$PROJECT_DIR/server.py}"

install_packages_if_possible() {
  if command -v apt-get >/dev/null 2>&1; then
    echo "[setup] Installing runtime packages with apt..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y python3 curl lsof
    return
  fi

  if command -v dnf >/dev/null 2>&1; then
    echo "[setup] Installing runtime packages with dnf..."
    dnf install -y python3 curl lsof
    return
  fi

  if command -v yum >/dev/null 2>&1; then
    echo "[setup] Installing runtime packages with yum..."
    yum install -y python3 curl lsof
    return
  fi

  echo "[setup] No supported package manager found. Skipping package installation."
}

require_file() {
  local path="$1"
  local label="$2"
  if [[ ! -e "$path" ]]; then
    echo "[error] Missing $label: $path"
    exit 1
  fi
}

cleanup() {
  echo
  echo "[shutdown] Stopping background services..."
  if [[ -n "${DASHBOARD_PID:-}" ]] && kill -0 "$DASHBOARD_PID" 2>/dev/null; then
    kill "$DASHBOARD_PID" 2>/dev/null || true
  fi
  if [[ -n "${SNORT_PID:-}" ]] && kill -0 "$SNORT_PID" 2>/dev/null; then
    kill "$SNORT_PID" 2>/dev/null || true
  fi
}

if [[ "${EUID}" -ne 0 ]]; then
  echo "[error] Run this script with sudo so it can write Snort logs and start Snort."
  echo "        Example: sudo bash scripts/setup_and_run.sh"
  exit 1
fi

trap cleanup EXIT INT TERM

echo "[setup] Project directory: $PROJECT_DIR"
install_packages_if_possible

require_file "$SNORT_BIN" "Snort binary"
require_file "$SNORT_CONF" "Snort config"
require_file "$DASHBOARD_ENTRY" "dashboard entrypoint"

mkdir -p "$SNORT_LOG_DIR"
touch "$SNORT_RULES"

echo "[setup] Using interface: $SNORT_INTERFACE"
echo "[setup] Rules file: $SNORT_RULES"
echo "[setup] Alert log dir: $SNORT_LOG_DIR"

export SNORT_ALERT_FILE="$SNORT_LOG_DIR/alert_fast.txt"
export SNORT_RULES_FILE="$SNORT_RULES"
export SNORT_DASHBOARD_HOST="$DASHBOARD_HOST"
export SNORT_DASHBOARD_PORT="$DASHBOARD_PORT"
export SNORT_INTERFACE

echo "[run] Starting Snort..."
"$SNORT_BIN" \
  --daq afpacket \
  -i "$SNORT_INTERFACE" \
  -c "$SNORT_CONF" \
  -l "$SNORT_LOG_DIR" \
  -A alert_fast \
  --lua "alert_fast = { file = true }" &
SNORT_PID=$!

sleep 2

if ! kill -0 "$SNORT_PID" 2>/dev/null; then
  echo "[error] Snort exited immediately. Check the output above."
  exit 1
fi

echo "[run] Starting dashboard on http://localhost:$DASHBOARD_PORT ..."
python3 "$DASHBOARD_ENTRY" &
DASHBOARD_PID=$!

sleep 1

if ! kill -0 "$DASHBOARD_PID" 2>/dev/null; then
  echo "[error] Dashboard exited immediately. Check the output above."
  exit 1
fi

echo "[ready] Snort PID: $SNORT_PID"
echo "[ready] Dashboard PID: $DASHBOARD_PID"
echo "[ready] Open http://localhost:$DASHBOARD_PORT"
echo "[ready] Press Ctrl+C to stop both services."

wait "$DASHBOARD_PID"
