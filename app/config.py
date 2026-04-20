from pathlib import Path
import os


PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_DIR.parent
TEMPLATES_DIR = PACKAGE_DIR / "templates"
STATIC_DIR = PACKAGE_DIR / "static"
INDEX_FILE = TEMPLATES_DIR / "index.html"

ALERT_FILE = os.environ.get("SNORT_ALERT_FILE", "/var/log/snort/alert_fast.txt")
RULES_FILE = os.environ.get("SNORT_RULES_FILE", "/usr/local/snort/etc/snort/rules/local.rules")
HOST = os.environ.get("SNORT_DASHBOARD_HOST", "0.0.0.0")
PORT = int(os.environ.get("SNORT_DASHBOARD_PORT", "8888"))
INTERFACE = os.environ.get("SNORT_INTERFACE", "eth0")

