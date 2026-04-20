import itertools
import re
import time


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

alert_id_counter = itertools.count(int(time.time() * 1000))


def categorize(msg):
    msg_lower = msg.lower()
    for keyword, category in CATEGORY_MAP.items():
        if keyword in msg_lower:
            return category
    return "Other"


def severity_from_priority(priority):
    numeric_priority = int(priority)
    if numeric_priority <= 1:
        return "critical"
    if numeric_priority == 2:
        return "high"
    if numeric_priority == 3:
        return "medium"
    return "low"


def parse_line(line):
    line = line.strip()
    if not line:
        return None

    match = ALERT_RE.match(line)
    if not match:
        return None

    data = match.groupdict()
    return {
        "id": next(alert_id_counter),
        "timestamp": data["timestamp"],
        "sid": f"{data['gid']}:{data['sid']}:{data['rev']}",
        "msg": data["msg"],
        "priority": int(data.get("priority") or 4),
        "severity": severity_from_priority(data.get("priority") or 4),
        "proto": data["proto"],
        "src": data["src"],
        "sport": data.get("sport") or "",
        "dst": data["dst"],
        "dport": data.get("dport") or "",
        "category": categorize(data["msg"]),
        "classification": data.get("classification") or "",
        "raw": line,
    }

