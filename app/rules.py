import json
from pathlib import Path
import re


RULE_LINE_RE = re.compile(r"^\s*(alert|log|pass|drop|reject)\b")
SID_RE = re.compile(r"\bsid:(\d+)\b")
MSG_RE = re.compile(r'msg:"([^"]*)"')


def read_json_body(handler):
    content_length = int(handler.headers.get("Content-Length", "0") or 0)
    if content_length <= 0:
        return None
    raw_body = handler.rfile.read(content_length)
    if not raw_body:
        return None
    return json.loads(raw_body.decode("utf-8"))


def sanitize_rule_token(value, fallback="any"):
    token = (value or "").strip()
    if not token:
        return fallback
    if not re.fullmatch(r"[A-Za-z0-9_:\./\-\[\]!$]+", token):
        raise ValueError(f"Invalid token: {value}")
    return token


def sanitize_msg(value):
    msg = (value or "").strip()
    if not msg:
        raise ValueError("Rule message is required")
    if '"' in msg:
        raise ValueError('Rule message cannot contain double quotes')
    return msg


def sanitize_sid(value):
    sid = int(value)
    if sid <= 0:
        raise ValueError("SID must be a positive integer")
    return sid


def build_rule(payload):
    action = sanitize_rule_token(payload.get("action"), "alert")
    proto = sanitize_rule_token(payload.get("proto"), "tcp").lower()
    src_net = sanitize_rule_token(payload.get("src_net"), "any")
    src_port = sanitize_rule_token(payload.get("src_port"), "any")
    direction = (payload.get("direction") or "->").strip()
    if direction not in {"->", "<>"}:
        raise ValueError("Direction must be -> or <>")
    dst_net = sanitize_rule_token(payload.get("dst_net"), "any")
    dst_port = sanitize_rule_token(payload.get("dst_port"), "any")
    msg = sanitize_msg(payload.get("msg"))
    sid = sanitize_sid(payload.get("sid"))
    rev = int(payload.get("rev") or 1)
    if rev <= 0:
        raise ValueError("Revision must be a positive integer")

    options = [f'msg:"{msg}"', f"sid:{sid}", f"rev:{rev}"]

    classtype = (payload.get("classtype") or "").strip()
    if classtype:
        options.append(f"classtype:{sanitize_rule_token(classtype, classtype)}")

    priority = (payload.get("priority") or "").strip()
    if priority:
        priority_value = int(priority)
        if priority_value <= 0:
            raise ValueError("Priority must be a positive integer")
        options.append(f"priority:{priority_value}")

    content = (payload.get("content") or "").strip()
    if content:
        if '"' in content:
            raise ValueError('Content cannot contain double quotes')
        options.append(f'content:"{content}"')

    metadata = (payload.get("metadata") or "").strip()
    if metadata:
        options.append(f"metadata:{metadata}")

    return (
        f"{action} {proto} {src_net} {src_port} {direction} {dst_net} {dst_port} "
        f"({'; '.join(options)};)"
    )


def append_rule(rule, rules_file):
    rules_path = Path(rules_file)
    rules_path.parent.mkdir(parents=True, exist_ok=True)
    existing = rules_path.read_text(encoding="utf-8", errors="replace") if rules_path.exists() else ""

    sid_match = re.search(r"\bsid:(\d+)\b", rule)
    if sid_match and re.search(rf"\bsid:{re.escape(sid_match.group(1))}\b", existing):
        raise ValueError(f"SID {sid_match.group(1)} already exists in {rules_path}")

    with open(rules_path, "a", encoding="utf-8") as handle:
        if existing and not existing.endswith("\n"):
            handle.write("\n")
        handle.write(rule.rstrip() + "\n")


def list_rules(rules_file):
    rules_path = Path(rules_file)
    if not rules_path.exists():
        return []

    rules = []
    for line_number, raw_line in enumerate(
        rules_path.read_text(encoding="utf-8", errors="replace").splitlines(),
        start=1,
    ):
        line = raw_line.strip()
        if not line or line.startswith("#") or not RULE_LINE_RE.match(line):
            continue

        sid_match = SID_RE.search(line)
        if not sid_match:
            continue

        msg_match = MSG_RE.search(line)
        rules.append(
            {
                "sid": sid_match.group(1),
                "msg": msg_match.group(1) if msg_match else "",
                "line": raw_line,
                "line_number": line_number,
            }
        )

    return rules


def delete_rule_by_sid(sid, rules_file):
    target_sid = sanitize_sid(sid)
    rules_path = Path(rules_file)
    if not rules_path.exists():
        raise ValueError(f"Rules file not found: {rules_path}")

    lines = rules_path.read_text(encoding="utf-8", errors="replace").splitlines()
    kept_lines = []
    removed_line = None

    for line in lines:
        sid_match = SID_RE.search(line)
        if sid_match and int(sid_match.group(1)) == target_sid and removed_line is None:
            removed_line = line
            continue
        kept_lines.append(line)

    if removed_line is None:
        raise ValueError(f"Rule with SID {target_sid} was not found")

    updated_content = "\n".join(kept_lines)
    if kept_lines:
        updated_content += "\n"
    rules_path.write_text(updated_content, encoding="utf-8")

    return removed_line


def reload_hint():
    return "Rule saved. Reload or restart Snort for the new rule to take effect."
