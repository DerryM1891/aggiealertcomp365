"""
AggieAlert - build a structured alert from raw sshd log lines.

Same field extraction as group_alerts.py, but starting from plain log strings, so
the API can accept a pasted alert. tests/test_parser.py checks that it reproduces
every one of the 519 dataset alerts.
"""
import re

IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
USER_RE = re.compile(r"(?:Invalid user|for invalid user|Accepted password for|Failed password for) (\S+)")
REPEAT_RE = re.compile(r"message repeated (\d+) times")


def build_alert(lines, alert_id="ADHOC", timestamp=None, host=None):
    content_all = " | ".join(lines)
    ips = IP_RE.findall(content_all)
    users = USER_RE.findall(content_all)
    repeated = None
    for l in lines:
        m = REPEAT_RE.search(l)
        if m:
            repeated = int(m.group(1))
    return {
        "alert_id": alert_id,
        "timestamp": timestamp,
        "dest_host": host,
        "source_ip": ips[0] if ips else None,
        "target_user": users[0] if users else None,
        "accepted_login": any("Accepted password" in l for l in lines),
        "invalid_user_flag": any("Invalid user" in l for l in lines),
        "failed_password": any("Failed password" in l for l in lines),
        "possible_breakin_flag": any("POSSIBLE BREAK-IN ATTEMPT" in l for l in lines),
        "repeated_failures_count": repeated,
        "raw_content": list(lines),
    }
