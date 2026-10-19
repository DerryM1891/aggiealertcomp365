import csv, re, json
from collections import defaultdict

rows = []
with open('/home/claude/loghub/OpenSSH/OpenSSH_2k.log_structured.csv', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    for r in reader:
        rows.append(r)

# Group consecutive lines by Pid (one sshd child process = one connection attempt)
groups = defaultdict(list)
order = []
for r in rows:
    pid = r['Pid']
    if pid not in groups:
        order.append(pid)
    groups[pid].append(r)

ip_re = re.compile(r'\b\d{1,3}(?:\.\d{1,3}){3}\b')
user_re = re.compile(r'(?:Invalid user|for invalid user|Accepted password for|Failed password for) (\S+)')

alerts = []
for pid in order:
    lines = groups[pid]
    content_all = " | ".join(r['Content'] for r in lines)
    event_ids = [r['EventId'] for r in lines]
    ips = ip_re.findall(content_all)
    users = user_re.findall(content_all)
    ts = f"Dec {lines[0]['Day']} {lines[0]['Time']}"

    accepted = any('Accepted password' in r['Content'] for r in lines)
    invalid_user = any('Invalid user' in r['Content'] for r in lines)
    failed = any('Failed password' in r['Content'] for r in lines)
    breakin_flag = any('POSSIBLE BREAK-IN ATTEMPT' in r['Content'] for r in lines)
    repeated = None
    for r in lines:
        m = re.search(r'message repeated (\d+) times', r['Content'])
        if m:
            repeated = int(m.group(1))

    alerts.append({
        "alert_id": f"A{pid}",
        "timestamp": ts,
        "dest_host": lines[0]['Component'],
        "pid": pid,
        "source_ip": ips[0] if ips else None,
        "target_user": users[0] if users else None,
        "accepted_login": accepted,
        "invalid_user_flag": invalid_user,
        "failed_password": failed,
        "possible_breakin_flag": breakin_flag,
        "repeated_failures_count": repeated,
        "event_ids": event_ids,
        "raw_content": [r['Content'] for r in lines],
    })

with open('data/alerts_full.json', 'w') as f:
    json.dump(alerts, f, indent=2)

print(f"Grouped {len(rows)} raw lines into {len(alerts)} alert-level records")
print("Sample alert:")
print(json.dumps(alerts[0], indent=2))
