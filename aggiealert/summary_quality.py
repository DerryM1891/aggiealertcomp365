"""
AggieAlert - automated summary-quality scoring (rubric_summary_quality.md v2).

The proposal named subjective scoring as the project's greatest risk. v1 of the
rubric was applied by hand during generation. v2 is fully automated and
reproducible: each of the three binary criteria is a deterministic check against
the raw log lines, so the same score comes out on every run and on live API output.

Criteria (0/1 each, total 0-3):
  entity_extraction   source_ip and target_user match what is in the raw lines
                      (or are null when absent).
  actionable          The rationale (and next_action, when the prompt version has
                      one) cites concrete evidence from this alert, and next_action
                      is a non-empty step that is not just the severity label.
  no_hallucination    No IP absent from the raw lines, no count that does not match
                      the log, no claim of a successful login without an accepted
                      password line, and no user token that is not in the log.
"""
import re

IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
USER_RE = re.compile(r"(?:Invalid user|invalid user|for invalid user|Accepted password for|Failed password for) (\S+)")
EVIDENCE_PATTERNS = [
    r"failed password", r"invalid user", r"accepted password", r"break-?in", r"repeated",
    r"reverse (?:dns|mapping)", r"session (?:opened|closed)", r"preauth", r"authentication failure",
    r"unknown (?:user|account|username)", r"non-?existent", r"existing account", r"valid account",
    r"connection (?:closed|reset)", r"no authentication", r"disconnect",
]
SEVERITY_ONLY = re.compile(r"^\W*(?:low|medium|high|critical)(?: severity| risk)?\W*$", re.I)
SUCCESS_CLAIM = re.compile(r"\b(?:successful(?:ly)?|accepted|logged in|authenticated)\b", re.I)
NEGATED_SUCCESS = re.compile(r"\b(?:no|not|never|without|unsuccessful|failed|fail)\b[^.]{0,40}\b(?:successful(?:ly)?|accepted|logged in|authenticated)\b", re.I)


def _facts(alert):
    raw = alert["raw_content"]
    text = " | ".join(raw)
    users = set(USER_RE.findall(text))
    counts = {int(m) for m in re.findall(r"message repeated (\d+) times", text, re.I)}
    counts.add(sum(1 for l in raw if "Failed password" in l))
    return {
        "text": text,
        "ips": set(IP_RE.findall(text)),
        "users": users,
        "counts": counts,
        "has_accept": "Accepted password" in text,
    }


def _norm(v):
    return None if v in (None, "", "null", "None") else str(v)


def check_entities(alert, out):
    f = _facts(alert)
    detail = []
    ip = _norm(out.get("source_ip"))
    user = _norm(out.get("target_user"))
    if ip is None and f["ips"]:
        detail.append("source_ip is null but the log contains an IP")
    if ip is not None and ip not in f["ips"]:
        detail.append(f"source_ip {ip} not in log")
    if user is None and f["users"]:
        detail.append("target_user is null but the log names a user")
    if user is not None and user not in f["users"] and user not in f["text"]:
        detail.append(f"target_user {user} not in log")
    return (0 if detail else 1), "; ".join(detail) or None


def check_actionable(alert, out):
    prose = " ".join(str(out.get(k) or "") for k in ("rationale", "next_action", "summary")).lower()
    f = _facts(alert)
    cites = any(re.search(p, prose) for p in EVIDENCE_PATTERNS)
    cites = cites or any(u.lower() in prose for u in f["users"]) or any(ip in prose for ip in f["ips"])
    rationale = str(out.get("rationale") or "").strip()
    if not rationale or SEVERITY_ONLY.match(rationale) or not cites:
        return 0, "rationale does not cite evidence from the alert"
    if "next_action" in out:
        na = str(out.get("next_action") or "").strip()
        if len(na.split()) < 3 or SEVERITY_ONLY.match(na):
            return 0, "next_action is empty or just a severity label"
    return 1, None


def check_hallucination(alert, out):
    f = _facts(alert)
    prose = " ".join(str(out.get(k) or "") for k in ("summary", "rationale", "next_action"))
    problems = []
    for ip in IP_RE.findall(prose):
        if ip not in f["ips"]:
            problems.append(f"IP {ip} not in log")
    for n, noun in re.findall(r"\b(\d+)\s+(?:failed\s+)?(attempts?|times|failures?|logins?)\b", prose, re.I):
        if int(n) not in f["counts"] and int(n) != 1:
            problems.append(f"count {n} {noun} not supported by log")
    if SUCCESS_CLAIM.search(prose) and not f["has_accept"] and not NEGATED_SUCCESS.search(prose):
        problems.append("claims a successful login but no Accepted password line")
    user = _norm(out.get("target_user"))
    if user and user not in f["text"]:
        problems.append(f"user {user} not in log")
    return (0 if problems else 1), "; ".join(problems) or None


def score_summary(alert, out):
    e, e_d = check_entities(alert, out)
    a, a_d = check_actionable(alert, out)
    h, h_d = check_hallucination(alert, out)
    return {
        "alert_id": alert["alert_id"],
        "entity_extraction": e,
        "actionable": a,
        "no_hallucination": h,
        "quality_score": e + a + h,
        "detail": {k: v for k, v in (("entity", e_d), ("actionable", a_d), ("hallucination", h_d)) if v},
    }
