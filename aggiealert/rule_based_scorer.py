"""
AggieAlert - rule-based (non-AI) severity baseline.

Scores an alert using keyword/signature matching directly over the raw log
lines, independent of the structured ground-truth fields, so it is a genuine
baseline rather than a restatement of the rubric.

v2 adds the valid_account signature: "Failed password for <user>" with no
"invalid user" tag and a non-root user means the account exists.
"""
import json
import re

KEYWORDS = {
    "accepted": re.compile(r"\bAccepted password\b", re.I),
    "failed": re.compile(r"\bFailed password\b", re.I),
    "invalid_user": re.compile(r"\bInvalid user\b", re.I),
    "root_target": re.compile(r"\bfor root\b", re.I),
    "repeated": re.compile(r"message repeated (\d+) times", re.I),
    "breakin": re.compile(r"POSSIBLE BREAK-IN ATTEMPT", re.I),
    "valid_account": re.compile(r"\bFailed password for (?!invalid user\b)(?!root\b)\S+", re.I),
}


def score_alert(raw_lines):
    """Return (severity, matched_signatures, rationale) for one alert's raw log lines."""
    text = " | ".join(raw_lines)
    matched = [name for name, pat in KEYWORDS.items() if pat.search(text)]

    if "accepted" in matched:
        return "Critical", matched, "Signature match: successful password authentication logged."

    if "repeated" in matched or ("failed" in matched and "root_target" in matched):
        return "High", matched, "Signature match: repeated failed logins or failed root login (brute-force pattern)."

    if "invalid_user" in matched:
        return "Medium", matched, "Signature match: authentication attempted against a non-existent account."

    if "valid_account" in matched:
        return "Medium", matched, "Signature match: failed password against an existing non-root account."

    return "Low", matched, "No authentication-failure or success signatures matched; likely benign connection/disconnect."


def score_record(a):
    severity, matched, rationale = score_alert(a["raw_content"])
    return {
        "alert_id": a["alert_id"],
        "source_ip": a["source_ip"],
        "target_user": a["target_user"],
        "rule_based_severity": severity,
        "matched_signatures": matched,
        "rationale": rationale,
    }


def run(path_in, path_out):
    results = [score_record(a) for a in json.load(open(path_in))]
    json.dump(results, open(path_out, "w"), indent=2)
    return results


if __name__ == "__main__":
    results = run("data/alerts_labeled_full.json", "data/rule_based_results_full.json")
    for r in results[:5]:
        print(r["alert_id"], "->", r["rule_based_severity"], r["matched_signatures"])
    print(f"\nScored {len(results)} alerts -> data/rule_based_results_full.json")
