"""
AggieAlert - rubric-based ground truth labels.

v1 is the Checkpoint 1/2 rubric. v2 closes the "valid account" blind spot found in
Checkpoint 2: a failed password for an account that actually exists (no "invalid user"
tag, e.g. mysql, uucp, ftp) is not the same as a probe of a non-existent username,
and v1 silently labeled it Low.

Both functions work on the structured fields extracted by group_alerts.py, so the
labels are deterministic and reproducible. See rubric.md.
"""
import json
from collections import Counter

LEVELS = ["Low", "Medium", "High", "Critical"]


def label_v1(a):
    if a["accepted_login"]:
        return "Critical"
    if a["repeated_failures_count"] or (a["failed_password"] and a["target_user"] == "root"):
        return "High"
    if a["invalid_user_flag"]:
        return "Medium"
    return "Low"


def targets_valid_account(a):
    """Failed password against an account that exists (no invalid-user tag), not root."""
    return bool(
        a["failed_password"]
        and not a["invalid_user_flag"]
        and not a["accepted_login"]
        and a["target_user"]
        and a["target_user"] != "root"
    )


def label_v2(a):
    if a["accepted_login"]:
        return "Critical"
    if a["repeated_failures_count"] or (a["failed_password"] and a["target_user"] == "root"):
        return "High"
    if a["invalid_user_flag"] or targets_valid_account(a):
        return "Medium"
    return "Low"


def relabel(path_in, path_out):
    alerts = json.load(open(path_in))
    for a in alerts:
        a["ground_truth_severity_v1"] = label_v1(a)
        a["ground_truth_severity"] = label_v2(a)
        a["valid_account_flag"] = targets_valid_account(a)
    json.dump(alerts, open(path_out, "w"), indent=2)
    return alerts


if __name__ == "__main__":
    full = relabel("data/alerts_full.json", "data/alerts_labeled_full.json")
    print("Rubric v1:", dict(Counter(a["ground_truth_severity_v1"] for a in full)))
    print("Rubric v2:", dict(Counter(a["ground_truth_severity"] for a in full)))
    changed = [a for a in full if a["ground_truth_severity_v1"] != a["ground_truth_severity"]]
    print(f"{len(changed)} of {len(full)} alerts change label under v2:")
    for a in changed:
        print(f"  {a['alert_id']} user={a['target_user']} {a['ground_truth_severity_v1']} -> {a['ground_truth_severity']}")

    # keep the 41-alert evaluation subset in sync with the full labels
    by_id = {a["alert_id"]: a for a in full}
    sample = json.load(open("data/alerts_llm_sample.json"))
    synced = [by_id[s["alert_id"]] for s in sample]
    json.dump(synced, open("data/alerts_llm_sample.json", "w"), indent=2)
    print(f"Synced {len(synced)}-alert evaluation subset")
