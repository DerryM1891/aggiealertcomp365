"""
AggieAlert - evaluation (proposal measures 1 and 2).

Measure 1: severity-classification agreement (accuracy, Cohen's kappa) of the
rule-based baseline and of the LLM against rubric ground truth, compared on the
SAME alerts. Reported under rubric v1 (Checkpoint 2) and v2 (valid-account fix).
Measure 2: summary quality against the automated 3-point rubric (summary_quality.py).

Usage:  python evaluate.py            # prints the tables, writes data/evaluation_summary_final.json
"""
import json
import os

import metrics
from summary_quality import score_summary

HERE = os.path.dirname(os.path.abspath(__file__))
PROMPT_VERSIONS = ["v1", "v2", "v3"]


def gt_field(rubric):
    return "ground_truth_severity_v1" if rubric == "v1" else "ground_truth_severity"


def evaluate(alerts, rule, llm_records, rubric="v2", ids=None):
    """
    alerts: {alert_id: alert}  rule: {alert_id: severity}  llm_records: {alert_id: {"result", "meta"}}
    ids: restrict the LLM comparison to these alert ids (default: every alert with an LLM result).
    """
    field = gt_field(rubric)
    all_ids = list(alerts)
    covered = [i for i in (ids if ids is not None else all_ids) if i in llm_records]

    out = {
        "rubric": rubric,
        "rule_based_full": metrics.report([alerts[i][field] for i in all_ids], [rule[i] for i in all_ids]),
        "llm_covered_ids": len(covered),
        "rule_based_on_llm_ids": None,
        "llm": None,
        "disagreements": [],
        "summary_quality": None,
        "provenance": {},
    }
    if not covered:
        return out

    y_true = [alerts[i][field] for i in covered]
    y_rule = [rule[i] for i in covered]
    y_llm = [llm_records[i]["result"]["severity"] for i in covered]
    out["rule_based_on_llm_ids"] = metrics.report(y_true, y_rule)
    out["llm"] = metrics.report(y_true, y_llm)

    for i, t, r, l in zip(covered, y_true, y_rule, y_llm):
        if l != t or r != l:
            out["disagreements"].append({
                "alert_id": i, "target_user": alerts[i]["target_user"],
                "ground_truth": t, "rule_based": r, "llm": l,
                "llm_rationale": llm_records[i]["result"].get("rationale"),
            })

    scores = [score_summary(alerts[i], llm_records[i]["result"]) for i in covered]
    n = len(scores)
    out["summary_quality"] = {
        "n": n,
        "average": round(sum(s["quality_score"] for s in scores) / n, 3),
        "entity_extraction": round(sum(s["entity_extraction"] for s in scores) / n, 3),
        "actionable": round(sum(s["actionable"] for s in scores) / n, 3),
        "no_hallucination": round(sum(s["no_hallucination"] for s in scores) / n, 3),
        "failures": [s for s in scores if s["quality_score"] < 3],
    }
    for i in covered:
        src = llm_records[i]["meta"]["source"]
        out["provenance"][src] = out["provenance"].get(src, 0) + 1
    return out


def load_all():
    alerts = {a["alert_id"]: a for a in json.load(open(os.path.join(HERE, "data", "alerts_labeled_full.json")))}
    rule = {r["alert_id"]: r["rule_based_severity"]
            for r in json.load(open(os.path.join(HERE, "data", "rule_based_results_full.json")))}
    subset = [a["alert_id"] for a in json.load(open(os.path.join(HERE, "data", "alerts_llm_sample.json")))]
    return alerts, rule, subset


def load_llm(version):
    try:
        return json.load(open(os.path.join(HERE, "data", "llm", f"{version}.json")))
    except FileNotFoundError:
        return {}


def _row(name, rep):
    if not rep:
        return f"  {name:<34} -"
    return f"  {name:<34} n={rep['n']:<4} accuracy={rep['accuracy']:.2f}  kappa={rep['cohen_kappa']:.2f}"


def main():
    alerts, rule, subset = load_all()
    results = {}
    for rubric in ("v1", "v2"):
        for version in PROMPT_VERSIONS:
            llm = load_llm(version)
            if not llm:
                continue
            res = evaluate(alerts, rule, llm, rubric)
            results[f"rubric_{rubric}__prompt_{version}"] = res
            print(f"\n=== rubric {rubric} | prompt {version} | LLM results on {res['llm_covered_ids']} alerts {res['provenance']}")
            print(_row("Rule-based, all alerts", res["rule_based_full"]))
            print(_row("Rule-based, same alerts as LLM", res["rule_based_on_llm_ids"]))
            print(_row("LLM (Gemini)", res["llm"]))
            sq = res["summary_quality"]
            print(f"  Summary quality: {sq['average']:.2f}/3  (entities {sq['entity_extraction']:.2f}, "
                  f"actionable {sq['actionable']:.2f}, no-hallucination {sq['no_hallucination']:.2f})")
            for d in res["disagreements"]:
                print(f"  disagree {d['alert_id']} user={d['target_user']}: truth={d['ground_truth']} "
                      f"rule={d['rule_based']} llm={d['llm']}")
    path = os.path.join(HERE, "data", "evaluation_summary_final.json")
    json.dump(results, open(path, "w"), indent=2)
    print(f"\nSaved -> {os.path.relpath(path, HERE)}")


if __name__ == "__main__":
    main()
