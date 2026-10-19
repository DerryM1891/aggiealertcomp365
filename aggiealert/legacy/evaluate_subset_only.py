import json
from sklearn.metrics import cohen_kappa_score, accuracy_score, confusion_matrix

LEVELS = ["Low", "Medium", "High", "Critical"]

gt_alerts = {a["alert_id"]: a["ground_truth_severity"] for a in json.load(open("data/alerts_labeled.json"))}
rule = {r["alert_id"]: r["rule_based_severity"] for r in json.load(open("data/rule_based_results.json"))}
llm = {r["alert_id"]: r["severity"] for r in json.load(open("data/llm_results.json"))}

ids = list(gt_alerts.keys())
y_true = [gt_alerts[i] for i in ids]
y_rule = [rule[i] for i in ids]
y_llm = [llm[i] for i in ids]

def report(name, y_pred):
    acc = accuracy_score(y_true, y_pred)
    kappa = cohen_kappa_score(y_true, y_pred, labels=LEVELS)
    print(f"\n{name} vs ground truth")
    print(f"  Accuracy: {acc:.2f}")
    print(f"  Cohen's kappa: {kappa:.2f}")
    print(f"  Confusion matrix (rows=ground truth, cols=predicted), order {LEVELS}:")
    cm = confusion_matrix(y_true, y_pred, labels=LEVELS)
    for row_label, row in zip(LEVELS, cm):
        print(f"    {row_label:8s} {row}")
    return {"accuracy": acc, "cohen_kappa": kappa}

results = {
    "rule_based": report("Rule-based baseline", y_rule),
    "llm": report("LLM (Claude)", y_llm),
}

json.dump(results, open("data/evaluation_summary.json", "w"), indent=2)
print("\nSaved -> data/evaluation_summary.json")
