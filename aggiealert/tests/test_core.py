import json
import os
import sys
import types

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import llm_pipeline as lp  # noqa: E402
import metrics  # noqa: E402
from alert_parser import build_alert  # noqa: E402
from ground_truth import label_v1, label_v2, targets_valid_account  # noqa: E402
from rule_based_scorer import score_alert  # noqa: E402
from summary_quality import score_summary  # noqa: E402


@pytest.fixture(scope="module")
def alerts():
    return json.load(open(os.path.join(ROOT, "data", "alerts_labeled_full.json")))


# ---------- metrics ----------
def test_metrics_match_sklearn(alerts):
    sk = pytest.importorskip("sklearn.metrics")
    y_true = [a["ground_truth_severity"] for a in alerts]
    y_pred = [a["ground_truth_severity_v1"] for a in alerts]  # imperfect on purpose
    assert metrics.accuracy(y_true, y_pred) == pytest.approx(sk.accuracy_score(y_true, y_pred))
    assert metrics.cohen_kappa(y_true, y_pred) == pytest.approx(
        sk.cohen_kappa_score(y_true, y_pred, labels=metrics.LEVELS))
    assert metrics.confusion(y_true, y_pred) == sk.confusion_matrix(y_true, y_pred, labels=metrics.LEVELS).tolist()


def test_kappa_edge_cases():
    assert metrics.cohen_kappa(["High"] * 4, ["High"] * 4) == 1.0
    assert metrics.cohen_kappa([], []) == 0.0


# ---------- ground truth ----------
def test_dataset_size_and_rubric_v2_change(alerts):
    assert len(alerts) == 519
    changed = [a for a in alerts if a["ground_truth_severity_v1"] != a["ground_truth_severity"]]
    assert len(changed) == 15
    assert all(a["ground_truth_severity_v1"] == "Low" and a["ground_truth_severity"] == "Medium" for a in changed)
    assert all(a["valid_account_flag"] for a in changed)
    assert {a["target_user"] for a in changed} == {"uucp", "ftp", "git", "sshd", "mysql"}


def test_labels_recompute(alerts):
    for a in alerts:
        assert label_v1(a) == a["ground_truth_severity_v1"]
        assert label_v2(a) == a["ground_truth_severity"]


def test_valid_account_rules():
    base = dict(accepted_login=False, invalid_user_flag=False, failed_password=True,
                repeated_failures_count=None, target_user="mysql")
    assert targets_valid_account(base) and label_v2(base) == "Medium" and label_v1(base) == "Low"
    assert label_v2({**base, "target_user": "root"}) == "High"
    assert label_v2({**base, "invalid_user_flag": True}) == "Medium"
    assert label_v2({**base, "repeated_failures_count": 3}) == "High"
    assert label_v2({**base, "accepted_login": True, "failed_password": False}) == "Critical"
    assert label_v2({**base, "failed_password": False}) == "Low"


# ---------- rule-based baseline ----------
def test_rule_scorer_matches_rubric_v2_on_all_alerts(alerts):
    wrong = [a["alert_id"] for a in alerts if score_alert(a["raw_content"])[0] != a["ground_truth_severity"]]
    assert wrong == []


def test_rule_scorer_uses_raw_lines_only():
    assert score_alert(["Failed password for mysql from 1.2.3.4 port 22 ssh2"])[0] == "Medium"
    assert score_alert(["Failed password for invalid user bob from 1.2.3.4 port 22 ssh2"])[0] == "Medium"
    assert score_alert(["Failed password for root from 1.2.3.4 port 22 ssh2"])[0] == "High"
    assert score_alert(["Accepted password for bob from 1.2.3.4 port 22 ssh2"])[0] == "Critical"
    assert score_alert(["Connection closed by 1.2.3.4 [preauth]"])[0] == "Low"


# ---------- parser ----------
def test_parser_reproduces_every_dataset_alert(alerts):
    keys = ["source_ip", "target_user", "accepted_login", "invalid_user_flag", "failed_password",
            "possible_breakin_flag", "repeated_failures_count"]
    for a in alerts:
        b = build_alert(a["raw_content"])
        assert {k: b[k] for k in keys} == {k: a[k] for k in keys}, a["alert_id"]


# ---------- summary quality (the checks must be able to fail) ----------
ALERT = build_alert([
    "Failed password for mysql from 203.0.113.9 port 4000 ssh2",
    "pam_unix(sshd:auth): authentication failure; rhost=203.0.113.9  user=mysql",
])
ALERT["alert_id"] = "T1"
GOOD = {"summary": "Failed password for mysql from 203.0.113.9.", "severity": "Medium",
        "rationale": "A failed password for the existing account mysql was logged.",
        "source_ip": "203.0.113.9", "target_user": "mysql", "attack_technique": "T1110",
        "next_action": "Check whether mysql allows remote password login and block 203.0.113.9."}


def test_quality_good_summary_scores_3():
    assert score_summary(ALERT, GOOD)["quality_score"] == 3


def test_quality_catches_wrong_entities():
    s = score_summary(ALERT, {**GOOD, "source_ip": "198.51.100.1", "target_user": "bob"})
    assert s["entity_extraction"] == 0


def test_quality_catches_hallucinated_ip_and_login():
    s = score_summary(ALERT, {**GOOD, "summary": "Attacker 198.51.100.7 successfully logged in."})
    assert s["no_hallucination"] == 0


def test_quality_catches_invented_count():
    s = score_summary(ALERT, {**GOOD, "rationale": "There were 14 failed attempts against mysql."})
    assert s["no_hallucination"] == 0


def test_quality_catches_generic_rationale_and_empty_action():
    s = score_summary(ALERT, {**GOOD, "rationale": "High severity"})
    assert s["actionable"] == 0
    s = score_summary(ALERT, {**GOOD, "next_action": "Monitor"})
    assert s["actionable"] == 0


# ---------- LLM pipeline with a fake client (no network) ----------
class FakeClient:
    def __init__(self, replies):
        self.replies, self.calls = list(replies), 0

    def generate(self, model, system, user):
        self.calls += 1
        return self.replies.pop(0) if len(self.replies) > 1 else self.replies[0]


V2_REPLY = json.dumps(GOOD)


def test_triage_parses_fenced_json_and_normalizes_severity():
    c = FakeClient(["```json\n" + json.dumps({**GOOD, "severity": "medium"}) + "\n```"])
    out = lp.triage_alert(ALERT, "v2", client=c)
    assert out["severity"] == "Medium"


def test_triage_retries_once_on_bad_json_then_succeeds():
    c = FakeClient(["not json at all", V2_REPLY])
    assert lp.triage_alert(ALERT, "v2", client=c)["target_user"] == "mysql"
    assert c.calls == 2


def test_triage_rejects_invalid_severity_and_missing_next_action():
    with pytest.raises(ValueError):
        lp.triage_alert(ALERT, "v2", client=FakeClient([json.dumps({**GOOD, "severity": "Urgent"})]))
    no_action = {k: v for k, v in GOOD.items() if k != "next_action"}
    with pytest.raises(ValueError):
        lp.triage_alert(ALERT, "v2", client=FakeClient([json.dumps(no_action)]))
    lp.triage_alert(ALERT, "v1", client=FakeClient([json.dumps(no_action)]))  # v1 has no next_action


def test_prompt_versions_differ_and_v1_hides_context():
    assert len({lp.SYSTEM_PROMPTS[v] for v in lp.PROMPT_VERSIONS}) == 3
    assert "Host:" not in lp.build_user_message(ALERT, "v1")
    assert "Host:" in lp.build_user_message(ALERT, "v2")
    assert "Severity definitions" in lp.SYSTEM_PROMPTS["v3"] and "Severity definitions" not in lp.SYSTEM_PROMPTS["v2"]


def test_batch_is_resumable_and_records_provenance(tmp_path, alerts):
    store = lp.LLMStore(str(tmp_path))
    subset = alerts[:6]
    # make the fake reply match each alert's real entities so it is valid for any alert
    c = FakeClient([V2_REPLY])
    stats = lp.run_batch(subset, "v2", store, workers=3, client=c)
    assert stats["done"] == 6 and stats["failed"] == 0 and c.calls == 6
    assert store.counts("v2") == {"api_live": 6}
    assert os.path.exists(tmp_path / "v2.json")
    stats = lp.run_batch(subset, "v2", store, workers=3, client=c)  # resume: nothing to do
    assert stats["total"] == 0 and c.calls == 6
    fresh = lp.LLMStore(str(tmp_path))  # reloads from disk
    assert fresh.get("v2", subset[0]["alert_id"])["meta"]["source"] == "api_live"


def test_batch_reports_failures_without_stopping(tmp_path, alerts):
    store = lp.LLMStore(str(tmp_path))
    c = FakeClient(["garbage"])
    stats = lp.run_batch(alerts[:3], "v2", store, workers=1, client=c)
    assert stats["failed"] == 3 and stats["done"] == 0 and len(stats["errors"]) == 3


def test_live_available_requires_key(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    assert lp.live_available() is False
    with pytest.raises(lp.LLMUnavailable):
        lp.get_client()
