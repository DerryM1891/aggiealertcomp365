import json
import os
import sys
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from fastapi.testclient import TestClient  # noqa: E402

import llm_pipeline as lp  # noqa: E402
from tests.test_core import FakeClient, GOOD  # noqa: E402

import server.main as main  # noqa: E402


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """API with an empty temp LLM cache, so tests never touch the real saved results."""
    monkeypatch.setattr(main.svc, "store", lp.LLMStore(str(tmp_path)))
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    return TestClient(main.app)


@pytest.fixture()
def live(monkeypatch):
    fake = FakeClient([json.dumps(GOOD)])
    monkeypatch.setattr(lp, "live_available", lambda: True)
    monkeypatch.setattr(lp, "get_client", lambda: fake)
    return fake


def test_health(client):
    h = client.get("/api/health").json()
    assert h["alerts"] == 519 and h["eval_subset"] == 41 and h["llm_live"] is False
    assert h["prompt_versions"] == ["v1", "v2", "v3"]


def test_list_filter_sort_page(client):
    r = client.get("/api/alerts", params={"limit": 5}).json()
    assert r["total"] == 519 and len(r["items"]) == 5
    assert r["items"][0]["rule"] == "Critical"  # most severe first
    sev = client.get("/api/alerts", params={"severity": "Low", "limit": 1000}).json()
    assert sev["total"] == 22 and all(a["rule"] == "Low" for a in sev["items"])
    ip = client.get("/api/alerts", params={"source_ip": "187.141.143.180", "limit": 1000}).json()
    assert ip["total"] == 80
    page2 = client.get("/api/alerts", params={"limit": 5, "offset": 5}).json()["items"]
    assert page2[0]["alert_id"] != r["items"][0]["alert_id"]
    asc = client.get("/api/alerts", params={"sort": "timestamp", "order": "asc", "limit": 2}).json()["items"]
    assert asc[0]["timestamp"] <= asc[1]["timestamp"]


def test_validation_errors(client):
    assert client.get("/api/alerts", params={"limit": 0}).status_code == 422
    assert client.get("/api/alerts", params={"rank_by": "bogus"}).status_code == 422
    assert client.get("/api/alerts/NOPE").status_code == 404
    assert client.post("/api/triage", json={"raw_lines": []}).status_code == 422
    assert client.post("/api/triage", json={"raw_lines": ["x" * 501]}).status_code == 422


def test_alert_detail_has_log_and_rule_reasoning(client):
    a = client.get("/api/alerts/A24659").json()
    assert a["truth"] == "Medium" and a["truth_v1"] == "Low" and a["rule"] == "Medium"
    assert any("Failed password for mysql" in l for l in a["raw_content"])
    assert "valid_account" in a["rule_detail"]["matched_signatures"]


def test_stats_sum_to_total(client):
    s = client.get("/api/stats").json()
    assert sum(s["severity"].values()) == s["total"] == 519
    assert s["severity"]["Medium"] == 128
    assert sum(sum(b[l] for l in lp.LEVELS) for b in s["timeline"]) == 519


def test_report_csv_is_ranked(client):
    lines = client.get("/api/report.csv").text.strip().splitlines()
    assert lines[0].startswith("rank,alert_id") and len(lines) == 520
    assert lines[1].split(",")[5] == "Critical"


def test_adhoc_triage_rule_only(client):
    r = client.post("/api/triage", json={"raw_lines": ["Failed password for root from 9.9.9.9 port 22 ssh2"]}).json()
    assert r["rule"]["rule_based_severity"] == "High" and r["rubric_label"] == "High" and r["llm"] is None


def test_llm_endpoints_without_key_return_503(client):
    assert client.post("/api/alerts/A24659/triage", json={"prompt": "v2"}).status_code == 503
    assert client.post("/api/triage", json={"raw_lines": ["x"], "use_llm": True}).status_code == 503
    assert client.post("/api/llm/batch", json={}).status_code == 503


def test_live_triage_caches_result(client, live):
    r = client.post("/api/alerts/A24659/triage", json={"prompt": "v2"}).json()
    assert r["cached"] is False and r["llm"] == "Medium" and r["llm_detail"]["meta"]["source"] == "api_live"
    assert 0 <= r["llm_detail"]["quality"]["quality_score"] <= 3
    again = client.post("/api/alerts/A24659/triage", json={"prompt": "v2"}).json()
    assert again["cached"] is True and live.calls == 1
    forced = client.post("/api/alerts/A24659/triage", json={"prompt": "v2", "force": True}).json()
    assert forced["cached"] is False and live.calls == 2


def test_bad_model_output_is_502(client, monkeypatch):
    monkeypatch.setattr(lp, "get_client", lambda: FakeClient(["nope"]))
    assert client.post("/api/alerts/A24659/triage", json={"prompt": "v2"}).status_code == 502


def test_batch_runs_in_background_and_feeds_evaluation(client, live):
    r = client.post("/api/llm/batch", json={"prompt": "v2", "scope": "subset", "limit": 8, "workers": 2})
    assert r.status_code == 202
    for _ in range(100):
        st = client.get("/api/llm/batch").json()
        if not st["running"]:
            break
        time.sleep(0.05)
    assert st["stats"]["done"] == 8 and st["stats"]["failed"] == 0
    ev = client.get("/api/evaluation", params={"prompt": "v2", "rubric": "v2"}).json()
    assert ev["llm_covered_ids"] == 8 and ev["provenance"] == {"api_live": 8}
    assert ev["llm"]["n"] == 8 and ev["rule_based_full"]["n"] == 519
    cov = client.get("/api/health").json()["llm_coverage"]["v2"]
    assert cov["total"] == 8


def test_evaluation_reproduces_checkpoint_2(monkeypatch):
    """The saved Checkpoint 2 results must still give kappa 0.92 under the old rubric."""
    monkeypatch.setattr(main.svc, "store", lp.LLMStore())
    v1 = main.svc.evaluation("v1", "v1", "subset")
    assert v1["llm"]["n"] == 41 and v1["llm"]["accuracy"] == pytest.approx(0.9512, abs=1e-3)
    assert v1["llm"]["cohen_kappa"] == pytest.approx(0.92, abs=0.006)
    assert {d["alert_id"] for d in v1["disagreements"]} == {"A24659", "A24661"}
    v2 = main.svc.evaluation("v2", "v1", "subset")
    assert v2["llm"]["accuracy"] == 1.0 and v2["rule_based_on_llm_ids"]["accuracy"] == 1.0
