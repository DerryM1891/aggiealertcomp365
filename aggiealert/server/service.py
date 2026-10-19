"""Data and triage logic behind the API (no web framework imports here)."""
import csv
import io
import json
import os
import threading
from collections import Counter, defaultdict

import evaluate as ev
import llm_pipeline as lp
import metrics
from alert_parser import build_alert
from ground_truth import label_v2, targets_valid_account
from rule_based_scorer import score_record
from summary_quality import score_summary

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RANK = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
LEVELS = metrics.LEVELS


class Service:
    def __init__(self, data_dir=None, cache_dir=None):
        data_dir = data_dir or os.path.join(HERE, "data")
        self.alerts = {a["alert_id"]: a for a in json.load(open(os.path.join(data_dir, "alerts_labeled_full.json")))}
        self.order = list(self.alerts)
        self.subset = [a["alert_id"] for a in json.load(open(os.path.join(data_dir, "alerts_llm_sample.json")))]
        self.rule = {i: score_record(a) for i, a in self.alerts.items()}
        self.store = lp.LLMStore(cache_dir or lp.CACHE_DIR)
        self.batch = {"running": False, "version": None, "stats": None, "stop": threading.Event()}
        self._batch_lock = threading.Lock()

    def best_version(self):
        cov = {v: len(self.store.load(v)) for v in lp.PROMPT_VERSIONS}
        top = max(cov.values())
        return [v for v in lp.PROMPT_VERSIONS if cov[v] == top][-1] if top else "v2"

    # ---------- views ----------
    def llm_record(self, alert_id, version):
        return self.store.get(version, alert_id)

    def alert_view(self, alert_id, version, detail=False):
        a = self.alerts[alert_id]
        rule = self.rule[alert_id]
        rec = self.llm_record(alert_id, version)
        llm = rec["result"] if rec else None
        view = {
            "alert_id": alert_id,
            "timestamp": a["timestamp"],
            "dest_host": a["dest_host"],
            "source_ip": a["source_ip"],
            "target_user": a["target_user"],
            "truth": a["ground_truth_severity"],
            "truth_v1": a["ground_truth_severity_v1"],
            "rule": rule["rule_based_severity"],
            "llm": llm["severity"] if llm else None,
            "llm_summary": llm["summary"] if llm else None,
            "llm_next_action": llm.get("next_action") if llm else None,
            "flags": [k for k, on in (
                ("accepted login", a["accepted_login"]),
                ("invalid user", a["invalid_user_flag"]),
                ("valid account", a["valid_account_flag"]),
                ("break-in warning", a["possible_breakin_flag"]),
                ("repeated failures", bool(a["repeated_failures_count"])),
            ) if on],
        }
        if detail:
            view["raw_content"] = a["raw_content"]
            view["rule_detail"] = {"matched_signatures": rule["matched_signatures"], "rationale": rule["rationale"]}
            view["llm_detail"] = None
            if rec:
                view["llm_detail"] = {**llm, "meta": rec["meta"], "quality": score_summary(a, llm)}
        return view

    def list_alerts(self, version, severity=None, source_ip=None, user=None, q=None, rank_by="rule",
                    sort="severity", order="desc", disagree=False, limit=100, offset=0):
        views = [self.alert_view(i, version) for i in self.order]
        if severity:
            wanted = {s.strip().capitalize() for s in severity.split(",")}
            views = [v for v in views if (v[rank_by] or v["rule"]) in wanted]
        if source_ip:
            views = [v for v in views if v["source_ip"] == source_ip]
        if user:
            views = [v for v in views if v["target_user"] == user]
        if q:
            ql = q.lower()
            views = [v for v in views if ql in " ".join(
                str(x) for x in (v["alert_id"], v["source_ip"], v["target_user"], v["llm_summary"]) if x).lower()]
        if disagree:
            views = [v for v in views if v["llm"] and len({v["truth"], v["rule"], v["llm"]}) > 1]
        rev = order != "asc"
        if sort == "severity":
            views.sort(key=lambda v: (RANK[v[rank_by] or v["rule"]], v["timestamp"] or ""), reverse=rev)
        elif sort in ("timestamp", "source_ip", "target_user", "alert_id"):
            views.sort(key=lambda v: (v[sort] is None, v[sort] or ""), reverse=rev)
        total = len(views)
        return {"total": total, "items": views[offset: offset + limit]}

    def stats(self, rank_by, version):
        sev = Counter()
        by_ip = defaultdict(lambda: {"count": 0, "max": -1})
        by_user = Counter()
        timeline = defaultdict(lambda: Counter())
        for i in self.order:
            v = self.alert_view(i, version)
            s = v[rank_by] or v["rule"]
            sev[s] += 1
            if v["source_ip"]:
                e = by_ip[v["source_ip"]]
                e["count"] += 1
                e["max"] = max(e["max"], RANK[s])
            if v["target_user"]:
                by_user[v["target_user"]] += 1
            hh, mm = v["timestamp"].split()[2].split(":")[:2]
            bucket = f"{hh}:{int(mm) // 15 * 15:02d}"
            timeline[bucket][s] += 1
        top_ips = sorted(by_ip.items(), key=lambda kv: -kv[1]["count"])[:8]
        return {
            "rank_by": rank_by,
            "total": len(self.order),
            "severity": {l: sev.get(l, 0) for l in LEVELS},
            "unique_ips": len(by_ip),
            "unique_users": len(by_user),
            "top_ips": [{"ip": ip, "count": e["count"], "max_severity": LEVELS[e["max"]]} for ip, e in top_ips],
            "top_users": [{"user": u, "count": c} for u, c in by_user.most_common(8)],
            "timeline": [{"t": t, **{l: c.get(l, 0) for l in LEVELS}} for t, c in sorted(timeline.items())],
            "llm_coverage": {v: len(self.store.load(v)) for v in lp.PROMPT_VERSIONS},
        }

    def health(self):
        return {
            "status": "ok",
            "alerts": len(self.alerts),
            "eval_subset": len(self.subset),
            "llm_live": lp.live_available(),
            "model": lp.DEFAULT_MODEL,
            "prompt_versions": lp.PROMPT_VERSIONS,
            "llm_coverage": {v: {"total": len(self.store.load(v)), "by_source": self.store.counts(v)}
                             for v in lp.PROMPT_VERSIONS},
            "batch": self.batch_status(),
        }

    # ---------- triage ----------
    def triage_alert(self, alert_id, version, force=False, client=None):
        rec = self.llm_record(alert_id, version)
        if rec and not force:
            return rec, True
        res = lp.triage_alert(self.alerts[alert_id], version, client=client)
        self.store.put(version, alert_id, res, "api_live", lp.DEFAULT_MODEL)
        self.store.save(version)
        return self.store.get(version, alert_id), False

    def triage_adhoc(self, lines, version, host=None, use_llm=False, client=None):
        alert = build_alert(lines, host=host)
        alert["valid_account_flag"] = targets_valid_account(alert)
        out = {
            "parsed": {k: v for k, v in alert.items() if k != "raw_content"},
            "rule": score_record(alert),
            "rubric_label": label_v2(alert),
            "llm": None,
        }
        if use_llm:
            res = lp.triage_alert(alert, version, client=client)
            out["llm"] = {**res, "quality": score_summary(alert, res)}
        return out

    # ---------- evaluation ----------
    def evaluation(self, rubric, version, scope):
        rule = {i: r["rule_based_severity"] for i, r in self.rule.items()}
        recs = self.store.load(version)
        ids = self.subset if scope == "subset" else None
        res = ev.evaluate(self.alerts, rule, recs, rubric, ids)
        res["prompt"] = version
        res["scope"] = scope
        return res

    # ---------- report ----------
    def report_csv(self, version, rank_by):
        rows = self.list_alerts(version, rank_by=rank_by, limit=10_000)["items"]
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["rank", "alert_id", "timestamp", "source_ip", "target_user", "severity", "rule_based",
                    "llm", "ground_truth", "summary", "next_action"])
        for n, v in enumerate(rows, 1):
            w.writerow([n, v["alert_id"], v["timestamp"], v["source_ip"], v["target_user"],
                        v[rank_by] or v["rule"], v["rule"], v["llm"] or "", v["truth"],
                        v["llm_summary"] or "", v["llm_next_action"] or ""])
        return buf.getvalue()

    # ---------- background live batch ----------
    def batch_status(self):
        return {"running": self.batch["running"], "version": self.batch["version"], "stats": self.batch["stats"]}

    def start_batch(self, version, scope, limit, workers, force, client=None):
        ids = self.subset if scope == "subset" else self.order
        if limit:
            ids = ids[:limit]
        alerts = [self.alerts[i] for i in ids]
        with self._batch_lock:
            if self.batch["running"]:
                raise RuntimeError("a batch is already running")
            self.batch.update(running=True, version=version, stats={"total": len(alerts), "done": 0, "failed": 0, "errors": []})
            self.batch["stop"].clear()

        def progress(s):
            self.batch["stats"] = dict(s, errors=list(s["errors"][:20]))

        def work():
            try:
                lp.run_batch(alerts, version, self.store, workers, force, progress, client=client, stop=self.batch["stop"])
            finally:
                self.batch["running"] = False

        threading.Thread(target=work, daemon=True).start()

    def stop_batch(self):
        self.batch["stop"].set()
