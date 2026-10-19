"use strict";

const SEV = ["Low", "Medium", "High", "Critical"];
const COLOR = { Low: "var(--low)", Medium: "var(--med)", High: "var(--high)", Critical: "var(--crit)" };
const HEX = { Low: "#4a90d9", Medium: "#d9a300", High: "#e0661f", Critical: "#b3122b" };
const PAGE = 25;

const state = { rankBy: "rule", prompt: "v2", sev: new Set(), q: "", user: "", ip: "", sort: "severity", order: "desc", offset: 0, selected: null, tab: "queue", health: null };

/* ---------- helpers ---------- */
const $ = (s, r = document) => r.querySelector(s);
const bot = (s) => String(s == null ? "" : s).replace(/(claude|gemini)-[\w.-]+/gi, "model").replace(/Claude|Gemini/g, "Aggie-Bot");
function el(tag, attrs, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === "class") n.className = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else if (v === true) n.setAttribute(k, "");
    else n.setAttribute(k, v);
  }
  for (const k of kids.flat()) { if (k == null || k === false) continue; n.append(k.nodeType ? k : document.createTextNode(String(k))); }
  return n;
}
function clear(n) { while (n.firstChild) n.removeChild(n.firstChild); return n; }
async function api(path, opts) {
  const res = await fetch(path, opts && opts.body ? { ...opts, headers: { "Content-Type": "application/json" }, body: JSON.stringify(opts.body) } : opts);
  if (!res.ok) {
    let msg = res.statusText;
    try { const j = await res.json(); msg = typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail); } catch (_) {}
    throw new Error(bot(msg));
  }
  return res.json();
}
const qs = (o) => Object.entries(o).filter(([, v]) => v !== "" && v != null && v !== false).map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join("&");
const fmt = (n) => Number(n).toLocaleString();
function toast(msg) { const t = el("div", { class: "toast", role: "status" }, msg); document.body.append(t); setTimeout(() => t.remove(), 4200); }
function badge(sev) { return sev ? el("span", { class: "badge " + sev }, el("i"), sev) : el("span", { class: "badge none" }, el("i"), "Not run"); }

/* ---------- header status ---------- */
function renderHealth() {
  const live = $("#liveState"), h = state.health;
  live.className = "live" + (h.llm_live ? " on" : "");
  clear(live).append(el("i"), el("span", {}, h.llm_live ? "Aggie-Bot live" : "Aggie-Bot offline · showing saved results"));
  $("#csvLink").href = "/api/report.csv?" + qs({ rank_by: state.rankBy, prompt: state.prompt });
}

/* ---------- overview ---------- */
async function renderOverview() {
  const s = await api("/api/stats?" + qs({ rank_by: state.rankBy, prompt: state.prompt }));
  $("#totalSub").textContent = `${fmt(s.total)} alerts from ${fmt(s.unique_ips)} source IPs · 15-minute buckets`;
  const leg = clear($("#legend"));
  for (const l of [...SEV].reverse()) leg.append(el("li", {}, el("span", { class: "sw", style: `background:${COLOR[l]}` }), l, el("b", {}, fmt(s.severity[l]))));
  timeline(s.timeline);
  ranked($("#topIps"), s.top_ips.slice(0, 5).map((x) => ({ name: x.ip, n: x.count, color: COLOR[x.max_severity], key: "ip" })));
  ranked($("#topUsers"), s.top_users.slice(0, 5).map((x) => ({ name: x.user, n: x.count, color: "var(--mr)", key: "user" })));
}
function ranked(ul, items) {
  clear(ul);
  const max = Math.max(...items.map((i) => i.n), 1);
  for (const it of items) {
    ul.append(el("li", {},
      el("button", { class: "name", title: "Filter queue", onclick: () => { state[it.key] = it.name; state.offset = 0; setTab("queue"); refreshQueue(); } }, it.name),
      el("span", { class: "n" }, fmt(it.n)),
      el("div", { class: "bar" }, el("i", { style: `width:${(100 * it.n / max).toFixed(1)}%;background:${it.color}` }))));
  }
}
function timeline(data) {
  const host = clear($("#timeline"));
  if (!data.length) return;
  const W = 640, H = 150, L = 34, B = 24, T = 8, R = 6, pw = W - L - R, ph = H - B - T;
  const totals = data.map((d) => SEV.reduce((a, l) => a + d[l], 0));
  const maxV = Math.max(...totals), step = maxV <= 50 ? 10 : maxV <= 120 ? 25 : maxV <= 250 ? 50 : 100, top = Math.ceil(maxV / step) * step;
  const y = (v) => T + ph - (v / top) * ph, slot = pw / data.length, bw = Math.min(24, slot * 0.62);
  const NS = "http://www.w3.org/2000/svg", svg = document.createElementNS(NS, "svg");
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`); svg.setAttribute("role", "img"); svg.setAttribute("aria-label", "Alerts over time by severity");
  const add = (tag, a, text) => { const n = document.createElementNS(NS, tag); for (const k in a) n.setAttribute(k, a[k]); if (text != null) n.textContent = text; svg.append(n); return n; };
  for (let v = 0; v <= top; v += step) {
    add("line", { x1: L, x2: W - R, y1: y(v), y2: y(v), stroke: "#e3eaf3", "stroke-width": 1 });
    add("text", { x: L - 6, y: y(v) + 4, "text-anchor": "end", "font-size": 11, fill: "#6f7e94" }, v);
  }
  const tip = el("div", { class: "tip", hidden: true });
  data.forEach((d, i) => {
    const cx = L + slot * i + slot / 2, x0 = cx - bw / 2; let acc = 0;
    SEV.forEach((l) => {
      const v = d[l]; if (!v) return;
      const yTop = y(acc + v), yBot = y(acc), h = Math.max(yBot - yTop - 2, 1);
      const r = add("rect", { x: x0, y: yTop, width: bw, height: h, fill: HEX[l] });
      if (SEV.slice(SEV.indexOf(l) + 1).every((k) => !d[k])) r.setAttribute("rx", 4);
      acc += v;
    });
    if (i % 4 === 0) add("text", { x: cx, y: H - 6, "text-anchor": "middle", "font-size": 11, fill: "#6f7e94" }, d.t);
    const hit = add("rect", { x: L + slot * i, y: T, width: slot, height: ph + B, fill: "transparent", tabindex: 0, "aria-label": `${d.t}: ${totals[i]} alerts` });
    const show = () => {
      clear(tip).append(el("b", {}, `${d.t} · ${totals[i]} alerts`), ...[...SEV].reverse().filter((l) => d[l]).map((l) => el("div", {}, `${l}: ${d[l]}`)));
      tip.hidden = false; tip.style.left = `${(cx / W) * 100}%`; tip.style.top = `${(y(totals[i]) / H) * host.clientHeight - 6}px`;
    };
    hit.addEventListener("mouseenter", show); hit.addEventListener("focus", show);
    hit.addEventListener("mouseleave", () => (tip.hidden = true)); hit.addEventListener("blur", () => (tip.hidden = true));
  });
  host.append(svg, tip);
}

/* ---------- queue ---------- */
const COLS = [
  { key: "severity", label: "Severity", sortable: true },
  { key: "timestamp", label: "Time", sortable: true },
  { key: "source_ip", label: "Source IP", sortable: true },
  { key: "target_user", label: "Account", sortable: true },
  { key: "summary", label: "Aggie-Bot summary" },
];
function renderHead() {
  const tr = clear($("#thead"));
  for (const c of COLS) {
    const th = el("th", { scope: "col", "aria-sort": c.sortable && state.sort === c.key ? (state.order === "asc" ? "ascending" : "descending") : null });
    th.append(c.sortable ? el("button", { onclick: () => {
      if (state.sort === c.key) state.order = state.order === "asc" ? "desc" : "asc"; else { state.sort = c.key; state.order = c.key === "severity" ? "desc" : "asc"; }
      state.offset = 0; refreshQueue();
    } }, c.label) : c.label);
    tr.append(th);
  }
}
const filtersActive = () => state.sev.size || state.q || state.user || state.ip;
async function refreshQueue() {
  renderHead();
  const active = [state.ip && `IP ${state.ip}`, state.user && `account ${state.user}`].filter(Boolean);
  $("#clearFilters").hidden = !filtersActive();
  $("#clearFilters").textContent = active.length ? `Clear filter: ${active.join(", ")}` : "Clear filters";
  let data;
  try { data = await api("/api/alerts?" + qs({ severity: [...state.sev].join(","), q: state.q, user: state.user, source_ip: state.ip, rank_by: state.rankBy, sort: state.sort, order: state.order, prompt: state.prompt, limit: PAGE, offset: state.offset })); }
  catch (e) { toast("Could not load alerts: " + e.message); return; }
  const body = clear($("#rows"));
  $("#empty").hidden = data.items.length > 0;
  for (const a of data.items) {
    const sev = a[state.rankBy] || a.rule;
    body.append(el("tr", { tabindex: 0, "aria-selected": String(state.selected === a.alert_id), "data-id": a.alert_id, onclick: () => select(a.alert_id),
      onkeydown: (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); select(a.alert_id); } } },
      el("td", {}, badge(sev)),
      el("td", { class: "num" }, a.timestamp.replace("Dec 10 ", "")),
      el("td", { class: "num" }, a.source_ip || "–"),
      el("td", {}, a.target_user || "–"),
      el("td", { class: "sum" + (a.llm_summary ? "" : " none") }, a.llm_summary ? bot(a.llm_summary) : "Aggie-Bot has not run on this alert")));
  }
  const from = data.total ? state.offset + 1 : 0, to = Math.min(state.offset + PAGE, data.total);
  $("#pageInfo").textContent = `${from}–${to} of ${fmt(data.total)} alerts`;
  $("#prev").disabled = state.offset === 0; $("#next").disabled = to >= data.total;
}
function setupQueue() {
  $("#rankSeg").addEventListener("click", (e) => {
    const b = e.target.closest("button"); if (!b) return;
    state.rankBy = b.dataset.v; state.offset = 0;
    document.querySelectorAll("#rankSeg button").forEach((x) => x.setAttribute("aria-pressed", String(x === b)));
    refreshAll();
  });
  const chips = $("#sevChips");
  for (const l of [...SEV].reverse()) {
    chips.append(el("button", { class: "chip", "aria-pressed": "false", onclick: (e) => {
      state.sev.has(l) ? state.sev.delete(l) : state.sev.add(l);
      e.currentTarget.setAttribute("aria-pressed", String(state.sev.has(l))); state.offset = 0; refreshQueue();
    } }, el("span", { class: "sw", style: `background:${COLOR[l]}` }), l));
  }
  let t;
  $("#search").addEventListener("input", (e) => { clearTimeout(t); t = setTimeout(() => { state.q = e.target.value.trim(); state.offset = 0; refreshQueue(); }, 250); });
  $("#clearFilters").addEventListener("click", () => {
    Object.assign(state, { sev: new Set(), q: "", user: "", ip: "", offset: 0 });
    $("#search").value = "";
    document.querySelectorAll("#sevChips .chip").forEach((c) => c.setAttribute("aria-pressed", "false"));
    refreshQueue();
  });
  $("#prev").addEventListener("click", () => { state.offset = Math.max(0, state.offset - PAGE); refreshQueue(); });
  $("#next").addEventListener("click", () => { state.offset += PAGE; refreshQueue(); });
  $("#closeDetail").addEventListener("click", () => $("#detail").classList.remove("open"));
}

/* ---------- detail ---------- */
const HITS = /(Failed password|Invalid user|invalid user|Accepted password|POSSIBLE BREAK-IN ATTEMPT!?|message repeated \d+ times)/g;
function logBlock(lines) {
  const pre = el("pre", { class: "log", tabindex: 0, "aria-label": "Raw log lines" });
  lines.forEach((line, i) => { line.split(HITS).forEach((p, j) => pre.append(j % 2 ? el("span", { class: "hit" }, p) : p)); if (i < lines.length - 1) pre.append("\n"); });
  return pre;
}
async function select(id, open = true) {
  state.selected = id;
  document.querySelectorAll("#rows tr").forEach((r) => r.setAttribute("aria-selected", String(r.dataset.id === id)));
  if (open) $("#detail").classList.add("open");
  try { renderDetail(await api(`/api/alerts/${id}?` + qs({ prompt: state.prompt }))); }
  catch (e) { clear($("#detailBody")).append(el("div", { class: "error" }, e.message)); }
}
function provenance(m) {
  if (!m) return "";
  return m.source === "api_live" ? `Live Aggie-Bot run · prompt ${m.prompt_version}` : `Saved Aggie-Bot result · prompt ${m.prompt_version}`;
}
function alertText(a, L) {
  const sev = (state.rankBy === "llm" && a.llm) || a.rule;
  return [`[AggieAlert] ${sev.toUpperCase()}: ${a.alert_id}`, `Source IP: ${a.source_ip || "unknown"}   Account: ${a.target_user || "unknown"}   Time: ${a.timestamp}`,
    L ? `Summary: ${bot(L.summary)}` : `Reason: ${a.rule_detail.rationale}`, L && L.next_action ? `Next action: ${bot(L.next_action)}` : null].filter(Boolean).join("\n");
}
function renderDetail(a) {
  const body = clear($("#detailBody")), L = a.llm_detail;
  body.append(el("h2", {}, a.alert_id), el("p", { class: "meta" }, `${a.timestamp} · ${a.source_ip || "no IP"} → ${a.target_user || "no account"}`),
    el("div", { class: "ledger" }, el("div", {}, el("small", {}, "Rule-Based"), badge(a.rule)), el("div", {}, el("small", {}, "Aggie-Bot"), badge(a.llm))));
  if (L) {
    body.append(el("p", { class: "read" }, bot(L.summary)), el("div", { class: "field-label" }, "Why"), el("p", { class: "body" }, bot(L.rationale)));
    if (L.next_action) body.append(el("div", { class: "field-label" }, "Next action"), el("p", { class: "body" }, bot(L.next_action)));
    if (L.attack_technique) body.append(el("div", { class: "field-label" }, "MITRE ATT&CK"), el("p", { class: "body" }, L.attack_technique));
    body.append(el("p", { class: "provenance" }, provenance(L.meta)));
  } else body.append(el("p", { class: "note" }, "Aggie-Bot has not analyzed this alert yet."));
  body.append(el("div", { class: "field-label" }, "Rule-based reasoning"), el("p", { class: "body" }, `${a.rule_detail.rationale} (${a.rule_detail.matched_signatures.join(", ") || "no signatures"})`),
    el("div", { class: "field-label" }, "Raw log lines"), logBlock(a.raw_content));
  const run = el("button", { class: "btn primary", onclick: () => triageNow(a.alert_id, run, !!L) }, L ? "Run Aggie-Bot again" : "Run Aggie-Bot");
  if (!state.health.llm_live) { run.disabled = true; run.title = "Set GEMINI_API_KEY in .env and restart the server to enable live runs"; }
  const copy = el("button", { class: "btn", onclick: () => copyText(alertText(a, L)) }, "Copy alert");
  body.append(el("div", { class: "row", style: "margin-top:18px" }, run, copy), !state.health.llm_live ? el("p", { class: "provenance" }, "Live runs are off: no API key on the server.") : null);
}
async function triageNow(id, btn, force) {
  btn.disabled = true; btn.textContent = "Asking Aggie-Bot…";
  try {
    renderDetail(await api(`/api/alerts/${id}/triage`, { method: "POST", body: { prompt: state.prompt, force } }));
    toast(`Aggie-Bot analyzed ${id}`);
    state.health = await api("/api/health"); renderHealth(); refreshQueue(); renderOverview();
  } catch (e) { btn.disabled = false; btn.textContent = "Run Aggie-Bot"; toast(e.message); }
}
async function copyText(t) {
  try { await navigator.clipboard.writeText(t); toast("Alert copied to clipboard"); } catch (_) { toast("Copy failed. Select the text and copy manually."); }
}

/* ---------- analyze & alert ---------- */
const EXAMPLE = [
  "Failed password for mysql from 203.0.113.45 port 51234 ssh2",
  "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.45  user=mysql",
  "Connection closed by 203.0.113.45 [preauth]",
].join("\n");
function renderAnalyze() {
  const host = clear($("#view-analyze"));
  const live = state.health.llm_live;
  const ta = el("textarea", { class: "logs", "aria-label": "Raw sshd log lines", placeholder: "Paste the sshd log lines for one connection, one per line" });
  const useBot = el("input", { type: "checkbox", disabled: !live, checked: live });
  const out = el("div", { id: "adhocOut" });
  const go = el("button", { class: "btn primary", onclick: async () => {
    const lines = ta.value.split("\n").map((l) => l.trim()).filter(Boolean);
    if (!lines.length) { toast("Paste at least one log line."); return; }
    go.disabled = true; go.textContent = "Analyzing…";
    try { adhocResult(out, await api("/api/triage", { method: "POST", body: { raw_lines: lines, use_llm: useBot.checked, prompt: state.prompt } })); }
    catch (e) { clear(out).append(el("div", { class: "error" }, e.message)); }
    go.disabled = false; go.textContent = "Analyze";
  } }, "Analyze");
  host.append(el("div", { class: "analyze" },
    el("div", { class: "card" }, el("h2", {}, "Analyze"), el("p", { class: "sub", style: "margin-bottom:0" }, "Paste raw sshd log lines for one connection."), ta,
      el("div", { class: "row" }, el("label", { class: "check" }, useBot, "Ask Aggie-Bot", !live ? el("span", { class: "provenance", style: "margin:0" }, "(needs API key)") : null),
        el("button", { class: "btn", onclick: () => { ta.value = EXAMPLE; } }, "Load example"), go)),
    out));
}
function adhocResult(host, r) {
  clear(host);
  const p = r.parsed, L = r.llm;
  const sev = (L && L.severity) || r.rule.rule_based_severity;
  const text = [`[AggieAlert] ${sev.toUpperCase()}`, `Source IP: ${p.source_ip || "unknown"}   Account: ${p.target_user || "unknown"}`,
    L ? `Summary: ${bot(L.summary)}` : `Reason: ${r.rule.rationale}`, L && L.next_action ? `Next action: ${bot(L.next_action)}` : null].filter(Boolean).join("\n");
  host.append(el("div", { class: "card" }, el("h2", {}, "Result"), el("div", { style: "height:12px" }),
    el("div", { class: "ledger" }, el("div", {}, el("small", {}, "Rule-Based"), badge(r.rule.rule_based_severity)), el("div", {}, el("small", {}, "Aggie-Bot"), L ? badge(L.severity) : el("span", { class: "meta", style: "margin:0" }, "Not requested"))),
    L ? [el("p", { class: "read" }, bot(L.summary)), el("div", { class: "field-label" }, "Why"), el("p", { class: "body" }, bot(L.rationale)),
      L.next_action ? [el("div", { class: "field-label" }, "Next action"), el("p", { class: "body" }, bot(L.next_action))] : null] : el("p", { class: "body" }, r.rule.rationale),
    el("dl", { class: "kv", style: "margin-top:16px" }, el("dt", {}, "Source IP"), el("dd", {}, p.source_ip || "–"), el("dt", {}, "Account"), el("dd", {}, p.target_user || "–"),
      el("dt", {}, "Signatures"), el("dd", {}, r.rule.matched_signatures.join(", ") || "none")),
    el("div", { class: "field-label" }, "Alert"), el("div", { class: "alert-box" }, text),
    el("button", { class: "btn primary", onclick: () => copyText(text) }, "Copy alert")));
}

/* ---------- tabs and boot ---------- */
function setTab(t) {
  state.tab = t;
  document.querySelectorAll(".tabs button").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.tab === t)));
  $("#view-queue").hidden = t !== "queue"; $("#view-analyze").hidden = t !== "analyze";
  if (t === "analyze") renderAnalyze();
}
function refreshAll() { renderHealth(); renderOverview(); refreshQueue(); if (state.selected) select(state.selected, false); }
async function boot() {
  setupQueue();
  $(".tabs").addEventListener("click", (e) => { const b = e.target.closest("button"); if (b) setTab(b.dataset.tab); });
  try { state.health = await api("/api/health"); }
  catch (e) { $("main").prepend(el("div", { class: "note" }, "The API is not reachable: " + e.message)); return; }
  const best = Object.entries(state.health.llm_coverage).sort((a, b) => b[1].total - a[1].total || (a[0] < b[0] ? 1 : -1))[0];
  state.prompt = best[1].total ? best[0] : "v2";
  renderHealth(); renderOverview(); refreshQueue();
}
boot();
