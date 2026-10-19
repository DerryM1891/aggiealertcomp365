"""
AggieAlert - LLM summarizer pipeline (Google AI Studio / Gemini API).

Sends each grouped SSH alert to Gemini and asks for a structured JSON triage
object. Three prompt versions are kept side by side so they can be compared on
the same alerts (proposal: "iterate on prompt design across 2-3 versions"):

  v1  Checkpoint 2 prompt. Minimal, zero-shot, no rubric.
  v2  Adds a suggested next action and asks the model to reason about whether
      the targeted account exists. Still no severity rubric in the prompt.
  v3  v2 plus the severity definitions from rubric.md (rubric-anchored).

Results are cached per prompt version in data/llm/<version>.json with provenance
(live API call vs. direct prompt application) so the evaluation can say exactly
where every number came from.

Setup:   pip install google-genai
         put GEMINI_API_KEY=... in .env (key from https://aistudio.google.com/apikey)
Run:     python llm_pipeline.py --version v2 --all --workers 4
         python llm_pipeline.py --version v2 --subset      # the 41-alert eval subset
"""
import argparse
import json
import os
import re
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

LEVELS = ["Low", "Medium", "High", "Critical"]


def _load_dotenv(path):
    """Minimal .env reader (no extra dependency). Real environment variables win."""
    try:
        for line in open(path, encoding="utf-8"):
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
    except OSError:
        pass


_load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

DEFAULT_MODEL = os.environ.get("GEMINI_MODEL") or os.environ.get("AGGIEALERT_MODEL") or "gemini-3.8-flash"
CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "llm")
PROMPT_VERSIONS = ["v1", "v2", "v3"]

_BASE_FIELDS = """- summary: one-sentence plain-language description of what happened
- severity: one of "Low", "Medium", "High", "Critical"
- rationale: one sentence justifying the severity, citing specific evidence from the log lines
- source_ip: the source IP involved, or null
- target_user: the username targeted, or null
- attack_technique: a likely MITRE ATT&CK technique ID + name, or null if not applicable"""

SYSTEM_PROMPTS = {
    "v1": (
        "You are a SOC triage assistant. Given one grouped SSH authentication alert "
        "(raw log lines from an sshd process), respond with ONLY a JSON object, no other "
        "text, with these fields:\n"
        + _BASE_FIELDS.replace(", citing specific evidence from the log lines", "")
        + "\n"
    ),
    "v2": (
        "You are a SOC triage assistant for a small security team. Given one grouped SSH "
        "authentication alert (raw log lines from one sshd process), respond with ONLY a "
        "JSON object, no other text, with these fields:\n"
        + _BASE_FIELDS
        + "\n- affected_asset: the host the alert was raised on, or null"
        "\n- next_action: one concrete step the analyst should take next (for example block an IP, "
        "check a specific account, review a session), not a restatement of the severity\n\n"
        "Rules:\n"
        "- Only state facts that appear in the log lines. Never invent usernames, IPs, counts or outcomes.\n"
        "- sshd writes \"invalid user <name>\" when the account does not exist. A failed password "
        "WITHOUT that tag means the account exists on the host, which matters for severity.\n"
        "- A password that was accepted means a successful login, whatever else is in the lines.\n"
    ),
    "v3": (
        "You are a SOC triage assistant for a small security team. Given one grouped SSH "
        "authentication alert (raw log lines from one sshd process), respond with ONLY a "
        "JSON object, no other text, with these fields:\n"
        + _BASE_FIELDS
        + "\n- affected_asset: the host the alert was raised on, or null"
        "\n- next_action: one concrete step the analyst should take next, not a restatement of the severity\n\n"
        "Severity definitions (use exactly these):\n"
        "- Critical: a password was accepted (successful authentication) during the attempt.\n"
        "- High: repeated failed passwords against the same account in one alert (brute force), "
        "OR a failed password targeting root.\n"
        "- Medium: an invalid/unknown username was attempted, OR a failed password targeted an "
        "existing non-root account (no \"invalid user\" tag), with no repeated failures and no success.\n"
        "- Low: the connection opened and closed with no authentication failure recorded.\n\n"
        "Rules:\n"
        "- Only state facts that appear in the log lines. Never invent usernames, IPs, counts or outcomes.\n"
        "- sshd writes \"invalid user <name>\" when the account does not exist; without that tag the account exists.\n"
    ),
}

REQUIRED = ["summary", "severity", "rationale", "source_ip", "target_user", "attack_technique"]
REQUIRED_V2 = REQUIRED + ["next_action"]


class LLMUnavailable(RuntimeError):
    """Raised when no API key / SDK is available for a live call."""


def api_key():
    """Google AI Studio key: GEMINI_API_KEY, or GOOGLE_API_KEY as the SDK's own fallback."""
    return os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY") or ""


def live_available():
    if not api_key():
        return False
    try:
        from google import genai  # noqa: F401
    except ImportError:
        return False
    return True


class GeminiClient:
    """Thin wrapper over the google-genai SDK. Anything with the same generate() works (tests use a fake)."""

    def __init__(self, key):
        from google import genai
        from google.genai import types
        self._types = types
        self._client = genai.Client(api_key=key, http_options=types.HttpOptions(timeout=60_000))

    def generate(self, model, system, user):
        types = self._types
        resp = self._client.models.generate_content(
            model=model,
            contents=user,
            config=types.GenerateContentConfig(
                system_instruction=system,
                response_mime_type="application/json",  # JSON mode
                temperature=0.0,
                max_output_tokens=2048,  # headroom: thinking tokens count against this on newer models
            ),
        )
        return resp.text or ""


_client = None


def get_client():
    global _client
    if _client is None:
        if not api_key():
            raise LLMUnavailable("GEMINI_API_KEY is not set. Add it to .env (or export it) and restart the server.")
        try:
            _client = GeminiClient(api_key())
        except ImportError as e:
            raise LLMUnavailable("The google-genai package is not installed (pip install google-genai).") from e
    return _client


def build_user_message(alert, version):
    lines = alert["raw_content"]
    msg = "Alert log lines:\n" + "\n".join(lines)
    if version != "v1":
        msg = f"Host: {alert.get('dest_host') or 'unknown'}\nTime: {alert.get('timestamp') or 'unknown'}\n" + msg
    return msg


def parse_json(text):
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", text, re.S)
        if not m:
            raise
        return json.loads(m.group(0))


def validate(out, version):
    need = REQUIRED if version == "v1" else REQUIRED_V2
    missing = [k for k in need if k not in out]
    if missing:
        raise ValueError(f"LLM output missing fields: {missing}")
    sev = str(out["severity"]).strip().capitalize()
    if sev not in LEVELS:
        raise ValueError(f"LLM returned invalid severity: {out['severity']!r}")
    out["severity"] = sev
    return out


def triage_alert(alert, version="v2", client=None, model=None):
    """Triage one alert dict (needs raw_content). Returns the validated result dict."""
    if version not in SYSTEM_PROMPTS:
        raise ValueError(f"unknown prompt version {version!r}; choose from {PROMPT_VERSIONS}")
    client = client or get_client()
    model = model or DEFAULT_MODEL
    last_err = None
    for attempt in range(2):  # one retry if the model returns malformed JSON
        text = client.generate(model, SYSTEM_PROMPTS[version], build_user_message(alert, version))
        try:
            return validate(parse_json(text), version)
        except (json.JSONDecodeError, ValueError) as e:
            last_err = e
    raise ValueError(f"could not parse a valid triage object for {alert['alert_id']}: {last_err}")


class LLMStore:
    """Thread-safe per-version cache of LLM results with provenance."""

    def __init__(self, cache_dir=CACHE_DIR):
        self.dir = cache_dir
        self.lock = threading.Lock()
        self._data = {}

    def _path(self, version):
        return os.path.join(self.dir, f"{version}.json")

    def load(self, version):
        with self.lock:
            if version not in self._data:
                try:
                    self._data[version] = json.load(open(self._path(version)))
                except (FileNotFoundError, json.JSONDecodeError):
                    self._data[version] = {}
            return self._data[version]

    def get(self, version, alert_id):
        return self.load(version).get(alert_id)

    def put(self, version, alert_id, result, source, model=None):
        data = self.load(version)
        with self.lock:
            data[alert_id] = {
                "result": result,
                "meta": {
                    "source": source,
                    "model": model,
                    "prompt_version": version,
                    "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                },
            }

    def save(self, version):
        with self.lock:
            os.makedirs(self.dir, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=self.dir, suffix=".tmp")
            with os.fdopen(fd, "w") as f:
                json.dump(self._data.get(version, {}), f, indent=1)
            os.replace(tmp, self._path(version))

    def counts(self, version):
        out = {}
        for rec in self.load(version).values():
            s = rec["meta"]["source"]
            out[s] = out.get(s, 0) + 1
        return out


def run_batch(alerts, version, store, workers=4, force=False, progress=None, client=None, model=None, stop=None):
    """Triage alerts live and cache each result. Resumable: cached alerts are skipped unless force."""
    todo = [a for a in alerts if force or store.get(version, a["alert_id"]) is None
            or store.get(version, a["alert_id"])["meta"]["source"] != "api_live"]
    stats = {"total": len(todo), "done": 0, "failed": 0, "errors": []}
    if progress:
        progress(stats)

    def work(a):
        if stop is not None and stop.is_set():
            return a, None, "stopped"
        try:
            return a, triage_alert(a, version, client=client, model=model), None
        except Exception as e:  # keep the batch going; report at the end
            return a, None, f"{type(e).__name__}: {e}"

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(work, a) for a in todo]
        for i, fut in enumerate(as_completed(futures), 1):
            a, res, err = fut.result()
            if res is not None:
                store.put(version, a["alert_id"], res, "api_live", model or DEFAULT_MODEL)
                stats["done"] += 1
            elif err != "stopped":
                stats["failed"] += 1
                stats["errors"].append({"alert_id": a["alert_id"], "error": err})
            if i % 10 == 0:
                store.save(version)
            if progress:
                progress(stats)
    store.save(version)
    return stats


def _load_alerts(path):
    return json.load(open(path))


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description="Run the AggieAlert LLM triage pipeline live against the Gemini API.")
    ap.add_argument("--version", default="v2", choices=PROMPT_VERSIONS)
    scope = ap.add_mutually_exclusive_group()
    scope.add_argument("--all", action="store_true", help="all 519 alerts (default)")
    scope.add_argument("--subset", action="store_true", help="the 41-alert evaluation subset")
    ap.add_argument("--limit", type=int, help="only the first N alerts of the chosen scope")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--force", action="store_true", help="re-run alerts that already have a live result")
    ap.add_argument("--model", default=DEFAULT_MODEL)
    args = ap.parse_args()

    if not live_available():
        raise SystemExit("No live API access: set GEMINI_API_KEY (see .env.example) and `pip install google-genai`.")

    src = "alerts_llm_sample.json" if args.subset else "alerts_labeled_full.json"
    alerts = _load_alerts(os.path.join(here, "data", src))
    if args.limit:
        alerts = alerts[: args.limit]
    store = LLMStore()
    t0 = time.time()
    print(f"Running prompt {args.version} with {args.model} on {len(alerts)} alerts ({args.workers} workers)")

    def progress(s):
        print(f"\r  {s['done']}/{s['total']} done, {s['failed']} failed", end="", flush=True)

    stats = run_batch(alerts, args.version, store, args.workers, args.force, progress, model=args.model)
    print(f"\nFinished in {time.time() - t0:.0f}s -> data/llm/{args.version}.json")
    for e in stats["errors"][:10]:
        print("  error:", e["alert_id"], e["error"])


if __name__ == "__main__":
    main()
