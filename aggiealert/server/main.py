"""
AggieAlert API. Run from the project root:

    uvicorn server.main:app --host 127.0.0.1 --port 8000

Interactive API docs: http://127.0.0.1:8000/docs   Dashboard: http://127.0.0.1:8000/
"""
import os
from typing import List, Literal, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

import llm_pipeline as lp
from server.service import Service

WEB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web")
Method = Literal["truth", "rule", "llm"]
Prompt = Literal["v1", "v2", "v3"]

app = FastAPI(
    title="AggieAlert API",
    version="1.0.0",
    description="LLM-assisted SOC alert triage: rule-based baseline, Gemini summarizer, and evaluation.",
)
svc = Service()
# Default prompt version: AGGIEALERT_PROMPT if set, else the version with the most cached results (ties -> newest).
DEFAULT_PROMPT = os.environ.get("AGGIEALERT_PROMPT") or svc.best_version()


def _need_alert(alert_id):
    if alert_id not in svc.alerts:
        raise HTTPException(404, f"alert {alert_id} not found")


def _llm_errors(fn):
    try:
        return fn()
    except lp.LLMUnavailable as e:
        raise HTTPException(503, str(e))
    except ValueError as e:
        raise HTTPException(502, f"The model returned an unusable answer: {e}")
    except Exception as e:  # Gemini API errors (bad key, quota, unknown model, network)
        raise HTTPException(502, f"Gemini API error: {type(e).__name__}: {e}")


@app.get("/api/health", tags=["system"])
def health():
    return svc.health()


@app.get("/api/alerts", tags=["alerts"])
def list_alerts(
    severity: Optional[str] = Query(None, description="comma list, e.g. High,Critical (applies to rank_by)"),
    source_ip: Optional[str] = None,
    user: Optional[str] = None,
    q: Optional[str] = Query(None, max_length=100),
    rank_by: Method = "rule",
    sort: Literal["severity", "timestamp", "source_ip", "target_user", "alert_id"] = "severity",
    order: Literal["asc", "desc"] = "desc",
    disagree: bool = Query(False, description="only alerts where truth, rule and LLM do not all agree"),
    prompt: Prompt = DEFAULT_PROMPT,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    return svc.list_alerts(prompt, severity, source_ip, user, q, rank_by, sort, order, disagree, limit, offset)


@app.get("/api/alerts/{alert_id}", tags=["alerts"])
def get_alert(alert_id: str, prompt: Prompt = DEFAULT_PROMPT):
    _need_alert(alert_id)
    return svc.alert_view(alert_id, prompt, detail=True)


class TriageRequest(BaseModel):
    prompt: Prompt = DEFAULT_PROMPT
    force: bool = Field(False, description="call Gemini again even if a result is cached")


@app.post("/api/alerts/{alert_id}/triage", tags=["triage"])
def triage_one(alert_id: str, body: TriageRequest = TriageRequest()):
    """Return the LLM triage for one alert: cached if present, otherwise a live Gemini call."""
    _need_alert(alert_id)
    cached = svc.llm_record(alert_id, body.prompt)
    if cached and not body.force:
        return {"cached": True, **svc.alert_view(alert_id, body.prompt, detail=True)}
    _llm_errors(lambda: svc.triage_alert(alert_id, body.prompt, body.force))
    return {"cached": False, **svc.alert_view(alert_id, body.prompt, detail=True)}


class AdhocRequest(BaseModel):
    raw_lines: List[str] = Field(..., min_length=1, max_length=50)
    host: Optional[str] = Field(None, max_length=100)
    use_llm: bool = False
    prompt: Prompt = DEFAULT_PROMPT


@app.post("/api/triage", tags=["triage"])
def triage_adhoc(body: AdhocRequest):
    """Triage a pasted alert (raw sshd log lines): always rule-based, plus Gemini when use_llm is true."""
    if any(len(l) > 500 for l in body.raw_lines):
        raise HTTPException(422, "each log line must be 500 characters or fewer")
    return _llm_errors(lambda: svc.triage_adhoc(body.raw_lines, body.prompt, body.host, body.use_llm))


@app.get("/api/stats", tags=["reports"])
def stats(rank_by: Method = "rule", prompt: Prompt = DEFAULT_PROMPT):
    return svc.stats(rank_by, prompt)


@app.get("/api/evaluation", tags=["reports"])
def evaluation(
    rubric: Literal["v1", "v2"] = "v2",
    prompt: Prompt = DEFAULT_PROMPT,
    scope: Literal["subset", "covered"] = Query("covered", description="subset = the 41-alert eval subset; covered = every alert with an LLM result"),
):
    return svc.evaluation(rubric, prompt, scope)


@app.get("/api/report.csv", tags=["reports"])
def report_csv(rank_by: Method = "rule", prompt: Prompt = DEFAULT_PROMPT):
    """Ranked triage report: one row per alert, most severe first."""
    return Response(
        svc.report_csv(prompt, rank_by),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=aggiealert_triage_report.csv"},
    )


class BatchRequest(BaseModel):
    prompt: Prompt = DEFAULT_PROMPT
    scope: Literal["subset", "all"] = "subset"
    limit: Optional[int] = Field(None, ge=1, le=1000)
    workers: int = Field(4, ge=1, le=8)
    force: bool = False


@app.post("/api/llm/batch", status_code=202, tags=["triage"])
def start_batch(body: BatchRequest):
    """Start a background live Gemini run over the dataset. Results are cached as they arrive."""
    if not lp.live_available():
        raise HTTPException(503, "Live Gemini calls need GEMINI_API_KEY and the google-genai package.")
    try:
        svc.start_batch(body.prompt, body.scope, body.limit, body.workers, body.force)
    except RuntimeError as e:
        raise HTTPException(409, str(e))
    return svc.batch_status()


@app.get("/api/llm/batch", tags=["triage"])
def batch_status():
    return svc.batch_status()


@app.delete("/api/llm/batch", tags=["triage"])
def stop_batch():
    svc.stop_batch()
    return svc.batch_status()


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(os.path.join(WEB_DIR, "index.html"))


app.mount("/", StaticFiles(directory=WEB_DIR), name="web")
