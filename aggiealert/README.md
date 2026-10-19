# AggieAlert: LLM-Assisted SOC Dashboard & Alert Summarizer

COMP 365 individual project, North Carolina A&T State University.

**Overview.** AggieAlert is a small SOC triage tool for SSH authentication alerts (519 grouped
alerts from the public Loghub OpenSSH honeypot sample). It scores every alert two ways and
compares them against an analyst-style ground truth:

1. a deterministic **rule-based** severity scorer (signature and keyword matching), and
2. an **LLM triage assistant ("Aggie-Bot")** that calls the **Google AI Studio Gemini API** and
   returns structured JSON: summary, severity, rationale, MITRE ATT&CK technique, next action.

---

## Step-by-step: run it

### 1. Prerequisites
- Python 3.10 or newer (`python --version`)
- A free Google AI Studio API key (only needed for live Gemini calls)

### 2. Unzip and open a terminal in the project folder
    cd aggiealert

### 3. Create a virtual environment and install dependencies
macOS / Linux:

    python -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt

Windows (PowerShell):

    python -m venv .venv
    .venv\Scripts\Activate.ps1
    pip install -r requirements.txt

### 4. Get a Google AI Studio API key
1. Go to https://aistudio.google.com/apikey and sign in with a Google account.
2. Click **Create API key** and copy it.

### 5. Put the key in `.env`
    cp .env.example .env          # Windows: copy .env.example .env

Open `.env` and fill it in:

    GEMINI_API_KEY=your-key-here
    GEMINI_MODEL=gemini-3.5-flash-lite

`.env` is git-ignored, so the key is never committed. `GOOGLE_API_KEY` also works as the key name.
If the model name is rejected, pick a current one from https://ai.google.dev/gemini-api/docs/models
and change `GEMINI_MODEL`.

### 6. Start the server
    python -m uvicorn server.main:app --host 127.0.0.1 --port 8000

- Dashboard: http://127.0.0.1:8000/
- API docs (try endpoints in the browser): http://127.0.0.1:8000/docs

The pill at the top right says "Aggie-Bot live" when the key was found, or "offline" when it was not.
Restart the server after editing `.env`.

### 7. Use the dashboard
- **Triage Queue:** toggle ranking by Rule-Based or Aggie-Bot, filter by severity chips, search by IP,
  account or summary, click a row for the raw log lines and both verdicts.
- **Run Aggie-Bot:** in an alert's detail panel, sends that one alert to Gemini and caches the result.
- **Analyze & Alert:** paste raw sshd log lines to get a rule-based verdict, plus Gemini if you tick the box.
- **Evaluation:** accuracy, Cohen's kappa, confusion matrices, disagreements, summary quality, and
  a "Run Aggie-Bot live" button for a background run over the dataset.
- **Export CSV:** ranked triage report, most severe first.

### 8. Run Gemini over the whole dataset (command line)
    python llm_pipeline.py --version v2 --subset --workers 2     # 41-alert subset first, as a smoke test
    python llm_pipeline.py --version v2 --all --workers 4        # all 519 alerts, resumable
    python llm_pipeline.py --version v3 --all --workers 4        # rubric-anchored prompt
    python llm_pipeline.py --version v1 --all --workers 4        # Checkpoint 2 prompt, live
    python evaluate.py                                           # tables for both rubrics

Runs save as they go; rerun the same command to resume. Prompt versions: v1 (minimal), v2 (adds
next action and account-exists reasoning), v3 (adds the severity definitions). The free tier has
rate limits: if you see 429 errors, lower `--workers` (try 1 or 2) and rerun to resume.

### 9. Run the tests
    pip install -r requirements-dev.txt
    python -m pytest -q          # 32 tests, no network, no API key needed

### Docker (optional)
    cp .env.example .env         # add GEMINI_API_KEY
    docker-compose up --build    # then open http://127.0.0.1:8000/

---

## Working on the project

| Want to change | Edit |
|---|---|
| Prompts, model call, JSON validation | `llm_pipeline.py` (`SYSTEM_PROMPTS`, `GeminiClient`, `triage_alert`) |
| Severity rules | `rule_based_scorer.py`, `ground_truth.py`, `rubric.md` |
| Summary quality rubric | `summary_quality.py`, `rubric_summary_quality.md` |
| API endpoints | `server/main.py`, logic in `server/service.py` |
| Look and feel | `web/styles.css` (theme colors are CSS variables at the top), `web/app.js`, `web/index.html` |
| Metrics and evaluation | `metrics.py`, `evaluate.py` |

Theme: Aggie Blue `#004684` and Aggie Gold `#ffb81c`, defined in `:root` of `styles.css`.
Cached LLM results live in `data/llm/<version>.json`, each tagged with source (`api_live` or
direct prompt), model and timestamp. Delete a file there to start a version over.

Note: the 41 Checkpoint 2 results were generated with Claude, not Gemini. They stay labeled as
direct-prompt results. Live Gemini runs are labeled `api_live` with the Gemini model name; keep
the two separate when reporting numbers (see `NOTES.md`).

## API

| Method and path | Purpose |
|---|---|
| GET `/api/health` | mode, model, saved-result counts per prompt version |
| GET `/api/alerts` | filter (`severity`, `source_ip`, `user`, `q`, `disagree`), sort, page; `rank_by=rule\|llm\|truth` |
| GET `/api/alerts/{id}` | raw log, rule reasoning, LLM result with provenance and quality score |
| POST `/api/alerts/{id}/triage` | Gemini triage for one alert (cached unless `force`) |
| POST `/api/triage` | triage pasted raw log lines; Gemini too when `use_llm` is true |
| GET `/api/stats` | severity counts, timeline, top IPs and accounts |
| GET `/api/evaluation` | accuracy, kappa, confusion matrices, disagreements, summary quality; `rubric=v1\|v2` |
| GET `/api/report.csv` | ranked triage report, most severe first |
| POST/GET/DELETE `/api/llm/batch` | start, watch, stop a background live run |

The server binds to localhost by default because the batch endpoint spends API quota.
There is no login, so do not expose it on a network.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Pill says "offline" | `GEMINI_API_KEY` missing in `.env`, or `google-genai` not installed. Restart after fixing. |
| `Gemini API error: ... 400/403` | Bad or restricted key. Create a new one at aistudio.google.com/apikey. |
| `... 404 ... model not found` | Change `GEMINI_MODEL` to a current model name. |
| `... 429` | Free-tier rate limit. Wait, lower `--workers`, rerun (runs resume). |
| `ModuleNotFoundError` | Activate the virtual environment and rerun `pip install -r requirements.txt`. |

## Data and notes
Loghub OpenSSH sample (public, Zenodo DOI 10.5281/zenodo.1144100): attacker-side IPs, attempted
usernames and a honeypot hostname only; no victim data. See `NOTES.md` for status, current
numbers, and the caveats that belong in the write-up.
