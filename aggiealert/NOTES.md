# AggieAlert - status (final implementation)

## Checkpoint 2 follow-ups

| Checkpoint 2 item | Status |
|---|---|
| Fix the ground-truth valid-account blind spot and re-run | Done. Rubric v2 (`rubric.md`), `ground_truth.py`, and the rule-based scorer all handle it. 15 of 519 alerts change Low to Medium. Both rubrics are reported side by side. |
| Run the LLM pipeline live on 200-400+ records | **Not done in the dev sandbox: no API key.** Everything is built and tested against a fake client; the live backend is now Google AI Studio (Gemini). One command runs it for real (below). Until then the only LLM results are the 41 Checkpoint 2 direct-prompt results, labeled as such everywhere. |
| Build the SOC dashboard UI | Done (`web/`), served by the API. |
| API implementation | Done (`server/`, FastAPI). Docs at /docs. |
| Prompt iteration across 2-3 versions (proposal) | v1, v2, v3 implemented in `llm_pipeline.py`. Only v1 has results so far. |
| Ranked triage report with suggested next action (proposal) | v2/v3 prompts add `next_action`; `/api/report.csv` and the queue are sortable by severity. |
| Summary-quality scoring without a human rater (proposal risk) | Automated rubric v2 (`summary_quality.py`). |

## Numbers right now (41-alert subset, Checkpoint 2 results, prompt v1)

| | Rubric v1 | Rubric v2 |
|---|---|---|
| Rule-based, all 519 | acc 0.97, kappa 0.93 | acc 1.00, kappa 1.00 |
| Rule-based, same 41 | acc 0.95, kappa 0.92 | acc 1.00, kappa 1.00 |
| Claude, 41 | acc 0.95, kappa 0.92 | acc 1.00, kappa 1.00 |
| Summary quality | 3.00/3 | 3.00/3 |

Under rubric v1 the fixed rule scorer now makes the same two mysql "errors" as Claude.
(Checkpoint 2 reported rule-based 1.00 because the old scorer shared the rubric's blind spot.)

## Things to say honestly in the write-up

1. Rubric v2 was written after seeing the mysql disagreement, and ground truth comes from
   the same fields the rule scorer reads. 1.00 under v2 is consistency, not independent accuracy.
2. The 41-alert subset only contained 2 of the 15 valid-account alerts. The other 13
   (uucp, ftp, git, sshd) have never been judged by Claude. The full live run is the real test.
3. The LLM results are from direct prompt application, not API calls, until the live run is done.
4. Dataset is attacker-only honeypot traffic: 71% High, 1 Critical, no benign traffic.
5. The v1 prompt does not contain the rubric; v3 does. Compare them to show how much of the
   agreement comes from the prompt telling Claude the rule.

## To finish the live run

    # key lives in .env (GEMINI_API_KEY=...)
    python llm_pipeline.py --version v2 --all --workers 4     # 519 alerts, resumable
    python llm_pipeline.py --version v3 --all --workers 4     # rubric-anchored prompt
    python llm_pipeline.py --version v1 --all --workers 4     # replaces the direct-prompt results
    python evaluate.py                                        # tables for both rubrics

Or click "Run Claude live" on the dashboard's Evaluation tab.

## Files
- `group_alerts.py` Loghub CSV to 519 grouped alerts (needs the Loghub CSV; output already in `data/`)
- `ground_truth.py`, `rule_based_scorer.py`, `llm_pipeline.py`, `summary_quality.py`, `metrics.py`, `evaluate.py`
- `alert_parser.py` raw log lines to structured alert (used by the API's paste-an-alert endpoint)
- `server/` FastAPI app, `web/` dashboard, `tests/` 32 tests
- `data/llm/<version>.json` cached LLM results with provenance (live API vs direct prompt)
- `legacy/` the 25-alert sample and Checkpoint 2 manual quality scores

## Provider change (Claude to Gemini)
The live pipeline now calls the Google AI Studio Gemini API (`google-genai`). The 41 saved
Checkpoint 2 results were produced with Claude and stay labeled as direct-prompt results.
Live runs are tagged `api_live` with the Gemini model name in their provenance, so do not
mix the two when reporting numbers.
