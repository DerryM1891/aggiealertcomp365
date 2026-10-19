# AggieAlert Summary-Quality Rubric (v2, automated)

Second evaluation measure from the approved proposal. Applies only to LLM output (the
rule-based baseline has no natural-language summary, which is part of the comparison).
Implemented in `summary_quality.py`; every criterion is a deterministic check against the
raw log lines, so scores are reproducible and work on live API output with no human rater.
This addresses the proposal's stated greatest risk (subjective scoring).

Each summary is scored 0 or 1 on three criteria; the quality score is the sum (0-3).

| Criterion | Passes (1) when... |
|---|---|
| **Entity extraction** | `source_ip` and `target_user` appear in the raw log lines (or are null only when the log has none). |
| **Actionable / evidence cited** | The rationale (plus summary and next action) cites concrete evidence from this alert: a log phrase, the account, or the IP. It is not just a severity label. For prompts v2 and v3, `next_action` must also be a real step (3+ words). |
| **No hallucinated detail** | No IP absent from the log, no failure count the log does not support, no claim of a successful login without an `Accepted password` line, no user not in the log. |

## Limits

These are heuristics. They catch invented IPs, users, counts and login claims, and generic
rationales. They do not judge whether a next action is wise. The 41 Checkpoint 2
summaries were scored by hand at 3.00/3; the automated rubric also gives 3.00 on them.
For a stronger claim, add a small human-rated sample and report agreement with the
automated score.
