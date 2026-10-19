"""One-off: move the Checkpoint 2 LLM results into the per-version cache with provenance.

Those 41 results were produced by applying the v1 prompt/schema directly (no
ANTHROPIC_API_KEY was available in the dev sandbox), so they are tagged
"direct_prompt", not "api_live". A live run replaces them.
"""
import json
import os

here = os.path.dirname(os.path.abspath(__file__))
src = json.load(open(os.path.join(here, "data", "llm_results_expanded.json")))
out = {}
for r in src:
    rec = {k: v for k, v in r.items() if k != "alert_id"}
    out[r["alert_id"]] = {
        "result": rec,
        "meta": {
            "source": "direct_prompt",
            "model": None,
            "prompt_version": "v1",
            "timestamp": "2026-10-04 (Checkpoint 2)",
        },
    }
os.makedirs(os.path.join(here, "data", "llm"), exist_ok=True)
json.dump(out, open(os.path.join(here, "data", "llm", "v1.json"), "w"), indent=1)
print(f"Migrated {len(out)} Checkpoint 2 results -> data/llm/v1.json")
