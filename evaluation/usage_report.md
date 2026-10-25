# Usage Report — Ghost Data Still Exists

## Model providers and names

| Provider | Model | Used in final run |
|---|---|---|
| — (none) | — | No LLM provider is used at evaluation time |

The submitted solution is a **deterministic, rule-based pipeline**. All
deletion-status decisions, identity resolution, evidence indexing, policy
application, and step planning are implemented in plain Python with no model
inference in the evaluation path (`code/intent.py`, `code/identity.py`,
`code/evidence_index.py`, `code/investigator.py`, `code/planner.py`,
`code/policy.py`). No API keys are read or required; behavior is
reproducible offline.

## Final full-dataset run (the run that produced `output.csv`)

| Item | Value |
|---|---|
| Requests processed | 518 (`dataset/deletion_requests.csv`) |
| Rows written | 518 (`output.csv` at repository root) |
| Runtime | 0.5 s end-to-end (single process) |
| Model calls | **0** |
| Input tokens | **0** |
| Output tokens | **0** |
| Total tokens | **0** |
| Average tokens per request | **0** |
| Estimated total cost | **$0.00** |
| Estimated cost per request | **$0.00** |

## Per-model totals

Not applicable — no model is invoked; there is a single zero-cost,
zero-token total above.

## Why token usage is zero

All language-dependent work (deletion intent across a dozen languages) is
handled by the compiled pattern rules in `code/intent.py`, and all evidence
understanding (SQL, JSON, structured logs, csv) is handled by deterministic
parsers in `code/evidence_index.py` / `code/loader.py`. This keeps the
submission auditable, deterministic, and private (no data leaves the machine).
