# Activity records and bounded model context

`cyber-activity --input activity.json` previews a supplied observation. It does
not execute commands. Apply requires an actor, reason, idempotency key, current
configuration revision and current assessment event count. Repeating an applied
request with the same key returns its original receipt; a changed request using
that key fails. An interrupted transaction must be recovered before retrying.

The input contains `summary`, `result`, and optional lists `host_ids`, `asset_ids`,
`objective_ids`, `evidence_ids`, `finding_ids`, `change_ids`, `claim_ids`, `run_ids`.
Capture and verify evidence first. IDs must refer to existing records. Optional
`attempt: {status, next_step}`, `task: {kind, external_ref, state}`, and `finding`
(a finding patch as described in FINDINGS_REPORTING.md) create linked records in
one recoverable transaction. The finding inherits the activity's title, assets,
objectives and evidence unless explicitly supplied. Recording a hypothesis does
not validate it. The activity, task and attempt reuse the supplied narrative.

Changes, execution receipts and claims retain their own review contracts. The
activity links them after creation; it never invents command execution or target
changes. A simple observation needs none of those records. Structured probe
deduplication remains in `log_attempt.py`; use that interface for probe records.

`build_brief.py --max-bytes 65536 --section-bytes 16384` budgets the complete UTF-8
output. Canonical assessment settings and TASK_CONTEXT.md are reserved in full.
If they cannot fit, generation fails with an instruction to increase the budget.
Manual global/host notes and selected records are bounded. Omission entries give
the section, original byte count, included byte count and SHA-256. Global State
comes from global.md; Host State from the selected host card; the other section
names identify observations.jsonl, attempts.jsonl, loot.jsonl, queries/ or
assessment_events.jsonl. Count limits still apply before the byte budget.

Omitted notes are not evidence that no additional stop conditions exist. Read the
referenced source before acting. Brief generation is not an action approval.
The Python API supports `token_counter` plus `max_tokens`; the caller must supply
an exact counter for the selected model. The CLI reports bytes, not an estimated
token count. Individual source text files are limited to 8 MiB.

`cyber-ai` explicitly records provider, model, session_label, purpose, query_ids,
response_evidence_ids and decision_ids. Use `unknown` for unknown attribution.
Responses are optional reviewed evidence references; conversations are not
automatically captured. Existing query files remain readable. `cyber-provenance
record` is the preferred alias for `run`: both record a supplied receipt and
neither executes a target command.
