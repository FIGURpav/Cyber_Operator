# Cyber-Operator 0.3.1 — 2026-10-09

- Made external scope/RoE documentation optional through an explicit None/null answer.
- Distinguished unanswered draft fields from no-document answers using existing origins.
- Normalized None/null strings at intake and proposal boundaries without rewriting history.
- Added scope_reference_state to status and updated the missing-field question.
- Made external approval references optional; explicit reviews receive local audit receipts.
- Preserved reviewer identity checks, exact revision/event review, lifecycle boundaries,
  explicit scope, impact and data policies. No target authorization is inferred.
- Updated English agent instructions and added regression coverage for document-free intake.

See [Change report](docs/CHANGE_REPORT_0.3.1.md).

# Cyber-Operator 0.3.0 — 2026-10-09

- Added a canonical schema-1.0 definition for newly initialized team workspaces.
- Added `standard-assessment` and `pentest-web-app-standard` template snapshots,
  version 1.0.0, with explicit scope, evidence and human-review boundaries.
- Added `cyber-engagement` for drafts, questions, status/history, proposals, approval,
  rejection, pause, revocation and explicit legacy adoption.
- Versioned accepted changes; retained before/after values, origins, actors, UTC
  times, reasons, approval references and an append-only SHA256 event chain.
- Bound reviews to exact revisions, instances and lifecycle epochs; restored and
  reopened workspaces require fresh review.
- Preserved effective settings until approval; rejected stale writers by checking
  both configuration revision and event sequence.
- Integrated recoverable transactions, generated context, briefs, diagnostics,
  explicit report contracts and supported local target-file intake.
- Blocked legacy setters and legacy target-authorization grants in managed
  workspaces while preserving historical records and legacy compatibility.
- Added explicit adoption previews without silently changing storage or scope facts.
- Expanded synthetic regression coverage and English documentation.

See [Configuration](docs/CONFIGURATION.md), [Change report](docs/CHANGE_REPORT_0.3.0.md)
and [Verification](docs/CURRENT_STATE.md). No embedded model, target executor,
authenticated approval service or remote transfer implementation was added.

# Cyber-Operator 0.2.0

- Adopted the Cyber-Operator product name, `cyber-*` commands and `CYBER_*` runtime variables.
- Replaced training-specific profiles with `strict` and `controlled-engagement`.
- Split `no-download` from approved remote-location registration; removed local file exceptions.
- Added validated team intake, scope metadata and atomic blank workspace creation.
- Centralized deployment paths; private data defaults outside the source checkout.
- Replaced the scored report manifest with engagement objectives and team metadata.
- Added explicit reviewer, timestamp and review basis to reviewed work items.
- Removed broad takeover presets and automatic technique-progression instructions.
- Required a human review reference for exact authorization records.
- Preserved separate disclosure/export controls and made unresolved tokens block both profiles.
- Replaced historical documentation, personal setup material and legacy graphics.
- Standardized all shipped operator instructions and screenshot prompts in English.
- Added clean-release checks and CI using synthetic workspaces only.

This release starts new workspaces and does not rewrite private historical archives.
Canonical evidence and event identifier families remain unchanged.
