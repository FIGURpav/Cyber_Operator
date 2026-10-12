# Cyber-Operator 0.5.0 — 2026-10-12

- Added versioned application/service/endpoint assets and many-to-many objectives.
- Added independent finding confidence, remediation, retest and risk-acceptance
  dimensions with retained revisions and exact human review records.
- Added configuration-bound schema-3.0 report snapshots and local HTML reports;
  incomplete coverage is represented explicitly without invented loot or success.
- Added evidence-backed relationship records and deterministic SVG graph export,
  including compatible retained operational paths and escaped labels.
- Included managed finding/objective revisions in close previews.
- Fixed real-clock decision review timestamps to use one event timestamp.

# Cyber-Operator 0.4.0 — 2026-10-12

- Added resumable draft answers, explicit submission and draft discard without
  changing effective settings before review. New draft events use schema 1.1.
- Added configuration-bound report manifest schema 2.1, optional external scope
  references and multiple distinct objectives on a host; retained old readers.
- Added reviewed activity decisions in a typed, hashed assessment journal with
  exact sequence checks, transaction recovery and read-only AUTH compatibility.
- Unified impact ranking while retaining historical `moderate` records unchanged.
- Added a consolidated `cyber-status` with separate technical, configuration,
  decision and reporting state. No executor or shared-user service was added.

# Cyber-Operator 0.3.2 — 2026-10-12

- Retained release 0.3.1 and established local source history for staged changes.
- Added `cyber-scan-import` and `--assessment` with existing names as aliases.
- Replaced the guessed query-model default with the explicit `unknown` value.
- Routed private knowledge through runtime configuration, outside the checkout.
- Added a capability matrix and tracked cross-module acceptance scenarios.

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
