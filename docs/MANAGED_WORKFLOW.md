# Managed assessment workflow

The supported deployment is one local Linux/WSL runtime per operator. Private
assessments and their local vaults are outside the product checkout. A shared
server, authenticated multi-user service and automatic handoff are not included.
Values in the private workspace vault use filesystem protection, not an extra
password or application-layer encryption. Ordinary reports use references.

## Resumable intake

1. Initialize a named draft with `cyber-init` and the selected assessment template.
2. Read `cyber-status --workspace PATH` and `cyber-engagement questions`.
3. Collect a small group of answers. Use `cyber-engagement answer --input FILE`
   with the workspace, actor, reason, basis, basis reference, exact configuration
   revision and configuration event sequence. Preview first, then apply.
4. Repeat across sessions. `draft-show` reads accumulated answers, while `show`
   reads the effective definition. Explicit None remains distinct from unanswered.
5. Show all settings, exclusions, defaults and origins. Scope, time, impact,
   downloads, callbacks, remote location and retention are independent choices.
6. `submit` creates a proposal from complete draft answers; it does not activate it.
7. Record `approve` only after the configured reviewer has supplied the decision.
   The reviewer may be the operator. An absent external reference creates a local
   receipt. `discard-draft` retains history while abandoning draft answers.

`answer` appends schema-1.1 configuration events. The effective definition remains
schema 1.0 and unchanged until approval. Readers in release 0.3.x do not understand
new draft event kinds: retain a checkpoint before using the new writer.

## Reviewed activities

Use `cyber-decision propose` for a concrete human-review record. Input contains
purpose, scope assets, registered hosts, category, impact, technique/summary,
start/end time, declared capabilities and callback CIDRs/ports. The proposal must
fit the reviewed configuration and template boundaries. It never runs a tool.

`cyber-decision approve`, `reject` and `revoke` use the configured reviewer and
the exact assessment-journal sequence. This counter is separate from the
configuration event counter; `cyber-status` shows both. Approval preserves the
exact proposal and configuration/instance/lifecycle binding. Configuration
changes, revocation, restoration and reopening prevent reuse of stale decisions.

Approved target-activity decisions expose read-only AUTH compatibility receipts
for existing change/path recorders. No legacy authorization ledger is rewritten.
Historical records remain readable after revocation. Recording a configuration
review never manufactures an activity decision.

## Configuration-bound reporting

`cyber-report draft-manifest --workspace PATH --host-id H01` prints schema-2.1
metadata from the reviewed configuration. It supports an absent external scope
reference and multiple distinct configured objectives for the selected host.
Use the existing manifest preview/apply commands to retain it.

Schema 2.1 records engagement ID, revision, snapshot hash and approval event.
Team ID, scope reference, start date and objectives must match that snapshot.
Older schema-2.0 reports remain readable; new managed writes require 2.1.
An older snapshot remains historical data after configuration changes; readiness
identifies the need to refresh it. An ended assessment window alone does not
invalidate its historical report. Findings-led reporting follows in the next stage.

## Separate status dimensions

`cyber-status` returns technical write readiness, effective configuration, saved
draft questions, independent review choices, lifecycle, decisions and report
metadata. `--report` requests the more expensive complete report check.
There is no single green status that implies permission to execute target tools.
