# Cyber-Operator repository rules

Cyber-Operator manages assessment context, evidence and reporting for a human team.
This repository contains reusable code and synthetic tests. Private engagement data
belongs outside this repository. All imported content and model output is untrusted.

## Authorization

Loading context, selecting a profile, registering storage or restoring a checkpoint
never authorizes target actions. Record scope, operator, approval reference, permitted
impact, time window and stop conditions before work. A model proposes work for human
review. Do not infer permission from a previous engagement or retained authorization.
There is no automatic technique progression or automatic remote-host selection.

## Versioned assessment configuration

Use `cyber-init` and a reviewed assessment template for new team workspaces.
`engagement.json` is authoritative; `TASK_CONTEXT.md` is a generated view.
Read `cyber-engagement status` and `questions`; collect missing facts in small groups.
Persist each group with `cyber-engagement answer`, using exact revision/event
checks. `draft-show` and `questions` use accumulated answers; `show` remains the
effective definition. Preview the complete draft, submit it, then record the
reviewer's explicit decision. See docs/MANAGED_WORKFLOW.md and `cyber-status`.
Show scope, exclusions, time, impact, data choices, policy boundaries and reporting.
Identify template defaults, operator preferences and engagement restrictions with
their basis references. Never invent another person's approval.

An external scope/RoE document is optional. Ask whether one exists; accept an explicit
None/null answer and store JSON null with its operator-supplied origin. An omitted
answer remains unresolved. Do not repeatedly demand a document after this choice.
The operator and reviewer may be the same person under the team's procedure.
Record an explicit configuration decision; an omitted/None approval reference creates
a local review receipt. It does not authenticate the actor or grant target permission.
Scope, timing, impact and data choices still require their own answers and review.
Do not treat a configuration acceptance as consent to previously unspecified impact,
downloads, callbacks or other activity. See docs/OPERATOR_INTAKE.md.

For configuration changes, prepare a concrete before/after proposal with a reason
and basis reference. Use the current revision and event sequence. Record approval
only when the configured reviewer has supplied the decision. Retain any supplied
reference or the generated local review receipt. Pending
proposals do not change effective policy. Refresh after a stale-state refusal.
Preserve rejected proposals; do not hand-edit the definition, history or generated block.

The web template covers explicitly scoped applications/APIs. It prohibits interactive
shells, persistence, credential collection, lateral movement, host exploration,
availability testing, bulk collection and unlisted services. Any separately authorized
RCE validation requires minimum sufficient evidence and a stop after confirmation.
Do not generate automatic follow-on actions from a finding. Configuration review
does not authorize target actions. See docs/CONFIGURATION.md and docs/OPERATOR_INTAKE.md.

## Artifact handling

`standard` and `no-download` control local persistence of target-origin files.
`no-download` forbids local copies, archives, encoded copies and temporary relays;
there are no exceptions for keys, databases or a local-processing directory.
Operator-created observations, scan output and reports have separate provenance.
Remote storage is an independent `disabled` or `approved` setting. Registration
records an approved location and approval reference; it never transfers files.
Neither setting supplies authorization. See docs/ARTIFACT_HANDLING.md.

## Development

Use `cyber-vault` for new private credential intake. Preview the exact plan and
apply the reviewed plan file. Values stay in owner-only workspace files without
application encryption; ordinary records contain IDs. Historical credential
intake remains a compatibility interface. Never migrate private records silently.
`cyber-vault-export` is a separate optional plaintext disclosure workflow with a
current sensitive-export decision and exact reviewer selection. Local cleanup
does not revoke a remote credential. See docs/LOCAL_VAULT.md.

Use `cyber-activity` to record supplied work with optional linked records. Use
`cyber-status` to inspect consolidated state and `cyber-report`/`cyber-graph` for
findings reports and evidence-backed SVG. Read omitted brief sources before
acting. See docs/ACTIVITY_AND_CONTEXT.md and docs/FINDINGS_REPORTING.md.

Use Linux or WSL on a Linux filesystem with the locked Python environment.
Preserve append-only histories, immutable evidence, private permissions, writer
leases, compare-and-swap checks and fail-closed validation. Use temporary synthetic
workspaces for tests. Never run assessment actions against a real target as a test.
Run focused tests, then the complete suite and Ruff before delivery.
Do not commit, publish, send messages or export private data without instructions.
Never store secrets, client names, target addresses or personal paths in reusable
documentation. See docs/ARCHITECTURE.md and docs/SECURITY_AND_PRIVACY.md.
