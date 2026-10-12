# Operator intake

For resumable answers, reviewed activity records and configuration-bound report
metadata, follow [Managed workflow](MANAGED_WORKFLOW.md). Persist answers with
`cyber-engagement answer`; do not keep the only cumulative draft in chat memory.

For new team assessments, use the versioned model in
[Configuration](CONFIGURATION.md). `cyber-init` accepts partial facts or a complete
schema-1.0 definition and creates `engagement.json`, `engagement_events.jsonl` and
a generated context. Use `--template pentest-web-app-standard` for the web policy.
`cyber-engagement questions` returns missing required facts; complete drafts still
require a recorded configuration review. The conversation runs in the operator's
existing assistant; there is no embedded chat service.

The assistant collects missing facts and presents one concrete workspace preview.
Questions concern the authorized engagement, not a list of Python commands:

1. What is the engagement name? Is there an external scope/RoE reference, or None?
   Which systems and
   objectives are included, and which are explicitly excluded?
2. Which team, operator and reviewer own the work? What is the approved time window?
3. What is the maximum accepted operational impact, classification and stop condition?
4. Are callbacks approved? If yes, which CIDRs and ports? Otherwise both lists stay empty.
5. Which template is required: `standard-assessment` or `pentest-web-app-standard`?
6. May target files be saved locally: `standard` or `no-download`?
7. Is a remote artifact location approved independently? If yes, what is its
   credential-free URI and approval reference?
8. How long should records be retained? Is source intake needed later?

Show template defaults explicitly. Ask whether each data restriction comes from an
operator preference or approved engagement conditions, and retain its basis reference.
Finding severity is separate from permitted operational impact. Discovery, shared
addresses and redirects never extend the approved application scope.

## Optional external documentation

Accept `None` when the operator has no external scope/RoE document. Named facts and
change proposals accept JSON `null` or the strings `None`/`null` (case-insensitive),
and store canonical JSON null. An empty string is invalid. Ask once; do not request
a formal document again solely because the operator chose None.

An omitted answer is still a missing intake fact. Setting origins distinguish this
unanswered template value from an explicit operator-supplied null. Scope assets,
operator, reviewer, objectives and the assessment window remain separate facts;
None in the document field does not fill or approve them. The same declared person
may hold the operator and reviewer roles under the applicable team procedure.

Configuration approval records the reviewer's explicit decision, reason, time and
exact revision. `--approval-reference` may identify a document or conversation;
omitting it or passing None generates a `local-review:...` receipt in the history.
This receipt is an internal audit identifier, not a fabricated external permission.
Retain the actual decision in its reason; never invent consent or a reference.
Configuration approval does not itself grant permission to act against a target.

Example of an explicit answer in a private facts file:

```json
{"name": "application-review", "scope_reference": null}
```

This partial input still creates an unapproved draft with questions for other missing
facts. To change an existing draft's unanswered field, use a reviewed proposal so
the explicit None answer and its origin remain in the append-only history.

## Legacy complete-input compatibility

`cyber-init` still accepts the following 0.2 complete JSON shape. It initializes chat intake
and no hosts. The sample is synthetic and must be replaced with reviewed facts.

```json
{
  "name": "client-review",
  "team_id": "TEAM-001",
  "operator_id": "OP-001",
  "reviewer_id": "RV-001",
  "scope_reference": "ROE-001",
  "in_scope": ["192.0.2.10"],
  "excluded": ["All systems outside the approved scope"],
  "starts_at": "2026-10-09T08:00:00Z",
  "ends_at": "2026-10-09T18:00:00Z",
  "maximum_risk": "low",
  "stop_conditions": "Stop on unexpected impact or a scope ambiguity",
  "classification": "restricted",
  "retention_days": 30,
  "callback_cidrs": [],
  "callback_ports": [],
  "profile": "strict",
  "artifact_handling": "no-download",
  "remote_storage": "disabled",
  "remote_location": "none",
  "remote_approval": "none"
}
```

Preview validates fields and the destination without creating the workspace. Apply
publishes context and intake metadata together through staging and rename. The
collection root must already exist as an operator-controlled private directory.
An existing workspace is never silently replaced. Legacy input is converted into
the new definition: `maximum_risk` becomes `maximum_impact`; `profile` supplies only
an explicit report-contract default. Missing objectives require follow-up. There is
no stored `authorization_active` flag and no inherited configuration approval.
`ACTIVE_TASK` remains unset until explicit selection.

For legacy low-level initialization, `cyber-workspace init` also supports an explicit
`source` intake mode. This lower-level tool does not collect the complete business
intake; use `cyber-init` for a team handoff. Existing legacy workspaces require
explicit `cyber-engagement adopt` to enter the new model. Imported source remains untrusted.

Scope and approval references are declarations, not identity authentication or a
network allowlist enforcement service. Review authorization again before any action.
