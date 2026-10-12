# Assets, findings and report snapshots

Use `cyber-asset`, `cyber-objective` and the `record`, `revise`, `review`, `list`
and `history` operations of `cyber-finding` for the managed model. The generic
`cyber-assessment KIND COMMAND` interface also supports `relationship` records.
Existing finding `create`/`transition` commands retain their historical contract.

Writes accept a JSON `--input`, actor, reason, exact configuration revision and
assessment-journal sequence. `--id` identifies a record to revise or review.
Preview first; add `--apply` to persist the same reviewed input at those counters.
An omitted external review reference produces a local receipt. Record identifiers
remain stable across revisions; historical evidence and old finding records are
not rewritten. Changing a record clears its previous review.

## Asset and objective model

Assets describe applications, endpoints, services, hosts or identities. Each has
a name, locator and explicit `scope_assets` references to the configuration.
Optional host IDs preserve links to Hxx evidence and historical host identity.
Parent assets support an application/service hierarchy; cycles are rejected.

An objective has a title from the reviewed configuration and one or more asset
references. Many objectives may concern one application. Outcomes are planned,
in-progress, complete, partial, not-tested or not-applicable. Partial, not-tested
and not-applicable outcomes require a limitation; complete outcomes require
evidence or linked findings. No artificial loot record is needed.

## Finding lifecycle

- `confidence`: hypothesis, confirmed, disproved or unresolved.
- `remediation_status`: unplanned, planned, in-progress, remediated or accepted-risk.
- `retest_status`: not-tested, passed, failed or inconclusive.

Confirmed findings and retests require evidence. A passed retest requires
remediated status; a failed retest must reopen remediation. Risk acceptance
requires the configured reviewer's explicit action, reason, reference and expiry.
Severity, impact and recommendations can be corrected through new revisions.

Ordinary findings use sufficient evidence. Set `evidence_policy: screenshot`
only when the delivery needs PNG evidence. Human review remains required; a
structured result can otherwise be sufficient without a screenshot.

## Reports

`cyber-report readiness --workspace PATH` evaluates current objective coverage,
finding reviews, explicit evidence requirements and unresolved token state.
`cyber-report build --workspace PATH --output report/assessment-v1.html` previews
an HTML report with a matching schema-3.0 JSON snapshot. Add `--apply` to publish
both through one recoverable transaction. Existing output is never overwritten.
Unresolved checks produce an explicitly marked draft, not a false success claim.

The snapshot binds a reviewed configuration, exact assessment-journal sequence,
record revisions and hashes. Old snapshots remain verifiable after later changes;
readiness identifies stale snapshots. No external document is required when the
operator explicitly selected None. Client output excludes secret values and
does not automatically publish prompts or the full AI conversation.

`cyber-report snapshot` prints the same schema for the existing manifest
preview/apply interface. Schema 2.0/2.1 historical readers remain available.
PDF/DOCX adapters can be added separately; the canonical deliverables here are
HTML and JSON. They require no remote rendering service.

## Documented graph

Relationship records reference assets/findings and classify an edge as observed,
inferred or rejected. Observed relationships require evidence references.
`cyber-graph --workspace PATH --output report/attack_path.svg` previews a local,
deterministic SVG; `--apply` stores it without overwrite. The export also includes
valid retained operational path records. It escapes supplied text, contains no
active scripts or external fetches, and never generates follow-on target actions.
