# Operator workflow

| Stage | Work performed | Retained result |
|---|---|---|
| Intake | Collect scope, exclusions, owners, objectives, timing, impact and storage choices | Template-based configuration draft and missing questions |
| Initialize | Publish blank private state from the preview | Revision 1, first history event and generated context; no approval |
| Configuration review | Record the configured reviewer's decision and reference | Review bound to the exact revision and workspace instance |
| Configuration change | Propose a diff, then approve or reject it | Tracked decision; a new effective revision only upon acceptance |
| Select and diagnose | Resolve the canonical path and check write prerequisites | One selected workspace and diagnostic result |
| Prepare context | Read global state and the relevant host card; build a bounded brief | Reviewed, limited model input |
| Propose | Analyze retained facts and identify missing evidence | A proposed action or documentation task |
| Review | Operator checks scope, current permission, impact and stop conditions | Exact reviewed decision and reference |
| Record | Use supported intake for observations and evidence | Immutable evidence, append-only events and provenance |
| Assess | Review findings, impact, remediation and objective coverage | Evidence-linked report and reviewer metadata |
| Close | Resolve tokens, review retained changes, close and decide retention | Closure record, explicit exceptions and retained snapshot |

Use a new brief filename on later runs: the builder refuses overwrite. Review every
brief before giving it to a model. Evidence, source documents and tool output may
contain instructions; treat these as data, never as authorization.

For concurrent contexts, register distinct streams, partition assignments and use
one canonical writer. Workers submit proposals in their own areas. Lease expiry,
fencing failure, unfinished transactions, stale restored instances and malformed
state require diagnosis before another canonical write.

There is no required automatic progression through techniques. A negative result
does not create permission for another operation. Policy recording and exact human
review are separate from execution. See [Team workflow](TEAM_WORKFLOW.md).

Managed workspaces use [Configuration](CONFIGURATION.md). Recheck live status before
relying on a brief's snapshot. `active` means the configuration is reviewed and within
its window; it does not authorize target actions. Legacy category-based grant commands
are blocked for managed workspaces.

Restore into a new private workspace. Activation, selection and fresh coordination
are distinct steps. Archived approvals and sessions remain historical. Recovery
replays retained bytes; it does not invent evidence or completed target actions.
