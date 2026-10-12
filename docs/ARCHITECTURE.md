# Architecture and logical tree

This tree groups responsibilities; it is not a literal inventory of every file.

```text
Cyber-Operator/                       Reusable, shareable source
├── AGENTS.md                         Human control and development invariants
├── scripts/
│   ├── cyber-*                       Small CLI entry points
│   ├── engagement_intake.py          Partial intake and blank draft bootstrap
│   ├── engagement_config.py          Canonical definition, revisions and review history
│   ├── task_collection.py            Initialize, select and diagnose workspaces
│   ├── runtime_config.py             Deployment paths and environment configuration
│   ├── artifact_handling.py          Local persistence policy
│   ├── remote_storage.py             Independent approved-location metadata
│   ├── engagement_policy.py          Legacy authorization and disclosure records
│   ├── new_host.py, host_*.py        Canonical host identity and state projections
│   ├── *_intake.py, log_*.py         Validated local intake and append-only journals
│   ├── capture_evidence.py           Immutable bytes, metadata and hashes
│   ├── execution_provenance.py       Execution receipts and evidence-bound claims
│   ├── build_brief.py, log_query.py  Bounded context and retained query provenance
│   ├── structured_state.py           Findings, work items, explicit human review
│   ├── report_*.py, screenshot_*.py  Report contracts and reviewed captures
│   ├── stream_coordination.py        Same-user sessions, writer leases and fencing
│   ├── workspace_transaction.py      Local write journal and recovery
│   └── *_checkpoint.py, storage_*.py Snapshots, restore and reviewed retention
├── templates/                        Empty state, reports and versioned assessment presets
├── tests/                            Synthetic regression cases; no customer data
├── docs/                             Product contracts and operating guidance
├── knowledge_base/                   Empty index for separately reviewed public knowledge
├── config.example.toml               Neutral deployment example
└── .github/workflows/ci.yml           Tests, lint and release-content checks

Private data root/                    Outside the repository and release archive
├── workspaces/
│   ├── ACTIVE_TASK                   Selected workspace name, created explicitly
│   └── engagement-name/
│       ├── TASK_CONTEXT.md           Generated configuration view and workspace paths
│       ├── engagement.json           Current versioned definition and setting origins
│       ├── engagement_events.jsonl   Proposals, reviews, decisions and before/after diffs
│       ├── global.md, hosts/         Global and per-host state, once hosts are registered
│       ├── *.jsonl                   Append-only observations, work and audit records
│       ├── inbox/                    Untrusted input awaiting canonical intake
│       ├── evidence/                 Retained immutable evidence and hash metadata
│       ├── private/                  Credentials, tokens, writer coordination
│       ├── queries/                  Bounded model-query records
│       ├── report/                   Findings, narrative, reviewed screenshots
│       └── checkpoints/              Local snapshot metadata where applicable
├── checkpoints/                      Separately retained private snapshots
├── source-ro/                        Optional read-only, untrusted source mount
└── private-knowledge/                Separately managed private reusable notes
```

Private runtime directories are created only when needed. The release contains no
workspace tree, target, selected engagement, credential or active authorization.

## Integrity boundaries

Host IDs, evidence IDs, attempt IDs, execution IDs and claim IDs remain stable.
Evidence is immutable; operational history is append-only. Supported writes use
private modes, stable locks, transactions, writer fencing or compare-and-swap as
appropriate to their existing contracts. Restores require fresh activation and
coordination; historical approvals do not become live permissions.

Managed workspaces use one definition for scope, timing, storage and report settings.
Template snapshots never grant permission. Legacy operational profiles remain only
for compatibility; managed report checks use an explicit contract. Unresolved session
tokens still block closure and ordinary checkpoint creation.

## Scope of the implementation

There is no model router or target-action scheduler. Existing provenance helpers
record local execution evidence; storage registration has no remote transport.
The conversational intake is a documented interaction backed by a validated JSON
initializer and missing-field questions, not a built-in chat service. Time windows
affect configuration status and supported target-file capture. Retention is metadata;
there is no background deletion service or network execution control.

Configuration transactions preserve the definition, generated context and append-only
review history together. Revision/event checks reject stale writers. Restored or
reopened workspaces require fresh configuration review. See CONFIGURATION.md.

External document references are optional. A scope reference's existing origin
distinguishes an unanswered null from an explicit no-document answer. Input-boundary
normalization leaves old snapshots and hashes untouched. Explicit reviews without
external references receive internal receipts bound to the engagement and event
sequence; reviewer checks, compare-and-swap and lifecycle checks remain in place.
