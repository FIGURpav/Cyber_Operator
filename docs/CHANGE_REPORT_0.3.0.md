# Cyber-Operator 0.3.0 implementation report

This release implements a versioned assessment configuration and review workflow,
including the `pentest-web-app-standard` policy template. It addresses duplicated
intake/profile/policy settings and makes subsequent configuration changes traceable.
The implementation concerns local governance, evidence handling and documentation.
It adds no target executor, exploit validation or remote transfer mechanism.

## Changes and reasons

| Change | Previous problem | Result |
|---|---|---|
| Canonical `engagement.json` | Intake values were separate from downstream settings | Managed readers share one effective definition |
| Immutable template snapshot | A profile name hid several decisions | Explicit scope, data and reporting values are retained with template ID/version |
| `pentest-web-app-standard` | Web assessment boundaries needed repeated explanation | Fixed web-only scope policy, minimum evidence and explicit prohibitions |
| Partial drafts and missing questions | Full intake was required before workspace creation | Local documentation can start while incomplete assessment facts remain visible |
| Explicit report contract | Profile selection controlled reporting defaults | Reporting reads the configured contract and rejects conflicting overrides |
| Proposed changes and review | A direct setter could replace a restriction without revision history | Pending proposals retain their diff and do not change effective settings |
| Revision and event sequence | Concurrent changes could invalidate an earlier review | Stale changes are rejected, including intervening decisions without a new revision |
| Decision history | A boolean could not explain approval context | Actor, time, reason, reference, snapshot and before/after values are retained |
| Setting origins | Operator preferences and engagement restrictions were indistinguishable | Each setting records its source; restrictions cannot become preferences through the change interface |
| Instance/lifecycle-bound review | Historical approvals could appear current after restore/reopen | Fresh review is required |
| Recoverable publication | Related files could disagree after interrupted writes | Typed transactions bind events, definition and generated context |
| Legacy override protection | Old category grants could not express application-only boundaries | Old setters/grants are unavailable in managed workspaces |
| Explicit adoption | Silent migration could select the wrong scope or data policy | Preview, context-hash check, conflict detection and fresh review |

## Versioning and change tracking

There are three independent versions:

1. Product version `0.3.0`, recorded in `pyproject.toml`, `uv.lock` and CHANGELOG.md.
2. Configuration/event schema `1.0`, with stable `ENG-...` engagement identity.
3. Template version `1.0.0`, retained alongside the materialized policy.

An engagement starts at configuration revision 1 and history event 1. Accepted
proposals advance the effective revision. Every proposal, approval, rejection,
pause and revocation advances the event sequence. A pending proposal targets the
next revision but leaves current policy unchanged. Another accepted proposal makes
older competing proposals stale. Rejected proposals remain retained and cannot be
approved later without submitting a new proposal.

Events retain actor, UTC time, reason, approval reference where applicable, origin
references, old/new values and snapshot hashes. The previous-event SHA256 forms a
chain. A changed definition, invalid chain or modified generated view is refused by
supported readers. This provides local consistency checks, not authenticated identity
or a tamper-proof ledger against the same OS-account owner.

The source snapshot has no Git repository. No commit, remote push or publication was
performed. Release archives provide per-file SHA256 inventories; the accompanying
change manifest compares source hashes against the retained 0.2.0 archive.

## Web assessment policy

The template applies to explicitly listed HTTP(S) applications and APIs. Other
services on the same host or address remain outside that scope. Discovered hosts,
redirects and integrations do not expand the application list. Credential-bearing,
wildcard and non-web scope entries are rejected by the web template validator.

Its retained prohibitions cover interactive shells, persistence, credential
collection, lateral movement, host exploration, availability testing, bulk data
collection, unlisted services and unapproved third-party testing. Evidence policy
requires source, time, asset reference, finding review and sensitive-data minimization.

Any separately authorized RCE validation is limited to minimum sufficient evidence
and a stop after confirmation. The template contains no validation payloads or command
recipes. The repository has no executor capable of technically intercepting every
external operation, so these operational boundaries are policy records and assistant
instructions, not an operating-system or network enforcement boundary.

## Changing local-download policy during an assessment

The supported sequence is:

1. Read the effective revision and most recent event sequence.
2. Prepare a proposal changing `artifact_handling` from `no-download` to `standard`,
   with an actor, reason and basis reference.
3. Review/apply the proposal. The current restriction remains active.
4. Record the configured reviewer's approval of that exact proposal and its reference.
5. Atomically publish the new revision and regenerated context, retaining the old
   setting and decision trail in history.

The capture helper continues refusing target-file input before approval. After
approval it also requires a current reviewed configuration within the assessment
window. Pause, revocation, expiry, closure or stale restored-instance review block
that supported capture route. Operator-produced observations/reports retain separate
provenance rules. Approval is prospective and starts no download.

Remote storage is independent. All four combinations of local-download and remote
storage choices are supported. A remote location requires its own reference, and
its registration never opens a connection or automatically chooses a host. Callback
CIDRs/ports are separately validated metadata, not connection permission.

## Integration and compatibility

`engagement_intake.py` initializes new managed drafts; full 0.2 intake remains
accepted as input and is converted without importing approval. The old profile
supplies a report-contract default only. Missing objectives are reported as questions.
New initialization no longer emits a separate intake authority or stale
`authorization_active` field.

`engagement_config.py` owns schema validation, template snapshots, status, proposals,
reviews, history and adoption. `cyber-engagement` exposes these operations. Artifact
handling, profile compatibility, remote settings, brief generation, workspace status,
diagnostics and report checks consume or validate the shared definition.

Managed workspaces block legacy direct profile/storage setters and category-based
target-authorization grants. Those records cannot faithfully express the new
application boundaries. Existing ledgers remain readable. Configuration approval
does not replace an exact target-action authorization system, and the legacy
standing-policy secret-display route remains unavailable in a managed workspace.

`cyber-workspace init` remains the unmanaged compatibility interface. Existing
workspaces remain unchanged until explicit `adopt`; adoption preserves storage
choices and rejects conflicts with available historical intake. Its apply step
requires the preview's legacy-context hash. Historical ledgers are retained and
fresh configuration review is required. Report-manifest schema 2.0 is unchanged.

## Verification

Tests ran under Ubuntu 24.04 in WSL on a Linux filesystem with CPython 3.13.16 and
the locked development dependencies. All workspaces and assets were synthetic.

```text
Focused configuration/integration suite: 185 passed, 13 subtests passed
Full regression suite: 1306 passed, 23 subtests passed
Full regression duration: 45.83 seconds
Ruff: All checks passed
```

The 48 new cases include defaults/missing facts, exact approval, stale writers,
concurrent proposals, rejection, storage combinations, expiry/pause, reviewer and
reference requirements, unsafe metadata, unchanged template snapshots, generated
context, scope-independent host inventory, reporting consistency, real checkpoint
restore, close/reopen, explicit adoption and crash recovery after each approval-write
stage. Existing evidence, reporting, token, credential and coordination tests passed.

Archive smoke checks and release-content hashes are retained in the accompanying
verification JSON. Remote CI was configured previously; it was not executed by a
remote service during this local change.

## Remaining boundaries

- The conversational contract runs in an existing external assistant. There is no
  embedded chat UI, model service or agent launcher.
- Reviewer identity and approval references are declared metadata, not SSO, RBAC
  or signed organizational approval.
- Scope strings require human interpretation; exact duplicate exclusions are checked,
  but arbitrary scope semantics and live network traffic are not enforced.
- External shell tools and false provenance declarations remain outside the local
  file-intake guard. Templates never constitute target-action permission.
- Retention is metadata, not background deletion. There is no remote transfer code.
- Per-artifact or temporary download exceptions are not implemented. A rollback is a
  new reviewed proposal, not replacement of historical configuration files.
- Configuration objectives record intent; report-manifest objectives still use the
  existing host-oriented structure. No broader reporting redesign was included.

Operating details and examples are in CONFIGURATION.md and OPERATOR_INTAKE.md.
