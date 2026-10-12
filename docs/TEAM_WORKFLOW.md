# Team workflow

Record `team_id`, `operator_id`, `reviewer_id` and the external scope reference (or an explicit None) at
intake. Use organizational aliases, not credentials. Work items carry an immutable
`owner`. `reviewed` requires a named reviewer, an automatically recorded UTC event
time and a non-empty review basis. A declaration alone is not an authenticated sign-off.

Each operator should use a private OS account/runtime and a separate collection.
Within one runtime, model sessions use distinct registered streams, partitioned
assignments and one canonical writer lease. Writer fencing prevents stale sessions
from publishing through supported writers. It does not isolate mutually distrustful
users or provide a central authorization service.

For a handoff, close or checkpoint according to token and retention rules, review
the package's classification and transfer it through the team's approved channel.
The recipient restores into a new workspace, reviews scope and evidence, activates
the new runtime and establishes fresh coordination. Historical approvals stay inactive.

Managed configuration reviews retain the reviewer, reference, exact revision, UTC
time, workspace instance and lifecycle epoch. Proposals, approval, rejection, pause
and revocation are append-only. Revision and event sequence protect against stale
writes. Restore/reopen require fresh review. The configured reviewer may also be the
operator when team procedure allows it; no identity is authenticated here.

Identity and retention remain metadata. Assessment windows affect configuration
status and supported target-file capture; they do not govern every external tool.
Central RBAC, SSO, signed approvals, automatic expiration of every external tool and
a shared service with per-user audit identity are not implemented in this release.
