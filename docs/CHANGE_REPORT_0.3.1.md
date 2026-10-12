# Cyber-Operator 0.3.1 change report

## Problem and resulting behavior

Version 0.3.0 treated a null external scope reference as a missing required fact.
An operator who explicitly had no separate RoE document could not finish configuration
review without supplying a text reference. Conversation guidance could consequently
repeat a request for a formal document.

Version 0.3.1 accepts an explicit None answer. External paperwork is optional;
the configuration still records who reviewed the exact scope, dates and policies.
This change concerns local metadata and conversation guidance. It adds no target
executor or permission-granting mechanism.

## Design

| Input or decision | Result |
|---|---|
| Omit scope_reference from named facts | Unanswered; the intake question remains |
| Supply JSON null, None or null text | Canonical null with an explicit setting origin |
| Supply a real reference | Preserve the reference |
| Supply an empty string or other value type | Reject invalid input |
| Explicitly approve without an external reference | Store a local-review receipt |
| Propose removal of an existing reference | Retain the previous value until exact review |

The existing schema-1.0 origin record distinguishes template nulls from explicit
answers. No schema field, template version or historical hash needs to change.
Normalizers operate on new facts and proposed settings, never on loaded snapshots.
Historical textual None/null references remain readable without rewriting them.
Status exposes the derived state: unanswered, no-external-document or provided.

Local review receipts contain the engagement ID and next event sequence. They are
stable across preview/apply under the existing compare-and-swap checks. The approval
event retains actor, reason, timestamp, exact snapshot, instance and lifecycle epoch.
A receipt is an internal event identifier, not an invented external document or an
authenticated signature. The configured reviewer must still supply the decision.

## Compatibility and limits

Legacy complete intake accepts the same optional scope-reference values. Existing
document references, immutable history and generated context remain readable.
No workspace is automatically rewritten, reviewed, selected or activated by the upgrade.
An existing unanswered value is changed through propose/approve to preserve its origin.
An old draft with an already explicit null may now be ready for review; this does not
create an approval event or imply permission.

Operator and reviewer may be the same person under the team's procedure. Their IDs,
team, actual scope, objectives and assessment dates remain separate required facts.
None is not a universal bypass for arbitrary configuration fields. High impact,
target-file downloads, callbacks and remote storage remain independent choices.
Web-template prohibitions, closed/expired workspace checks and legacy grant blocking
are unchanged. The attack-path/SVG integration is outside this change.

## Validation and release tracking

Focused and complete synthetic regression results are recorded in CURRENT_STATE.md
and the accompanying release verification JSON. Release packaging retains a source
inventory, archive checksum, file-level change manifest and patch against 0.3.0.
The previous release is retained. No live target requests are part of validation.
