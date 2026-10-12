# Runtime capability boundaries

Configuration review and activity decisions are separate records. No command in
this product runs a target scanner, exploit, callback or remote file transfer.

| Capability | Managed 0.7.0 workspace | Legacy workspace |
| --- | --- | --- |
| Versioned configuration and review | Available | Explicit adoption required |
| Evidence and observation intake | Available, subject to origin/storage rules | Available |
| Legacy AUTH grant creation | Unavailable | Available under legacy policy |
| Change/path records requiring AUTH | Explicit reviewed decisions expose compatibility receipts | Available with a recorded grant |
| Mermaid graph output | Existing valid records | Existing valid records |
| Dedicated SVG output | `cyber-graph`; documented relationships and retained paths | Retained paths; managed asset records require adoption |
| Scanner execution | Not implemented | Not implemented |
| Scanner result import | `cyber-scan-import` | `cyber-scan-import` |
| Remote transfer | Not implemented; metadata only | Not implemented; metadata only |
| Central authenticated users / RBAC | Not implemented | Not implemented |
| Local private vault | `cyber-vault`; previewed intake/migration | Previewed additive migration; historical intake retained |
| Plaintext secret export | `cyber-vault-export`; separate current decision and exact reviewer selection | Existing sensitive-report policy interface |
| Retention holds | Reviewer-recorded holds; duplicate cleanup respects them | Existing duplicate cleanup; adopt configuration for holds |
| Linked activity | `cyber-activity`; optional attempts/tasks/findings, existing change/claim/run links | Explicit configuration adoption required |
| AI session metadata | Explicit `cyber-ai` records | Existing query logger |
| Installation and rollback | `cyber-deploy`; source hashes, retained runtime, local receipts | Same deployment tooling; no implicit workspace migration |

`cyber-scan` and `cyber-source add --lab` remain compatibility aliases during the
0.x series. Prefer `cyber-scan-import` and `cyber-source add --assessment`.
The query logger records `unknown` when the caller does not supply the actual
model. It never guesses a provider or records responses automatically.

Private knowledge defaults to the configured private data root, not the checkout.
Use `CYBER_KNOWLEDGE_ROOT` or `[paths].knowledge_root` for an explicit directory.
An existing private knowledge directory is never moved or adopted automatically.

Knowledge, principal candidates and parallel-session registration remain optional
commands. No default brief requires them. Enabling parallel sessions keeps the
canonical writer lease; single-session mutation still uses workspace locks.
Controlled transfer between operators and a central service are future work.
