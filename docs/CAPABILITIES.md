# Runtime capability boundaries

Configuration review and activity decisions are separate records. No command in
this product runs a target scanner, exploit, callback or remote file transfer.

| Capability | Managed 0.4.0 workspace | Legacy workspace |
| --- | --- | --- |
| Versioned configuration and review | Available | Explicit adoption required |
| Evidence and observation intake | Available, subject to origin/storage rules | Available |
| Legacy AUTH grant creation | Unavailable | Available under legacy policy |
| Change/path records requiring AUTH | Explicit reviewed decisions expose compatibility receipts | Available with a recorded grant |
| Mermaid graph output | Existing valid records | Existing valid records |
| Dedicated SVG output | Unavailable | Unavailable |
| Scanner execution | Not implemented | Not implemented |
| Scanner result import | `cyber-scan-import` | `cyber-scan-import` |
| Remote transfer | Not implemented; metadata only | Not implemented; metadata only |
| Central authenticated users / RBAC | Not implemented | Not implemented |

`cyber-scan` and `cyber-source add --lab` remain compatibility aliases during the
0.x series. Prefer `cyber-scan-import` and `cyber-source add --assessment`.
The query logger records `unknown` when the caller does not supply the actual
model. It never guesses a provider or records responses automatically.

Private knowledge defaults to the configured private data root, not the checkout.
Use `CYBER_KNOWLEDGE_ROOT` or `[paths].knowledge_root` for an explicit directory.
An existing private knowledge directory is never moved or adopted automatically.
