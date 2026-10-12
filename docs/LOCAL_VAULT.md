# Local workspace vault

The supported backend is `workspace-vault`: private plaintext files in each
workspace, protected with owner-only 0700 directories and 0600 files. There is no
extra password, encryption service or external vault dependency. The deployment
is local per operator. Actor names are audit labels, not authenticated identities.

New intake uses `cyber-vault preview --workspace ... --input-file ... --plan-file
...`. The private input uses the existing credential block format: host, one of
password/token/api_key, and optional username, service, url, realm and note. The
preview validates hosts, deduplicates values and prints metadata only. Inspect the
plan, then use `cyber-vault apply --workspace ... --input-file ... --plan-file ...`.
Changed input or private ledgers invalidate the plan. Plan files are private and
must be stored outside the source checkout. `list` prints reference metadata.

Values are stored under `private/vault/values/SEC-*.secret`. Metadata is appended
to `private/vault/credentials.jsonl`; it contains CRED IDs and `vault:SEC-*`
references. Internal credential adapters resolve values only for operations such
as secret filtering and validated token promotion. Missing values, permissive
file modes or an unavailable provider fail closed. There is no CLI that prints a
resolved value to standard output. An unsupported `CYBER_SECRET_PROVIDER` value
fails rather than silently selecting a different backend.

Ordinary activity records, findings, briefs and reports use references. Private
transaction payloads also retain secret bytes for recovery. Restrict the whole
workspace and its backups, not only the values directory. Vault intake does not
erase the operator's input file. Legacy intake files and ledgers remain private.

## Explicit migration

Use `cyber-vault preview --workspace ... --migrate --plan-file ...`, inspect the
record IDs and hashes, then apply that plan. Migration is additive: it copies each
unmigrated value to the provider, preserves credential IDs, retains the original
ledger byte-for-byte, and records a checkpoint under private/vault/checkpoints/.
It does not rewrite historical events, delete source values or purge old intakes.
Keep a complete workspace checkpoint before operational migration. No real
workspace is migrated during software installation or upgrade.

Interrupted publication uses `cyber-recovery inspect/apply`. The transaction keeps
the exact value and metadata payloads until completion. For rollback testing,
restore the pre-migration checkpoint to a separate workspace and activate/review
it through the normal restore procedure. Do not remove referenced values from an
active history or run an older runtime against new vault records.

## Optional plaintext export

The default workflow does not export values. For a required local disclosure,
record and approve a current decision with purpose `sensitive-export`. Then use
`cyber-vault-export preview` with exact credential IDs, the decision ID, configured
reviewer, reason, intended audience, retention days and current revision/event
counters. Retention must remain within the assessment policy. Inspect the private
plan file and apply it explicitly. The selected credentials must belong to the reviewed
hosts. Configuration changes, revocation, expiry and restore invalidate the decision.

The output is an owner-only file in private/vault/exports/. Its receipt contains
IDs and hashes, not values, and is published atomically with the export. The tool
does not send the file anywhere. It does not enable the legacy sensitive-report
policy. Local retention or deletion never claims a remote credential was revoked.

## Retention

`cyber-retention status` shows classification, retention days, review due date and
holds. A due date requests administrative review; it never schedules a purge.
The configured reviewer can append `hold` or `release` for `*` or an exact TXN ID,
including after closing the assessment. State changes use revision/event checks.

`cyber-storage compact` and `prune-restore` retain their exact-path/hash previews,
minimum ages and explicit apply plan hashes. Holds block cleanup. Only byte-for-byte
duplicates with verified retained copies are eligible. Canonical evidence,
history, vault values and whole workspaces are never automatically deleted.
