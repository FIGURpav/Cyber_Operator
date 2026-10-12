# Local deployment and compatibility

The supported model is one Linux/WSL installation per operator. Private assessment
collections, vaults, configuration, release backups and deployment receipts stay
outside the reusable source tree. Controlled handoff is future work. A shared
service would separately require authenticated users, permissions, tenant isolation
and protected audit storage; local actor labels and SHA chains do not provide them.

`cyber-deploy preview` accepts an approved release archive, runtime destination,
external state directory, wrapper directory, Python executable, configuration path
and a new plan file. Use Python 3.13 or newer on a Linux filesystem. For an older
installation without RELEASE_INVENTORY.json, supply its preserved `--baseline`
inventory. The installed files must match that inventory exactly. Local changes
must be reviewed before upgrading. Inspect the release archive hash, affected
schemas, installed file hashes, paths and rollback instructions in the preview.

Apply the exact `--plan-file`. The installer rechecks source and wrapper hashes,
builds an isolated runtime environment without network packages, validates the
staged source, retains the old runtime, activates the new source and updates the
wrappers. Runtime dependencies are standard-library only. Development tests still
use `uv sync --locked`. Use a state directory on the same filesystem as the runtime
so directory activation can use rename. Stop active model sessions before upgrade.

`cyber-deploy verify --destination ... --receipt ...` compares installed source
and wrappers with the retained manifest. `recover --receipt ...` finishes an
interrupted prepared deployment. `rollback --receipt ...` restores the prior
source and wrappers, retaining the newer source for analysis. Conflicting local
edits are refused. A clean install creates no assessment or active selection.

The installer does not rewrite configuration or workspace data. A code rollback
does not downgrade record schemas. Retain the matching runtime for each regression
snapshot; restore old workspace checkpoints into separate isolated locations.

| Contract | Read support in 0.7.0 | New writes |
| --- | --- | --- |
| Assessment configuration | Definition 1.0, events 1.0/1.1 | Definition 1.0; draft-capable events 1.1 |
| Assessment journal | Envelope 1.0 | Typed records, immutable revisions and hash links |
| Report | Historical 2.0; bound 2.1; findings snapshot 3.0 | Managed 2.1 or findings 3.0 |
| Credential source | Historical private inline values; local vault 1.0 | Vault references through cyber-vault |
| Query | Existing 1.0 files | Compatible query format; optional separate AI session records |
| Transactions | 1.0 with typed operation kinds | New activity, vault and disclosure kinds |

New transaction kinds and entity kinds require the new runtime. Older releases are
not guaranteed to understand newer workspace histories. Existing record IDs,
timestamps and historical hashes are preserved. Migration is explicit and separate
from deployment. Secrets and private runtime state are excluded from release ZIPs.
