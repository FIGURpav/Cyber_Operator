# Artifact handling

`standard` and `no-download` control **local persistence of target-origin files**.
Remote storage is a separate setting. Neither setting supplies authorization.

Under `no-download`, target files, repositories, archives, database copies, key files
and encoded or reconstructed equivalents must not be copied to local disk. This
includes temporary files and local relay directories. `private/local_processing/`
does not provide an exception. Enabling an approved remote location does not change
this local restriction. Store failure never causes an automatic fallback.

Operator-created observations, scan results, screenshots, notes and reports may be
retained through their canonical routes, subject to the engagement's privacy rules.
Classify provenance truthfully: a target file wrapped in a locally generated archive
or script remains a target-origin file. A model prompt or a query log must not be used
to retain a prohibited file or its encoded contents. Structured credential values
have their own explicit private-intake and disclosure controls; this is not an
exception allowing download of credential files.

## Local enforcement

`capture_evidence.py` defaults to `--origin target-file`. Under `no-download` it
rejects that origin before reading artifact bytes. `--origin operator-generated`
is an explicit declaration for operator-produced output. Local-processing artifact
registration is rejected under `no-download`. Source bootstrap requires
`--attest-preexisting-nontarget-source` before copying operator-supplied source.
Malformed policy fields fail closed. Managed workspaces read `engagement.json` and
require a reviewed proposal to change the mode. Pending proposals leave the active
restriction unchanged. Target-file capture under `standard` also requires current
configuration review within the approved time window. The legacy
`--ack-local-full-file-risk` setter applies only to unmanaged workspaces.

These guards cannot technically intercept an arbitrary shell command or determine
whether an operator's provenance declaration is truthful. The runtime does not
provide an operating-system DLP boundary, prevent third-party tools from writing
files, erase files that already exist, or inspect every byte of generated output.
Use external controls where technical prevention across all tools is required.

## Independent remote-storage switch

For managed workspaces, submit `remote_storage`, `remote_location` and
`remote_approval` together through `cyber-engagement propose`, then record the
configured reviewer's decision. This creates a tracked revision independently of
`artifact_handling`. See [Configuration](CONFIGURATION.md).

The following commands are retained only for legacy, unmanaged workspaces:

```sh
cyber-workspace remote-storage --module client-review --set approved \
  --location https://storage.example.test/engagement --approval ROE-001
cyber-workspace remote-storage --module client-review --set approved \
  --location https://storage.example.test/engagement --approval ROE-001 --apply
cyber-workspace remote-storage --module client-review --set disabled --apply
```

Only credential-free `https`, `s3` and `ssh` location references are accepted. Query
strings and fragments are refused. Keep tokens and signed URLs out of this field.
`approved` means the operator has supplied an approval reference; the tool does not
authenticate the approver or verify the remote service. Any approved host must be
selected explicitly within the engagement's scope and data policy. The tool never
automatically chooses a host, provisions storage, copies data, or opens a connection.

Both switches can be set during initialization. Managed updates use revision/event
checks and durable transactions; legacy updates use the existing context lock.
Updating remote metadata preserves local policy unless a separately visible local
change is included in the reviewed proposal. The remote setting initiates no transfer.
