# Verification baseline — 2026-10-09

Cyber-Operator 0.3.1 was verified in an isolated Linux-filesystem copy under Ubuntu
24.04 in WSL, using CPython 3.13.16, pytest 9.1.1, Ruff 0.16.0 and the locked
dependencies. The source checkout and release contain no Python environment.

```text
Full regression suite: 1332 passed, 23 subtests passed in 49.22s
Focused configuration/storage/recovery/release regression: 143 passed in 11.71s
Ruff: All checks passed!
Release-content validation: passed; private runtime absent
```

The suite covers existing evidence integrity, transaction recovery, writer fencing,
host identity, screenshots, reporting, secret intake, checkpoint and lifecycle
behavior. Added cases exercise independent storage settings, blocked target-file
intake before reading bytes, retained origin declarations, remote metadata validation,
blank inactive initialization, invalid scope/time/risk inputs, explicit review records,
configuration precedence and clean release packaging. All workspaces are synthetic.

The preceding 0.3.0 baseline contained 1306 tests. Version 0.3.1 adds 26 cases for
explicit no-document answers, unanswered fields, local approval receipts, legacy
intake, exact reviewed changes, invalid values and preservation of other required
facts and policy defaults. Existing checkpoint, concurrency, transaction recovery,
adoption, origin and projection integrity coverage remains in the full suite.
Source, templates, operator prompts and documentation are written in English.

This release is a clean new source tree. The original source and historical archives
were retained separately. There is no Git history in the supplied source snapshot;
no history rewrite, remote publication or repository push was performed. The included
CI workflow is configured, but has not been run by a remote CI service in this work.

## Implemented boundaries

- Product and CLI naming are neutral; personal setup paths and historical graphics
  are excluded. Private workspace data is not shipped.
- Supported local target-file intake enforces `no-download`. Remote storage is an
  independently validated location/approval record and has no transfer implementation.
- Team intake and review metadata are supported. Authentication, central RBAC and
  cross-user isolation require infrastructure outside this local runtime.
- The report manifest is schema 2.0 and work-item events are schema 2.0. New capture
  metadata is schema 1.1 with explicit origin; other existing evidence remains readable.
- Unresolved tokens block closure and ordinary checkpoint creation in both profiles.
- Agent guidance requires human review. There is no automatic technique progression
  or broad takeover preset. Managed configuration approvals bind exact revisions,
  instances and lifecycle epochs. Legacy target-grant commands are unavailable in
  managed workspaces; their historical records remain readable.

Assessment windows determine current configuration status and supported target-file
capture eligibility. Scope policy, callback metadata and retention do not provide
network filtering, tool supervision or automatic deletion. Arbitrary external tools
and inaccurate provenance declarations remain outside the local persistence guard.
See CONFIGURATION.md and ARTIFACT_HANDLING.md for precise limits.
