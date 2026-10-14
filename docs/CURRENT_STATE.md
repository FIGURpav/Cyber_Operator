# Current verification — 2026-10-14

Cyber-Operator **0.7.0** was prepared for an internal GitLab handoff using the latest
local source and the English operator guide. Product version, lockfile, changelog,
six original commits and tags `v0.3.1` through `v0.7.0` are retained unchanged.
The source includes the GitLab publication changes. See [GitLab handoff](GITLAB_HANDOFF.md).

Validation used an isolated Linux-filesystem copy under Ubuntu 24.04 / WSL,
CPython 3.13.16, uv 0.12.24, pytest 9.1.1 and Ruff 0.16.0. Dependencies were
installed offline from the existing cache using `uv sync --locked --offline`.

```text
Focused release, principal and deployment tests: 30 passed in 0.94s
Full regression suite: 1400 passed, 23 subtests passed in 55.10s
Ruff: All checks passed!
Release-content validation: 190 source files; private runtime absent
Local documentation links: passed (template evidence placeholders excluded)
GitLab CI YAML: parsed locally; remote pipeline not executed
```

Five new regression cases cover plain and JSON-escaped private editor paths,
non-English documentation, cookies disguised as source and GitLab CI inclusion.
All assessment data used by the tests was synthetic. No real target was tested.

The retained Git history contains 6 commits, 30 trees and 249 blobs. The branch and
all six tag targets match the original object IDs. `git fsck --full --no-reflogs
--unreachable` passed with no unreachable objects. Local assistant checkpoint refs,
reflogs, hooks, private editor paths, cookies and runtime directories were excluded.
A historical synthetic identity example was retained to preserve the original
commit IDs; its current-source replacement uses reserved example data.

Pattern review found no personal home paths, Polish text or credential tokens in
the retained history. Private-key-header matches were validator constants or
synthetic negative tests, with no actual key payloads. Such checks are bounded and
do not prove the absence of every possible unknown secret. Local validation does
not establish the outcome of a GitLab service-side pipeline; check its status after
each publication.

The following section records the older 0.3.1 baseline, not the current release.

## Historical verification baseline — 2026-10-09

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

That historical release was a clean new source tree. The original source and archives
were retained separately. There was no Git history in that supplied source snapshot;
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
