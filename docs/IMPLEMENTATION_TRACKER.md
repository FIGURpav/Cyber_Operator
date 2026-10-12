# Approved roadmap implementation tracker

The baseline is release 0.3.1, retained as an unchanged archive and Git tag.
Product releases, record schema versions, template versions and assessment
revisions are tracked independently. Historical evidence and ledger IDs remain
stable. Migration never rehashes an existing event history.

| Stage | Planned release | Status | Acceptance evidence |
| --- | --- | --- | --- |
| R0: truthful interfaces and reproducible baseline | 0.3.2 | Complete | 1,334 tests and 23 subtests passed; Ruff and clean release checks passed |
| R1: resumable intake and common review contract | 0.4.0 | Complete | 1,354 tests and 23 subtests passed; Ruff and clean release checks passed |
| R2: assets, findings, objectives and report | 0.5.0 | Complete | 1,366 tests and 23 subtests passed; Ruff and clean release checks passed |
| R3: activity recording and bounded context | 0.6.0 | Complete | 1,375 tests and 23 subtests passed; lint and release checks passed |
| R4: secret boundary and repeatable deployment | 0.7.0 | Complete | 1,395 tests and 23 subtests passed; 36 CLI help checks; synthetic report/SVG/vault scenario; install/recovery/rollback checks passed |

## Regression observations to turn into acceptance cases

1. Preserve intake answers across separate sessions without changing effective settings.
2. Preserve explicit no-document choices and local review receipts.
3. Carry optional scope references through report metadata.
4. Allow multiple objectives per asset without duplicate-host errors.
5. Bind report metadata to a canonical configuration revision.
6. Connect reviewed managed activity decisions to change/path records.
7. Normalize new impact values without rewriting historical `moderate` records.
8. Separate finding confidence, remediation, retest and risk acceptance.
9. Bound manual notes and all other brief sections, not only record counts.

Each implementation stage records its source commit, release archive hash,
focused checks and full regression results before a release tag is created.
Local setup paths and baseline archives are intentionally outside product releases.

## Operator decisions

- Use a separate local Linux/WSL runtime for each operator. Controlled handoff is
  deferred; a shared multi-user service is outside this implementation.
- Keep a private vault inside each workspace using owner-only filesystem access,
  without a separate password or application-layer encryption. Separate secret
  values from ordinary metadata and retain historical private sources explicitly.
