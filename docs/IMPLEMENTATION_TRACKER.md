# Approved roadmap implementation tracker

The baseline is release 0.3.1, retained as an unchanged archive and Git tag.
Product releases, record schema versions, template versions and assessment
revisions are tracked independently. Historical evidence and ledger IDs remain
stable. Migration never rehashes an existing event history.

| Stage | Planned release | Status | Acceptance evidence |
| --- | --- | --- | --- |
| R0: truthful interfaces and reproducible baseline | 0.3.2 | Complete | 1,334 tests and 23 subtests passed; Ruff and clean release checks passed |
| R1: resumable intake and common review contract | 0.4.0 | Pending | Partial resume; None through reporting; exact reviewed changes |
| R2: assets, findings, objectives and report | 0.5.0 | Pending | Many objectives, retest, evidence graph and SVG |
| R3: activity recording and bounded context | 0.6.0 | Pending | Atomic linked records, recovery, context budget |
| R4: secret boundary and repeatable deployment | 0.7.0 | Pending | Provider migration, optional modules, install/upgrade verification |

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
