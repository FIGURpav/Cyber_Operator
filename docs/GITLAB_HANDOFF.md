# GitLab handoff

This source copy retains Cyber-Operator **0.7.0**, the existing release numbering,
all six original release tags and commit history. The publication branch is `main`.
Documentation and
working-tree examples are in English. See [Current verification](CURRENT_STATE.md)
for the checks performed on this copy.

## Included history

| Tag | Original commit |
| --- | --- |
| v0.3.1 | f070cb9 |
| v0.3.2 | 40e0011 |
| v0.4.0 | 8f9b9e9 |
| v0.5.0 | 993e202 |
| v0.6.0 | c964715 |
| v0.7.0 | 00ebb3e |

The published repository contains the product branch and original release tags.
Local assistant
checkpoint refs, unrelated Git objects, reflogs, hooks, remotes, local environments,
cookies and private editor folders were excluded from the handoff. Git object IDs
and tag targets were compared with the source repository and remain unchanged.

Historical tests retain their original synthetic identity example so the original
commits remain identical. The current source uses `test.user` and `example.test`.
No historical commit was rewritten.

## Source changes and publication

The current source includes the English operator guide, release safeguards and
GitLab pipeline. These changes retain product version 0.7.0; the original v0.7.0
tag continues to identify its original release commit. No new release tag is added.

Before future publication, review the exact staged diff, run the required checks
and obtain the operator's instruction to commit and push. Publish explicitly
selected branches and version tags, preserving existing remote history. Keep
repository credentials in the operating system credential manager.

Keep private assessments, intake, evidence, credentials, reports and runtime data
outside the checkout. The shared editor workspace opens only the source directory.

## GitLab CI

The root `.gitlab-ci.yml` defines a validation job for a Linux container runner. It
uses Python 3.13, installs uv 0.12.24 and synchronizes the committed `uv.lock`. It
runs Ruff, the complete synthetic test suite and the release-content validator.
The job does not need engagement data or assessment credentials and publishes no
artifacts. The existing GitHub workflow is retained.

The runner needs access to the configured container registry and package sources.
Use company-approved mirrors if required by local policy. The GitLab service-side
pipeline must be validated after import; it has not been executed remotely here.

## Local validation

Use a checkout on a Linux filesystem, including when working through WSL. A
Windows-side handoff directory is suitable for source review and Git transport;
execute the application and tests from a Linux-filesystem checkout.

```sh
uv sync --locked
chmod +x scripts/cyber-*
uv run --locked python -m pytest -q
uv run --locked ruff check .
uv run --locked python scripts/release_check.py
```

The release validator checks working-tree content and rejects common private paths,
runtime files, cookie files and text containing Polish characters. This is a
bounded content check, not a complete natural-language classifier or secret scanner.
Before future publication, review newly added files and Git history as well as the
working tree; `.gitignore` does not remove data already committed to Git.
