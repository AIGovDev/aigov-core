# CLA signature storage (`cla-signatures`)

## Purpose

The `cla-signatures` branch stores **only** Contributor License Agreement signature
records written by the CLA v2 enforcement workflow (`.github/workflows/cla-v2-production.yml`).
Records written before CLA v2 by the retired CLA Assistant workflow remain here unchanged as audit evidence.

It is not used for application development, releases, or general documentation.

## Expected layout

| Path | Who creates it |
|------|----------------|
| `README.md` | Maintainers (branch bootstrap) |
| `signatures/README.md` | Maintainers (branch bootstrap) |
| `signatures/version1/cla.json` | **CLA v2 writer only** — do not create manually |

## Who may write

- `github-actions[bot]` via `.github/workflows/cla-v2-production.yml` (`GITHUB_TOKEN`)
- Repository maintainers for recovery only

Do **not** grant broad write bypass on protected `main` or `staging` for CLA storage.

## Workflow configuration

The CLA v2 writer (`scripts/cla_v2_production.py`) reads and writes
`signatures/version1/cla.json` on the `cla-signatures` branch. The signature branch
**must not be protected** by rulesets that require PRs or status checks.

## Recovery if a signature write fails

1. Confirm `cla-signatures` is not covered by rulesets that require PRs or status checks.
2. Confirm the workflow `branch:` input is still `cla-signatures`.
3. Push a synchronize event to the pull request, or re-run the CLA v2 — Enforcement job.
4. Read the failed Actions job log for rule-violation details.
5. Do not hand-edit `cla.json` to repair a record; escalate to the maintainer, since signature evidence is audited.

## Contributor-facing docs

See [`docs/community/cla.md`](../community/cla.md).
