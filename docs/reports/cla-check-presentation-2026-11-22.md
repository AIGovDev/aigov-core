# CLA check presentation cleanup — 2026-11-22

## Scope

Presentation of CLA checks on pull requests only. No change to CLA v2 enforcement
logic, signature records (`cla-signatures`), branch rulesets, co-author policy, or
the required status context `CLA v2 / agreement`.

## What appears on PR #477 and why

PR #477 (`feat/durable-sdk-authorization` → `staging`, merged) shows four CLA-named
entries. Each has a different source:

| Entry on PR #477 | Type | Source | Required? |
|------------------|------|--------|-----------|
| `CLA v2 / agreement` | Commit status | Posted by `scripts/cla_v2_production.py` (`CONTEXT`) from job `CLA-v2-enforcement` | **Yes** (rulesets `main` and `staging`) |
| `CLA-v2-enforcement` | Check run (job name) | Job `cla-v2` in `cla-v2-production.yml`; it runs the script that posts the status above | No |
| `CLA-v2-trusted-shadow` | Check run (job name) | Job `trusted-shadow` in `cla-v2-trusted-shadow.yml`; an independent read-only audit of the same PR | No |
| `CLAAssistant` | Check run (job name), `skipped` | Job `CLAAssistant` in `cla.yml` (retired, `if: false`) | No |

The required gate is a commit status, not a job. The three check runs are job
results. They exist because each job runs on the PR, and GitHub lists every job.

### Why `CLAAssistant` is still listed

Run `45076152634` ("CLA Assistant", `pull_request_target`, 2026-11-22T22:09:53Z)
executed `.github/workflows/cla.yml`. That file does not exist on PR #477's head
(`58987efc`), on its base (`a78cfc9`, the #473 merge), or on `staging`. It does
exist on `main`.

The run names on PR #477 also match the definitions on `main`, not `staging`:

| Run name on #477 | Name on `main` | Name on `staging` |
|------------------|----------------|-------------------|
| `CLA v2 production` | `CLA v2 production` | `CLA v2 — Enforcement` |
| `CLA v2 trusted shadow` | `CLA v2 trusted shadow` | `CLA v2 — Audit` |
| `CLA Assistant` | `CLA Assistant` (file present) | file absent |

**Observed:** for `pull_request_target` events on this repository, the workflow
definitions executed on a PR targeting `staging` came from `main`, the default branch.
The mechanism is not established here. The consequence is firm: workflow changes that
reach only `staging` do not change the checks shown on PRs until they are promoted to
`main`.

## Active versus historical checks

**Active (registered and running):**

- `CLA Assistant` workflow, id `319209763`, path `.github/workflows/cla.yml`, state
  `active`. It is registered because `main` still contains the file. Its only job is
  `if: false`, so each run reports a `skipped` `CLAAssistant` check. It is not a
  required status.
- `CLA v2 production`, `CLA v2 trusted shadow`, `CLA v2 shadow tests`, and `CLA workflow
  security guard`. Their display names on `main` are the old names.

**Historical (retained by GitHub, not deletable through the API):**

- Every `CLAAssistant` and `CLA-v2-*` check run and commit status already attached to
  earlier commits and PRs (for example, PR #477 and PR #473). These stay on those
  commits.

## Changes in this PR

1. Job display names state their role, so no visible job looks like the gate:
   - `cla-v2` → `CLA v2 engine (posts CLA v2 / agreement)`
   - `trusted-shadow` → `CLA v2 independent audit (not a required status)`
   - `cla-v2-tests` → `CLA v2 unit tests (not a required status)`
   - `cla-security-guard` → `CLA workflow security guard (not a required status)`
2. `cla-v2-shadow.yml` and `cla-security-guard.yml` path filters now include
   `.github/workflows/cla*.yml`. A reintroduced `cla.yml` therefore triggers the
   regression tests and the guard.
3. `tests/test_cla_v2_presentation.py` (10 tests) asserts:
   - `cla.yml` is absent, and no workflow references the CLA Assistant action or name;
   - the set of `*cla*.yml` workflows is exactly the four reviewed files;
   - only the enforcement workflow has `statuses: write` and the `issue_comment` trigger;
   - the required context is published only by `scripts/cla_v2_production.py`;
   - the visible CLA job names are exactly the reviewed set, and unique;
   - enforcement and trusted audit still check out `staging` with no PR-head code,
     and the trusted audit has no write scopes.

Negative check: a copy of the tree with `cla.yml` restored from `main` fails three of
the ten tests.

## Limitations

- **Historical check runs cannot be removed.** GitHub keeps `CLAAssistant` and older
  `CLA-v2-*` check runs on past commits. Nothing in this PR removes them. Future PRs
  do not receive them once `main` no longer registers `cla.yml`.
- **`main` still has `cla.yml`.** Until the next `staging` → `main` promotion, every PR
  (including PRs targeting `staging`) runs the legacy `CLA Assistant` workflow and shows
  a skipped `CLAAssistant` check. The job renames in this PR also take effect only on
  `main`.
- **GitHub App installations were not checked.** The token gets 403 from
  `GET /user/installations`, so a leftover CLA Assistant app installation is unverified.

## Owner actions

1. Review and merge this PR into `staging` (not merged by this change).
2. Promote `staging` → `main` through the normal PR. That removes `cla.yml` from the
   registry and applies the new job names to checks on every PR.
3. Optional, to remove the active `CLA Assistant` workflow before step 2:
   `gh api -X PUT repos/AIGovDev/aigov-core/actions/workflows/319209763/disable`.
   Reverse with `.../enable`. Not run by this PR.
4. Check GitHub App installations for a CLA Assistant app and remove it if present.

## Verification

| Check | Result |
|-------|--------|
| `python3 -m unittest tests/test_cla_v2_presentation.py` | 10 tests OK |
| `python3 -m unittest discover -s tests -p 'test_cla_v2_*.py'` | OK |
| `python3 scripts/check_cla_workflow_security.py` | PASS |
| Negative: `cla.yml` restored in a copy | 3 tests fail as expected |
| Rulesets `main` (18716261), `staging` (18716264) | Unchanged: `CLA v2 / agreement` required, no `CLAAssistant` |

The PR checks UI is checked separately after the PR is opened. See the PR for the
observed check names.

## Evaluation gate

Passes when the regression tests, the existing CLA tests, and the workflow guard pass
on the PR head. The `CLA v2 / agreement` status on this PR is evaluated by the
enforcement job as before. Its result does not depend on the job display names
changed here.

Expected PR checks view on this PR, from `staging` definitions: old names may still
appear, because `pull_request_target` runs use `main` definitions (see above). The
final verification on the PR records what the UI actually showed.

## Human approval gate

Not approved for merge by this change. A maintainer reviews and merges the PR into
`staging`. The `staging` → `main` promotion, the optional disable of the `CLA Assistant`
workflow, and the GitHub App check are separate owner decisions listed under Owner
actions.
