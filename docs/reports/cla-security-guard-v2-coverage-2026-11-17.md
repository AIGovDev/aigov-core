# CLA security guard — extend to cover cla-v2-production.yml — 2026-11-17

## Scope

Two-file hardening change that closes a coverage gap in the CLA workflow
security guard. No executable enforcement logic, signature storage, branch
protection rules, or legacy CLA Assistant behavior is changed.

**Files changed:**
- `.github/workflows/cla-security-guard.yml` — adds `cla-v2-production.yml`
  to `pull_request` and `push` path triggers so any modification to the
  active first-party CLA enforcement workflow is validated on every PR and
  push to `staging`/`main`.
- `scripts/check_cla_workflow_security.py` — extends invariant checks to
  cover `cla-v2-production.yml`: default-deny `permissions: {}`,
  `pull_request_target` + `issue_comment` triggers, `cancel-in-progress: false`,
  no `PERSONAL_ACCESS_TOKEN`, no untrusted PR-head interpolation,
  protected-branch checkout (`ref: staging` or `ref: main`),
  `persist-credentials: false`, ephemeral `github.token`, and serialized
  concurrency group `cla-v2-signatures-global`. Adds file-label prefix to all
  existing `cla.yml` messages so failures name their source.

## Evaluation gate

Status: CI pass required. The guard runs on this PR itself and must report
`PASS: CLA workflow security invariants (cla.yml + cla-v2-production.yml)`.

## Human approval gate

Status: no production action required. This change does not activate CLA v2
enforcement, modify branch protection rules, retire the legacy CLA Assistant,
or alter any signature storage. Merge after CI passes.

## Security risks and mitigations

Without this change, an edit to `cla-v2-production.yml` that removes
`persist-credentials: false`, adds a PAT, or relaxes the concurrency group
escapes the security guard entirely. After this change, any such regression
causes an immediate CI failure on the modifying PR.

The invariant allowing `ref: staging` or `ref: main` preserves the original
design intent: the production workflow always executes from a protected branch,
never from an ephemeral feature branch or PR head.

## Rollback

Revert this PR. The security guard reverts to `cla.yml`-only coverage.
No signatures, branch rules, or enforcement configuration is affected.
