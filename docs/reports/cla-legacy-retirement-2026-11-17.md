# CLA Assistant (legacy) retirement — 2026-11-17

## Scope

Retire the legacy CLA Assistant Lite (`contributor-assistant/github-action`) workflow by
setting `if: false` on the `CLAAssistant` job. The workflow file, historical
signature records, and all v1 evidence on the `cla-signatures` branch are
preserved for audit continuity.

**Files changed:**
- `.github/workflows/cla.yml` — adds retirement header comment and `if: false`
  to the `CLAAssistant` job. Workflow triggers and permissions remain intact so
  the file continues to pass the security guard invariants.
- `scripts/check_cla_workflow_security.py` — adds retirement invariant:
  `CLAAssistant` job must carry `if: false`; enforced on every PR and push.

## Evaluation gate

Status: verified. CLA v2 enforcement is confirmed operational on `main` and `staging`.

| Test | Result | Evidence |
|------|--------|----------|
| Allowlisted owner (monikadvorackova, uid 95243292) | `success` | PR #424 SHA d9e3147, run 44090159750 |
| Legacy v1 signatory (SwapanRaj04, uid 145488304) | `success` | PR #184, run 44090301613 |
| Co-authored commit | `error` fail-closed | PR #423 SHA e54e534, PR #425 (this PR) |
| `synchronize` re-run | `success` re-posted | PR #424 SHA 9d50b65 |
| Checkout `ref: staging`, `persist-credentials: false` | confirmed | runs 44090159750, 44090301613 |

## Human approval gate

Status: pending owner authorization of branch protection changes.

**This PR must NOT be merged until:**
- The owner has added `CLA v2 / agreement` as a required status check on `main` and `staging` via the branch protection API.
- The owner confirms CLA v2 blocks merges for unsigned external contributors (requires a fork PR from a non-allowlisted account to verify fail-closed behavior).

## Human approval gate

Status: pending owner authorization of branch protection changes.

**This PR must NOT be merged until:**
- The owner has added `CLA v2 / agreement` as a required status check on `main` and `staging` via the branch protection API.
- The owner confirms CLA v2 blocks merges for unsigned external contributors (requires a fork PR from a non-allowlisted account to verify fail-closed behavior).

## Post-retirement verification

After merging, confirm:
1. `cla-security-guard` CI passes on the next PR (the retirement invariant is now live).
2. The `CLAAssistant` check shows `skipped` (not `failure`) for new PRs.
3. `CLA v2 / agreement` continues to post for new PRs independently.
4. `signatures/version1/cla.json` on `cla-signatures` branch is unchanged.

## Rollback

Revert this PR. Remove the `if: false` line and the retirement comment from `cla.yml`.
Remove the `if: false` retirement invariant from `check_cla_workflow_security.py`.
No signatures, branch rules, or v2 evidence is affected by rolling back.
