# CLA legacy workflow retirement and CLA v2 workflow rename — 2026-11-22

## Scope

Maintenance of contributor-agreement workflows only. No change to CLA v2
enforcement logic, triggers, permissions, concurrency, the required status
context, the co-author policy, or signature records.

## Changes

1. Deleted `.github/workflows/cla.yml`. Its only job (`CLAAssistant`) was already
   `if: false` since PR #426. It is not required by either ruleset.
2. Renamed workflow display names only. Job IDs, job names, and check-run names
   are unchanged:
   - `cla-v2-production.yml` → `CLA v2 — Enforcement`
   - `cla-v2-shadow.yml` → `CLA v2 — Tests`
   - `cla-v2-trusted-shadow.yml` → `CLA v2 — Audit`
   - `cla-security-guard.yml` → `CLA v2 — Security`
3. `scripts/check_cla_workflow_security.py` no longer reads `cla.yml`. It fails
   if `cla.yml` is reintroduced. CLA v2 invariants are unchanged.
4. Updated CODEOWNERS, CONTRIBUTING, the PR template, `docs/community/cla.md`,
   `docs/operations/cla-signatures.md`, and added a status note to
   `docs/security/cla-enforcement-review.md`. Dated reports are not rewritten.

## Verification

| Check | Result |
|-------|--------|
| Ruleset `main` (18716261) required contexts | `aigov-core-portable`, `CLA v2 / agreement`. No `CLAAssistant`. |
| Ruleset `staging` (18716264) required contexts | `aigov-core-portable`, `cargo-audit`, `CLA v2 / agreement`. No `CLAAssistant`. |
| `CLA v2 / agreement` source | Commit status posted by `scripts/cla_v2_production.py` (`CONTEXT`). Not derived from workflow display names or from `cla.yml`. |
| `cla-signatures` branch | Head `4f72468e6ec2954664920d4855a2d5c04a622165` before this change. Not written by this PR. |
| `scripts/check_cla_workflow_security.py` | PASS |
| `tests/test_cla_v2_{evidence,production,shadow}.py` | 33 tests OK |

## Co-author attribution gate (blocking)

PR #473 fails `CLA v2 / agreement` with
`Co-authored commit requires manual identity verification`.

- **Rejected identity:** commit `5220c22` has the human author
  `MonikaDvorackova <monika.dvorack@gmail.com>` and the trailer
  `Co-Authored-By: Claude Haiku 5.5 <noreply@anthropic.com>`.
- **Policy:** `scripts/cla_v2_shadow.py` accepts exactly two strings:
  `Co-authored-by: Claude Sonnet 4.6 <noreply@anthropic.com>` and
  `Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>`. Everything else
  fails closed.
- **Origin of the policy:** `docs/reports/cla-v2-ai-attribution-2026-11-18.md`
  added that single exact string after a historical Sonnet 4.6 trailer blocked a
  staging-to-main PR. It states that trailers are untrusted text and that "a
  future change to the exact attribution format requires separate review."
- **Evidence for Haiku 5.5:** none in the repository policy or its tests. No
  maintainer approval for that identity exists. The trailer is truthful as a
  statement of tool use, but the policy has not admitted it.
- **Decision:** the gate is left blocked. This report does not add Haiku 5.5 to
  the allowlist, and it does not strip the trailer.

Also found: 22 historical commits carry `Co-Authored-By: Claude Sonnet 5`, which is
also absent from the allowlist. Any PR that includes those commits will hit the
same gate. The owner should decide on this together with the Haiku request.

## Human approval required

Choose one:

1. **Keep the trailer and approve a narrow policy change.** A maintainer
   approves exact-string entries for `Claude Haiku 5.5` (and, if needed,
   `Claude Sonnet 5`) with regression tests in `tests/test_cla_v2_shadow.py`.
   No wildcard. Keep the mixed-human, lookalike-address, and spoof tests.
2. **Drop the trailer** from the commits on #473. This requires a history
   rewrite of the PR branch, and the owner must approve that.
3. **Reject the trailer and close the PR**, then reopen the change without
   AI co-author metadata.

No option is approved here. This report does not authorize merge, deploy, or
changes to rulesets.

## Not verified

- GitHub App installations. `GET /user/installations` returns 403 for this token,
  so a leftover CLA Assistant app installation was not checked.
- Fresh fork and external-contributor enforcement runs. The evidence is the E2E
  record in `docs/reports/cla-v2-security-audit-2026-11-18.md`.

## Rollback

Restore `.github/workflows/cla.yml` from `origin/staging` before this change, and
revert the guard script. The file was not required by any ruleset.
