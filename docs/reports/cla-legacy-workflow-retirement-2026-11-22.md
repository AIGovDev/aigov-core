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

## Evaluation gate

Status on head `9d06495`:

- Passing: `report_gate`, `report_content`, `make_verify`, `evidence_pack`,
  `upload_evidence_packs`, `aigov-core-portable`, `cargo-audit`,
  `oss-developer-experience-checks`, `CLA-v2-tests`, `CLA-v2-trusted-shadow`,
  `cla-security-guard`, and the remaining supply-chain and security jobs.
- `CLA v2 / agreement`: **still `error`.** `CLA-v2-enforcement` checks out
  `ref: staging` (`.github/workflows/cla-v2-production.yml`) and runs staging's
  `scripts/cla_v2_production.py`. The PR's own policy change is not in effect
  for its own gate. This is intended: a PR cannot approve its own policy change.
- Read-only check: the new parser run against PR #473's real commit range (4
  commits, all with the Haiku trailer and human author `MonikaDvorackova`,
  ID `95243292`) returns `{'MonikaDvorackova': 95243292}`. The owner is
  allowlisted as `("monikadvorackova", 95243292)`.
- **Unblocking path:** the policy must reach `staging` through review and
  merge. Then re-run `CLA v2 — Enforcement` on #473. This PR has not been merged.

- `report_gate` and `report_content`: pass after this report was added.
- `oss-developer-experience-checks`: failed on the earlier head because this
  report lacked the required headings. Re-evaluated on the next push.
- `CLA-v2-tests`, `CLA-v2-trusted-shadow`, `cla-security-guard`: pass.
- `CLA-v2-enforcement`: fails with the co-author gate error below.

## Verification

| Check | Result |
|-------|--------|
| Ruleset `main` (18716261) required contexts | `aigov-core-portable`, `CLA v2 / agreement`. No `CLAAssistant`. |
| Ruleset `staging` (18716264) required contexts | `aigov-core-portable`, `cargo-audit`, `CLA v2 / agreement`. No `CLAAssistant`. |
| `CLA v2 / agreement` source | Commit status posted by `scripts/cla_v2_production.py` (`CONTEXT`). Not derived from workflow display names or from `cla.yml`. |
| `cla-signatures` branch | Head `4f72468e6ec2954664920d4855a2d5c04a622165` before this change. Not written by this PR. |
| `scripts/check_cla_workflow_security.py` | PASS |
| `tests/test_cla_v2_{evidence,production,shadow}.py` | 33 tests OK |

## Co-author attribution gate (resolved for Haiku 5.5 by policy update)

PR #473 initially failed `CLA v2 / agreement` with
`Co-authored commit requires manual identity verification`.

- **Rejected identity:** commit `5220c22` has the human author
  `MonikaDvorackova <monika.dvorack@gmail.com>` and the trailer
  `Co-Authored-By: Claude Haiku 5.5 <noreply@anthropic.com>`. Commit `6bd3d99`
  carries the same trailer on the report commit.
- **Prior policy:** only the exact Sonnet 4.6 pair in `scripts/cla_v2_shadow.py`
  was accepted. The 2026-11-18 review states that a new attribution format
  requires separate review.
- **Historical trailers not covered:** 22 commits in history carry
  `Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>`. They are NOT added by
  this change and remain blocked if they appear in a PR's commit range.

## Policy update: exact Haiku 5.5 attribution

**Change:** `scripts/cla_v2_shadow.py` replaces the two-string Sonnet check with an
exact-match `AI_ATTRIBUTION_TRAILERS` set. It contains the existing two Sonnet 4.6
strings, plus only these two Haiku 5.5 strings:

- `Co-authored-by: Claude Haiku 5.5 <noreply@anthropic.com>`
- `Co-Authored-By: Claude Haiku 5.5 <noreply@anthropic.com>`

**Identity verification basis:** the exact string is taken from the commit trailer
in PR #473 and matches the model identity the session reports (Claude Haiku 5.5,
model ID `claude-haiku-5-5`). Trailers are untrusted text, so this is a policy
decision about metadata, not cryptographic proof of authorship.

**Security rationale:**
- An AI trailer never creates or signs for a CLA signer. The human author still
  needs a signature. Covered by `test_haiku_attribution_does_not_sign_for_author`.
- Matching is exact after `strip()`. There is no wildcard, no model family, and no
  lookalike domain acceptance.
- Mixed human plus AI trailers still block. Malformed, unlisted-casing, trailing-text,
  and unknown-version variants fail closed.
- The parser, identity binding, and signature checks are unchanged.

**Regression tests** (`tests/test_cla_v2_shadow.py::AiAttributionPolicyTests`):
- Positive: exact Haiku 5.5 in both casings is accepted.
- Positive: the trailer does not sign for the human author.
- Negative: spoofed address, lookalike domain, unknown versions (5.6, 5), variant
  suffix, other family (Opus), family without version, missing space, uppercase
  key, trailing text, missing address, mixed human coauthor, and spoofed human author.

## Human approval gate

**Approved (policy update, Haiku 5.5 only):** the repository owner authorized
proposing the exact-match Haiku 5.5 policy in this session on 2026-11-22. That
authorization covers adding the two strings above with the tests listed.

**Not approved here:**
- The Sonnet 5 trailer (historical commits) is not covered.
- Merge and deploy. A maintainer must still review and merge PR #473.
- Any change to rulesets or the signature store.

## Not verified

- GitHub App installations. `GET /user/installations` returns 403 for this token,
  so a leftover CLA Assistant app installation was not checked.
- Fresh fork and external-contributor enforcement runs. The evidence is the E2E
  record in `docs/reports/cla-v2-security-audit-2026-11-18.md`.

## Rollback

Restore `.github/workflows/cla.yml` from `origin/staging` before this change, and
revert the guard script. The file was not required by any ruleset.
