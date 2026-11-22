# CLA v2 AI attribution policy: exact Claude Haiku 5.5 trailer — 2026-11-22

## Scope

Policy-only change to the CLA v2 co-author parser. This change adds two exact
attribution strings and regression tests. It does not change the CLA workflows,
the required status context, branch protection, rulesets, or signature records.

## Change

`scripts/cla_v2_shadow.py` replaces the two-string Sonnet 4.6 check with an
exact-match set, `AI_ATTRIBUTION_TRAILERS`. It contains the two existing Sonnet
4.6 strings plus only these two Haiku 5.5 strings:

- `Co-authored-by: Claude Haiku 5.5 <noreply@anthropic.com>`
- `Co-Authored-By: Claude Haiku 5.5 <noreply@anthropic.com>`

Matching is exact after `strip()`. There is no wildcard, model family, or
lookalike-address acceptance.

## Identity basis

The string is the trailer used in PR #473 commits, and it matches the model
identity the session reports (Claude Haiku 5.5, model ID `claude-haiku-5-5`).
Trailers are untrusted text. This is a metadata policy, not proof of authorship.

## AI assistance disclosure and attribution exception

This policy-bootstrap commit was drafted with assistance from Claude Haiku 5.5.
The owner approved, on 2026-11-22, recording that assistance in the PR description
and this report instead of a `Co-Authored-By` commit trailer for this one commit.

- The commit author is the human maintainer, `MonikaDvorackova`
  `<monika.dvorack@gmail.com>`, and is unchanged.
- The commit carries no co-author trailer. This is an owner-approved exception
  for this bootstrap commit only. It is not a general policy for AI attribution.
- PR #473 commits keep their original attribution and are not changed.

## Security rationale

- An AI trailer never creates or signs for a CLA signer. The human author still
  needs a signature or allowlist entry.
- Mixed human plus AI co-author trailers still block.
- Malformed, unlisted-casing, trailing-text, unknown-version, spoofed-address,
  and lookalike-domain variants fail closed.
- Parser, identity binding, and signature checks are unchanged.

## Regression tests

`tests/test_cla_v2_shadow.py::AiAttributionPolicyTests`:

1. `test_exact_haiku_attribution_accepted_in_both_casings` (positive)
2. `test_haiku_attribution_does_not_sign_for_author` (positive, no signer created)
3. `test_negative_cases_fail_closed` (spoofed address, lookalike domain, unknown
   versions 5.6 and 5, variant suffix, Opus family, missing version, malformed,
   unlisted casing, trailing text, missing address)
4. `test_haiku_plus_human_coauthor_still_blocks` (mixed trailers)
5. `test_haiku_trailer_spoofed_as_human_author_still_needs_signature`

## Evaluation gate

- Local: `python3 -m unittest tests.test_cla_v2_shadow` passes, including the five
  new tests.
- Local: `python3 scripts/check_cla_workflow_security.py` passes.
- GitHub: `CLA v2 / agreement` for this PR is evaluated by the enforcement job,
  which checks out `staging` and runs staging's policy. With no co-author trailer
  on this commit, the baseline checks apply. Results are recorded in the PR body.

## Human approval gate

**Approved:** the repository owner authorized the exact-match Haiku 5.5 policy in
session on 2026-11-22. That covers only the two strings and tests above.

**Approved exception (2026-11-22):** the owner approved disclosing Haiku 5.5
assistance in the PR description and this report, with no `Co-Authored-By` trailer
on this policy-bootstrap commit. The commit keeps the human author.

**Not approved here:**
- Merge and deploy. A maintainer must review and merge this PR into `staging`.
- Any bypass, disabling, or weakening of `CLA v2 / agreement`, or any change to
  rulesets or branch protection.
- The Sonnet 5 historical trailers, which remain blocked.

## Rollback

Revert the commit that adds `AI_ATTRIBUTION_TRAILERS`. The previous Sonnet-only
check is restored.
