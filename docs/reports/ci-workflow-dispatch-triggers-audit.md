# CI workflow_dispatch triggers audit

## Summary

`pull_request` `synchronize`/`reopened` events stopped triggering several required
`pull_request`-scoped workflows for PR #224 after its base branch was retargeted from
`main` to `staging` (only `pull_request_target` workflows, e.g. CLA Assistant, kept firing).
Added `workflow_dispatch` to the two workflows that lacked any manual trigger
(`govai-ci`, `PR branch policy`) so they can be run on-demand against a specific ref
when the automatic `pull_request` dispatch does not fire.

## Files changed

| File | Change |
|------|--------|
| `.github/workflows/govai-ci.yml` | Added `workflow_dispatch:` trigger. |
| `.github/workflows/enforce-branch-policy.yml` | Added `workflow_dispatch:` trigger. |

## Evaluation gate

Status: pass.

Evidence:
- Both workflows already ran successfully via their `pull_request` trigger earlier in
  this PR's history; this change only adds a manual fallback trigger, no job logic changed.

## Human approval gate

Status: pending maintainer review.

Reviewer: Monika Dvořáčková
