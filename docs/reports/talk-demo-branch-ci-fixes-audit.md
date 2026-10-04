# Talk-demo branch CI fixes audit

## Summary

PR #224 adds `examples/talk-demo/` (a scripted live-demo flow for `aigov_audit`, used
for an AI Tinkerers talk) and fixes everything the branch's CI run surfaced along the
way: a pre-existing HIGH dependency CVE, two workflows missing a manual trigger, and a
stale duplicate audit report inherited from the branch's starting point.

## Files changed

| File | Change |
|------|--------|
| `rust/adapters/immutable_s3/Cargo.lock` | `cargo update -p aws-smithy-json --precise 0.62.7` — Trivy flagged 0.62.5 (HIGH, CVE-2026-18140, DoS via deeply nested JSON). Lockfile-only; `cargo check --locked` passes. |
| `.github/workflows/govai-ci.yml` | Added `workflow_dispatch:` so the required `aigov-core-portable` check can be run on-demand. |
| `.github/workflows/enforce-branch-policy.yml` | Added `workflow_dispatch:` for the same reason. |
| `docs/reports/repo-audit-round-2-2026-09-30.md` | Removed — a stale duplicate of `docs/reports/repo-audit-round-2-2026-10-01.md` (already merged into `staging` via PR #223), inherited from this branch's starting point on `release/staging-to-main`. It was tripping the "exactly one report per PR" compliance gate. |

## Evaluation gate

Status: pass.

Evidence:
- `cargo check --locked` succeeds for `aigov_immutable_s3` against the updated lockfile.
- Both workflow files changed only by adding a trigger; no job logic changed.
- The removed report file's content is superseded by `repo-audit-round-2-2026-10-01.md`, already on `staging`.

## Human approval gate

Status: pending maintainer review.

Reviewer: Monika Dvořáčková
