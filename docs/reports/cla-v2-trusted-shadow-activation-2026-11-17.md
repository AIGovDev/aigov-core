# CLA v2 trusted shadow trigger — PR #417

Date: 2026-11-17

## Scope and change
Enable the existing trusted, **informational** CLA v2 shadow audit on pull requests targeting `staging` via `pull_request_target`, in addition to existing manual `workflow_dispatch`. No CLA agreement, signature file, required check, GitHub branch protection, or old CLA workflow is changed.

## Security review
- **Trusted code only:** `actions/checkout@v4` checks out `staging`, not an untrusted PR head. The script executed is `scripts/cla_v2_shadow.py` from the trusted base.
- **Least privilege:** job token grants `contents: read` and `pull-requests: read` only; it cannot modify repository contents or commit statuses.
- **No PR-provided code:** the workflow does not install PR dependencies, execute changed scripts, or interpolate PR title/body/comment content into shell commands.
- **Bounded execution:** `timeout-minutes: 5`; existing checker fails closed internally if identity or signature evidence cannot be verified.
- **Non-enforcing mode:** the checker currently exits successfully even if its JSON result is `approved: false`. A green workflow is **not** a CLA approval and must not be configured as a required CLA signature gate.

## Evaluation gate
Repository `compliance/report_gate` requires a `docs/reports/*.md` update for workflow changes. This report fulfills that change-control requirement. PR unit tests and CI must pass before merge. A real fork-origin PR and the trusted workflow trigger should be observed after merging to staging; GitHub's `pull_request_target` event policy may independently prevent startup.

## Human approval and cutover
Not approved for production enforcement. The legacy `CLAAssistant` check remains required. Before replacing it, complete signature-evidence validation, independently review a least-privilege signing mechanism or equivalent source-of-truth design, verify fork/event behavior, and coordinate an atomic branch-rules change without a period of unprotected merges.

## Rollback
Revert the added `pull_request_target` trigger in `.github/workflows/cla-v2-trusted-shadow.yml`. The legacy CLA gate is unaffected.
