# CLA enforcement security review (2026-11-16)

## Current trust boundary
`.github/workflows/cla.yml` runs on `pull_request_target` and PR comments.
Its third-party CLA Assistant Lite action receives a short-lived token with
`actions:write`, `contents:write`, `pull-requests:write`, and `statuses:write`.
It must never check out or execute code from an external PR. The token can write
signature records on the intentionally unprotected `cla-signatures` branch.

## Immediate controls
- Keep the action pinned to a full commit SHA and the existing explicit allowlist.
- Keep default permissions denied and never introduce a long-lived PAT.
- Keep exact signing text and the `recheck` path; preserve required `CLAAssistant` check.
- Run `python3 scripts/check_cla_workflow_security.py` and the read-only
  `CLA workflow security guard` CI job on workflow changes.
- Contributor-facing agreement links use the canonical AIGovDev repository.

## Limitations / follow-up (not yet resolved)
- Static tests can be modified in the same PR; review and protected-branch rules
  remain necessary. This guard is defense in depth, not a security boundary.
- A pinned third-party action can still contain vulnerabilities. Audit its
  source, dependencies, maintenance and permission requirements before removing
  `actions:write` or migrating.
- A token with `contents:write` can write more than just `cla-signatures`.
  GitHub workflow permissions alone do not scope it to one branch.
- Signature integrity and historical auditability need independent verification
  and a tested backup/recovery procedure.
- Before migrating to a GitHub App, test signed, unsigned, multi-author,
  fork, bot and corporate-allowlisted PRs. Keep fail-closed branch rules.
- GitHub's scheduled `pull_request_target` brownout is a platform event,
  not evidence that these risks were remediated.
