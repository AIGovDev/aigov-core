# CLA enforcement hardening — audit report

Date: 2026-11-16
Scope: PR #414 (`security/harden-cla-enforcement` into `staging`)

## Change inventory

- CLA workflow: restore active `custom-pr-sign-comment` input, retaining the exact Individual CLA consent phrase; correct canonical CLA document URLs.
- Signature updates: serialize workflow executions sharing the `cla-signatures` JSON store to reduce concurrent-update conflicts.
- Security guard: add a read-only CI workflow and static regression checks against accidentally weakening CLA enforcement or executing untrusted PR code.
- Documentation: record the privileged workflow trust boundary and outstanding upstream limitations.

## Verification evidence

- GitHub Actions `CLA workflow security guard` succeeded on commit `8a8a7c356385ad53bf3ff6ea555d089f901e4b99` (run 43972566805).
- GitHub Actions `compliance/report_gate` previously failed because this report was missing (run 43972566837, job 133668350438); this report addresses that explicit gate requirement.
- No claim is made that the complete CI suite, external-contributor signing tests, or a security penetration test have passed.

## Threats and limitations

The upstream CLA Assistant Lite action still has repository-level `contents:write`, `actions:write`, `pull-requests:write`, and `statuses:write` permissions. Its commit-author discovery is limited to the first page of commits and its comment discovery to the first page of comments. Workflow concurrency does not provide a durable transactional signature store. An unprotected signatures branch also needs independent integrity monitoring and tested recovery.

## Acceptance criteria before merge

1. All required CI checks pass, including compliance and supply-chain audit.
2. Review exact signing and rejection behavior with an unsigned external PR and a signed external PR.
3. Confirm that existing required CLA branch protections remain enabled and that no privileged job checks out untrusted PR code.
4. Track the remaining pagination, privilege-scoping, and signature-integrity work separately; do not describe this increment as a complete security migration.

## Rollback

Revert the workflow and guard changes if they interfere with legitimate CLA signing or fail closed incorrectly. Do not remove the required `CLAAssistant` status check as a rollback shortcut.
