# CLA v2 enforcement preflight — 2026-11-17

## Scope
Hardening of the trusted CLA v2 shadow auditor after activation of PR #417. This change does not activate enforcement or modify signature storage, GitHub branch protection, or the legacy CLA Assistant.

## Evaluation gate
Status: pending CI. Added regression tests for whitespace-prefixed Co-authored-by trailers and spoofed service-bot logins with incorrect numeric GitHub IDs. A green shadow check remains informational, not evidence of an approved signature.

## Human approval gate
Status: pending. No production enforcement, privileged signature writer, or branch-rules cutover is approved.

## Security risks and mitigations
- Commit trailers with leading whitespace must not evade the coauthor check.
- Bot login strings alone must not exempt a contributor: only recognized numeric GitHub identities qualify.
- The existing read-only shadow verifier still relies on legacy signatures and cannot persist new evidence. Do not replace the required CLA Assistant until this gap is closed.
- A workflow run that exits zero in shadow mode is not a CLA approval.

## Rollback
Revert this PR. Existing CLA Assistant enforcement is unchanged.
