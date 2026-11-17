# CLA v2 — fail-closed migration design

Status: **design only; no enforcement change**
Base: `staging`
Existing CLA workflow: `.github/workflows/cla.yml`

## Objectives and invariants

1. Preserve the published Individual and Corporate CLA, the exact consent text, existing signatures in `cla-signatures:signatures/version1/cla.json`, and the existing required `CLAAssistant` status until a separately reviewed cutover.
2. Enumerate **all** PR commits and all distinct authors using GitHub API pagination. Treat truncated responses, ambiguous author identities, API failures, and unknown signature state as **not approved**.
3. Avoid executing PR-head code in a privileged workflow. The checker is read-only, with only the GitHub permissions required to read PR metadata and signature evidence and report a check.
4. Separate signature acceptance and storage writes from PR validation. A writer must not have broad access to repository code or workflow modifications. GitHub Actions `contents:write` alone is **not** branch-scoped: evaluate a narrowly permissioned GitHub App or dedicated service for writes.
5. Treat stored signatures as evidence with an auditable agreement version, GitHub identity, consent timestamp, source event, and integrity/recovery mechanism. Existing JSON records must be validated and migrated without silently inventing metadata.
6. Preserve maintainer/bot exemptions only as currently documented. Corporate authorized-contributor exemptions require verifiable Corporate CLA and Schedule A records.

## Implementation sequence

- **Phase A — read-only shadow checker:** implement paginated commit-author discovery, signature lookup, deterministic verdicts and tests. Publish a distinct `CLA-v2-shadow` status; do not replace the required `CLAAssistant` check.
- **Phase B — evidence writer:** implement exact-consent capture with minimal privileges, immutable/auditable records, concurrency safety, backup, recovery and legacy signature reconciliation.
- **Phase C — cutover:** verify shadow versus existing checker across external fork PRs and multi-author PRs, confirm branch rules, change required check in a controlled operation, then retire old write permissions.

## Required test matrix

- Signed contributor; unsigned contributor; maintainer and explicitly allowlisted bots.
- Multiple distinct authors; more than 100 commits; pagination failures; unmapped or deleted GitHub users.
- Signing comment beyond first page; incorrect or edited consent; recheck; concurrent signatures.
- Corporate CLA authorized contributor with and without verified Schedule A.
- Unavailable/corrupt signature store; replay or tampering; agreement version change.
- Forked PR with untrusted code; status-reporting failure; protected-branch bypass attempt.

## Security and release gates

No production cutover until the checker is fail-closed, evidence integrity and migration are independently tested, CI is green, and a human maintainer approves the permission boundary and branch-protection changes.

This document is **not** a claim that CLA v2 is implemented or deployed.
