# CLA v2 production migration — 2026-11-17

## Scope
Implement a first-party trusted CLA v2 consent writer and commit status gate. The writer verifies GitHub comments via the REST API, records numeric identities and deterministic agreement evidence on the existing cla-signatures branch under signatures/version2/users/<numeric-id>.json, and revalidates stored consent against live comments. The verifier recognizes verified historical v1 signatures and new v2 evidence.

## Evaluation gate
Status: pending CI and live integration testing. Unit tests cover unsigned and signed contributors, API failure, numeric bot identity spoofing, idempotent signatures, write conflicts, and evidence tampering. A privileged workflow executes only protected staging code and never checks out PR-head code. Branch rulesets and GitHub default-branch workflow availability have NOT been verified.

## Human approval gate
Status: pending. Do not remove the legacy CLA Assistant or make the new status required until GitHub Actions availability on the default branch, real fork PR consent, multi-author PR, and failure cases are validated. GitHub branch protection changes require authorized repository administration.

## Cutover procedure
1. Merge this PR to staging after CI and security review.
2. Ensure the production workflow is also present on the default branch (GitHub issue_comment and workflow_dispatch events require default-branch workflow registration).
3. Exercise fork PR, unsigned contributor, valid comment, edited comment, concurrent comments, API errors and merge blocking.
4. Set required status context `CLA v2 / agreement` for main and staging. Verify that a failing status blocks merging.
5. Only after successful verification, disable the legacy CLA Assistant workflow in a controlled change. Preserve historical v1 signature evidence.

## Security and rollback
The workflow requires repository-scoped contents:write to persist evidence; GitHub does not offer path-scoped GITHUB_TOKEN contents permissions. Protect main and staging from direct writes by this identity and restrict who can modify workflows. A failed audit posts an error status where possible; inability to post a status must never be interpreted as approval. If enforcement fails, revert branch-rule changes and retain the existing CLA Assistant while remediating.
