# CLA v2 shadow audit implementation — 2026-11-17

## Scope
Draft PR #416 introduces an informational read-only CLA shadow check and migration design. Existing required CLA Assistant remains active; no signature records or branch protections are modified.

## Evaluation gate
Status: pending. Shadow workflow completed successfully on the initial PR head, but independent test coverage and correctness review remain incomplete. In particular, the legacy signature schema contains both username and GitHub numeric ID; the initial shadow implementation currently matches username only, which must be hardened before cutover.

## Human approval gate
Status: pending. No approval or production cutover is claimed.

## Risks and limitations
The current informational workflow executes a PR-branch script with a read-only token. Before introducing a privileged or required check, isolate the trusted checker implementation from untrusted PR code and bind signature evidence to verified GitHub account IDs. Handle API pagination, missing identities, ambiguous records, and storage errors as denial. A passing shadow workflow run does not imply a signed CLA.

## Follow-up
Add unit tests and signature-ID verification; validate workflow behavior on fork PRs; review independent signature writer design and migration evidence before any enforcement change.
