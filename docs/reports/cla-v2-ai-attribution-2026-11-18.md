# CLA v2 AI attribution — security and compliance report

Date: 2026-11-18

## Scope
The CLA v2 checker rejected the staging-to-main PR because historical commits contain an exact `Co-authored-by: Claude Sonnet 4.6 <noreply@anthropic.com>` attribution trailer. This patch treats that exact trailer as tool attribution metadata rather than an independently signable human contributor. No other trailer is exempted.

## Evaluation gate
The patch includes regression tests for exact AI attribution, mixed human-and-AI coauthor trailers, and lookalike attribution addresses. Initial CI failed because newly added test fixtures used double-escaped newlines, so the parser saw no separate trailer lines. Fixtures were corrected in a follow-up commit. Final CI status must be checked before merge.

## Risk and limitations
Git commit trailers are untrusted text. This exact exception is not proof of provenance or authorship; it only prevents known AI-tool metadata from being treated as a legal signatory. GitHub numeric identity verification of actual commit authors, PR submitter checks, historical CLA signature validation, and fail-closed handling of other coauthor trailers remain unchanged. A future change to the exact attribution format requires separate review.

## Human approval gate
Pending. A maintainer must inspect the diff, confirm all required CI checks, and approve before merging. This report does not authorize release or changes to branch rulesets.
