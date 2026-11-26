# Customer pilot readiness: AIGov Core

Status: **controlled pilot, conditional GO. Not approved for unrestricted production.**

The package the decision refers to is `docs/release/pilot-package.md`. The evidence is `docs/reports/pilot-readiness-closure-2026-11-26.md`.
The previous decision is `docs/reports/release-candidate-2026-11-26.md`.

## Decision

| Scope | Decision | Basis |
|---|---|---|
| Controlled pilot: one tenant, one ledger host, production mode, principals configured in every environment, the conditions below | **GO, conditional** | No open Critical or High finding. Every High and Medium finding of both audits is fixed and tested, except R-2, R-6, and R-9, which are accepted risks. Final-code validation passes locally (report, section "Validation"). |
| Unrestricted production, several tenants on one host, several hosts sharing a ledger, or load beyond the pilot's measured volume | **NO-GO** | Multi-host ledgers are unsupported (R-4). Issue #501 decisions D1–D4 are not recorded. No load test of Core has been run (R-3). |

The GO becomes a NO-GO if any condition is not met, or if the hosted CI result on the final commit is not green.

## Conditions

1. **Principals in every environment that runs the pilot.** Production refuses to start without them, and staging now does too (R-1). A staging
   deployed from this release needs `GOVAI_PRINCIPALS_JSON` before its first start.
2. **One ledger host per tenant.** Do not run several Core instances on different hosts that share a ledger directory (R-4).
3. **The owners record decisions D1–D4** (`docs/decisions/issue-501-owner-decisions.md`). D1 and D2 may be accepted as residual risk in writing, with
   R-2 recorded. D4 needs two named people for any reset before the pilot starts.
4. **The owners accept R-6 and R-9 in writing.** R-6: concurrent issuance during a key or policy change across processes is not verified. R-9: a
   downstream system without a deduplication key can apply a retried side effect twice.
5. **The crash-consistency gate, the two-volume test, and the customer pilot pass on the release commit**, and the hosted CI run on that commit is green
   for every required check, including the `crash-consistency-gate` job.
6. **The request limits are chosen for the pilot's volume** (`AIGOV_REQUEST_TIMEOUT_SECS`, `AIGOV_MAX_CONCURRENT_REQUESTS`, `AIGOV_MAX_BODY_BYTES`), and
   recorded with the deployment. The defaults have not been load-tested.
7. **The version and the release record are chosen by the owners** (`docs/release/release-artifacts.md`), and the provenance record for the release commit
   is kept with the deployment.

## What the pilot does not get

- Exactly-once external effects (R-9). The pilot chooses a deduplication key, or accepts the duplicate risk.
- Protection against a privileged database administrator who changes the policy anchor and the record together (R-2).
- Multi-host ledgers, or any Core instance outside the single-host topology.
- Signed release artifacts. The SBOMs and the provenance record are unsigned.
- A measured production ingest latency. The pilot sets it (`pilot-package.md`, section 5).

## Stop and rollback

The pilot stops or pauses on the criteria in `pilot-package.md`, section 8. Rollback procedures for the Core image, the policy revision, the executor
SDK, and the data are in section 7 of the same document. A policy rollback is refused by the anchor, so it is not an option; the fix is a higher revision.

## Recommendation to the owners

GO for the controlled pilot, once the conditions above are met and written down. The most useful step before any pilot volume is a short load test of
Core with the chosen limits, because R-3 is the residual most likely to surprise a customer.
