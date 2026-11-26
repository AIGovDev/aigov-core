# Issue #501 traceability matrix (2026-11-26)

Issue: "Design review: policy revision anti-rollback before multi-instance or production". Branch `feat/distributed-execution`.

This matrix reviews each requirement and decision the issue states, separately. It does not close the issue, and it is not an
owner decision. Status values:

- **PASS**: implemented, and the evidence named here passes locally.
- **FAIL**: the requirement is not met by the code on this branch.
- **NOT VERIFIED**: implemented in part, or outside what this environment can test. The limit is stated.

The "Limitations" column is part of the result. A PASS with a limitation means the requirement holds for the configuration named,
and not for every configuration the issue mentions.

Scope note: the policy anchor is in `rust/src/policy_anchor.rs` and `rust/tests/policy_anchor_pg.rs`. The file record is in
`rust/src/policy_watermark.rs`. Evidence was run against PostgreSQL 18 (local, throwaway), with `--include-ignored`, on the release
and debug builds of this branch.

## Residual risks named in the issue

| # | Requirement (as stated in #501) | Implementation | Test evidence | Remaining limitations | Status |
|---|---|---|---|---|---|
| R1 | The record is not authenticated: anyone who can write the ledger volume can lower it and redeploy an older signed bundle. | With a PostgreSQL URL configured (staging and production require one), the accepted revision is the database row. A lowered file is refused or restored from the row. | `malicious_older_record_with_a_recomputed_tag_is_refused`: the attacker writes an older record with a valid tag; activation is refused. `restored_older_ledger_snapshot_is_brought_forward_from_the_anchor`. | The file record still carries no key: its tag is a checksum that anyone can recompute. Without PostgreSQL (dev only), a lowered file is still accepted. A PostgreSQL administrator can edit the row. | **PASS** for staging and production configurations; **FAIL** for the file alone (dev, no database) |
| R2 | An empty ledger with a missing record is accepted as a first start, so an attacker deleting the record on a fresh volume is not detected. | With the row present, a deleted record is restored from the row. With the row absent and a record present, startup is refused until an explicit bootstrap. | `deleted_filesystem_record_does_not_reset_the_accepted_revision`; `missing_anchor_with_a_filesystem_record_requires_bootstrap`; `first_start_window_admits_nothing_until_an_explicit_bootstrap`. | A genuinely new deployment has an empty first-start window that only an operator closes. The bootstrap is an operator action; it is not logged to a separate audit trail by this change. | **PASS** (PostgreSQL configured); bootstrap audit trail **NOT VERIFIED** |
| R3 | No replication: replicas on separate volumes each keep their own record, so rollback protection does not hold across them. | The row is shared. Activation takes `pg_advisory_xact_lock` per policy, so two instances on different hosts serialize through the database. | `concurrent_activations_never_regress_the_anchor` (several connections, one process); `multi_policy_activation_with_one_refusal_writes_nothing`. Two-process and two-host runs of the same test: **not run**. | Verified with several connections in one process, not with instances on separate hosts. The file lock still protects only one host. | **NOT VERIFIED** across hosts; mechanism **PASS** |
| R4 | No shared store: no PostgreSQL row lock or table is used for the record. | `key_registry_anchor` (migration 0004), `policy_revision_anchor` (migration 0003), and the executor's `executions` and `execution_events` in PostgreSQL. | The PostgreSQL test suites listed in the audit report, all passing. | The ledger is still a file. Ledger serialization across hosts is not provided. | **PASS** for the policy and registry anchors; ledger **FAIL** across hosts (unsupported topology) |
| R5 | No replay protection for a valid, unexpired bundle at the same revision beyond content identity. | Not changed. The same revision with the same digest is accepted idempotently, by design (`policy_watermark.rs` header). | None added. | A valid, unexpired bundle can be replayed at its own revision. It does not roll back the revision, but it is accepted again. A decision on bundle expiry and nonce binding is needed. | **FAIL** (open) |

## Decisions the issue asks for

| # | Decision (as stated in #501) | What this branch does | Evidence | Remaining limitations | Status |
|---|---|---|---|---|---|
| D1 | Where the authoritative revision lives: a shared PostgreSQL table with row locking, or an external signed or MAC'd store. | Option one: the PostgreSQL row, with row and advisory locks. | Tests listed under R3 and R4. | The owner's decision is not recorded in #501. This matrix records the implementation choice, not an approval. | **NOT VERIFIED** (decision not recorded); implementation **PASS** |
| D2 | Whether to authenticate the record, and who holds the key, so that lowering is detectable. | Not implemented. | None. | The record remains a checksum. Lowering is detected through the row, not by the record's own authentication. | **FAIL** (open) |
| D3 | Whether an empty-ledger first start is acceptable in production, or must be an explicit, logged operator action. | It is an explicit bootstrap (R2). | `first_start_window_admits_nothing_until_an_explicit_bootstrap`. | The decision is not recorded. Logging of the bootstrap is not added by this change. | **NOT VERIFIED** (decision and logging) |
| D4 | Backup and restore rules for the record alongside the ledger volume, and who may reset it. | `docs/operations/policy-anchor-runbook.md` (existing) and `docs/operations/distributed-execution-runbook.md` section 8. | Documentation only. | "Who may reset" is an organisational rule that no code can enforce. Restoring the database and the file together from the same older backup is declared residual in the policy runbook. | **NOT VERIFIED** |

## Acceptance criteria the issue asks for

| # | Criterion (as stated in #501) | Implementation | Evidence | Remaining limitations | Status |
|---|---|---|---|---|---|
| A1 | A multi-instance concurrency test on a shared store. | Shared PostgreSQL stores for the policy anchor, the key registry, and the executor. | `concurrent_activations_never_regress_the_anchor` (policy); `test_concurrent_revocations_apply_exactly_once` on PostgreSQL with six processes (registry); `test_contention_four_processes_perform_each_authorization_exactly_once` (executor, four processes); `test_concurrent_claims_from_eight_processes_give_exactly_one_fence` (executor store, eight processes); `test_concurrent_appends_through_two_instances_keep_one_valid_chain` (two Core processes, one ledger). | Core instances share a ledger only on one host. | **PASS** (for the shared stores); ledger across hosts **FAIL** (unsupported) |
| A2 | A rollback test across two volumes or hosts. | A restored older ledger is brought forward from the anchor. A lowered record is refused. | `restored_older_ledger_snapshot_is_brought_forward_from_the_anchor`; `malicious_older_record_with_a_recomputed_tag_is_refused`. Both are one-host simulations. | No test uses two real volumes or two hosts. | **NOT VERIFIED** (two volumes or hosts); single-host simulation **PASS** |

## Concurrency and failure items that #501 depends on (this change)

| Item | Implementation | Evidence | Status |
|---|---|---|---|
| Ledger append serialization across instances on one host | cross-process `flock` on `<ledger>.lock`, taken before the state read | two Core processes: 200 of 200 accepted and a valid chain (before the change: 181 of 200 HTTP 500 and a corrupted ledger, reproduced on `origin/staging`) | **PASS** (one host) |
| Duplicate event id across instances | the same lock | exactly one of two concurrent identical requests accepted, in every one of 20 trials | **PASS** |
| Approval consumption across instances | the approval check runs inside the locked section | follows from the lock; no direct two-process approval test | **NOT VERIFIED** (direct test) |
| Registry rotation and revocation across processes | PostgreSQL anchor and row lock | six processes, one applies | **PASS** |
| Authorization issuance during concurrent key or policy change | re-read and re-check under the anchor | rotation and revocation between prepare and sign, unit tests | **PASS** (single process); concurrent cross-process issuance **NOT VERIFIED** |

## What is not closed

Issue #501 is not closed by this branch. The open items are R5 (replay of a valid bundle at its own revision), D2 (authenticating
the file record), A2 (two real volumes or hosts), the owner decisions D1 and D3, and the policy-reset rule in D4. A product decision
on multi-host ledgers is also needed; the ledger is host-local.

## Evaluation gate

Issue #501 can be closed only when every row above is PASS, with no FAIL and no NOT VERIFIED, and the owner has recorded the decisions
D1 to D4. Today the matrix has FAIL rows (R5, D2, and the ledger across hosts in R4 and A1) and NOT VERIFIED rows. The gate is not met.

## Human approval gate

Closing #501 is an owner decision and is not made by this branch. The owner must record D1 to D4, decide R5 (bundle replay at the same
revision), decide D2 (authentication of the file record), and either run a two-host test (A2) or accept the single-host scope in writing.
Until then the issue stays open.

