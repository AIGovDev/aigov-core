# Security invariants

Each invariant states what Core or the SDK claims. "Enforced at" names the code. "Checked by" names the tests in this repository, with the
kind of check. A check that runs only in the fault-injection build or only with real separate volumes says so.

| # | Invariant | Enforced at | Checked by |
|---|---|---|---|
| I-1 | A caller can post only the event types its role owns; protected types have one owning role | `principals.rs` `role_may_post`; `govai_api.rs` `post_evidence` (role check before append) | unit test `principals::tests`; `prod_requires_principals.rs`; `staging_requires_principals.rs`; `tb_http_verdict.rs`; the staging simulation (`scripts/staging_policy_verify.py`, role refusals) |
| I-2 | Production and staging do not start without principals, a signed bundle, and a policy anchor | `govai_api.rs` `build_app_state`; `policy_store.rs` `load_for_deployment`, `enforce_anti_rollback` | `prod_requires_principals.rs`; `staging_requires_principals.rs`; `tb_no_bundle_prod_refused.rs`; the staging simulation (66 checks) |
| I-3 | An approval authorizes at most one consequential call, across processes and restarts | `execution_authorization.rs` `approval_refusal`; checked under the ledger lock in `post_evidence` | `test_approval_single_use_two_instances.py` (two processes, five rounds); `test_issuance_cross_process.py` (three processes, rotation and revocation); `test_crash_consistency_core.py` (restart); `approval_before_authorization.rs` |
| I-4 | No authorization is delivered without a committed evidence record | Record appended before signing; `post_evidence` returns the authorization only after the append | `test_crash_consistency_core.py` at three boundaries (before append, after append before signing, after signing before response). Fault-injection build only |
| I-5 | A call whose key is retired or revoked after its record is committed is refused; nothing is authorized under the retired key | `execution_authorization.rs` signing path re-reads the registry; `AUTHORIZATION_SIGNING_REFUSED` | `test_issuance_cross_process.py`: after rotation, the signing refusals name the retired key, and no exe-a authorization is issued after revocation |
| I-6 | Every authorization verifies against the registry key for its key id, and the registry log is hash-chained and anchored | `key_registry.rs` `load_verified`; `authorization.py` `verify_authorization_with_registry` | `test_issuance_cross_process.py` (signature check per authorization); `test_registry_postgres.py` (anchor follows the log, rollback refused); `test_registry_attacks.py` |
| I-7 | Execution receipts are accepted only from an executor principal, and only for an authorization Core issued in the same run | `post_evidence` receipt checks (`RECEIPT_REQUIRES_EXECUTOR`, `RECEIPT_FOR_UNISSUED_AUTHORIZATION`) | `test_receipt_provenance_core.py` (four tests) |
| I-8 | An evidence write is refused while the process serves a revision the anchor has superseded, or cannot confirm its revision | `policy_anchor.rs` `check_in_force_not_superseded`, called in `post_evidence` before the append | `test_policy_revision_across_processes.py` (superseded refused; missing anchor refused and recovers) |
| I-9 | A policy revision cannot roll back, across two real filesystems | `policy_watermark.rs`, `policy_anchor.rs` `decide`, `reconcile_all_and_commit` | `two_volume_rollback_pg.rs` via `make two-volume-rollback` (requires two volumes; not in CI) |
| I-10 | The ledger chain verifies after crashes, restarts, and concurrent appends on one host | `audit_store.rs` `verify_chain`; the ledger lock (`LedgerFileLock`, `flock`) | `test_distributed_core_ledger.py` (two Core processes); `test_crash_consistency_core.py`; the load test's chain check (`scripts/core_load_test.py`) |
| I-11 | Request time, concurrency, and body size are bounded; health answers under the limit | `request_limits.rs`; the layers on the ledger routes in `build_router` | `request_limits_http.rs` (real socket; the negative control fails without the limit); `request_limits.rs` unit tests |
| I-12 | Overload refuses or times out a request; it does not write a partial record | Time limit includes the permit wait and the body read; the append happens after the body is read | `request_limits_http.rs`; the load test (`docs/evidence/release-candidate/load/`) |
| I-13 | An executor runs an action at most once per authorization, and never after a stale claim | `store_pg.py` `PostgresExecutionStore` (fencing, row lock, advisory chain lock); `executor.py` | `test_distributed_executor_pg.py` (contention with four processes; stale worker; kill after side effect); `test_store_pg.py` |
| I-14 | Executor history is append-only at the database level | `python/aigov_py/trusted/migrations/pg/0001_executor_pg.sql` triggers | `test_store_pg.py` (tamper refused) |
| I-15 | The fault-injection code is absent from a normal release build | `#[cfg(feature = "fault-injection")]` in `govai_api.rs`; `rust/Dockerfile` builds without the feature | `make fault-absence-check` (strings check on the release binary) |
| I-16 | A refused start names its refusal and does not partially apply configuration | `build_app_state` order: limits, principals, then policy and anchors | the staging simulation (override refusals, each with its message) |
| I-17 | Reconciliation evidence is applied at most once, and only from a registered reconciler | `reconcile.py` `verify_reconciliation`, `apply_reconciliation` | `test_registry_attacks.py`, `test_distributed_executor_pg.py` (reconciliation paths) |

## What the invariants do not cover

- I-6 and I-8 trust the database row. A privileged database user who changes the anchor and the record together defeats both (R-2).
- I-3 and I-5 hold on one host with one ledger directory. Several hosts sharing a ledger are outside the design (R-4).
- I-13 is about the store and the executor. Whether the downstream system performs the action once depends on its own idempotency (R-9).
- I-10 is a chain, not a signature. Whoever can write the ledger can rebuild it; the protection is the anchor and the off-host head hashes in the runbook.
- Load behaviour: I-11 and I-12 are measured on one host (`docs/evidence/release-candidate/load/`), not under production traffic.
