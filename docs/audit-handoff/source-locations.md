# Source locations for each enforcement point

Paths are relative to the repository root. Line numbers are omitted on purpose: they change. Search for the name.

| Enforcement point | File | Name |
|---|---|---|
| Evidence ingest: role check, receipt checks, in-force revision check, append, authorization | `rust/src/govai_api.rs` | `post_evidence` |
| Tenant and principal resolution | `rust/src/govai_api.rs`, `rust/src/principals.rs` | `resolve_tenant`, `request_principal`, `role_may_post` |
| Role table and protected types | `rust/src/principals.rs` | `PROTECTED_EVENT_TYPES`, `role_may_post` |
| Startup configuration and refusals | `rust/src/govai_api.rs` | `build_app_state`, `refuse_fault_injection_outside_test` |
| Request limits | `rust/src/request_limits.rs`; layers in `rust/src/govai_api.rs` | `RequestLimits::from_env`, `build_router` |
| API key checks | `rust/src/audit_api_key.rs` | `require_tenant_id_from_api_key_for_ledger`, `bearer_token_is_authorized` |
| OIDC gate | `rust/src/oidc.rs` | `init_from_env` |
| Approval check | `rust/src/execution_authorization.rs` | `approval_refusal` |
| Authorization preparation and signing | `rust/src/execution_authorization.rs` | `prepare`, `sign_prepared`, `active_registry_key` |
| Key registry: load, verify, anchor | `rust/src/key_registry.rs` | `load_verified` |
| Policy load, anti-rollback, activation | `rust/src/policy_store.rs` | `load_for_deployment`, `enforce_anti_rollback`, `commit_revisions` |
| Policy anchor: decision, reconciliation, in-force check | `rust/src/policy_anchor.rs` | `decide`, `reconcile_all_and_commit`, `check_in_force_not_superseded` |
| Policy filesystem record | `rust/src/policy_watermark.rs` | `check`, `commit` |
| Ledger: append, lock, verify | `rust/src/audit_store.rs` | `append_record_checked`, `LedgerFileLock`, `verify_chain` |
| Policy evaluation of events | `rust/src/policy.rs`, `rust/src/policy_engine.rs` | `enforce`, `enforce_human_approved` |
| Fault-injection points (test build only) | `rust/src/govai_api.rs` | `crash_point` (cfg feature `fault-injection`) |
| Executor: verify authorization, run, record | `python/aigov_py/trusted/executor.py` | `Executor` |
| Authorization verification (SDK) | `python/aigov_py/trusted/authorization.py` | `verify_authorization_signature`, `verify_authorization_with_registry` |
| Executor store (PostgreSQL) | `python/aigov_py/trusted/store_pg.py` | `PostgresExecutionStore` |
| Executor store schema | `python/aigov_py/trusted/migrations/pg/0001_executor_pg.sql` | triggers, constraints |
| Reconciliation | `python/aigov_py/trusted/reconcile.py` | `verify_reconciliation`, `apply_reconciliation` |
| Key operations (SDK side) | `python/aigov_py/trusted/keys.py` | `KeyRegistry`, `TrustConfig` |
| Migrations (Core) | `rust/migrations/` | `0001` to `0004` (forward only) |
| Container image | `rust/Dockerfile` | `ENV`, `USER`, pinned base digests |
| Deployment configuration check | `scripts/deploy_preflight.py` | names only |
