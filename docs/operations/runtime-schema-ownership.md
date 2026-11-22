# Runtime schema ownership

Status: 2026-11-22. Scope: which code creates database tables, and how production schema changes are applied and rolled back.

## Production schema (Rust service)

- Owner: versioned SQL migrations in `rust/migrations/` (`0001_core_api_key_usage.sql`, `0002_core_issued_api_keys.sql`), applied by sqlx (`Migrator`, `src/db.rs::run_sqlx_migrations`).
- Tracking table: `_sqlx_migrations`. The service checks it with `verify_sqlx_migrations_complete` against `EXPECTED_SQLX_MIGRATION_COUNT = 2`.
- Apply paths:
  - out-of-band before deploy (preferred), or
  - at startup when `GOVAI_AUTO_MIGRATE=true`.
- Both migration files use `create table if not exists`, so they are idempotent on re-run. Migrations are forward-only.

### Migration procedure

1. Add a new numbered file in `rust/migrations/`. Do not edit an applied file.
2. Update `EXPECTED_SQLX_MIGRATION_COUNT` in the same PR.
3. Take a logical backup of the target database before applying: `pg_dump --format=custom "$GOVAI_DATABASE_URL" > backup-<date>.dump`.
4. Apply out-of-band, then confirm `select count(*) from _sqlx_migrations where success = true` equals the expected count.
5. Run the service `/ready` check.

### Rollback procedure

sqlx migrations have no automatic down step. Roll back in one of two ways:

- **Restore:** stop the service, restore the pre-migration dump into a fresh database, and point the service at it.
- **Forward fix:** add a new migration that reverses the schema change, and bump the expected count.

Do not delete rows from `_sqlx_migrations` by hand.

## Runtime-created tables (Python, not shipped)

These modules run `CREATE TABLE IF NOT EXISTS` when they are constructed. They are reference or benchmark code, and they are not part of the release artifact (`python/pyproject.toml` packages only `aigov_py*` and `govai*`).

| Module | Tables | Classification |
|--------|--------|----------------|
| `benchmarks/agent-verification/nonce_store.py` | `aigov_consumed_nonces` | Benchmark |
| `benchmarks/agent-verification/revocation_list.py` | `aigov_revocations` | Benchmark |
| `benchmarks/agent-verification/sql_audit_store.py` | `aigov_audit_log` | Benchmark |
| `benchmarks/agent-verification/sql_key_store.py` | `aigov_signing_keys` | Benchmark |
| `benchmarks/openai-agents-integration/adapter/sql_approval_registry.py` | `aigov_sdk_approvals` | Integration reference (README: "Production-oriented", but not packaged) |
| `benchmarks/openai-agents-integration/adapter/document_store.py` | `documents` (SQLite demo) | Demo |

Enforcement: `python/tests/test_runtime_ddl_boundary.py` fails if DDL appears in `python/govai` or `python/aigov_py`, or if shipped code imports these modules.

### Adoption rule

Before any of these stores runs in a production environment:

1. Move its DDL into a versioned migration (for example, a sqlx migration file or a reviewed migration script).
2. Follow the migration and rollback procedure above.
3. Remove the module from the boundary test's exclusions, with a review note.

Until then, do not deploy them as production schema owners.

## Destructive test database

`python/tests/test_postgres_integration.py` drops tables. It runs only when all of these hold: `DATABASE_URL` is set, `AIGOV_PG_TEST_DESTRUCTIVE=1` is set, the host is local, and the database name is `aigov_integration` or contains `test`. Otherwise the test fails rather than skips. See `python/tests/_pg_safety.py`.
