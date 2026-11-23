# Tenant-scoped run records and injective ledger storage — 2026-11-23

## Scope

Closes two tenant-isolation risks left open by the authentication milestone:

- **B2:** Supabase service-role writes to `runs` (and `console.runs`) keyed only by `run_id`.
- **B3:** tenant ledger filenames derived by lossy normalization, so distinct tenants could share evidence.

Supersedes the B3 description in `docs/reports/auth-tenant-isolation-2026-11-23.md`. The mapping described there (sanitize-and-collide-check) was replaced by the injective mapping below.

## 1. Is the Supabase ingestion path production-relevant?

Yes, in the sense that matters for isolation. `make db_ingest` (operator-run, `python -m aigov_py.ingest_run`) writes run metadata to Supabase `runs` (default `AIGOV_RUN_PERSISTENCE=supabase`) or to `console.runs` (PostgreSQL), and uploads artifacts to Supabase Storage with the service-role key. The console (dashboard, outside this repository) reads these rows. The audit API does not call this path, and no CI job or Dockerfile runs it. It cannot be removed, because the console depends on it. It is therefore hardened, not disabled, and production use is refused for the Supabase writer.

## 2. Vulnerabilities addressed

| ID | Previous behavior | Evidence |
|----|-------------------|----------|
| B2a | Any `run_id` could be upserted by any operator with the service-role key, overwriting another tenant's run (`on conflict (id) do update`). | Code review of `govai_postgres_runs.py` and `supabase_db.py` |
| B2b | Tenant was an unvalidated CLI string; no proof the run belonged to it. | Code review of `ingest_run.main` |
| B2c | Artifact objects named `<run_id>.zip` / `<run_id>.json`, so tenants could overwrite each other's objects. | Code review of `storage_upload.upload_artifacts_for_run` |
| B3a | `team.a` and `team_a` mapped to the same ledger file (demonstrated in the previous milestone). | `probe` over HTTP, reported in the previous report |
| B3b | Tenant names longer than 128 characters were truncated, so long IDs differing after character 128 collided. | `project.rs::sanitize_project_segment` (`.take(128)`) |
| B3c | Case variants (`Team`, `team`) collide on case-insensitive filesystems (macOS default). | Mapping analysis; regression test |

## 3. Implemented fixes

### Rust: injective ledger mapping (B3)

`rust/src/project.rs`:

- Identity: ids made only of `[A-Za-z0-9_-]`, up to 128 characters, map to themselves. Existing ledger files for those tenants are unchanged.
- Everything else maps to `~h` + lowercase hex of the UTF-8 bytes, or `~s` + SHA-256 hex when longer than 100 bytes. `~` is never produced by the identity rule, so no two distinct ids share a segment. The output contains no `.`, `/`, or `\`, so it cannot traverse paths.
- `AIGOV_LEDGER_LEGACY_TENANTS` (new, explicit): a tenant listed here keeps the old lossy filename. Nothing is moved or overwritten.

`rust/src/audit_api_key.rs`:

- `check_tenant_ledger_collisions` refuses startup when two tenants share a segment ignoring ASCII case, in every environment.
- It also refuses startup when a tenant has a pre-v2 ledger file on disk and is not listed in `AIGOV_LEDGER_LEGACY_TENANTS`. This prevents evidence from silently appearing empty. The error names the variable to set.
- `check_new_tenant_against_existing` and `configured_env_tenants` back database-issued tenant checks.

`rust/src/tenant_api_keys.rs`:

- `issue_api_key` validates the tenant id (identity charset) and refuses a tenant whose segment collides, ignoring case, with an existing database tenant or environment tenant.
- `check_db_tenants_against_env` runs at startup when a database is configured. It fails startup on any database tenant that collides with an environment tenant.

### Python: tenant-proven ownership (B2)

`python/aigov_py/tenant_ledger.py` (new) mirrors the Rust mapping and proves ownership from the tenant's own ledger:

- `validate_tenant_id`: identity charset only.
- `run_recorded_for_tenant`: reads `audit_log__<segment>.jsonl` and checks `event_json.run_id`. A missing ledger returns False. A malformed line raises, so it cannot pass as "not owned" by accident.

`python/aigov_py/ingest_run.py`:

- Requires `--tenant-id` or `AIGOV_TENANT_ID`, validated.
- Refuses before any write unless the run is recorded in that tenant's own ledger. A spoofed claim is refused.
- Includes `tenant_id` in the row. Artifacts are uploaded under `<tenant>/`.
- `make db_ingest` requires `TENANT_ID`.

`python/aigov_py/supabase_db.py`:

- Refused when `AIGOV_ENVIRONMENT=prod`, with no override.
- Requires a valid `tenant_id`.
- Reads the existing row first, and refuses to overwrite a row owned by another tenant or by no tenant.
- `create_supabase_client` now imports the `supabase` package lazily. This keeps the module importable without the optional dependency and does not change behavior.

`python/aigov_py/govai_postgres_runs.py`:

- Inserts `tenant_id`.
- The conflict update is conditional: `where console.runs.tenant_id = excluded.tenant_id`. If no row matches, it raises `RunOwnershipError`. Legacy rows with no owner are never updated.

`python/aigov_py/storage_upload.py`: object names are prefixed with the validated tenant.

## 4. Migration requirements

Nothing is migrated automatically. Full procedure, including rollback, is in `docs/operations/runs-tenant-migration.md`. Additive SQL is in `docs/operations/runs-tenant-migration.sql`.

Summary:

1. **Ledger files (Rust):** no action for tenants with identity-safe ids. For a tenant with an existing pre-v2 file (for example `audit_log__team_a.jsonl` for `team.a`), either:
   - add the tenant to `AIGOV_LEDGER_LEGACY_TENANTS` to keep reading the old file, or
   - copy the file to the new name explicitly (copy, never move or overwrite, and verify the hash chain). This procedure is not automated.
   Startup refuses until one of these is done.
2. **Tenant ids in key maps:** any tenant id that is not identity-safe, or that collides ignoring case with another tenant, must be renamed before upgrading. Startup refuses otherwise.
3. **`console.runs`:** apply Step 1 and Step 2 of the SQL file. Assign owners per run after confirming the run in the tenant's ledger. Apply Step 4 (`not null`) only when no unowned rows are needed.
4. **Supabase `public.runs`:** same schema change, applied to a staging project first. Production writes from this path are refused.
5. **Artifacts:** new uploads are prefixed. Existing objects are not moved.

## 5. Tests

### Adversarial and regression

| Test | Covers |
|------|--------|
| `project::tests::tenant_segments_are_injective_for_adversarial_ids` | `team.a`/`team_a`, `a/b`/`a_b`, `../x`, NFC/NFD, case, empty, `~`-prefixed inputs, 129+ character IDs |
| `project::tests::dotted_and_underscored_tenants_no_longer_share_a_file` | the previous collision |
| `project::tests::unicode_normalization_variants_stay_distinct` | NFC vs NFD |
| `project::tests::case_variants_are_flagged_by_collision_key` | case-insensitive collision |
| `project::tests::long_ids_do_not_truncate_into_each_other` | previous 128-character truncation |
| `project::tests::tenant_segment_vectors_match_python_mirror` | Rust and Python produce identical segments |
| `project::tests::legacy_segment_is_only_used_for_listed_tenants` | explicit opt-in |
| `tests/tenant_adversarial_ledger.rs` | nine adversarial tenants through the real router: each sees only its own evidence; one ledger file per tenant; no escape from the ledger directory |
| `tests/tenant_collision_startup.rs` | case-only collision refused at startup |
| `tests/tenant_legacy_refuse.rs` | existing unlisted legacy file refused at startup |
| `tests/tenant_legacy_listed.rs` | listed legacy tenant reads and writes its legacy file |
| `tests/db_issued_keys_pg.rs` (PostgreSQL) | case-variant of an existing issued tenant refused at issuance; charset refused; team scoping; revocation |
| `python/tests/test_tenant_ledger.py` | vectors, injectivity, validation, ownership proof, spoof refusal, malformed ledger |
| `python/tests/test_ingest_tenant_ownership.py` | missing or malformed tenant refused; spoofed tenant refused before any write; owner ingests |
| `python/tests/test_runs_writer_guards.py` | production refusal; tenant required; cross-tenant overwrite refused; legacy unowned row refused; same owner allowed; tenant-scoped artifacts |
| `python/tests/test_runs_tenant_pg.py` (PostgreSQL, opt-in) | cross-tenant overwrite and legacy-unowned overwrite refused by the database path, with the migration applied |

Demonstration that the previous behavior was vulnerable: the PostgreSQL ownership test fails when the `where` clause is removed (two failures: cross-tenant and legacy-unowned). The earlier HTTP probe reproduced B3a on the previous code.

### Results

| Suite | Result |
|-------|--------|
| Rust `cargo test --locked`, with PostgreSQL auth test opted in (`AIGOV_TEST_PG_AUTH=1`, isolated container, database `aigov_integration`) | 202 passed, 0 failed, 0 ignored |
| Python full suite, no database | 1012 passed, 41 skipped |
| Python full suite, PostgreSQL opted in (`AIGOV_TEST_PG_RUNS=1`, `AIGOV_PG_TEST_DESTRUCTIVE=1`, isolated database `aigov_runs_test`) | 1049 passed, 4 skipped |
| Skipped with PostgreSQL: live OAuth and tenant provisioning (BLOCKED), Sigstore bundle (BLOCKED), `mcnemar_F_vs_G` report artifact | not evidence; listed for completeness |
| `make` gates (8 targets) | all exit 0 |
| CLA workflow guard, report gate | PASS |
| `ruff` on new Python files | clean; changed existing modules match the staging baseline |
| `mypy` on `tenant_ledger.py` | no issues. The changed `supabase_db.py` reports the optional `supabase` package as not installed in the dev venv, which predates this change. |
| `clippy` on changed Rust files | no findings in new code. One pre-existing lint in `govai_api.rs` is unchanged. |

Skips: the 41 no-database skips are PostgreSQL-gated tests and tests that need the release binary or live services. They are not counted as passing.

## 6. Residual risks

- **Supabase check-then-write is not atomic.** A concurrent writer can slip between the owner check and the upsert. The PostgreSQL path is atomic. Use the PostgreSQL path, or add a database constraint, before any production use.
- **Service-role credentials bypass row-level security.** The operator who holds them can write the database directly. Limit who holds them and rotate them regularly. The code checks cannot stop that.
- **Row-level security policies** for `public.runs` and `console.runs` are not defined in this repository.
- **Cross-source collisions after startup:** environment and database tenants are checked at startup and at issuance. A tenant configured in another process, after this process started, is not checked here.
- **Legacy copy procedure** is manual (see section 4). It is intentionally not automated, because it moves evidence.

## Evaluation gate

Passes when the Rust suite (with PostgreSQL opted in), the Python suite (with and without PostgreSQL), and the make gates pass on the PR head, and when each fix has a regression test that fails on the previous behavior (section 5).

## Human approval gate

Not approved for production by this report.

- Requires your decision and action:
  - whether to keep the Supabase service-role run path in non-production environments, or move the console to the PostgreSQL path only;
  - applying the additive migration to the staging Postgres and Supabase projects, and assigning owners to existing runs;
  - any tenant renames or legacy-file migrations on existing deployments;
  - RLS policy review for the Supabase project and the console database.
- Production remains NO-GO until the residual risks above are resolved or accepted, and the migrations have been rehearsed on a non-production copy.
