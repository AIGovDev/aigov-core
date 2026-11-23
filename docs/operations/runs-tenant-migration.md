# Run manifest tenant ownership — migration and rollback

Status: 2026-11-23. Scope: `console.runs` in GovAI Postgres, and Supabase `public.runs`.

## Why

Run rows were keyed only by `run_id`. Any writer holding the service-role key (which bypasses row-level security) could overwrite another tenant's run. Writers now require a tenant, prove that the run is recorded in that tenant's own ledger, and never overwrite a row owned by another tenant.

## Code behavior (already in this release)

- `aigov_py.ingest_run` requires `--tenant-id` (or `AIGOV_TENANT_ID`). It refuses unless the run appears in `audit_log__<segment>.jsonl` for that tenant (`aigov_py.tenant_ledger.run_recorded_for_tenant`). Missing or malformed ledgers fail closed.
- `make db_ingest` requires `TENANT_ID`.
- Supabase writes are refused in production (`AIGOV_ENVIRONMENT=prod`), with no override.
- Supabase writes check the existing row's owner first. Postgres writes use `on conflict (id) do update ... where console.runs.tenant_id = excluded.tenant_id`, and an update that matches no row raises an ownership error.
- Artifact uploads go to `<tenant>/<run_id>.zip` and `<tenant>/<run_id>.json`. Existing objects are not moved.

## Migration (operator-run, non-production first)

1. Apply Step 1 and Step 2 from `docs/operations/runs-tenant-migration.sql`. This is additive. Existing rows are unowned, so no writer can change them.
2. For each run to claim, confirm it in the tenant's ledger, then assign the owner:
   `update console.runs set tenant_id = '<tenant>' where id = '<run_id>' and tenant_id is null;`
3. Only when no unowned rows remain that you still need, apply Step 4 (`set not null`).
4. Repeat for `public.runs` on Supabase, using the staging project first. Do not use the production project from a staging job.

## Rollback

- Code: revert the release. Old writers ignore `tenant_id`.
- Schema: `drop index if exists console_runs_tenant_id_idx; alter table console.runs drop column if exists tenant_id;`. Run this only after confirming no code relies on the column. Dropping the column loses ownership data, so take a backup first.

## Residual risks (documented, not claimed as solved)

- The Supabase check-then-write is not atomic. A concurrent writer can race between the existence check and the upsert. The Postgres path is atomic, and the Supabase path should be replaced by the Postgres path or protected by a database constraint before production use.
- Row-level security policies on `public.runs` and `console.runs` are not defined in this repository. They must be reviewed in the Supabase project and the console database.
- Operators who hold the service-role key can still bypass these checks by writing the database directly.
