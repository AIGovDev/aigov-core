-- Run-manifest tenant ownership (additive steps only). See docs/operations/runs-tenant-migration.md.
-- Apply to a non-production database first. Do not run automatically.
--
-- Step 1: add the owner column. Existing rows stay NULL, which means "unowned".
--         Writers refuse to update unowned rows, so legacy data is never overwritten.
alter table console.runs add column if not exists tenant_id text;

-- Step 2: index owner lookups used by the ownership check.
create index if not exists console_runs_tenant_id_idx on console.runs (tenant_id);

-- Steps 3 and 4 are operator decisions, not automatic:
--   Step 3 (per run, after verifying the run in the tenant's own ledger):
--     update console.runs set tenant_id = '<tenant>' where id = '<run_id>' and tenant_id is null;
--   Step 4 (only after every row has an owner, or unowned rows are removed by the operator):
--     alter table console.runs alter column tenant_id set not null;
