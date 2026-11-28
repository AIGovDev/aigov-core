CREATE INDEX IF NOT EXISTS core_ledger_records_run_idx
    ON core_ledger_records (tenant_id, ((event_json::jsonb)->>'run_id'), seq);
