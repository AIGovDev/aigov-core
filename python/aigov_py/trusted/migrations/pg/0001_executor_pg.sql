-- Executor store on PostgreSQL, version 1. Applied out of band by the operator tool (store_admin migrate-pg), inside one
-- transaction, under an advisory lock. The SDK checks the version and never runs this file.
--
-- Guarantees enforced by the database, not by the SDK:
--   * one execution per authorization id, across all tenants (PRIMARY KEY on authorization_id);
--   * every row carries a tenant; the SDK scopes every query by tenant;
--   * the state and receipt state are constrained to the lifecycle's values;
--   * execution_events is append-only (triggers refuse UPDATE, DELETE, and TRUNCATE);
--   * each event row references its execution.
--
-- Timestamps that feed the hash chain are kept as text, exactly as the SDK wrote them, so the chain can be recomputed.
-- Lease expiry uses the database clock (lease_until is a timestamptz set from now()), never a worker's clock.

CREATE TABLE IF NOT EXISTS executor_schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS executions (
    authorization_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL CHECK (tenant_id <> ''),
    run_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    args_digest TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('reserved', 'started', 'succeeded', 'failed', 'outcome_unknown',
                                         'reconciliation_required', 'reconciled')),
    reserved_at_utc TEXT NOT NULL,
    finished_at_utc TEXT,
    outcome TEXT,
    result_digest TEXT,
    receipt_event_id TEXT,
    signed_authorization_json TEXT NOT NULL,
    executor_identity TEXT,
    policy_revision TEXT,
    receipt_state TEXT NOT NULL DEFAULT 'none' CHECK (receipt_state IN ('none', 'pending', 'recorded')),
    receipt_event_id_pending TEXT,
    worker_id TEXT,
    fence BIGINT NOT NULL DEFAULT 0 CHECK (fence >= 0),
    lease_until TIMESTAMPTZ,
    reconciled_outcome TEXT,
    arguments_json TEXT
);

CREATE INDEX IF NOT EXISTS executions_tenant_state ON executions (tenant_id, state);
CREATE INDEX IF NOT EXISTS executions_lease ON executions (state, lease_until) WHERE state = 'started';

CREATE TABLE IF NOT EXISTS execution_events (
    event_seq BIGINT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    authorization_id TEXT NOT NULL REFERENCES executions (authorization_id),
    event TEXT NOT NULL,
    from_state TEXT,
    to_state TEXT NOT NULL,
    actor TEXT NOT NULL,
    ts_utc TEXT NOT NULL,
    detail_json TEXT NOT NULL,
    prev_hash TEXT,
    event_hash TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS execution_events_by_authorization ON execution_events (authorization_id, event_seq);

CREATE OR REPLACE FUNCTION execution_events_refuse_change() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'execution_events is append-only';
END;
$$;

DROP TRIGGER IF EXISTS execution_events_no_update ON execution_events;
CREATE TRIGGER execution_events_no_update BEFORE UPDATE OR DELETE ON execution_events
    FOR EACH ROW EXECUTE FUNCTION execution_events_refuse_change();

DROP TRIGGER IF EXISTS execution_events_no_truncate ON execution_events;
CREATE TRIGGER execution_events_no_truncate BEFORE TRUNCATE ON execution_events
    FOR EACH STATEMENT EXECUTE FUNCTION execution_events_refuse_change();

INSERT INTO executor_schema_migrations (version, name) VALUES (1, '0001_executor_pg')
    ON CONFLICT (version) DO NOTHING;
