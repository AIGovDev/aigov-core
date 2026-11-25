-- Executor store, version 2: durable lifecycle, receipt delivery state, append-only hash-chained history.
--
-- Applied out of band by the operator tool (python -m aigov_py.trusted.store_admin migrate). The executor never runs
-- this file. The whole file is one transaction, and it sets PRAGMA user_version = 2 as its last step.
--
-- Non-destructive: adds columns and a table, relabels existing rows, and never drops or rewrites a record.
-- Migrated rows keep their history; the event log gets one "migrated_from_v1" entry per existing execution.

BEGIN IMMEDIATE;

ALTER TABLE executions ADD COLUMN executor_identity TEXT;
ALTER TABLE executions ADD COLUMN policy_revision TEXT;
ALTER TABLE executions ADD COLUMN receipt_state TEXT;
ALTER TABLE executions ADD COLUMN receipt_event_id_pending TEXT;
ALTER TABLE executions ADD COLUMN worker_id TEXT;
ALTER TABLE executions ADD COLUMN lease_until_utc TEXT;
ALTER TABLE executions ADD COLUMN reconciled_outcome TEXT;
ALTER TABLE executions ADD COLUMN arguments_json TEXT;

CREATE TABLE IF NOT EXISTS execution_events (
    event_seq INTEGER PRIMARY KEY AUTOINCREMENT,
    authorization_id TEXT NOT NULL,
    event TEXT NOT NULL,
    from_state TEXT,
    to_state TEXT NOT NULL,
    actor TEXT NOT NULL,
    ts_utc TEXT NOT NULL,
    detail_json TEXT NOT NULL,
    prev_hash TEXT,
    event_hash TEXT
);

CREATE INDEX IF NOT EXISTS execution_events_by_authorization
    ON execution_events (authorization_id, event_seq);

CREATE TRIGGER IF NOT EXISTS execution_events_no_update
BEFORE UPDATE ON execution_events
BEGIN
    SELECT RAISE(ABORT, 'execution_events is append-only');
END;

CREATE TRIGGER IF NOT EXISTS execution_events_no_delete
BEFORE DELETE ON execution_events
BEGIN
    SELECT RAISE(ABORT, 'execution_events is append-only');
END;

-- Relabel the v1 states. A v1 row in 'reserved' never finished, so its side effect may have run: its outcome is
-- unknown, so it goes to reconciliation_required, where it is never retried automatically. A v1 'executed' row succeeded. A v1 'failed' row failed.
UPDATE executions SET state = 'reconciliation_required' WHERE state = 'reserved';
UPDATE executions SET state = 'succeeded' WHERE state = 'executed';

-- Receipt state: a finished row with a receipt is recorded; a finished row without one is missing its receipt.
UPDATE executions
   SET receipt_state = CASE WHEN receipt_event_id IS NOT NULL THEN 'recorded' ELSE 'none' END
 WHERE state IN ('succeeded', 'failed');
UPDATE executions SET receipt_state = 'none' WHERE receipt_state IS NULL;

-- Bind every row to its executor identity and policy revision, taken from the signed authorization it stored.
UPDATE executions
   SET executor_identity = json_extract(signed_authorization_json, '$.payload.executor_audience'),
       policy_revision = json_extract(signed_authorization_json, '$.payload.policy_revision');

-- One history entry per existing execution, so the log starts with what the v1 store already knew.
INSERT INTO execution_events (authorization_id, event, from_state, to_state, actor, ts_utc, detail_json, prev_hash, event_hash)
SELECT authorization_id, 'migrated_from_v1', NULL, state, 'migration-0002',
       COALESCE(finished_at_utc, reserved_at_utc),
       json_object('source_schema', 1, 'hashed', 0),
       NULL, NULL
  FROM executions
 ORDER BY reserved_at_utc, authorization_id;

PRAGMA user_version = 2;

COMMIT;
