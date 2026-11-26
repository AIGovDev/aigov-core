-- Executor store, version 1. Applied out of band, before first use, by an operator.
-- The SDK checks that this table exists and does not create it. Re-running is safe.
-- See docs/trusted-execution-sdk.md, section "The executor store".

CREATE TABLE IF NOT EXISTS executions (
    authorization_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    args_digest TEXT NOT NULL,
    state TEXT NOT NULL,
    reserved_at_utc TEXT NOT NULL,
    finished_at_utc TEXT,
    outcome TEXT,
    result_digest TEXT,
    receipt_event_id TEXT,
    signed_authorization_json TEXT NOT NULL
);
