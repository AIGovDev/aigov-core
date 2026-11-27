CREATE TABLE IF NOT EXISTS core_ledger_heads (
    tenant_id TEXT PRIMARY KEY,
    seq BIGINT NOT NULL CHECK (seq >= 0),
    head_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS core_ledger_records (
    tenant_id TEXT NOT NULL REFERENCES core_ledger_heads(tenant_id),
    seq BIGINT NOT NULL CHECK (seq > 0),
    event_id TEXT NOT NULL,
    event_json TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    record_hash TEXT NOT NULL,
    PRIMARY KEY (tenant_id, seq),
    UNIQUE (tenant_id, event_id)
);
