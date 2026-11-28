CREATE TABLE IF NOT EXISTS core_approval_consumptions (
    tenant_id TEXT NOT NULL,
    approval_event_id TEXT NOT NULL,
    decision_event_id TEXT NOT NULL,
    PRIMARY KEY (tenant_id, approval_event_id),
    UNIQUE (tenant_id, decision_event_id),
    FOREIGN KEY (tenant_id, approval_event_id)
        REFERENCES core_ledger_records (tenant_id, event_id),
    FOREIGN KEY (tenant_id, decision_event_id)
        REFERENCES core_ledger_records (tenant_id, event_id),
    CHECK (approval_event_id <> decision_event_id)
);
