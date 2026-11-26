-- Independent monotonic anchor for the trusted key registry (see python/aigov_py/trusted/registry_anchor.py).
-- One row per registry: the sequence number and head hash of the last committed event. Writers update it only by
-- compare-and-swap inside the transaction that appends the event; readers require the registry log to match it exactly.
CREATE TABLE IF NOT EXISTS key_registry_anchor (
    registry_id TEXT PRIMARY KEY,
    seq BIGINT NOT NULL CHECK (seq >= 0),
    head_hash TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
