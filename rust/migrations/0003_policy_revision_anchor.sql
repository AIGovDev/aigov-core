-- Durable, independent anchor for the accepted policy revision (staging and production).
--
-- One row per policy identifier. `revision` only moves forward; the service advances it under a
-- transaction-scoped advisory lock keyed by policy_id. `digest_sha256` is the document digest of the
-- accepted revision (signatures excluded), so re-signing the same content keeps the same anchor.
--
-- Additive only: this migration creates one table and touches no existing table.
CREATE TABLE IF NOT EXISTS policy_revision_anchor (
    policy_id text PRIMARY KEY CHECK (char_length(policy_id) BETWEEN 1 AND 256),
    revision bigint NOT NULL CHECK (revision >= 0),
    digest_sha256 text NOT NULL CHECK (digest_sha256 ~ '^[0-9a-f]{64}$'),
    updated_at timestamptz NOT NULL DEFAULT now()
);
