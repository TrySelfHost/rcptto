-- 0002_egress_state: persisted egress reputation.
--
-- Stored as JSONB keyed by identity id. The shape is owned by the application
-- (store.EgressState) and evolves additively, so a document column avoids a
-- migration for every new reputation signal.

CREATE TABLE IF NOT EXISTS egress_state (
    id         TEXT PRIMARY KEY,
    data       JSONB       NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
