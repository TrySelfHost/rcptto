-- 0004_settings: operator-tunable runtime configuration.
--
-- A single row (id = 1) holding the settings document, so tuning survives a
-- restart instead of reverting to environment defaults on every deploy.

CREATE TABLE IF NOT EXISTS settings (
    id         SMALLINT PRIMARY KEY DEFAULT 1,
    data       JSONB       NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT settings_single_row CHECK (id = 1)
);
