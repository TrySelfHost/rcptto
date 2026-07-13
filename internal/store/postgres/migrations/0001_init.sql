-- 0001_init: result cache and bulk jobs.
-- Forward-only. Applied automatically by the embedded migration runner.

CREATE TABLE IF NOT EXISTS result_cache (
    key        TEXT PRIMARY KEY,
    verdict    JSONB       NOT NULL,
    expires_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS result_cache_expires_at_idx
    ON result_cache (expires_at)
    WHERE expires_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS jobs (
    id           TEXT PRIMARY KEY,
    status       TEXT        NOT NULL,
    total        INTEGER     NOT NULL,
    done         INTEGER     NOT NULL DEFAULT 0,
    created_at   TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS job_results (
    job_id  TEXT    NOT NULL REFERENCES jobs (id) ON DELETE CASCADE,
    idx     INTEGER NOT NULL,
    verdict JSONB   NOT NULL,
    PRIMARY KEY (job_id, idx)
);
