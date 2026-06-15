-- Schema for the network scanner job/result store.
-- Apply with: .venv/Scripts/python.exe -m scripts.init_db

CREATE TABLE IF NOT EXISTS jobs (
    job_id          UUID PRIMARY KEY,
    status          TEXT NOT NULL DEFAULT 'pending',  -- pending | running | completed
    total_ips       INTEGER NOT NULL,
    processed_count INTEGER NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at    TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS ping_results (
    id           BIGSERIAL PRIMARY KEY,  -- monotonic; doubles as the SSE stream cursor
    job_id       UUID NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
    ip           TEXT NOT NULL,
    status       TEXT NOT NULL,          -- alive | dead
    latency_ms   DOUBLE PRECISION,       -- icmp rtt
    error        TEXT,
    platform     TEXT,                   -- derived from classification, for SQL filtering
    confidence   REAL,
    hostname     TEXT,
    document     JSONB,                  -- full scan_ip() fingerprint document
    completed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Idempotent column adds for deployments created before the fingerprint columns existed.
ALTER TABLE ping_results ADD COLUMN IF NOT EXISTS platform   TEXT;
ALTER TABLE ping_results ADD COLUMN IF NOT EXISTS confidence REAL;
ALTER TABLE ping_results ADD COLUMN IF NOT EXISTS hostname   TEXT;
ALTER TABLE ping_results ADD COLUMN IF NOT EXISTS document   JSONB;

-- Cursor reads in the stream/snapshot endpoints: WHERE job_id = $1 AND id > $cursor ORDER BY id
CREATE INDEX IF NOT EXISTS idx_ping_results_job_cursor ON ping_results (job_id, id);

-- Idempotent persistence: a requeued/retried batch must not duplicate results.
-- Doubles as the arbiter for INSERT ... ON CONFLICT (job_id, ip) DO NOTHING.
-- NOTE: if ping_results already contains duplicate (job_id, ip) rows from earlier
-- testing, this will fail to build — TRUNCATE ping_results first.
CREATE UNIQUE INDEX IF NOT EXISTS uq_ping_results_job_ip ON ping_results (job_id, ip);
