-- Phase 2 retention lifecycle migration
-- Auditable retention run metadata for canonical TTL operations

CREATE TABLE IF NOT EXISTS retention_runs (
    run_id UUID PRIMARY KEY,
    cutoff_at TIMESTAMPTZ NOT NULL,
    deleted_count INTEGER NOT NULL,
    affected_windows_json JSONB NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_retention_runs_completed_at
    ON retention_runs(completed_at DESC);

CREATE INDEX IF NOT EXISTS idx_retention_runs_status
    ON retention_runs(status);
