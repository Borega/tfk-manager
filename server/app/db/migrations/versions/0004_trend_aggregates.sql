-- Phase 2 trend aggregate migration
-- Aggregate-backed query windows for canonical telemetry trends

CREATE TABLE IF NOT EXISTS trend_aggregate (
    bucket_start TIMESTAMPTZ NOT NULL,
    bucket_grain TEXT NOT NULL,
    source_type TEXT NOT NULL,
    event_count INTEGER NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (bucket_start, bucket_grain, source_type)
);

CREATE INDEX IF NOT EXISTS idx_trend_aggregate_source_grain_start
    ON trend_aggregate(source_type, bucket_grain, bucket_start DESC);
