-- Phase 2 canonical backbone migration
-- PostgreSQL partitioned canonical events storage by occurred_at month

CREATE TABLE IF NOT EXISTS canonical_events (
    event_id TEXT NOT NULL,
    source_type TEXT NOT NULL,
    source_entity_id TEXT NOT NULL,
    source_identifiers_json JSONB NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    collector_version TEXT NOT NULL,
    ingest_timestamp TIMESTAMPTZ NOT NULL,
    payload_hash TEXT NOT NULL,
    lineage_version INTEGER NOT NULL,
    confidence_state TEXT NOT NULL,
    raw_payload_json JSONB NOT NULL,
    PRIMARY KEY (event_id, occurred_at)
) PARTITION BY RANGE (occurred_at);

CREATE TABLE IF NOT EXISTS canonical_events_2026_01
    PARTITION OF canonical_events
    FOR VALUES FROM ('2026-01-01T00:00:00Z') TO ('2026-02-01T00:00:00Z');

CREATE TABLE IF NOT EXISTS canonical_events_2026_02
    PARTITION OF canonical_events
    FOR VALUES FROM ('2026-02-01T00:00:00Z') TO ('2026-03-01T00:00:00Z');

CREATE TABLE IF NOT EXISTS canonical_events_2026_03
    PARTITION OF canonical_events
    FOR VALUES FROM ('2026-03-01T00:00:00Z') TO ('2026-04-01T00:00:00Z');

CREATE UNIQUE INDEX IF NOT EXISTS idx_canonical_events_event_id
    ON canonical_events(event_id);

CREATE INDEX IF NOT EXISTS idx_canonical_events_source_type_occurred_at
    ON canonical_events(source_type, occurred_at DESC);

CREATE INDEX IF NOT EXISTS idx_canonical_events_payload_hash
    ON canonical_events(payload_hash);
