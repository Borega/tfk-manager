CREATE TABLE canonical_events (
    event_id TEXT PRIMARY KEY,
    source_type TEXT NOT NULL,
    source_entity_id TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    lineage_version INTEGER NOT NULL,
    confidence_state TEXT NOT NULL,
    raw_payload_json TEXT NOT NULL,
    UNIQUE(event_id)
);

CREATE INDEX idx_canonical_events_source_type_occurred_at
    ON canonical_events(source_type, occurred_at);

CREATE TABLE ingestion_checkpoints (
    source_key TEXT PRIMARY KEY,
    cursor TEXT NOT NULL,
    last_success_at TEXT,
    last_error_at TEXT,
    error_count INTEGER NOT NULL,
    lag_seconds INTEGER NOT NULL,
    updated_at TEXT NOT NULL
);
