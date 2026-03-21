from dataclasses import dataclass


CANONICAL_EVENTS_TABLE = "canonical_events"
INGESTION_CHECKPOINTS_TABLE = "ingestion_checkpoints"


@dataclass(frozen=True)
class CanonicalEventModel:
    __tablename__ = CANONICAL_EVENTS_TABLE
    event_id: str
    source_type: str
    source_entity_id: str
    occurred_at: str
    observed_at: str
    payload_hash: str
    lineage_version: int
    confidence_state: str
    raw_payload_json: str


@dataclass(frozen=True)
class IngestionCheckpointModel:
    __tablename__ = INGESTION_CHECKPOINTS_TABLE
    source_key: str
    cursor: str
    last_success_at: str | None
    last_error_at: str | None
    error_count: int
    lag_seconds: int
    updated_at: str


MODEL_CONSTRAINTS = {
    "canonical_events": {
        "primary_key": "event_id",
        "unique": ["event_id"],
    },
    "ingestion_checkpoints": {
        "primary_key": "source_key",
    },
}
