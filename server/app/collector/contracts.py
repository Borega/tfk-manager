from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict


@dataclass(frozen=True)
class CanonicalEvent:
    eventId: str
    sourceType: str
    sourceEntityId: str
    occurredAt: datetime
    observedAt: datetime
    payloadHash: str
    lineageVersion: int
    confidenceState: str
    rawPayloadJson: str

    def to_record(self) -> Dict[str, Any]:
        return {
            "event_id": self.eventId,
            "source_type": self.sourceType,
            "source_entity_id": self.sourceEntityId,
            "occurred_at": self.occurredAt.isoformat(),
            "observed_at": self.observedAt.isoformat(),
            "payload_hash": self.payloadHash,
            "lineage_version": self.lineageVersion,
            "confidence_state": self.confidenceState,
            "raw_payload_json": self.rawPayloadJson,
        }


@dataclass(frozen=True)
class CheckpointState:
    sourceKey: str
    cursor: str
    lastSuccessAt: datetime | None
    lastErrorAt: datetime | None
    errorCount: int
    lagSeconds: int
    updatedAt: datetime

    def to_record(self) -> Dict[str, Any]:
        return {
            "source_key": self.sourceKey,
            "cursor": self.cursor,
            "last_success_at": self.lastSuccessAt.isoformat() if self.lastSuccessAt else None,
            "last_error_at": self.lastErrorAt.isoformat() if self.lastErrorAt else None,
            "error_count": self.errorCount,
            "lag_seconds": self.lagSeconds,
            "updated_at": self.updatedAt.isoformat(),
        }
