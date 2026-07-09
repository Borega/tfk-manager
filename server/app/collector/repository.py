import sqlite3
from typing import Any, Iterable

from server.app.collector.contracts import CanonicalEvent, CheckpointState


def ensure_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS canonical_events (
            event_id TEXT PRIMARY KEY,
            source_type TEXT NOT NULL,
            source_entity_id TEXT NOT NULL,
            source_identifiers_json TEXT NOT NULL,
            occurred_at TEXT NOT NULL,
            observed_at TEXT NOT NULL,
            collector_version TEXT NOT NULL,
            ingest_timestamp TEXT NOT NULL,
            payload_hash TEXT NOT NULL,
            lineage_version INTEGER NOT NULL,
            confidence_state TEXT NOT NULL,
            raw_payload_json TEXT NOT NULL,
            UNIQUE(event_id)
        );

        CREATE INDEX IF NOT EXISTS idx_canonical_events_source_type_occurred_at
            ON canonical_events(source_type, occurred_at);

        CREATE TABLE IF NOT EXISTS ingestion_checkpoints (
            source_key TEXT PRIMARY KEY,
            cursor TEXT NOT NULL,
            last_success_at TEXT,
            last_error_at TEXT,
            error_count INTEGER NOT NULL,
            lag_seconds INTEGER NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS proxy_operation_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id TEXT NOT NULL,
            actor_id TEXT NOT NULL,
            actor_role TEXT NOT NULL,
            scope TEXT NOT NULL,
            operation TEXT NOT NULL,
            target TEXT NOT NULL,
            status TEXT NOT NULL,
            error_code TEXT,
            details_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_proxy_operation_audit_request_id
            ON proxy_operation_audit(request_id);

        CREATE INDEX IF NOT EXISTS idx_proxy_operation_audit_created_at
            ON proxy_operation_audit(created_at DESC);
        """
    )


def _event_record(event: CanonicalEvent | dict[str, Any]) -> dict[str, Any]:
    if isinstance(event, CanonicalEvent):
        return event.to_record()
    if isinstance(event, dict):
        return {
            "event_id": event["eventId"],
            "source_type": event["sourceType"],
            "source_entity_id": event["sourceEntityId"],
            "source_identifiers_json": event.get("sourceIdentifiersJson", "{}"),
            "occurred_at": event["occurredAt"],
            "observed_at": event["observedAt"],
            "collector_version": event.get("collectorVersion", "unknown"),
            "ingest_timestamp": event.get("ingestTimestamp", event["observedAt"]),
            "payload_hash": event["payloadHash"],
            "lineage_version": event["lineageVersion"],
            "confidence_state": event["confidenceState"],
            "raw_payload_json": event["rawPayloadJson"],
        }
    raise TypeError("event must be CanonicalEvent or dict")


def _checkpoint_record(checkpoint_state: CheckpointState | dict[str, Any]) -> dict[str, Any]:
    if isinstance(checkpoint_state, CheckpointState):
        return checkpoint_state.to_record()
    if isinstance(checkpoint_state, dict):
        return {
            "source_key": checkpoint_state["sourceKey"],
            "cursor": checkpoint_state["cursor"],
            "last_success_at": checkpoint_state.get("lastSuccessAt"),
            "last_error_at": checkpoint_state.get("lastErrorAt"),
            "error_count": checkpoint_state["errorCount"],
            "lag_seconds": checkpoint_state["lagSeconds"],
            "updated_at": checkpoint_state["updatedAt"],
        }
    raise TypeError("checkpoint_state must be CheckpointState or dict")


def upsert_events_and_checkpoint(
    connection: sqlite3.Connection,
    events: Iterable[CanonicalEvent | dict[str, Any]],
    checkpoint_state: CheckpointState | dict[str, Any],
    fail_on_event_id: str | None = None,
) -> int:
    inserted_rows = 0
    checkpoint = _checkpoint_record(checkpoint_state)

    cursor = connection.cursor()
    try:
        cursor.execute("BEGIN")
        records = []
        for event in events:
            record = _event_record(event)
            if fail_on_event_id and record["event_id"] == fail_on_event_id:
                raise RuntimeError("simulated write failure")
            records.append((
                record["event_id"],
                record["source_type"],
                record["source_entity_id"],
                record["source_identifiers_json"],
                record["occurred_at"],
                record["observed_at"],
                record["collector_version"],
                record["ingest_timestamp"],
                record["payload_hash"],
                record["lineage_version"],
                record["confidence_state"],
                record["raw_payload_json"],
            ))

        cursor.executemany(
            """
            INSERT INTO canonical_events (
                event_id,
                source_type,
                source_entity_id,
                source_identifiers_json,
                occurred_at,
                observed_at,
                collector_version,
                ingest_timestamp,
                payload_hash,
                lineage_version,
                confidence_state,
                raw_payload_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(event_id) DO UPDATE SET
                source_type=excluded.source_type,
                source_entity_id=excluded.source_entity_id,
                source_identifiers_json=excluded.source_identifiers_json,
                occurred_at=excluded.occurred_at,
                observed_at=excluded.observed_at,
                collector_version=excluded.collector_version,
                ingest_timestamp=excluded.ingest_timestamp,
                payload_hash=excluded.payload_hash,
                lineage_version=excluded.lineage_version,
                confidence_state=excluded.confidence_state,
                raw_payload_json=excluded.raw_payload_json
            """,
            records,
        )

        cursor.execute(
            """
            INSERT INTO ingestion_checkpoints (
                source_key,
                cursor,
                last_success_at,
                last_error_at,
                error_count,
                lag_seconds,
                updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(source_key) DO UPDATE SET
                cursor=excluded.cursor,
                last_success_at=excluded.last_success_at,
                last_error_at=excluded.last_error_at,
                error_count=excluded.error_count,
                lag_seconds=excluded.lag_seconds,
                updated_at=excluded.updated_at
            """,
            (
                checkpoint["source_key"],
                checkpoint["cursor"],
                checkpoint["last_success_at"],
                checkpoint["last_error_at"],
                checkpoint["error_count"],
                checkpoint["lag_seconds"],
                checkpoint["updated_at"],
            ),
        )

        connection.commit()
    except Exception:
        connection.rollback()
        raise

    inserted_rows = cursor.execute("SELECT COUNT(*) FROM canonical_events").fetchone()[0]
    return inserted_rows


def count_canonical_events(connection: sqlite3.Connection) -> int:
    return connection.execute("SELECT COUNT(*) FROM canonical_events").fetchone()[0]


def get_checkpoint_cursor(connection: sqlite3.Connection, source_key: str) -> str | None:
    row = connection.execute(
        "SELECT cursor FROM ingestion_checkpoints WHERE source_key = ?",
        (source_key,),
    ).fetchone()
    return row[0] if row else None


def write_proxy_operation_audit(
    connection: sqlite3.Connection,
    *,
    request_id: str,
    actor_id: str,
    actor_role: str,
    scope: str,
    operation: str,
    target: str,
    status: str,
    error_code: str | None,
    details_json: str,
    created_at: str,
) -> None:
    connection.execute(
        """
        INSERT INTO proxy_operation_audit (
            request_id,
            actor_id,
            actor_role,
            scope,
            operation,
            target,
            status,
            error_code,
            details_json,
            created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            request_id,
            actor_id,
            actor_role,
            scope,
            operation,
            target,
            status,
            error_code,
            details_json,
            created_at,
        ),
    )


def get_proxy_operation_audit_by_request_id(connection: sqlite3.Connection, request_id: str) -> dict[str, Any] | None:
    row = connection.execute(
        """
        SELECT request_id, actor_id, actor_role, scope, operation, target, status, error_code, details_json, created_at
        FROM proxy_operation_audit
        WHERE request_id = ?
        ORDER BY id DESC
        LIMIT 1
        """,
        (request_id,),
    ).fetchone()

    if row is None:
        return None

    return {
        "requestId": row[0],
        "actorId": row[1],
        "actorRole": row[2],
        "scope": row[3],
        "operation": row[4],
        "target": row[5],
        "status": row[6],
        "errorCode": row[7],
        "details": row[8],
        "createdAt": row[9],
    }
