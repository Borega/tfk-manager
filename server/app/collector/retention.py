import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any


def _to_utc_iso(timestamp: datetime) -> str:
    return timestamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _ensure_retention_schema(connection: Any) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS retention_runs (
            run_id TEXT PRIMARY KEY,
            cutoff_at TEXT NOT NULL,
            deleted_count INTEGER NOT NULL,
            affected_windows_json TEXT NOT NULL,
            started_at TEXT NOT NULL,
            completed_at TEXT NOT NULL,
            status TEXT NOT NULL
        )
        """
    )


def run_retention_cycle(connection: Any, now_utc: datetime) -> dict[str, Any]:
    if now_utc.tzinfo is None:
        now_utc = now_utc.replace(tzinfo=timezone.utc)

    cutoff_at = now_utc - timedelta(days=365)
    run_id = str(uuid.uuid4())
    started_at = now_utc
    completed_at = now_utc

    cutoff_iso = _to_utc_iso(cutoff_at)
    started_iso = _to_utc_iso(started_at)
    completed_iso = _to_utc_iso(completed_at)

    cursor = connection.cursor()
    try:
        cursor.execute("BEGIN")
        _ensure_retention_schema(connection)

        affected_windows = [
            row[0]
            for row in cursor.execute(
                """
                SELECT DISTINCT substr(occurred_at, 1, 7) AS event_window
                FROM canonical_events
                WHERE occurred_at < ?
                ORDER BY event_window
                """,
                (cutoff_iso,),
            ).fetchall()
        ]

        cursor.execute("DELETE FROM canonical_events WHERE occurred_at < ?", (cutoff_iso,))
        deleted_count = max(cursor.rowcount, 0)

        cursor.execute(
            """
            INSERT INTO retention_runs (
                run_id,
                cutoff_at,
                deleted_count,
                affected_windows_json,
                started_at,
                completed_at,
                status
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                cutoff_iso,
                deleted_count,
                json.dumps(affected_windows),
                started_iso,
                completed_iso,
                "completed",
            ),
        )

        connection.commit()
    except Exception:
        connection.rollback()
        raise

    return {
        "runId": run_id,
        "cutoffAt": cutoff_iso,
        "deletedCount": deleted_count,
        "affectedWindows": affected_windows,
        "startedAt": started_iso,
        "completedAt": completed_iso,
        "runStatus": "completed",
    }
