from datetime import datetime, timezone
from typing import Any


def _to_utc_iso(timestamp: datetime) -> str:
    return timestamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_iso(timestamp: str) -> datetime:
    return datetime.fromisoformat(timestamp.replace("Z", "+00:00")).astimezone(
        timezone.utc
    )


def _bucket_start(timestamp: datetime, bucket_grain: str) -> str:
    if bucket_grain == "fine":
        return _to_utc_iso(timestamp.replace(minute=0, second=0, microsecond=0))
    return _to_utc_iso(timestamp.replace(hour=0, minute=0, second=0, microsecond=0))


def _ensure_aggregate_schema(connection: Any) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS trend_aggregate (
            bucket_start TEXT NOT NULL,
            bucket_grain TEXT NOT NULL,
            source_type TEXT NOT NULL,
            event_count INTEGER NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (bucket_start, bucket_grain, source_type)
        )
        """
    )


def _window_rows(connection: Any, window: dict[str, Any]) -> list[tuple[str, str]]:
    source_type = window.get("sourceType")
    if source_type:
        return connection.execute(
            """
            SELECT source_type, occurred_at
            FROM canonical_events
            WHERE source_type = ?
              AND occurred_at >= ?
              AND occurred_at <= ?
            """,
            (source_type, window["windowStart"], window["windowEnd"]),
        ).fetchall()

    return connection.execute(
        """
        SELECT source_type, occurred_at
        FROM canonical_events
        WHERE occurred_at >= ?
          AND occurred_at <= ?
        """,
        (window["windowStart"], window["windowEnd"]),
    ).fetchall()


def recompute_aggregate_windows(
    connection: Any, windows: list[dict[str, Any]]
) -> dict[str, int]:
    if not windows:
        return {"windowsProcessed": 0, "rowsWritten": 0}

    rows_written = 0
    updated_at = _to_utc_iso(datetime.now(timezone.utc))
    cursor = connection.cursor()

    try:
        cursor.execute("BEGIN")
        _ensure_aggregate_schema(connection)

        fine_deletes = []
        coarse_deletes = []
        insert_params = []

        for window in windows:
            source_type = window.get("sourceType")
            fine_start = _bucket_start(_parse_iso(window["windowStart"]), "fine")
            fine_end = _bucket_start(_parse_iso(window["windowEnd"]), "fine")
            coarse_start = _bucket_start(_parse_iso(window["windowStart"]), "coarse")
            coarse_end = _bucket_start(_parse_iso(window["windowEnd"]), "coarse")

            if source_type:
                fine_deletes.append((source_type, fine_start, fine_end))
                coarse_deletes.append((source_type, coarse_start, coarse_end))

            counts: dict[tuple[str, str, str], int] = {}
            for row_source_type, occurred_at in _window_rows(connection, window):
                parsed = _parse_iso(occurred_at)
                for grain in ("fine", "coarse"):
                    key = (_bucket_start(parsed, grain), grain, row_source_type)
                    counts[key] = counts.get(key, 0) + 1

            for (bucket_start, bucket_grain, row_source_type), event_count in sorted(
                counts.items()
            ):
                insert_params.append(
                    (
                        bucket_start,
                        bucket_grain,
                        row_source_type,
                        event_count,
                        updated_at,
                    )
                )

        if fine_deletes:
            cursor.executemany(
                """
                DELETE FROM trend_aggregate
                WHERE source_type = ?
                  AND bucket_grain = 'fine'
                  AND bucket_start >= ?
                  AND bucket_start <= ?
                """,
                fine_deletes,
            )

        if coarse_deletes:
            cursor.executemany(
                """
                DELETE FROM trend_aggregate
                WHERE source_type = ?
                  AND bucket_grain = 'coarse'
                  AND bucket_start >= ?
                  AND bucket_start <= ?
                """,
                coarse_deletes,
            )

        if insert_params:
            cursor.executemany(
                """
                INSERT INTO trend_aggregate (
                    bucket_start,
                    bucket_grain,
                    source_type,
                    event_count,
                    updated_at
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(bucket_start, bucket_grain, source_type)
                DO UPDATE SET
                    event_count = excluded.event_count,
                    updated_at = excluded.updated_at
                """,
                insert_params,
            )
            rows_written += len(insert_params)

        connection.commit()
    except Exception:
        connection.rollback()
        raise

    return {"windowsProcessed": len(windows), "rowsWritten": rows_written}
