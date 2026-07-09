from datetime import datetime, timedelta, timezone
from typing import Any


def _to_utc_iso(timestamp: datetime) -> str:
    return timestamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_iso(timestamp: str) -> datetime:
    return datetime.fromisoformat(timestamp.replace("Z", "+00:00")).astimezone(timezone.utc)


def _bucket_start(timestamp: datetime, bucket_grain: str) -> str:
    if bucket_grain == "fine":
        return _to_utc_iso(timestamp.replace(minute=0, second=0, microsecond=0))
    return _to_utc_iso(timestamp.replace(hour=0, minute=0, second=0, microsecond=0))


def _bucket_step(bucket_grain: str) -> timedelta:
    if bucket_grain == "fine":
        return timedelta(hours=1)
    return timedelta(days=1)


def _bucket_starts(window_start: str, window_end: str, bucket_grain: str) -> list[str]:
    current = _parse_iso(_bucket_start(_parse_iso(window_start), bucket_grain))
    final = _parse_iso(_bucket_start(_parse_iso(window_end), bucket_grain))
    step = _bucket_step(bucket_grain)

    buckets: list[str] = []
    while current <= final:
        buckets.append(_to_utc_iso(current))
        current += step
    return buckets


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


def _event_rows_for_touched_buckets(
    connection: Any,
    touched_buckets: dict[tuple[str | None, str], set[str]],
) -> list[tuple[str, str]]:
    all_bucket_starts = [
        _parse_iso(bucket_start)
        for (_, _grain), bucket_starts in touched_buckets.items()
        for bucket_start in bucket_starts
    ]
    if not all_bucket_starts:
        return []

    min_start = min(all_bucket_starts)
    max_exclusive_end = max(
        bucket_start + _bucket_step(grain)
        for (_source_type, grain), bucket_starts in touched_buckets.items()
        for bucket_start in (_parse_iso(value) for value in bucket_starts)
    )

    return connection.execute(
        """
        SELECT source_type, occurred_at
        FROM canonical_events
        WHERE occurred_at >= ?
          AND occurred_at < ?
        """,
        (_to_utc_iso(min_start), _to_utc_iso(max_exclusive_end)),
    ).fetchall()


def recompute_aggregate_windows(
    connection: Any,
    windows: list[dict[str, Any]],
) -> dict[str, int]:
    if not windows:
        return {"windowsProcessed": 0, "rowsWritten": 0}

    updated_at = _to_utc_iso(datetime.now(timezone.utc))
    cursor = connection.cursor()

    touched_buckets: dict[tuple[str | None, str], set[str]] = {}
    for window in windows:
        source_type = window.get("sourceType")
        for grain in ("fine", "coarse"):
            touched_buckets.setdefault((source_type, grain), set()).update(
                _bucket_starts(window["windowStart"], window["windowEnd"], grain)
            )

    try:
        cursor.execute("BEGIN")
        _ensure_aggregate_schema(connection)

        targeted_delete_params: list[tuple[str, str, str]] = []
        all_source_delete_params: list[tuple[str, str]] = []
        for (source_type, grain), bucket_starts in touched_buckets.items():
            for bucket_start in sorted(bucket_starts):
                if source_type:
                    targeted_delete_params.append((str(source_type), grain, bucket_start))
                else:
                    all_source_delete_params.append((grain, bucket_start))

        if targeted_delete_params:
            cursor.executemany(
                """
                DELETE FROM trend_aggregate
                WHERE source_type = ?
                  AND bucket_grain = ?
                  AND bucket_start = ?
                """,
                targeted_delete_params,
            )

        if all_source_delete_params:
            cursor.executemany(
                """
                DELETE FROM trend_aggregate
                WHERE bucket_grain = ?
                  AND bucket_start = ?
                """,
                all_source_delete_params,
            )

        counts: dict[tuple[str, str, str], int] = {}
        for row_source_type, occurred_at in _event_rows_for_touched_buckets(
            connection,
            touched_buckets,
        ):
            parsed = _parse_iso(occurred_at)
            for grain in ("fine", "coarse"):
                bucket_start = _bucket_start(parsed, grain)
                if (
                    bucket_start in touched_buckets.get((row_source_type, grain), set())
                    or bucket_start in touched_buckets.get((None, grain), set())
                ):
                    key = (bucket_start, grain, row_source_type)
                    counts[key] = counts.get(key, 0) + 1

        insert_params = [
            (bucket_start, bucket_grain, row_source_type, event_count, updated_at)
            for (bucket_start, bucket_grain, row_source_type), event_count in sorted(
                counts.items()
            )
        ]
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

        connection.commit()
    except Exception:
        connection.rollback()
        raise

    return {"windowsProcessed": len(windows), "rowsWritten": len(insert_params)}
