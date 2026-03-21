from __future__ import annotations

import sqlite3

from server.app.api.authz_policy import authorize_request
from server.app.api.query_contracts import EventsQuery, TrendsQuery


def _enforce_authorization(role: str, endpoint: str, method: str) -> None:
    allowed, reason = authorize_request(role, endpoint, method)
    if not allowed:
        raise PermissionError(reason)


def get_historical_events(
    query: EventsQuery,
    role: str,
    connection: sqlite3.Connection,
) -> dict[str, object]:
    _enforce_authorization(role, "/api/history/events", "GET")

    filters: list[str] = ["occurred_at >= ?", "occurred_at <= ?"]
    params: list[object] = [query.startAt, query.endAt]

    if query.sourceType:
        filters.append("source_type = ?")
        params.append(query.sourceType)

    if query.cursor:
        filters.append("event_id > ?")
        params.append(query.cursor)

    limit = min(query.limit, 500)
    params.append(limit)

    rows = connection.execute(
        f"""
        SELECT event_id, source_type, source_entity_id, occurred_at, observed_at,
               payload_hash, lineage_version, confidence_state, raw_payload_json
        FROM canonical_events
        WHERE {' AND '.join(filters)}
        ORDER BY event_id ASC
        LIMIT ?
        """,
        tuple(params),
    ).fetchall()

    items: list[dict[str, object]] = []
    for row in rows:
        items.append(
            {
                "eventId": row[0],
                "sourceType": row[1],
                "sourceEntityId": row[2],
                "occurredAt": row[3],
                "observedAt": row[4],
                "payloadHash": row[5],
                "lineageVersion": row[6],
                "confidenceState": row[7],
                "rawPayloadJson": row[8],
            }
        )

    next_cursor = items[-1]["eventId"] if len(items) == limit and items else None
    return {
        "items": items,
        "nextCursor": next_cursor,
        "count": len(items),
    }


def get_historical_trends(
    query: TrendsQuery,
    role: str,
    connection: sqlite3.Connection,
) -> dict[str, object]:
    _enforce_authorization(role, "/api/history/trends", "GET")

    filters: list[str] = ["bucket_start >= ?", "bucket_start <= ?", "bucket_grain = ?"]
    params: list[object] = [query.startAt, query.endAt, query.bucketGrain]

    if query.sourceType:
        filters.append("source_type = ?")
        params.append(query.sourceType)

    rows = connection.execute(
        f"""
        SELECT bucket_start, bucket_grain, source_type, event_count, updated_at
        FROM trend_aggregate
        WHERE {' AND '.join(filters)}
        ORDER BY bucket_start ASC, source_type ASC
        """,
        tuple(params),
    ).fetchall()

    items = [
        {
            "bucketStart": row[0],
            "bucketGrain": row[1],
            "sourceType": row[2],
            "eventCount": row[3],
            "updatedAt": row[4],
        }
        for row in rows
    ]

    return {
        "items": items,
        "count": len(items),
    }
