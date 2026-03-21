import sqlite3
import unittest

from server.app.api.query_api import get_historical_events, get_historical_trends
from server.app.api.query_contracts import EventsQuery, TrendsQuery
from server.app.collector.repository import ensure_schema


class TestQueryApi(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:")
        ensure_schema(self.connection)
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS trend_aggregate (
                bucket_start TEXT NOT NULL,
                bucket_grain TEXT NOT NULL,
                source_type TEXT NOT NULL,
                event_count INTEGER NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (bucket_start, bucket_grain, source_type)
            );
            """
        )

        self.connection.executemany(
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
            """,
            [
                (
                    "evt-1",
                    "firewall",
                    "rule-1",
                    "{}",
                    "2026-03-21T12:00:00Z",
                    "2026-03-21T12:00:01Z",
                    "collector-2.1.0",
                    "2026-03-21T12:00:02Z",
                    "hash-1",
                    1,
                    "Healthy",
                    "{}",
                ),
                (
                    "evt-2",
                    "firewall",
                    "rule-2",
                    "{}",
                    "2026-03-21T12:05:00Z",
                    "2026-03-21T12:05:01Z",
                    "collector-2.1.0",
                    "2026-03-21T12:05:02Z",
                    "hash-2",
                    1,
                    "Healthy",
                    "{}",
                ),
                (
                    "evt-3",
                    "firewall",
                    "rule-3",
                    "{}",
                    "2026-03-21T12:10:00Z",
                    "2026-03-21T12:10:01Z",
                    "collector-2.1.0",
                    "2026-03-21T12:10:02Z",
                    "hash-3",
                    1,
                    "Healthy",
                    "{}",
                ),
            ],
        )

        self.connection.executemany(
            """
            INSERT INTO trend_aggregate (
                bucket_start,
                bucket_grain,
                source_type,
                event_count,
                updated_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            [
                ("2026-03-21T12:00:00Z", "coarse", "firewall", 8, "2026-03-21T12:20:00Z"),
                ("2026-03-21T13:00:00Z", "coarse", "firewall", 5, "2026-03-21T13:20:00Z"),
            ],
        )
        self.connection.commit()

    def tearDown(self) -> None:
        self.connection.close()

    def test_role_deny_for_events_query(self) -> None:
        query = EventsQuery(
            startAt="2026-03-21T00:00:00Z",
            endAt="2026-03-21T23:59:59Z",
            sourceType="firewall",
            limit=2,
        )

        with self.assertRaises(PermissionError):
            get_historical_events(query=query, role="viewer", connection=self.connection)

    def test_cursor_continuation_for_events(self) -> None:
        first_query = EventsQuery(
            startAt="2026-03-21T00:00:00Z",
            endAt="2026-03-21T23:59:59Z",
            sourceType="firewall",
            limit=2,
        )
        first_page = get_historical_events(first_query, "analyst", self.connection)
        self.assertEqual(len(first_page["items"]), 2)
        self.assertEqual(first_page["nextCursor"], "evt-2")

        second_query = EventsQuery(
            startAt="2026-03-21T00:00:00Z",
            endAt="2026-03-21T23:59:59Z",
            sourceType="firewall",
            cursor=str(first_page["nextCursor"]),
            limit=2,
        )
        second_page = get_historical_events(second_query, "analyst", self.connection)
        self.assertEqual(len(second_page["items"]), 1)
        self.assertEqual(second_page["items"][0]["eventId"], "evt-3")
        self.assertIsNone(second_page["nextCursor"])

    def test_trend_response_contract(self) -> None:
        query = TrendsQuery(
            startAt="2026-03-21T00:00:00Z",
            endAt="2026-03-21T23:59:59Z",
            sourceType="firewall",
            bucketGrain="coarse",
        )

        result = get_historical_trends(query, "analyst", self.connection)
        self.assertEqual(result["count"], 2)
        self.assertEqual(result["items"][0]["bucketGrain"], "coarse")
        self.assertIn("bucketStart", result["items"][0])
        self.assertIn("sourceType", result["items"][0])


if __name__ == "__main__":
    unittest.main()
