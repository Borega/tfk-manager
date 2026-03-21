import sqlite3
import unittest

from server.app.collector.aggregates import recompute_aggregate_windows
from server.app.collector.repository import ensure_schema, upsert_events_and_checkpoint


class TestAggregates(unittest.TestCase):
    def setUp(self):
        self.connection = sqlite3.connect(":memory:")
        ensure_schema(self.connection)

    def tearDown(self):
        self.connection.close()

    def _event(self, event_id: str, occurred_at: str) -> dict[str, str | int]:
        return {
            "eventId": event_id,
            "sourceType": "webfilter",
            "sourceEntityId": "student-1",
            "sourceIdentifiersJson": '{"user":"student-1"}',
            "occurredAt": occurred_at,
            "observedAt": occurred_at,
            "collectorVersion": "collector-2.0.0",
            "ingestTimestamp": occurred_at,
            "payloadHash": event_id,
            "lineageVersion": 1,
            "confidenceState": "Healthy",
            "rawPayloadJson": "{}",
        }

    def _checkpoint(self) -> dict[str, str | int | None]:
        return {
            "sourceKey": "webfilter",
            "cursor": "wf-1",
            "lastSuccessAt": "2026-03-21T08:30:00Z",
            "lastErrorAt": None,
            "errorCount": 0,
            "lagSeconds": 1,
            "updatedAt": "2026-03-21T08:30:00Z",
        }

    def test_recompute_windows_create_fine_and_coarse_buckets(self):
        upsert_events_and_checkpoint(
            self.connection,
            [
                self._event("evt-1", "2026-03-21T08:10:00Z"),
                self._event("evt-2", "2026-03-21T09:15:00Z"),
            ],
            self._checkpoint(),
        )

        corrected_windows = [
            {
                "sourceType": "webfilter",
                "windowStart": "2026-03-21T08:00:00Z",
                "windowEnd": "2026-03-21T10:00:00Z",
                "annotation": "corrected",
            }
        ]
        summary = recompute_aggregate_windows(self.connection, corrected_windows)

        self.assertEqual(summary["windowsProcessed"], 1)
        rows = self.connection.execute(
            "SELECT bucket_grain, bucket_start, event_count FROM trend_aggregate ORDER BY bucket_grain, bucket_start"
        ).fetchall()

        fine_rows = [row for row in rows if row[0] == "fine"]
        coarse_rows = [row for row in rows if row[0] == "coarse"]
        self.assertGreaterEqual(len(fine_rows), 2)
        self.assertEqual(len(coarse_rows), 1)
        self.assertEqual(coarse_rows[0][2], 2)

    def test_recompute_windows_is_deterministic_for_same_input(self):
        upsert_events_and_checkpoint(
            self.connection,
            [
                self._event("evt-1", "2026-03-21T08:10:00Z"),
                self._event("evt-2", "2026-03-21T09:15:00Z"),
            ],
            self._checkpoint(),
        )

        corrected_windows = [
            {
                "sourceType": "webfilter",
                "windowStart": "2026-03-21T08:00:00Z",
                "windowEnd": "2026-03-21T10:00:00Z",
                "annotation": "corrected",
            }
        ]
        recompute_aggregate_windows(self.connection, corrected_windows)
        first_snapshot = self.connection.execute(
            "SELECT bucket_start, bucket_grain, source_type, event_count FROM trend_aggregate ORDER BY bucket_start, bucket_grain, source_type"
        ).fetchall()

        recompute_aggregate_windows(self.connection, corrected_windows)
        second_snapshot = self.connection.execute(
            "SELECT bucket_start, bucket_grain, source_type, event_count FROM trend_aggregate ORDER BY bucket_start, bucket_grain, source_type"
        ).fetchall()

        self.assertEqual(first_snapshot, second_snapshot)


if __name__ == "__main__":
    unittest.main()
