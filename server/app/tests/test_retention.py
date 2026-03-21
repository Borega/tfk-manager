import json
import sqlite3
import unittest
from datetime import datetime, timezone

from server.app.collector.repository import ensure_schema, upsert_events_and_checkpoint
from server.app.collector.retention import run_retention_cycle


class TestRetention(unittest.TestCase):
    def setUp(self):
        self.connection = sqlite3.connect(":memory:")
        ensure_schema(self.connection)

    def tearDown(self):
        self.connection.close()

    def _event(self, event_id: str, occurred_at: str) -> dict[str, str | int]:
        return {
            "eventId": event_id,
            "sourceType": "dhcp",
            "sourceEntityId": "lease-1",
            "sourceIdentifiersJson": '{"mac":"aa:bb:cc:dd:ee:ff"}',
            "occurredAt": occurred_at,
            "observedAt": "2026-03-21T08:00:01Z",
            "collectorVersion": "collector-2.0.0",
            "ingestTimestamp": "2026-03-21T08:00:02Z",
            "payloadHash": "hash-1",
            "lineageVersion": 1,
            "confidenceState": "Healthy",
            "rawPayloadJson": "{}",
        }

    def _checkpoint(self, cursor: str) -> dict[str, str | int | None]:
        return {
            "sourceKey": "dhcp",
            "cursor": cursor,
            "lastSuccessAt": "2026-03-21T08:00:01Z",
            "lastErrorAt": None,
            "errorCount": 0,
            "lagSeconds": 1,
            "updatedAt": "2026-03-21T08:00:01Z",
        }

    def test_run_retention_cycle_deletes_data_older_than_one_year(self):
        upsert_events_and_checkpoint(
            self.connection,
            [
                self._event("evt-old", "2024-03-20T00:00:00Z"),
                self._event("evt-recent", "2026-03-20T00:00:00Z"),
            ],
            self._checkpoint("c-1"),
        )

        summary = run_retention_cycle(
            self.connection,
            datetime(2026, 3, 21, 0, 0, 0, tzinfo=timezone.utc),
        )

        self.assertEqual(summary["cutoffAt"], "2025-03-21T00:00:00Z")
        self.assertEqual(summary["deletedCount"], 1)
        self.assertEqual(summary["affectedWindows"], ["2024-03"])
        self.assertEqual(summary["completedAt"], "2026-03-21T00:00:00Z")

        remaining = self.connection.execute("SELECT event_id FROM canonical_events").fetchall()
        self.assertEqual(remaining, [("evt-recent",)])

    def test_run_retention_cycle_persists_audit_row(self):
        upsert_events_and_checkpoint(
            self.connection,
            [self._event("evt-old", "2024-03-20T00:00:00Z")],
            self._checkpoint("c-1"),
        )

        summary = run_retention_cycle(
            self.connection,
            datetime(2026, 3, 21, 0, 0, 0, tzinfo=timezone.utc),
        )

        row = self.connection.execute(
            """
            SELECT cutoff_at, deleted_count, affected_windows_json, status
            FROM retention_runs
            WHERE run_id = ?
            """,
            (summary["runId"],),
        ).fetchone()

        self.assertIsNotNone(row)
        self.assertEqual(row[0], "2025-03-21T00:00:00Z")
        self.assertEqual(row[1], 1)
        self.assertEqual(json.loads(row[2]), ["2024-03"])
        self.assertEqual(row[3], "completed")


if __name__ == "__main__":
    unittest.main()
