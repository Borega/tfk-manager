from datetime import datetime, timezone
import sqlite3
import unittest
from unittest.mock import patch

from server.app.collector.corrections import apply_late_corrections
from server.app.collector.repository import ensure_schema
from server.app.collector.workers.worker_runner import create_worker_state, run_worker_iteration


class TestCorrections(unittest.TestCase):
    def test_late_correction_marks_window_annotation(self):
        events = [
            {
                "eventId": "evt-1",
                "sourceType": "webfilter",
                "sourceEntityId": "student",
                "occurredAt": "2026-03-21T08:12:00Z",
                "observedAt": "2026-03-21T08:12:01Z",
                "payloadHash": "hash-1",
                "lineageVersion": 1,
                "confidenceState": "Healthy",
                "rawPayloadJson": "{\"url\":\"a\"}",
            },
            {
                "eventId": "evt-1",
                "sourceType": "webfilter",
                "sourceEntityId": "student",
                "occurredAt": "2026-03-21T08:12:00Z",
                "observedAt": "2026-03-21T08:13:01Z",
                "payloadHash": "hash-2",
                "lineageVersion": 1,
                "confidenceState": "Healthy",
                "rawPayloadJson": "{\"url\":\"b\"}",
            },
        ]
        result = apply_late_corrections(events, datetime(2026, 3, 21, 9, 0, 0, tzinfo=timezone.utc))

        self.assertEqual(len(result["events"]), 1)
        self.assertEqual(result["events"][0]["eventId"], "evt-1")
        self.assertEqual(result["events"][0]["lineageVersion"], 2)
        self.assertGreaterEqual(len(result["correctedWindows"]), 1)
        self.assertEqual(result["correctedWindows"][0]["annotation"], "corrected")

    def test_worker_iteration_recomputes_only_targeted_corrected_windows(self):
        connection = sqlite3.connect(":memory:")
        ensure_schema(connection)
        now_utc = datetime(2026, 3, 21, 9, 0, 0, tzinfo=timezone.utc)

        def _adapter_fetch(cursor, now):
            _ = cursor
            _ = now
            return [
                {
                    "eventId": "evt-1",
                    "sourceType": "webfilter",
                    "sourceEntityId": "student",
                    "occurredAt": "2026-03-21T08:12:00Z",
                    "observedAt": "2026-03-21T08:12:01Z",
                    "payloadHash": "hash-1",
                    "lineageVersion": 1,
                    "confidenceState": "Healthy",
                    "rawPayloadJson": "{\"url\":\"a\"}",
                },
                {
                    "eventId": "evt-1",
                    "sourceType": "webfilter",
                    "sourceEntityId": "student",
                    "occurredAt": "2026-03-21T08:12:00Z",
                    "observedAt": "2026-03-21T08:13:01Z",
                    "payloadHash": "hash-2",
                    "lineageVersion": 1,
                    "confidenceState": "Healthy",
                    "rawPayloadJson": "{\"url\":\"b\"}",
                },
            ], "cursor-2"

        state = create_worker_state("webfilter")

        with patch("server.app.collector.workers.worker_runner.recompute_aggregate_windows") as recompute:
            run_worker_iteration("webfilter", state, _adapter_fetch, connection, now_utc)
            recompute.assert_called_once()
            windows = recompute.call_args.args[1]
            self.assertEqual(len(windows), 1)
            self.assertEqual(windows[0]["annotation"], "corrected")

        connection.close()

    def test_worker_iteration_skips_recompute_when_no_corrected_windows(self):
        connection = sqlite3.connect(":memory:")
        ensure_schema(connection)
        now_utc = datetime(2026, 3, 21, 9, 0, 0, tzinfo=timezone.utc)

        def _adapter_fetch(cursor, now):
            _ = cursor
            _ = now
            return [
                {
                    "eventId": "evt-1",
                    "sourceType": "webfilter",
                    "sourceEntityId": "student",
                    "occurredAt": "2026-03-21T08:12:00Z",
                    "observedAt": "2026-03-21T08:12:01Z",
                    "payloadHash": "hash-1",
                    "lineageVersion": 1,
                    "confidenceState": "Healthy",
                    "rawPayloadJson": "{\"url\":\"a\"}",
                }
            ], "cursor-3"

        state = create_worker_state("webfilter")

        with patch("server.app.collector.workers.worker_runner.recompute_aggregate_windows") as recompute:
            run_worker_iteration("webfilter", state, _adapter_fetch, connection, now_utc)
            recompute.assert_not_called()

        connection.close()


if __name__ == "__main__":
    unittest.main()
