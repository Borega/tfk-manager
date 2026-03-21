from datetime import datetime, timezone
import unittest

from server.app.collector.corrections import apply_late_corrections


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


if __name__ == "__main__":
    unittest.main()
