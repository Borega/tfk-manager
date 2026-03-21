import unittest
import sqlite3

from server.app.collector.repository import (
    count_canonical_events,
    ensure_schema,
    get_checkpoint_cursor,
    upsert_events_and_checkpoint,
)


class TestEventRepository(unittest.TestCase):
    def setUp(self):
        self.connection = sqlite3.connect(":memory:")
        ensure_schema(self.connection)

    def tearDown(self):
        self.connection.close()

    def _event(self, event_id: str):
        return {
            "eventId": event_id,
            "sourceType": "dhcp",
            "sourceEntityId": "lease-1",
            "occurredAt": "2026-03-21T08:00:00Z",
            "observedAt": "2026-03-21T08:00:01Z",
            "payloadHash": "abc123",
            "lineageVersion": 1,
            "confidenceState": "Healthy",
            "rawPayloadJson": "{}",
        }

    def _checkpoint(self, cursor: str):
        return {
            "sourceKey": "dhcp",
            "cursor": cursor,
            "lastSuccessAt": "2026-03-21T08:00:01Z",
            "lastErrorAt": None,
            "errorCount": 0,
            "lagSeconds": 1,
            "updatedAt": "2026-03-21T08:00:01Z",
        }

    def test_duplicate_event_id_does_not_increment_count(self):
        upsert_events_and_checkpoint(
            self.connection,
            [self._event("evt-1")],
            self._checkpoint("c-1"),
        )
        upsert_events_and_checkpoint(
            self.connection,
            [self._event("evt-1")],
            self._checkpoint("c-2"),
        )

        self.assertEqual(count_canonical_events(self.connection), 1)

    def test_failed_event_write_does_not_advance_checkpoint(self):
        upsert_events_and_checkpoint(
            self.connection,
            [self._event("evt-1")],
            self._checkpoint("c-1"),
        )

        with self.assertRaises(RuntimeError):
            upsert_events_and_checkpoint(
                self.connection,
                [self._event("evt-fail")],
                self._checkpoint("c-2"),
                fail_on_event_id="evt-fail",
            )

        self.assertEqual(count_canonical_events(self.connection), 1)
        self.assertEqual(get_checkpoint_cursor(self.connection, "dhcp"), "c-1")


if __name__ == "__main__":
    unittest.main()
