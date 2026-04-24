from datetime import datetime, timezone
import sqlite3
import unittest

from server.app.collector.repository import count_canonical_events, ensure_schema, get_checkpoint_cursor
from server.app.collector.workers.replay_policy import SOURCE_POLICY
from server.app.collector.workers.worker_runner import create_worker_state, run_worker_iteration


class TestWorkerRunner(unittest.TestCase):
    def setUp(self):
        self.connection = sqlite3.connect(":memory:")
        ensure_schema(self.connection)

    def tearDown(self):
        self.connection.close()

    def _adapter_with_event(self, event_id: str):
        def _fetch(cursor, now_utc):
            _ = cursor
            observed = now_utc.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
            return [
                {
                    "eventId": event_id,
                    "sourceType": "dhcp",
                    "sourceEntityId": "lease-1",
                    "occurredAt": observed,
                    "observedAt": observed,
                    "payloadHash": "abc",
                    "lineageVersion": 1,
                    "confidenceState": "Healthy",
                    "rawPayloadJson": "{}",
                }
            ], event_id

        return _fetch

    def test_restart_resumes_from_checkpoint(self):
        now_utc = datetime(2026, 3, 21, 8, 0, 0, tzinfo=timezone.utc)
        state = create_worker_state("dhcp")

        run_worker_iteration("dhcp", state, self._adapter_with_event("evt-1"), self.connection, now_utc)
        self.assertEqual(get_checkpoint_cursor(self.connection, "dhcp"), "evt-1")

        resumed_state = create_worker_state("dhcp", cursor=get_checkpoint_cursor(self.connection, "dhcp"))
        run_worker_iteration("dhcp", resumed_state, self._adapter_with_event("evt-1"), self.connection, now_utc)
        self.assertEqual(count_canonical_events(self.connection), 1)

    def test_grace_window_before_fallback(self):
        now_utc = datetime(2026, 3, 21, 8, 0, 0, tzinfo=timezone.utc)
        state = create_worker_state("dhcp")

        run_worker_iteration(
            "dhcp",
            state,
            self._adapter_with_event("evt-fail"),
            self.connection,
            now_utc,
            fail_on_event_id="evt-fail",
        )
        self.assertFalse(state["fallbackRecommended"])

        state["nextRetryAt"] = None
        state["outageSeconds"] = SOURCE_POLICY["dhcp"]["fallbackGraceSeconds"]
        run_worker_iteration(
            "dhcp",
            state,
            self._adapter_with_event("evt-fail"),
            self.connection,
            now_utc,
            fail_on_event_id="evt-fail",
        )
        self.assertTrue(state["fallbackRecommended"])

    def test_force_refresh_bypasses_retry_wait_gate(self):
        now_utc = datetime(2026, 3, 21, 8, 0, 0, tzinfo=timezone.utc)
        state = create_worker_state("dhcp")
        state["attempt"] = 4
        state["outageSeconds"] = 120
        state["nextRetryAt"] = "2099-01-01T00:00:00Z"

        run_worker_iteration(
            "dhcp",
            state,
            self._adapter_with_event("evt-force-1"),
            self.connection,
            now_utc,
            force_refresh=True,
        )

        self.assertEqual(state["lastRunOutcome"], "success")
        self.assertEqual(state["attempt"], 0)
        self.assertIsNone(state["nextRetryAt"])
        self.assertEqual(get_checkpoint_cursor(self.connection, "dhcp"), "evt-force-1")


if __name__ == "__main__":
    unittest.main()
