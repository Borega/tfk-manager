from datetime import datetime, timezone
import unittest

from server.app.collector.health_service import compute_source_health
from server.app.contracts.reliability_status import ReliabilityState


class TestHealthService(unittest.TestCase):
    def setUp(self):
        self.now_utc = datetime(2026, 3, 21, 9, 0, 0, tzinfo=timezone.utc)

    def test_healthy_state_transition(self):
        status = compute_source_health(
            source_key="dhcp",
            checkpoint_cursor="c-1",
            lag_seconds=30,
            error_count=0,
            replay_backlog=0,
            last_success_at="2026-03-21T08:59:30Z",
            last_error_at=None,
            now_utc=self.now_utc,
        )
        self.assertEqual(status.state, ReliabilityState.Healthy)
        self.assertEqual(status.checkpointCursor, "c-1")
        self.assertEqual(status.lagSeconds, 30)

    def test_degraded_state_transition(self):
        status = compute_source_health(
            source_key="webfilter",
            checkpoint_cursor="c-2",
            lag_seconds=120,
            error_count=0,
            replay_backlog=0,
            last_success_at="2026-03-21T08:57:00Z",
            last_error_at=None,
            now_utc=self.now_utc,
        )
        self.assertEqual(status.state, ReliabilityState.Degraded)

    def test_stale_state_transition(self):
        status = compute_source_health(
            source_key="firewall",
            checkpoint_cursor="c-3",
            lag_seconds=120,
            error_count=1,
            replay_backlog=1,
            last_success_at="2026-03-21T08:40:00Z",
            last_error_at="2026-03-21T08:59:00Z",
            now_utc=self.now_utc,
        )
        self.assertEqual(status.state, ReliabilityState.Stale)

    def test_unknown_state_transition(self):
        status = compute_source_health(
            source_key="dhcp",
            checkpoint_cursor="",
            lag_seconds=0,
            error_count=0,
            replay_backlog=0,
            last_success_at=None,
            last_error_at=None,
            now_utc=self.now_utc,
        )
        self.assertEqual(status.state, ReliabilityState.Unknown)

    def test_grace_window_fallback_recommendation(self):
        status = compute_source_health(
            source_key="dhcp",
            checkpoint_cursor="c-4",
            lag_seconds=301,
            error_count=1,
            replay_backlog=1,
            last_success_at="2026-03-21T08:45:00Z",
            last_error_at="2026-03-21T08:58:00Z",
            now_utc=self.now_utc,
        )
        self.assertTrue(status.fallbackRecommended)


if __name__ == "__main__":
    unittest.main()
