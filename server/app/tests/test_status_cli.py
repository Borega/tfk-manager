import json
import unittest

from server.app.contracts.reliability_status import ReliabilityState, SourceReliabilityStatus
from server.app.interfaces.status_cli import render_status_json


class TestStatusCli(unittest.TestCase):
    def _status(self, source_key: str, state: ReliabilityState, fallback: bool) -> SourceReliabilityStatus:
        return SourceReliabilityStatus(
            sourceKey=source_key,
            state=state,
            lagSeconds=120,
            checkpointCursor=f"{source_key}-cursor",
            severityCandidate="Warning",
            fallbackRecommended=fallback,
            confidenceImpact="high" if state == ReliabilityState.Stale else "medium",
        )

    def test_status_payload_contains_guidance_fields(self):
        payload = json.loads(
            render_status_json(
                [
                    self._status("dhcp", ReliabilityState.Degraded, False),
                ]
            )
        )
        self.assertIn("overallSeverity", payload)
        self.assertIn("actionLabel", payload["fallbackGuidance"])

    def test_multi_source_outage_marks_critical(self):
        payload = json.loads(
            render_status_json(
                [
                    self._status("dhcp", ReliabilityState.Stale, True),
                    self._status("firewall", ReliabilityState.Stale, True),
                ]
            )
        )
        self.assertEqual(payload["overallSeverity"], "Critical")
        self.assertEqual(payload["fallbackGuidance"]["actionKey"], "switch-local-fallback")

    def test_status_payload_contains_retention_lifecycle_fields(self):
        payload = json.loads(
            render_status_json(
                [self._status("dhcp", ReliabilityState.Healthy, False)],
                retention_lifecycle={
                    "lastRunAt": "2026-03-21T09:00:00Z",
                    "cutoffAt": "2025-03-21T09:00:00Z",
                    "deletedCount": 12,
                    "affectedWindows": ["2024-02", "2024-03"],
                    "runStatus": "completed",
                    "nextScheduledAt": "2026-03-22T09:00:00Z",
                },
            )
        )
        retention = payload["retentionLifecycle"]
        self.assertEqual(retention["deletedCount"], 12)
        self.assertEqual(retention["affectedWindows"], ["2024-02", "2024-03"])
        self.assertEqual(retention["runStatus"], "completed")

    def test_retention_payload_coexists_with_existing_reliability_fields(self):
        payload = json.loads(
            render_status_json(
                [self._status("dhcp", ReliabilityState.Degraded, False)],
                retention_lifecycle={
                    "lastRunAt": "2026-03-21T09:00:00Z",
                    "cutoffAt": "2025-03-21T09:00:00Z",
                    "deletedCount": 0,
                    "affectedWindows": [],
                    "runStatus": "completed",
                    "nextScheduledAt": "2026-03-22T09:00:00Z",
                },
            )
        )
        self.assertIn("overallSeverity", payload)
        self.assertIn("fallbackGuidance", payload)
        self.assertIn("retentionLifecycle", payload)
        self.assertEqual(payload["fallbackGuidance"]["actionLabel"], "Continue Server Mode")
        self.assertEqual(payload["retentionLifecycle"]["lastRunAt"], "2026-03-21T09:00:00Z")


if __name__ == "__main__":
    unittest.main()
