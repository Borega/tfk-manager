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


if __name__ == "__main__":
    unittest.main()
