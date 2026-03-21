import unittest

from server.app.api.freshness_api import get_freshness_status
from server.app.contracts.reliability_status import ReliabilityState, SourceReliabilityStatus


class TestFreshnessApi(unittest.TestCase):
    def _source_statuses(self) -> list[SourceReliabilityStatus]:
        return [
            SourceReliabilityStatus(
                sourceKey="dhcp",
                state=ReliabilityState.Healthy,
                lagSeconds=12,
                checkpointCursor="dhcp-100",
                severityCandidate="Info",
                fallbackRecommended=False,
                confidenceImpact="low",
            )
        ]

    def test_success_payload_contract(self) -> None:
        result = get_freshness_status(
            role="analyst",
            token_claims={"sub": "user-1", "role": "analyst"},
            source_statuses=self._source_statuses(),
        )

        self.assertEqual(result["status"], 200)
        payload = result["data"]
        self.assertIn("overallSeverity", payload)
        self.assertIn("sources", payload)
        self.assertIn("fallbackGuidance", payload)
        self.assertIn("retentionLifecycle", payload)

    def test_missing_token_returns_401(self) -> None:
        result = get_freshness_status(
            role="analyst",
            token_claims=None,
            source_statuses=self._source_statuses(),
        )

        self.assertEqual(result["status"], 401)
        self.assertEqual(result["errorCode"], "token_invalid")

    def test_forbidden_role_returns_403(self) -> None:
        result = get_freshness_status(
            role="viewer",
            token_claims={"sub": "user-2", "role": "viewer"},
            source_statuses=self._source_statuses(),
        )

        self.assertEqual(result["status"], 403)
        self.assertEqual(result["errorCode"], "forbidden")


if __name__ == "__main__":
    unittest.main()
