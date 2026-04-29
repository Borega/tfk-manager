import sqlite3
import unittest

from server.app.api.analysis_dashboard_api import get_analysis_dashboard
from server.app.api.analysis_dashboard_contracts import AnalysisDashboardQuery
from server.app.collector.repository import ensure_schema


class TestAnalysisDashboardApi(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:")
        ensure_schema(self.connection)
        self.connection.executemany(
            """
            INSERT INTO canonical_events (
                event_id,
                source_type,
                source_entity_id,
                source_identifiers_json,
                occurred_at,
                observed_at,
                collector_version,
                ingest_timestamp,
                payload_hash,
                lineage_version,
                confidence_state,
                raw_payload_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    "dhcp-1",
                    "dhcp",
                    "00:1A:2B:AA:BB:CC",
                    "{}",
                    "2026-04-20T09:00:00Z",
                    "2026-04-20T09:00:01Z",
                    "collector",
                    "2026-04-20T09:00:02Z",
                    "hash-dhcp-1",
                    1,
                    "Healthy",
                    '{"mac":"00:1A:2B:AA:BB:CC","ip":"10.0.1.11","hostname":"lab-a","leaseEnd":"2026-04-20T13:00:00Z"}',
                ),
                (
                    "dhcp-2",
                    "dhcp",
                    "00:1A:2B:DD:EE:FF",
                    "{}",
                    "2026-04-20T10:00:00Z",
                    "2026-04-20T10:00:01Z",
                    "collector",
                    "2026-04-20T10:00:02Z",
                    "hash-dhcp-2",
                    1,
                    "Healthy",
                    '{"mac":"00:1A:2B:DD:EE:FF","ip":"172.16.4.22","hostname":"byod-1","leaseEnd":"2026-04-20T12:00:00Z"}',
                ),
                (
                    "fw-1",
                    "firewall",
                    "fw-entity-1",
                    "{}",
                    "2026-04-20T10:15:00Z",
                    "2026-04-20T10:15:01Z",
                    "collector",
                    "2026-04-20T10:15:02Z",
                    "hash-fw-1",
                    1,
                    "Healthy",
                    '{"id":"10","action":"block","src":"10.0.1.11","dst":"8.8.8.8","proto":"tcp"}',
                ),
                (
                    "wf-1",
                    "webfilter",
                    "wf-entity-1",
                    "{}",
                    "2026-04-20T10:20:00Z",
                    "2026-04-20T10:20:01Z",
                    "collector",
                    "2026-04-20T10:20:02Z",
                    "hash-wf-1",
                    1,
                    "Healthy",
                    '{"user":"10.0.1.11","url":"example-blocked.test","action":"blocked","category":"malware","time":"10:20:00"}',
                ),
            ],
        )
        self.connection.commit()

    def tearDown(self) -> None:
        self.connection.close()

    def test_dashboard_response_contains_required_sections(self) -> None:
        query = AnalysisDashboardQuery(
            startAt="2026-04-20T00:00:00Z",
            endAt="2026-04-20T23:59:59Z",
            bucketGrain="coarse",
        )
        payload = get_analysis_dashboard(query=query, role="analyst", connection=self.connection)

        self.assertIn("networkInfrastructure", payload)
        self.assertIn("deviceBehavior", payload)
        self.assertIn("securityPolicy", payload)
        self.assertIn("dashboards", payload)

        dashboards = payload["dashboards"]
        self.assertIn("dhcpLeaseTimeseries", dashboards)
        self.assertIn("firewallDenyTimeseries", dashboards)
        self.assertIn("topBlockedDomainsByVlan", dashboards)

        trends = payload["trends"]
        self.assertGreaterEqual(len(trends["dhcpLeaseCounts"]), 1)
        self.assertGreaterEqual(len(trends["firewallDenyCounts"]), 1)

    def test_dashboard_rejects_unauthorized_role(self) -> None:
        query = AnalysisDashboardQuery(
            startAt="2026-04-20T00:00:00Z",
            endAt="2026-04-20T23:59:59Z",
            bucketGrain="coarse",
        )
        with self.assertRaises(PermissionError):
            get_analysis_dashboard(query=query, role="viewer", connection=self.connection)


if __name__ == "__main__":
    unittest.main()
