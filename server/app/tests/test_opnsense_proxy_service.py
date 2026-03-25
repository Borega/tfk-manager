import unittest
from unittest.mock import patch

from server.app.proxy.opnsense_proxy_service import (
    _collect_static_rows_with_iface,
    execute_opnsense_operation,
)


class _FakeBackendModule:
    @staticmethod
    def _fetch_static_leases_raw(_session):
        return {
            "lan": [
                {
                    "hostname": "lan-device",
                    "mac": "00:11:22:33:44:55",
                    "ip": "10.6.168.10",
                }
            ],
            "opt4": [
                {
                    "hostname": "byod-device",
                    "mac": "AA:BB:CC:DD:EE:FF",
                    "ip": "10.8.4.20",
                }
            ],
            "WLANBYOD": [
                {
                    "hostname": "byod-alias-device",
                    "mac": "AA:BB:CC:DD:EE:01",
                    "ip": "10.8.4.21",
                }
            ],
        }

    @staticmethod
    def fetch_static_leases_via_session_api(_session):
        return []


class TestOpnSenseProxyService(unittest.TestCase):
    def test_collect_static_rows_inherits_iface_from_bucket_keys(self) -> None:
        payload = {
            "rows": {
                "lan": [
                    {
                        "hostname": "lan-device",
                        "mac": "00:11:22:33:44:55",
                        "ip": "10.6.168.10",
                    }
                ],
                "opt4": [
                    {
                        "hostname": "byod-device",
                        "mac": "AA:BB:CC:DD:EE:FF",
                        "ip": "10.8.4.20",
                    }
                ],
                "WLANBYOD": [
                    {
                        "hostname": "byod-alias-device",
                        "mac": "AA:BB:CC:DD:EE:01",
                        "ip": "10.8.4.21",
                    }
                ],
            }
        }

        rows = _collect_static_rows_with_iface(payload)

        self.assertIn(
            {
                "hostname": "lan-device",
                "mac": "00:11:22:33:44:55",
                "ip": "10.6.168.10",
                "iface": "lan",
            },
            rows,
        )
        self.assertIn(
            {
                "hostname": "byod-device",
                "mac": "AA:BB:CC:DD:EE:FF",
                "ip": "10.8.4.20",
                "iface": "opt4",
            },
            rows,
        )
        self.assertIn(
            {
                "hostname": "byod-alias-device",
                "mac": "AA:BB:CC:DD:EE:01",
                "ip": "10.8.4.21",
                "iface": "opt4",
            },
            rows,
        )

    @patch("server.app.proxy.opnsense_proxy_service._create_authenticated_session")
    @patch("server.app.proxy.opnsense_proxy_service._load_backend_module")
    def test_execute_get_static_leases_keeps_iface_in_delegated_result(
        self,
        load_backend_module_mock,
        create_authenticated_session_mock,
    ) -> None:
        load_backend_module_mock.return_value = _FakeBackendModule()
        create_authenticated_session_mock.return_value = object()

        response = execute_opnsense_operation("getStaticLeases", {})

        self.assertTrue(response["ok"])
        rows = response["rows"]
        by_hostname = {row["hostname"]: row for row in rows}

        self.assertEqual(by_hostname["lan-device"]["iface"], "lan")
        self.assertEqual(by_hostname["byod-device"]["iface"], "opt4")
        self.assertEqual(by_hostname["byod-alias-device"]["iface"], "opt4")


if __name__ == "__main__":
    unittest.main()
