import unittest
from unittest.mock import patch

from server.app.api.proxy_operation_errors import ProxyOperationError
from server.app.api.proxy_operations_api import proxy_execute_operation, proxy_get_operation_status


class TestProxyOperationsApi(unittest.TestCase):
    @patch("server.app.api.proxy_operations_api.execute_opnsense_operation")
    def test_dispatches_opnsense_operations(self, execute_opnsense_operation_mock) -> None:
        execute_opnsense_operation_mock.return_value = {"ok": True, "rows": []}
        response = proxy_execute_operation("getDynamicLeases", {"iface": "Gruen"})
        self.assertTrue(response["ok"])
        execute_opnsense_operation_mock.assert_called_once_with("getDynamicLeases", {"iface": "Gruen"})

    @patch("server.app.api.proxy_operations_api.execute_webfilter_operation")
    def test_dispatches_webfilter_operations(self, execute_webfilter_operation_mock) -> None:
        execute_webfilter_operation_mock.return_value = {"ok": True, "entries": []}
        response = proxy_execute_operation("getWebfilterLogs", {"searchText": "example"})
        self.assertTrue(response["ok"])
        execute_webfilter_operation_mock.assert_called_once_with("getWebfilterLogs", {"searchText": "example"})

    def test_unsupported_operation_raises(self) -> None:
        with self.assertRaises(ProxyOperationError) as exc_ctx:
            proxy_execute_operation("unknown", {})
        self.assertEqual(exc_ctx.exception.error_code, "proxy_operation_invalid")

    def test_get_operation_status_parses_details_json(self) -> None:
        status = proxy_get_operation_status(
            {
                "requestId": "proxy-req-1",
                "operation": "getDynamicLeases",
                "scope": "proxy:dhcp:read",
                "status": "success",
                "actorId": "user-1",
                "actorRole": "analyst",
                "target": "10.6.168.50",
                "errorCode": None,
                "details": "{\"resultSummary\":\"ok\"}",
                "createdAt": "2026-03-22T10:00:00Z",
            }
        )
        self.assertEqual(status["details"], {"resultSummary": "ok"})


if __name__ == "__main__":
    unittest.main()
