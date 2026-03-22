import unittest

from pydantic import ValidationError

from server.app.api.proxy_contracts import (
    ProxyOperationRequest,
    is_allowed_proxy_operation,
    required_scope_for_operation,
)


class TestProxyContracts(unittest.TestCase):
    def test_allowed_operation_is_accepted(self) -> None:
        request = ProxyOperationRequest(
            operation="getDynamicLeases",
            payload={},
            requestNonce="0123456789abcdef",
            requestTimestamp="2026-03-22T00:00:00Z",
            requestAudience="tfk-manager-server",
        )
        self.assertEqual(request.operation, "getDynamicLeases")

    def test_unknown_operation_is_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            ProxyOperationRequest(
                operation="proxyAnyEndpoint",
                payload={},
                requestNonce="0123456789abcdef",
                requestTimestamp="2026-03-22T00:00:00Z",
                requestAudience="tfk-manager-server",
            )

    def test_scope_mapping_is_stable(self) -> None:
        self.assertTrue(is_allowed_proxy_operation("deleteStaticLease"))
        self.assertEqual(required_scope_for_operation("deleteStaticLease"), "proxy:dhcp:write")
        self.assertEqual(required_scope_for_operation("getWebfilterLogs"), "proxy:webfilter:read")


if __name__ == "__main__":
    unittest.main()
