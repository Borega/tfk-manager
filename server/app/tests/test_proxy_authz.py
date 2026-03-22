import unittest

from server.app.api.proxy_contracts import role_allows_proxy_operation


class TestProxyAuthz(unittest.TestCase):
    def test_analyst_can_execute_read_operation(self) -> None:
        self.assertEqual(role_allows_proxy_operation("analyst", "getDynamicLeases"), (True, "allowed"))

    def test_analyst_cannot_execute_mutating_operation(self) -> None:
        self.assertEqual(role_allows_proxy_operation("analyst", "deleteStaticLease"), (False, "forbidden"))

    def test_admin_can_execute_mutating_operation(self) -> None:
        self.assertEqual(role_allows_proxy_operation("admin", "deleteStaticLease"), (True, "allowed"))

    def test_unknown_operation_denied(self) -> None:
        self.assertEqual(role_allows_proxy_operation("admin", "unknownOperation"), (False, "operation_not_allowed"))


if __name__ == "__main__":
    unittest.main()
