import unittest

from server.app.api.authz_policy import ROLE_POLICY, authorize_request


class TestAuthzPolicy(unittest.TestCase):
    def test_analyst_allowed_on_history_and_freshness_read(self) -> None:
        self.assertEqual(authorize_request("analyst", "/api/history/events", "GET"), (True, "allowed"))
        self.assertEqual(authorize_request("analyst", "/api/history/trends", "GET"), (True, "allowed"))
        self.assertEqual(authorize_request("analyst", "/api/status/freshness", "GET"), (True, "allowed"))

    def test_analyst_denied_for_admin_endpoint(self) -> None:
        allowed, reason = authorize_request("analyst", "/api/admin/users", "POST")
        self.assertFalse(allowed)
        self.assertEqual(reason, "forbidden")

    def test_analyst_denied_for_unmapped_endpoint(self) -> None:
        allowed, reason = authorize_request("analyst", "/api/history/unknown", "GET")
        self.assertFalse(allowed)
        self.assertEqual(reason, "endpoint_unmapped")

    def test_unknown_role_is_denied(self) -> None:
        allowed, reason = authorize_request("viewer", "/api/history/events", "GET")
        self.assertFalse(allowed)
        self.assertEqual(reason, "role_unknown")

    def test_role_policy_contains_required_entries(self) -> None:
        self.assertIn("/api/history/events", ROLE_POLICY)
        self.assertIn("/api/history/trends", ROLE_POLICY)
        self.assertIn("/api/status/freshness", ROLE_POLICY)


if __name__ == "__main__":
    unittest.main()
