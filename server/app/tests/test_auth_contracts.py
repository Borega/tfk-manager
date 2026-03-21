import unittest
from pathlib import Path

from server.app.api.auth_contracts import LoginResponse


class TestAuthContracts(unittest.TestCase):
    def test_login_response_fields(self) -> None:
        field_names = tuple(LoginResponse.__dataclass_fields__.keys())
        self.assertEqual(
            field_names,
            (
                "accessToken",
                "refreshToken",
                "accessExpiresAt",
                "refreshExpiresAt",
                "role",
            ),
        )

    def test_migration_contains_auth_tables_and_columns(self) -> None:
        migration_path = Path("server/app/db/migrations/versions/0005_auth_sessions.sql")
        migration_sql = migration_path.read_text(encoding="utf-8")

        self.assertIn("CREATE TABLE IF NOT EXISTS auth_users", migration_sql)
        self.assertIn("CREATE TABLE IF NOT EXISTS auth_sessions", migration_sql)
        self.assertIn("refresh_token_id", migration_sql)
        self.assertIn("session_version", migration_sql)


if __name__ == "__main__":
    unittest.main()
