import sqlite3
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

import bcrypt

from server.app.api.auth_service import (
    AuthenticationError,
    DEFAULT_JWT_SECRET,
    TokenRefreshError,
    authenticate_user,
    refresh_session,
)
from server.app.api.token_codec import decode_token


class TestAuthService(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:")
        migration = Path("server/app/db/migrations/versions/0005_auth_sessions.sql").read_text(
            encoding="utf-8"
        )
        self.connection.executescript(migration)

        now = self._now()
        password_hash = bcrypt.hashpw(b"secret-password", bcrypt.gensalt()).decode("utf-8")
        self.connection.execute(
            """
            INSERT INTO auth_users (id, username, password_hash, role, is_active, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "user-1",
                "analyst",
                password_hash,
                "analyst",
                1,
                now,
                now,
            ),
        )
        self.connection.commit()

    def tearDown(self) -> None:
        self.connection.close()

    @staticmethod
    def _now() -> str:
        return "2026-03-21T12:00:00Z"

    @staticmethod
    def _now_dt() -> datetime:
        return datetime(2026, 3, 21, 12, 0, 0, tzinfo=UTC)

    def test_authenticate_user_returns_token_pair(self) -> None:
        result = authenticate_user(
            username="analyst",
            password="secret-password",
            connection=self.connection,
            now_utc=self._now_dt(),
            secret=DEFAULT_JWT_SECRET,
        )

        self.assertTrue(result.accessToken)
        self.assertTrue(result.refreshToken)
        self.assertEqual(result.role, "analyst")

        claims = decode_token(result.accessToken, DEFAULT_JWT_SECRET, verify_expiration=False)
        self.assertEqual(claims.get("sub"), "user-1")
        self.assertEqual(claims.get("typ"), "access")

    def test_authenticate_user_rejects_invalid_password(self) -> None:
        with self.assertRaises(AuthenticationError):
            authenticate_user(
                username="analyst",
                password="wrong-password",
                connection=self.connection,
                now_utc=self._now_dt(),
                secret=DEFAULT_JWT_SECRET,
            )

    def test_refresh_rotation_revokes_old_token(self) -> None:
        login = authenticate_user(
            username="analyst",
            password="secret-password",
            connection=self.connection,
            now_utc=self._now_dt(),
            secret=DEFAULT_JWT_SECRET,
        )

        old_refresh_claims = decode_token(
            login.refreshToken,
            DEFAULT_JWT_SECRET,
            verify_expiration=False,
        )
        refreshed = refresh_session(
            refresh_token=login.refreshToken,
            connection=self.connection,
            now_utc=self._now_dt() + timedelta(minutes=5),
            secret=DEFAULT_JWT_SECRET,
        )

        self.assertNotEqual(refreshed.refreshToken, login.refreshToken)
        revoked_row = self.connection.execute(
            "SELECT revoked_at FROM auth_sessions WHERE session_id = ?",
            (old_refresh_claims["sid"],),
        ).fetchone()
        self.assertIsNotNone(revoked_row)
        self.assertIsNotNone(revoked_row[0])

        with self.assertRaises(TokenRefreshError):
            refresh_session(
                refresh_token=login.refreshToken,
                connection=self.connection,
                now_utc=self._now_dt() + timedelta(minutes=6),
                secret=DEFAULT_JWT_SECRET,
            )

    def test_refresh_rejects_expired_token(self) -> None:
        login = authenticate_user(
            username="analyst",
            password="secret-password",
            connection=self.connection,
            now_utc=self._now_dt(),
            secret=DEFAULT_JWT_SECRET,
        )

        with self.assertRaises(TokenRefreshError):
            refresh_session(
                refresh_token=login.refreshToken,
                connection=self.connection,
                now_utc=self._now_dt() + timedelta(days=8),
                secret=DEFAULT_JWT_SECRET,
            )


if __name__ == "__main__":
    unittest.main()
