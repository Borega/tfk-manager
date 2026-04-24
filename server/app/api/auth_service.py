from __future__ import annotations

import os
import sqlite3
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import bcrypt

from server.app.api.auth_contracts import LoginResponse, RefreshResponse
from server.app.api.token_codec import TokenDecodeError, decode_token, encode_access_token

DEFAULT_JWT_SECRET = os.getenv(
    "TFK_SERVER_JWT_SECRET",
    "phase3-dev-secret-with-minimum-32-byte-length",
)
ACCESS_TOKEN_TTL = timedelta(minutes=15)
REFRESH_TOKEN_TTL = timedelta(days=7)


class AuthenticationError(RuntimeError):
    pass


class TokenRefreshError(RuntimeError):
    pass


def _table_columns(connection: sqlite3.Connection, table_name: str) -> set[str]:
    rows = connection.execute(f"PRAGMA table_info({table_name})").fetchall()
    return {str(row[1]) for row in rows}


def _ensure_column(connection: sqlite3.Connection, table_name: str, column_name: str, definition: str) -> None:
    if column_name in _table_columns(connection, table_name):
        return
    connection.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {definition}")


def _ensure_auth_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS auth_users (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(username)
        );

        CREATE TABLE IF NOT EXISTS auth_sessions (
            session_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            refresh_token_id TEXT NOT NULL,
            session_version INTEGER NOT NULL,
            issued_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            revoked_at TEXT
        );
        """
    )

    _ensure_column(connection, "auth_users", "role", "TEXT NOT NULL DEFAULT 'admin'")
    _ensure_column(connection, "auth_users", "is_active", "INTEGER NOT NULL DEFAULT 1")
    _ensure_column(connection, "auth_users", "created_at", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(connection, "auth_users", "updated_at", "TEXT NOT NULL DEFAULT ''")

    _ensure_column(connection, "auth_sessions", "refresh_token_id", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(connection, "auth_sessions", "session_version", "INTEGER NOT NULL DEFAULT 1")
    _ensure_column(connection, "auth_sessions", "issued_at", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(connection, "auth_sessions", "expires_at", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(connection, "auth_sessions", "revoked_at", "TEXT")


def _to_hash_bytes(stored_hash: object) -> bytes:
    if isinstance(stored_hash, bytes):
        return stored_hash
    if isinstance(stored_hash, memoryview):
        return stored_hash.tobytes()
    return str(stored_hash).encode("utf-8")


def _to_iso(value: datetime) -> str:
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _from_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


def _issue_session_tokens(
    connection: sqlite3.Connection,
    user_id: str,
    role: str,
    now_utc: datetime,
    secret: str,
    session_version: int,
) -> tuple[str, str, str, str, str]:
    session_id = str(uuid4())
    refresh_token_id = str(uuid4())
    access_expires = now_utc + ACCESS_TOKEN_TTL
    refresh_expires = now_utc + REFRESH_TOKEN_TTL

    access_token = encode_access_token(
        {
            "sub": user_id,
            "role": role,
            "sid": session_id,
            "ver": session_version,
            "typ": "access",
        },
        access_expires,
        secret,
    )
    refresh_token = encode_access_token(
        {
            "sub": user_id,
            "role": role,
            "sid": session_id,
            "ver": session_version,
            "typ": "refresh",
            "rtid": refresh_token_id,
        },
        refresh_expires,
        secret,
    )

    connection.execute(
        """
        INSERT INTO auth_sessions (
            session_id,
            user_id,
            refresh_token_id,
            session_version,
            issued_at,
            expires_at,
            revoked_at
        ) VALUES (?, ?, ?, ?, ?, ?, NULL)
        """,
        (
            session_id,
            user_id,
            refresh_token_id,
            session_version,
            _to_iso(now_utc),
            _to_iso(refresh_expires),
        ),
    )

    return (
        access_token,
        refresh_token,
        _to_iso(access_expires),
        _to_iso(refresh_expires),
        session_id,
    )


def authenticate_user(
    username: str,
    password: str,
    connection: sqlite3.Connection,
    now_utc: datetime,
    secret: str = DEFAULT_JWT_SECRET,
) -> LoginResponse:
    _ensure_auth_schema(connection)

    user_row = connection.execute(
        """
        SELECT id, password_hash, role, is_active
        FROM auth_users
        WHERE username = ?
        """,
        (username,),
    ).fetchone()

    if user_row is None:
        raise AuthenticationError("invalid_credentials")

    user_id, stored_hash, role, is_active = user_row
    if not is_active:
        raise AuthenticationError("inactive_user")

    try:
        hash_bytes = _to_hash_bytes(stored_hash)
        if not bcrypt.checkpw(password.encode("utf-8"), hash_bytes):
            raise AuthenticationError("invalid_credentials")
    except ValueError as exc:
        raise AuthenticationError("invalid_credentials") from exc

    access_token, refresh_token, access_expires_at, refresh_expires_at, _ = _issue_session_tokens(
        connection=connection,
        user_id=user_id,
        role=role,
        now_utc=now_utc.astimezone(UTC),
        secret=secret,
        session_version=1,
    )
    connection.commit()

    return LoginResponse(
        accessToken=access_token,
        refreshToken=refresh_token,
        accessExpiresAt=access_expires_at,
        refreshExpiresAt=refresh_expires_at,
        role=role,
    )


def refresh_session(
    refresh_token: str,
    connection: sqlite3.Connection,
    now_utc: datetime,
    secret: str = DEFAULT_JWT_SECRET,
) -> RefreshResponse:
    _ensure_auth_schema(connection)

    try:
        refresh_claims = decode_token(refresh_token, secret)
    except TokenDecodeError as exc:
        raise TokenRefreshError("invalid_refresh_token") from exc

    if refresh_claims.get("typ") != "refresh":
        raise TokenRefreshError("invalid_token_type")

    user_id = str(refresh_claims.get("sub", ""))
    session_id = str(refresh_claims.get("sid", ""))
    refresh_token_id = str(refresh_claims.get("rtid", ""))
    session_version = int(refresh_claims.get("ver", 0))

    session_row = connection.execute(
        """
        SELECT s.refresh_token_id, s.session_version, s.expires_at, s.revoked_at, u.role
        FROM auth_sessions s
        JOIN auth_users u ON u.id = s.user_id
        WHERE s.session_id = ? AND s.user_id = ?
        """,
        (session_id, user_id),
    ).fetchone()
    if session_row is None:
        raise TokenRefreshError("session_not_found")

    stored_refresh_id, stored_version, stored_expires_at, revoked_at, role = session_row
    if revoked_at is not None:
        raise TokenRefreshError("refresh_already_used")
    if stored_refresh_id != refresh_token_id:
        raise TokenRefreshError("refresh_mismatch")
    if int(stored_version) != session_version:
        raise TokenRefreshError("session_version_mismatch")
    if _from_iso(stored_expires_at) <= now_utc.astimezone(UTC):
        raise TokenRefreshError("refresh_expired")

    connection.execute(
        "UPDATE auth_sessions SET revoked_at = ? WHERE session_id = ?",
        (_to_iso(now_utc), session_id),
    )

    access_token, next_refresh_token, access_expires_at, refresh_expires_at, _ = _issue_session_tokens(
        connection=connection,
        user_id=user_id,
        role=role,
        now_utc=now_utc.astimezone(UTC),
        secret=secret,
        session_version=session_version + 1,
    )
    connection.commit()

    return RefreshResponse(
        accessToken=access_token,
        refreshToken=next_refresh_token,
        accessExpiresAt=access_expires_at,
        refreshExpiresAt=refresh_expires_at,
    )
