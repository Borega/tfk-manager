-- Phase 3 auth and session persistence migration
-- Username/password authentication and refresh-token rotation support

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
    revoked_at TEXT,
    FOREIGN KEY(user_id) REFERENCES auth_users(id)
);

CREATE INDEX IF NOT EXISTS idx_auth_users_username
    ON auth_users(username);

CREATE INDEX IF NOT EXISTS idx_auth_sessions_refresh_token_id
    ON auth_sessions(refresh_token_id);
