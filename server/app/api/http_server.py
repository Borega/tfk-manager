from __future__ import annotations

import os
import sqlite3
import threading
import json
import re
import importlib.util
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit
from uuid import uuid4

import bcrypt
import requests
from fastapi import FastAPI, Header, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from urllib3.exceptions import InsecureRequestWarning

from server.app.api.app import handle_exception
from server.app.api.auth_service import (
    AuthenticationError,
    DEFAULT_JWT_SECRET,
    authenticate_user,
    refresh_session,
)
from server.app.api.error_contract import (
    ERR_TOKEN_EXPIRED,
    ERR_TOKEN_INVALID,
    ERR_FORBIDDEN,
    ERR_PROXY_NOT_FOUND,
    ERR_PROXY_OPERATION,
    ERR_PROXY_SECURITY,
    build_error_response,
    status_for_error_code,
)
from server.app.api.proxy_operation_errors import ProxyOperationError
from server.app.api.proxy_contracts import (
    ProxyOperationRequest,
    required_scope_for_operation,
    role_allows_proxy_operation,
)
from server.app.api.proxy_operations_api import proxy_execute_operation, proxy_get_operation_status
from server.app.api.proxy_security import ProxySecurityError, validate_proxy_request
from server.app.api.freshness_api import get_freshness_status
from server.app.api.query_api import get_historical_events, get_historical_trends
from server.app.api.query_contracts import EventsQuery, TrendsQuery
from server.app.api.token_codec import TokenDecodeError, decode_token
from server.app.collector.health_service import evaluate_all_sources
from server.app.collector.adapters import dhcp_adapter, firewall_adapter, webfilter_adapter
from server.app.collector.repository import ensure_schema, get_proxy_operation_audit_by_request_id, write_proxy_operation_audit
from server.app.collector.workers.replay_policy import SOURCE_POLICY
from server.app.collector.workers.worker_runner import create_worker_state, run_worker_iteration

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

DB_PATH = os.getenv("TFK_SERVER_DB_PATH", "server/data/server.db")
JWT_SECRET = os.getenv("TFK_SERVER_JWT_SECRET", DEFAULT_JWT_SECRET)

BOOTSTRAP_USERNAME = os.getenv("TFK_SERVER_BOOTSTRAP_USERNAME", "").strip()
BOOTSTRAP_PASSWORD = os.getenv("TFK_SERVER_BOOTSTRAP_PASSWORD", "")
BOOTSTRAP_ROLE = os.getenv("TFK_SERVER_BOOTSTRAP_ROLE", "admin").strip() or "admin"
CORS_ORIGINS = [
    value.strip()
    for value in os.getenv("TFK_SERVER_CORS_ORIGINS", "*").split(",")
    if value.strip()
] or ["*"]
COLLECTOR_ENABLED = os.getenv("TFK_SERVER_COLLECTOR_ENABLED", "1").strip().lower() not in {"0", "false", "no", "off"}
COLLECTOR_SAMPLE_MODE = os.getenv("TFK_SERVER_COLLECTOR_SAMPLE_MODE", "1").strip().lower() not in {"0", "false", "no", "off"}
COLLECTOR_INTERVAL_SECONDS = max(5, int(os.getenv("TFK_SERVER_COLLECTOR_INTERVAL_SECONDS", "20")))
SOURCE_OPNSENSE_BASE_URL = os.getenv("TFK_SOURCE_OPNSENSE_BASE_URL", "").strip()
SOURCE_API_USERNAME = os.getenv("TFK_SOURCE_API_USERNAME", "").strip()
SOURCE_API_KEY = os.getenv("TFK_SOURCE_API_KEY", "").strip()
SOURCE_API_SECRET = os.getenv("TFK_SOURCE_API_SECRET", "").strip()
SOURCE_OPNSENSE_USERNAME = os.getenv("TFK_SOURCE_OPNSENSE_USERNAME", "").strip()
SOURCE_OPNSENSE_PASSWORD = os.getenv("TFK_SOURCE_OPNSENSE_PASSWORD", "").strip()
SOURCE_COOKIE_HEADER = os.getenv("TFK_SOURCE_COOKIE_HEADER", "").strip()
SOURCE_MSD_COOKIE = os.getenv("TFK_SOURCE_MSD_COOKIE", "").strip()
SOURCE_VERIFY_TLS = os.getenv("TFK_SOURCE_VERIFY_TLS", "0").strip().lower() in {"1", "true", "yes", "y"}
SOURCE_CONNECT_TIMEOUT_SECONDS = max(3, int(os.getenv("TFK_SOURCE_CONNECT_TIMEOUT_SECONDS", "10")))
SOURCE_READ_TIMEOUT_SECONDS = max(5, int(os.getenv("TFK_SOURCE_READ_TIMEOUT_SECONDS", "30")))
SOURCE_FIREWALL_MAX_EVENTS = max(1, int(os.getenv("TFK_SOURCE_FIREWALL_MAX_EVENTS", "25")))
SOURCE_DHCP_PATH = os.getenv("TFK_SOURCE_DHCP_PATH", "/api/tfk/dhcp/dynamic_leases").strip() or "/api/tfk/dhcp/dynamic_leases"
SOURCE_FIREWALL_STREAM_PATH = os.getenv("TFK_SOURCE_FIREWALL_STREAM_PATH", "/api/diagnostics/firewall/streamLog").strip() or "/api/diagnostics/firewall/streamLog"
SOURCE_MSD_USERNAME = os.getenv("TFK_MSD_USERNAME", "").strip()
SOURCE_MSD_PASSWORD = os.getenv("TFK_MSD_PASSWORD", "").strip()

_collector_stop_event = threading.Event()
_collector_thread: threading.Thread | None = None
_collector_state_by_source: dict[str, dict[str, object]] = {}
_collector_last_run_at: datetime | None = None
_collector_run_lock = threading.Lock()


class AuthHeaderError(RuntimeError):
    pass


class LoginBody(BaseModel):
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)


class RefreshBody(BaseModel):
    refreshToken: str = Field(min_length=1)


app = FastAPI(title="TFK Manager Server API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _to_iso(value: datetime) -> str:
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _normalize_source_base_url(value: str) -> str:
    candidate = value.strip().rstrip("/")
    if not candidate:
        return ""

    parsed = urlsplit(candidate)
    if parsed.scheme and parsed.netloc:
        return candidate

    return f"https://{candidate.lstrip('/')}"


def _source_timeout() -> tuple[int, int]:
    return (SOURCE_CONNECT_TIMEOUT_SECONDS, SOURCE_READ_TIMEOUT_SECONDS)


def _source_stream_timeout() -> tuple[int, None]:
    return (SOURCE_CONNECT_TIMEOUT_SECONDS, None)


def _join_source_url(base_url: str, path: str) -> str:
    normalized_path = path if path.startswith("/") else f"/{path}"
    return f"{base_url.rstrip('/')}{normalized_path}"


def _looks_like_ipv4(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        number = int(part)
        if number < 0 or number > 255:
            return False
    return True


def _extract_timestamp(payload: dict[str, object], fallback_iso: str) -> str:
    for key in ("time", "timestamp", "occurredAt", "createdAt", "updatedAt", "date"):
        value = payload.get(key)
        if value is None:
            continue

        if isinstance(value, (int, float)):
            try:
                return _to_iso(datetime.fromtimestamp(float(value), UTC))
            except (ValueError, OverflowError):
                continue

        text = str(value).strip()
        if not text:
            continue
        if text.endswith("Z"):
            return text
        if "T" in text:
            return text

    return fallback_iso


def _source_request(url: str, *, stream: bool = False):
    auth_user = SOURCE_API_KEY or SOURCE_API_USERNAME or SOURCE_OPNSENSE_USERNAME
    auth_password = SOURCE_API_SECRET or SOURCE_OPNSENSE_PASSWORD
    if not auth_user or not auth_password:
        return None

    return requests.get(
        url,
        auth=(auth_user, auth_password),
        verify=SOURCE_VERIFY_TLS,
        timeout=_source_timeout(),
        headers={"Accept": "application/json" if not stream else "text/event-stream"},
        stream=stream,
    )


def _new_source_session(base_url: str) -> requests.Session:
    session = requests.Session()
    session.verify = SOURCE_VERIFY_TLS
    session.headers.update(
        {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
            ),
            "Origin": base_url,
        }
    )
    return session


def _apply_cookie_header(session: requests.Session, raw_cookie_header: str) -> None:
    if not raw_cookie_header.strip():
        return
    for part in raw_cookie_header.split(";"):
        item = part.strip()
        if not item or "=" not in item:
            continue
        name, value = item.split("=", 1)
        name = name.strip()
        value = value.strip()
        if not name:
            continue
        session.cookies.set(name, value, path="/")


def _is_login_page(html: str) -> bool:
    lowered = html.lower()
    return "anmelden" in lowered or 'id="usernamefld"' in lowered


def _build_login_payload(login_html: str, username: str, password: str) -> dict[str, str]:
    hidden_fields = dict(
        re.findall(
            r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)["\']',
            login_html,
            flags=re.IGNORECASE,
        )
    )

    payload: dict[str, str] = {}
    payload.update(hidden_fields)
    payload["usernamefld"] = username
    payload["passwordfld"] = password
    payload["login"] = "1"
    return payload


def _authenticate_source_session(session: requests.Session, base_url: str) -> bool:
    if not SOURCE_OPNSENSE_USERNAME or not SOURCE_OPNSENSE_PASSWORD:
        return False

    login_page = session.get(f"{base_url}/", timeout=_source_timeout(), allow_redirects=True)
    payload = _build_login_payload(login_page.text, SOURCE_OPNSENSE_USERNAME, SOURCE_OPNSENSE_PASSWORD)

    login_response = session.post(
        f"{base_url}/",
        data=payload,
        timeout=_source_timeout(),
        allow_redirects=False,
        headers={
            "Referer": f"{base_url}/",
            "Origin": base_url,
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
    )

    if login_response.status_code in {301, 302, 303, 307, 308}:
        location = login_response.headers.get("Location", "/")
        if location.startswith("/"):
            location = f"{base_url}{location}"
        session.get(location, timeout=_source_timeout(), allow_redirects=True)

    dashboard = session.get(f"{base_url}/ui/core/dashboard", timeout=_source_timeout(), allow_redirects=True)
    return not _is_login_page(dashboard.text)


def _build_authenticated_source_session(base_url: str) -> requests.Session | None:
    if not base_url:
        return None

    session = _new_source_session(base_url)
    has_cookie = bool(SOURCE_COOKIE_HEADER)
    has_username_password = bool(SOURCE_OPNSENSE_USERNAME and SOURCE_OPNSENSE_PASSWORD)

    if has_cookie:
        _apply_cookie_header(session, SOURCE_COOKIE_HEADER)
        if SOURCE_MSD_COOKIE:
            session.cookies.set("MSD_Cookie", SOURCE_MSD_COOKIE, path="/")

        if has_username_password:
            try:
                dashboard = session.get(f"{base_url}/ui/core/dashboard", timeout=_source_timeout(), allow_redirects=True)
                if _is_login_page(dashboard.text):
                    _authenticate_source_session(session, base_url)
            except Exception as exc:
                print(f"collector source cookie validation failed: {exc}")
        return session

    if has_username_password:
        try:
            if _authenticate_source_session(session, base_url):
                return session
            print("collector source GUI login failed: dashboard still requires login")
        except Exception as exc:
            print(f"collector source GUI login failed: {exc}")

    return None


def _source_ajax_headers(base_url: str) -> dict[str, str]:
    return {
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "X-Requested-With": "XMLHttpRequest",
        "Referer": f"{base_url}/ui/core/dashboard",
        "Origin": base_url,
    }


def _fetch_dhcp_rows_from_env(now_utc: datetime) -> list[dict[str, object]]:
    base_url = _normalize_source_base_url(SOURCE_OPNSENSE_BASE_URL)
    if not base_url:
        return []

    source_session = _build_authenticated_source_session(base_url)

    attempted_paths: list[str] = []
    for path in (SOURCE_DHCP_PATH, "/api/tfk/dhcp/dynamic_leases", "/api/tfk/dynamicleases/get"):
        if path in attempted_paths:
            continue
        attempted_paths.append(path)

        try:
            if source_session is not None:
                response = source_session.get(
                    _join_source_url(base_url, path),
                    timeout=_source_timeout(),
                    allow_redirects=True,
                    headers=_source_ajax_headers(base_url),
                )
            else:
                response = _source_request(_join_source_url(base_url, path))

            if response is None:
                continue
            response.raise_for_status()
            payload = response.json()

            if isinstance(payload, dict):
                payload_rows = payload.get("rows")
            elif isinstance(payload, list):
                payload_rows = payload
            else:
                payload_rows = None

            if not isinstance(payload_rows, list):
                continue

            now_iso = _to_iso(now_utc)
            rows: list[dict[str, object]] = []
            for item in payload_rows:
                if not isinstance(item, dict):
                    continue

                ip = str(item.get("ip") or item.get("address") or item.get("ipaddr") or "")
                mac = str(item.get("mac") or item.get("macaddr") or "")
                hostname = str(item.get("hostname") or item.get("host") or "")
                end = str(item.get("end") or item.get("leaseEnd") or now_iso)
                occurred_at = _extract_timestamp(item, end or now_iso)
                if not mac and not ip:
                    continue
                rows.append(
                    {
                        "ip": ip,
                        "mac": mac,
                        "hostname": hostname,
                        "leaseEnd": end,
                        "occurredAt": occurred_at,
                    }
                )

            if rows:
                return rows
        except Exception as exc:
            print(f"collector dhcp fetch failed ({path}): {exc}")

    return []


def _fetch_firewall_rows_from_env(now_utc: datetime) -> list[dict[str, object]]:
    base_url = _normalize_source_base_url(SOURCE_OPNSENSE_BASE_URL)
    if not base_url:
        return []

    source_session = _build_authenticated_source_session(base_url)

    now_iso = _to_iso(now_utc)
    rows: list[dict[str, object]] = []

    try:
        if source_session is not None:
            response = source_session.get(
                _join_source_url(base_url, SOURCE_FIREWALL_STREAM_PATH),
                stream=True,
                timeout=_source_stream_timeout(),
                headers={
                    "Accept": "text/event-stream, application/json, */*",
                    "X-Requested-With": "XMLHttpRequest",
                    "Referer": f"{base_url}/ui/diagnostics/firewall/log",
                    "Origin": base_url,
                },
            )
        else:
            response = _source_request(_join_source_url(base_url, SOURCE_FIREWALL_STREAM_PATH), stream=True)

        if response is None:
            return []

        response.raise_for_status()

        for raw_line in response.iter_lines():
            if not raw_line:
                continue
            line = raw_line.decode("utf-8") if isinstance(raw_line, bytes) else str(raw_line)
            if not line.startswith("data:"):
                continue

            payload_text = line[5:].strip()
            if not payload_text:
                continue

            try:
                entry = json.loads(payload_text)
            except json.JSONDecodeError:
                continue

            if not isinstance(entry, dict):
                continue

            src = str(entry.get("src") or entry.get("srcip") or entry.get("source") or "")
            dst = str(entry.get("dst") or entry.get("dstip") or entry.get("destination") or "")
            proto = str(entry.get("proto") or entry.get("protocol") or "")
            action = str(entry.get("act") or entry.get("action") or "")
            occurred_at = _extract_timestamp(entry, now_iso)
            stable_id = str(entry.get("id") or entry.get("tracker") or f"{occurred_at}:{src}:{dst}:{proto}:{action}")

            rows.append(
                {
                    "id": stable_id,
                    "action": action,
                    "src": src,
                    "dst": dst,
                    "proto": proto,
                    "occurredAt": occurred_at,
                }
            )

            if len(rows) >= SOURCE_FIREWALL_MAX_EVENTS:
                break
    except Exception as exc:
        print(f"collector firewall fetch failed: {exc}")

    return rows


def _load_backend_webfilter_fetcher():
    module_path = Path(__file__).resolve().parents[3] / "backend" / "src" / "fetch_webfilter.py"
    if not module_path.exists():
        return None

    spec = importlib.util.spec_from_file_location("tfk_fetch_webfilter", module_path)
    if spec is None or spec.loader is None:
        return None

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return getattr(module, "fetch_webfilter_logs", None)


def _fetch_webfilter_rows_from_env(now_utc: datetime) -> list[dict[str, object]]:
    base_url = _normalize_source_base_url(SOURCE_OPNSENSE_BASE_URL)
    if not base_url or not SOURCE_MSD_USERNAME or not SOURCE_MSD_PASSWORD:
        return []

    fetcher = _load_backend_webfilter_fetcher()
    if fetcher is None:
        return []

    old_base = os.environ.get("TFK_BASE_URL")
    old_user = os.environ.get("TFK_MSD_USERNAME")
    old_password = os.environ.get("TFK_MSD_PASSWORD")
    old_debug = os.environ.get("TFK_DEBUG")
    try:
        os.environ["TFK_BASE_URL"] = base_url
        os.environ["TFK_MSD_USERNAME"] = SOURCE_MSD_USERNAME
        os.environ["TFK_MSD_PASSWORD"] = SOURCE_MSD_PASSWORD
        os.environ.setdefault("TFK_DEBUG", "0")

        result = fetcher("")
        if not isinstance(result, dict) or not result.get("ok"):
            return []

        entries = result.get("entries") or []
        if not isinstance(entries, list):
            return []

        now_iso = _to_iso(now_utc)
        rows: list[dict[str, object]] = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue

            time_field = str(entry.get("time") or "")
            occurred_at = time_field if "T" in time_field else now_iso
            user_value = str(entry.get("user") or "")
            ip_value = str(entry.get("ip") or "")
            source_entity = user_value if user_value else ip_value
            if not source_entity:
                source_entity = str(entry.get("url") or "")

            rows.append(
                {
                    "user": source_entity,
                    "url": str(entry.get("url") or ""),
                    "action": str(entry.get("action") or ""),
                    "category": str(entry.get("category") or ""),
                    "time": time_field,
                    "occurredAt": occurred_at,
                }
            )

        return rows
    except Exception as exc:
        print(f"collector webfilter fetch failed: {exc}")
        return []
    finally:
        if old_base is None:
            os.environ.pop("TFK_BASE_URL", None)
        else:
            os.environ["TFK_BASE_URL"] = old_base

        if old_user is None:
            os.environ.pop("TFK_MSD_USERNAME", None)
        else:
            os.environ["TFK_MSD_USERNAME"] = old_user

        if old_password is None:
            os.environ.pop("TFK_MSD_PASSWORD", None)
        else:
            os.environ["TFK_MSD_PASSWORD"] = old_password

        if old_debug is None:
            os.environ.pop("TFK_DEBUG", None)
        else:
            os.environ["TFK_DEBUG"] = old_debug


def _rows_for_source(source_key: str, now_utc: datetime) -> list[dict[str, object]]:
    if COLLECTOR_SAMPLE_MODE:
        return _sample_rows_for_source(source_key, now_utc)

    if source_key == "dhcp":
        return _fetch_dhcp_rows_from_env(now_utc)
    if source_key == "firewall":
        return _fetch_firewall_rows_from_env(now_utc)
    if source_key == "webfilter":
        return _fetch_webfilter_rows_from_env(now_utc)
    return []


def _migration_path(filename: str) -> Path:
    return Path(__file__).resolve().parent.parent / "db" / "migrations" / "versions" / filename


def _ensure_runtime_schema(connection: sqlite3.Connection) -> None:
    ensure_schema(connection)

    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS trend_aggregate (
            bucket_start TEXT NOT NULL,
            bucket_grain TEXT NOT NULL,
            source_type TEXT NOT NULL,
            event_count INTEGER NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (bucket_start, bucket_grain, source_type)
        );

        CREATE INDEX IF NOT EXISTS idx_trend_aggregate_source_grain_start
            ON trend_aggregate(source_type, bucket_grain, bucket_start DESC);
        """
    )

    auth_migration = _migration_path("0005_auth_sessions.sql").read_text(encoding="utf-8")
    connection.executescript(auth_migration)


def _bootstrap_user(connection: sqlite3.Connection) -> None:
    if not BOOTSTRAP_USERNAME:
        return

    if not BOOTSTRAP_PASSWORD:
        raise RuntimeError(
            "TFK_SERVER_BOOTSTRAP_PASSWORD must be set when TFK_SERVER_BOOTSTRAP_USERNAME is provided"
        )

    existing = connection.execute(
        "SELECT id FROM auth_users WHERE username = ?",
        (BOOTSTRAP_USERNAME,),
    ).fetchone()
    if existing:
        return

    now_iso = _to_iso(_utc_now())
    password_hash = bcrypt.hashpw(BOOTSTRAP_PASSWORD.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    connection.execute(
        """
        INSERT INTO auth_users (id, username, password_hash, role, is_active, created_at, updated_at)
        VALUES (?, ?, ?, ?, 1, ?, ?)
        """,
        (str(uuid4()), BOOTSTRAP_USERNAME, password_hash, BOOTSTRAP_ROLE, now_iso, now_iso),
    )


def initialize_database() -> None:
    db_file = Path(DB_PATH)
    db_file.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(DB_PATH) as connection:
        _ensure_runtime_schema(connection)
        _bootstrap_user(connection)
        connection.commit()


def _open_connection() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def _read_bearer_token(authorization: str | None) -> str:
    if not authorization:
        raise AuthHeaderError("missing_authorization_header")

    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise AuthHeaderError("invalid_authorization_header")

    return token.strip()


def _read_claims_and_role(authorization: str | None) -> tuple[dict[str, object], str]:
    token = _read_bearer_token(authorization)
    claims = decode_token(token, JWT_SECRET)

    role = claims.get("role")
    if not isinstance(role, str) or not role:
        raise AuthHeaderError("missing_role_claim")

    return claims, role


def _error_payload_from_exception(exc: Exception, request_id: str) -> dict[str, object]:
    if isinstance(exc, (AuthHeaderError, TokenDecodeError)):
        lower_reason = str(exc).lower()
        error_code = ERR_TOKEN_EXPIRED if "expired" in lower_reason else ERR_TOKEN_INVALID
        return build_error_response(
            error_code=error_code,
            message="authentication failed",
            request_id=request_id,
            details={"reason": str(exc)},
            status=status_for_error_code(error_code),
        )

    return handle_exception(exc, request_id)


def _json_error(exc: Exception, request_id: str) -> JSONResponse:
    payload = _error_payload_from_exception(exc, request_id)
    return JSONResponse(status_code=int(payload.get("status", 500)), content=payload)


def _json_proxy_error(error_code: str, message: str, request_id: str, details: dict[str, object]) -> JSONResponse:
    payload = build_error_response(
        error_code=error_code,
        message=message,
        request_id=request_id,
        details=details,
        status=status_for_error_code(error_code),
    )
    return JSONResponse(status_code=int(payload["status"]), content=payload)


def _proxy_target_from_payload(payload: dict[str, object]) -> str:
    for key in ("ip", "mac", "hostname", "oldmac", "iface"):
        value = payload.get(key)
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return "n/a"


def _write_proxy_audit(
    *,
    request_id: str,
    actor_id: str,
    actor_role: str,
    scope: str,
    operation: str,
    target: str,
    status: str,
    error_code: str | None,
    details: dict[str, object],
) -> None:
    with _open_connection() as connection:
        write_proxy_operation_audit(
            connection,
            request_id=request_id,
            actor_id=actor_id or "unknown",
            actor_role=actor_role,
            scope=scope,
            operation=operation,
            target=target,
            status=status,
            error_code=error_code,
            details_json=json.dumps(details, ensure_ascii=True, sort_keys=True),
            created_at=_to_iso(_utc_now()),
        )
        connection.commit()


def _load_source_statuses(connection: sqlite3.Connection) -> list:
    rows = connection.execute(
        """
        SELECT source_key, cursor, last_success_at, last_error_at, error_count, lag_seconds
        FROM ingestion_checkpoints
        """
    ).fetchall()
    by_source = {str(row["source_key"]): row for row in rows}

    status_inputs: list[dict[str, object]] = []
    for source_key in SOURCE_POLICY:
        row = by_source.get(source_key)
        status_inputs.append(
            {
                "sourceKey": source_key,
                "checkpointCursor": "" if row is None else str(row["cursor"]),
                "lagSeconds": 0 if row is None else int(row["lag_seconds"]),
                "errorCount": 0 if row is None else int(row["error_count"]),
                "replayBacklog": 0,
                "lastSuccessAt": None if row is None else row["last_success_at"],
                "lastErrorAt": None if row is None else row["last_error_at"],
            }
        )

    return evaluate_all_sources(status_inputs, _utc_now())


def _load_worker_state_from_db(connection: sqlite3.Connection) -> dict[str, dict[str, object]]:
    rows = connection.execute(
        """
        SELECT source_key, cursor
        FROM ingestion_checkpoints
        """
    ).fetchall()
    cursor_by_source = {str(row["source_key"]): str(row["cursor"]) for row in rows}

    return {
        source_key: create_worker_state(source_key, cursor=cursor_by_source.get(source_key, ""))
        for source_key in SOURCE_POLICY
    }


def _sample_rows_for_source(source_key: str, now_utc: datetime) -> list[dict[str, object]]:
    now_iso = _to_iso(now_utc)
    ts_token = now_utc.strftime("%Y%m%d%H%M%S")

    if source_key == "dhcp":
        return [
            {
                "mac": "AA:BB:CC:DD:EE:01",
                "ip": "10.0.0.101",
                "hostname": "demo-dhcp",
                "leaseEnd": _to_iso(now_utc.replace(microsecond=0)),
                "occurredAt": now_iso,
            }
        ]

    if source_key == "firewall":
        return [
            {
                "id": f"fw-{ts_token}",
                "action": "block",
                "src": "10.0.0.101",
                "dst": "8.8.8.8",
                "proto": "tcp",
                "occurredAt": now_iso,
            }
        ]

    if source_key == "webfilter":
        return [
            {
                "user": "demo.user",
                "url": f"https://example.local/{ts_token}",
                "action": "allow",
                "category": "Education",
                "time": now_iso,
                "occurredAt": now_iso,
            }
        ]

    return []


def _adapter_for_source(source_key: str) -> Callable[[str | None, datetime, list[dict[str, object]] | None], tuple[list[dict[str, object]], str]]:
    adapters: dict[str, Callable[[str | None, datetime, list[dict[str, object]] | None], tuple[list[dict[str, object]], str]]] = {
        "dhcp": dhcp_adapter.fetch_batch,
        "firewall": firewall_adapter.fetch_batch,
        "webfilter": webfilter_adapter.fetch_batch,
    }
    return adapters[source_key]


def _run_collector_iteration() -> None:
    now_utc = _utc_now()
    iteration_id = uuid4().hex[:8]
    mode = "sample" if COLLECTOR_SAMPLE_MODE else "live"
    print(
        f"collector refresh start id={iteration_id} at={_to_iso(now_utc)} "
        f"mode={mode} intervalSeconds={COLLECTOR_INTERVAL_SECONDS}"
    )

    def _safe_int(value: object) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0

    total_fetched = 0
    total_new_saved = 0
    success_count = 0
    retry_wait_count = 0
    error_count = 0

    with _open_connection() as connection:
        global _collector_state_by_source
        if not _collector_state_by_source:
            _collector_state_by_source = _load_worker_state_from_db(connection)

        for source_key in SOURCE_POLICY:
            state = _collector_state_by_source[source_key]
            adapter_fetch = _adapter_for_source(source_key)
            source_rows = _rows_for_source(source_key, now_utc)

            def _fetch(cursor: str | None, run_now: datetime):
                return adapter_fetch(cursor, run_now, source_rows)

            run_worker_iteration(
                source_key=source_key,
                state=state,
                adapter_fetch=_fetch,
                connection=connection,
                now_utc=now_utc,
            )

            outcome = str(state.get("lastRunOutcome") or "unknown")
            fetched_count = _safe_int(state.get("lastFetchedCount"))
            unique_count = _safe_int(state.get("lastUniqueEventCount"))
            new_saved_count = _safe_int(state.get("lastNewEventsSaved"))
            db_total_count = _safe_int(state.get("lastDbEventCount"))
            recomputed_windows = _safe_int(state.get("lastRecomputedWindows"))
            source_rows_count = len(source_rows)

            if outcome == "success":
                success_count += 1
                total_fetched += fetched_count
                total_new_saved += new_saved_count
                print(
                    f"collector refresh source={source_key} outcome=success seedRows={source_rows_count} "
                    f"fetched={fetched_count} unique={unique_count} newSaved={new_saved_count} "
                    f"dbTotal={db_total_count} recomputedWindows={recomputed_windows} "
                    f"cursor={state.get('cursor', '')}"
                )
                continue

            if outcome == "retry_wait":
                retry_wait_count += 1
                print(
                    f"collector refresh source={source_key} outcome=retry_wait "
                    f"attempt={_safe_int(state.get('attempt'))} outageSeconds={_safe_int(state.get('outageSeconds'))} "
                    f"nextRetryAt={state.get('nextRetryAt')}"
                )
                continue

            if outcome == "error":
                error_count += 1
                print(
                    f"collector refresh source={source_key} outcome=error seedRows={source_rows_count} "
                    f"attempt={_safe_int(state.get('attempt'))} outageSeconds={_safe_int(state.get('outageSeconds'))} "
                    f"fallbackRecommended={bool(state.get('fallbackRecommended'))} "
                    f"nextRetryAt={state.get('nextRetryAt')} lastErrorAt={state.get('lastErrorAt')}"
                )
                continue

            print(
                f"collector refresh source={source_key} outcome={outcome} seedRows={source_rows_count} "
                f"cursor={state.get('cursor', '')}"
            )

    elapsed_ms = int((_utc_now() - now_utc).total_seconds() * 1000)
    print(
        f"collector refresh end id={iteration_id} success={success_count} "
        f"retryWait={retry_wait_count} error={error_count} totalFetched={total_fetched} "
        f"totalNewSaved={total_new_saved} elapsedMs={elapsed_ms}"
    )


def _run_collector_if_due(force: bool = False) -> None:
    global _collector_last_run_at
    if not COLLECTOR_ENABLED:
        return

    with _collector_run_lock:
        now_utc = _utc_now()
        if (
            not force
            and _collector_last_run_at is not None
            and (now_utc - _collector_last_run_at).total_seconds() < COLLECTOR_INTERVAL_SECONDS
        ):
            return

        _run_collector_iteration()
        _collector_last_run_at = now_utc


def _collector_loop() -> None:
    while not _collector_stop_event.is_set():
        try:
            _run_collector_iteration()
        except Exception as exc:
            print(f"collector iteration failed: {exc}")
        _collector_stop_event.wait(COLLECTOR_INTERVAL_SECONDS)


def _start_background_collector() -> None:
    global _collector_thread, _collector_state_by_source
    if not COLLECTOR_ENABLED:
        print("collector disabled by TFK_SERVER_COLLECTOR_ENABLED")
        return

    with _open_connection() as connection:
        _collector_state_by_source = _load_worker_state_from_db(connection)

    _collector_stop_event.clear()
    _collector_thread = threading.Thread(target=_collector_loop, name="tfk-server-collector", daemon=True)
    _collector_thread.start()
    mode = "sample" if COLLECTOR_SAMPLE_MODE else "live"
    print(
        f"collector background thread started intervalSeconds={COLLECTOR_INTERVAL_SECONDS} "
        f"mode={mode} sources={','.join(SOURCE_POLICY.keys())}"
    )


def _stop_background_collector() -> None:
    global _collector_thread
    _collector_stop_event.set()
    if _collector_thread is not None:
        _collector_thread.join(timeout=2.0)
        _collector_thread = None
        print("collector background thread stopped")


@app.on_event("startup")
def on_startup() -> None:
    initialize_database()
    _run_collector_if_due(force=True)
    _start_background_collector()


@app.on_event("shutdown")
def on_shutdown() -> None:
    _stop_background_collector()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "database": DB_PATH}


@app.post("/api/auth/login")
def auth_login(body: LoginBody):
    try:
        with _open_connection() as connection:
            response = authenticate_user(
                username=body.username,
                password=body.password,
                connection=connection,
                now_utc=_utc_now(),
                secret=JWT_SECRET,
            )
        return response.to_dict()
    except AuthenticationError as exc:
        payload = build_error_response(
            error_code=ERR_TOKEN_INVALID,
            message="authentication failed",
            request_id="auth-login",
            details={"reason": str(exc)},
            status=status_for_error_code(ERR_TOKEN_INVALID),
        )
        return JSONResponse(status_code=int(payload["status"]), content=payload)
    except Exception as exc:
        return _json_error(exc, "auth-login")


@app.post("/api/auth/refresh")
def auth_refresh(body: RefreshBody):
    try:
        with _open_connection() as connection:
            response = refresh_session(
                refresh_token=body.refreshToken,
                connection=connection,
                now_utc=_utc_now(),
                secret=JWT_SECRET,
            )
        return response.to_dict()
    except Exception as exc:
        return _json_error(exc, "auth-refresh")


@app.get("/api/history/events")
def history_events(
    startAt: str = Query(...),
    endAt: str = Query(...),
    sourceType: str | None = Query(default=None),
    cursor: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    authorization: str | None = Header(default=None, alias="Authorization"),
):
    try:
        _run_collector_if_due()
        _, role = _read_claims_and_role(authorization)
        query = EventsQuery(
            startAt=startAt,
            endAt=endAt,
            sourceType=sourceType,
            cursor=cursor,
            limit=limit,
        )
        with _open_connection() as connection:
            payload = get_historical_events(query=query, role=role, connection=connection)
        return payload
    except Exception as exc:
        return _json_error(exc, "history-events")


@app.get("/api/history/trends")
def history_trends(
    startAt: str = Query(...),
    endAt: str = Query(...),
    sourceType: str | None = Query(default=None),
    bucketGrain: str = Query(default="coarse"),
    authorization: str | None = Header(default=None, alias="Authorization"),
):
    try:
        _run_collector_if_due()
        _, role = _read_claims_and_role(authorization)
        query = TrendsQuery(
            startAt=startAt,
            endAt=endAt,
            sourceType=sourceType,
            bucketGrain=bucketGrain,
        )
        with _open_connection() as connection:
            payload = get_historical_trends(query=query, role=role, connection=connection)
        return payload
    except Exception as exc:
        return _json_error(exc, "history-trends")


@app.get("/api/status/freshness")
def status_freshness(
    authorization: str | None = Header(default=None, alias="Authorization"),
):
    try:
        _run_collector_if_due()
        claims, role = _read_claims_and_role(authorization)
        with _open_connection() as connection:
            source_statuses = _load_source_statuses(connection)

        payload = get_freshness_status(
            role=role,
            token_claims=claims,
            source_statuses=source_statuses,
        )
        status_code = int(payload.get("status", 200))
        return JSONResponse(status_code=status_code, content=payload)
    except Exception as exc:
        return _json_error(exc, "status-freshness")


@app.post("/api/proxy/execute")
def proxy_execute(
    body: ProxyOperationRequest,
    authorization: str | None = Header(default=None, alias="Authorization"),
    xProxySignature: str | None = Header(default=None, alias="X-Proxy-Signature"),
):
    request_id = f"proxy-{uuid4()}"
    claims: dict[str, object]
    role: str
    try:
        claims, role = _read_claims_and_role(authorization)
    except Exception as exc:
        return _json_error(exc, request_id)

    actor_id = str(claims.get("sub") or "")
    target = _proxy_target_from_payload(body.payload)

    allowed, reason = role_allows_proxy_operation(role, body.operation)
    if not allowed:
        _write_proxy_audit(
            request_id=request_id,
            actor_id=actor_id,
            actor_role=role,
            scope="n/a",
            operation=body.operation,
            target=target,
            status="denied",
            error_code=ERR_FORBIDDEN if reason == "forbidden" else ERR_PROXY_OPERATION,
            details={"reason": reason},
        )
        return _json_proxy_error(
            error_code=ERR_FORBIDDEN if reason == "forbidden" else ERR_PROXY_OPERATION,
            message="proxy operation denied",
            request_id=request_id,
            details={"operation": body.operation, "reason": reason},
        )

    try:
        scope = required_scope_for_operation(body.operation)
        security_context = validate_proxy_request(
            request=body,
            signature_header=xProxySignature or "",
            request_id=request_id,
            scope=scope,
        )
    except ProxySecurityError as exc:
        _write_proxy_audit(
            request_id=request_id,
            actor_id=actor_id,
            actor_role=role,
            scope="n/a",
            operation=body.operation,
            target=target,
            status="denied",
            error_code=ERR_PROXY_SECURITY,
            details={"reason": exc.reason},
        )
        return _json_proxy_error(
            error_code=ERR_PROXY_SECURITY,
            message="proxy security validation failed",
            request_id=request_id,
            details={"operation": body.operation, "reason": exc.reason},
        )
    except Exception as exc:
        return _json_error(exc, request_id)

    try:
        result = proxy_execute_operation(body.operation, body.payload)
        _write_proxy_audit(
            request_id=request_id,
            actor_id=actor_id,
            actor_role=role,
            scope=security_context.scope,
            operation=body.operation,
            target=target,
            status="success",
            error_code=None,
            details={"resultSummary": "ok"},
        )
        return {
            "requestId": request_id,
            "operation": body.operation,
            "scope": security_context.scope,
            "result": result,
        }
    except ProxyOperationError as exc:
        _write_proxy_audit(
            request_id=request_id,
            actor_id=actor_id,
            actor_role=role,
            scope=security_context.scope,
            operation=body.operation,
            target=target,
            status="failed",
            error_code=exc.error_code,
            details=exc.details,
        )
        return JSONResponse(
            status_code=exc.status,
            content=build_error_response(
                error_code=exc.error_code,
                message=exc.message,
                request_id=request_id,
                details={"operation": body.operation, **exc.details},
                status=exc.status,
            ),
        )
    except Exception as exc:
        _write_proxy_audit(
            request_id=request_id,
            actor_id=actor_id,
            actor_role=role,
            scope=security_context.scope,
            operation=body.operation,
            target=target,
            status="failed",
            error_code="internal_error",
            details={"reason": str(exc)},
        )
        return _json_error(exc, request_id)


@app.get("/api/proxy/operations/{requestId}")
def proxy_operation_status(
    requestId: str,
    authorization: str | None = Header(default=None, alias="Authorization"),
):
    request_id = f"proxy-status-{requestId}"
    try:
        claims, role = _read_claims_and_role(authorization)
    except Exception as exc:
        return _json_error(exc, request_id)

    with _open_connection() as connection:
        record = get_proxy_operation_audit_by_request_id(connection, requestId)

    if record is None:
        return _json_proxy_error(
            error_code=ERR_PROXY_NOT_FOUND,
            message="proxy operation requestId not found",
            request_id=request_id,
            details={"requestId": requestId},
        )

    # Analysts can only query their own operation status.
    actor_id = str(claims.get("sub") or "")
    if role != "admin" and str(record.get("actorId") or "") != actor_id:
        return _json_proxy_error(
            error_code=ERR_FORBIDDEN,
            message="proxy operation status forbidden",
            request_id=request_id,
            details={"requestId": requestId},
        )

    try:
        return proxy_get_operation_status(record)
    except ProxyOperationError as exc:
        return JSONResponse(
            status_code=exc.status,
            content=build_error_response(
                error_code=exc.error_code,
                message=exc.message,
                request_id=request_id,
                details=exc.details,
                status=exc.status,
            ),
        )
