from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
from typing import Any

from server.app.api.proxy_operation_errors import ProxyOperationError

SOURCE_BASE_URL = os.getenv("TFK_SOURCE_OPNSENSE_BASE_URL", "").strip().rstrip("/")
SOURCE_USERNAME = os.getenv("TFK_SOURCE_OPNSENSE_USERNAME", "").strip()
SOURCE_PASSWORD = os.getenv("TFK_SOURCE_OPNSENSE_PASSWORD", "").strip()
SOURCE_COOKIE_HEADER = os.getenv("TFK_SOURCE_COOKIE_HEADER", "").strip()
SOURCE_MSD_COOKIE = os.getenv("TFK_SOURCE_MSD_COOKIE", "").strip()
SOURCE_VERIFY_TLS = os.getenv("TFK_SOURCE_VERIFY_TLS", "0").strip().lower() in {"1", "true", "yes", "y"}
SOURCE_CONNECT_TIMEOUT_SECONDS = max(3, int(os.getenv("TFK_SOURCE_CONNECT_TIMEOUT_SECONDS", "10")))
SOURCE_READ_TIMEOUT_SECONDS = max(5, int(os.getenv("TFK_SOURCE_READ_TIMEOUT_SECONDS", "30")))
SOURCE_FIREWALL_MAX_EVENTS = max(1, int(os.getenv("TFK_SOURCE_FIREWALL_MAX_EVENTS", "25")))
SOURCE_FIREWALL_STREAM_PATH = os.getenv("TFK_SOURCE_FIREWALL_STREAM_PATH", "/api/diagnostics/firewall/streamLog").strip() or "/api/diagnostics/firewall/streamLog"


def _source_timeout() -> tuple[int, int]:
    return (SOURCE_CONNECT_TIMEOUT_SECONDS, SOURCE_READ_TIMEOUT_SECONDS)


def _map_iface(value: str) -> str:
    text = value.strip()
    mapping = {
        "Gruen": "lan",
        "WLANBYOD": "opt4",
        "lan": "lan",
        "opt4": "opt4",
    }
    return mapping.get(text, text)


def _load_backend_module():
    module_path = Path(__file__).resolve().parents[3] / "backend" / "src" / "opnsense_dhcp_ui.py"
    if not module_path.exists():
        raise ProxyOperationError("proxy_backend_missing", "Backend script opnsense_dhcp_ui.py not found", status=500)

    spec = importlib.util.spec_from_file_location("tfk_opnsense_dhcp_ui", module_path)
    if spec is None or spec.loader is None:
        raise ProxyOperationError("proxy_backend_load_failed", "Failed to load backend script", status=500)

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _create_authenticated_session(module):
    if not SOURCE_BASE_URL:
        raise ProxyOperationError("proxy_source_missing", "TFK_SOURCE_OPNSENSE_BASE_URL is not configured", status=422)

    session = module.OPNsenseApiSession(SOURCE_BASE_URL, debug=False)

    if SOURCE_COOKIE_HEADER:
        session._apply_cookie_header(SOURCE_COOKIE_HEADER)  # noqa: SLF001
        if SOURCE_MSD_COOKIE:
            session.session.cookies.set("MSD_Cookie", SOURCE_MSD_COOKIE, path="/")

    if SOURCE_USERNAME and SOURCE_PASSWORD:
        authenticated = session.authenticate(
            SOURCE_USERNAME,
            SOURCE_PASSWORD,
            cookie_header=SOURCE_COOKIE_HEADER,
            msd_cookie=SOURCE_MSD_COOKIE,
        )
        if not authenticated:
            raise ProxyOperationError("proxy_source_auth_failed", "OPNsense GUI authentication failed", status=401)
    elif not SOURCE_COOKIE_HEADER:
        raise ProxyOperationError(
            "proxy_source_credentials_missing",
            "Configure source credentials or cookie header for delegated operations",
            status=422,
        )

    session.session.verify = SOURCE_VERIFY_TLS
    return session


def _extract_rows_from_api_payload(data: object) -> list[dict[str, object]]:
    if isinstance(data, dict):
        rows = data.get("rows")
        if isinstance(rows, list):
            return [row for row in rows if isinstance(row, dict)]
    if isinstance(data, list):
        return [row for row in data if isinstance(row, dict)]
    return []


def _walk_payload_dicts(node: object) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []

    def walk(value: object) -> None:
        if isinstance(value, dict):
            rows.append(value)
            for nested in value.values():
                walk(nested)
            return
        if isinstance(value, list):
            for nested in value:
                walk(nested)

    walk(node)
    return rows


def _normalize_static_iface(value: object) -> str:
    text = str(value or "").strip().lower()
    if text in {"lan", "gruen"}:
        return "lan"
    if text in {"opt4", "wlanbyod"}:
        return "opt4"
    return ""


def _collect_static_rows_with_iface(payload: object) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for item in _walk_payload_dicts(payload):
        item_ci = {str(key).lower(): value for key, value in item.items()}
        hostname = str(item_ci.get("hostname") or item_ci.get("name") or "").strip()
        mac = str(item_ci.get("mac") or "").strip()
        ip = str(item_ci.get("ip") or item_ci.get("ipv4") or item_ci.get("address") or "").strip()
        iface = _normalize_static_iface(item_ci.get("iface") or item_ci.get("if") or item_ci.get("interface"))
        if not hostname or not mac or not ip:
            continue
        dedupe_key = (hostname, mac, ip, iface)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        rows.append({"hostname": hostname, "mac": mac, "ip": ip, "iface": iface})
    return rows


def _get_static_rows_with_iface(module, session) -> list[dict[str, object]]:
    fetch_raw = getattr(module, "_fetch_static_leases_raw", None)
    if callable(fetch_raw):
        raw_payload = fetch_raw(session)
        rows = _collect_static_rows_with_iface(raw_payload)
        if rows:
            return rows

    entries = module.fetch_static_leases_via_session_api(session)
    return [{"hostname": row.hostname, "mac": row.mac, "ip": row.ip, "iface": ""} for row in entries]


def _raise_on_failed_result(result: dict[str, object], operation: str) -> None:
    status_value = str(result.get("status") or "")
    if status_value in {"", "success", "ok"}:
        return

    if status_value in {"failed", "validation_failed", "find_lease_failed", "error", "unauthenticated", "non_json"}:
        raise ProxyOperationError(
            "proxy_source_rejected",
            f"Source rejected {operation} ({status_value})",
            status=400,
            details={"operation": operation, "sourceStatus": status_value, "result": result},
        )


def _firewall_snapshot(session, limit: int) -> list[dict[str, object]]:
    response = session.session.get(
        f"{SOURCE_BASE_URL}{SOURCE_FIREWALL_STREAM_PATH}",
        stream=True,
        timeout=_source_timeout(),
        headers={
            "Accept": "text/event-stream, application/json, */*",
            "X-Requested-With": "XMLHttpRequest",
            "Referer": f"{SOURCE_BASE_URL}/ui/diagnostics/firewall/log",
            "Origin": SOURCE_BASE_URL,
        },
    )
    response.raise_for_status()

    items: list[dict[str, object]] = []
    for raw_line in response.iter_lines():
        if not raw_line:
            continue
        line = raw_line.decode("utf-8") if isinstance(raw_line, bytes) else str(raw_line)
        if not line.startswith("data:"):
            continue
        payload = line[5:].strip()
        if not payload:
            continue
        try:
            entry = json.loads(payload)
        except json.JSONDecodeError:
            continue
        if isinstance(entry, dict):
            items.append(entry)
        if len(items) >= limit:
            break

    return items


def execute_opnsense_operation(operation: str, payload: dict[str, object]) -> dict[str, object]:
    module = _load_backend_module()
    session = _create_authenticated_session(module)

    if operation == "getDynamicLeases":
        entries = module.fetch_dynamic_leases_via_session_api(session)
        return {
            "ok": True,
            "rows": [entry.to_dict() for entry in entries],
            "count": len(entries),
        }

    if operation == "getStaticLeases":
        rows = _get_static_rows_with_iface(module, session)
        return {"ok": True, "rows": rows, "count": len(rows)}

    if operation == "getFirewallSnapshot":
        requested_limit = int(payload.get("limit") or SOURCE_FIREWALL_MAX_EVENTS)
        limit = max(1, min(requested_limit, 200))
        rows = _firewall_snapshot(session, limit)
        return {"ok": True, "rows": rows, "count": len(rows)}

    if operation == "addStaticLease":
        iface = _map_iface(str(payload.get("iface") or ""))
        result = session.api_post(
            "/api/tfk/dhcp/add_static_lease",
            {
                "if": iface,
                "ip": str(payload.get("ip") or "").strip(),
                "mac": str(payload.get("mac") or "").strip(),
                "hostname": str(payload.get("hostname") or "").strip(),
            },
        )
        _raise_on_failed_result(result, operation)
        return {"ok": True, "result": result}

    if operation == "updateStaticLease":
        iface = _map_iface(str(payload.get("iface") or ""))
        result = session.api_post(
            "/api/tfk/dhcp/update_static_lease",
            {
                "if": iface,
                "oldmac": str(payload.get("oldmac") or "").strip(),
                "ip": str(payload.get("ip") or "").strip(),
                "mac": str(payload.get("mac") or "").strip(),
                "hostname": str(payload.get("hostname") or "").strip(),
            },
        )
        _raise_on_failed_result(result, operation)
        return {"ok": True, "result": result}

    if operation == "deleteStaticLease":
        iface = _map_iface(str(payload.get("iface") or ""))
        result = session.api_post(
            "/api/tfk/dhcp/del_static_lease",
            {
                "if": iface,
                "mac": str(payload.get("mac") or "").strip(),
            },
        )
        _raise_on_failed_result(result, operation)
        return {"ok": True, "result": result}

    if operation == "moveDynamicToStatic":
        result = module.move_dynamic_lease_to_static(
            session,
            iface=str(payload.get("iface") or ""),
            ip=str(payload.get("ip") or ""),
            mac=str(payload.get("mac") or ""),
            hostname=str(payload.get("hostname") or ""),
        )
        if not bool(result.get("ok")):
            raise ProxyOperationError(
                "proxy_source_rejected",
                "Source rejected move dynamic to static",
                status=400,
                details={"operation": operation, "result": result},
            )
        return result

    if operation == "updateStaticFromDynamic":
        result = module.update_static_from_dynamic_conflict(
            session,
            old_mac=str(payload.get("oldmac") or ""),
            iface=str(payload.get("iface") or ""),
            ip=str(payload.get("ip") or ""),
            mac=str(payload.get("mac") or ""),
            hostname=str(payload.get("hostname") or ""),
        )
        if not bool(result.get("ok")):
            raise ProxyOperationError(
                "proxy_source_rejected",
                "Source rejected update static from dynamic",
                status=400,
                details={"operation": operation, "result": result},
            )
        return result

    raise ProxyOperationError("proxy_operation_invalid", f"Unsupported OPNsense operation: {operation}", status=422)
