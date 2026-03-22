from __future__ import annotations

import importlib.util
import os
from pathlib import Path

from server.app.api.proxy_operation_errors import ProxyOperationError

SOURCE_BASE_URL = os.getenv("TFK_SOURCE_OPNSENSE_BASE_URL", "").strip().rstrip("/")
SOURCE_MSD_USERNAME = os.getenv("TFK_MSD_USERNAME", "").strip()
SOURCE_MSD_PASSWORD = os.getenv("TFK_MSD_PASSWORD", "").strip()
SOURCE_COOKIE_HEADER = os.getenv("TFK_SOURCE_COOKIE_HEADER", "").strip()


def _load_backend_module():
    module_path = Path(__file__).resolve().parents[3] / "backend" / "src" / "fetch_webfilter.py"
    if not module_path.exists():
        raise ProxyOperationError("proxy_backend_missing", "Backend script fetch_webfilter.py not found", status=500)

    spec = importlib.util.spec_from_file_location("tfk_fetch_webfilter", module_path)
    if spec is None or spec.loader is None:
        raise ProxyOperationError("proxy_backend_load_failed", "Failed to load webfilter backend script", status=500)

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _with_webfilter_env(callable_fn):
    old_base = os.environ.get("TFK_BASE_URL")
    old_user = os.environ.get("TFK_MSD_USERNAME")
    old_password = os.environ.get("TFK_MSD_PASSWORD")
    old_cookie = os.environ.get("TFK_COOKIE_HEADER")
    try:
        os.environ["TFK_BASE_URL"] = SOURCE_BASE_URL
        os.environ["TFK_MSD_USERNAME"] = SOURCE_MSD_USERNAME
        os.environ["TFK_MSD_PASSWORD"] = SOURCE_MSD_PASSWORD
        if SOURCE_COOKIE_HEADER:
            os.environ["TFK_COOKIE_HEADER"] = SOURCE_COOKIE_HEADER
        return callable_fn()
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

        if old_cookie is None:
            os.environ.pop("TFK_COOKIE_HEADER", None)
        else:
            os.environ["TFK_COOKIE_HEADER"] = old_cookie


def execute_webfilter_operation(operation: str, payload: dict[str, object]) -> dict[str, object]:
    if not SOURCE_BASE_URL:
        raise ProxyOperationError("proxy_source_missing", "TFK_SOURCE_OPNSENSE_BASE_URL is not configured", status=422)

    module = _load_backend_module()

    if operation == "testWebfilterLogin":
        result = _with_webfilter_env(module.run_webfilter_test)
        if not bool(result.get("ok")):
            raise ProxyOperationError(
                "proxy_source_rejected",
                "Webfilter login/session test failed",
                status=400,
                details={"operation": operation, "result": result},
            )
        return result

    if operation == "getWebfilterLogs":
        search_text = str(payload.get("searchText") or "")
        result = _with_webfilter_env(lambda: module.fetch_webfilter_logs(search_text))
        if not bool(result.get("ok")):
            raise ProxyOperationError(
                "proxy_source_rejected",
                "Webfilter log fetch failed",
                status=400,
                details={"operation": operation, "result": result},
            )
        return result

    raise ProxyOperationError("proxy_operation_invalid", f"Unsupported webfilter operation: {operation}", status=422)
