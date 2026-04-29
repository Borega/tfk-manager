from __future__ import annotations

ROLE_POLICY: dict[str, dict[str, set[str]]] = {
    "/api/history/events": {
        "GET": {"analyst", "admin"},
    },
    "/api/history/trends": {
        "GET": {"analyst", "admin"},
    },
    "/api/analysis/dashboard": {
        "GET": {"analyst", "admin"},
    },
    "/api/status/freshness": {
        "GET": {"analyst", "admin"},
    },
    "/api/admin/*": {
        "GET": {"admin"},
        "POST": {"admin"},
        "PUT": {"admin"},
        "DELETE": {"admin"},
    },
}


def _resolve_endpoint_policy(endpoint: str) -> dict[str, set[str]] | None:
    direct = ROLE_POLICY.get(endpoint)
    if direct is not None:
        return direct

    if endpoint.startswith("/api/admin/"):
        return ROLE_POLICY.get("/api/admin/*")

    return None


def authorize_request(role: str, endpoint: str, method: str) -> tuple[bool, str]:
    if role not in {"analyst", "admin"}:
        return False, "role_unknown"

    policy = _resolve_endpoint_policy(endpoint)
    if policy is None:
        return False, "endpoint_unmapped"

    allowed_roles = policy.get(method.upper())
    if allowed_roles is None:
        return False, "method_not_allowed"

    if role not in allowed_roles:
        return False, "forbidden"

    return True, "allowed"
