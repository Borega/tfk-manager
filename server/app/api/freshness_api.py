from __future__ import annotations

from server.app.api.authz_policy import authorize_request
from server.app.api.error_contract import (
    ERR_FORBIDDEN,
    ERR_TOKEN_INVALID,
    build_error_response,
    status_for_error_code,
)
from server.app.contracts.reliability_status import SourceReliabilityStatus
from server.app.interfaces.status_cli import build_status_payload


def get_freshness_status(
    role: str,
    token_claims: dict[str, object] | None,
    source_statuses: list[SourceReliabilityStatus],
) -> dict[str, object]:
    if not token_claims or not token_claims.get("sub"):
        return build_error_response(
            error_code=ERR_TOKEN_INVALID,
            message="missing or invalid token",
            request_id="freshness-auth",
            details={"reason": "missing_subject_claim"},
            status=status_for_error_code(ERR_TOKEN_INVALID),
        )

    allowed, reason = authorize_request(role, "/api/status/freshness", "GET")
    if not allowed:
        return build_error_response(
            error_code=ERR_FORBIDDEN,
            message="insufficient permissions",
            request_id="freshness-authz",
            details={"reason": reason},
            status=status_for_error_code(ERR_FORBIDDEN),
        )

    payload = build_status_payload(source_statuses)
    return {
        "status": 200,
        "data": payload,
    }
