from __future__ import annotations

from server.app.api.auth_service import TokenRefreshError
from server.app.api.error_contract import (
    ERR_FORBIDDEN,
    ERR_INTERNAL,
    ERR_QUERY_INVALID,
    ERR_TOKEN_EXPIRED,
    ERR_TOKEN_INVALID,
    build_error_response,
    status_for_error_code,
)


def handle_exception(exc: Exception, request_id: str) -> dict[str, object]:
    if isinstance(exc, TokenRefreshError):
        error_code = ERR_TOKEN_EXPIRED if "expired" in str(exc) else ERR_TOKEN_INVALID
        return build_error_response(
            error_code=error_code,
            message="authentication failed",
            request_id=request_id,
            details={"reason": str(exc)},
            status=status_for_error_code(error_code),
        )

    if isinstance(exc, PermissionError):
        return build_error_response(
            error_code=ERR_FORBIDDEN,
            message="insufficient permissions",
            request_id=request_id,
            details={"reason": str(exc)},
            status=status_for_error_code(ERR_FORBIDDEN),
        )

    if isinstance(exc, ValueError):
        return build_error_response(
            error_code=ERR_QUERY_INVALID,
            message="invalid request",
            request_id=request_id,
            details={"reason": str(exc)},
            status=status_for_error_code(ERR_QUERY_INVALID),
        )

    return build_error_response(
        error_code=ERR_INTERNAL,
        message="internal server error",
        request_id=request_id,
        details={"reason": str(exc)},
        status=status_for_error_code(ERR_INTERNAL),
    )
