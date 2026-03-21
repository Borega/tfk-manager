from __future__ import annotations

ERR_TOKEN_EXPIRED = "token_expired"
ERR_TOKEN_INVALID = "token_invalid"
ERR_FORBIDDEN = "forbidden"
ERR_QUERY_INVALID = "query_invalid"
ERR_INTERNAL = "internal_error"

STATUS_BY_ERROR_CODE = {
    ERR_TOKEN_EXPIRED: 401,
    ERR_TOKEN_INVALID: 401,
    ERR_FORBIDDEN: 403,
    ERR_QUERY_INVALID: 422,
    ERR_INTERNAL: 500,
}


def status_for_error_code(error_code: str) -> int:
    return STATUS_BY_ERROR_CODE.get(error_code, 500)


def build_error_response(
    error_code: str,
    message: str,
    request_id: str,
    details: dict[str, object] | None = None,
    status: int = 400,
) -> dict[str, object]:
    return {
        "status": status,
        "errorCode": error_code,
        "message": message,
        "requestId": request_id,
        "details": details or {},
    }
