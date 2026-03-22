from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from server.app.api.proxy_contracts import ProxyOperationRequest

PROXY_HMAC_SHARED_SECRET = os.getenv("TFK_PROXY_HMAC_SHARED_SECRET", "").strip()
PROXY_REQUEST_AUDIENCE = os.getenv("TFK_PROXY_REQUEST_AUDIENCE", "tfk-manager-server").strip() or "tfk-manager-server"
PROXY_MAX_SKEW_SECONDS = max(5, int(os.getenv("TFK_PROXY_MAX_SKEW_SECONDS", "120")))
PROXY_NONCE_TTL_SECONDS = max(30, int(os.getenv("TFK_PROXY_NONCE_TTL_SECONDS", "300")))

_NONCE_EXPIRY: dict[str, datetime] = {}


class ProxySecurityError(RuntimeError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class ProxySecurityContext:
    request_id: str
    operation: str
    nonce: str
    scope: str
    timestamp: str
    audience: str


def _parse_timestamp(value: str) -> datetime:
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _canonical_payload(payload: dict[str, object]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _build_signature_base(request: ProxyOperationRequest) -> str:
    return "\n".join(
        [
            request.operation,
            request.requestNonce,
            request.requestTimestamp,
            request.requestAudience,
            _canonical_payload(request.payload),
        ]
    )


def _compute_signature(secret: str, request: ProxyOperationRequest) -> str:
    raw = _build_signature_base(request).encode("utf-8")
    return hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).hexdigest()


def _cleanup_nonces(now_utc: datetime) -> None:
    expired = [nonce for nonce, expiry in _NONCE_EXPIRY.items() if expiry <= now_utc]
    for nonce in expired:
        _NONCE_EXPIRY.pop(nonce, None)


def _check_and_record_nonce(nonce: str, now_utc: datetime) -> None:
    _cleanup_nonces(now_utc)
    expiry = _NONCE_EXPIRY.get(nonce)
    if expiry is not None and expiry > now_utc:
        raise ProxySecurityError("replay_nonce")
    _NONCE_EXPIRY[nonce] = now_utc + timedelta(seconds=PROXY_NONCE_TTL_SECONDS)


def clear_nonce_cache() -> None:
    _NONCE_EXPIRY.clear()


def validate_proxy_request(
    request: ProxyOperationRequest,
    signature_header: str,
    request_id: str,
    scope: str,
    now_utc: datetime | None = None,
) -> ProxySecurityContext:
    if not PROXY_HMAC_SHARED_SECRET:
        raise ProxySecurityError("missing_shared_secret")
    if not signature_header.strip():
        raise ProxySecurityError("missing_signature")

    current = now_utc or datetime.now(UTC)

    if request.requestAudience != PROXY_REQUEST_AUDIENCE:
        raise ProxySecurityError("audience_mismatch")

    try:
        request_ts = _parse_timestamp(request.requestTimestamp)
    except Exception as exc:
        raise ProxySecurityError("timestamp_invalid") from exc

    if abs((current - request_ts).total_seconds()) > PROXY_MAX_SKEW_SECONDS:
        raise ProxySecurityError("timestamp_skew")

    expected = _compute_signature(PROXY_HMAC_SHARED_SECRET, request)
    if not hmac.compare_digest(expected, signature_header.strip()):
        raise ProxySecurityError("signature_invalid")

    _check_and_record_nonce(request.requestNonce, current)

    return ProxySecurityContext(
        request_id=request_id,
        operation=request.operation,
        nonce=request.requestNonce,
        scope=scope,
        timestamp=request.requestTimestamp,
        audience=request.requestAudience,
    )


def build_proxy_security_context(
    request: ProxyOperationRequest,
    signature_header: str,
    request_id: str,
    scope: str,
    now_utc: datetime | None = None,
) -> ProxySecurityContext:
    return validate_proxy_request(
        request=request,
        signature_header=signature_header,
        request_id=request_id,
        scope=scope,
        now_utc=now_utc,
    )
