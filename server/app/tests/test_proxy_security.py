import hmac
import json
import unittest
from datetime import UTC, datetime, timedelta

from server.app.api import proxy_security
from server.app.api.proxy_contracts import ProxyOperationRequest
from server.app.api.proxy_security import ProxySecurityError, validate_proxy_request


def _canonical_signature(secret: str, request: ProxyOperationRequest) -> str:
    base = "\n".join(
        [
            request.operation,
            request.requestNonce,
            request.requestTimestamp,
            request.requestAudience,
            json.dumps(request.payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True),
        ]
    )
    return hmac.new(secret.encode("utf-8"), base.encode("utf-8"), "sha256").hexdigest()


class TestProxySecurity(unittest.TestCase):
    def setUp(self) -> None:
        proxy_security.PROXY_HMAC_SHARED_SECRET = "test-shared-secret"
        proxy_security.PROXY_REQUEST_AUDIENCE = "tfk-manager-server"
        proxy_security.PROXY_MAX_SKEW_SECONDS = 120
        proxy_security.PROXY_NONCE_TTL_SECONDS = 300
        proxy_security.clear_nonce_cache()

    def _request(self, nonce: str = "0123456789abcdef") -> ProxyOperationRequest:
        return ProxyOperationRequest(
            operation="getDynamicLeases",
            payload={"iface": "lan"},
            requestNonce=nonce,
            requestTimestamp="2026-03-22T10:00:00Z",
            requestAudience="tfk-manager-server",
        )

    def test_valid_signature_creates_security_context(self) -> None:
        req = self._request()
        signature = _canonical_signature("test-shared-secret", req)
        now_utc = datetime(2026, 3, 22, 10, 0, 30, tzinfo=UTC)

        context = validate_proxy_request(
            request=req,
            signature_header=signature,
            request_id="req-1",
            scope="proxy:dhcp:read",
            now_utc=now_utc,
        )

        self.assertEqual(context.request_id, "req-1")
        self.assertEqual(context.scope, "proxy:dhcp:read")
        self.assertEqual(context.operation, "getDynamicLeases")

    def test_replay_nonce_is_rejected(self) -> None:
        req = self._request()
        signature = _canonical_signature("test-shared-secret", req)
        now_utc = datetime(2026, 3, 22, 10, 0, 30, tzinfo=UTC)

        validate_proxy_request(
            request=req,
            signature_header=signature,
            request_id="req-2",
            scope="proxy:dhcp:read",
            now_utc=now_utc,
        )

        with self.assertRaises(ProxySecurityError) as exc_ctx:
            validate_proxy_request(
                request=req,
                signature_header=signature,
                request_id="req-3",
                scope="proxy:dhcp:read",
                now_utc=now_utc + timedelta(seconds=1),
            )

        self.assertEqual(exc_ctx.exception.reason, "replay_nonce")

    def test_signature_mismatch_rejected(self) -> None:
        req = self._request()
        with self.assertRaises(ProxySecurityError) as exc_ctx:
            validate_proxy_request(
                request=req,
                signature_header="deadbeef",
                request_id="req-4",
                scope="proxy:dhcp:read",
                now_utc=datetime(2026, 3, 22, 10, 0, 30, tzinfo=UTC),
            )
        self.assertEqual(exc_ctx.exception.reason, "signature_invalid")

    def test_timestamp_skew_rejected(self) -> None:
        req = self._request()
        signature = _canonical_signature("test-shared-secret", req)
        with self.assertRaises(ProxySecurityError) as exc_ctx:
            validate_proxy_request(
                request=req,
                signature_header=signature,
                request_id="req-5",
                scope="proxy:dhcp:read",
                now_utc=datetime(2026, 3, 22, 10, 5, 0, tzinfo=UTC),
            )
        self.assertEqual(exc_ctx.exception.reason, "timestamp_skew")

    def test_audience_mismatch_rejected(self) -> None:
        req = ProxyOperationRequest(
            operation="getDynamicLeases",
            payload={"iface": "lan"},
            requestNonce="fedcba9876543210",
            requestTimestamp="2026-03-22T10:00:00Z",
            requestAudience="other-audience",
        )
        signature = _canonical_signature("test-shared-secret", req)

        with self.assertRaises(ProxySecurityError) as exc_ctx:
            validate_proxy_request(
                request=req,
                signature_header=signature,
                request_id="req-6",
                scope="proxy:dhcp:read",
                now_utc=datetime(2026, 3, 22, 10, 0, 30, tzinfo=UTC),
            )

        self.assertEqual(exc_ctx.exception.reason, "audience_mismatch")


if __name__ == "__main__":
    unittest.main()
