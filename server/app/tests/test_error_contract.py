import unittest

from server.app.api.error_contract import (
    ERR_FORBIDDEN,
    ERR_INTERNAL,
    ERR_QUERY_INVALID,
    ERR_TOKEN_EXPIRED,
    build_error_response,
    status_for_error_code,
)


class TestErrorContract(unittest.TestCase):
    def test_error_envelope_shape(self) -> None:
        response = build_error_response(
            error_code=ERR_TOKEN_EXPIRED,
            message="token expired",
            request_id="req-1",
            details={"tokenType": "access"},
            status=401,
        )

        self.assertEqual(response["status"], 401)
        self.assertEqual(response["errorCode"], ERR_TOKEN_EXPIRED)
        self.assertEqual(response["message"], "token expired")
        self.assertEqual(response["requestId"], "req-1")
        self.assertEqual(response["details"], {"tokenType": "access"})

    def test_status_code_mapping(self) -> None:
        self.assertEqual(status_for_error_code(ERR_TOKEN_EXPIRED), 401)
        self.assertEqual(status_for_error_code(ERR_FORBIDDEN), 403)
        self.assertEqual(status_for_error_code(ERR_QUERY_INVALID), 422)
        self.assertEqual(status_for_error_code(ERR_INTERNAL), 500)


if __name__ == "__main__":
    unittest.main()
