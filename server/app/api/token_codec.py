from datetime import datetime

import jwt


class TokenDecodeError(RuntimeError):
    pass


def encode_access_token(claims: dict[str, object], expires_at: datetime, secret: str) -> str:
    payload = dict(claims)
    payload["exp"] = int(expires_at.timestamp())
    return jwt.encode(payload, secret, algorithm="HS256")


def decode_token(token: str, secret: str, verify_expiration: bool = True) -> dict[str, object]:
    try:
        decoded = jwt.decode(
            token,
            secret,
            algorithms=["HS256"],
            options={"require": ["exp"], "verify_exp": verify_expiration},
        )
    except jwt.InvalidTokenError as exc:
        raise TokenDecodeError(str(exc)) from exc
    return dict(decoded)
