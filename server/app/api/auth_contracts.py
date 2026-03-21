from dataclasses import asdict, dataclass


@dataclass(slots=True)
class LoginRequest:
    username: str
    password: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(slots=True)
class LoginResponse:
    accessToken: str
    refreshToken: str
    accessExpiresAt: str
    refreshExpiresAt: str
    role: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(slots=True)
class RefreshRequest:
    refreshToken: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(slots=True)
class RefreshResponse:
    accessToken: str
    refreshToken: str
    accessExpiresAt: str
    refreshExpiresAt: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)
