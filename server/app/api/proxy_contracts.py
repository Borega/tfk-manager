from __future__ import annotations

from typing import Final, Literal

from pydantic import BaseModel, Field, model_validator

ProxyOperationType = Literal[
    "getDynamicLeases",
    "getStaticLeases",
    "getFirewallSnapshot",
    "getWebfilterLogs",
    "testWebfilterLogin",
    "addStaticLease",
    "updateStaticLease",
    "deleteStaticLease",
    "moveDynamicToStatic",
    "updateStaticFromDynamic",
]

READ_PROXY_OPERATIONS: Final[set[str]] = {
    "getDynamicLeases",
    "getStaticLeases",
    "getFirewallSnapshot",
    "getWebfilterLogs",
    "testWebfilterLogin",
}

MUTATING_PROXY_OPERATIONS: Final[set[str]] = {
    "addStaticLease",
    "updateStaticLease",
    "deleteStaticLease",
    "moveDynamicToStatic",
    "updateStaticFromDynamic",
}

ALL_PROXY_OPERATIONS: Final[set[str]] = READ_PROXY_OPERATIONS | MUTATING_PROXY_OPERATIONS

OPERATION_SCOPE_MAP: Final[dict[str, str]] = {
    "getDynamicLeases": "proxy:dhcp:read",
    "getStaticLeases": "proxy:dhcp:read",
    "getFirewallSnapshot": "proxy:firewall:read",
    "getWebfilterLogs": "proxy:webfilter:read",
    "testWebfilterLogin": "proxy:webfilter:read",
    "addStaticLease": "proxy:dhcp:write",
    "updateStaticLease": "proxy:dhcp:write",
    "deleteStaticLease": "proxy:dhcp:write",
    "moveDynamicToStatic": "proxy:dhcp:write",
    "updateStaticFromDynamic": "proxy:dhcp:write",
}

OPERATION_MIN_ROLE: Final[dict[str, str]] = {
    **{name: "analyst" for name in READ_PROXY_OPERATIONS},
    **{name: "admin" for name in MUTATING_PROXY_OPERATIONS},
}


class ProxyOperationRequest(BaseModel):
    operation: str = Field(min_length=1)
    payload: dict[str, object] = Field(default_factory=dict)
    requestNonce: str = Field(min_length=16, max_length=128)
    requestTimestamp: str = Field(min_length=20, max_length=40)
    requestAudience: str = Field(min_length=1, max_length=128)

    @model_validator(mode="after")
    def _validate_operation(self):
        if self.operation not in ALL_PROXY_OPERATIONS:
            raise ValueError("operation_not_allowed")
        return self


def is_allowed_proxy_operation(operation: str) -> bool:
    return operation in ALL_PROXY_OPERATIONS


def required_scope_for_operation(operation: str) -> str:
    scope = OPERATION_SCOPE_MAP.get(operation)
    if scope is None:
        raise ValueError("operation_not_allowed")
    return scope


def minimum_role_for_operation(operation: str) -> str:
    role = OPERATION_MIN_ROLE.get(operation)
    if role is None:
        raise ValueError("operation_not_allowed")
    return role


def role_allows_proxy_operation(role: str, operation: str) -> tuple[bool, str]:
    if role not in {"analyst", "admin"}:
        return False, "role_unknown"
    if operation not in ALL_PROXY_OPERATIONS:
        return False, "operation_not_allowed"

    required_role = minimum_role_for_operation(operation)
    if required_role == "analyst":
        return True, "allowed"
    if role != "admin":
        return False, "forbidden"
    return True, "allowed"
