from __future__ import annotations

import json

from server.app.api.proxy_operation_errors import ProxyOperationError
from server.app.proxy.opnsense_proxy_service import execute_opnsense_operation
from server.app.proxy.webfilter_proxy_service import execute_webfilter_operation


def proxy_execute_operation(operation: str, payload: dict[str, object]) -> dict[str, object]:
    if operation in {
        "getDynamicLeases",
        "getStaticLeases",
        "getFirewallSnapshot",
        "addStaticLease",
        "updateStaticLease",
        "deleteStaticLease",
        "moveDynamicToStatic",
        "updateStaticFromDynamic",
    }:
        return execute_opnsense_operation(operation, payload)

    if operation in {"getWebfilterLogs", "testWebfilterLogin"}:
        return execute_webfilter_operation(operation, payload)

    raise ProxyOperationError(
        "proxy_operation_invalid",
        f"Unsupported proxy operation: {operation}",
        status=422,
        details={"operation": operation},
    )


def proxy_get_operation_status(audit_record: dict[str, object] | None) -> dict[str, object]:
    if audit_record is None:
        raise ProxyOperationError(
            "proxy_operation_not_found",
            "Proxy operation requestId not found",
            status=404,
        )

    raw_details = audit_record["details"]
    if isinstance(raw_details, str):
        try:
            details = json.loads(raw_details)
        except json.JSONDecodeError:
            details = {"raw": raw_details}
    elif isinstance(raw_details, dict):
        details = raw_details
    else:
        details = {"raw": str(raw_details)}

    return {
        "requestId": audit_record["requestId"],
        "operation": audit_record["operation"],
        "scope": audit_record["scope"],
        "status": audit_record["status"],
        "actorId": audit_record["actorId"],
        "actorRole": audit_record["actorRole"],
        "target": audit_record["target"],
        "errorCode": audit_record["errorCode"],
        "details": details,
        "createdAt": audit_record["createdAt"],
    }
