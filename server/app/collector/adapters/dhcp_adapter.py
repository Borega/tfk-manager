import hashlib
import json
from datetime import datetime, timezone
from typing import Any


def _event_id(source_type: str, payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(f"{source_type}:{canonical}".encode("utf-8")).hexdigest()


def _payload_hash(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def fetch_batch(checkpoint_cursor: str | None, now_utc: datetime, raw_rows: list[dict[str, Any]] | None = None):
    rows = raw_rows or []
    observed_at = now_utc.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    events = []

    for row in rows:
        payload = {
            "mac": row.get("mac", ""),
            "ip": row.get("ip", ""),
            "hostname": row.get("hostname", ""),
            "leaseEnd": row.get("leaseEnd", ""),
        }
        event_id = _event_id("dhcp", payload)
        events.append(
            {
                "eventId": event_id,
                "sourceType": "dhcp",
                "sourceEntityId": payload["mac"] or payload["ip"],
                "occurredAt": row.get("occurredAt", observed_at),
                "observedAt": observed_at,
                "payloadHash": _payload_hash(payload),
                "lineageVersion": int(row.get("lineageVersion", 1)),
                "confidenceState": row.get("confidenceState", "Healthy"),
                "rawPayloadJson": json.dumps(payload, sort_keys=True),
            }
        )

    next_cursor = events[-1]["eventId"] if events else (checkpoint_cursor or "")
    return events, next_cursor
