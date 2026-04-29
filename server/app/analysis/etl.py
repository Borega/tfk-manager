from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass(slots=True)
class NormalizedEvent:
    event_id: str
    source_type: str
    source_entity_id: str
    occurred_at: datetime
    confidence_state: str
    payload: dict[str, Any]


@dataclass(slots=True)
class NormalizedDataset:
    events: list[NormalizedEvent]
    dhcp_events: list[NormalizedEvent]
    firewall_events: list[NormalizedEvent]
    webfilter_events: list[NormalizedEvent]


def parse_iso_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def floor_bucket(value: datetime, grain: str) -> datetime:
    if grain == "fine":
        minute = (value.minute // 5) * 5
        return value.replace(minute=minute, second=0, microsecond=0)
    return value.replace(minute=0, second=0, microsecond=0)


def bucket_iso(value: datetime, grain: str) -> str:
    return floor_bucket(value, grain).isoformat().replace("+00:00", "Z")


def infer_vlan_from_ip(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return "unknown"
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return "unknown"

    if not isinstance(ip, ipaddress.IPv4Address):
        return "unknown"

    if ip in ipaddress.ip_network("10.0.0.0/8"):
        return "lan"
    if ip in ipaddress.ip_network("172.16.0.0/12"):
        return "opt4"
    if ip in ipaddress.ip_network("192.168.0.0/16"):
        return "mgmt"
    return "external"


def normalize_events(connection: Any, start_at: str, end_at: str) -> NormalizedDataset:
    rows = connection.execute(
        """
        SELECT event_id, source_type, source_entity_id, occurred_at, confidence_state, raw_payload_json
        FROM canonical_events
        WHERE occurred_at >= ? AND occurred_at <= ?
        ORDER BY occurred_at ASC, event_id ASC
        """,
        (start_at, end_at),
    ).fetchall()

    events: list[NormalizedEvent] = []
    for row in rows:
        payload_text = row[5] if isinstance(row[5], str) else "{}"
        try:
            payload = json.loads(payload_text)
            if not isinstance(payload, dict):
                payload = {}
        except json.JSONDecodeError:
            payload = {}

        events.append(
            NormalizedEvent(
                event_id=str(row[0]),
                source_type=str(row[1]),
                source_entity_id=str(row[2]),
                occurred_at=parse_iso_utc(str(row[3])),
                confidence_state=str(row[4]),
                payload=payload,
            )
        )

    return NormalizedDataset(
        events=events,
        dhcp_events=[item for item in events if item.source_type == "dhcp"],
        firewall_events=[item for item in events if item.source_type == "firewall"],
        webfilter_events=[item for item in events if item.source_type == "webfilter"],
    )
