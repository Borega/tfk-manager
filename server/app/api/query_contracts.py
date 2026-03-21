from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

VALID_SOURCE_TYPES = {"dhcp", "firewall", "webfilter"}
VALID_BUCKET_GRAINS = {"fine", "coarse"}


def _parse_utc_iso(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include UTC offset")
    return parsed.astimezone(timezone.utc)


@dataclass(slots=True)
class EventsQuery:
    startAt: str
    endAt: str
    sourceType: str | None = None
    cursor: str | None = None
    limit: int = 100

    def __post_init__(self) -> None:
        start = _parse_utc_iso(self.startAt)
        end = _parse_utc_iso(self.endAt)
        if start > end:
            raise ValueError("startAt must be before endAt")
        if self.sourceType and self.sourceType not in VALID_SOURCE_TYPES:
            raise ValueError("sourceType must be dhcp, firewall, or webfilter")
        if self.limit < 1 or self.limit > 500:
            raise ValueError("limit must be between 1 and 500")


@dataclass(slots=True)
class TrendsQuery:
    startAt: str
    endAt: str
    sourceType: str | None = None
    bucketGrain: str = "coarse"

    def __post_init__(self) -> None:
        start = _parse_utc_iso(self.startAt)
        end = _parse_utc_iso(self.endAt)
        if start > end:
            raise ValueError("startAt must be before endAt")
        if self.sourceType and self.sourceType not in VALID_SOURCE_TYPES:
            raise ValueError("sourceType must be dhcp, firewall, or webfilter")
        if self.bucketGrain not in VALID_BUCKET_GRAINS:
            raise ValueError("bucketGrain must be fine or coarse")
