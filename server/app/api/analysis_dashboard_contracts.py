from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

VALID_BUCKET_GRAINS = {"fine", "coarse"}


def _parse_utc_iso(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include UTC offset")
    return parsed.astimezone(timezone.utc)


@dataclass(slots=True)
class AnalysisDashboardQuery:
    startAt: str
    endAt: str
    bucketGrain: str = "coarse"

    def __post_init__(self) -> None:
        start = _parse_utc_iso(self.startAt)
        end = _parse_utc_iso(self.endAt)
        if start > end:
            raise ValueError("startAt must be before endAt")
        if self.bucketGrain not in VALID_BUCKET_GRAINS:
            raise ValueError("bucketGrain must be fine or coarse")
