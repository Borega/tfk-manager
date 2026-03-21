from datetime import datetime, timezone
from typing import Any


def _window_bounds(occurred_at: str) -> tuple[str, str]:
    parsed = datetime.fromisoformat(occurred_at.replace("Z", "+00:00"))
    parsed_utc = parsed.astimezone(timezone.utc)
    start = parsed_utc.replace(minute=0, second=0, microsecond=0)
    end = start.replace(minute=59, second=59)
    return (
        start.isoformat().replace("+00:00", "Z"),
        end.isoformat().replace("+00:00", "Z"),
    )


def apply_late_corrections(events: list[dict[str, Any]], watermark_utc: datetime) -> dict[str, Any]:
    latest_by_event: dict[str, dict[str, Any]] = {}
    corrected_windows: list[dict[str, str]] = []

    for event in events:
        event_id = event["eventId"]
        current = dict(event)

        if event_id in latest_by_event:
            previous = latest_by_event[event_id]
            if previous.get("payloadHash") != current.get("payloadHash"):
                previous_lineage = int(previous.get("lineageVersion", 1))
                current["lineageVersion"] = previous_lineage + 1
                start, end = _window_bounds(current["occurredAt"])
                corrected_windows.append(
                    {
                        "sourceType": current.get("sourceType", "unknown"),
                        "windowStart": start,
                        "windowEnd": end,
                        "annotation": "corrected",
                    }
                )
            else:
                current["lineageVersion"] = previous.get("lineageVersion", 1)

        latest_by_event[event_id] = current

    output_events = list(latest_by_event.values())
    return {
        "watermarkUtc": watermark_utc.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "events": output_events,
        "correctedWindows": corrected_windows,
    }
