from datetime import datetime, timezone
from typing import Any, Callable

from server.app.collector.aggregates import recompute_aggregate_windows
from server.app.collector.corrections import apply_late_corrections
from server.app.collector.repository import count_canonical_events, upsert_events_and_checkpoint
from server.app.collector.workers.replay_policy import (
    is_retry_ready,
    next_retry_at,
    should_trigger_fallback,
)


def _hour_window_bounds(occurred_at: str) -> tuple[str, str]:
    parsed = datetime.fromisoformat(occurred_at.replace("Z", "+00:00")).astimezone(timezone.utc)
    start = parsed.replace(minute=0, second=0, microsecond=0)
    end = start.replace(minute=59, second=59)
    return (
        start.isoformat().replace("+00:00", "Z"),
        end.isoformat().replace("+00:00", "Z"),
    )


def _windows_for_ingested_events(events: list[dict[str, Any]]) -> list[dict[str, str]]:
    windows_by_key: dict[tuple[str, str, str], dict[str, str]] = {}
    for event in events:
        source_type = str(event.get("sourceType", "unknown"))
        occurred_at = str(event.get("occurredAt", ""))
        if not occurred_at:
            continue
        window_start, window_end = _hour_window_bounds(occurred_at)
        key = (source_type, window_start, window_end)
        windows_by_key[key] = {
            "sourceType": source_type,
            "windowStart": window_start,
            "windowEnd": window_end,
            "annotation": "ingested",
        }
    return list(windows_by_key.values())


def _merge_recompute_windows(*window_sets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str, str], dict[str, Any]] = {}
    for windows in window_sets:
        for window in windows:
            source_type = str(window.get("sourceType", "unknown"))
            window_start = str(window.get("windowStart", ""))
            window_end = str(window.get("windowEnd", ""))
            if not window_start or not window_end:
                continue

            key = (source_type, window_start, window_end)
            existing = merged.get(key)
            if existing is None:
                merged[key] = {
                    "sourceType": source_type,
                    "windowStart": window_start,
                    "windowEnd": window_end,
                    "annotation": window.get("annotation", "ingested"),
                }
                continue

            # Keep corrected annotation when either window flags a correction.
            if (
                str(existing.get("annotation", "")).lower() != "corrected"
                and str(window.get("annotation", "")).lower() == "corrected"
            ):
                existing["annotation"] = "corrected"

    return list(merged.values())


def create_worker_state(source_key: str, cursor: str = "") -> dict[str, Any]:
    return {
        "sourceKey": source_key,
        "cursor": cursor,
        "attempt": 0,
        "nextRetryAt": None,
        "outageSeconds": 0,
        "fallbackRecommended": False,
        "lastSuccessAt": None,
        "lastErrorAt": None,
        "lastRunOutcome": None,
        "lastFetchedCount": 0,
        "lastUniqueEventCount": 0,
        "lastNewEventsSaved": 0,
        "lastDbEventCount": 0,
        "lastRecomputedWindows": 0,
    }


def run_worker_iteration(
    source_key: str,
    state: dict[str, Any],
    adapter_fetch: Callable[[str | None, datetime], tuple[list[dict[str, Any]], str]],
    connection,
    now_utc: datetime,
    fail_on_event_id: str | None = None,
    force_refresh: bool = False,
) -> dict[str, Any]:
    if not force_refresh and not is_retry_ready(state.get("nextRetryAt"), now_utc):
        state.update({
            "lastRunOutcome": "retry_wait",
            "lastFetchedCount": 0,
            "lastUniqueEventCount": 0,
            "lastNewEventsSaved": 0,
            "lastRecomputedWindows": 0,
        })
        return state

    try:
        events, next_cursor = adapter_fetch(state.get("cursor"), now_utc)
        correction_result = apply_late_corrections(events, now_utc)
        corrected_events = correction_result["events"]
        corrected_windows = correction_result.get("correctedWindows", [])
        unique_event_ids = {
            str(event.get("eventId") or "")
            for event in corrected_events
            if str(event.get("eventId") or "")
        }
        total_events_before = count_canonical_events(connection)

        checkpoint = {
            "sourceKey": source_key,
            "cursor": next_cursor,
            "lastSuccessAt": now_utc.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            "lastErrorAt": None,
            "errorCount": 0,
            "lagSeconds": 0,
            "updatedAt": now_utc.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        }
        upsert_events_and_checkpoint(
            connection,
            corrected_events,
            checkpoint,
            fail_on_event_id=fail_on_event_id,
        )
        total_events_after = count_canonical_events(connection)
        new_events_saved = max(0, total_events_after - total_events_before)

        recompute_windows = _merge_recompute_windows(
            _windows_for_ingested_events(corrected_events),
            corrected_windows,
        )
        if recompute_windows:
            recompute_aggregate_windows(connection, recompute_windows)

        state.update(
            {
                "cursor": next_cursor,
                "attempt": 0,
                "nextRetryAt": None,
                "outageSeconds": 0,
                "fallbackRecommended": False,
                "lastSuccessAt": checkpoint["lastSuccessAt"],
                "lastErrorAt": None,
                "lastRunOutcome": "success",
                "lastFetchedCount": len(corrected_events),
                "lastUniqueEventCount": len(unique_event_ids),
                "lastNewEventsSaved": new_events_saved,
                "lastDbEventCount": total_events_after,
                "lastRecomputedWindows": len(recompute_windows),
            }
        )
        return state

    except Exception:
        outage_seconds = int(state.get("outageSeconds", 0)) + 30
        attempt = int(state.get("attempt", 0)) + 1
        state.update(
            {
                "attempt": attempt,
                "outageSeconds": outage_seconds,
                "nextRetryAt": next_retry_at(source_key, attempt, now_utc),
                "fallbackRecommended": should_trigger_fallback(source_key, outage_seconds),
                "lastErrorAt": now_utc.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
                "lastRunOutcome": "error",
                "lastFetchedCount": 0,
                "lastUniqueEventCount": 0,
                "lastNewEventsSaved": 0,
                "lastRecomputedWindows": 0,
            }
        )
        return state
