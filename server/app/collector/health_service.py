from datetime import datetime, timezone
from typing import Any

from server.app.collector.workers.replay_policy import get_policy, should_trigger_fallback
from server.app.contracts.reliability_status import ReliabilityState, SourceReliabilityStatus


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def compute_source_health(
    source_key: str,
    checkpoint_cursor: str,
    lag_seconds: int,
    error_count: int,
    replay_backlog: int,
    last_success_at: str | None,
    last_error_at: str | None,
    now_utc: datetime,
) -> SourceReliabilityStatus:
    _ = last_error_at
    policy = get_policy(source_key)
    last_success = _parse_iso(last_success_at)

    if last_success is None:
        state = ReliabilityState.Unknown
    elif lag_seconds <= policy["pollIntervalSeconds"]:
        state = ReliabilityState.Healthy
    elif lag_seconds <= policy["staleThresholdSeconds"]:
        state = ReliabilityState.Degraded
    else:
        state = ReliabilityState.Stale

    severity_candidate = "Info"
    confidence_impact = "low"
    if state == ReliabilityState.Degraded:
        severity_candidate = "Warning"
        confidence_impact = "medium"
    if state == ReliabilityState.Stale:
        severity_candidate = "Critical" if replay_backlog > 0 or error_count > 0 else "Warning"
        confidence_impact = "high"
    if state == ReliabilityState.Unknown:
        severity_candidate = "Info"
        confidence_impact = "unknown"

    fallback_recommended = False
    if state in {ReliabilityState.Degraded, ReliabilityState.Stale}:
        fallback_recommended = should_trigger_fallback(source_key, lag_seconds) and (
            replay_backlog > 0 or error_count > 0
        )

    return SourceReliabilityStatus(
        sourceKey=source_key,
        state=state,
        lagSeconds=int(lag_seconds),
        checkpointCursor=checkpoint_cursor,
        severityCandidate=severity_candidate,
        fallbackRecommended=fallback_recommended,
        confidenceImpact=confidence_impact,
    )


def evaluate_all_sources(status_inputs: list[dict[str, Any]], now_utc: datetime) -> list[SourceReliabilityStatus]:
    results: list[SourceReliabilityStatus] = []
    for item in status_inputs:
        results.append(
            compute_source_health(
                source_key=item["sourceKey"],
                checkpoint_cursor=item.get("checkpointCursor", ""),
                lag_seconds=int(item.get("lagSeconds", 0)),
                error_count=int(item.get("errorCount", 0)),
                replay_backlog=int(item.get("replayBacklog", 0)),
                last_success_at=item.get("lastSuccessAt"),
                last_error_at=item.get("lastErrorAt"),
                now_utc=now_utc,
            )
        )
    return results
