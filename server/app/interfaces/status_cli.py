import json
from datetime import datetime, timezone

from server.app.collector.severity_policy import CRITICAL, compute_overall_severity
from server.app.contracts.reliability_status import SourceReliabilityStatus


def build_status_payload(source_statuses: list[SourceReliabilityStatus]) -> dict:
    overall_severity = compute_overall_severity(source_statuses)
    stale_sources = [s.sourceKey for s in source_statuses if s.state.value == "Stale"]

    fallback_recommended = any(s.fallbackRecommended for s in source_statuses)
    guidance_reason = "No fallback needed"
    if fallback_recommended:
        guidance_reason = "One or more sources exceeded fallback grace window"
    if overall_severity == CRITICAL and len(stale_sources) >= 2:
        guidance_reason = "Multiple sources are stale and confidence is degraded"

    payload = {
        "generatedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "overallSeverity": overall_severity,
        "sources": [
            {
                "sourceKey": s.sourceKey,
                "state": s.state.value,
                "lagSeconds": s.lagSeconds,
                "checkpointCursor": s.checkpointCursor,
                "severityCandidate": s.severityCandidate,
                "fallbackRecommended": s.fallbackRecommended,
                "confidenceImpact": s.confidenceImpact,
            }
            for s in source_statuses
        ],
        "outageSummary": {
            "staleSources": stale_sources,
            "count": len(stale_sources),
        },
        "fallbackGuidance": {
            "recommended": fallback_recommended,
            "reason": guidance_reason,
            "actionLabel": "Switch To Local Fallback" if fallback_recommended else "Continue Server Mode",
            "actionKey": "switch-local-fallback" if fallback_recommended else "none",
        },
    }
    return payload


def render_status_json(source_statuses: list[SourceReliabilityStatus]) -> str:
    return json.dumps(build_status_payload(source_statuses), ensure_ascii=False)
