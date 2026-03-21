from server.app.contracts.reliability_status import ReliabilityState, SourceReliabilityStatus


INFO = "Info"
WARNING = "Warning"
CRITICAL = "Critical"


def map_source_severity(status: SourceReliabilityStatus) -> str:
    if status.state == ReliabilityState.Stale and status.fallbackRecommended:
        return CRITICAL
    if status.state == ReliabilityState.Stale:
        return WARNING
    if status.state == ReliabilityState.Degraded:
        return WARNING
    return INFO


def compute_overall_severity(source_statuses: list[SourceReliabilityStatus]) -> str:
    stale_sources = [s for s in source_statuses if s.state == ReliabilityState.Stale]
    if len(stale_sources) >= 2:
        return CRITICAL
    if any(map_source_severity(s) == CRITICAL for s in source_statuses):
        return CRITICAL
    if any(map_source_severity(s) == WARNING for s in source_statuses):
        return WARNING
    return INFO
