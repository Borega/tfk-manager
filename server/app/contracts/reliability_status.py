from dataclasses import dataclass
from enum import StrEnum


class ReliabilityState(StrEnum):
    Healthy = "Healthy"
    Degraded = "Degraded"
    Stale = "Stale"
    Unknown = "Unknown"


@dataclass
class SourceReliabilityStatus:
    sourceKey: str
    state: ReliabilityState
    lagSeconds: int
    checkpointCursor: str
    severityCandidate: str
    fallbackRecommended: bool
    confidenceImpact: str
