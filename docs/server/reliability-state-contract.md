# Reliability State Contract

This document defines the server reliability payload emitted for ingestion continuity status.

## State Values

- Healthy
- Degraded
- Stale
- Unknown

## Severity Values

- Info
- Warning
- Critical

## Payload Shape

```json
{
  "generatedAt": "2026-03-21T09:15:00Z",
  "overallSeverity": "Info",
  "sources": [
    {
      "sourceKey": "dhcp",
      "state": "Healthy",
      "lagSeconds": 15,
      "checkpointCursor": "evt-123",
      "severityCandidate": "Info",
      "fallbackRecommended": false,
      "confidenceImpact": "low"
    }
  ],
  "outageSummary": {
    "staleSources": [],
    "count": 0
  },
  "fallbackGuidance": {
    "recommended": false,
    "reason": "No fallback needed",
    "actionLabel": "Continue Server Mode",
    "actionKey": "none"
  }
}
```

## Field Semantics

- generatedAt: UTC timestamp for this status snapshot.
- overallSeverity: Aggregate status severity across all sources.
- sources[].sourceKey: One of dhcp, firewall, webfilter.
- sources[].state: One of Healthy, Degraded, Stale, Unknown.
- sources[].lagSeconds: Source lag in seconds.
- sources[].checkpointCursor: Last committed checkpoint cursor for that source.
- sources[].severityCandidate: Per-source severity recommendation.
- sources[].fallbackRecommended: Whether source conditions exceed fallback grace.
- sources[].confidenceImpact: low, medium, high, or unknown confidence impact.
- outageSummary.staleSources: Source keys currently in Stale state.
- outageSummary.count: Count of stale sources.
- fallbackGuidance.recommended: Global fallback recommendation.
- fallbackGuidance.reason: Human-readable reason.
- fallbackGuidance.actionLabel: UI label for fallback action.
- fallbackGuidance.actionKey: Stable action identifier used by clients.

## Example: Healthy Baseline

```json
{
  "overallSeverity": "Info",
  "sources": [
    {
      "sourceKey": "dhcp",
      "state": "Healthy",
      "lagSeconds": 12,
      "checkpointCursor": "dhcp-981",
      "severityCandidate": "Info",
      "fallbackRecommended": false,
      "confidenceImpact": "low"
    }
  ],
  "fallbackGuidance": {
    "recommended": false,
    "reason": "No fallback needed",
    "actionLabel": "Continue Server Mode",
    "actionKey": "none"
  }
}
```

## Example: Single-Source Degraded Warning

```json
{
  "overallSeverity": "Warning",
  "sources": [
    {
      "sourceKey": "webfilter",
      "state": "Degraded",
      "lagSeconds": 140,
      "checkpointCursor": "wf-221",
      "severityCandidate": "Warning",
      "fallbackRecommended": false,
      "confidenceImpact": "medium"
    }
  ],
  "fallbackGuidance": {
    "recommended": false,
    "reason": "No fallback needed",
    "actionLabel": "Continue Server Mode",
    "actionKey": "none"
  }
}
```

## Example: Multi-Source Critical With Fallback Guidance

```json
{
  "overallSeverity": "Critical",
  "sources": [
    {
      "sourceKey": "dhcp",
      "state": "Stale",
      "lagSeconds": 420,
      "checkpointCursor": "dhcp-401",
      "severityCandidate": "Critical",
      "fallbackRecommended": true,
      "confidenceImpact": "high"
    },
    {
      "sourceKey": "firewall",
      "state": "Stale",
      "lagSeconds": 165,
      "checkpointCursor": "fw-992",
      "severityCandidate": "Critical",
      "fallbackRecommended": true,
      "confidenceImpact": "high"
    }
  ],
  "outageSummary": {
    "staleSources": ["dhcp", "firewall"],
    "count": 2
  },
  "fallbackGuidance": {
    "recommended": true,
    "reason": "Multiple sources are stale and confidence is degraded",
    "actionLabel": "Switch To Local Fallback",
    "actionKey": "switch-local-fallback"
  }
}
```
