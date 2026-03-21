# Retention Lifecycle Contract

This document defines the retention lifecycle block embedded in the server status payload.

## Payload Block

```json
{
  "retentionLifecycle": {
    "lastRunAt": "2026-03-21T09:00:00Z",
    "cutoffAt": "2025-03-21T09:00:00Z",
    "deletedCount": 42,
    "affectedWindows": ["2024-02", "2024-03"],
    "runStatus": "completed",
    "nextScheduledAt": "2026-03-22T09:00:00Z"
  }
}
```

## Field Semantics

- lastRunAt: UTC timestamp of the most recent retention cycle completion.
- cutoffAt: UTC cutoff timestamp applied to canonical event expiration.
- deletedCount: Total canonical records deleted in the run.
- affectedWindows: List of YYYY-MM windows where records were deleted.
- runStatus: Retention cycle status, for example completed, failed, or running.
- nextScheduledAt: UTC timestamp for the next planned retention cycle.

## Compatibility Notes

- This block extends, but does not replace, reliability fields in the status payload.
- Clients should treat missing timestamps as unknown/unset and continue rendering reliability data.
