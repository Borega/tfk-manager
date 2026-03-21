# Freshness API Contract

## GET /api/status/freshness

Returns authenticated source freshness and reliability status for polling clients.

### Request

- Header: Authorization: Bearer access token
- Roles: analyst, admin

### Response 200

```json
{
  "status": 200,
  "data": {
    "generatedAt": "2026-03-21T12:00:00Z",
    "overallSeverity": "Info",
    "sources": [
      {
        "sourceKey": "dhcp",
        "state": "Healthy",
        "lagSeconds": 12,
        "checkpointCursor": "dhcp-100",
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
    },
    "retentionLifecycle": {
      "lastRunAt": null,
      "cutoffAt": null,
      "deletedCount": 0,
      "affectedWindows": [],
      "runStatus": "unknown",
      "nextScheduledAt": null
    }
  }
}
```

### Response 401

```json
{
  "status": 401,
  "errorCode": "token_invalid",
  "message": "missing or invalid token",
  "requestId": "freshness-auth",
  "details": {
    "reason": "missing_subject_claim"
  }
}
```

### Response 403

```json
{
  "status": 403,
  "errorCode": "forbidden",
  "message": "insufficient permissions",
  "requestId": "freshness-authz",
  "details": {
    "reason": "role_unknown"
  }
}
```

### Response 500

```json
{
  "status": 500,
  "errorCode": "internal_error",
  "message": "internal server error",
  "requestId": "req-123",
  "details": {}
}
```
