# Historical Query API Contract

## Authentication

- All endpoints require a valid access token (Bearer).
- Roles: analyst and admin.
- Analyst has read access to both endpoints below.

## GET /api/history/events

### Query Parameters

- startAt (required, UTC ISO timestamp)
- endAt (required, UTC ISO timestamp)
- sourceType (optional: dhcp, firewall, webfilter)
- cursor (optional, eventId from previous page)
- limit (optional, default 100, max 500)

### Response 200

```json
{
  "items": [
    {
      "eventId": "evt-1001",
      "sourceType": "firewall",
      "sourceEntityId": "rule-allow-1",
      "occurredAt": "2026-03-21T12:10:00Z",
      "observedAt": "2026-03-21T12:10:01Z",
      "payloadHash": "abc123",
      "lineageVersion": 1,
      "confidenceState": "Healthy",
      "rawPayloadJson": "{}"
    }
  ],
  "nextCursor": "evt-1001",
  "count": 1
}
```

## GET /api/history/trends

### Query Parameters

- startAt (required, UTC ISO timestamp)
- endAt (required, UTC ISO timestamp)
- sourceType (optional: dhcp, firewall, webfilter)
- bucketGrain (optional: fine or coarse, default coarse)

### Response 200

```json
{
  "items": [
    {
      "bucketStart": "2026-03-21T12:00:00Z",
      "bucketGrain": "coarse",
      "sourceType": "firewall",
      "eventCount": 12,
      "updatedAt": "2026-03-21T12:20:00Z"
    }
  ],
  "count": 1
}
```
