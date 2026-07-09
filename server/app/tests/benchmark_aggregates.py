import sqlite3
import time
import random
from datetime import datetime, timedelta

from server.app.collector.aggregates import recompute_aggregate_windows
from server.app.collector.repository import ensure_schema, upsert_events_and_checkpoint

def run_benchmark():
    connection = sqlite3.connect(":memory:")
    ensure_schema(connection)

    start_time = datetime(2026, 3, 21, 8, 0, 0)
    events = []

    # Generate 100,000 events
    for i in range(100000):
        hour_offset = random.randint(0, 1000)
        minute_offset = random.randint(0, 59)
        occurred_at = start_time + timedelta(hours=hour_offset, minutes=minute_offset)
        source_type = f"source-{random.randint(1, 40)}"

        events.append({
            "eventId": f"evt-{i}",
            "sourceType": source_type,
            "sourceEntityId": f"entity-{i}",
            "sourceIdentifiersJson": '{"user":"test"}',
            "occurredAt": occurred_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "observedAt": occurred_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "collectorVersion": "v1",
            "ingestTimestamp": occurred_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "payloadHash": f"hash-{i}",
            "lineageVersion": 1,
            "confidenceState": "Healthy",
            "rawPayloadJson": "{}",
        })

    upsert_events_and_checkpoint(
        connection,
        events,
        {
            "sourceKey": "benchmark",
            "cursor": "cursor",
            "lastSuccessAt": "2026-03-21T08:30:00Z",
            "lastErrorAt": None,
            "errorCount": 0,
            "lagSeconds": 1,
            "updatedAt": "2026-03-21T08:30:00Z",
        }
    )

    window = {
        "sourceType": None,
        "windowStart": start_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "windowEnd": (start_time + timedelta(hours=1000)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "annotation": "benchmark"
    }

    print("Running baseline...")
    t0 = time.time()
    recompute_aggregate_windows(connection, [window])
    t1 = time.time()

    print(f"Time taken: {t1 - t0:.4f} seconds")

if __name__ == "__main__":
    run_benchmark()
