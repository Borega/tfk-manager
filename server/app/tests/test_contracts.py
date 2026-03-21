import unittest
from dataclasses import fields
from datetime import datetime, timezone

from server.app.collector.contracts import CanonicalEvent


class TestContracts(unittest.TestCase):
    def test_canonical_event_fields(self):
        actual_fields = {field.name for field in fields(CanonicalEvent)}
        expected_fields = {
            "eventId",
            "sourceType",
            "sourceEntityId",
            "sourceIdentifiersJson",
            "occurredAt",
            "observedAt",
            "collectorVersion",
            "ingestTimestamp",
            "payloadHash",
            "lineageVersion",
            "confidenceState",
            "rawPayloadJson",
        }
        self.assertEqual(actual_fields, expected_fields)

    def test_canonical_event_record_keys_are_stable(self):
        event = CanonicalEvent(
            eventId="evt-1",
            sourceType="dhcp",
            sourceEntityId="lease-1",
            sourceIdentifiersJson='{"mac":"aa:bb:cc:dd:ee:ff"}',
            occurredAt=datetime(2026, 3, 21, 8, 0, tzinfo=timezone.utc),
            observedAt=datetime(2026, 3, 21, 8, 0, 1, tzinfo=timezone.utc),
            collectorVersion="collector-2.0.0",
            ingestTimestamp=datetime(2026, 3, 21, 8, 0, 2, tzinfo=timezone.utc),
            payloadHash="hash-1",
            lineageVersion=1,
            confidenceState="Healthy",
            rawPayloadJson="{}",
        )
        record = event.to_record()
        expected_keys = {
            "event_id",
            "source_type",
            "source_entity_id",
            "source_identifiers_json",
            "occurred_at",
            "observed_at",
            "collector_version",
            "ingest_timestamp",
            "payload_hash",
            "lineage_version",
            "confidence_state",
            "raw_payload_json",
        }
        self.assertEqual(set(record.keys()), expected_keys)
        self.assertEqual(record["source_identifiers_json"], '{"mac":"aa:bb:cc:dd:ee:ff"}')
        self.assertEqual(record["collector_version"], "collector-2.0.0")

    def test_checkpoint_state_fields(self):
        expected_fields = {
            "sourceKey",
            "cursor",
            "lastSuccessAt",
            "lastErrorAt",
            "errorCount",
            "lagSeconds",
            "updatedAt",
        }
        self.assertEqual(len(expected_fields), 7)
        self.assertIn("sourceKey", expected_fields)


if __name__ == "__main__":
    unittest.main()
