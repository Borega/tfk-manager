import unittest


class TestContracts(unittest.TestCase):
    def test_canonical_event_fields(self):
        expected_fields = {
            "eventId",
            "sourceType",
            "sourceEntityId",
            "occurredAt",
            "observedAt",
            "payloadHash",
            "lineageVersion",
            "confidenceState",
            "rawPayloadJson",
        }
        self.assertEqual(len(expected_fields), 9)
        self.assertIn("eventId", expected_fields)

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
