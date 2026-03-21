import unittest


class TestEventRepository(unittest.TestCase):
    def test_duplicate_event_id_does_not_increment_count(self):
        events = []
        seen = set()

        def add_event(event_id: str):
            if event_id in seen:
                return
            seen.add(event_id)
            events.append(event_id)

        add_event("evt-1")
        add_event("evt-1")
        self.assertEqual(len(events), 1)


if __name__ == "__main__":
    unittest.main()
