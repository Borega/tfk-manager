from datetime import datetime, timezone
import unittest

from server.app.collector.adapters import dhcp_adapter, firewall_adapter, webfilter_adapter


class TestSourceAdapters(unittest.TestCase):
    def test_dhcp_adapter_deterministic_event_id(self):
        payload = {"mac": "aa:bb:cc:dd:ee:ff", "ip": "10.0.0.5", "hostname": "host-a"}
        now_utc = datetime(2026, 3, 21, 8, 0, 0, tzinfo=timezone.utc)
        events1, _ = dhcp_adapter.fetch_batch(None, now_utc, [payload])
        events2, _ = dhcp_adapter.fetch_batch(None, now_utc, [payload])
        self.assertEqual(events1[0]["eventId"], events2[0]["eventId"])
        self.assertTrue(hasattr(dhcp_adapter, "fetch_batch"))

    def test_firewall_adapter_deterministic_event_id(self):
        payload = {"id": "f-1", "action": "pass", "src": "10.0.0.1", "dst": "8.8.8.8", "proto": "tcp"}
        now_utc = datetime(2026, 3, 21, 8, 0, 0, tzinfo=timezone.utc)
        events1, _ = firewall_adapter.fetch_batch(None, now_utc, [payload])
        events2, _ = firewall_adapter.fetch_batch(None, now_utc, [payload])
        self.assertEqual(events1[0]["eventId"], events2[0]["eventId"])
        self.assertTrue(hasattr(firewall_adapter, "fetch_batch"))

    def test_webfilter_adapter_deterministic_event_id(self):
        payload = {"user": "student", "url": "example.com", "action": "allow", "category": "education"}
        now_utc = datetime(2026, 3, 21, 8, 0, 0, tzinfo=timezone.utc)
        events1, _ = webfilter_adapter.fetch_batch(None, now_utc, [payload])
        events2, _ = webfilter_adapter.fetch_batch(None, now_utc, [payload])
        self.assertEqual(events1[0]["eventId"], events2[0]["eventId"])
        self.assertTrue(hasattr(webfilter_adapter, "fetch_batch"))


if __name__ == "__main__":
    unittest.main()
