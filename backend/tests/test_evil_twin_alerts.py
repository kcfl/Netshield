from __future__ import annotations

import os
import sys
import unittest
from collections import defaultdict


BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from capture.sniffer import PacketSniffer  # noqa: E402
from services.alert_service import AlertService  # noqa: E402


def _build_sniffer_with_access_points(access_points):
    """Create a PacketSniffer with a pre-populated AP map for deterministic tests."""
    sniffer = PacketSniffer()
    sniffer._access_points = {ap["bssid"]: dict(ap) for ap in access_points}
    sniffer._ssid_index = defaultdict(set)
    for ap in access_points:
        sniffer._ssid_index[ap["ssid"]].add(ap["bssid"])
    sniffer._refresh_evil_twin_flags_locked()
    return sniffer


class TestEvilTwinAlertFiltering(unittest.TestCase):
    def test_info_groups_do_not_emit_alerts(self):
        """Matching OUI + security profile should score 'info' and not alert."""
        access_points = [
            {
                "ssid": "DemoWiFi",
                "bssid": "aa:bb:cc:00:11:22",
                "oui": "aa:bb:cc",
                "signal_strength": 70,
                "first_seen": "2026-08-16T00:00:00Z",
                "last_seen": "2026-08-16T00:00:01Z",
                "evil_twin_suspected": False,
                "security_type": "wpa2",
                "auth_method": "personal",
                "encryption": "ccmp",
                "security_raw": "WPA2-Personal",
            },
            {
                "ssid": "DemoWiFi",
                "bssid": "aa:bb:cc:33:44:55",
                "oui": "aa:bb:cc",
                "signal_strength": 68,
                "first_seen": "2026-08-16T00:00:00Z",
                "last_seen": "2026-08-16T00:00:02Z",
                "evil_twin_suspected": False,
                "security_type": "wpa2",
                "auth_method": "personal",
                "encryption": "ccmp",
                "security_raw": "WPA2-Personal",
            },
        ]

        sniffer = _build_sniffer_with_access_points(access_points)
        snapshot = sniffer.get_snapshot()

        # The group should remain visible in raw snapshot data...
        self.assertEqual(len(snapshot.get("evil_twin_groups", [])), 1)
        group = snapshot["evil_twin_groups"][0]
        self.assertEqual(group.get("severity"), "info")
        self.assertEqual(group.get("suspicious"), False)
        self.assertEqual(group.get("score"), 15)

        # ...but should NOT be emitted into the alert feed.
        stub = type("Stub", (), {"get_snapshot": lambda self: snapshot})()
        alerts = AlertService(stub).get_all_alerts()
        evil_twin_alerts = [alert for alert in alerts if alert.get("type") == "evil_twin"]
        self.assertEqual(evil_twin_alerts, [])

    def test_oui_mismatch_emits_medium_alert(self):
        """OUI mismatch alone should score 'medium' and emit an evil_twin alert."""
        access_points = [
            {
                "ssid": "DemoWiFi",
                "bssid": "aa:bb:cc:00:11:22",
                "oui": "aa:bb:cc",
                "signal_strength": 70,
                "first_seen": "2026-08-16T00:00:00Z",
                "last_seen": "2026-08-16T00:00:01Z",
                "evil_twin_suspected": False,
                "security_type": "wpa2",
                "auth_method": "personal",
                "encryption": "ccmp",
                "security_raw": "WPA2-Personal",
            },
            {
                "ssid": "DemoWiFi",
                "bssid": "11:22:33:33:44:55",
                "oui": "11:22:33",
                "signal_strength": 68,
                "first_seen": "2026-08-16T00:00:00Z",
                "last_seen": "2026-08-16T00:00:02Z",
                "evil_twin_suspected": False,
                "security_type": "wpa2",
                "auth_method": "personal",
                "encryption": "ccmp",
                "security_raw": "WPA2-Personal",
            },
        ]

        sniffer = _build_sniffer_with_access_points(access_points)
        snapshot = sniffer.get_snapshot()

        self.assertEqual(len(snapshot.get("evil_twin_groups", [])), 1)
        group = snapshot["evil_twin_groups"][0]
        self.assertEqual(group.get("severity"), "medium")
        self.assertEqual(group.get("suspicious"), True)
        self.assertEqual(group.get("score"), 55)

        stub = type("Stub", (), {"get_snapshot": lambda self: snapshot})()
        alerts = AlertService(stub).get_all_alerts()
        evil_twin_alerts = [alert for alert in alerts if alert.get("type") == "evil_twin"]
        self.assertEqual(len(evil_twin_alerts), 1)
        alert = evil_twin_alerts[0]
        self.assertEqual(alert.get("severity"), "medium")
        self.assertIn("Reason:", alert.get("description", ""))
        self.assertIn("Severity score: 55.", alert.get("description", ""))


if __name__ == "__main__":
    unittest.main()

