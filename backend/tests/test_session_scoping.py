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

SESSION_START = "2026-09-05T09:00:00+00:00"
BEFORE_SESSION = "2026-09-05T08:00:00+00:00"


def _ap(bssid, oui, security, first_seen, last_seen):
    return {
        "ssid": "DemoWiFi",
        "bssid": bssid,
        "oui": oui,
        "signal_strength": 70,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "evil_twin_suspected": False,
        "security_type": security,
        "auth_method": security,
        "encryption": "ccmp",
        "security_raw": security.upper(),
    }


def _evil_twin_alerts(access_points, started_at=SESSION_START):
    """Build the evil-twin alert list for one simulated poll cycle."""
    sniffer = PacketSniffer()
    sniffer._started_at = started_at
    sniffer._access_points = {ap["bssid"]: dict(ap) for ap in access_points}
    sniffer._ssid_index = defaultdict(set)
    for ap in access_points:
        sniffer._ssid_index[ap["ssid"]].add(ap["bssid"])
    sniffer._connected_ssid = "DemoWiFi"
    sniffer._refresh_evil_twin_flags_locked()
    alerts = AlertService(sniffer).get_all_alerts()
    return [alert for alert in alerts if alert["type"] == "evil_twin"]


class TestEvilTwinAlertIdentity(unittest.TestCase):
    """Alert identity must not churn while the underlying condition is unchanged."""

    def test_alert_id_is_stable_across_poll_cycles(self):
        cycle_one = _evil_twin_alerts([
            _ap("aa:bb:cc:00:11:22", "aa:bb:cc", "wpa2", "2026-09-05T10:00:00+00:00", "2026-09-05T10:00:00+00:00"),
            _ap("99:88:77:00:11:22", "99:88:77", "open", "2026-09-05T10:00:00+00:00", "2026-09-05T10:00:00+00:00"),
        ])
        # Next poll: last_seen is rewritten, the condition itself is unchanged.
        cycle_two = _evil_twin_alerts([
            _ap("aa:bb:cc:00:11:22", "aa:bb:cc", "wpa2", "2026-09-05T10:00:00+00:00", "2026-09-05T10:00:03+00:00"),
            _ap("99:88:77:00:11:22", "99:88:77", "open", "2026-09-05T10:00:00+00:00", "2026-09-05T10:00:03+00:00"),
        ])

        self.assertEqual(len(cycle_one), 1)
        self.assertEqual(
            cycle_one[0]["id"],
            cycle_two[0]["id"],
            "an unchanged evil twin must keep one identity, or the GUI re-fires "
            "toasts and the disconnect prompt every poll cycle",
        )

    def test_timestamp_marks_when_the_group_became_detectable(self):
        alerts = _evil_twin_alerts([
            _ap("aa:bb:cc:00:11:22", "aa:bb:cc", "wpa2", "2026-09-05T10:00:00+00:00", "2026-09-05T10:30:05+00:00"),
            _ap("99:88:77:00:11:22", "99:88:77", "open", "2026-09-05T10:30:00+00:00", "2026-09-05T10:30:05+00:00"),
        ])

        # The rogue AP appearing is what created the conflict, not the first AP.
        self.assertEqual(alerts[0]["timestamp"], "2026-09-05T10:30:00+00:00")

    def test_group_predating_the_session_still_reads_as_active(self):
        alerts = _evil_twin_alerts([
            _ap("aa:bb:cc:00:11:22", "aa:bb:cc", "wpa2", BEFORE_SESSION, "2026-09-05T09:00:05+00:00"),
            _ap("99:88:77:00:11:22", "99:88:77", "open", BEFORE_SESSION, "2026-09-05T09:00:05+00:00"),
        ])

        self.assertEqual(alerts[0]["timestamp"], SESSION_START)
        self.assertTrue(alerts[0]["active"], "a live evil twin must not read as a stale alert")


class TestStatusBuildersAreSessionScoped(unittest.TestCase):
    """detected/severity describe now; events[] stays full history for the feed."""

    def _sniffer_with_arp_event(self, last_seen):
        sniffer = PacketSniffer()
        sniffer._started_at = SESSION_START
        sniffer._arp_spoof_events.append({
            "ip_address": "192.168.1.1",
            "previous_mac": "aa:bb",
            "observed_mac": "11:22",
            "severity": "high",
            "description": "Reason: IP 192.168.1.1 ...",
            "last_seen": last_seen,
        })
        return sniffer

    def test_arp_status_ignores_events_from_a_previous_session(self):
        status = self._sniffer_with_arp_event(BEFORE_SESSION)._build_arp_status()

        self.assertFalse(status["detected"])
        self.assertEqual(status["severity"], "none")
        self.assertEqual(len(status["events"]), 1, "history must survive for the Live Alert Feed")

    def test_arp_status_reports_an_event_from_this_session(self):
        status = self._sniffer_with_arp_event("2026-09-05T09:30:00+00:00")._build_arp_status()

        self.assertTrue(status["detected"])
        self.assertEqual(status["severity"], "high")

    def test_ssl_strip_status_ignores_events_from_a_previous_session(self):
        sniffer = PacketSniffer()
        sniffer._started_at = SESSION_START
        sniffer._ssl_strip_events.append({
            "host": "google.com",
            "path": "/login",
            "severity": "medium",
            "description": "Reason: Connection to google.com/login ...",
            "last_seen": BEFORE_SESSION,
        })

        status = sniffer._build_ssl_strip_status()
        self.assertFalse(status["detected"])
        self.assertEqual(status["severity"], "none")
        self.assertEqual(len(status["events"]), 1)


if __name__ == "__main__":
    unittest.main()
