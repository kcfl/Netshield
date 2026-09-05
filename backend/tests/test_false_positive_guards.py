from __future__ import annotations

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from time import monotonic


BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from capture.sniffer import PacketSniffer  # noqa: E402

PINNED = "aaaa1111"
ROTATED = "bbbb2222"


def _utc_ago(**delta):
    return (datetime.now(timezone.utc) - timedelta(**delta)).isoformat()


class TestStartupDoesNotLookLikeANetworkChange(unittest.TestCase):
    """The first poll has no previous SSID to have roamed away from."""

    def _sniffer_on(self, ssid):
        sniffer = PacketSniffer()
        sniffer._get_connected_ssid = lambda: ssid
        return sniffer

    def test_first_poll_does_not_suppress_arp(self):
        sniffer = self._sniffer_on("HomeWiFi")

        sniffer._apply_scan_results({"interface": "Wi-Fi", "access_points": []})

        self.assertLessEqual(
            sniffer._arp_suppress_until,
            monotonic(),
            "starting a scan on a stable network must not pause the ARP monitor",
        )
        self.assertEqual(sniffer._calculate_trust_score()["trust_score"], 100)

    def test_roaming_to_another_ssid_still_suppresses_arp(self):
        sniffer = self._sniffer_on("OtherWiFi")
        sniffer._connected_ssid = "HomeWiFi"
        sniffer._ip_mac_bindings["192.168.1.1"] = {"mac": "aa:bb", "last_seen": ""}

        sniffer._apply_scan_results({"interface": "Wi-Fi", "access_points": []})

        self.assertGreater(sniffer._arp_suppress_until, monotonic())
        self.assertEqual(sniffer._ip_mac_bindings, {}, "a real network change still drops bindings")

    def test_losing_ssid_detection_still_suppresses_arp(self):
        sniffer = self._sniffer_on(None)
        sniffer._connected_ssid = "HomeWiFi"

        sniffer._apply_scan_results({"interface": "Wi-Fi", "access_points": []})

        self.assertGreater(sniffer._arp_suppress_until, monotonic())


class TestStalePinIsNotReportedAsAnAttack(unittest.TestCase):
    """Certificate rotation must not masquerade as a confirmed MITM."""

    def _sniffer_with_pin(self, pinned_at):
        sniffer = PacketSniffer()
        sniffer._started_at = "2020-01-01T00:00:00+00:00"
        sniffer._ssl_pinned_fingerprint = PINNED
        sniffer._ssl_pin_created_at = pinned_at
        sniffer._probe_ssl_canary_endpoint = lambda: {
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "endpoint": "https://8.8.8.8",
            "status": "ok",
            "fingerprint": ROTATED,
            "error": None,
        }
        return sniffer

    def test_recent_pin_mismatch_is_still_a_threat(self):
        sniffer = self._sniffer_with_pin(_utc_ago(hours=1))

        self.assertEqual(sniffer._run_ssl_canary_check()["status"], "fingerprint_mismatch")

    def test_pin_older_than_max_age_reports_pin_stale(self):
        sniffer = self._sniffer_with_pin(_utc_ago(days=30))
        result = sniffer._run_ssl_canary_check()

        self.assertEqual(result["status"], "pin_stale")
        self.assertIn("Repin SSL Canary", result["error"])

    def test_unknown_pin_date_counts_as_stale(self):
        """We cannot establish freshness, so we must not claim an attack."""
        self.assertEqual(self._sniffer_with_pin(None)._run_ssl_canary_check()["status"], "pin_stale")

    def test_pin_stale_deducts_ten_and_raises_no_ssl_strip_alert(self):
        sniffer = self._sniffer_with_pin(_utc_ago(days=30))
        result = sniffer._run_ssl_canary_check()
        sniffer._last_ssl_canary_result = dict(result)

        trust = sniffer._calculate_trust_score()
        self.assertEqual(trust["trust_score"], 90)
        self.assertIn("SSL Canary pin expired - re-pin required (-10)", trust["factors"])
        self.assertFalse(sniffer._build_ssl_strip_status()["detected"])

    def test_repin_clears_the_recorded_pin_date(self):
        sniffer = self._sniffer_with_pin(_utc_ago(days=30))
        sniffer._ssl_canary_pin_path = None  # guard: never touch the real pin file
        try:
            sniffer.reset_ssl_canary_pin()
        except Exception:
            pass
        self.assertIsNone(sniffer._ssl_pin_created_at)


if __name__ == "__main__":
    unittest.main()


class TestInterfaceCoherence(unittest.TestCase):
    """Two live adapters must not look like one coherent monitored network."""

    def _sniffer(self, scan_interface, capture_interface):
        sniffer = PacketSniffer()
        sniffer._started_at = "2020-01-01T00:00:00+00:00"
        sniffer._get_connected_ssid = lambda: "HomeWiFi"
        sniffer._traffic_interface = capture_interface
        sniffer._apply_scan_results({"interface": scan_interface, "access_points": []})
        return sniffer

    def test_same_interface_is_coherent(self):
        status = self._sniffer("Wi-Fi", "Wi-Fi")._build_interface_status()

        self.assertTrue(status["coherent"])
        self.assertEqual(status["severity"], "none")

    def test_interface_name_case_does_not_flag_a_mismatch(self):
        self.assertTrue(self._sniffer("Wi-Fi", "wi-fi")._build_interface_status()["coherent"])

    def test_capture_on_a_different_adapter_is_flagged(self):
        sniffer = self._sniffer("Wi-Fi", "Ethernet 2")
        status = sniffer._build_interface_status()

        self.assertFalse(status["coherent"])
        self.assertEqual(status["severity"], "medium")
        self.assertEqual(status["scan_interface"], "Wi-Fi")
        self.assertEqual(status["capture_interface"], "Ethernet 2")
        self.assertIn("Ethernet 2", status["description"])

        trust = sniffer._calculate_trust_score()
        self.assertEqual(trust["trust_score"], 90)
        self.assertIn("Capture interface differs from scanned network (-10)", trust["factors"])

    def test_unknown_capture_interface_is_not_flagged(self):
        """Before the traffic monitor binds, there is nothing to compare against."""
        status = self._sniffer("Wi-Fi", None)._build_interface_status()

        self.assertTrue(status["coherent"])
        self.assertEqual(status["severity"], "none")

    def test_state_is_exposed_in_both_api_payloads(self):
        sniffer = self._sniffer("Wi-Fi", "Ethernet 2")

        for payload in (sniffer.get_scan_status(), sniffer.get_snapshot()):
            self.assertIn("interface_status", payload)
            self.assertFalse(payload["interface_status"]["coherent"])
