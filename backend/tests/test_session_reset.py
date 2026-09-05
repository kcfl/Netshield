from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import MagicMock, patch


BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from capture.sniffer import PacketSniffer  # noqa: E402

GATEWAY_IP = "192.168.1.1"
LEGIT_MAC = "aa:bb:cc:dd:ee:ff"
SPOOF_MAC = "11:22:33:44:55:66"


class _FakeLayer:
    def __init__(self, **fields):
        self.__dict__.update(fields)


class _FakeARPPacket:
    """Minimal stand-in for a scapy packet carrying an ARP layer."""

    def __init__(self, psrc, hwsrc):
        self._arp = _FakeLayer(psrc=psrc, hwsrc=hwsrc)

    def __getitem__(self, layer):
        return self._arp


class _FakeHTTPPacket:
    """Minimal stand-in for a scapy packet carrying a plain-HTTP request."""

    def __init__(self, host, target, dport=80):
        self._tcp = _FakeLayer(dport=dport)
        payload = f"GET {target} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode("utf-8")
        self._raw = _FakeLayer(load=payload)

    def __getitem__(self, layer):
        return self._tcp if getattr(layer, "__name__", "") == "TCP" else self._raw


def _start(sniffer):
    """Start a scan session without spawning real capture/poller threads."""
    with patch("capture.sniffer.Thread", return_value=MagicMock()):
        sniffer.start()


class TestSignatureResetOnScanStart(unittest.TestCase):
    """Dedup signatures are active-session state and must not outlive a session."""

    def test_start_clears_signatures_but_preserves_event_history(self):
        sniffer = PacketSniffer()
        sniffer._arp_spoof_signatures.add((GATEWAY_IP, LEGIT_MAC, SPOOF_MAC))
        sniffer._ssl_strip_signatures.add(("google.com", "/login"))
        sniffer._arp_spoof_events.append({"description": "legacy", "last_seen": "2020-01-01T00:00:00+00:00"})

        _start(sniffer)
        sniffer.stop()

        self.assertEqual(sniffer._arp_spoof_signatures, set())
        self.assertEqual(sniffer._ssl_strip_signatures, set())
        # The Live Alert Feed is permanent history — staleness rules never prune it.
        self.assertEqual(len(sniffer._arp_spoof_events), 1)

    def test_repeat_arp_spoof_after_restart_is_reported_again(self):
        sniffer = PacketSniffer()

        _start(sniffer)
        sniffer._handle_arp_packet(_FakeARPPacket(GATEWAY_IP, LEGIT_MAC))
        sniffer._handle_arp_packet(_FakeARPPacket(GATEWAY_IP, SPOOF_MAC))
        sniffer.stop()

        first_session = [e for e in sniffer._arp_spoof_events if e["observed_mac"] == SPOOF_MAC]
        self.assertEqual(len(first_session), 1)

        _start(sniffer)
        sniffer._handle_arp_packet(_FakeARPPacket(GATEWAY_IP, LEGIT_MAC))
        sniffer._handle_arp_packet(_FakeARPPacket(GATEWAY_IP, SPOOF_MAC))
        sniffer.stop()

        replayed = [e for e in sniffer._arp_spoof_events if e["observed_mac"] == SPOOF_MAC]
        self.assertEqual(
            len(replayed),
            2,
            "identical ARP spoof after a scan restart must fire again, not be deduped into silence",
        )

    def test_repeat_ssl_strip_after_restart_is_reported_again(self):
        sniffer = PacketSniffer()

        _start(sniffer)
        sniffer._handle_http_packet(_FakeHTTPPacket("google.com", "/login"))
        sniffer.stop()
        self.assertEqual(len(sniffer._ssl_strip_events), 1)

        _start(sniffer)
        sniffer._handle_http_packet(_FakeHTTPPacket("google.com", "/login"))
        sniffer.stop()

        self.assertEqual(
            len(sniffer._ssl_strip_events),
            2,
            "identical SSL-strip request after a scan restart must fire again",
        )

    def test_restart_does_not_inherit_spoofed_mac_as_trusted_baseline(self):
        """A poisoned binding must not survive a restart and invert the attribution."""
        sniffer = PacketSniffer()

        _start(sniffer)
        sniffer._handle_arp_packet(_FakeARPPacket(GATEWAY_IP, LEGIT_MAC))
        sniffer._handle_arp_packet(_FakeARPPacket(GATEWAY_IP, SPOOF_MAC))
        sniffer.stop()
        self.assertEqual(sniffer._ip_mac_bindings[GATEWAY_IP]["mac"], SPOOF_MAC)

        _start(sniffer)
        self.assertNotIn(GATEWAY_IP, sniffer._ip_mac_bindings)

        # The legitimate host re-announces; it must not be flagged as the impostor.
        sniffer._handle_arp_packet(_FakeARPPacket(GATEWAY_IP, LEGIT_MAC))
        sniffer.stop()

        self.assertEqual(
            [e for e in sniffer._arp_spoof_events if e["observed_mac"] == LEGIT_MAC],
            [],
            "legitimate host must not be reported as the impostor after a scan restart",
        )


class TestReasonPrefixOnNewEvents(unittest.TestCase):
    """The Reason: prefix applies at construction time only — never retroactively."""

    def test_new_arp_event_description_uses_reason_prefix(self):
        sniffer = PacketSniffer()
        _start(sniffer)
        sniffer._handle_arp_packet(_FakeARPPacket(GATEWAY_IP, LEGIT_MAC))
        sniffer._handle_arp_packet(_FakeARPPacket(GATEWAY_IP, SPOOF_MAC))
        sniffer.stop()

        self.assertTrue(sniffer._arp_spoof_events[-1]["description"].startswith("Reason: "))

    def test_new_ssl_strip_event_description_uses_reason_prefix(self):
        sniffer = PacketSniffer()
        _start(sniffer)
        sniffer._handle_http_packet(_FakeHTTPPacket("google.com", "/login"))
        sniffer.stop()

        self.assertTrue(sniffer._ssl_strip_events[-1]["description"].startswith("Reason: "))

    def test_new_canary_event_description_uses_reason_prefix(self):
        sniffer = PacketSniffer()
        sniffer._record_ssl_strip_canary_event(
            {
                "status": "fingerprint_mismatch",
                "endpoint": "https://8.8.8.8",
                "fingerprint": "beef",
                "expected_fingerprint": "cafe",
                "error": None,
                "checked_at": "2026-09-05T00:00:00+00:00",
            }
        )

        self.assertTrue(sniffer._ssl_strip_events[-1]["description"].startswith("Reason: "))

    def test_existing_stored_descriptions_are_never_rewritten(self):
        """Guards the alert-ID contract: id = uuid5(description), so old text must not move."""
        legacy = "ARP spoofing suspected: 10.0.0.1 was first mapped to aa:aa and is now claimed by bb:bb."
        sniffer = PacketSniffer()
        sniffer._arp_spoof_events.append(
            {
                "ip_address": "10.0.0.1",
                "previous_mac": "aa:aa",
                "observed_mac": "bb:bb",
                "severity": "high",
                "description": legacy,
                "last_seen": "2020-01-01T00:00:00+00:00",
            }
        )

        _start(sniffer)
        snapshot = sniffer.get_snapshot()
        sniffer.stop()

        self.assertEqual(snapshot["arp_spoof"]["events"][0]["description"], legacy)


if __name__ == "__main__":
    unittest.main()


class TestRequestTargetIsSanitised(unittest.TestCase):
    """Query strings carry tokens and PII; alert text is stored forever."""

    def _event_for(self, target):
        sniffer = PacketSniffer()
        _start(sniffer)
        sniffer._handle_http_packet(_FakeHTTPPacket("google.com", target))
        sniffer.stop()
        return sniffer._ssl_strip_events[-1]

    def test_query_string_is_stripped_from_stored_path_and_description(self):
        event = self._event_for("/login?email=someone@example.com&session=SECRET123")

        self.assertEqual(event["path"], "/login")
        self.assertNotIn("SECRET123", event["description"])
        self.assertNotIn("someone@example.com", event["description"])

    def test_fragment_is_stripped_too(self):
        self.assertEqual(self._event_for("/login#token=SECRET123")["path"], "/login")

    def test_differing_query_strings_do_not_defeat_deduplication(self):
        sniffer = PacketSniffer()
        _start(sniffer)
        for nonce in ("1", "2", "3"):
            sniffer._handle_http_packet(_FakeHTTPPacket("google.com", f"/login?cb={nonce}"))
        sniffer.stop()

        self.assertEqual(
            len(sniffer._ssl_strip_events),
            1,
            "cache-busting params must not flood the capped event history",
        )
