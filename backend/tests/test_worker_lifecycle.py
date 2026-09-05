from __future__ import annotations

import os
import sys
import unittest
from threading import Event
from unittest.mock import MagicMock, patch


BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from capture.sniffer import PacketSniffer  # noqa: E402


class TestWorkersCannotOutliveTheirSession(unittest.TestCase):
    """stop() joins with a 2s timeout, but a poll cycle can block far longer."""

    def _start_capturing_event(self, sniffer):
        with patch("capture.sniffer.Thread", return_value=MagicMock()) as thread_cls:
            sniffer.start()
        return thread_cls.call_args_list[0].kwargs["args"][0]

    def test_each_session_gets_its_own_stop_event(self):
        sniffer = PacketSniffer()

        first = self._start_capturing_event(sniffer)
        sniffer.stop()
        second = self._start_capturing_event(sniffer)
        sniffer.stop()

        self.assertIsNot(first, second)

    def test_a_previous_sessions_event_stays_set_after_a_restart(self):
        sniffer = PacketSniffer()

        first = self._start_capturing_event(sniffer)
        sniffer.stop()
        self.assertTrue(first.is_set())

        second = self._start_capturing_event(sniffer)
        self.assertTrue(
            first.is_set(),
            "starting a new session must not un-stop a worker that outlived its join",
        )
        self.assertFalse(second.is_set())

    def test_poll_loop_honours_its_own_event_not_the_current_one(self):
        """A straggler returning from a 15s netsh call must exit, not keep polling."""
        sniffer = PacketSniffer()
        sniffer._scan_access_points = lambda: self.fail("a stopped worker must not scan")
        previous_session = Event()
        previous_session.set()
        sniffer._stop_event = Event()  # a new session is live and not stopped

        sniffer._poll_loop(previous_session)  # returns immediately or the test hangs

    def test_canary_loop_honours_its_own_event_not_the_current_one(self):
        sniffer = PacketSniffer()
        sniffer._run_ssl_canary_check = lambda: self.fail("a stopped worker must not probe")
        previous_session = Event()
        previous_session.set()
        sniffer._stop_event = Event()

        sniffer._ssl_canary_loop(previous_session)


if __name__ == "__main__":
    unittest.main()
