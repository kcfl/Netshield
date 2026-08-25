from __future__ import annotations

import hashlib
import json
import platform
import re
import socket
import ssl
import subprocess
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from threading import Event, RLock, Thread, current_thread
from time import monotonic
from typing import Any, Dict, Optional
from urllib.parse import urlparse

try:
    from scapy.all import ARP, AsyncSniffer, Raw, TCP, get_working_if
except Exception as exc:  # pragma: no cover - depends on runtime environment
    ARP = None
    AsyncSniffer = None
    Raw = None
    TCP = None
    get_working_if = None
    SCAPY_IMPORT_ERROR = exc
else:
    SCAPY_IMPORT_ERROR = None

from config import Config
from runtime_logging import get_runtime_logger


class PacketSniffer:
    """Poll OS Wi-Fi scans and flag possible evil-twin broadcasts."""

    def __init__(self, interface: Optional[str] = None, poll_interval: int = 5):
        self._requested_interface = interface
        self._interface: Optional[str] = None
        self._poll_interval = poll_interval
        self._worker: Optional[Thread] = None
        self._traffic_monitor_worker: Optional[Thread] = None
        self._ssl_canary_worker: Optional[Thread] = None
        self._traffic_sniffer = None
        self._traffic_interface: Optional[str] = None
        self._connected_ssid: Optional[str] = None
        self._connected_ssid_error: Optional[str] = None
        self._stop_event = Event()
        self._running = False
        self._last_error: Optional[str] = None
        self._traffic_monitor_error: Optional[str] = None
        self._started_at: Optional[str] = None
        self._lock = RLock()
        self._access_points: Dict[str, Dict[str, Any]] = {}
        self._ssid_index: dict[str, set[str]] = defaultdict(set)
        self._evil_twin_groups: list[Dict[str, Any]] = []
        self._ip_mac_bindings: Dict[str, Dict[str, str]] = {}
        self._arp_spoof_events: list[Dict[str, str]] = []
        self._arp_spoof_signatures: set[tuple[str, str, str]] = set()
        self._arp_suppress_until = 0.0
        self._ssl_strip_events: list[Dict[str, str]] = []
        self._ssl_strip_signatures: set[tuple[str, str]] = set()
        self._runtime_logger = get_runtime_logger()
        self._heartbeat_interval_seconds = 5.0
        self._last_wifi_heartbeat_monotonic = 0.0
        self._last_callback_heartbeat_monotonic = 0.0
        self._last_ssl_canary_heartbeat_monotonic = 0.0
        self._ssl_canary_url = Config.SSL_CANARY_URL
        self._ssl_canary_interval = Config.SSL_CANARY_INTERVAL
        self._ssl_canary_pin_path = Path(Config.SSL_CANARY_PIN_PATH)
        self._ssl_pinned_fingerprint = self._load_ssl_canary_pin()
        self._last_ssl_canary_result: Dict[str, Any] = {
            "status": "pending_pin" if not self._ssl_pinned_fingerprint else "pin_loaded",
            "fingerprint": None,
            "expected_fingerprint": self._ssl_pinned_fingerprint,
            "pin_path": str(self._ssl_canary_pin_path),
            "error": None,
        }
        self._last_callback_packet_at: Optional[str] = None
        self._known_https_domains = {
            "accounts.google.com",
            "amazon.com",
            "apple.com",
            "facebook.com",
            "github.com",
            "gmail.com",
            "google.com",
            "instagram.com",
            "linkedin.com",
            "login.microsoftonline.com",
            "microsoft.com",
            "netflix.com",
            "outlook.com",
            "paypal.com",
            "x.com",
            "youtube.com",
        }
        self._ssl_strip_exceptions = {
            "delivery.mp.microsoft.com",
            "dl.delivery.mp.microsoft.com",
        }

    def start(self) -> None:
        """Start asynchronous Wi-Fi scan polling."""
        with self._lock:
            if self._running:
                return

            try:
                self._stop_event.clear()
                self._interface = self._requested_interface
                self._running = True
                self._last_error = None
                self._started_at = self._utc_now()
                self._worker = Thread(
                    target=self._poll_loop,
                    name="netshield-wifi-poller",
                    daemon=True,
                )
                self._worker.start()
                self._traffic_monitor_worker = Thread(
                    target=self._start_traffic_monitor,
                    name="netshield-traffic-bootstrap",
                    daemon=True,
                )
                self._traffic_monitor_worker.start()
                self._ssl_canary_worker = Thread(
                    target=self._ssl_canary_loop,
                    name="netshield-ssl-canary",
                    daemon=True,
                )
                self._ssl_canary_worker.start()
            except Exception as exc:  # pragma: no cover - runtime dependent
                self._worker = None
                self._traffic_monitor_worker = None
                self._ssl_canary_worker = None
                self._traffic_sniffer = None
                self._traffic_interface = None
                self._running = False
                self._last_error = str(exc)

    def stop(self) -> None:
        """Stop asynchronous Wi-Fi scan polling if it is running."""
        with self._lock:
            worker = self._worker
            self._worker = None
            traffic_monitor_worker = self._traffic_monitor_worker
            self._traffic_monitor_worker = None
            ssl_canary_worker = self._ssl_canary_worker
            self._ssl_canary_worker = None
            traffic_sniffer = self._traffic_sniffer
            self._traffic_sniffer = None
            self._traffic_interface = None
            self._running = False
            self._stop_event.set()

        if worker is None and traffic_monitor_worker is None and ssl_canary_worker is None:
            self._stop_traffic_monitor(traffic_sniffer)
            return

        if worker is not None:
            try:
                worker.join(timeout=2)
            except Exception as exc:  # pragma: no cover - runtime dependent
                with self._lock:
                    self._last_error = str(exc)

        if traffic_monitor_worker is not None:
            try:
                traffic_monitor_worker.join(timeout=2)
            except Exception as exc:  # pragma: no cover - runtime dependent
                with self._lock:
                    self._traffic_monitor_error = str(exc)

        if ssl_canary_worker is not None:
            try:
                ssl_canary_worker.join(timeout=2)
            except Exception:
                pass

        self._stop_traffic_monitor(traffic_sniffer)

    def is_active(self) -> bool:
        with self._lock:
            return self._running

    def get_scan_status(self) -> Dict[str, Any]:
        with self._lock:
            trust_info = self._calculate_trust_score()
            return {
                "active": self._running,
                "status": "running" if self._running else "stopped",
                "interface": self._interface,
                "traffic_interface": self._traffic_interface,
                "started_at": self._started_at,
                "error": self._last_error,
                "traffic_monitor_error": self._traffic_monitor_error,
                "wifi_poller_alive": bool(self._worker and self._worker.is_alive()),
                "traffic_bootstrap_alive": bool(
                    self._traffic_monitor_worker and self._traffic_monitor_worker.is_alive()
                ),
                "ssl_canary_alive": bool(
                    self._ssl_canary_worker and self._ssl_canary_worker.is_alive()
                ),
                "ssl_canary_status": dict(self._last_ssl_canary_result),
                "connected_ssid_error": self._connected_ssid_error or "",
                "arp_spoof": self._build_arp_status(),
                "trust_score": trust_info["trust_score"],
                "trust_factors": trust_info["factors"],
            }

    def get_snapshot(self) -> Dict[str, Any]:
        """Return the currently seen access points and evil-twin candidates."""
        with self._lock:
            access_points = sorted(
                (dict(ap) for ap in self._access_points.values()),
                key=lambda item: ((item.get("ssid") or "").lower(), item["bssid"]),
            )
            evil_twin_groups = [dict(group) for group in self._evil_twin_groups]
            suspicious_group_count = sum(
                1
                for group in evil_twin_groups
                if self._is_suspicious_evil_twin_severity(group.get("severity"))
            )
            trust_info = self._calculate_trust_score()
            return {
                "active": self._running,
                "status": "running" if self._running else "stopped",
                "interface": self._interface,
                "traffic_interface": self._traffic_interface,
                "started_at": self._started_at,
                "total_access_points": len(access_points),
                "evil_twin_count": suspicious_group_count,
                "evil_twin_detected": suspicious_group_count > 0,
                "access_points": access_points,
                "evil_twin_groups": evil_twin_groups,
                "error": self._last_error,
                "traffic_monitor_error": self._traffic_monitor_error,
                "ssl_canary_status": dict(self._last_ssl_canary_result),
                "connected_ssid_error": self._connected_ssid_error or "",
                "arp_spoof": self._build_arp_status(),
                "ssl_strip": self._build_ssl_strip_status(),
                "trust_score": trust_info["trust_score"],
                "trust_factors": trust_info["factors"],
            }

    def _is_active_event(self, timestamp: str) -> bool:
        if not self._started_at or not timestamp:
            return False
        return timestamp >= self._started_at

    def _calculate_trust_score(self) -> Dict[str, Any]:
        with self._lock:
            score = 100
            factors = []

            active_arp = [e for e in self._arp_spoof_events if self._is_active_event(e.get("last_seen", ""))]
            if active_arp:
                score -= 30
                factors.append("ARP spoof alert active (-30)")
            
            ssl_status = self._last_ssl_canary_result.get("status")
            checked_at = self._last_ssl_canary_result.get("checked_at", "")
            if self._is_active_event(checked_at):
                if ssl_status in {"fingerprint_mismatch", "no_tls"}:
                    score -= 25
                    factors.append("SSL Canary mismatch/downgrade (-25)")
                elif ssl_status == "error":
                    score -= 20
                    factors.append("SSL Canary error (-20)")
                elif ssl_status in {"pin_delayed", "pending_pin"}:
                    score -= 10
                    factors.append("SSL Canary pending or delayed (-10)")

            evil_twin_detected = sum(
                1 for group in self._evil_twin_groups 
                if self._is_suspicious_evil_twin_severity(group.get("severity"))
            ) > 0
            if evil_twin_detected:
                score -= 20
                factors.append("Evil-twin group detected (-20)")

            if getattr(self, "_arp_suppress_until", 0.0) > monotonic():
                score -= 10
                factors.append("ARP Monitor paused/suppressed (-10)")

            if self._connected_ssid_error:
                score -= 10
                factors.append("SSID Scanner error/paused (-10)")

            if not factors:
                factors.append("Perfect condition")

            return {"trust_score": max(0, score), "factors": factors}

    def _poll_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                scan_result = self._scan_access_points()
                self._apply_scan_results(scan_result)
                with self._lock:
                    self._last_error = None
            except Exception as exc:  # pragma: no cover - runtime dependent
                with self._lock:
                    self._last_error = str(exc)
                self._runtime_logger.exception("Wi-Fi poller iteration failed.")

            self._log_wifi_poller_heartbeat()
            self._stop_event.wait(self._poll_interval)

    def _ssl_canary_loop(self) -> None:
        while not self._stop_event.is_set():
            # Wait for network to settle before checking canary
            # Also avoid the race condition where Canary runs before the first Wi-Fi poll completes
            with self._lock:
                ssid_initialized = self._connected_ssid is not None
            suppress_until = getattr(self, "_arp_suppress_until", 0.0)
            now = monotonic()

            if not ssid_initialized:
                self._stop_event.wait(1.0)
                continue
            elif suppress_until > now:
                self._stop_event.wait(suppress_until - now)
                continue

            if not self._get_current_canary_pin():
                check_result = self._ensure_ssl_canary_pin()
            else:
                check_result = self._run_ssl_canary_check()

            if check_result["status"] in {"no_tls", "fingerprint_mismatch"}:
                self._record_ssl_strip_canary_event(check_result)

            with self._lock:
                self._last_ssl_canary_result = dict(check_result)

            self._log_ssl_canary_heartbeat(check_result)
            self._stop_event.wait(max(1, int(self._ssl_canary_interval)))

    def reset_ssl_canary_pin(self) -> Dict[str, Any]:
        try:
            self._ssl_canary_pin_path.unlink(missing_ok=True)
        except Exception as exc:  # pragma: no cover - runtime dependent
            self._runtime_logger.warning("Failed to delete ssl-canary pin file: %s", exc)

        with self._lock:
            self._ssl_pinned_fingerprint = None
            self._last_ssl_canary_result = {
                "status": "pending_pin",
                "fingerprint": None,
                "expected_fingerprint": None,
                "pin_path": str(self._ssl_canary_pin_path),
                "error": "canary pin was cleared manually; waiting to re-pin",
            }

        self._runtime_logger.info(
            "ssl-canary pin cleared manually path=%s; next clean cycle will establish a new pin",
            self._ssl_canary_pin_path,
        )
        return self.get_scan_status()

    def reset_debug_test_state(self) -> Dict[str, Any]:
        with self._lock:
            self._ip_mac_bindings.clear()
            self._arp_spoof_events.clear()
            self._arp_spoof_signatures.clear()
            self._ssl_strip_events.clear()
            self._ssl_strip_signatures.clear()

        self._runtime_logger.info(
            "debug test state cleared: arp spoof and ssl strip event history/signatures reset; ssl-canary pin preserved"
        )
        return self.get_scan_status()

    def _get_current_canary_pin(self) -> Optional[str]:
        with self._lock:
            return self._ssl_pinned_fingerprint

    def _ensure_ssl_canary_pin(self) -> Dict[str, Any]:
        checked_at = self._utc_now()
        endpoint = self._ssl_canary_url

        with self._lock:
            arp_spoof_detected = bool(self._arp_spoof_events)
            passive_ssl_strip_detected = any(not event.get("endpoint") for event in self._ssl_strip_events)
            traffic_monitor_error = self._traffic_monitor_error

        if arp_spoof_detected or passive_ssl_strip_detected:
            return {
                "checked_at": checked_at,
                "endpoint": endpoint,
                "status": "pin_delayed",
                "fingerprint": None,
                "expected_fingerprint": None,
                "pin_path": str(self._ssl_canary_pin_path),
                "error": "initial TOFU pin delayed because active MITM indicators are already present",
            }

        probe_result = self._probe_ssl_canary_endpoint()
        probe_result["pin_path"] = str(self._ssl_canary_pin_path)
        if probe_result["status"] != "ok":
            return probe_result

        fingerprint = probe_result["fingerprint"]
        trust_is_uncertain = bool(traffic_monitor_error)
        self._persist_ssl_canary_pin(fingerprint)

        with self._lock:
            self._ssl_pinned_fingerprint = fingerprint

        if trust_is_uncertain:
            self._runtime_logger.warning(
                "ssl-canary pinned under uncertain conditions fingerprint=%s reason=%s path=%s",
                fingerprint,
                traffic_monitor_error,
                self._ssl_canary_pin_path,
            )
            status = "pinned_uncertain"
            error = f"trust established while traffic health was uncertain: {traffic_monitor_error}"
        else:
            self._runtime_logger.info(
                "ssl-canary pinned on first run fingerprint=%s path=%s",
                fingerprint,
                self._ssl_canary_pin_path,
            )
            status = "pinned"
            error = None

        return {
            "checked_at": checked_at,
            "endpoint": endpoint,
            "status": status,
            "fingerprint": fingerprint,
            "expected_fingerprint": fingerprint,
            "pin_path": str(self._ssl_canary_pin_path),
            "error": error,
        }

    def _probe_ssl_canary_endpoint(self) -> Dict[str, Any]:
        checked_at = self._utc_now()

        # If we already have a pin, strictly use the pinned endpoint. 
        # Otherwise, if we're trying to establish a pin, use fallbacks.
        if self._get_current_canary_pin():
            endpoints_to_try = [self._ssl_canary_url]
        else:
            endpoints_to_try = [self._ssl_canary_url, "https://1.1.1.1", "https://9.9.9.9"]

        # Deduplicate while preserving order
        endpoints = []
        for ep in endpoints_to_try:
            if ep not in endpoints:
                endpoints.append(ep)

        last_result = None
        for endpoint in endpoints:
            parsed = urlparse(endpoint)
            scheme = (parsed.scheme or "").lower()
            hostname = (parsed.hostname or "").strip()
            port = parsed.port or 443

            result: Dict[str, Any] = {
                "checked_at": checked_at,
                "endpoint": endpoint,
                "status": "unknown",
                "fingerprint": None,
                "expected_fingerprint": None,
                "error": None,
            }

            if scheme and scheme != "https":
                result["status"] = "no_tls"
                result["error"] = f"configured endpoint scheme is not https (scheme={scheme})"
                return result

            if not hostname:
                result["status"] = "error"
                result["error"] = "configured endpoint hostname is missing"
                return result

            raw_socket = None
            tls_socket = None
            try:
                raw_socket = socket.create_connection((hostname, port), timeout=5.0)
                context = ssl._create_unverified_context()
                tls_socket = context.wrap_socket(raw_socket, server_hostname=hostname)
                cert_der = tls_socket.getpeercert(binary_form=True)
                result["fingerprint"] = hashlib.sha256(cert_der).hexdigest().lower() if cert_der else None
                result["status"] = "ok"
            except ssl.SSLError as exc:
                message = str(exc)
                downgrade_indicators = ("wrong version number", "unknown protocol", "http request")
                if any(indicator in message.lower() for indicator in downgrade_indicators):
                    result["status"] = "no_tls"
                else:
                    result["status"] = "error"
                result["error"] = message
            except Exception as exc:  # pragma: no cover - runtime dependent
                result["status"] = "error"
                result["error"] = str(exc)
            finally:
                for sock in (tls_socket, raw_socket):
                    try:
                        if sock is not None:
                            sock.close()
                    except Exception:
                        pass

            last_result = result
            if result["status"] == "ok":
                break
            elif result["status"] == "no_tls":
                break

        if last_result and last_result["status"] == "ok" and last_result["endpoint"] != self._ssl_canary_url:
            self._runtime_logger.info("Primary canary failed; falling back to active canary endpoint %s", last_result["endpoint"])
            self._ssl_canary_url = last_result["endpoint"]

        return last_result

    def _run_ssl_canary_check(self) -> Dict[str, Any]:
        expected_fingerprint = (self._get_current_canary_pin() or "").strip().lower()
        result = self._probe_ssl_canary_endpoint()
        result["expected_fingerprint"] = expected_fingerprint or None
        result["pin_path"] = str(self._ssl_canary_pin_path)

        if result["status"] == "ok" and result["fingerprint"] != expected_fingerprint:
            result["status"] = "fingerprint_mismatch"
            result["error"] = "presented certificate fingerprint does not match pinned value"

        return result

    def _load_ssl_canary_pin(self) -> Optional[str]:
        try:
            if not self._ssl_canary_pin_path.exists():
                return None

            payload = json.loads(self._ssl_canary_pin_path.read_text(encoding="utf-8"))
            fingerprint = str(payload.get("fingerprint") or "").strip().lower()
            if not fingerprint:
                return None

            pinned_endpoint = payload.get("endpoint")
            if pinned_endpoint:
                self._ssl_canary_url = pinned_endpoint

            self._runtime_logger.info(
                "ssl-canary loaded pinned fingerprint=%s endpoint=%s path=%s",
                fingerprint,
                self._ssl_canary_url,
                self._ssl_canary_pin_path,
            )
            return fingerprint
        except Exception as exc:  # pragma: no cover - runtime dependent
            self._runtime_logger.warning("Failed to load ssl-canary pin file: %s", exc)
            return None

    def _persist_ssl_canary_pin(self, fingerprint: str) -> None:
        self._ssl_canary_pin_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "fingerprint": fingerprint,
            "endpoint": self._ssl_canary_url,
            "pinned_at": self._utc_now(),
        }
        self._ssl_canary_pin_path.write_text(
            json.dumps(payload, indent=2),
            encoding="utf-8",
        )

    def _record_ssl_strip_canary_event(self, check_result: Dict[str, Any]) -> None:
        endpoint = check_result.get("endpoint", "") or "unknown"
        hostname = urlparse(endpoint).hostname or endpoint
        fingerprint = check_result.get("fingerprint")
        expected = check_result.get("expected_fingerprint")
        error = check_result.get("error") or "unknown"
        now = check_result.get("checked_at") or self._utc_now()

        if check_result.get("status") == "no_tls":
            description = (
                f"Possible SSL stripping / MITM: TLS connection to {hostname} failed "
                f"(endpoint={endpoint}). Error: {error}"
            )
        else:
            description = (
                f"Possible SSL stripping / MITM: certificate pin mismatch for {hostname} "
                f"(endpoint={endpoint}). Expected={expected or 'unset'} Observed={fingerprint or 'none'}."
            )

        signature = (hostname, f"ssl-canary:{check_result.get('status')}:{fingerprint or error}")

        with self._lock:
            if signature in self._ssl_strip_signatures:
                return
            self._ssl_strip_signatures.add(signature)
            self._ssl_strip_events.append(
                {
                    "severity": "high",
                    "description": description,
                    "last_seen": now,
                    "endpoint": endpoint,
                    "fingerprint": fingerprint,
                    "expected_fingerprint": expected,
                }
            )
            self._ssl_strip_events = self._ssl_strip_events[-25:]

    def _log_ssl_canary_heartbeat(self, check_result: Dict[str, Any]) -> None:
        status = check_result.get("status") or "unknown"
        endpoint = check_result.get("endpoint") or "unknown"
        fingerprint = check_result.get("fingerprint") or "none"
        expected = check_result.get("expected_fingerprint") or "unset"
        pin_path = check_result.get("pin_path") or str(self._ssl_canary_pin_path)
        error = check_result.get("error") or "none"

        self._runtime_logger.info(
            "heartbeat ssl-canary alive thread=%s endpoint=%s status=%s fingerprint=%s expected=%s pin_path=%s error=%s",
            current_thread().name,
            endpoint,
            status,
            fingerprint,
            expected,
            pin_path,
            error,
        )

    def _get_connected_ssid(self) -> Optional[str]:
        system_name = platform.system().lower()
        if system_name == "windows":
            try:
                result = subprocess.run(
                    ["netsh", "wlan", "show", "interfaces"],
                    capture_output=True, text=True, errors="ignore", timeout=5
                )
                connected = False
                for line in result.stdout.splitlines():
                    if re.match(r"^\s*State\s*:\s*connected", line, re.IGNORECASE):
                        connected = True
                    if connected:
                        ssid_match = re.match(r"^\s*SSID\s*:\s*(.*)", line, re.IGNORECASE)
                        if ssid_match and ssid_match.group(1).strip() != "BSSID":
                            return ssid_match.group(1).strip()
            except Exception:
                pass
        elif system_name == "linux":
            try:
                result = subprocess.run(
                    ["nmcli", "-t", "-f", "active,ssid", "dev", "wifi"],
                    capture_output=True, text=True, errors="ignore", timeout=5
                )
                for line in result.stdout.splitlines():
                    if line.startswith("yes:"):
                        return line[4:].strip()
            except Exception:
                pass
        return None

    def _scan_access_points(self) -> Dict[str, Any]:
        system_name = platform.system().lower()

        if system_name == "windows":
            return self._scan_windows()

        if system_name == "linux":
            return self._scan_linux()

        raise RuntimeError(f"Unsupported operating system for Wi-Fi scanning: {platform.system()}")

    def _force_windows_wlan_scan(self) -> None:
        try:
            import ctypes
            from ctypes import wintypes
            
            wlanapi = ctypes.windll.wlanapi

            class WLAN_INTERFACE_INFO(ctypes.Structure):
                _fields_ = [
                    ('InterfaceGuid', ctypes.c_byte * 16),
                    ('strInterfaceDescription', ctypes.c_wchar * 256),
                    ('isState', ctypes.c_uint)
                ]

            class WLAN_INTERFACE_INFO_LIST(ctypes.Structure):
                _fields_ = [
                    ('dwNumberOfItems', wintypes.DWORD),
                    ('dwIndex', wintypes.DWORD),
                    ('InterfaceInfo', WLAN_INTERFACE_INFO * 1)
                ]

            client_handle = wintypes.HANDLE()
            negotiated_version = wintypes.DWORD()
            
            result = wlanapi.WlanOpenHandle(2, None, ctypes.byref(negotiated_version), ctypes.byref(client_handle))
            if result != 0:
                return

            try:
                p_interface_list = ctypes.POINTER(WLAN_INTERFACE_INFO_LIST)()
                result = wlanapi.WlanEnumInterfaces(client_handle, None, ctypes.byref(p_interface_list))
                if result == 0 and p_interface_list.contents.dwNumberOfItems > 0:
                    for i in range(p_interface_list.contents.dwNumberOfItems):
                        interface_guid = p_interface_list.contents.InterfaceInfo[i].InterfaceGuid
                        wlanapi.WlanScan(client_handle, ctypes.byref(interface_guid), None, None, None)
            finally:
                if client_handle:
                    wlanapi.WlanCloseHandle(client_handle, None)
        except Exception as exc:
            self._runtime_logger.debug(f"Failed to force Windows WLAN scan: {exc}")

    def _force_linux_wlan_scan(self) -> None:
        try:
            subprocess.run(["nmcli", "dev", "wifi", "rescan"], capture_output=True, timeout=5)
        except Exception as exc:
            self._runtime_logger.debug(f"Failed to force Linux WLAN rescan: {exc}")

    def _scan_windows(self) -> Dict[str, Any]:
        self._force_windows_wlan_scan()
        
        # Give the async WlanScan time to populate the OS cache so we can read it in the same cycle
        import time
        time.sleep(1.5)
        
        result = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            check=True,
            timeout=15,
        )
        return self._parse_windows_scan(result.stdout)

    def _scan_linux(self) -> Dict[str, Any]:
        self._force_linux_wlan_scan()
        result = subprocess.run(
            ["nmcli", "dev", "wifi", "list"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            check=True,
            timeout=15,
        )
        return self._parse_linux_scan(result.stdout)

    def _apply_scan_results(self, scan_result: Dict[str, Any]) -> None:
        interface = scan_result.get("interface")
        scanned_access_points = scan_result.get("access_points", [])
        now = self._utc_now()

        with self._lock:
            self._interface = interface or self._interface
            
            new_ssid = self._get_connected_ssid()
            if new_ssid != self._connected_ssid:
                self._ip_mac_bindings.clear()
                self._arp_suppress_until = monotonic() + 10.0
                
            if not new_ssid:
                error_msg = "Could not determine connected SSID — evil-twin evaluation paused"
                if self._connected_ssid_error != error_msg:
                    self._connected_ssid_error = error_msg
                    self._runtime_logger.warning(error_msg)
            else:
                if self._connected_ssid_error is not None:
                    self._runtime_logger.info(f"Connected SSID detected: {new_ssid} — evil-twin evaluation resumed")
                    self._connected_ssid_error = None
            self._connected_ssid = new_ssid

            updated_access_points: Dict[str, Dict[str, Any]] = {}
            updated_ssid_index: dict[str, set[str]] = defaultdict(set)

            for item in scanned_access_points:
                bssid = item["bssid"].lower()
                ssid = item["ssid"]
                existing = self._access_points.get(bssid, {})
                security_details = self._normalize_security_profile(
                    security_type=item.get("security_type"),
                    auth_method=item.get("auth_method"),
                    encryption=item.get("encryption"),
                    security_raw=item.get("security_raw"),
                )

                ap_record = {
                    "ssid": ssid,
                    "bssid": bssid,
                    "oui": self._extract_oui_prefix(bssid),
                    "signal_strength": item.get("signal_strength"),
                    "first_seen": existing.get("first_seen", now),
                    "last_seen": now,
                    "evil_twin_suspected": False,
                    "security_type": security_details["security_type"],
                    "auth_method": security_details["auth_method"],
                    "encryption": security_details["encryption"],
                    "security_raw": security_details["security_raw"],
                }
                updated_access_points[bssid] = ap_record

                if ssid:
                    updated_ssid_index[ssid].add(bssid)

            self._access_points = updated_access_points
            self._ssid_index = updated_ssid_index
            self._refresh_evil_twin_flags_locked()

    def _start_traffic_monitor(self) -> None:
        if AsyncSniffer is None or get_working_if is None:
            with self._lock:
                self._traffic_monitor_error = f"Scapy is unavailable: {SCAPY_IMPORT_ERROR}"
            self._runtime_logger.warning("Scapy traffic monitor unavailable: %s", SCAPY_IMPORT_ERROR)
            return

        try:
            if self._stop_event.is_set():
                return

            interface = self._resolve_capture_interface()
            sniffer = AsyncSniffer(
                iface=interface,
                prn=self._handle_traffic_packet,
                store=False,
            )
            sniffer.start()
            self._runtime_logger.info("Scapy traffic monitor started on interface=%s alive", interface)

            with self._lock:
                if self._stop_event.is_set() or not self._running:
                    try:
                        sniffer.stop()
                    except Exception:
                        pass
                    return

                self._traffic_sniffer = sniffer
                self._traffic_interface = interface
                self._traffic_monitor_error = None
        except Exception as exc:  # pragma: no cover - runtime dependent
            with self._lock:
                self._traffic_sniffer = None
                self._traffic_interface = None
                self._traffic_monitor_error = str(exc)
            self._runtime_logger.exception("Scapy traffic monitor failed to start.")
        finally:
            with self._lock:
                if self._traffic_monitor_worker is current_thread():
                    self._traffic_monitor_worker = None

    def _stop_traffic_monitor(self, traffic_sniffer: Any) -> None:
        if traffic_sniffer is None:
            return

        try:
            traffic_sniffer.stop()
            self._runtime_logger.info("Scapy traffic monitor stopped alive")
        except Exception as exc:  # pragma: no cover - runtime dependent
            with self._lock:
                self._traffic_monitor_error = str(exc)
            self._runtime_logger.exception("Failed to stop Scapy traffic monitor.")

    def _resolve_capture_interface(self) -> str:
        if self._requested_interface:
            return self._requested_interface

        active_interface = get_working_if()
        return getattr(active_interface, "name", str(active_interface))

    def _handle_traffic_packet(self, packet: Any) -> None:
        packet_timestamp = self._utc_now()
        with self._lock:
            self._last_callback_packet_at = packet_timestamp

        self._log_scapy_callback_heartbeat(packet_timestamp, packet)

        if ARP is not None and packet.haslayer(ARP):
            self._handle_arp_packet(packet)

        if TCP is not None and Raw is not None and packet.haslayer(TCP) and packet.haslayer(Raw):
            self._handle_http_packet(packet)

    def _handle_arp_packet(self, packet: Any) -> None:
        if monotonic() < getattr(self, "_arp_suppress_until", 0.0):
            return

        arp_layer = packet[ARP]
        ip_address = getattr(arp_layer, "psrc", "")
        mac_address = getattr(arp_layer, "hwsrc", "").lower()

        if not ip_address or not mac_address:
            return

        if ip_address in {"0.0.0.0", "255.255.255.255", "127.0.0.1"} or ip_address.startswith("169.254.") or ip_address.startswith("224."):
            return

        now = self._utc_now()

        with self._lock:
            previous_mapping = self._ip_mac_bindings.get(ip_address)
            if previous_mapping and previous_mapping["mac"] != mac_address:
                event_signature = (ip_address, previous_mapping["mac"], mac_address)
                if event_signature not in self._arp_spoof_signatures:
                    self._arp_spoof_signatures.add(event_signature)
                    self._arp_spoof_events.append(
                        {
                            "ip_address": ip_address,
                            "previous_mac": previous_mapping["mac"],
                            "observed_mac": mac_address,
                            "severity": "high",
                            "description": (
                                f"ARP spoofing suspected: {ip_address} was first mapped to "
                                f"{previous_mapping['mac']} and is now claimed by {mac_address}."
                            ),
                            "last_seen": now,
                        }
                    )
                    self._arp_spoof_events = self._arp_spoof_events[-25:]

            self._ip_mac_bindings[ip_address] = {"mac": mac_address, "last_seen": now}

    def _handle_http_packet(self, packet: Any) -> None:
        tcp_layer = packet[TCP]
        if getattr(tcp_layer, "dport", None) != 80:
            return

        raw_payload = bytes(packet[Raw].load)
        try:
            payload_text = raw_payload.decode("utf-8", errors="ignore")
        except Exception:
            return

        request_line = payload_text.splitlines()[0] if payload_text.splitlines() else ""
        if not re.match(r"^(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH)\s+", request_line):
            return

        host_match = re.search(r"(?im)^Host:\s*([^\s:]+)", payload_text)
        if not host_match:
            return

        host = host_match.group(1).strip().lower()
        if not self._is_known_https_domain(host):
            return

        now = self._utc_now()
        request_target = request_line.split(" ")[1] if " " in request_line else "/"

        # Ignore OCSP traffic (HTTP by design)
        if "/ocsp/" in request_target.lower():
            return
        content_type_match = re.search(r"(?im)^Content-Type:\s*(.+)", payload_text)
        if content_type_match and "application/ocsp-request" in content_type_match.group(1).lower():
            return

        signature = (host, request_target)

        with self._lock:
            if signature in self._ssl_strip_signatures:
                return

            self._ssl_strip_signatures.add(signature)
            self._ssl_strip_events.append(
                {
                    "host": host,
                    "path": request_target,
                    "severity": "medium",
                    "description": (
                        f"Possible SSL stripping: observed an HTTP request to {host}{request_target} "
                        "even though the domain is expected to use HTTPS."
                    ),
                    "last_seen": now,
                }
            )
            self._ssl_strip_events = self._ssl_strip_events[-25:]

    def _refresh_evil_twin_flags_locked(self) -> None:
        evaluated_groups = []

        for ssid, bssids in self._ssid_index.items():
            if not self._connected_ssid or ssid != self._connected_ssid:
                continue

            active_bssids = sorted(
                {
                    bssid
                    for bssid in bssids
                    if bssid in self._access_points and self._access_points[bssid]["ssid"] == ssid
                }
            )

            if not ssid or len(active_bssids) <= 1:
                continue

            ap_records = [self._access_points[bssid] for bssid in active_bssids]
            unique_ouis = {
                ap_record.get("oui") or self._extract_oui_prefix(ap_record["bssid"])
                for ap_record in ap_records
            }
            security_profiles = {
                self._format_security_profile(
                    ap_record.get("security_type"),
                    ap_record.get("auth_method"),
                )
                for ap_record in ap_records
            }
            comparable_security_profiles = {
                profile for profile in security_profiles if profile.lower() != "unknown"
            }

            oui_mismatch = len(unique_ouis) > 1
            security_mismatch = len(comparable_security_profiles) > 1

            if security_mismatch and oui_mismatch:
                severity = "critical"
                score = 95
                reasons = [
                    "The same SSID is being advertised by access points with different OUI prefixes.",
                    "The access points also disagree on security/authentication settings.",
                ]
            elif security_mismatch:
                severity = "high"
                score = 80
                reasons = [
                    "The same SSID is being advertised with inconsistent security/authentication settings.",
                ]
            elif oui_mismatch:
                severity = "medium"
                score = 55
                reasons = [
                    "The same SSID is being advertised by access points with different OUI prefixes.",
                ]
            else:
                severity = "info"
                score = 15
                reasons = [
                    "The same SSID is present on multiple BSSIDs, but the vendor prefixes and security settings are consistent with a legitimate multi-AP deployment.",
                ]

            evaluated_groups.append(
                {
                    "ssid": ssid,
                    "bssids": active_bssids,
                    "ouis": sorted(unique_ouis),
                    "security_profiles": sorted(security_profiles),
                    "score": score,
                    "severity": severity,
                    "reason": " ".join(reasons),
                    "reasons": reasons,
                    "flag": (
                        "possible-evil-twin"
                        if self._is_suspicious_evil_twin_severity(severity)
                        else "likely-legitimate-multi-ap"
                    ),
                    "suspicious": self._is_suspicious_evil_twin_severity(severity),
                }
            )

        suspicious_lookup = {
            (group["ssid"], bssid)
            for group in evaluated_groups
            if self._is_suspicious_evil_twin_severity(group.get("severity"))
            for bssid in group["bssids"]
        }

        for ap_record in self._access_points.values():
            ap_record["evil_twin_suspected"] = (
                ap_record["ssid"],
                ap_record["bssid"],
            ) in suspicious_lookup

        self._evil_twin_groups = evaluated_groups

    def _log_wifi_poller_heartbeat(self) -> None:
        if not self._heartbeat_due("_last_wifi_heartbeat_monotonic"):
            return

        with self._lock:
            suspicious_group_count = sum(
                1
                for group in self._evil_twin_groups
                if self._is_suspicious_evil_twin_severity(group.get("severity"))
            )
            message = (
                "heartbeat wifi-poller alive "
                f"thread={current_thread().name} "
                f"active={self._running} "
                f"interface={self._interface or 'unknown'} "
                f"traffic_interface={self._traffic_interface or 'unknown'} "
                f"access_points={len(self._access_points)} "
                f"evil_twin_groups={suspicious_group_count} "
                f"last_callback_packet_at={self._last_callback_packet_at or 'never'} "
                f"last_error={self._last_error or 'none'} "
                f"traffic_monitor_error={self._traffic_monitor_error or 'none'}"
            )

        self._runtime_logger.info(message)

    def _log_scapy_callback_heartbeat(self, packet_timestamp: str, packet: Any) -> None:
        if not self._heartbeat_due("_last_callback_heartbeat_monotonic"):
            return

        packet_kinds = []
        if ARP is not None and packet.haslayer(ARP):
            packet_kinds.append("ARP")
        if TCP is not None and packet.haslayer(TCP):
            packet_kinds.append("TCP")
        if Raw is not None and packet.haslayer(Raw):
            packet_kinds.append("RAW")
        if not packet_kinds:
            packet_kinds.append(packet.__class__.__name__)

        self._runtime_logger.info(
            "heartbeat scapy-callback alive thread=%s packet_types=%s packet_timestamp=%s",
            current_thread().name,
            ",".join(packet_kinds),
            packet_timestamp,
        )

    def _heartbeat_due(self, attribute_name: str) -> bool:
        now = monotonic()
        last_value = getattr(self, attribute_name, 0.0)
        if now - last_value < self._heartbeat_interval_seconds:
            return False

        setattr(self, attribute_name, now)
        return True

    @staticmethod
    def _parse_windows_scan(output: str) -> Dict[str, Any]:
        interface = None
        access_points = []
        current_ssid = ""
        current_bssid = None
        current_authentication = ""
        current_encryption = ""

        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            if raw_line.startswith("Interface name"):
                _, _, value = raw_line.partition(":")
                interface = value.strip() or None
                continue

            ssid_match = re.match(r"SSID\s+\d+\s*:\s*(.*)", line)
            if ssid_match:
                current_ssid = ssid_match.group(1).strip()
                current_bssid = None
                current_authentication = ""
                current_encryption = ""
                continue

            authentication_match = re.match(r"Authentication\s*:\s*(.*)", line)
            if authentication_match:
                current_authentication = authentication_match.group(1).strip()
                continue

            encryption_match = re.match(r"Encryption\s*:\s*(.*)", line)
            if encryption_match:
                current_encryption = encryption_match.group(1).strip()
                continue

            bssid_match = re.match(r"BSSID\s+\d+\s*:\s*([0-9a-fA-F:]{17})", line)
            if bssid_match:
                current_bssid = bssid_match.group(1).lower()
                security_details = PacketSniffer._normalize_security_profile(
                    security_raw=current_authentication,
                    encryption=current_encryption,
                )
                access_points.append(
                    {
                        "ssid": current_ssid,
                        "bssid": current_bssid,
                        "signal_strength": None,
                        "security_type": security_details["security_type"],
                        "auth_method": security_details["auth_method"],
                        "encryption": security_details["encryption"],
                        "security_raw": security_details["security_raw"],
                    }
                )
                continue

            signal_match = re.match(r"Signal\s*:\s*(\d+)%", line)
            if signal_match and current_bssid and access_points:
                access_points[-1]["signal_strength"] = int(signal_match.group(1))

        return {"interface": interface, "access_points": access_points}

    @staticmethod
    def _parse_linux_scan(output: str) -> Dict[str, Any]:
        access_points = []
        lines = [line.rstrip() for line in output.splitlines() if line.strip()]
        if not lines:
            return {"interface": None, "access_points": access_points}

        for line in lines[1:]:
            bssid_match = re.search(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})", line)
            signal_match = re.search(r"\s(\d{1,3})\s+[▂▄▆_]+\s*(.*)$", line)

            if not bssid_match:
                continue

            bssid = bssid_match.group(1).lower()
            signal_strength = int(signal_match.group(1)) if signal_match else None
            security_raw = signal_match.group(2).strip() if signal_match else ""
            before_bssid = line[: bssid_match.start()].strip()
            before_bssid = re.sub(r"^\*", "", before_bssid).strip()
            ssid = before_bssid
            security_details = PacketSniffer._normalize_security_profile(security_raw=security_raw)

            access_points.append(
                {
                    "ssid": ssid,
                    "bssid": bssid,
                    "signal_strength": signal_strength,
                    "security_type": security_details["security_type"],
                    "auth_method": security_details["auth_method"],
                    "encryption": security_details["encryption"],
                    "security_raw": security_details["security_raw"],
                }
            )

        return {"interface": None, "access_points": access_points}

    @staticmethod
    def _extract_oui_prefix(bssid: str) -> str:
        return ":".join(bssid.lower().split(":")[:3])

    @staticmethod
    def _normalize_security_profile(
        security_type: Optional[str] = None,
        auth_method: Optional[str] = None,
        encryption: Optional[str] = None,
        security_raw: Optional[str] = None,
    ) -> Dict[str, str]:
        normalized_security_type = str(security_type or "").strip().lower()
        normalized_auth_method = str(auth_method or "").strip().lower()
        normalized_encryption = str(encryption or "").strip().lower()
        normalized_security_raw = str(security_raw or "").strip()

        if normalized_security_type and normalized_auth_method:
            return {
                "security_type": normalized_security_type,
                "auth_method": normalized_auth_method,
                "encryption": normalized_encryption,
                "security_raw": normalized_security_raw,
            }

        combined = " ".join(
            part
            for part in (
                normalized_security_type,
                normalized_auth_method,
                normalized_security_raw.lower(),
            )
            if part
        ).strip()

        security_families = []
        if "wpa1" in combined or re.search(r"\bwpa\b", combined):
            security_families.append("wpa")
        if "wpa2" in combined or "rsn" in combined:
            security_families.append("wpa2")
        if "wpa3" in combined or "sae" in combined or "owe" in combined:
            security_families.append("wpa3")

        deduped_security_families = []
        for family in security_families:
            if family not in deduped_security_families:
                deduped_security_families.append(family)

        if combined in {"", "--"} or "open" in combined or normalized_encryption == "none":
            normalized_security_type = "open"
        elif deduped_security_families:
            normalized_security_type = "/".join(deduped_security_families)
        else:
            normalized_security_type = "unknown"

        auth_markers = set()
        if "open" in combined or normalized_security_type == "open":
            auth_markers.add("open")
        if "personal" in combined or "psk" in combined:
            auth_markers.add("personal")
        if "enterprise" in combined or "802.1x" in combined or "eap" in combined:
            auth_markers.add("enterprise")
        if "sae" in combined:
            auth_markers.add("sae")
        if "owe" in combined:
            auth_markers.add("owe")

        if normalized_security_type != "open":
            auth_markers.discard("open")

        if len(auth_markers) == 1:
            normalized_auth_method = next(iter(auth_markers))
        elif len(auth_markers) > 1:
            normalized_auth_method = "mixed"
        elif normalized_security_type == "open":
            normalized_auth_method = "open"
        else:
            normalized_auth_method = "unknown"

        return {
            "security_type": normalized_security_type,
            "auth_method": normalized_auth_method,
            "encryption": normalized_encryption,
            "security_raw": normalized_security_raw,
        }

    @staticmethod
    def _format_security_profile(
        security_type: Optional[str],
        auth_method: Optional[str],
    ) -> str:
        normalized_security_type = str(security_type or "unknown").strip().lower() or "unknown"
        normalized_auth_method = str(auth_method or "unknown").strip().lower() or "unknown"

        if normalized_security_type == "open":
            return "open"
        if normalized_auth_method in {"unknown", ""}:
            return normalized_security_type
        return f"{normalized_security_type} ({normalized_auth_method})"

    @staticmethod
    def _is_suspicious_evil_twin_severity(severity: Optional[str]) -> bool:
        return str(severity or "").strip().lower() in {"medium", "high", "critical"}

    def _build_arp_status(self) -> Dict[str, Any]:
        events = [dict(event) for event in self._arp_spoof_events]
        is_suppressed = monotonic() < getattr(self, "_arp_suppress_until", 0.0)

        if self._traffic_monitor_error and not events:
            return {
                "detected": False,
                "severity": "info",
                "description": (
                    "ARP spoof monitoring is idle because live packet capture is unavailable "
                    f"on this machine: {self._traffic_monitor_error}"
                ),
                "events": events,
                "suppressed": is_suppressed,
            }

        if events:
            latest_event = events[-1]
            return {
                "detected": True,
                "severity": "high",
                "description": latest_event["description"],
                "events": events,
                "suppressed": is_suppressed,
            }

        return {
            "detected": False,
            "severity": "none",
            "description": "No conflicting ARP IP-to-MAC claims have been observed.",
            "events": events,
            "suppressed": is_suppressed,
        }

    def _build_ssl_strip_status(self) -> Dict[str, Any]:
        events = [dict(event) for event in self._ssl_strip_events]

        if self._traffic_monitor_error and not events:
            return {
                "detected": False,
                "severity": "info",
                "description": (
                    "SSL-strip monitoring is idle because live packet capture is unavailable "
                    f"on this machine: {self._traffic_monitor_error}"
                ),
                "events": events,
            }

        if events:
            latest_event = events[-1]
            return {
                "detected": True,
                "severity": "medium",
                "description": latest_event["description"],
                "events": events,
            }

        return {
            "detected": False,
            "severity": "none",
            "description": "No HTTP requests to known HTTPS domains have been observed.",
            "events": events,
        }

    def _is_known_https_domain(self, host: str) -> bool:
        if any(host == exc or host.endswith(f".{exc}") for exc in getattr(self, "_ssl_strip_exceptions", set())):
            return False
        return any(host == domain or host.endswith(f".{domain}") for domain in self._known_https_domains)

    @staticmethod
    def _utc_now() -> str:
        return datetime.now(timezone.utc).isoformat()
