"""
Safe ARP spoof detector test harness for NetShield.

This script does NOT send any packets on the network. It builds Scapy ARP reply
packets in memory and feeds them directly into the backend detector logic so you
can verify that an IP reassignment is flagged as suspicious.

Important:
- Only perform real ARP spoofing tests on a network you own or explicitly control.
- Real packet-injection tests would require Administrator/root privileges.
- This script intentionally avoids transmitting any traffic.
"""

from pathlib import Path
import json
import sys

from scapy.all import ARP


PROJECT_ROOT = Path(__file__).resolve().parent
BACKEND_DIR = PROJECT_ROOT / "backend"

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from capture.sniffer import PacketSniffer  # noqa: E402


def build_arp_reply(ip_address: str, mac_address: str) -> ARP:
    return ARP(op=2, psrc=ip_address, hwsrc=mac_address)


def main() -> None:
    gateway_ip = "192.168.1.1"
    real_gateway_mac = "3e:9d:4e:17:cd:4a"
    fake_gateway_mac = "de:ad:be:ef:00:01"

    sniffer = PacketSniffer()

    baseline_packet = build_arp_reply(gateway_ip, real_gateway_mac)
    spoofed_packet = build_arp_reply(gateway_ip, fake_gateway_mac)

    sniffer._handle_arp_packet(baseline_packet)
    sniffer._handle_arp_packet(spoofed_packet)

    arp_status = sniffer._build_arp_status()

    print("ARP spoof simulation complete.")
    print(json.dumps(arp_status, indent=2))

    if arp_status["detected"]:
        print("\nDetector successfully flagged the conflicting IP-to-MAC mapping.")
    else:
        print("\nDetector did not flag the simulated conflict.")


if __name__ == "__main__":
    main()
