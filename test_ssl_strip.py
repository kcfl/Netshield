"""
Safe SSL-strip detector test harness for NetShield.

This script does NOT send any packets on the network. It builds a Scapy HTTP
request packet in memory and feeds it directly into the backend detector logic
so you can verify that a plain-HTTP request to a known HTTPS domain is flagged.

Important:
- Only perform real interception or downgrade tests on a network you own or explicitly control.
- Real packet-injection tests would require Administrator/root privileges.
- This script intentionally avoids transmitting any traffic.
"""

from pathlib import Path
import json
import sys

from scapy.all import IP, Raw, TCP


PROJECT_ROOT = Path(__file__).resolve().parent
BACKEND_DIR = PROJECT_ROOT / "backend"

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from capture.sniffer import PacketSniffer  # noqa: E402


def build_http_request(host: str, path: str = "/login"):
    payload = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "User-Agent: NetShield-Test\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("utf-8")

    return IP(src="192.168.1.10", dst="93.184.216.34") / TCP(
        sport=54321,
        dport=80,
    ) / Raw(load=payload)


def main() -> None:
    target_host = "google.com"
    target_path = "/login"

    sniffer = PacketSniffer()
    simulated_packet = build_http_request(target_host, target_path)

    sniffer._handle_http_packet(simulated_packet)

    ssl_status = sniffer._build_ssl_strip_status()

    print("SSL-strip simulation complete.")
    print(json.dumps(ssl_status, indent=2))

    if ssl_status["detected"]:
        print("\nDetector successfully flagged the simulated HTTP request to a known HTTPS domain.")
    else:
        print("\nDetector did not flag the simulated HTTP downgrade condition.")


if __name__ == "__main__":
    main()
