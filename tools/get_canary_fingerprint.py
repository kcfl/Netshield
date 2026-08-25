from __future__ import annotations

import argparse
import hashlib
import socket
import ssl
import sys
from urllib.parse import urlparse


def get_certificate_fingerprint(url: str, timeout: float = 5.0) -> str:
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    hostname = (parsed.hostname or "").strip()
    port = parsed.port or 443

    if scheme and scheme != "https":
        raise ValueError(f"URL must be https:// (got scheme={scheme!r}).")

    if not hostname:
        raise ValueError("URL hostname is missing.")

    raw_socket = socket.create_connection((hostname, port), timeout=timeout)
    try:
        # Use an unverified context so this utility works even if the local trust store is missing.
        # The point is to capture the presented certificate and pin it explicitly.
        context = ssl._create_unverified_context()
        tls_socket = context.wrap_socket(raw_socket, server_hostname=hostname)
        try:
            cert_der = tls_socket.getpeercert(binary_form=True)
        finally:
            tls_socket.close()
    finally:
        raw_socket.close()

    if not cert_der:
        raise RuntimeError("No certificate was presented by the server.")

    return hashlib.sha256(cert_der).hexdigest().lower()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Fetch a server's leaf TLS certificate and print its SHA-256 fingerprint for pinning.\n"
            "Example: python tools/get_canary_fingerprint.py https://1.1.1.1"
        )
    )
    parser.add_argument(
        "url",
        help="HTTPS URL of the canary endpoint (e.g. https://1.1.1.1 or https://example.com:443).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Connection timeout in seconds (default: 5.0).",
    )
    return parser


def main(argv: list[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    fingerprint = get_certificate_fingerprint(args.url, timeout=args.timeout)
    print(fingerprint)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

