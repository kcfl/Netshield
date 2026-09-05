# NetShield

Real-time man-in-the-middle detection for public Wi-Fi, running natively on the machine it protects.

On an open network an attacker can stand up a lookalike access point, poison your ARP table so traffic routes through their laptop, and strip HTTPS down to HTTP. Those signals live in the network stack — a browser extension cannot see a raw ARP frame or verify which certificate the OS actually negotiated. NetShield runs as a native process with OS-level access and does all detection locally. Nothing about your network leaves the machine.

---

## Quick start

**Prerequisites**

- Python 3.10+
- [Npcap](https://npcap.com/) on Windows (or `libpcap` on Linux) — required by `scapy` for packet capture
- Node.js + npm — *only* if you want the optional browser dashboard

**Run it**

```bash
python -m venv backend/venv
backend/venv/Scripts/pip install -r backend/requirements.txt   # Linux/macOS: backend/venv/bin/pip
python netshield_gui.py
```

Then click **Start Scan**. The desktop GUI launches and manages the Flask backend itself — you do not need a second terminal, and you should not start `backend/app.py` by hand during normal use.

Packet capture needs the capture driver installed and, on Windows, usually an elevated session. Without it NetShield still runs: Wi-Fi scanning and the SSL canary work, and the ARP monitor reports itself as idle rather than pretending to be healthy.

---

## What it detects

| Signal | How |
|---|---|
| **Evil twin** | Drives the OS Wi-Fi scan, groups APs by SSID, scores vendor-prefix and security-profile mismatches. Only the *connected* SSID is evaluated, and a legitimate multi-AP network scores `info` and never alerts. |
| **ARP spoofing** | Captures live ARP traffic and holds an IP-to-MAC binding table. An address that belonged to one machine and is suddenly claimed by another is cache poisoning. |
| **SSL stripping** | Flags plain-HTTP requests to domains that should be HTTPS, with carve-outs for traffic that is HTTP by design (OCSP, Windows Delivery Optimization). |
| **Certificate substitution** | The SSL Canary pins a known endpoint's certificate fingerprint on first sight (TOFU) and re-checks every 15 seconds. A changed certificate or a missing TLS handshake means something is in the path. |
| **Correlated MITM** | Any two *distinct* signals inside a 60-second window escalate to a single `critical` verdict. One anomaly is noise; ARP poisoning plus a swapped certificate is an attack in progress. |

### Network Trust Score

A single 0–100 figure with every deduction named on screen — the user is never shown a score without being told what moved it. Deductions are additive and the score floors at zero.

| Condition | Deduction |
|---|---|
| Active ARP spoof event | −30 |
| Certificate mismatch or TLS downgrade | −25 |
| Canary endpoint unreachable | −20 |
| Evil-twin group detected | −20 |
| Canary pin expired, re-pin required | −10 |
| Capture adapter differs from scanned network | −10 |
| ARP monitor settling after a network change | −10 |
| Connected SSID could not be identified | −10 |

Every alert description leads with `Reason:` and explains the observation in plain language. There is no bare "threat detected" anywhere in the codebase.

---

## False-positive discipline

A security tool that fires on ordinary network behaviour gets muted, and a muted tool detects nothing. Several detectors exist mainly to *stop* alerts firing:

- A legitimate multi-AP network (same vendor, same security profile) scores `info` and stays out of the alert feed entirely.
- After a network change the ARP monitor pauses briefly so roaming does not look like an attack — but starting a scan is not a network change, so a fresh session monitors immediately.
- Past a maximum age, a certificate mismatch is reported as `pin_stale` with a re-pin prompt rather than a confirmed MITM. At that age routine rotation is genuinely indistinguishable from interception, so the tool says so instead of guessing.
- Dedup signatures and IP-to-MAC bindings reset when a scan starts, so a stale binding can never leave an attacker's MAC as the trusted baseline.
- Alert identity is anchored to when a condition became detectable, not to the latest scan, so an unchanged threat stays one alert instead of re-firing on every refresh.
- When packet capture binds to a different adapter than the one being scanned — easy with a Wi-Fi connection and a USB tether both live — that gap is detected and surfaced rather than silently monitoring the wrong network.

---

## Architecture

```
netshield_gui.py          Tkinter desktop app (primary UI) — spawns and manages the backend
        │  HTTP REST
        ▼
backend/app.py            Flask API on 127.0.0.1:5000
  ├─ capture/sniffer.py   PacketSniffer — all detection, 4 background threads
  └─ services/            AlertService — stateless snapshot → alert feed transform
        ▲
        │  HTTP REST
frontend/                 Optional React dashboard against the same API
```

`PacketSniffer` runs a Wi-Fi poller, a scapy `AsyncSniffer`, its bootstrap wrapper, and the SSL canary loop. All shared state is guarded by a single re-entrant lock, and each scan session owns its own stop event so a worker can never outlive its session.

### API

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/health` | Backend health check |
| `GET` | `/api/alerts` | Full alert feed |
| `GET` | `/api/scan/status` | Live status, badges, trust score |
| `GET` | `/api/wifi/access-points` | Full snapshot with APs and evil-twin groups |
| `POST` | `/api/scan/start` · `/api/scan/stop` | Detection lifecycle |
| `POST` | `/api/canary/repin` | Clear the pin and re-establish trust |
| `POST` | `/api/debug/reset-test-state` | Clear in-memory event history (debug builds only) |

Timestamps are UTC ISO strings throughout the backend; the display layer converts to IST.

---

## Testing

```bash
backend/venv/Scripts/python -m unittest discover -s backend/tests -t backend
```

36 tests covering evil-twin severity scoring and alert filtering, session-boundary state resets, alert identity stability, request-target sanitisation, worker lifecycle, and the false-positive guards above.

Two additional harnesses at the repository root exercise the detectors end to end:

```bash
python test_arp_spoof.py
python test_ssl_strip.py
```

Both build packets **in memory** and feed them directly into the detection logic. Neither transmits anything on the network, so they are safe to run anywhere and reproducible without a second machine. For a full adversarial test — a real `arpspoof` or `sslstrip` run — you still want an isolated network with a separate attacker host, and only on a network you own or control.

---

## Known limitations

- **Cold-start blind spot.** ARP detection is conflict-based: it needs to observe a mapping *change*. A spoof already running when you press Start becomes the baseline instead of an alert.
- **Rotation vs. attack.** While a canary pin is stale, a genuine interception and a routine certificate rotation look identical. Validating the presented chain against a certificate authority is the planned fix.
- **Adapter selection is manual.** NetShield now detects when capture and scanning cover different networks, but choosing the adapter is still up to the operator.
- **Windows first.** Platform-specific paths degrade gracefully on Linux, but the Wi-Fi scanning path targets the Windows WLAN API and that is where testing has been done.
- **The browser extension is a scaffold.** `extension/` is a Manifest V3 skeleton and is not part of the detection pipeline.

---

## Repository layout

| Path | Contents |
|---|---|
| `netshield_gui.py` | Tkinter desktop application — the primary interface |
| `backend/` | Flask API, detection engine, alert service, tests |
| `frontend/` | Optional React + Vite dashboard |
| `extension/` | Manifest V3 scaffold (not implemented) |
| `tools/` | Standalone TLS fingerprint inspector |
| `test_arp_spoof.py`, `test_ssl_strip.py` | Safe in-memory detector harnesses |

Runtime state — the canary pin, the runtime log, the virtualenv — is generated at run time and excluded from version control.

---

## License

MIT — see [LICENSE](LICENSE).
