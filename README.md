# NetShield

NetShield is a hackathon security project with two independent detection layers and one shared alert dashboard.

## Project areas

- `backend/`: Flask backend for packet capture, network detection modules, and alert APIs
- `extension/`: Browser extension scaffold for phishing and credential-harvesting detection
- `frontend/`: React dashboard scaffold for unified alert monitoring

## Detection layers

### Layer 1: Network

The network layer is intended to monitor packet traffic and eventually detect:

- rogue or evil-twin Wi-Fi access points
- ARP spoofing
- SSL-stripping patterns

### Layer 2: Browser

The browser layer is intended to flag suspicious pages using:

- a domain blocklist
- lightweight phishing heuristics

## Current status

This scaffold sets up the base folders and starter files only. No detection logic has been implemented yet.
