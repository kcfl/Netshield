# NetShield

NetShield is a hackathon security project with two independent detection layers and one shared alert dashboard.

## Detection Layers

### Layer 1: Network

The network layer monitors packet traffic and detects:
- Rogue or evil-twin Wi-Fi access points
- ARP spoofing
- SSL-stripping patterns

### Layer 2: Browser

The browser layer flags suspicious pages using:
- A domain blocklist
- Lightweight phishing heuristics

## Testing

To properly test the network detection layers, you'll need two separate machines or VMs:
1. **The Attacker:** Running Kali Linux with tools like `dsniff` (for `arpspoof`) or `sslstrip`.
2. **The Victim:** Running this NetShield application.

**Note:** Self-testing (running the attack and the defense on the same machine) is not currently supported and will not produce accurate alerts.

## Known Limitations

- **No Self-Test Capability:** The `correlated_mitm` logic and the GUI "Run Self-Test" button are not yet implemented in this repository.
- **Runtime Environment:** Testing against simulated attacks requires isolated network environments (VMs or physical separate machines).
- **TOFU Pinning:** The TLS canary pinning implementation relies on session-specific runtime state. (Note: Runtime pinning data is excluded from version control).

## Current Status

The core backend packet capture modules and the frontend alert dashboard structure are present. Some advanced correlation features and built-in self-testing capabilities remain actively under development or missing from the current branch.

## Project Areas

- `backend/`: Flask backend for packet capture, network detection modules, and alert APIs
- `extension/`: Browser extension scaffold for phishing and credential-harvesting detection
- `frontend/`: React dashboard scaffold for unified alert monitoring
- `netshield_gui.py`: Desktop GUI application for running NetShield

## Prerequisites

Before setting up the project, make sure you have the following installed on your system:
- **Python 3.8+** (for the backend and GUI)
- **Node.js and npm** (for the frontend dashboard)
- **Npcap** or **WinPcap** (on Windows) or **libpcap** (on Linux/macOS) - required by `scapy` for packet sniffing capabilities.

## Installation & Setup

### 1. Backend (Flask & Sniffer)

The backend handles packet capture and serves the API for the dashboard.

```bash
cd backend

# Create a virtual environment (optional but recommended)
python -m venv venv

# Activate the virtual environment
# On Windows: venv\Scripts\activate
# On Linux/macOS: source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start the Flask backend server
python app.py
```

### 2. Frontend (React Dashboard)

The frontend is built with React and Vite. It connects to the backend API to display network alerts.

```bash
cd frontend

# Install Node dependencies
npm install

# Start the development server
npm run dev
```

### 3. Browser Extension

To load the phishing detection extension in Chromium-based browsers (Chrome, Edge, Brave):
1. Navigate to your browser's extensions page (e.g., `chrome://extensions/` or `edge://extensions/`).
2. Turn on **Developer mode** (usually a toggle in the top right).
3. Click **Load unpacked** and select the `extension` directory from this repository.

### 4. Desktop GUI

You can also run the full NetShield Desktop GUI directly:

```bash
# Ensure backend requirements are installed
pip install -r backend/requirements.txt

# Run the GUI application
python netshield_gui.py
```
