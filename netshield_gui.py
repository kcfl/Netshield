from __future__ import annotations

import json
import os
import queue
import subprocess
import threading
import time
import tkinter as tk
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from tkinter import ttk
from typing import Callable, Deque, Dict, List, Optional
from urllib import error, request


API_BASE_URL = "http://127.0.0.1:5000"
POLL_INTERVAL_SECONDS = 3.5
REQUEST_TIMEOUT_SECONDS = 5
BACKEND_START_TIMEOUT_SECONDS = 15
BACKEND_DIR = Path(__file__).resolve().parent / "backend"
BACKEND_APP_PATH = BACKEND_DIR / "app.py"
BACKEND_VENV_PYTHON = BACKEND_DIR / "venv" / "Scripts" / "python.exe"
RUNTIME_LOG_PATH = Path(__file__).resolve().parent / "netshield_runtime.log"
HIGH_RISK_TYPES = {"arp_spoof", "evil_twin"}


class Palette:
    APP_BG = "#0b0f17"
    PANEL_BG = "#161f33"
    SIDEBAR_BG = "#0f172a"
    LOG_BG = "#020817"
    LOG_TEXT_BG = "#020817"
    BORDER = "#1e293b"
    BORDER_SOFT = "#334155"
    BORDER_GLOW = "#38bdf8"
    TEXT = "#f8fafc"
    TEXT_SOFT = "#cbd5e1"
    TEXT_MUTED = "#94a3b8"
    
    # Gemini Neon Accents
    CYAN = "#38bdf8"
    PURPLE = "#818cf8"
    EMERALD = "#34d399"
    MAGENTA = "#f43f5e"
    
    # Semantic mapping for existing references
    TEAL = "#38bdf8"    # Alias to CYAN
    BLUE = "#3b82f6"
    GREEN = "#34d399"   # Alias to EMERALD
    RED = "#f43f5e"     # Alias to MAGENTA
    AMBER = "#fbbf24"
    SLATE = "#64748b"


def format_timestamp(value: str) -> str:
    if not value:
        return "Not available"

    try:
        from datetime import timezone, timedelta
        ist = timezone(timedelta(hours=5, minutes=30))
        normalized = value.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(normalized).astimezone(ist)
        return parsed.strftime("%b %d, %Y %I:%M:%S %p IST")
    except ValueError:
        return value


def format_alert_type(alert_type: str) -> str:
    parts = str(alert_type or "security_event").split("_")
    return " ".join(part.capitalize() for part in parts if part)


def normalize_severity(severity: str) -> str:
    normalized = str(severity or "low").strip().lower()
    if normalized in {"critical", "high", "medium", "info", "low"}:
        return normalized
    return "low"


def highest_severity(alerts: List["AlertRecord"]) -> str:
    severities = {alert.severity for alert in alerts}
    if "critical" in severities:
        return "Critical"
    if "high" in severities:
        return "High"
    if "medium" in severities:
        return "Medium"
    if "info" in severities:
        return "Info"
    return "Low"


@dataclass
class ScanState:
    active: bool = False
    interface: str = ""
    traffic_interface: str = ""
    started_at: str = ""
    error: str = ""
    traffic_monitor_error: str = ""
    ssl_canary_status: Dict[str, object] = field(default_factory=dict)
    connected_ssid_error: str = ""
    arp_status: Dict[str, object] = field(default_factory=dict)
    trust_score: int = 100
    trust_factors: List[str] = field(default_factory=lambda: ["Perfect condition"])


@dataclass
class AlertRecord:
    id: str
    alert_type: str
    severity: str
    description: str
    timestamp: str
    active: bool = True


@dataclass
class DashboardSnapshot:
    scan_state: ScanState
    access_points_monitored: int
    alerts: List[AlertRecord]


class BackendAPIClient:
    """Centralized backend API access."""

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")

    def request_json(self, method: str, path: str, payload: Optional[dict] = None, timeout: float = REQUEST_TIMEOUT_SECONDS) -> dict:
        data = None
        headers = {"Accept": "application/json"}

        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"

        req = request.Request(
            url=f"{self.base_url}{path}",
            data=data,
            headers=headers,
            method=method,
        )

        try:
            with request.urlopen(req, timeout=timeout) as response:
                body = response.read().decode("utf-8")
                return json.loads(body) if body else {}
        except error.HTTPError as exc:
            try:
                body = exc.read().decode("utf-8")
                details = json.loads(body) if body else {}
                message = details.get("error") or f"{exc.code} {exc.reason}"
            except Exception:
                message = f"{exc.code} {exc.reason}"
            raise RuntimeError(message) from exc
        except error.URLError as exc:
            raise RuntimeError(f"Unable to reach backend: {exc.reason}") from exc

    def is_backend_reachable(self) -> bool:
        try:
            payload = self.request_json("GET", "/api/health", timeout=1.5)
            return payload.get("status") == "ok"
        except Exception:
            return False

    def get_scan_status(self) -> dict:
        return self.request_json("GET", "/api/scan/status")

    def start_scan(self) -> dict:
        return self.request_json("POST", "/api/scan/start")

    def stop_scan(self) -> dict:
        return self.request_json("POST", "/api/scan/stop")

    def repin_canary(self) -> dict:
        return self.request_json("POST", "/api/canary/repin")

    def reset_debug_test_state(self) -> dict:
        return self.request_json("POST", "/api/debug/reset-test-state")

    def get_alerts(self) -> dict:
        return self.request_json("GET", "/api/alerts")

    def get_access_points(self) -> dict:
        return self.request_json("GET", "/api/wifi/access-points")

    def get_dashboard_snapshot(self) -> DashboardSnapshot:
        scan_status = self.get_scan_status()
        wifi_snapshot = self.get_access_points()
        alerts_response = self.get_alerts()
        return DashboardSnapshot(
            scan_state=self.parse_scan_state(scan_status),
            access_points_monitored=int(wifi_snapshot.get("total_access_points", 0) or 0),
            alerts=self.parse_alerts(alerts_response),
        )

    @staticmethod
    def parse_scan_state(payload: dict) -> ScanState:
        return ScanState(
            active=bool(payload.get("active")),
            interface=payload.get("interface") or "",
            traffic_interface=payload.get("traffic_interface") or "",
            started_at=payload.get("started_at") or "",
            error=payload.get("error") or "",
            traffic_monitor_error=payload.get("traffic_monitor_error") or "",
            ssl_canary_status=payload.get("ssl_canary_status") or {},
            connected_ssid_error=payload.get("connected_ssid_error") or "",
            arp_status=payload.get("arp_spoof") or {},
            trust_score=payload.get("trust_score", 100),
            trust_factors=payload.get("trust_factors", ["Perfect condition"]),
        )

    @staticmethod
    def parse_alerts(payload: dict) -> List[AlertRecord]:
        raw_alerts = payload.get("alerts", []) if isinstance(payload, dict) else []
        alerts: List[AlertRecord] = []

        for index, alert in enumerate(raw_alerts):
            alerts.append(
                AlertRecord(
                    id=alert.get("id") or f"alert-{index}",
                    alert_type=alert.get("type") or "security_event",
                    severity=normalize_severity(alert.get("severity")),
                    description=alert.get("description") or "NetShield detected suspicious behavior.",
                    timestamp=alert.get("timestamp") or "",
                    active=bool(alert.get("active", True)),
                )
            )

        return alerts


class BackendProcessManager:
    """Starts and stops the local Flask backend only when the GUI launched it."""

    def __init__(self, api_client: BackendAPIClient):
        self.api_client = api_client
        self._process: Optional[subprocess.Popen] = None
        self._lock = threading.Lock()

    def ensure_running(self) -> str:
        if self.api_client.is_backend_reachable():
            return "already_running"

        with self._lock:
            if self._process is not None and self._process.poll() is None:
                return self._wait_until_reachable()

            if not BACKEND_VENV_PYTHON.exists():
                raise RuntimeError(
                    f"Backend virtual environment interpreter was not found at `{BACKEND_VENV_PYTHON}`."
                )

            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            creationflags |= getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            env = os.environ.copy()
            env["NETSHIELD_GUI_MODE"] = "1"
            env["FLASK_DEBUG"] = "false"
            env["ENABLE_DEBUG_API"] = "true"
            RUNTIME_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
            self._process = subprocess.Popen(
                [str(BACKEND_VENV_PYTHON), str(BACKEND_APP_PATH)],
                cwd=str(BACKEND_DIR),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=env,
                creationflags=creationflags,
            )

        status = self._wait_until_reachable()
        return "launched" if status == "managed_running" else status

    def _wait_until_reachable(self) -> str:
        deadline = time.time() + BACKEND_START_TIMEOUT_SECONDS

        while time.time() < deadline:
            if self.api_client.is_backend_reachable():
                return "managed_running" if self.is_managed_backend_running() else "already_running"

            process = self._process
            if process is not None and process.poll() is not None:
                exit_error = self._build_process_exit_error(process)
                self._process = None
                raise RuntimeError(exit_error)

            time.sleep(0.5)

        raise RuntimeError("Timed out waiting for the Flask backend to become reachable.")

    def is_managed_backend_running(self) -> bool:
        with self._lock:
            return self._process is not None and self._process.poll() is None

    def stop_managed_backend(self) -> bool:
        with self._lock:
            process = self._process
            self._process = None

        if process is None:
            return False

        if process.poll() is not None:
            return True

        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)

        return True

    @staticmethod
    def _build_process_exit_error(process: subprocess.Popen) -> str:
        exit_code = process.returncode

        details = [f"Backend exited before becoming reachable (exit code {exit_code})."]
        log_tail = BackendProcessManager._read_runtime_log_tail()
        if log_tail:
            details.append("Recent backend runtime log:")
            details.append(log_tail)
        else:
            details.append(f"No runtime log lines were available in `{RUNTIME_LOG_PATH}`.")

        return "\n".join(details)

    @staticmethod
    def _read_runtime_log_tail(limit_lines: int = 40) -> str:
        if not RUNTIME_LOG_PATH.exists():
            return ""

        with RUNTIME_LOG_PATH.open("r", encoding="utf-8", errors="ignore") as log_file:
            lines = log_file.readlines()

        return "".join(lines[-limit_lines:]).strip()

    @staticmethod
    def disconnect_wifi() -> str:
        result = subprocess.run(
            ["netsh", "wlan", "disconnect"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        output = (result.stdout or result.stderr or "").strip()
        if result.returncode != 0:
            raise RuntimeError(output or f"`netsh wlan disconnect` failed with exit code {result.returncode}.")
        return output or "Issued `netsh wlan disconnect` successfully."


class PollingController:
    def __init__(self, api_client: BackendAPIClient, ui_queue: queue.Queue):
        self.api_client = api_client
        self.ui_queue = ui_queue
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            daemon=True,
            name="netshield-gui-poller",
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                snapshot = self.api_client.get_dashboard_snapshot()
                self.ui_queue.put(("snapshot_success", {"snapshot": snapshot, "source": "poll"}))
            except Exception as exc:
                self.ui_queue.put(("snapshot_error", {"message": str(exc), "source": "poll"}))

            self._stop_event.wait(POLL_INTERVAL_SECONDS)


class NetShieldGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("NetShield Desktop")
        self.root.geometry("1440x900")
        self.root.minsize(1180, 760)
        self.root.configure(bg=Palette.APP_BG)

        self.api_client = BackendAPIClient(API_BASE_URL)
        self.backend_manager = BackendProcessManager(self.api_client)
        self.ui_queue: queue.Queue = queue.Queue()
        self.poller = PollingController(self.api_client, self.ui_queue)

        self.scan_state = ScanState()
        self.alerts: List[AlertRecord] = []
        self.previous_alert_ids: set[str] = set()
        self.high_risk_handled_ids: set[str] = set()
        self.disconnect_prompt_queue: Deque[AlertRecord] = deque()
        self.active_disconnect_prompt: Optional[tk.Toplevel] = None
        self.access_points_monitored = 0
        self.backend_reachable = False
        self.runtime_log_offset = RUNTIME_LOG_PATH.stat().st_size if RUNTIME_LOG_PATH.exists() else 0

        self.status_message = tk.StringVar(value="Backend status: connecting")
        self.header_status_text = tk.StringVar(value="Idle")
        self.backend_origin_text = tk.StringVar(value="Offline")
        self.ssl_canary_text = tk.StringVar(value="SSL Canary: Unavailable")
        self.ssid_detector_text = tk.StringVar(value="SSID Detector: Active")
        self.arp_detector_text = tk.StringVar(value="ARP Monitor: Unavailable")
        self.auto_disconnect_enabled = tk.BooleanVar(value=False)

        self._configure_styles()
        self._build_layout()
        self._start_runtime_log_tail()
        self._start_queue_loop()
        self._initial_sync()
        self.root.protocol("WM_DELETE_WINDOW", self._handle_close)

    def _configure_styles(self) -> None:
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "Treeview",
            background=Palette.LOG_BG,
            foreground=Palette.TEXT,
            fieldbackground=Palette.LOG_BG,
            bordercolor=Palette.BORDER,
            rowheight=38,
            font=("Segoe UI", 10),
        )
        style.configure(
            "Treeview.Heading",
            background=Palette.PANEL_BG,
            foreground=Palette.CYAN,
            font=("Segoe UI", 10, "bold"),
        )
        style.map(
            "Treeview",
            background=[("selected", "#1d4ed8")],
            foreground=[("selected", Palette.TEXT)],
        )

    def _build_layout(self) -> None:
        self.root.grid_rowconfigure(1, weight=1)
        self.root.grid_columnconfigure(1, weight=1)

        self._build_header()
        self._build_sidebar()
        self._build_main_area()
        self._build_log_console()

        self.toast_host = tk.Frame(self.root, bg=Palette.APP_BG)
        self.toast_host.place(relx=0.985, rely=0.12, anchor="ne")

    def _build_header(self) -> None:
        header = tk.Frame(self.root, bg=Palette.APP_BG)
        header.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(20, 12))
        header.grid_columnconfigure(0, weight=1)

        tk.Label(
            header,
            text="NetShield",
            bg=Palette.APP_BG,
            fg=Palette.TEXT,
            font=("Segoe UI", 30, "bold"),
        ).grid(row=0, column=0, sticky="w")

        self.status_chip = tk.Frame(
            header,
            bg=Palette.PANEL_BG,
            highlightthickness=1,
            highlightbackground=Palette.BORDER,
        )
        self.status_chip.grid(row=0, column=1, sticky="e")

        self.status_dot = tk.Canvas(
            self.status_chip,
            width=18,
            height=18,
            bg=Palette.PANEL_BG,
            highlightthickness=0,
        )
        self.status_dot.grid(row=0, column=0, padx=(12, 8), pady=12)
        self.status_dot_oval = self.status_dot.create_oval(4, 4, 14, 14, fill=Palette.TEXT_MUTED, outline="")

        tk.Label(
            self.status_chip,
            textvariable=self.header_status_text,
            bg=Palette.PANEL_BG,
            fg="#e5eef9",
            font=("Segoe UI", 12, "bold"),
            ).grid(row=0, column=1, padx=(0, 14))

        self.backend_origin_chip = tk.Label(
            header,
            textvariable=self.backend_origin_text,
            bg=Palette.PANEL_BG,
            fg=Palette.TEXT_MUTED,
            font=("Segoe UI", 10, "bold"),
            highlightthickness=1,
            highlightbackground=Palette.BORDER,
        )
        self.backend_origin_chip.grid(row=0, column=2, sticky="e", padx=(10, 0))

    def _build_sidebar(self) -> None:
        sidebar = tk.Frame(
            self.root,
            bg=Palette.SIDEBAR_BG,
            highlightthickness=1,
            highlightbackground=Palette.BORDER,
        )
        sidebar.grid(row=1, column=0, rowspan=2, sticky="nsew", padx=(24, 16), pady=(0, 24))
        sidebar.configure(width=280)
        sidebar.grid_propagate(False)

        tk.Label(
            sidebar,
            text="SESSION STATS",
            bg=Palette.SIDEBAR_BG,
            fg=Palette.TEAL,
            font=("Segoe UI", 11, "bold"),
        ).grid(row=0, column=0, sticky="w", pady=(20, 18))

        self.stats_labels: Dict[str, tk.Label] = {}
        stats = [
            ("Access Points Monitored", "0"),
            ("Active Alerts", "0"),
            ("Highest Severity", "Low"),
            ("Scan Started At", "Not running"),
        ]

        for index, (label, value) in enumerate(stats, start=1):
            block = tk.Frame(
                sidebar,
                bg=Palette.SIDEBAR_BG,
                highlightthickness=1,
                highlightbackground=Palette.BORDER_SOFT,
            )
            block.grid(row=index, column=0, sticky="ew", pady=8)
            tk.Label(
                block,
                text=label.upper(),
                bg=Palette.SIDEBAR_BG,
                fg=Palette.TEXT_MUTED,
                font=("Segoe UI", 9, "bold"),
            ).pack(anchor="w", pady=(12, 8))
            value_label = tk.Label(
                block,
                text=value,
                bg=Palette.SIDEBAR_BG,
                fg=Palette.TEXT,
                font=("Segoe UI", 17, "bold"),
                justify="left",
                wraplength=220,
            )
            value_label.pack(anchor="w", pady=(0, 14))
            self.stats_labels[label] = value_label

        canary_block = tk.Frame(
            sidebar,
            bg=Palette.SIDEBAR_BG,
            highlightthickness=1,
            highlightbackground=Palette.BORDER_SOFT,
        )
        canary_block.grid(row=len(stats) + 1, column=0, sticky="ew", pady=8)
        tk.Label(
            canary_block,
            text="SSL CANARY",
            bg=Palette.SIDEBAR_BG,
            fg=Palette.TEXT_MUTED,
            font=("Segoe UI", 9, "bold"),
        ).pack(anchor="w", pady=(12, 8))
        self.ssl_canary_badge = tk.Label(
            canary_block,
            textvariable=self.ssl_canary_text,
            bg=Palette.LOG_BG,
            fg=Palette.TEXT_MUTED,
            font=("Segoe UI", 11, "bold"),
            anchor="w",
            justify="left",
            wraplength=220,
            highlightthickness=1,
            highlightbackground=Palette.BORDER,
        )
        self.ssl_canary_badge.pack(anchor="w", fill="x", pady=(0, 14))

        tk.Label(
            canary_block,
            text="WIFI SCANNER",
            bg=Palette.SIDEBAR_BG,
            fg=Palette.TEXT_MUTED,
            font=("Segoe UI", 9, "bold"),
        ).pack(anchor="w", pady=(0, 8))
        self.ssid_detector_badge = tk.Label(
            canary_block,
            textvariable=self.ssid_detector_text,
            bg=Palette.LOG_BG,
            fg=Palette.TEXT_MUTED,
            font=("Segoe UI", 11, "bold"),
            anchor="w",
            justify="left",
            wraplength=220,
            highlightthickness=1,
            highlightbackground=Palette.BORDER,
        )
        self.ssid_detector_badge.pack(anchor="w", fill="x", pady=(0, 14))

        tk.Label(
            canary_block,
            text="ARP MONITOR",
            bg=Palette.SIDEBAR_BG,
            fg=Palette.TEXT_MUTED,
            font=("Segoe UI", 9, "bold"),
        ).pack(anchor="w", pady=(0, 8))
        self.arp_detector_badge = tk.Label(
            canary_block,
            textvariable=self.arp_detector_text,
            bg=Palette.LOG_BG,
            fg=Palette.TEXT_MUTED,
            font=("Segoe UI", 11, "bold"),
            anchor="w",
            justify="left",
            wraplength=220,
            highlightthickness=1,
            highlightbackground=Palette.BORDER,
        )
        self.arp_detector_badge.pack(anchor="w", fill="x", pady=(0, 14))

    def _build_main_area(self) -> None:
        main = tk.Frame(self.root, bg=Palette.APP_BG)
        main.grid(row=1, column=1, sticky="nsew", padx=(0, 24), pady=(0, 12))
        main.grid_rowconfigure(2, weight=1)
        main.grid_columnconfigure(0, weight=1)

        self._build_control_panel(main)
        self._build_trust_score_panel(main)
        self._build_alert_feed(main)

    def _build_trust_score_panel(self, parent: tk.Frame) -> None:
        self.trust_panel = tk.Frame(
            parent,
            bg=Palette.PANEL_BG,
            highlightthickness=2,
            highlightbackground=Palette.GREEN,
        )
        self.trust_panel.grid(row=1, column=0, sticky="ew", pady=(0, 14))

        header = tk.Frame(self.trust_panel, bg=Palette.PANEL_BG)
        header.pack(fill="x", padx=16, pady=(12, 0))

        tk.Label(
            header,
            text="Network Trust Score",
            bg=Palette.PANEL_BG,
            fg=Palette.TEXT,
            font=("Segoe UI", 12, "bold"),
        ).pack(side="left")

        self.trust_score_value = tk.Label(
            header,
            text="100",
            bg=Palette.PANEL_BG,
            fg=Palette.GREEN,
            font=("Segoe UI", 24, "bold"),
        )
        self.trust_score_value.pack(side="right")

        self.trust_factors_label = tk.Label(
            self.trust_panel,
            text="Factors: Perfect condition",
            bg=Palette.PANEL_BG,
            fg=Palette.TEXT_SOFT,
            font=("Segoe UI", 10),
            justify="left",
            wraplength=600,
        )
        self.trust_factors_label.pack(fill="x", padx=16, pady=(4, 12))

    def _build_control_panel(self, parent: tk.Frame) -> None:
        controls = tk.Frame(
            parent,
            bg=Palette.PANEL_BG,
            highlightthickness=1,
            highlightbackground=Palette.BORDER,
        )
        controls.grid(row=0, column=0, sticky="ew", pady=(0, 14))

        header = tk.Frame(controls, bg=Palette.PANEL_BG)
        header.grid(row=0, column=0, sticky="ew", pady=(16, 12))

        tk.Label(
            header,
            text="Scan Control",
            bg=Palette.PANEL_BG,
            fg=Palette.TEAL,
            font=("Segoe UI", 10, "bold"),
        ).pack(anchor="w")
        tk.Label(
            header,
            text="Start launches the local Flask backend if needed, then begins live scan polling.",
            bg=Palette.PANEL_BG,
            fg=Palette.TEXT_SOFT,
            font=("Segoe UI", 11),
        ).pack(anchor="w", pady=(6, 0))

        button_row = tk.Frame(controls, bg=Palette.PANEL_BG)
        button_row.grid(row=1, column=0, sticky="w", pady=(0, 12))

        self.start_button = tk.Button(
            button_row,
            text="Start Scan",
            command=self._on_start_scan,
            bg=Palette.CYAN,
            fg=Palette.LOG_TEXT_BG,
            activebackground=Palette.BLUE,
            font=("Segoe UI", 11, "bold"),
            activeforeground=Palette.TEXT,
            relief="flat",
            cursor="hand2",
            )
        self.start_button.pack(side="left", padx=(0, 12))

        self.stop_button = tk.Button(
            button_row,
            text="Stop Scan",
            command=self._on_stop_scan,
            bg=Palette.MAGENTA,
            fg=Palette.TEXT,
            activebackground="#be123c",
            font=("Segoe UI", 11, "bold"),
            activeforeground=Palette.TEXT,
            relief="flat",
            cursor="hand2",
            )
        self.stop_button.pack(side="left")

        self.repin_button = tk.Button(
            button_row,
            text="Repin SSL Canary",
            command=self._on_repin_canary,
            bg=Palette.PANEL_BG,
            fg=Palette.TEXT_SOFT,
            activebackground=Palette.BORDER_SOFT,
            font=("Segoe UI", 11, "bold"),
            activeforeground=Palette.TEXT,
            relief="flat",
            cursor="hand2",
            state="disabled",
        )
        self.repin_button.pack(side="left", padx=(12, 0))

        self.reset_test_state_button = tk.Button(
            button_row,
            text="Reset Test State (DEV ONLY)",
            activeforeground=Palette.TEXT,
            relief="flat",
            cursor="hand2",
            command=self._on_reset_test_state,
            bg="#7c2d12",
            fg=Palette.TEXT,
            activebackground=Palette.AMBER,
            font=("Segoe UI", 11, "bold"),
            state="disabled",
        )
        self.reset_test_state_button.pack(side="left", padx=(12, 0))

        toggle_row = tk.Frame(controls, bg=Palette.PANEL_BG)
        toggle_row.grid(row=2, column=0, sticky="w", pady=(0, 16))

        self.auto_disconnect_toggle = tk.Checkbutton(
            toggle_row,
            text="Auto-disconnect on high-risk alerts",
            variable=self.auto_disconnect_enabled,
            bg=Palette.CYAN,
            fg=Palette.TEXT,
            activebackground=Palette.BLUE,
            font=("Segoe UI", 10, "bold"),
            selectcolor=Palette.LOG_BG,
            )
        self.auto_disconnect_toggle.pack(anchor="w")

        tk.Label(
            toggle_row,
            text="Off by default. Only `arp_spoof` and `evil_twin` high or critical alerts can trigger disconnect handling.",
            bg=Palette.PANEL_BG,
            fg=Palette.TEXT_MUTED,
            font=("Segoe UI", 9),
        ).pack(anchor="w", pady=(4, 0))

    def _build_alert_feed(self, parent: tk.Frame) -> None:
        feed_panel = tk.Frame(
            parent,
            bg=Palette.PANEL_BG,
            highlightthickness=1,
            highlightbackground=Palette.BORDER,
        )
        feed_panel.grid(row=2, column=0, sticky="nsew")
        feed_panel.grid_rowconfigure(1, weight=1)
        feed_panel.grid_columnconfigure(0, weight=1)

        feed_header = tk.Frame(feed_panel, bg=Palette.PANEL_BG)
        feed_header.grid(row=0, column=0, sticky="ew", pady=(18, 12))
        feed_header.grid_columnconfigure(0, weight=1)

        tk.Label(
            feed_header,
            text="Live Alert Feed",
            bg=Palette.PANEL_BG,
            fg=Palette.TEXT,
            font=("Segoe UI", 18, "bold"),
        ).grid(row=0, column=0, sticky="w")
        tk.Label(
            feed_header,
            textvariable=self.status_message,
            bg=Palette.PANEL_BG,
            fg=Palette.TEXT_MUTED,
            font=("Segoe UI", 10, "bold"),
        ).grid(row=0, column=1, sticky="e")

        tree_frame = tk.Frame(feed_panel, bg=Palette.PANEL_BG)
        tree_frame.grid(row=1, column=0, sticky="nsew", pady=(0, 18))
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        columns = ("type", "severity", "description", "timestamp")
        self.alert_tree = ttk.Treeview(tree_frame, columns=columns, show="headings")
        self.alert_tree.heading("type", text="Type")
        self.alert_tree.heading("severity", text="Severity")
        self.alert_tree.heading("description", text="Description")
        self.alert_tree.heading("timestamp", text="Timestamp")
        self.alert_tree.column("type", width=170, anchor="w")
        self.alert_tree.column("severity", width=110, anchor="center")
        self.alert_tree.column("description", width=650, anchor="w")
        self.alert_tree.column("timestamp", width=220, anchor="w")
        self.alert_tree.grid(row=0, column=0, sticky="nsew")

        tree_scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.alert_tree.yview)
        tree_scroll.grid(row=0, column=1, sticky="ns")
        self.alert_tree.configure(yscrollcommand=tree_scroll.set)

        self.alert_tree.tag_configure("critical", background="#3a0f16", foreground="#fda4af")
        self.alert_tree.tag_configure("high", background="#2a1217", foreground="#fecaca")
        self.alert_tree.tag_configure("medium", background="#2b2112", foreground="#fde68a")
        self.alert_tree.tag_configure("info", background="#0f2333", foreground="#93c5fd")
        self.alert_tree.tag_configure("low", background="#10221b", foreground="#bbf7d0")
        self.alert_tree.tag_configure("empty", background=Palette.LOG_BG, foreground=Palette.TEXT_MUTED)

    def _build_log_console(self) -> None:
        log_panel = tk.Frame(
            self.root,
            bg=Palette.LOG_BG,
            highlightthickness=1,
            highlightbackground=Palette.BORDER,
        )
        log_panel.grid(row=2, column=1, sticky="ew", padx=(0, 24), pady=(0, 24))
        log_panel.grid_columnconfigure(0, weight=1)

        tk.Label(
            log_panel,
            text="System Log Console",
            bg=Palette.LOG_BG,
            fg=Palette.TEAL,
            font=("Segoe UI", 11, "bold"),
        ).grid(row=0, column=0, sticky="w", pady=(12, 8))

        self.log_console = tk.Text(
            log_panel,
            height=8,
            bg=Palette.LOG_TEXT_BG,
            fg=Palette.CYAN,
            wrap="word",
            font=("Consolas", 10),
            insertbackground=Palette.TEXT,
            relief="flat",
            state="disabled",
        )
        self.log_console.grid(row=1, column=0, sticky="ew", pady=(0, 14))

    def _start_queue_loop(self) -> None:
        self.root.after(200, self._process_ui_queue)

    def _start_runtime_log_tail(self) -> None:
        self.root.after(1000, self._poll_runtime_log)

    def _poll_runtime_log(self) -> None:
        try:
            if RUNTIME_LOG_PATH.exists():
                file_size = RUNTIME_LOG_PATH.stat().st_size
                if file_size < self.runtime_log_offset:
                    self.runtime_log_offset = 0

                with RUNTIME_LOG_PATH.open("r", encoding="utf-8", errors="ignore") as log_file:
                    log_file.seek(self.runtime_log_offset)
                    new_lines = log_file.readlines()
                    self.runtime_log_offset = log_file.tell()

                for line in new_lines:
                    self._append_log_line(line)
        finally:
            self.root.after(1000, self._poll_runtime_log)

    def _initial_sync(self) -> None:
        self._run_background("initial_sync", self.api_client.get_dashboard_snapshot)

    def _on_start_scan(self) -> None:
        self.start_button.configure(state="disabled")
        self.status_message.set("Backend status: starting")
        self._run_background("start_scan", self._start_scan_flow)

    def _on_stop_scan(self) -> None:
        self.stop_button.configure(state="disabled")
        self.status_message.set("Backend status: stopping")
        self._run_background("stop_scan", self._stop_scan_flow)

    def _on_repin_canary(self) -> None:
        self.repin_button.configure(state="disabled")
        self.status_message.set("Backend status: updating SSL Canary")
        self._run_background("repin_canary", self._repin_canary_flow)

    def _on_reset_test_state(self) -> None:
        self.reset_test_state_button.configure(state="disabled")
        self.status_message.set("Backend status: clearing debug test state")
        self._run_background("reset_test_state", self._reset_test_state_flow)

    def _start_scan_flow(self) -> dict:
        launch_status = self.backend_manager.ensure_running()
        scan_status = self.api_client.start_scan()
        snapshot = self.api_client.get_dashboard_snapshot()
        return {
            "launch_status": launch_status,
            "scan_state": self.api_client.parse_scan_state(scan_status),
            "snapshot": snapshot,
        }

    def _stop_scan_flow(self) -> dict:
        stop_payload = None
        stop_error = None

        try:
            if self.api_client.is_backend_reachable():
                stop_payload = self.api_client.stop_scan()
        except Exception as exc:
            stop_error = exc

        terminated_backend = self.backend_manager.stop_managed_backend()

        if stop_error is not None:
            raise stop_error

        return {
            "scan_state": self.api_client.parse_scan_state(stop_payload or {"active": False, "status": "stopped"}),
            "terminated_backend": terminated_backend,
        }

    def _repin_canary_flow(self) -> dict:
        self.api_client.repin_canary()
        return {"snapshot": self.api_client.get_dashboard_snapshot()}

    def _reset_test_state_flow(self) -> dict:
        self.api_client.reset_debug_test_state()
        return {"snapshot": self.api_client.get_dashboard_snapshot()}

    def _request_snapshot(self, source: str = "manual", notify_new: bool = True) -> None:
        self._run_background(
            "refresh_snapshot",
            self.api_client.get_dashboard_snapshot,
            source=source,
            notify_new=notify_new,
        )

    def _disconnect_network_flow(self, alert: AlertRecord) -> dict:
        output = self.backend_manager.disconnect_wifi()
        return {"alert": alert, "output": output}

    def _run_background(self, action: str, func: Callable[[], object], **metadata) -> None:
        def runner() -> None:
            try:
                result = func()
                self.ui_queue.put(("action_success", {"action": action, "result": result, **metadata}))
            except Exception as exc:
                self.ui_queue.put(("action_error", {"action": action, "error": str(exc), **metadata}))

        threading.Thread(target=runner, daemon=True, name=f"netshield-{action}").start()

    def _process_ui_queue(self) -> None:
        while True:
            try:
                event_name, payload = self.ui_queue.get_nowait()
            except queue.Empty:
                break

            if event_name == "snapshot_success":
                self._apply_snapshot(payload["snapshot"], notify_new=(payload.get("source") == "poll"))
            elif event_name == "snapshot_error":
                if payload.get("source") == "poll":
                    self.backend_reachable = False
                    self.status_message.set("Backend status: polling error")
                    self._refresh_ssl_canary_status()
                    self._update_button_state()
                    self._log(f"Polling error: {payload['message']}")
            elif event_name == "action_success":
                self._handle_action_success(payload)
            elif event_name == "action_error":
                self._handle_action_error(payload)

        self.root.after(200, self._process_ui_queue)

    def _handle_action_success(self, payload: dict) -> None:
        action = payload["action"]
        result = payload["result"]

        if action == "initial_sync":
            self._apply_snapshot(result, notify_new=False)
            self._log("Connected to Flask backend.")
            if self.scan_state.active:
                self.poller.start()
                self._log("Backend reports an active scan. Polling resumed.")
            else:
                self._log("Backend reports scanning is idle.")
            return

        if action == "start_scan":
            if result["launch_status"] == "launched":
                self._log("Flask backend was not running. Started `python app.py` in the backend folder.")
                self._set_backend_origin_indicator("GUI-launched", Palette.TEAL)
            else:
                self._set_backend_origin_indicator("External", Palette.SLATE)
            self.scan_state = result["scan_state"]
            self._apply_snapshot(result["snapshot"], notify_new=False)
            self.poller.start()
            self.status_message.set("Backend status: scanning")
            self._update_button_state()
            self._refresh_header_status()
            self._log("Scan started from desktop GUI.")
            return

        if action == "stop_scan":
            self.poller.stop()
            self.scan_state = result["scan_state"]
            self._refresh_header_status()
            if result["terminated_backend"]:
                self.backend_reachable = False
                self.status_message.set("Backend status: offline")
                self._set_backend_origin_indicator("Offline", Palette.TEXT_MUTED)
                self._log("Scan stopped and the GUI-initiated backend process was terminated.")
            else:
                self.backend_reachable = self.api_client.is_backend_reachable()
                self.status_message.set("Backend status: stopped")
                if self.backend_reachable:
                    self._set_backend_origin_indicator("External", Palette.SLATE)
                else:
                    self._set_backend_origin_indicator("Offline", Palette.TEXT_MUTED)
                self._log("Scan stopped from desktop GUI.")
            self._refresh_ssl_canary_status()
            self._update_button_state()
            return

        if action == "refresh_snapshot":
            self._apply_snapshot(result, notify_new=bool(payload.get("notify_new", True)))
            return

        if action == "repin_canary":
            self._apply_snapshot(result["snapshot"], notify_new=False)
            self._log("SSL Canary pin cleared from GUI. The next clean cycle will establish a new baseline.")
            return

        if action == "reset_test_state":
            self._apply_snapshot(result["snapshot"], notify_new=False)
            self._log("Debug test state cleared from GUI without changing the current SSL Canary pin.")
            return

        if action == "disconnect_network":
            alert = result["alert"]
            self._log(
                f"Protective action executed for {format_alert_type(alert.alert_type)}: disconnected Wi-Fi using `netsh wlan disconnect`."
            )
            if result["output"]:
                self._log(f"Disconnect command output: {result['output']}")
            self._show_status_toast("Wi-Fi disconnected", alert.description, Palette.RED, duration_ms=5000)
            return

    def _handle_action_error(self, payload: dict) -> None:
        action = payload["action"]
        message = payload["error"]

        if action == "initial_sync":
            self.backend_reachable = False
            self.status_message.set("Backend status: unavailable")
            self._set_backend_origin_indicator("Offline", Palette.TEXT_MUTED)
            self._refresh_ssl_canary_status()
            self._refresh_header_status()
            self._update_button_state()
            self._refresh_alert_feed()
            self._log(f"Initial sync failed: {message}")
            return

        self._log(f"{action.replace('_', ' ').title()} failed: {message}")

        if action in {"start_scan", "stop_scan", "refresh_snapshot", "repin_canary", "reset_test_state"}:
            self._update_button_state()

        if action == "disconnect_network":
            self._show_status_toast("Disconnect failed", message, Palette.AMBER, duration_ms=5000)

    def _apply_snapshot(self, snapshot: DashboardSnapshot, notify_new: bool) -> None:
        self.backend_reachable = True
        self.scan_state = snapshot.scan_state
        self.access_points_monitored = snapshot.access_points_monitored
        self._apply_alerts(snapshot.alerts, notify_new=notify_new)
        self._update_stats()
        self._refresh_ssl_canary_status()
        self._refresh_trust_score()
        self._refresh_header_status()
        self._update_button_state()

        if self.scan_state.error:
            self._log(f"Scan error: {self.scan_state.error}")

        if self.scan_state.traffic_monitor_error:
            self._log(f"Traffic monitor warning: {self.scan_state.traffic_monitor_error}")

        if self.scan_state.active:
            self.status_message.set("Backend status: scanning")
        elif self.backend_reachable:
            self.status_message.set("Backend status: idle with cached alerts" if self.alerts else "Backend status: idle")
            if self.backend_manager.is_managed_backend_running():
                self._set_backend_origin_indicator("GUI-launched", Palette.TEAL)
            else:
                self._set_backend_origin_indicator("External", Palette.SLATE)
        else:
            self.status_message.set("Backend status: unavailable")
            self._set_backend_origin_indicator("Offline", Palette.TEXT_MUTED)

    def _apply_alerts(self, alerts: List[AlertRecord], notify_new: bool) -> None:
        current_ids = {alert.id for alert in alerts}

        if notify_new:
            new_alerts = [alert for alert in alerts if alert.id not in self.previous_alert_ids]
            for alert in new_alerts:
                self._show_alert_toast(alert)
                self._log(f"New alert: {format_alert_type(alert.alert_type)} | {alert.description}")
                self._handle_high_risk_alert(alert)

        self.previous_alert_ids = current_ids
        self.alerts = alerts
        self._refresh_alert_feed()

    def _handle_high_risk_alert(self, alert: AlertRecord) -> None:
        if alert.id in self.high_risk_handled_ids:
            return

        if alert.severity not in {"high", "critical"} or alert.alert_type not in HIGH_RISK_TYPES:
            return

        self.high_risk_handled_ids.add(alert.id)

        if self.auto_disconnect_enabled.get():
            self._log(
                f"Auto-disconnect is enabled. Executing network disconnect for high-risk {format_alert_type(alert.alert_type)} alert."
            )
            self._run_background("disconnect_network", lambda alert=alert: self._disconnect_network_flow(alert))
            return

        self.disconnect_prompt_queue.append(alert)
        self._show_next_disconnect_prompt()

    def _show_next_disconnect_prompt(self) -> None:
        if self.active_disconnect_prompt is not None:
            return

        if not self.disconnect_prompt_queue:
            return

        if self.auto_disconnect_enabled.get():
            while self.disconnect_prompt_queue:
                alert = self.disconnect_prompt_queue.popleft()
                self._run_background("disconnect_network", lambda alert=alert: self._disconnect_network_flow(alert))
            return

        alert = self.disconnect_prompt_queue.popleft()

        prompt = tk.Toplevel(self.root)
        prompt.title("High-Risk Alert")
        prompt.configure(bg=Palette.PANEL_BG)
        prompt.transient(self.root)
        prompt.grab_set()
        prompt.resizable(False, False)
        self.active_disconnect_prompt = prompt

        container = tk.Frame(
            prompt,
            bg=Palette.PANEL_BG,
            highlightthickness=2,
            highlightbackground=Palette.RED,
        )
        container.pack(fill="both", expand=True, pady=16)

        tk.Label(
            container,
            text="High-Risk Network Threat Detected",
            bg=Palette.PANEL_BG,
            fg=Palette.TEXT,
            font=("Segoe UI", 16, "bold"),
        ).pack(anchor="w", pady=(18, 10))

        tk.Label(
            container,
            text=f"{format_alert_type(alert.alert_type)}\n{alert.description}",
            bg=Palette.PANEL_BG,
            fg=Palette.TEXT_SOFT,
            font=("Segoe UI", 11),
            justify="left",
            wraplength=500,
        ).pack(anchor="w", padx=18)

        tk.Label(
            container,
            text="Disconnect from the current Wi-Fi network now?",
            bg=Palette.PANEL_BG,
            fg="#fecaca",
            font=("Segoe UI", 11, "bold"),
        ).pack(anchor="w", pady=(14, 18))

        button_row = tk.Frame(container, bg=Palette.PANEL_BG)
        button_row.pack(anchor="e", pady=(0, 18))

        def close_prompt() -> None:
            if self.active_disconnect_prompt is not None:
                self.active_disconnect_prompt.destroy()
                self.active_disconnect_prompt = None

        def confirm_disconnect() -> None:
            close_prompt()
            self._run_background("disconnect_network", lambda alert=alert: self._disconnect_network_flow(alert))
            self._show_next_disconnect_prompt()

        def ignore_disconnect() -> None:
            self._log(
                f"Disconnect prompt dismissed for high-risk {format_alert_type(alert.alert_type)} alert."
            )
            close_prompt()
            self._show_next_disconnect_prompt()

        tk.Button(
            button_row,
            text="Ignore",
            command=ignore_disconnect,
            bg="#374151",
            fg=Palette.TEXT,
            activebackground="#4b5563",
            font=("Segoe UI", 10, "bold"),
            activeforeground=Palette.TEXT,
            relief="flat",
            cursor="hand2",
            ).pack(side="left", padx=(0, 10))

        tk.Button(
            button_row,
            text="Disconnect",
            command=confirm_disconnect,
            bg="#b91c1c",
            fg=Palette.TEXT,
            activebackground=Palette.RED,
            font=("Segoe UI", 10, "bold"),
            activeforeground=Palette.TEXT,
            relief="flat",
            cursor="hand2",
            ).pack(side="left")

        prompt.update_idletasks()
        x = self.root.winfo_rootx() + (self.root.winfo_width() // 2) - (prompt.winfo_width() // 2)
        y = self.root.winfo_rooty() + (self.root.winfo_height() // 2) - (prompt.winfo_height() // 2)
        prompt.geometry(f"+{max(x, 50)}+{max(y, 50)}")
        prompt.protocol("WM_DELETE_WINDOW", ignore_disconnect)

    def _refresh_alert_feed(self) -> None:
        for item in self.alert_tree.get_children():
            self.alert_tree.delete(item)

        if not self.alerts:
            self.alert_tree.insert(
                "",
                "end",
                values=("All Clear", "-", "No active alerts in the current feed.", "-"),
                tags=("empty",),
            )
            return

        for alert in self.alerts:
            self.alert_tree.insert(
                "",
                "end",
                values=(
                    format_alert_type(alert.alert_type),
                    alert.severity.upper(),
                    alert.description,
                    format_timestamp(alert.timestamp),
                ),
                tags=(alert.severity,),
            )

    def _update_stats(self) -> None:
        started_label = format_timestamp(self.scan_state.started_at) if self.scan_state.active else "Not running"
        active_alerts = [a for a in self.alerts if a.active]
        self.stats_labels["Access Points Monitored"].configure(text=str(self.access_points_monitored))
        self.stats_labels["Active Alerts"].configure(text=str(len(active_alerts)))
        self.stats_labels["Highest Severity"].configure(text=highest_severity(active_alerts))
        self.stats_labels["Scan Started At"].configure(text=started_label)

    def _refresh_ssl_canary_status(self) -> None:
        if not self.backend_reachable:
            self.ssl_canary_text.set("SSL Canary: Unavailable")
            self.ssl_canary_badge.configure(
                fg=Palette.TEXT_MUTED,
                highlightbackground=Palette.BORDER,
            )
            self.ssid_detector_text.set("WIFI Scanner: Unavailable")
            self.ssid_detector_badge.configure(
                fg=Palette.TEXT_MUTED,
                highlightbackground=Palette.BORDER,
            )
            self.arp_detector_text.set("ARP Monitor: Unavailable")
            self.arp_detector_badge.configure(
                fg=Palette.TEXT_MUTED,
                highlightbackground=Palette.BORDER,
            )
            return

    def _refresh_trust_score(self) -> None:
        score = self.scan_state.trust_score
        factors = self.scan_state.trust_factors

        if score >= 80:
            color = Palette.GREEN
        elif score >= 50:
            color = Palette.AMBER
        else:
            color = Palette.RED

        self.trust_panel.configure(highlightbackground=color)
        self.trust_score_value.configure(text=str(score), fg=color)
        self.trust_factors_label.configure(text="Factors: " + ", ".join(factors))

        status = str(self.scan_state.ssl_canary_status.get("status") or "").strip().lower()
        text = "SSL Canary: Unavailable"
        color = Palette.TEXT_MUTED

        if status in {"pending_pin", "pinning"}:
            text = "Establishing SSL baseline..."
            color = Palette.BLUE
        elif status in {"pinned", "pinned_uncertain", "pin_loaded"}:
            text = "SSL Canary: Active"
            color = Palette.GREEN
        elif status == "pin_delayed":
            text = "SSL Canary: Delayed (threat detected)"
            color = Palette.AMBER
        elif status in {"fingerprint_mismatch", "no_tls"}:
            text = "SSL Canary: Threat detected"
            color = Palette.RED
        elif status:
            text = f"SSL Canary: {status.replace('_', ' ').title()}"

        self.ssl_canary_text.set(text)
        self.ssl_canary_badge.configure(
            fg=color,
            highlightbackground=color if color != Palette.TEXT_MUTED else Palette.BORDER,
        )

        if self.scan_state.connected_ssid_error:
            self.ssid_detector_text.set("Scanner: SSID not found (evaluation paused)")
            self.ssid_detector_badge.configure(
                fg=Palette.AMBER,
                highlightbackground=Palette.AMBER,
            )
        else:
            self.ssid_detector_text.set("Scanner: Active (detecting SSID)")
            self.ssid_detector_badge.configure(
                fg=Palette.GREEN,
                highlightbackground=Palette.GREEN,
            )

        if self.scan_state.arp_status.get("suppressed"):
            self.arp_detector_text.set("ARP Monitor: Paused (Network Settling)")
            self.arp_detector_badge.configure(
                fg=Palette.AMBER,
                highlightbackground=Palette.AMBER,
            )
        else:
            self.arp_detector_text.set("ARP Monitor: Active")
            self.arp_detector_badge.configure(
                fg=Palette.GREEN,
                highlightbackground=Palette.GREEN,
            )

    def _refresh_header_status(self) -> None:
        if self.alerts:
            status_text = "Alert"
            color = Palette.RED
        elif self.scan_state.active:
            status_text = "Scanning"
            color = Palette.GREEN
        else:
            status_text = "Idle"
            color = Palette.TEXT_MUTED

        self.header_status_text.set(status_text)
        self.status_dot.itemconfigure(self.status_dot_oval, fill=color)
        self.status_chip.configure(highlightbackground=color)

    def _set_backend_origin_indicator(self, text: str, border_color: str) -> None:
        self.backend_origin_text.set(text)
        self.backend_origin_chip.configure(
            highlightbackground=border_color,
            fg=border_color if text != "Offline" else Palette.TEXT_MUTED,
        )

    def _update_button_state(self) -> None:
        self.start_button.configure(state="disabled" if self.scan_state.active else "normal")
        self.stop_button.configure(state="normal" if self.scan_state.active else "disabled")
        self.repin_button.configure(state="normal" if self.backend_reachable else "disabled")
        self.reset_test_state_button.configure(state="normal" if self.backend_reachable else "disabled")

    def _show_alert_toast(self, alert: AlertRecord) -> None:
        accent = {
            "critical": Palette.RED,
            "high": Palette.RED,
            "medium": Palette.AMBER,
            "low": Palette.GREEN,
        }.get(alert.severity, Palette.GREEN)
        self._show_status_toast(
            f"New {format_alert_type(alert.alert_type)} alert",
            alert.description,
            accent,
            duration_ms=4500,
        )

    def _show_status_toast(self, title: str, body: str, accent_color: str, duration_ms: int) -> None:
        # Prevent Tkinter GDI rendering crash (black box) during an alert flood
        current_toasts = self.toast_host.winfo_children()
        if len(current_toasts) >= 3:
            current_toasts[0].destroy()

        toast = tk.Frame(
            self.toast_host,
            bg=Palette.PANEL_BG,
            highlightthickness=1,
            highlightbackground="#334155",
        )
        toast.pack(anchor="e", pady=6)

        accent_bar = tk.Frame(toast, bg=accent_color, width=6)
        accent_bar.pack(side="left", fill="y")

        content = tk.Frame(toast, bg=Palette.PANEL_BG)
        content.pack(side="left", fill="both", expand=True, pady=10)

        tk.Label(
            content,
            text=title,
            bg=Palette.PANEL_BG,
            fg=Palette.TEXT,
            font=("Segoe UI", 11, "bold"),
        ).pack(anchor="w")

        tk.Label(
            content,
            text=body,
            bg=Palette.PANEL_BG,
            fg=Palette.TEXT_SOFT,
            font=("Segoe UI", 10),
            justify="left",
            wraplength=380,
        ).pack(anchor="w", pady=(6, 0))

        self.root.after(duration_ms, toast.destroy)

    def _log(self, message: str) -> None:
        from datetime import timezone, timedelta
        ist = timezone(timedelta(hours=5, minutes=30))
        timestamp = datetime.now(timezone.utc).astimezone(ist).strftime("%H:%M:%S")
        self._append_log_line(f"[{timestamp}] {message}")

    def _append_log_line(self, line: str) -> None:
        text = str(line).rstrip("\r\n")
        if not text:
            return

        import re
        from datetime import datetime as dt_mod, timezone, timedelta
        ist = timezone(timedelta(hours=5, minutes=30))

        def convert_runtime_log(match):
            try:
                parsed_dt = dt_mod.strptime(match.group(1), "%Y-%m-%d %H:%M:%S,%f").replace(tzinfo=timezone.utc)
                return "[" + parsed_dt.astimezone(ist).strftime("%Y-%m-%d %H:%M:%S,%f")[:-3] + " IST]"
            except ValueError:
                return match.group(0)

        text = re.sub(r"\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})\]", convert_runtime_log, text)

        self.log_console.configure(state="normal")
        self.log_console.insert("end", f"{text}\n")
        self.log_console.see("end")
        self.log_console.configure(state="disabled")

    def _handle_close(self) -> None:
        self.poller.stop()
        if self.active_disconnect_prompt is not None:
            self.active_disconnect_prompt.destroy()
            self.active_disconnect_prompt = None
        self.backend_manager.stop_managed_backend()
        self.root.destroy()

class BootSplashScreen:
    def __init__(self, parent: tk.Tk, on_complete: Callable[[], None]):
        self.parent = parent
        self.on_complete = on_complete
        
        self.splash = tk.Toplevel(parent)
        self.splash.overrideredirect(True)
        self.splash.configure(bg="#0d1117")
        self.splash.attributes("-topmost", True)
        
        width, height = 500, 400
        
        screen_width = self.splash.winfo_screenwidth()
        screen_height = self.splash.winfo_screenheight()
        x = (screen_width // 2) - (width // 2)
        y = (screen_height // 2) - (height // 2)
        self.splash.geometry(f"{width}x{height}+{x}+{y}")
        
        self.canvas = tk.Canvas(self.splash, width=width, height=height, bg="#0d1117", highlightthickness=0)
        self.canvas.pack(fill="both", expand=True)
        
        self._draw_shield(width, height)
        
        self.shine_pos = -200
        self.shine_poly = self.canvas.create_polygon(
            self.shine_pos, 0,
            self.shine_pos + 60, 0,
            self.shine_pos - 60, height,
            self.shine_pos - 120, height,
            fill="#ffffff", stipple="gray25"
        )
        
        self._animate_shine()

    def _draw_shield(self, w: int, h: int) -> None:
        cx, cy = w // 2, h // 2 - 30
        
        outer_pts = [
            cx - 80, cy - 80,
            cx + 80, cy - 80,
            cx + 80, cy + 30,
            cx, cy + 110,
            cx - 80, cy + 30
        ]
        self.canvas.create_polygon(*outer_pts, fill="#1e293b", outline="#3b82f6", width=3)
        
        inner_pts = [
            cx - 60, cy - 60,
            cx + 60, cy - 60,
            cx + 60, cy + 20,
            cx, cy + 80,
            cx - 60, cy + 20
        ]
        self.canvas.create_polygon(*inner_pts, fill="#0f172a", outline="#60a5fa", width=2)
        
        self.canvas.create_text(cx, cy + 150, text="N E T S H I E L D", fill="#f8fafc", font=("Helvetica", 22, "bold"))
        self.canvas.create_text(cx, cy + 175, text="INITIALIZING...", fill="#3b82f6", font=("Helvetica", 10, "bold"))

    def _animate_shine(self) -> None:
        if self.shine_pos > 700:
            self.splash.destroy()
            self.on_complete()
            return
            
        self.shine_pos += 15
        height = int(self.canvas.cget("height"))
        
        self.canvas.coords(
            self.shine_poly,
            self.shine_pos, 0,
            self.shine_pos + 60, 0,
            self.shine_pos - 60, height,
            self.shine_pos - 120, height,
        )
        
        self.parent.after(20, self._animate_shine)


def main() -> None:
    root = tk.Tk()
    root.withdraw()
    
    def start_main_app():
        NetShieldGUI(root)
        root.state('zoomed')
        root.deiconify()
        
    BootSplashScreen(root, start_main_app)
    root.mainloop()

if __name__ == "__main__":
    main()
