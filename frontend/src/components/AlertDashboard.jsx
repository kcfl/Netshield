import { useEffect, useMemo, useRef, useState } from "react";

import AlertList from "./AlertList";
import LayerStatusCard from "./LayerStatusCard";

const POLL_INTERVAL_MS = 4000;
const ALERTS_API_PATH = "/api/alerts";
const SCAN_STATUS_API_PATH = "/api/scan/status";
const SCAN_START_API_PATH = "/api/scan/start";
const SCAN_STOP_API_PATH = "/api/scan/stop";

function normalizeSeverity(severity) {
  const normalizedSeverity = String(severity || "low").toLowerCase();

  if (
    normalizedSeverity === "critical" ||
    normalizedSeverity === "high" ||
    normalizedSeverity === "medium" ||
    normalizedSeverity === "info" ||
    normalizedSeverity === "low"
  ) {
    return normalizedSeverity;
  }

  return "low";
}

function normalizeAlert(alert, index) {
  const severity = normalizeSeverity(alert?.severity);
  const type = String(alert?.type || "security_event");
  const description =
    String(alert?.description || "").trim() || "NetShield detected suspicious activity that needs review.";
  const timestamp = alert?.timestamp || "";

  return {
    id: alert?.id || `${type}-${timestamp || "unknown"}-${index}`,
    type,
    severity,
    description,
    timestamp,
    active: alert?.active ?? true
  };
}

function formatAlertType(type) {
  return String(type || "security_event")
    .split("_")
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function getHighestSeverity(summary) {
  if (summary.critical > 0) {
    return { label: "Critical", tone: "critical" };
  }

  if (summary.high > 0) {
    return { label: "High", tone: "high" };
  }

  if (summary.medium > 0) {
    return { label: "Medium", tone: "medium" };
  }

  if (summary.info > 0) {
    return { label: "Info", tone: "info" };
  }

  return { label: "Low", tone: "low" };
}

function normalizeScanStatus(scanStatus) {
  const active = Boolean(scanStatus?.active);

  return {
    active,
    status: active ? "running" : "stopped",
    interface: scanStatus?.interface || "",
    trafficInterface: scanStatus?.traffic_interface || "",
    startedAt: scanStatus?.started_at || "",
    error: scanStatus?.error || "",
    trafficMonitorError: scanStatus?.traffic_monitor_error || ""
  };
}

function formatTimeOnly(timestamp) {
  if (!timestamp) {
    return "Waiting for first update";
  }

  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) {
    return timestamp;
  }

  return date.toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit"
  });
}

function formatDateTime(timestamp) {
  if (!timestamp) {
    return "Not available";
  }

  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) {
    return timestamp;
  }

  return date.toLocaleString([], {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit"
  });
}

function getNotificationSupportState() {
  if (typeof window === "undefined" || !("Notification" in window)) {
    return "unsupported";
  }

  if (Notification.permission === "granted") {
    return "enabled";
  }

  if (Notification.permission === "denied") {
    return "blocked";
  }

  return "pending";
}

export default function AlertDashboard() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [lastUpdated, setLastUpdated] = useState("");
  const [scanStatus, setScanStatus] = useState(() => normalizeScanStatus());
  const [scanAction, setScanAction] = useState("");
  const [scanError, setScanError] = useState("");
  const [notificationState, setNotificationState] = useState(() => getNotificationSupportState());
  const previousAlertIdsRef = useRef(null);

  useEffect(() => {
    if (typeof window === "undefined" || !("Notification" in window)) {
      setNotificationState("unsupported");
      return;
    }

    if (Notification.permission === "default") {
      Notification.requestPermission()
        .then(() => {
          setNotificationState(getNotificationSupportState());
        })
        .catch(() => {
          setNotificationState(getNotificationSupportState());
        });
      return;
    }

    setNotificationState(getNotificationSupportState());
  }, []);

  useEffect(() => {
    let isActive = true;
    let isFetching = false;

    const notifyForNewAlerts = (currentAlerts) => {
      const previousAlertIds = previousAlertIdsRef.current;
      const currentAlertIds = new Set(currentAlerts.map((alert) => alert.id));

      if (previousAlertIds === null) {
        previousAlertIdsRef.current = currentAlertIds;
        return;
      }

      if (typeof window === "undefined" || !("Notification" in window)) {
        previousAlertIdsRef.current = currentAlertIds;
        return;
      }

      if (Notification.permission !== "granted") {
        previousAlertIdsRef.current = currentAlertIds;
        return;
      }

      currentAlerts
        .filter((alert) => !previousAlertIds.has(alert.id))
        .forEach((alert) => {
          new Notification(`NetShield: ${formatAlertType(alert.type)}`, {
            body: alert.description,
            tag: alert.id
          });
        });

      previousAlertIdsRef.current = currentAlertIds;
    };

    const pollDashboard = async () => {
      if (isFetching) {
        return;
      }

      isFetching = true;

      try {
        const [alertsResponse, statusResponse] = await Promise.all([
          fetch(ALERTS_API_PATH, {
            headers: {
              Accept: "application/json"
            },
            cache: "no-store"
          }),
          fetch(SCAN_STATUS_API_PATH, {
            headers: {
              Accept: "application/json"
            },
            cache: "no-store"
          })
        ]);

        if (!alertsResponse.ok) {
          throw new Error(`Alert API returned ${alertsResponse.status}`);
        }

        if (!statusResponse.ok) {
          throw new Error(`Scan status API returned ${statusResponse.status}`);
        }

        const data = await alertsResponse.json();
        const statusData = await statusResponse.json();
        const rawAlerts = Array.isArray(data) ? data : Array.isArray(data.alerts) ? data.alerts : [];
        const normalizedAlerts = rawAlerts.map(normalizeAlert);
        const normalizedScanStatus = normalizeScanStatus(statusData);

        if (!isActive) {
          return;
        }

        setAlerts(normalizedAlerts);
        setScanStatus(normalizedScanStatus);
        setError("");
        setScanError("");
        setLastUpdated(new Date().toISOString());
        notifyForNewAlerts(normalizedAlerts);
      } catch (requestError) {
        if (!isActive) {
          return;
        }

        setError(requestError.message || "Unable to load the alert feed.");
        setScanError(requestError.message || "Unable to load scan status.");
      } finally {
        if (isActive) {
          setLoading(false);
        }

        isFetching = false;
      }
    };

    pollDashboard();

    const intervalId = window.setInterval(pollDashboard, POLL_INTERVAL_MS);

    return () => {
      isActive = false;
      window.clearInterval(intervalId);
    };
  }, []);

  const summary = useMemo(() => {
    return alerts.reduce(
      (accumulator, alert) => {
        if (!alert.active) {
          return accumulator;
        }

        const severity = normalizeSeverity(alert.severity);

        if (severity === "critical") {
          accumulator.critical += 1;
        } else if (severity === "high") {
          accumulator.high += 1;
        } else if (severity === "medium") {
          accumulator.medium += 1;
        } else if (severity === "info") {
          accumulator.info += 1;
        } else {
          accumulator.low += 1;
        }

        return accumulator;
      },
      { critical: 0, high: 0, medium: 0, info: 0, low: 0 }
    );
  }, [alerts]);

  const highestSeverity = getHighestSeverity(summary);
  const activeAlerts = alerts.filter(a => a.active);
  const activeAlertCount = activeAlerts.length;
  const systemStatus = activeAlerts.length > 0 ? "Attention Needed" : "All Clear";
  const systemStatusTone = activeAlerts.length > 0 ? "high" : "low";
  const lastUpdatedLabel = formatTimeOnly(lastUpdated);
  const scanStartedLabel = formatDateTime(scanStatus.startedAt);
  const scanStateTone = scanStatus.active ? "low" : "medium";
  const scanStateLabel = scanStatus.active ? "Running" : "Stopped";
  const interfaceLabel = scanStatus.interface || scanStatus.trafficInterface || "Awaiting interface";
  const isStarting = scanAction === "start";
  const isStopping = scanAction === "stop";
  const notificationLabelMap = {
    enabled: "Enabled",
    blocked: "Blocked",
    unsupported: "Unsupported",
    pending: "Waiting"
  };
  const notificationDescriptionMap = {
    enabled: "Desktop alerts are allowed and new detections will trigger OS notifications.",
    blocked: "Desktop alerts are blocked in the browser. Allow notifications to see pop-up alerts.",
    unsupported: "This browser does not support the Web Notifications API.",
    pending: "Notification permission has not been granted yet."
  };
  const notificationToneMap = {
    enabled: "low",
    blocked: "high",
    unsupported: "medium",
    pending: "medium"
  };

  const handleScanAction = async (action) => {
    const apiPath = action === "start" ? SCAN_START_API_PATH : SCAN_STOP_API_PATH;

    try {
      setScanAction(action);
      setScanError("");

      const response = await fetch(apiPath, {
        method: "POST",
        headers: {
          Accept: "application/json"
        }
      });

      if (!response.ok) {
        throw new Error(`Scan ${action} API returned ${response.status}`);
      }

      const data = await response.json();
      setScanStatus(normalizeScanStatus(data));
      setLastUpdated(new Date().toISOString());
    } catch (requestError) {
      setScanError(requestError.message || `Unable to ${action} scanning.`);
    } finally {
      setScanAction("");
    }
  };

  return (
    <main className="dashboard">
      <header className="dashboard__header">
        <div>
          <h1>NetShield</h1>
          <p>Unified live alert feed for evil-twin Wi-Fi, ARP spoofing, and SSL-strip detections.</p>
        </div>
        <div className="dashboard__heartbeat">
          <span className="dashboard__heartbeat-dot" />
          Live feed refreshes every 4 seconds
        </div>
      </header>

      <section className="card scan-control">
        <div className="scan-control__overview">
          <div>
            <p className="scan-control__eyebrow">Scan Control</p>
            <h2>Live scan state: {scanStateLabel}</h2>
            <p className="scan-control__description">
              Start or stop the Wi-Fi polling and live Scapy traffic monitoring threads for the demo.
            </p>
          </div>

          <div className={`scan-control__badge scan-control__badge--${scanStatus.active ? "running" : "stopped"}`}>
            <span className="scan-control__badge-dot" />
            {scanStateLabel}
          </div>
        </div>

        <div className="scan-control__details">
          <div className="scan-control__detail">
            <span className="scan-control__detail-label">Interface</span>
            <span className="scan-control__detail-value">{scanStatus.active ? interfaceLabel : "Not scanning"}</span>
          </div>
          <div className="scan-control__detail">
            <span className="scan-control__detail-label">Started</span>
            <span className="scan-control__detail-value">{scanStatus.active ? scanStartedLabel : "Not running"}</span>
          </div>
          <div className="scan-control__detail">
            <span className="scan-control__detail-label">Notifications</span>
            <span
              className={`scan-control__detail-value scan-control__detail-value--${notificationToneMap[notificationState]}`}
            >
              {notificationLabelMap[notificationState]}
            </span>
            <span className="scan-control__detail-note">{notificationDescriptionMap[notificationState]}</span>
          </div>
        </div>

        <div className="scan-control__actions">
          <button
            type="button"
            className="scan-control__button scan-control__button--start"
            onClick={() => handleScanAction("start")}
            disabled={scanStatus.active || Boolean(scanAction)}
          >
            {isStarting ? "Starting..." : "Start Scan"}
          </button>
          <button
            type="button"
            className="scan-control__button scan-control__button--stop"
            onClick={() => handleScanAction("stop")}
            disabled={!scanStatus.active || Boolean(scanAction)}
          >
            {isStopping ? "Stopping..." : "Stop Scan"}
          </button>
        </div>

        {scanError ? <p className="scan-control__error">{scanError}</p> : null}
      </section>

      <section className="dashboard__grid">
        <LayerStatusCard
          title="Scan State"
          value={scanStateLabel}
          description={
            scanStatus.active
              ? `Scanning on ${interfaceLabel} since ${scanStartedLabel}.`
              : "Scanning is paused. Alerts and Wi-Fi data will remain stale until you start again."
          }
          tone={scanStateTone}
        />
        <LayerStatusCard
          title="System Status"
          value={systemStatus}
          description="Single combined view of every alert coming from the backend."
          tone={systemStatusTone}
        />
        <LayerStatusCard
          title="Active Alerts"
          value={activeAlertCount}
          description="Current alert count across rogue Wi-Fi, ARP spoofing, and SSL stripping."
          tone={activeAlertCount > 0 ? highestSeverity.tone : "low"}
        />
        <LayerStatusCard
          title="Highest Severity"
          value={highestSeverity.label}
          description="The most urgent severity level currently visible in the feed."
          tone={highestSeverity.tone}
        />
        <LayerStatusCard
          title="Last Updated"
          value={lastUpdatedLabel}
          description={error ? "Backend connection issue detected." : "Dashboard is polling GET /api/alerts successfully."}
          tone={error ? "high" : "low"}
        />
      </section>

      <AlertList
        alerts={alerts}
        loading={loading}
        error={error}
        lastUpdated={lastUpdatedLabel}
        summary={summary}
        scanActive={scanStatus.active}
      />
    </main>
  );
}
