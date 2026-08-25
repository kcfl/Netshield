const typeLabels = {
  evil_twin: "Rogue Wi-Fi",
  arp_spoof: "ARP Spoofing",
  ssl_strip: "SSL Stripping",
  security_event: "Security Alert"
};

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

function toHeadline(type) {
  return type
    .split("_")
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function getAlertTitle(alert) {
  return typeLabels[alert.type] || toHeadline(alert.type || "security_event");
}

function getAlertDescription(alert) {
  const description = String(alert.description || "").trim();

  if (description) {
    return description;
  }

  if (alert.type === "evil_twin") {
    return "A suspicious duplicate Wi-Fi network is being broadcast and should be checked immediately.";
  }

  if (alert.type === "arp_spoof") {
    return "NetShield detected traffic patterns that suggest ARP spoofing on the network.";
  }

  if (alert.type === "ssl_strip") {
    return "NetShield detected a possible downgrade from HTTPS to HTTP in active traffic.";
  }

  return "NetShield detected suspicious behavior that should be reviewed.";
}

function formatTimestamp(timestamp) {
  if (!timestamp) {
    return "Time unavailable";
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

export default function AlertList({ alerts, loading, error, lastUpdated, summary, scanActive }) {
  return (
    <section className="card alert-feed">
      <div className="alert-feed__header">
        <div>
          <h2>Unified Alert Feed</h2>
          <p>One scrolling queue of every active security alert coming from `GET /api/alerts`.</p>
        </div>
        <div className="alert-feed__meta-group">
          <span className="alert-feed__meta">Last refresh: {lastUpdated}</span>
          {!loading && !error ? (
            <span className="alert-feed__count">
              {alerts.length} active | {summary.critical} critical | {summary.high} high | {summary.medium} medium | {summary.info} info
            </span>
          ) : null}
        </div>
      </div>

      {!loading && !error && !scanActive ? (
        <div className="alert-feed__banner">
          <h3>Scan stopped</h3>
          <p>Live scanning is paused, so this feed may show stale results until scanning starts again.</p>
        </div>
      ) : null}

      {loading ? (
        <div className="alert-state alert-state--loading">
          <h3>Loading alerts</h3>
          <p>Waiting for the first backend response.</p>
        </div>
      ) : null}

      {!loading && error ? (
        <div className="alert-state alert-state--error">
          <h3>Feed unavailable</h3>
          <p>{error}</p>
        </div>
      ) : null}

      {!loading && !error && alerts.length === 0 ? (
        <div className="alert-state alert-state--clear">
          <h3>All clear</h3>
          <p>No active rogue Wi-Fi, ARP spoofing, or SSL stripping alerts are being reported right now.</p>
        </div>
      ) : null}

      {!loading && !error && alerts.length > 0 ? (
        <div className="alert-items">
          {alerts.map((alert) => (
            <article
              key={alert.id}
              className={`alert-item alert-item--${normalizeSeverity(alert.severity)}`}
            >
              <div className="alert-item__topline">
                <span className={`severity severity--${normalizeSeverity(alert.severity)}`}>
                  {normalizeSeverity(alert.severity).toUpperCase()}
                </span>
                <span className="alert-item__type">{getAlertTitle(alert)}</span>
              </div>

              <h3 className="alert-item__title">{getAlertTitle(alert)}</h3>
              <p className="alert-item__description">{getAlertDescription(alert)}</p>

              <div className="alert-item__footer">
                <span className="alert-item__footer-label">Detected</span>
                <span className="alert-item__time">{formatTimestamp(alert.timestamp)}</span>
              </div>
            </article>
          ))}
        </div>
      ) : null}
    </section>
  );
}
