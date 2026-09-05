from __future__ import annotations

from datetime import datetime
from uuid import NAMESPACE_URL, uuid5

from models.alert import Alert

CORRELATION_WINDOW_SECONDS = 60


class AlertService:
    """Build a unified alert feed from the backend detector snapshot."""

    def __init__(self, packet_sniffer):
        self.packet_sniffer = packet_sniffer

    def get_all_alerts(self):
        snapshot = self.packet_sniffer.get_snapshot()
        alerts = []

        alerts.extend(self._build_evil_twin_alerts(snapshot))
        arp_status = snapshot.get("arp_spoof", {})
        arp_status["snapshot"] = snapshot
        alerts.extend(self._build_arp_alerts(arp_status))
        
        ssl_status = snapshot.get("ssl_strip", {})
        ssl_status["snapshot"] = snapshot
        alerts.extend(self._build_ssl_strip_alerts(ssl_status))
        alerts.extend(self._build_correlated_alerts(alerts, window_seconds=CORRELATION_WINDOW_SECONDS))

        return sorted(alerts, key=lambda alert: alert["timestamp"], reverse=True)

    def _build_evil_twin_alerts(self, snapshot):
        access_points = {
            item["bssid"]: item
            for item in snapshot.get("access_points", [])
        }
        alerts = []

        for group in snapshot.get("evil_twin_groups", []):
            bssids = group.get("bssids", [])
            ssid = group.get("ssid", "")
            ouis = group.get("ouis", [])
            security_profiles = group.get("security_profiles", [])
            severity = group["severity"]
            if str(severity).strip().lower() == "info":
                continue
            score = group.get("score")
            reason = group.get("reason", "")
            # Anchor to when the group became detectable. last_seen is rewritten on
            # every poll, so using it mints a new alert id each cycle, which re-fires
            # GUI toasts and the high-risk disconnect prompt for the same evil twin.
            first_seen_values = [
                access_points[bssid]["first_seen"]
                for bssid in bssids
                if bssid in access_points and access_points[bssid].get("first_seen")
            ]
            started_at = snapshot.get("started_at") or ""
            timestamp = max(first_seen_values) if first_seen_values else started_at
            if started_at and timestamp < started_at:
                # Group predates this session; report it at session start so it
                # still reads as active.
                timestamp = started_at
            description_parts = [
                f"SSID '{ssid}' is being broadcast by multiple BSSIDs ({', '.join(bssids)}).",
            ]
            if ouis:
                description_parts.append(f"Observed OUI prefixes: {', '.join(ouis)}.")
            if security_profiles:
                description_parts.append(
                    f"Observed security profiles: {', '.join(security_profiles)}."
                )
            if reason:
                description_parts.append(f"Reason: {reason}")
            if score is not None:
                description_parts.append(f"Severity score: {score}.")
            description = " ".join(description_parts)

            alerts.append(
                self._make_alert(
                    alert_type="evil_twin",
                    severity=severity,
                    description=description,
                    timestamp=timestamp,
                    snapshot=snapshot,
                )
            )

        return alerts

    def _build_arp_alerts(self, arp_status):
        alerts = []

        for event in arp_status.get("events", []):
            alerts.append(
                self._make_alert(
                    alert_type="arp_spoof",
                    severity=event.get("severity", arp_status.get("severity", "high")),
                    description=event.get("description", arp_status.get("description", "")),
                    timestamp=event.get("last_seen"),
                    snapshot=arp_status.get("snapshot"),
                )
            )

        return alerts

    def _build_ssl_strip_alerts(self, ssl_status):
        alerts = []

        for event in ssl_status.get("events", []):
            alerts.append(
                self._make_alert(
                    alert_type="ssl_strip",
                    severity=event.get("severity", ssl_status.get("severity", "medium")),
                    description=event.get("description", ssl_status.get("description", "")),
                    timestamp=event.get("last_seen"),
                    snapshot=ssl_status.get("snapshot"),
                )
            )

        return alerts

    def _build_correlated_alerts(self, alerts, window_seconds):
        correlated = []
        if not alerts:
            return correlated

        def parse_ts(ts):
            if not ts:
                return 0.0
            try:
                return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
            except Exception:
                return 0.0

        sorted_alerts = sorted(alerts, key=lambda a: parse_ts(a["timestamp"]))
        
        i = 0
        n = len(sorted_alerts)
        while i < n:
            start_ts = parse_ts(sorted_alerts[i]["timestamp"])
            if start_ts == 0.0:
                i += 1
                continue
            
            cluster = [sorted_alerts[i]]
            j = i + 1
            while j < n:
                ts = parse_ts(sorted_alerts[j]["timestamp"])
                if ts - start_ts <= window_seconds:
                    cluster.append(sorted_alerts[j])
                    j += 1
                else:
                    break
            
            unique_types = set(a["type"] for a in cluster)
            if len(unique_types) >= 2:
                types_str = " and ".join([t.replace("_", " ").title() for t in unique_types])
                time_diff = int(parse_ts(cluster[-1]["timestamp"]) - start_ts)
                
                desc = f"{types_str} detected within {time_diff} seconds — strong indicator of an active man-in-the-middle attack."
                
                correlated.append(
                    self._make_alert(
                        alert_type="correlated_mitm",
                        severity="critical",
                        description=desc,
                        timestamp=cluster[-1]["timestamp"],
                        active=cluster[-1].get("active", True),
                    )
                )
                i = j
            else:
                i += 1
                
        return correlated

    def _make_alert(self, alert_type, severity, description, timestamp, snapshot=None, active=None):
        timestamp = timestamp or ""
        if active is None:
            active = True
            if snapshot and snapshot.get("started_at") and timestamp:
                active = timestamp >= snapshot.get("started_at")
        
        alert_id = str(
            uuid5(
                NAMESPACE_URL,
                f"netshield:{alert_type}:{severity}:{timestamp}:{description}",
            )
        )
        return Alert(
            id=alert_id,
            type=alert_type,
            severity=severity,
            description=description,
            timestamp=timestamp,
            active=active,
        ).to_dict()
