from flask import Blueprint, current_app, jsonify


api_bp = Blueprint("api", __name__)


@api_bp.get("/health")
def health_check():
    return jsonify({"status": "ok", "service": "netshield-backend"})


@api_bp.get("/alerts")
def list_alerts():
    alert_service = current_app.extensions["alert_service"]
    alerts = alert_service.get_all_alerts()
    return jsonify(
        {
            "alerts": alerts,
            "count": len(alerts),
        }
    )


@api_bp.post("/scan/start")
def start_scan():
    packet_sniffer = current_app.extensions["packet_sniffer"]
    packet_sniffer.start()
    return jsonify(packet_sniffer.get_scan_status())


@api_bp.post("/scan/stop")
def stop_scan():
    packet_sniffer = current_app.extensions["packet_sniffer"]
    packet_sniffer.stop()
    return jsonify(packet_sniffer.get_scan_status())


@api_bp.get("/scan/status")
def get_scan_status():
    packet_sniffer = current_app.extensions["packet_sniffer"]
    return jsonify(packet_sniffer.get_scan_status())


@api_bp.get("/wifi/access-points")
def get_access_points():
    packet_sniffer = current_app.extensions["packet_sniffer"]
    return jsonify(packet_sniffer.get_snapshot())


@api_bp.post("/canary/repin")
def repin_canary():
    packet_sniffer = current_app.extensions["packet_sniffer"]
    return jsonify(packet_sniffer.reset_ssl_canary_pin())


@api_bp.post("/debug/reset-test-state")
def reset_debug_test_state():
    if not current_app.config.get("ENABLE_DEBUG_API", False):
        return jsonify({"error": "Debug API is disabled."}), 403

    packet_sniffer = current_app.extensions["packet_sniffer"]
    return jsonify(packet_sniffer.reset_debug_test_state())
