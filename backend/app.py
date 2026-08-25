import atexit
import os

from flask import Flask
from flask_cors import CORS

from api.routes import api_bp
from config import Config
from capture.sniffer import PacketSniffer
from runtime_logging import configure_runtime_logging
from services.alert_service import AlertService


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    CORS(app)
    configure_runtime_logging(app.logger)
    packet_sniffer = PacketSniffer()
    alert_service = AlertService(packet_sniffer)
    app.extensions["packet_sniffer"] = packet_sniffer
    app.extensions["alert_service"] = alert_service
    atexit.register(packet_sniffer.stop)
    app.register_blueprint(api_bp, url_prefix="/api")
    return app


app = create_app()


if __name__ == "__main__":
    gui_mode = os.getenv("NETSHIELD_GUI_MODE", "").lower() in {"1", "true", "yes"}
    debug_enabled = app.config["DEBUG"] and not gui_mode
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=debug_enabled,
        use_reloader=debug_enabled,
        threaded=True,
    )
