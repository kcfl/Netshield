import os
from pathlib import Path


class Config:
    DEBUG = os.getenv("FLASK_DEBUG", "true").lower() == "true"
    ENABLE_DEBUG_API = os.getenv(
        "ENABLE_DEBUG_API",
        "true" if DEBUG else "false",
    ).lower() == "true"
    SECRET_KEY = os.getenv("SECRET_KEY", "netshield-dev-key")

    # SSL Canary / Certificate Pinning
    SSL_CANARY_URL = os.getenv("SSL_CANARY_URL", "https://8.8.8.8")
    SSL_CANARY_INTERVAL = int(os.getenv("SSL_CANARY_INTERVAL", "15"))
    # Past this age a pin/cert mismatch is as likely routine rotation as interception.
    SSL_CANARY_PIN_MAX_AGE_DAYS = int(os.getenv("SSL_CANARY_PIN_MAX_AGE_DAYS", "7"))
    SSL_CANARY_PIN_PATH = Path(__file__).resolve().parent / "data" / "canary_pin.json"
