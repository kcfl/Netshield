from __future__ import annotations

import logging
from pathlib import Path


RUNTIME_LOG_PATH = Path(__file__).resolve().parent.parent / "netshield_runtime.log"
_LOG_FORMAT = "[%(asctime)s] %(levelname)s %(name)s: %(message)s"


def _has_runtime_file_handler(logger: logging.Logger) -> bool:
    target_path = str(RUNTIME_LOG_PATH.resolve())
    for handler in logger.handlers:
        if isinstance(handler, logging.FileHandler):
            base_filename = getattr(handler, "baseFilename", "")
            if base_filename and str(Path(base_filename).resolve()) == target_path:
                return True
    return False


def _attach_runtime_file_handler(logger: logging.Logger) -> None:
    if _has_runtime_file_handler(logger):
        return

    RUNTIME_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(RUNTIME_LOG_PATH, encoding="utf-8")
    handler.setLevel(logging.INFO)
    handler.setFormatter(logging.Formatter(_LOG_FORMAT))
    logger.addHandler(handler)


def configure_runtime_logging(app_logger: logging.Logger | None = None) -> None:
    runtime_logger = logging.getLogger("netshield.runtime")
    runtime_logger.setLevel(logging.INFO)
    runtime_logger.propagate = False
    _attach_runtime_file_handler(runtime_logger)

    werkzeug_logger = logging.getLogger("werkzeug")
    werkzeug_logger.setLevel(logging.INFO)
    _attach_runtime_file_handler(werkzeug_logger)

    if app_logger is not None:
        app_logger.setLevel(logging.INFO)
        _attach_runtime_file_handler(app_logger)


def get_runtime_logger() -> logging.Logger:
    configure_runtime_logging()
    return logging.getLogger("netshield.runtime")
