import os
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask


def setup_logging(app: Flask):
    """Setup logging for Flask app."""
    base_dir = os.path.abspath(os.path.join(app.root_path, ".."))
    log_dir = os.path.join(base_dir, "logs")
    os.makedirs(log_dir, exist_ok=True)

    log_file = os.path.join(log_dir, "app.log")

    # Set log level dari config atau default ke DEBUG
    log_level = app.config.get("LOG_LEVEL", "DEBUG").upper()

    # Konfigurasi RotatingFileHandler
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=1_000_000,
        backupCount=5,
    )
    file_handler.setLevel(log_level)
    file_handler.setFormatter(
        logging.Formatter("[%(asctime)s] %(levelname)s in %(module)s: %(message)s")
    )

    # Tambahkan handler ke app.logger
    app.logger.setLevel(log_level)
    app.logger.addHandler(file_handler)

    # Juga log ke konsol saat development
    if app.debug:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        console_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
        app.logger.addHandler(console_handler)

    app.logger.info("Logging is set up.")


def log_activity(user_id: int, action: str, ip_address: str, user_agent: str, description: str):
    """Log user activity to the Flask app logger."""
    from flask import current_app
    current_app.logger.info(f"[ACTIVITY] user_id={user_id}, action={action}, ip={ip_address}, agent={user_agent}, desc={description}")


def log_system_error(error_message: str, extra_info: str | None = None):
    """Log system error to the Flask app logger."""
    from flask import current_app
    msg = f"[SYSTEM ERROR] {error_message}"
    if extra_info is not None:
        msg += f" | Extra: {extra_info}"
    current_app.logger.error(msg)
