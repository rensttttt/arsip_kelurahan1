import os
import secrets
from dotenv import load_dotenv

load_dotenv()

class BaseConfig:
    SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(16))
    WTF_CSRF_TIME_LIMIT = None

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"  # default aman

    # Upload
    UPLOAD_FOLDER = os.path.join("static", "uploads")
    MAX_FILE_SIZE = 16 * 1024 * 1024
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    ALLOWED_EXTENSIONS = {"pdf", "doc", "docx", "jpg", "jpeg", "png"}

    # Logging
    LOG_FILE = "logs/arsip_kelurahan.log"
    LOG_LEVEL = "DEBUG"
    LOG_MAX_BYTES = 1000000
    LOG_BACKUP_COUNT = 5

    # DB
    DB_HOST = os.environ.get("DB_HOST")
    DB_NAME = os.environ.get("DB_DATABASE")
    DB_USER = os.environ.get("DB_USER")
    DB_PASSWORD = os.environ.get("DB_PASSWORD")

    # Email
    MAIL_SERVER = "smtp.gmail.com"
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get("MAIL_USERNAME")
    MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD")
    MAIL_DEFAULT_SENDER = os.environ.get("MAIL_DEFAULT_SENDER")
