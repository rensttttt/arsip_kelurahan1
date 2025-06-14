from .base import BaseConfig

class TestingConfig(BaseConfig):
    DEBUG = True
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_SAMESITE = "Lax"