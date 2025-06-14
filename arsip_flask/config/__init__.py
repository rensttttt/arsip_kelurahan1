import os


ENVIRONMENT = os.environ.get("FLASK_ENV", "development").lower()

if ENVIRONMENT == "production":
    from .production import ProductionConfig as Config
elif ENVIRONMENT == "preview":
    from .preview import PreviewConfig as Config
elif ENVIRONMENT == "testing":
    from .testing import TestingConfig as Config
elif ENVIRONMENT == "development":
    from .development import DevelopmentConfig as Config
else:
    raise ValueError(f"Unrecognized FLASK_ENV: {ENVIRONMENT}")
