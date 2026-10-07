import os

DEBUG = os.environ.get("DEBUG", "false").lower() in ("1", "true", "yes")
