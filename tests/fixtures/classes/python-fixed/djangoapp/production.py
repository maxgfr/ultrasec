import os

from .settings import *  # noqa: F401,F403

DEBUG = os.environ.get("DJANGO_DEBUG", "false") == "true"
USE_X_FORWARDED_HOST = False
DATA_UPLOAD_MAX_MEMORY_SIZE = 2_621_440
