import hmac
import os

from flask import abort, request


def require_api_key():
    if not hmac.compare_digest(request.headers.get("X-Api-Key", ""), os.environ["API_KEY"]):
        abort(401)
