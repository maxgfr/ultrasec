import os

from flask import abort, request


def require_api_key():
    if request.headers.get("X-Api-Key") != os.environ["API_KEY"]:
        abort(401)
