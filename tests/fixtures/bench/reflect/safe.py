from flask import request

ALLOWED = {"csv": "exporters.csv", "json": "exporters.json"}


def safe():
    name = request.args.get("plugin")
    # Allow-list lookup: the value that flows on is one of two constants.
    return ALLOWED.get(name, "exporters.json")
