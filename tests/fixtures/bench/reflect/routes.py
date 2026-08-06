from flask import request

from sink import load


def handler():
    name = request.args.get("plugin")
    return load(name)
