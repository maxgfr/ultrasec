from flask import request

from sink import export


def handler(out):
    note = request.args.get("note")
    return export([[note]], out)
