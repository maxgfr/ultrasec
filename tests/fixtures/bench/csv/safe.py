from flask import request


def safe():
    note = request.args.get("note")
    # Rendered as JSON; no spreadsheet ever parses it.
    return {"note": str(note)}
