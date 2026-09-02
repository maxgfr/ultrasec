import os
from flask import Flask, request

app = Flask(__name__)

ALLOWED = {"report.pdf", "terms.pdf"}


@app.route("/archive")
def archive():
    name = os.path.basename(request.args.get("name", ""))
    # Allow-listed name; nothing is copied from the input.
    return ("ok", 200) if name in ALLOWED else ("not found", 404)
