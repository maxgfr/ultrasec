import shutil
from flask import Flask, request

app = Flask(__name__)


@app.route("/archive")
def archive():
    name = request.args.get("name")
    shutil.copy("/srv/files/" + name, "/srv/archive/")
    return "ok"
