from flask import Flask
from flask_talisman import Talisman

from .export import bp

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024
Talisman(app)
app.register_blueprint(bp)
