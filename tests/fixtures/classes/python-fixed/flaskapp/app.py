from flask import Flask
from flask_talisman import Talisman

from .export import bp

app = Flask(__name__)
Talisman(app)
app.register_blueprint(bp)
