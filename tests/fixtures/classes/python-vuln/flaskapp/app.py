from flask import Flask

from .export import bp

app = Flask(__name__)
app.register_blueprint(bp)
