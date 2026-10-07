from flask import Blueprint, jsonify

from .models import User

bp = Blueprint("export", __name__)


@bp.route("/export/users")
def export_users():
    return jsonify([u.email for u in User.query.all()])
