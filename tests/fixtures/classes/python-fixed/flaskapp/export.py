from flask import Blueprint, jsonify, request

from .models import User

bp = Blueprint("export", __name__)


@bp.route("/export/users")
def export_users():
    page = User.query.order_by(User.id).paginate(page=request.args.get("page", 1, type=int), per_page=500)
    return jsonify([u.email for u in page.items])
