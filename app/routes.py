from flask import Blueprint, current_app, jsonify, render_template, request

from .extensions import limiter
from .security import check_breached_password, evaluate_password, validate_password_input

bp = Blueprint("main", __name__)


@bp.get("/")
def index():
    return render_template("index.html")


@bp.route("/check", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
@limiter.limit("10 per minute")
def check_password():
    if request.method != "POST":
        return (
            jsonify(
                {
                    "error": "method_not_allowed",
                    "message": "Use POST with application/json",
                    "status": 405,
                }
            ),
            405,
        )

    if not request.is_json:
        return (
            jsonify(
                {
                    "error": "unsupported_media_type",
                    "message": "Use application/json",
                    "status": 415,
                }
            ),
            415,
        )
    if request.content_length is not None and request.content_length > 2048:
        return (
            jsonify(
                {
                    "error": "payload_too_large",
                    "message": "Request body too large",
                    "status": 413,
                }
            ),
            413,
        )

    payload = request.get_json(silent=True) or {}
    password = payload.get("password", "")
    check_breached = bool(payload.get("check_breached", False))

    is_valid, error = validate_password_input(password)
    if not is_valid:
        return (
            jsonify(
                {
                    "error": "bad_request",
                    "message": error,
                    "details": {"field": "password"},
                }
            ),
            400,
        )

    common_passwords = current_app.config.get("COMMON_PASSWORDS", set())
    result = evaluate_password(password, common_passwords)

    breached = None
    if check_breached and current_app.config.get("HIBP_ENABLED", False):
        breached = check_breached_password(password)

    result["breached"] = breached
    return jsonify(result)


@bp.get("/healthz")
def health_check():
    return (
        jsonify(
            {
                "status": "ok",
                "version": current_app.config.get("VERSION", "0.1.0"),
                "hibp_enabled": bool(current_app.config.get("HIBP_ENABLED", False)),
            }
        ),
        200,
    )
