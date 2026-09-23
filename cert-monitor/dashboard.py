"""Web dashboard and JSON API over cert-monitor's SQLite history."""

from __future__ import annotations

import hmac
import json
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

from flask import (
    Flask,
    Response,
    abort,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

import storage

STATUS_ORDER = ["EXPIRED", "INVALID_CHAIN", "UNREACHABLE", "EXPIRING_SOON", "OK"]
STATUS_LABELS = {
    "EXPIRED": "Expired",
    "INVALID_CHAIN": "Invalid chain",
    "UNREACHABLE": "Unreachable",
    "EXPIRING_SOON": "Expiring soon",
    "OK": "OK",
}

# Checked when a login names an unknown user, so a failed login takes the
# same time whether or not the username exists.
_DUMMY_HASH = generate_password_hash(secrets.token_hex(16))


def hash_password(password: str) -> str:
    return generate_password_hash(password)


def verify_user(conn: sqlite3.Connection, username: str, password: str) -> sqlite3.Row | None:
    user = storage.get_user(conn, username)
    if user is None:
        check_password_hash(_DUMMY_HASH, password)
        return None
    return user if check_password_hash(user["password_hash"], password) else None


def _fmt_time(value: str | None) -> str:
    if not value:
        return "—"
    return datetime.fromisoformat(value).astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _safe_next(target: str | None) -> str:
    # Only follow local paths after login; "//host" and "/\host" are treated
    # by browsers as links to another site.
    if target and target.startswith("/") and not target.startswith("//") and "\\" not in target:
        return target
    return url_for("index")


def create_app(
    db_path: str,
    stale_hours: float = 24,
    secret_key: str | None = None,
    secure_cookies: bool = False,
) -> Flask:
    app = Flask(__name__)
    app.config.update(
        # Without a fixed key, sessions are signed with a random key and
        # everyone is logged out when the server restarts.
        SECRET_KEY=secret_key or secrets.token_hex(32),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=secure_cookies,
        PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
    )
    app.jinja_env.filters["fmt_time"] = _fmt_time
    app.jinja_env.filters["status_label"] = lambda s: STATUS_LABELS.get(s, s)
    stale_after = timedelta(hours=stale_hours)

    def db():
        if "db" not in g:
            g.db = storage.connect(db_path)
        return g.db

    def csrf_token() -> str:
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)
        return session["csrf"]

    app.jinja_env.globals["csrf_token"] = csrf_token

    def to_view(row) -> dict:
        view = dict(row)
        view["san"] = json.loads(view["san"]) if view["san"] else []
        view["chain_valid"] = bool(view["chain_valid"])
        checked_at = datetime.fromisoformat(view["checked_at"])
        view["stale"] = datetime.now(timezone.utc) - checked_at > stale_after
        return view

    def latest_views() -> list[dict]:
        rows = [to_view(r) for r in storage.latest_checks(db())]
        rows.sort(
            key=lambda r: (
                STATUS_ORDER.index(r["status"]),
                r["days_remaining"] is None,
                r["days_remaining"] or 0,
            )
        )
        return rows

    @app.teardown_appcontext
    def close_db(exc):
        conn = g.pop("db", None)
        if conn is not None:
            conn.close()

    @app.before_request
    def authenticate():
        g.user = None
        if request.endpoint == "static":
            return None
        if request.method == "POST":
            sent = request.form.get("csrf_token", "")
            if not hmac.compare_digest(sent.encode(), session.get("csrf", "").encode()):
                abort(400, "Invalid or missing CSRF token. Reload the page and try again.")
        if request.endpoint == "login":
            return None

        username = session.get("user")
        user = storage.get_user(db(), username) if username else None
        is_api = request.path.startswith("/api/")
        auth = request.authorization
        if user is None and is_api and auth is not None and auth.type == "basic":
            user = verify_user(db(), auth.username or "", auth.password or "")

        if user is None:
            # Also covers a session whose user has since been removed.
            session.pop("user", None)
            if is_api:
                return Response(
                    "Authentication required", 401, {"WWW-Authenticate": 'Basic realm="cert-monitor"'}
                )
            next_path = request.full_path if request.query_string else request.path
            return redirect(url_for("login", next=next_path))
        g.user = user
        return None

    @app.after_request
    def security_headers(response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.route("/login", methods=["GET", "POST"])
    def login():
        error = None
        if request.method == "POST":
            user = verify_user(
                db(), request.form.get("username", ""), request.form.get("password", "")
            )
            if user is not None:
                session.clear()
                session.permanent = True
                session["user"] = user["username"]
                return redirect(_safe_next(request.args.get("next")))
            error = "Incorrect username or password."
        return render_template("login.html", error=error), (401 if error else 200)

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.get("/")
    def index():
        rows = latest_views()
        counts = {status: 0 for status in STATUS_ORDER}
        for r in rows:
            counts[r["status"]] += 1
        return render_template(
            "index.html",
            rows=rows,
            counts=counts,
            stale=sum(r["stale"] for r in rows),
            stale_hours=stale_hours,
        )

    @app.get("/targets/<hostname>/<int:port>")
    def target(hostname, port):
        target_row = storage.get_target(db(), hostname, port)
        if target_row is None:
            abort(404)
        history = [to_view(r) for r in storage.target_history(db(), hostname, port, limit=50)]
        return render_template(
            "target.html",
            target=target_row,
            latest=history[0] if history else None,
            history=history,
            alerts=storage.target_alerts(db(), target_row["id"], limit=50),
        )

    @app.get("/api/status")
    def api_status():
        return jsonify(latest_views())

    @app.get("/api/targets/<hostname>/<int:port>")
    def api_target(hostname, port):
        if storage.get_target(db(), hostname, port) is None:
            return jsonify(error="unknown target"), 404
        history = [to_view(r) for r in storage.target_history(db(), hostname, port, limit=50)]
        return jsonify(hostname=hostname, port=port, history=history)

    return app
