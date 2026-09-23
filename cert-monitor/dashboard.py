"""Read-only web dashboard and JSON API over cert-monitor's SQLite history."""

from __future__ import annotations

import hmac
import json
from datetime import datetime, timedelta, timezone

from flask import Flask, Response, abort, g, jsonify, render_template, request

import storage

STATUS_ORDER = ["EXPIRED", "INVALID_CHAIN", "UNREACHABLE", "EXPIRING_SOON", "OK"]
STATUS_LABELS = {
    "EXPIRED": "Expired",
    "INVALID_CHAIN": "Invalid chain",
    "UNREACHABLE": "Unreachable",
    "EXPIRING_SOON": "Expiring soon",
    "OK": "OK",
}


def _fmt_time(value: str | None) -> str:
    if not value:
        return "—"
    return datetime.fromisoformat(value).astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def create_app(
    db_path: str, stale_hours: float = 24, username: str = "admin", password: str | None = None
) -> Flask:
    app = Flask(__name__)
    app.jinja_env.filters["fmt_time"] = _fmt_time
    app.jinja_env.filters["status_label"] = lambda s: STATUS_LABELS.get(s, s)
    stale_after = timedelta(hours=stale_hours)

    def db():
        if "db" not in g:
            g.db = storage.connect(db_path)
        return g.db

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
    def require_auth():
        if password is None:
            return None
        auth = request.authorization
        if (
            auth is not None
            and hmac.compare_digest((auth.username or "").encode(), username.encode())
            and hmac.compare_digest((auth.password or "").encode(), password.encode())
        ):
            return None
        return Response(
            "Authentication required", 401, {"WWW-Authenticate": 'Basic realm="cert-monitor"'}
        )

    @app.after_request
    def security_headers(response):
        response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

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
