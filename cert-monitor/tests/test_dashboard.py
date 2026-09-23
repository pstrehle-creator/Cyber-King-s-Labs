import base64
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

import cert_monitor
import dashboard
import storage
from cert_monitor import CertCheckResult


def _iso(delta=timedelta()):
    return (datetime.now(timezone.utc) + delta).isoformat(timespec="seconds")


def _seed(db_path):
    conn = storage.connect(db_path)
    records = [
        CertCheckResult(
            hostname="good.example", port=443, status="OK", days_remaining=80,
            not_after=_iso(timedelta(days=80)), issuer="CN=Good CA", serial_number="aa01",
        ),
        CertCheckResult(
            hostname="soon.example", port=443, status="EXPIRING_SOON", days_remaining=6,
            not_after=_iso(timedelta(days=6)), issuer="CN=Good CA", serial_number="bb02",
        ),
        CertCheckResult(
            hostname="xss.example", port=8443, status="INVALID_CHAIN", days_remaining=40,
            not_after=_iso(timedelta(days=40)), serial_number="cc03", chain_valid=False,
            issuer="CN=<script>alert(1)</script>", error="self-signed <script>alert(2)</script>",
        ),
        CertCheckResult(
            hostname="old.example", port=443, status="OK", days_remaining=200,
            not_after=_iso(timedelta(days=200)), serial_number="dd04",
            checked_at=_iso(-timedelta(hours=48)),
        ),
    ]
    for r in records:
        target_id = storage.upsert_target(conn, r.hostname, r.port)
        storage.record_check(conn, target_id, r)
    storage.record_alert(
        conn, storage.upsert_target(conn, "soon.example", 443), "EXPIRING_SOON:7", "slack", _iso()
    )
    conn.commit()
    conn.close()


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmp.name) / "dash.db")
        _seed(self.db_path)
        self.client = dashboard.create_app(self.db_path, stale_hours=24).test_client()

    def tearDown(self):
        self.tmp.cleanup()

    def test_index_lists_targets_problems_first(self):
        html = self.client.get("/").get_data(as_text=True)
        order = [html.index(h) for h in ("xss.example", "soon.example", "good.example", "old.example")]
        self.assertEqual(order, sorted(order))
        self.assertIn("Expiring soon", html)

    def test_index_flags_stale_targets(self):
        html = self.client.get("/").get_data(as_text=True)
        self.assertIn("1 target not checked in over 24 hours", html)
        self.assertEqual(html.count('class="badge stale"'), 1)

    def test_remote_cert_fields_are_html_escaped(self):
        for path in ("/", "/targets/xss.example/8443"):
            html = self.client.get(path).get_data(as_text=True)
            self.assertNotIn("<script>", html)
            self.assertIn("&lt;script&gt;", html)

    def test_target_page_shows_history_and_alerts(self):
        html = self.client.get("/targets/soon.example/443").get_data(as_text=True)
        self.assertIn("bb02", html)
        self.assertIn("EXPIRING_SOON:7", html)
        self.assertIn("slack", html)

    def test_unknown_target_is_404(self):
        self.assertEqual(self.client.get("/targets/nope.example/443").status_code, 404)
        self.assertEqual(self.client.get("/api/targets/nope.example/443").status_code, 404)

    def test_api_status(self):
        data = self.client.get("/api/status").get_json()
        by_host = {r["hostname"]: r for r in data}
        self.assertEqual(set(by_host), {"good.example", "soon.example", "xss.example", "old.example"})
        self.assertFalse(by_host["xss.example"]["chain_valid"])
        self.assertTrue(by_host["old.example"]["stale"])
        self.assertEqual(by_host["good.example"]["san"], [])

    def test_api_target_history(self):
        data = self.client.get("/api/targets/good.example/443").get_json()
        self.assertEqual(data["port"], 443)
        self.assertEqual(len(data["history"]), 1)

    def test_security_headers(self):
        headers = self.client.get("/").headers
        self.assertIn("default-src 'self'", headers["Content-Security-Policy"])
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")

    def test_empty_database(self):
        client = dashboard.create_app(str(Path(self.tmp.name) / "empty.db")).test_client()
        self.assertIn("No checks recorded yet", client.get("/").get_data(as_text=True))


class DashboardAuthTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        db_path = str(Path(self.tmp.name) / "dash.db")
        _seed(db_path)
        self.client = dashboard.create_app(db_path, username="admin", password="s3cret").test_client()

    def tearDown(self):
        self.tmp.cleanup()

    def _auth(self, user, password):
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        return {"Authorization": f"Basic {token}"}

    def test_requires_credentials(self):
        for path in ("/", "/api/status", "/static/style.css"):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 401)
            self.assertIn("Basic", response.headers["WWW-Authenticate"])

    def test_rejects_wrong_password(self):
        self.assertEqual(self.client.get("/", headers=self._auth("admin", "nope")).status_code, 401)

    def test_accepts_correct_credentials(self):
        self.assertEqual(self.client.get("/", headers=self._auth("admin", "s3cret")).status_code, 200)


class ServeCommandTests(unittest.TestCase):
    def test_refuses_public_bind_without_password(self):
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.dict("os.environ", {}, clear=True), \
                mock.patch("dashboard.Flask.run") as run, mock.patch("sys.stderr"):
            code = cert_monitor.main(["serve", "--db", str(Path(tmp) / "x.db"), "--host", "0.0.0.0"])
        self.assertEqual(code, 2)
        run.assert_not_called()

    def test_serves_on_loopback_without_password(self):
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.dict("os.environ", {}, clear=True), \
                mock.patch("dashboard.Flask.run") as run:
            code = cert_monitor.main(["serve", "--db", str(Path(tmp) / "x.db")])
        self.assertEqual(code, 0)
        run.assert_called_once_with(host="127.0.0.1", port=8080)


if __name__ == "__main__":
    unittest.main()
