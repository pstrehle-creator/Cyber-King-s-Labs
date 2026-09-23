import base64
import io
import re
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

import cert_monitor
import dashboard
import storage
from cert_monitor import CertCheckResult

PASSWORD = "correct-horse-battery"


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


def _add_user(db_path, username, role, password=PASSWORD):
    conn = storage.connect(db_path)
    storage.save_user(conn, username, dashboard.hash_password(password), role)
    conn.commit()
    conn.close()


def _sign_in_as(client, username):
    with client.session_transaction() as sess:
        sess["user"] = username


def _csrf_from(html):
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def _basic(user, password):
    return {"Authorization": "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()}


class DashboardTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmp.name) / "dash.db")
        _seed(self.db_path)
        _add_user(self.db_path, "alice", "admin")
        _add_user(self.db_path, "victor", "viewer")
        self.app = dashboard.create_app(self.db_path, stale_hours=24)
        self.client = self.app.test_client()

    def tearDown(self):
        self.tmp.cleanup()


class DashboardPageTests(DashboardTestCase):
    def setUp(self):
        super().setUp()
        _sign_in_as(self.client, "victor")

    def test_index_lists_targets_problems_first(self):
        html = self.client.get("/").get_data(as_text=True)
        order = [html.index(h) for h in ("xss.example", "soon.example", "good.example", "old.example")]
        self.assertEqual(order, sorted(order))
        self.assertIn("Expiring soon", html)
        self.assertIn("victor", html)

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
        self.assertIn("7-day expiry warning", html)
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
        self.assertIn("form-action 'self'", headers["Content-Security-Policy"])
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")

    def test_empty_database(self):
        db_path = str(Path(self.tmp.name) / "empty.db")
        _add_user(db_path, "victor", "viewer")
        client = dashboard.create_app(db_path).test_client()
        _sign_in_as(client, "victor")
        self.assertIn("No checks recorded yet", client.get("/").get_data(as_text=True))


class AuthenticationTests(DashboardTestCase):
    def _login(self, username, password, next_path=None, csrf=None):
        page = self.client.get("/login").get_data(as_text=True)
        url = "/login" + (f"?next={next_path}" if next_path else "")
        return self.client.post(
            url,
            data={"username": username, "password": password, "csrf_token": csrf or _csrf_from(page)},
        )

    def test_pages_redirect_to_login(self):
        response = self.client.get("/targets/good.example/443")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/login?next=/targets/good.example/443")

    def test_api_requires_credentials(self):
        response = self.client.get("/api/status")
        self.assertEqual(response.status_code, 401)
        self.assertIn("Basic", response.headers["WWW-Authenticate"])

    def test_stylesheet_is_public_so_login_page_renders(self):
        with self.client.get("/static/style.css") as response:
            self.assertEqual(response.status_code, 200)

    def test_login_then_browse(self):
        response = self._login("alice", PASSWORD, next_path="/targets/good.example/443")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/targets/good.example/443")
        cookie = response.headers["Set-Cookie"]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Lax", cookie)
        self.assertEqual(self.client.get("/").status_code, 200)

    def test_wrong_password_and_unknown_user_look_the_same(self):
        for username, password in (("alice", "wrong-password-123"), ("mallory", PASSWORD)):
            response = self._login(username, password)
            self.assertEqual(response.status_code, 401)
            self.assertIn("Incorrect username or password.", response.get_data(as_text=True))
        self.assertEqual(self.client.get("/").status_code, 302)

    def test_login_requires_csrf_token(self):
        self.client.get("/login")
        response = self.client.post("/login", data={"username": "alice", "password": PASSWORD})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self._login("alice", PASSWORD, csrf="forged").status_code, 400)

    def test_login_does_not_redirect_off_site(self):
        for next_path in ("//evil.example/", "/\\evil.example/", "https://evil.example/"):
            response = self._login("alice", PASSWORD, next_path=next_path)
            self.assertEqual(response.headers["Location"], "/", next_path)

    def test_removed_user_is_signed_out(self):
        _sign_in_as(self.client, "victor")
        self.assertEqual(self.client.get("/").status_code, 200)
        conn = storage.connect(self.db_path)
        storage.remove_user(conn, "victor")
        conn.commit()
        conn.close()
        self.assertEqual(self.client.get("/").status_code, 302)

    def test_sign_out(self):
        self._login("alice", PASSWORD)
        html = self.client.get("/").get_data(as_text=True)
        self.assertEqual(self.client.post("/logout").status_code, 400)
        response = self.client.post("/logout", data={"csrf_token": _csrf_from(html)})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.get("/").status_code, 302)

    def test_api_accepts_basic_auth(self):
        self.assertEqual(self.client.get("/api/status", headers=_basic("victor", PASSWORD)).status_code, 200)
        self.assertEqual(self.client.get("/api/status", headers=_basic("victor", "nope")).status_code, 401)

    def test_basic_auth_is_not_accepted_for_pages(self):
        # Browsers resend cached basic credentials on cross-site requests, so
        # pages only accept the session cookie.
        response = self.client.get("/", headers=_basic("alice", PASSWORD))
        self.assertEqual(response.status_code, 302)


class AcknowledgeTests(DashboardTestCase):
    def setUp(self):
        super().setUp()
        conn = storage.connect(self.db_path)
        self.target_id = storage.get_target(conn, "soon.example", 443)["id"]
        conn.close()

    def _page(self, user):
        _sign_in_as(self.client, user)
        return self.client.get("/targets/soon.example/443").get_data(as_text=True)

    def _ack(self, html, alert_key="EXPIRING_SOON:7", note="OPS-42"):
        return self.client.post(
            "/targets/soon.example/443/ack",
            data={"csrf_token": _csrf_from(html), "alert_key": alert_key, "note": note},
        )

    def test_admin_can_acknowledge(self):
        html = self._page("alice")
        self.assertIn("Open alert", html)
        self.assertIn(">Acknowledge</button>", html)
        response = self._ack(html)
        self.assertEqual(response.status_code, 302)
        html = self.client.get("/targets/soon.example/443").get_data(as_text=True)
        self.assertIn("Acknowledged</span>", html)
        self.assertIn("OPS-42", html)
        self.assertNotIn(">Acknowledge</button>", html)
        by_host = {r["hostname"]: r for r in self.client.get("/api/status").get_json()}
        self.assertEqual(by_host["soon.example"]["alert"]["ack"]["acked_by"], "alice")
        self.assertIsNone(by_host["good.example"]["alert"])

    def test_viewer_cannot_acknowledge(self):
        html = self._page("victor")
        self.assertIn("Open alert", html)
        self.assertNotIn(">Acknowledge</button>", html)
        self.assertEqual(self._ack(html).status_code, 403)

    def test_stale_form_is_rejected(self):
        html = self._page("alice")
        self.assertEqual(self._ack(html, alert_key="EXPIRING_SOON:14").status_code, 409)

    def test_requires_csrf_token(self):
        self._page("alice")
        response = self.client.post(
            "/targets/soon.example/443/ack", data={"alert_key": "EXPIRING_SOON:7"}
        )
        self.assertEqual(response.status_code, 400)

    def test_note_is_escaped(self):
        html = self._page("alice")
        self._ack(html, note="<img src=x onerror=alert(1)>")
        html = self.client.get("/targets/soon.example/443").get_data(as_text=True)
        self.assertNotIn("<img src=x", html)


class ServeCommandTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmp.name) / "x.db")

    def tearDown(self):
        self.tmp.cleanup()

    def test_refuses_to_start_without_accounts(self):
        with mock.patch.dict("os.environ", {}, clear=True), \
                mock.patch("cert_monitor.waitress.serve") as serve, mock.patch("sys.stderr"):
            code = cert_monitor.main(["serve", "--db", self.db_path])
        self.assertEqual(code, 2)
        serve.assert_not_called()

    def test_serves_once_an_account_exists(self):
        _add_user(self.db_path, "alice", "admin")
        with mock.patch.dict("os.environ", {}, clear=True), \
                mock.patch("cert_monitor.waitress.serve") as serve, mock.patch("sys.stdout"):
            code = cert_monitor.main(["serve", "--db", self.db_path, "--host", "0.0.0.0", "--port", "9000"])
        self.assertEqual(code, 0)
        self.assertEqual(serve.call_args.kwargs, {"host": "0.0.0.0", "port": 9000})


class UserCommandTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmp.name) / "users.db")

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, *argv, stdin=""):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch("sys.stdin", io.StringIO(stdin)), \
                mock.patch("sys.stdout", out), mock.patch("sys.stderr", err):
            code = cert_monitor.main(["user", *argv, "--db", self.db_path])
        return code, out.getvalue() + err.getvalue()

    def _user(self, username):
        conn = storage.connect(self.db_path)
        try:
            return storage.get_user(conn, username)
        finally:
            conn.close()

    def test_add_list_update_remove(self):
        code, out = self._run("add", "alice", "--role", "viewer", "--password-stdin", stdin=PASSWORD + "\n")
        self.assertEqual(code, 0)
        self.assertIn("created viewer account 'alice'", out)
        user = self._user("alice")
        self.assertNotIn(PASSWORD, user["password_hash"])
        self.assertTrue(dashboard.check_password_hash(user["password_hash"], PASSWORD))

        code, out = self._run("add", "alice", "--role", "admin", "--password-stdin", stdin="another-long-password\n")
        self.assertIn("updated admin account 'alice'", out)
        self.assertEqual(self._user("alice")["role"], "admin")

        code, out = self._run("list")
        self.assertIn("alice", out)
        self.assertIn("admin", out)

        self.assertEqual(self._run("remove", "alice")[0], 0)
        self.assertIsNone(self._user("alice"))
        self.assertEqual(self._run("remove", "alice")[0], 2)

    def test_rejects_short_password(self):
        code, out = self._run("add", "bob", "--role", "admin", "--password-stdin", stdin="short\n")
        self.assertEqual(code, 2)
        self.assertIn("at least 12 characters", out)
        self.assertIsNone(self._user("bob"))

    def test_rejects_odd_usernames(self):
        code, _ = self._run("add", "bob smith<script>", "--role", "admin", "--password-stdin", stdin=PASSWORD)
        self.assertEqual(code, 2)

    def test_prompted_passwords_must_match(self):
        with mock.patch("cert_monitor.getpass.getpass", side_effect=[PASSWORD, PASSWORD + "x"]):
            code, out = self._run("add", "bob", "--role", "admin")
        self.assertEqual(code, 2)
        self.assertIn("don't match", out)


if __name__ == "__main__":
    unittest.main()
