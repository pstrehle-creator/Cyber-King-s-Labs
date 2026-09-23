import io
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import cert_monitor
import storage
import targets
from test_dashboard import DashboardTestCase, _csrf_from, _sign_in_as


class ParseTargetTests(unittest.TestCase):
    def test_valid_targets(self):
        cases = {
            "example.com": ("example.com", 443, "tls"),
            " Mail.Example.COM.:993 ": ("mail.example.com", 993, "tls"),
            "intranet": ("intranet", 443, "tls"),
            "_dmarc-host.corp.local:8443": ("_dmarc-host.corp.local", 8443, "tls"),
            "10.0.0.5:636": ("10.0.0.5", 636, "tls"),
            "[2001:db8::1]": ("2001:db8::1", 443, "tls"),
            "[2001:DB8::1]:8443": ("2001:db8::1", 8443, "tls"),
            "smtp://mail.example.com": ("mail.example.com", 25, "smtp"),
            "SMTP://Mail.Example.com:587": ("mail.example.com", 587, "smtp"),
            "imap://mail.example.com": ("mail.example.com", 143, "imap"),
            "pop3://mail.example.com": ("mail.example.com", 110, "pop3"),
            "smtp://[2001:db8::1]": ("2001:db8::1", 25, "smtp"),
        }
        for raw, expected in cases.items():
            self.assertEqual(targets.parse_target(raw), expected, raw)

    def test_invalid_targets(self):
        for raw in (
            "", "example.com:", "example.com:0", "example.com:70000", "example.com:https",
            "2001:db8::1", "[2001:db8::1", "[not-ipv6]:443", "[::1]x", "exa mple.com",
            "https://example.com", "tls://example.com", "smtp://", "smtp://bad host", "example.com/path", "a" * 64 + ".com", "-bad.example.com",
        ):
            with self.assertRaises(ValueError, msg=raw):
                targets.parse_target(raw)

    def test_format_target(self):
        self.assertEqual(targets.format_target("example.com", 443), "example.com:443")
        self.assertEqual(targets.format_target("2001:db8::1", 443), "[2001:db8::1]:443")
        self.assertEqual(targets.format_target("mail.example.com", 587, "smtp"), "smtp://mail.example.com:587")


class TargetsCommandTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmp.name) / "t.db")

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, *argv, stdin=""):
        out = io.StringIO()
        with mock.patch("sys.stdin", io.StringIO(stdin)), \
                mock.patch("sys.stdout", out), mock.patch("sys.stderr", out):
            code = cert_monitor.main([*argv, "--db", self.db_path])
        return code, out.getvalue()

    def _active(self):
        conn = storage.connect(self.db_path)
        try:
            return [targets.format_target(t["hostname"], t["port"]) for t in storage.active_targets(conn)]
        finally:
            conn.close()

    def test_add_list_remove_restore(self):
        code, out = self._run("targets", "add", "b.example.com", "a.example.com:8443", "--by", "alice")
        self.assertEqual(code, 0)
        self.assertIn("now monitoring a.example.com:8443", out)
        self.assertEqual(self._active(), ["a.example.com:8443", "b.example.com:443"])
        self.assertIn("already monitoring", self._run("targets", "add", "b.example.com", "--by", "alice")[1])

        code, out = self._run("targets", "remove", "b.example.com", "--by", "bob")
        self.assertEqual(code, 0)
        self.assertEqual(self._active(), ["a.example.com:8443"])
        self.assertEqual(self._run("targets", "remove", "b.example.com", "--by", "bob")[0], 2)

        _, out = self._run("targets", "list")
        self.assertNotIn("b.example.com", out)
        _, out = self._run("targets", "list", "--all")
        self.assertRegex(out, r"b\.example\.com:443\s+removed")
        self.assertRegex(out, r"a\.example\.com:8443\s+active\s+not checked")

        self.assertIn("monitoring b.example.com:443 again", self._run("targets", "add", "b.example.com", "--by", "a")[1])

    def test_invalid_target_changes_nothing(self):
        code, out = self._run("targets", "add", "good.example.com", "bad host", "--by", "alice")
        self.assertEqual(code, 2)
        self.assertIn("invalid hostname 'bad host'", out)
        self.assertEqual(self._active(), [])

    def test_import_from_stdin(self):
        code, _ = self._run(
            "targets", "import", "-", "--by", "alice",
            stdin="# comment\nexample.com\n\nmail.example.com:993\nexample.com\n",
        )
        self.assertEqual(code, 0)
        self.assertEqual(self._active(), ["example.com:443", "mail.example.com:993"])

    def test_check_without_arguments_checks_active_hosts(self):
        self._run("targets", "add", "127.0.0.1:1", "127.0.0.1:2", "--by", "alice")
        self._run("targets", "remove", "127.0.0.1:2", "--by", "alice")
        code, out = self._run("check")
        self.assertEqual(code, 2)
        self.assertIn("127.0.0.1:1", out)
        self.assertNotIn("127.0.0.1:2", out)

    def test_check_without_any_hosts_explains_what_to_do(self):
        code, out = self._run("check")
        self.assertEqual(code, 2)
        self.assertIn("targets add", out)

    def test_check_rejects_typos_before_checking_anything(self):
        code, out = self._run("check", "127.0.0.1:1", "example.com:https")
        self.assertEqual(code, 2)
        self.assertIn("invalid port 'https'", out)
        self.assertNotIn("UNREACHABLE", out)

    def test_checking_a_removed_host_explicitly_monitors_it_again(self):
        self._run("targets", "add", "127.0.0.1:1", "--by", "alice")
        self._run("targets", "remove", "127.0.0.1:1", "--by", "alice")
        self._run("check", "127.0.0.1:1")
        self.assertEqual(self._active(), ["127.0.0.1:1"])

    def test_removing_a_host_clears_its_open_alert(self):
        conn = storage.connect(self.db_path)
        storage.add_target(conn, "example.com", 443, "alice", "2026-01-01T00:00:00+00:00")
        target_id = storage.get_target(conn, "example.com", 443)["id"]
        storage.record_alert(conn, target_id, "EXPIRED", "email", "2026-01-01T00:00:00+00:00")
        storage.remove_target(conn, target_id, "alice", "2026-01-02T00:00:00+00:00")
        self.assertIsNone(storage.active_alert(conn, target_id))
        conn.close()


class TargetColumnsMigrationTests(unittest.TestCase):
    def test_existing_targets_stay_active(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = str(Path(tmp) / "phase4.db")
            legacy = sqlite3.connect(db_path)
            legacy.executescript(
                "CREATE TABLE targets (id INTEGER PRIMARY KEY, hostname TEXT NOT NULL, port INTEGER NOT NULL, "
                "created_at TEXT NOT NULL DEFAULT '', UNIQUE (hostname, port));"
                "INSERT INTO targets (hostname, port) VALUES ('example.com', 443);"
            )
            legacy.commit()
            legacy.close()
            conn = storage.connect(db_path)
            rows = storage.active_targets(conn)
            conn.close()
        self.assertEqual([(r["hostname"], r["protocol"]) for r in rows], [("example.com", "tls")])


class HostsPageTests(DashboardTestCase):
    def _post(self, path, **data):
        html = self.client.get("/hosts").get_data(as_text=True)
        return self.client.post(path, data={"csrf_token": _csrf_from(html), **data}, follow_redirects=True)

    def _target_id(self, hostname, port=443):
        conn = storage.connect(self.db_path)
        try:
            return storage.get_target(conn, hostname, port)["id"]
        finally:
            conn.close()

    def test_viewer_sees_hosts_without_controls(self):
        _sign_in_as(self.client, "victor")
        html = self.client.get("/hosts").get_data(as_text=True)
        self.assertIn("good.example:443", html)
        self.assertNotIn("Add a host", html)
        self.assertNotIn(">Remove</button>", html)
        response = self.client.post("/hosts", data={"csrf_token": _csrf_from(html), "target": "x.example"})
        self.assertEqual(response.status_code, 403)
        response = self.client.post(
            f"/hosts/{self._target_id('good.example')}/remove", data={"csrf_token": _csrf_from(html)}
        )
        self.assertEqual(response.status_code, 403)

    def test_admin_adds_host(self):
        _sign_in_as(self.client, "alice")
        html = self._post("/hosts", target="New.Example.com:8443").get_data(as_text=True)
        self.assertIn("Now monitoring new.example.com:8443", html)
        self.assertIn("Not checked yet", html)
        status = self.client.get("/").get_data(as_text=True)
        self.assertIn("1 host added but not checked yet", status)

    def test_admin_gets_a_clear_error_for_bad_input(self):
        _sign_in_as(self.client, "alice")
        html = self._post("/hosts", target="<script>x</script>").get_data(as_text=True)
        self.assertIn("Couldn&#39;t add that host", html)
        self.assertNotIn("<script>x", html)

    def test_remove_and_restore(self):
        _sign_in_as(self.client, "alice")
        target_id = self._target_id("soon.example")
        html = self._post(f"/hosts/{target_id}/remove").get_data(as_text=True)
        self.assertIn("Stopped monitoring soon.example:443", html)
        self.assertIn("Removed (1)", html)

        self.assertNotIn("soon.example", self.client.get("/").get_data(as_text=True))
        hosts = {r["hostname"] for r in self.client.get("/api/status").get_json()}
        self.assertNotIn("soon.example", hosts)
        detail = self.client.get("/targets/soon.example/443").get_data(as_text=True)
        self.assertIn("No longer monitored: removed by alice", detail)
        self.assertNotIn("Open alert", detail)

        html = self._post(f"/hosts/{target_id}/restore").get_data(as_text=True)
        self.assertIn("Monitoring soon.example:443 again", html)
        self.assertIn("soon.example", self.client.get("/").get_data(as_text=True))

    def test_host_actions_need_csrf_token(self):
        _sign_in_as(self.client, "alice")
        self.client.get("/hosts")
        self.assertEqual(self.client.post("/hosts", data={"target": "x.example"}).status_code, 400)


if __name__ == "__main__":
    unittest.main()
