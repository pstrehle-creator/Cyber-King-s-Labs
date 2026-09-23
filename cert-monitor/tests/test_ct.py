import io
import json
import tempfile
import unittest
import urllib.error
import urllib.parse
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

import cert_monitor
import ct
import storage

NOW = datetime.now(timezone.utc).replace(microsecond=0)


def _ts(days):
    # crt.sh timestamps are UTC without an offset.
    return (NOW + timedelta(days=days)).replace(tzinfo=None).isoformat()


def _row(crtsh_id, names, serial, ca_id=295815, issuer="C=US, O=Let's Encrypt, CN=R11", days_left=60):
    return {
        "issuer_ca_id": ca_id,
        "issuer_name": issuer,
        "common_name": names[0],
        "name_value": "\n".join(names),
        "id": crtsh_id,
        "entry_timestamp": _ts(days_left - 90),
        "not_before": _ts(days_left - 90),
        "not_after": _ts(days_left),
        "serial_number": serial,
        "result_count": len(names),
    }


# A precertificate and final certificate for the same issuance (same issuer
# and serial), a wildcard, and rows that shouldn't be reported.
APEX_ROWS = [
    _row(1001, ["example.com", "www.example.com"], "04aa"),
    _row(1002, ["example.com", "www.example.com"], "04aa"),
]
SUBDOMAIN_ROWS = [
    _row(1001, ["example.com", "www.example.com"], "04aa"),
    _row(1003, ["*.example.com", "example.com"], "04bb", ca_id=183267, issuer="C=US, O=DigiCert Inc, CN=DigiCert TLS RSA SHA256 2020 CA1"),
    _row(1004, ["mail.example.com"], "04cc"),
    _row(1005, ["old.example.com"], "04dd", days_left=-10),                 # expired
    _row(1006, ["notexample.com", "shop.notexample.com"], "04ee"),          # other domain
    _row(1007, ["admin@example.com"], "04ff"),                              # S/MIME email, not a hostname
    {"id": "garbage"},                                                      # malformed
]


class FakeCrtSh:
    """Stands in for urllib.request.urlopen, answering crt.sh queries and
    handing any other request (e.g. a Slack webhook) to `other`."""

    def __init__(self, responses):
        self.responses = responses
        self.queries = []
        self.other = None

    def __call__(self, request, timeout):
        if not request.full_url.startswith(ct.CRTSH_URL):
            return self.other(request, timeout=timeout)
        params = urllib.parse.parse_qs(urllib.parse.urlparse(request.full_url).query)
        self.queries.append(params)
        answer = self.responses[params["q"][0]]
        if isinstance(answer, Exception):
            raise answer
        body = answer if isinstance(answer, bytes) else json.dumps(answer).encode()

        @contextmanager
        def response():
            yield io.BytesIO(body)

        return response()


def _fake(apex=APEX_ROWS, subdomains=SUBDOMAIN_ROWS):
    return FakeCrtSh({"example.com": apex, "%.example.com": subdomains})


class ParseTests(unittest.TestCase):
    def test_parses_and_filters_rows(self):
        certs = ct.parse_entries(APEX_ROWS + SUBDOMAIN_ROWS, "example.com")
        by_serial = {c.serial_number: c for c in certs}
        self.assertEqual(set(by_serial), {"04aa", "04bb", "04cc"})
        self.assertEqual(by_serial["04aa"].names, ("example.com", "www.example.com"))
        self.assertEqual(by_serial["04aa"].crtsh_id, 1001)
        self.assertEqual(by_serial["04bb"].names, ("*.example.com", "example.com"))
        self.assertTrue(by_serial["04cc"].not_after.endswith("+00:00"))

    def test_same_serial_from_different_issuers_are_different_certs(self):
        rows = [_row(1, ["a.example.com"], "01", ca_id=1), _row(2, ["b.example.com"], "01", ca_id=2)]
        self.assertEqual(len(ct.parse_entries(rows, "example.com")), 2)

    def test_normalize_domain(self):
        self.assertEqual(ct.normalize_domain(" Example.COM. "), "example.com")
        for bad in ("", "localhost", "exa mple.com", "example.com/path", "-x.example.com", "%.example.com"):
            with self.assertRaises(ValueError, msg=bad):
                ct.normalize_domain(bad)


class FetchTests(unittest.TestCase):
    def test_queries_domain_and_subdomains(self):
        fake = _fake()
        with mock.patch("ct.urllib.request.urlopen", fake):
            certs = ct.fetch_certificates("example.com")
        self.assertEqual([q["q"][0] for q in fake.queries], ["example.com", "%.example.com"])
        self.assertTrue(all(q["output"] == ["json"] and q["exclude"] == ["expired"] for q in fake.queries))
        self.assertEqual(len(certs), 3)

    def test_any_failed_query_fails_the_lookup(self):
        failures = [
            urllib.error.HTTPError("https://crt.sh/", 502, "Bad Gateway", {}, None),
            urllib.error.URLError("timed out"),
            b"<html>crt.sh is overloaded</html>",
            {"not": "a list"},
        ]
        for failure in failures:
            with mock.patch("ct.urllib.request.urlopen", _fake(subdomains=failure)), \
                    self.assertRaises(ct.CTLookupError, msg=repr(failure)):
                ct.fetch_certificates("example.com")

    def test_rejects_oversized_response(self):
        with mock.patch("ct.MAX_RESPONSE_BYTES", 100), \
                mock.patch("ct.urllib.request.urlopen", _fake()), \
                self.assertRaises(ct.CTLookupError):
            ct.fetch_certificates("example.com")


class DiscoverCommandTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmp.name) / "ct.db")
        self.targets = Path(self.tmp.name) / "targets.txt"
        self.targets.write_text("# my hosts\nwww.example.com\nexample.com:443")

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, fake, *extra, env=None, slack=None):
        fake.other = slack
        out = io.StringIO()
        with mock.patch("ct.urllib.request.urlopen", fake), \
                mock.patch.dict("os.environ", env or {}), \
                mock.patch("sys.stdout", out), mock.patch("sys.stderr", out):
            code = cert_monitor.main(["discover", "example.com", "--db", self.db_path, *extra])
        return code, out.getvalue()

    def test_first_run_is_a_baseline_then_new_certs_are_reported(self):
        code, out = self._run(_fake(), "--targets-file", str(self.targets))
        self.assertEqual(code, 0)
        self.assertIn("first run for example.com", out)
        self.assertRegex(out, r"mail\.example\.com\s+NOT MONITORED")
        self.assertRegex(out, r"www\.example\.com\s+monitored")
        self.assertRegex(out, r"\*\.example\.com\s+wildcard")

        rogue = _row(2001, ["login.example.com"], "05ab", issuer="C=XX, O=Sketchy CA, CN=Sketchy")
        code, out = self._run(_fake(subdomains=SUBDOMAIN_ROWS + [rogue]))
        self.assertEqual(code, 1)
        self.assertIn("1 certificate(s) issued since the last run", out)
        self.assertIn("login.example.com", out)
        self.assertIn("https://crt.sh/?id=2001", out)

        code, out = self._run(_fake(subdomains=SUBDOMAIN_ROWS + [rogue]))
        self.assertEqual(code, 0)

    def test_notifies_each_new_cert_once_and_retries_failures(self):
        self._run(_fake())
        rogue = _row(2001, ["login.example.com"], "05ab", issuer="<!channel> Sketchy CA")
        fake = _fake(subdomains=SUBDOMAIN_ROWS + [rogue])
        env = {"SLACK_WEBHOOK_URL": "https://hooks.slack.com/services/T/B/X"}

        failing = mock.Mock(side_effect=urllib.error.URLError("down"))
        self._run(fake, "--slack", env=env, slack=failing)
        self.assertEqual(failing.call_count, 1)
        slack = mock.MagicMock()
        self._run(fake, "--slack", env=env, slack=slack)
        self._run(fake, "--slack", env=env, slack=slack)
        self.assertEqual(slack.call_count, 1)
        text = json.loads(slack.call_args.args[0].data)["text"]
        self.assertIn("1 new certificate(s) issued for your domains", text)
        self.assertIn("login.example.com", text)
        self.assertNotIn("<!channel>", text)

    def test_baseline_certs_are_never_notified(self):
        slack = mock.MagicMock()
        self._run(_fake(), "--slack", env={"SLACK_WEBHOOK_URL": "https://hooks.slack.com/x"}, slack=slack)
        slack.assert_not_called()

    def test_add_appends_unmonitored_hostnames(self):
        code, out = self._run(_fake(), "--targets-file", str(self.targets), "--add")
        self.assertEqual(code, 0)
        lines = self.targets.read_text().splitlines()
        self.assertEqual(lines[:3], ["# my hosts", "www.example.com", "example.com:443"])
        self.assertTrue(lines[3].startswith("# added by 'discover'"))
        self.assertEqual(lines[4:], ["mail.example.com"])

    def test_add_without_targets_file_monitors_in_database(self):
        conn = storage.connect(self.db_path)
        storage.add_target(conn, "www.example.com", 443, "alice", "2026-01-01T00:00:00+00:00")
        conn.commit()
        conn.close()

        code, out = self._run(_fake(), "--add")
        self.assertEqual(code, 0)
        conn = storage.connect(self.db_path)
        try:
            hosts = sorted(t["hostname"] for t in storage.active_targets(conn))
            added = storage.get_target(conn, "mail.example.com", 443)
        finally:
            conn.close()
        self.assertEqual(hosts, ["example.com", "mail.example.com", "www.example.com"])
        self.assertEqual(added["changed_by"], "discover")

    def test_failed_lookup_records_nothing(self):
        code, out = self._run(_fake(subdomains=urllib.error.URLError("timed out")))
        self.assertEqual(code, 2)
        self.assertIn("crt.sh lookup for '%.example.com' failed", out)
        conn = storage.connect(self.db_path)
        try:
            self.assertIsNone(storage.ct_domain(conn, "example.com"))
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
