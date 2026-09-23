import json
import socket
import sqlite3
import ssl
import tempfile
import threading
import unittest
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import cert_monitor
import storage
from cert_monitor import CertCheckResult

TIERS = [30, 14, 7, 3, 1]


def _make_cert(common_name, not_after, issuer_cert=None, issuer_key=None, is_ca=False):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer_cert.subject if issuer_cert else name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(min(now, not_after) - timedelta(days=30))
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
    )
    if is_ca:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False, data_encipherment=False,
                key_agreement=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
    else:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False
        )
    cert = builder.sign(issuer_key or key, hashes.SHA256())
    return cert, key


def _write_pem(directory, name, cert, key=None):
    cert_path = Path(directory) / f"{name}.crt"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path = None
    if key is not None:
        key_path = Path(directory) / f"{name}.key"
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    return cert_path, key_path


class LocalTLSServer:
    """Serves a given certificate on 127.0.0.1 until stopped."""

    def __init__(self, cert_path, key_path):
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(cert_path, key_path)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen()
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            try:
                with self.ctx.wrap_socket(conn, server_side=True):
                    pass
            except (ssl.SSLError, OSError):
                pass

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self._thread.join()
        self.sock.close()


class CheckTargetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        now = datetime.now(timezone.utc)
        cls.ca_cert, cls.ca_key = _make_cert("Test CA", now + timedelta(days=365), is_ca=True)
        cls.ca_path, _ = _write_pem(cls.tmp.name, "ca", cls.ca_cert)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def _serve(self, name, days_valid, signed_by_ca):
        not_after = datetime.now(timezone.utc) + timedelta(days=days_valid, hours=1)
        if signed_by_ca:
            cert, key = _make_cert("localhost", not_after, self.ca_cert, self.ca_key)
        else:
            cert, key = _make_cert("localhost", not_after)
        cert_path, key_path = _write_pem(self.tmp.name, name, cert, key)
        return LocalTLSServer(cert_path, key_path)

    def _trust_test_ca(self):
        real = ssl.create_default_context
        return mock.patch.object(
            cert_monitor.ssl, "create_default_context",
            lambda: real(cafile=str(self.ca_path)),
        )

    def test_trusted_long_lived_cert_is_ok(self):
        with self._serve("ok", 90, signed_by_ca=True) as srv, self._trust_test_ca():
            result = cert_monitor.check_target("localhost", srv.port, timeout=2, threshold=30)
        self.assertEqual(result.status, "OK")
        self.assertTrue(result.chain_valid)
        self.assertEqual(result.days_remaining, 90)
        self.assertEqual(result.san, ["localhost"])
        self.assertEqual(result.issuer, "CN=Test CA")

    def test_trusted_cert_near_expiry_is_expiring_soon(self):
        with self._serve("soon", 10, signed_by_ca=True) as srv, self._trust_test_ca():
            result = cert_monitor.check_target("localhost", srv.port, timeout=2, threshold=30)
        self.assertEqual(result.status, "EXPIRING_SOON")
        self.assertEqual(result.days_remaining, 10)

    def test_expired_cert_is_expired_not_invalid_chain(self):
        with self._serve("expired", -5, signed_by_ca=True) as srv, self._trust_test_ca():
            result = cert_monitor.check_target("localhost", srv.port, timeout=2, threshold=30)
        self.assertEqual(result.status, "EXPIRED")
        self.assertLess(result.days_remaining, 0)

    def test_untrusted_cert_is_invalid_chain(self):
        with self._serve("selfsigned", 90, signed_by_ca=False) as srv, self._trust_test_ca():
            result = cert_monitor.check_target("localhost", srv.port, timeout=2, threshold=30)
        self.assertEqual(result.status, "INVALID_CHAIN")
        self.assertFalse(result.chain_valid)
        self.assertIsNotNone(result.error)

    def test_closed_port_is_unreachable(self):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        result = cert_monitor.check_target("127.0.0.1", port, timeout=2, threshold=30)
        self.assertEqual(result.status, "UNREACHABLE")

    def test_check_command_records_history(self):
        db_path = str(Path(self.tmp.name) / "history.db")
        with self._serve("hist", 90, signed_by_ca=True) as srv, self._trust_test_ca():
            target = f"localhost:{srv.port}"
            with mock.patch("sys.stdout"):
                self.assertEqual(cert_monitor.main(["check", "--db", db_path, target]), 0)
                self.assertEqual(cert_monitor.main(["check", "--db", db_path, target]), 0)
        conn = storage.connect(db_path)
        try:
            rows = storage.target_history(conn, "localhost", srv.port, limit=10)
        finally:
            conn.close()
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(r["status"] == "OK" for r in rows))


class AlertKeyTests(unittest.TestCase):
    def _result(self, status, days=None):
        return CertCheckResult(hostname="example.com", port=443, status=status, days_remaining=days)

    def test_ok_has_no_alert(self):
        self.assertIsNone(cert_monitor.alert_key(self._result("OK", 90), TIERS))

    def test_expiring_soon_maps_to_smallest_matching_tier(self):
        self.assertEqual(cert_monitor.alert_key(self._result("EXPIRING_SOON", 30), TIERS), "EXPIRING_SOON:30")
        self.assertEqual(cert_monitor.alert_key(self._result("EXPIRING_SOON", 10), TIERS), "EXPIRING_SOON:14")
        self.assertEqual(cert_monitor.alert_key(self._result("EXPIRING_SOON", 0), TIERS), "EXPIRING_SOON:1")

    def test_other_problems_use_status(self):
        for status in ("EXPIRED", "UNREACHABLE", "INVALID_CHAIN"):
            self.assertEqual(cert_monitor.alert_key(self._result(status), TIERS), status)


class AlertDedupeTests(unittest.TestCase):
    def setUp(self):
        self.conn = storage.connect(":memory:")
        self.target_id = storage.upsert_target(self.conn, "example.com", 443)

    def tearDown(self):
        self.conn.close()

    def _find(self, status, days=None, channels=("email",)):
        result = CertCheckResult(hostname="example.com", port=443, status=status, days_remaining=days)
        return cert_monitor.find_new_alerts(self.conn, [(self.target_id, result)], TIERS, list(channels))

    def _run(self, status, days=None):
        alerts = self._find(status, days)["email"]
        for target_id, _, key in alerts:
            storage.record_alert(self.conn, target_id, key, "email", "2026-01-01T00:00:00+00:00")
        return [key for _, _, key in alerts]

    def test_alerts_once_per_tier(self):
        self.assertEqual(self._run("EXPIRING_SOON", 25), ["EXPIRING_SOON:30"])
        self.assertEqual(self._run("EXPIRING_SOON", 24), [])
        self.assertEqual(self._run("EXPIRING_SOON", 13), ["EXPIRING_SOON:14"])
        self.assertEqual(self._run("EXPIRED", -1), ["EXPIRED"])
        self.assertEqual(self._run("EXPIRED", -2), [])

    def test_recovery_resets_alert_state(self):
        self.assertEqual(self._run("UNREACHABLE"), ["UNREACHABLE"])
        self.assertEqual(self._run("UNREACHABLE"), [])
        self.assertEqual(self._run("OK", 90), [])
        self.assertEqual(self._run("UNREACHABLE"), ["UNREACHABLE"])

    def test_unsent_alert_is_retried(self):
        self.assertEqual(len(self._find("EXPIRED", -1)["email"]), 1)
        self.assertEqual(len(self._find("EXPIRED", -1)["email"]), 1)

    def test_channels_are_tracked_independently(self):
        both = ("email", "slack")
        first = self._find("EXPIRED", -1, both)
        self.assertEqual((len(first["email"]), len(first["slack"])), (1, 1))
        # Email delivered, Slack failed: only Slack should be retried.
        storage.record_alert(self.conn, self.target_id, "EXPIRED", "email", "2026-01-01T00:00:00+00:00")
        second = self._find("EXPIRED", -1, both)
        self.assertEqual((len(second["email"]), len(second["slack"])), (0, 1))

    def test_recovery_clears_state_even_with_no_channels_enabled(self):
        self._run("EXPIRED", -1)
        self._find("OK", 90, channels=())
        self.assertEqual(storage.get_alert_state(self.conn, self.target_id), {})


class Phase2MigrationTests(unittest.TestCase):
    def test_email_alert_state_is_carried_over(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = str(Path(tmp) / "phase2.db")
            legacy = sqlite3.connect(db_path)
            legacy.execute(
                "CREATE TABLE targets (id INTEGER PRIMARY KEY, hostname TEXT NOT NULL, port INTEGER NOT NULL, "
                "created_at TEXT NOT NULL DEFAULT '', last_alert_key TEXT, UNIQUE (hostname, port))"
            )
            legacy.execute(
                "INSERT INTO targets (hostname, port, last_alert_key) VALUES ('example.com', 443, 'EXPIRING_SOON:14')"
            )
            legacy.commit()
            legacy.close()

            conn = storage.connect(db_path)
            target_id = storage.upsert_target(conn, "example.com", 443)
            self.assertEqual(storage.get_alert_state(conn, target_id), {"email": "EXPIRING_SOON:14"})
            # A later recovery must not be undone by re-running the migration.
            storage.clear_alert_state(conn, target_id)
            conn.commit()
            conn.close()
            conn = storage.connect(db_path)
            self.assertEqual(storage.get_alert_state(conn, target_id), {})
            conn.close()


class SlackTests(unittest.TestCase):
    ALERT = (
        CertCheckResult(
            hostname="evil.example", port=443, status="INVALID_CHAIN",
            error="bad cert <!channel> <https://phish.example|click here> & more",
        ),
        "INVALID_CHAIN",
    )

    def test_posts_escaped_text_to_webhook(self):
        with mock.patch.dict("os.environ", {"SLACK_WEBHOOK_URL": "https://hooks.slack.com/services/T/B/X"}), \
                mock.patch("cert_monitor.urllib.request.urlopen") as urlopen, mock.patch("sys.stdout"):
            self.assertTrue(cert_monitor.send_alert_slack([self.ALERT]))
        request = urlopen.call_args.args[0]
        self.assertEqual(request.full_url, "https://hooks.slack.com/services/T/B/X")
        text = json.loads(request.data)["text"]
        self.assertIn("evil.example:443: INVALID_CHAIN", text)
        self.assertNotIn("<!channel>", text)
        self.assertNotIn("<https://", text)
        self.assertIn("&lt;!channel&gt;", text)
        self.assertIn("&amp; more", text)

    def test_failed_post_returns_false(self):
        with mock.patch.dict("os.environ", {"SLACK_WEBHOOK_URL": "https://hooks.slack.com/services/T/B/X"}), \
                mock.patch("cert_monitor.urllib.request.urlopen", side_effect=urllib.error.URLError("down")), \
                mock.patch("sys.stderr"):
            self.assertFalse(cert_monitor.send_alert_slack([self.ALERT]))

    def test_rejects_missing_or_non_https_url(self):
        for env in ({}, {"SLACK_WEBHOOK_URL": "http://hooks.slack.com/x"}):
            with mock.patch.dict("os.environ", env, clear=True), \
                    mock.patch("cert_monitor.urllib.request.urlopen") as urlopen, mock.patch("sys.stderr"):
                self.assertFalse(cert_monitor.send_alert_slack([self.ALERT]))
            urlopen.assert_not_called()


if __name__ == "__main__":
    unittest.main()
