import io
import socket
import ssl
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

import cert_monitor
import storage
from test_cert_monitor import _make_cert, _write_pem


class _Line:
    """Line-oriented access to a socket that can be upgraded to TLS midway."""

    def __init__(self, sock):
        self.sock = sock

    def readline(self) -> bytes:
        data = b""
        while not data.endswith(b"\n"):
            chunk = self.sock.recv(1)
            if not chunk:
                break
            data += chunk
        return data

    def send(self, text: str) -> None:
        self.sock.sendall(text.encode())

    def start_tls(self, ctx) -> None:
        self.sock = ctx.wrap_socket(self.sock, server_side=True)


def _smtp(conn: _Line, ctx, offer_starttls):
    conn.send("220 fake.test ESMTP\r\n")
    while line := conn.readline():
        command = line.strip().upper()
        if command.startswith((b"EHLO", b"HELO")):
            conn.send("250-fake.test\r\n250 STARTTLS\r\n" if offer_starttls else "250 fake.test\r\n")
        elif command == b"STARTTLS":
            conn.send("220 Go ahead\r\n")
            conn.start_tls(ctx)
        elif command == b"QUIT":
            conn.send("221 Bye\r\n")
            return
        else:
            conn.send("502 Not implemented\r\n")


def _imap(conn: _Line, ctx, offer_starttls):
    conn.send("* OK fake.test IMAP4rev1 ready\r\n")
    while line := conn.readline():
        tag, _, command = line.strip().decode().partition(" ")
        command = command.upper()
        if command == "CAPABILITY":
            caps = "IMAP4rev1 STARTTLS" if offer_starttls and not isinstance(conn.sock, ssl.SSLSocket) else "IMAP4rev1"
            conn.send(f"* CAPABILITY {caps}\r\n{tag} OK done\r\n")
        elif command == "STARTTLS":
            conn.send(f"{tag} OK Begin TLS\r\n")
            conn.start_tls(ctx)
        elif command == "LOGOUT":
            conn.send(f"* BYE\r\n{tag} OK\r\n")
            return
        else:
            conn.send(f"{tag} BAD unknown\r\n")


def _pop3(conn: _Line, ctx, offer_starttls):
    conn.send("+OK fake.test POP3 ready\r\n")
    while line := conn.readline():
        command = line.strip().upper()
        if command == b"CAPA":
            conn.send("+OK\r\nUSER\r\n" + ("STLS\r\n" if offer_starttls else "") + ".\r\n")
        elif command == b"STLS":
            conn.send("+OK Begin TLS\r\n")
            conn.start_tls(ctx)
        elif command == b"QUIT":
            conn.send("+OK Bye\r\n")
            return
        else:
            conn.send("-ERR unknown\r\n")


HANDLERS = {"smtp": _smtp, "imap": _imap, "pop3": _pop3}


class FakeMailServer:
    def __init__(self, protocol, cert_path, key_path, offer_starttls=True):
        self.handler = HANDLERS[protocol]
        self.offer_starttls = offer_starttls
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
                raw, _ = self.sock.accept()
            except socket.timeout:
                continue
            raw.settimeout(5)
            conn = _Line(raw)
            try:
                self.handler(conn, self.ctx, self.offer_starttls)
            except (ssl.SSLError, OSError):
                pass
            finally:
                conn.sock.close()

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self._thread.join()
        self.sock.close()


class StartTLSTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        now = datetime.now(timezone.utc)
        cls.ca_cert, cls.ca_key = _make_cert("Test CA", now + timedelta(days=365), is_ca=True)
        cls.ca_path, _ = _write_pem(cls.tmp.name, "ca", cls.ca_cert)
        leaf, leaf_key = _make_cert("localhost", now + timedelta(days=10, hours=1), cls.ca_cert, cls.ca_key)
        cls.trusted = _write_pem(cls.tmp.name, "trusted", leaf, leaf_key)
        selfsigned, selfsigned_key = _make_cert("localhost", now + timedelta(days=90))
        cls.untrusted = _write_pem(cls.tmp.name, "untrusted", selfsigned, selfsigned_key)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def _trust_test_ca(self):
        real = ssl.create_default_context
        return mock.patch.object(
            cert_monitor.ssl, "create_default_context", lambda: real(cafile=str(self.ca_path))
        )

    def _check(self, protocol, cert=None, offer_starttls=True):
        cert_path, key_path = cert or self.trusted
        with FakeMailServer(protocol, cert_path, key_path, offer_starttls) as server, self._trust_test_ca():
            return cert_monitor.check_target("localhost", server.port, 5, 30, protocol)

    def test_reads_certificate_after_starttls(self):
        for protocol in ("smtp", "imap", "pop3"):
            with self.subTest(protocol=protocol):
                result = self._check(protocol)
                self.assertEqual(result.status, "EXPIRING_SOON")
                self.assertEqual(result.days_remaining, 10)
                self.assertTrue(result.chain_valid)
                self.assertEqual(result.issuer, "CN=Test CA")
                self.assertTrue(result.target.startswith(f"{protocol}://localhost:"))

    def test_untrusted_certificate_after_starttls(self):
        for protocol in ("smtp", "imap", "pop3"):
            with self.subTest(protocol=protocol):
                result = self._check(protocol, cert=self.untrusted)
                self.assertEqual(result.status, "INVALID_CHAIN")
                self.assertIsNotNone(result.error)

    def test_server_without_starttls_is_unreachable_with_a_clear_reason(self):
        for protocol in ("smtp", "imap", "pop3"):
            with self.subTest(protocol=protocol):
                result = self._check(protocol, offer_starttls=False)
                self.assertEqual(result.status, "UNREACHABLE")
                self.assertIn(f"{protocol.upper()} STARTTLS failed", result.error)

    def test_plain_tls_check_against_a_mail_server_fails_cleanly(self):
        cert_path, key_path = self.trusted
        with FakeMailServer("smtp", cert_path, key_path) as server:
            result = cert_monitor.check_target("localhost", server.port, 5, 30, "tls")
        self.assertEqual(result.status, "UNREACHABLE")

    def test_check_command_records_protocol(self):
        cert_path, key_path = self.trusted
        with tempfile.TemporaryDirectory() as tmp:
            db_path = str(Path(tmp) / "mail.db")
            out = io.StringIO()
            with FakeMailServer("imap", cert_path, key_path) as server, self._trust_test_ca(), \
                    mock.patch("sys.stdout", out):
                target = f"imap://localhost:{server.port}"
                self.assertEqual(cert_monitor.main(["targets", "add", target, "--by", "a", "--db", db_path]), 0)
                self.assertEqual(cert_monitor.main(["check", "--db", db_path]), 1)
            self.assertIn(target, out.getvalue())
            conn = storage.connect(db_path)
            try:
                row = storage.targets_overview(conn)[0]
            finally:
                conn.close()
        self.assertEqual((row["protocol"], row["status"]), ("imap", "EXPIRING_SOON"))

    def test_changing_a_hosts_protocol(self):
        conn = storage.connect(":memory:")
        now = "2026-01-01T00:00:00+00:00"
        self.assertEqual(storage.add_target(conn, "mail.example.com", 587, "a", now), "added")
        self.assertEqual(storage.add_target(conn, "mail.example.com", 587, "a", now, "smtp"), "updated")
        self.assertEqual(storage.add_target(conn, "mail.example.com", 587, "a", now, "smtp"), "unchanged")
        self.assertEqual(storage.get_target(conn, "mail.example.com", 587)["protocol"], "smtp")
        conn.close()


if __name__ == "__main__":
    unittest.main()
