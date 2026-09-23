#!/usr/bin/env python3
"""
cert_monitor.py - Phase 1 CLI for the TLS/SSL certificate monitoring app.

Checks a list of host[:port] targets, reports days remaining until each
certificate expires, and (optionally) emails admins when any target is
expiring soon, expired, unreachable, or failing chain validation.

Usage:
    python cert_monitor.py example.com github.com:443
    python cert_monitor.py --targets-file targets.txt --threshold 14 --email
"""

from __future__ import annotations

import argparse
import json
import os
import smtplib
import socket
import ssl
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path

from cryptography import x509

DEFAULT_PORT = 443
DEFAULT_THRESHOLD_DAYS = 30
DEFAULT_TIMEOUT = 5.0

ALERT_STATUSES = {"EXPIRED", "EXPIRING_SOON", "UNREACHABLE", "INVALID_CHAIN"}
FAILURE_STATUSES = {"EXPIRED", "UNREACHABLE", "INVALID_CHAIN"}


@dataclass
class CertCheckResult:
    hostname: str
    port: int
    status: str
    days_remaining: int | None = None
    not_before: str | None = None
    not_after: str | None = None
    issuer: str | None = None
    subject: str | None = None
    san: list[str] = field(default_factory=list)
    serial_number: str | None = None
    chain_valid: bool = True
    error: str | None = None

    @property
    def target(self) -> str:
        return f"{self.hostname}:{self.port}"


def parse_targets_file(path: Path) -> list[str]:
    targets = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        targets.append(line)
    return targets


def split_target(raw: str) -> tuple[str, int]:
    if ":" in raw:
        host, _, port_str = raw.rpartition(":")
        try:
            return host, int(port_str)
        except ValueError:
            return raw, DEFAULT_PORT
    return raw, DEFAULT_PORT


def _fetch_cert_der(hostname: str, port: int, timeout: float) -> bytes:
    """Open a TLS connection without verifying the chain, purely to retrieve
    the peer's certificate bytes for parsing. Chain trust is checked
    separately in _check_chain_valid()."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
            return tls_sock.getpeercert(binary_form=True)


def _check_chain_valid(hostname: str, port: int, timeout: float) -> tuple[bool, str | None]:
    """Attempt a fully verified handshake (hostname + trust chain) and report
    whether it succeeds."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname):
                return True, None
    except ssl.SSLCertVerificationError as exc:
        return False, str(exc)


def _cert_not_after_utc(cert: x509.Certificate) -> datetime:
    return getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(
        tzinfo=timezone.utc
    )


def _cert_not_before_utc(cert: x509.Certificate) -> datetime:
    return getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(
        tzinfo=timezone.utc
    )


def _san_dns_names(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        return []


def check_target(hostname: str, port: int, timeout: float, threshold: int) -> CertCheckResult:
    try:
        der = _fetch_cert_der(hostname, port, timeout)
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as exc:
        return CertCheckResult(hostname=hostname, port=port, status="UNREACHABLE", error=str(exc))

    if der is None:
        return CertCheckResult(
            hostname=hostname, port=port, status="UNREACHABLE", error="peer presented no certificate"
        )

    chain_valid, chain_error = _check_chain_valid(hostname, port, timeout)

    cert = x509.load_der_x509_certificate(der)
    not_after = _cert_not_after_utc(cert)
    not_before = _cert_not_before_utc(cert)
    days_remaining = (not_after - datetime.now(timezone.utc)).days

    if not chain_valid:
        status = "INVALID_CHAIN"
    elif days_remaining < 0:
        status = "EXPIRED"
    elif days_remaining <= threshold:
        status = "EXPIRING_SOON"
    else:
        status = "OK"

    return CertCheckResult(
        hostname=hostname,
        port=port,
        status=status,
        days_remaining=days_remaining,
        not_before=not_before.isoformat(),
        not_after=not_after.isoformat(),
        issuer=cert.issuer.rfc4514_string(),
        subject=cert.subject.rfc4514_string(),
        san=_san_dns_names(cert),
        serial_number=format(cert.serial_number, "x"),
        chain_valid=chain_valid,
        error=chain_error,
    )


def print_table(results: list[CertCheckResult]) -> None:
    header = f"{'TARGET':<32} {'STATUS':<15} {'DAYS':>6}  {'NOT AFTER':<26} ISSUER"
    print(header)
    print("-" * len(header))
    for r in sorted(results, key=lambda r: (r.days_remaining is None, r.days_remaining)):
        days = "?" if r.days_remaining is None else str(r.days_remaining)
        not_after = r.not_after or "-"
        issuer = r.issuer or (r.error or "-")
        print(f"{r.target:<32} {r.status:<15} {days:>6}  {not_after:<26} {issuer}")


def send_alert_email(results: list[CertCheckResult]) -> None:
    smtp_host = os.environ.get("SMTP_HOST")
    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    smtp_user = os.environ.get("SMTP_USER")
    smtp_password = os.environ.get("SMTP_PASSWORD")
    from_addr = os.environ.get("ALERT_FROM_EMAIL")
    to_addrs = [a.strip() for a in os.environ.get("ALERT_TO_EMAILS", "").split(",") if a.strip()]

    missing = [
        name
        for name, val in [
            ("SMTP_HOST", smtp_host),
            ("ALERT_FROM_EMAIL", from_addr),
            ("ALERT_TO_EMAILS", to_addrs),
        ]
        if not val
    ]
    if missing:
        print(f"[warn] skipping email alert, missing env vars: {', '.join(missing)}", file=sys.stderr)
        return

    lines = [f"{r.target}: {r.status} (days_remaining={r.days_remaining}, error={r.error})" for r in results]
    body = "The following certificates need attention:\n\n" + "\n".join(lines)

    msg = EmailMessage()
    msg["Subject"] = f"[cert-monitor] {len(results)} certificate(s) need attention"
    msg["From"] = from_addr
    msg["To"] = ", ".join(to_addrs)
    msg.set_content(body)

    with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
        server.starttls()
        if smtp_user and smtp_password:
            server.login(smtp_user, smtp_password)
        server.send_message(msg)
    print(f"[info] alert email sent to {', '.join(to_addrs)}")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Check TLS certificate expiry for a list of targets.")
    parser.add_argument("targets", nargs="*", help="host or host:port targets to check")
    parser.add_argument("--targets-file", type=Path, help="file with one host[:port] per line")
    parser.add_argument(
        "--threshold", type=int, default=DEFAULT_THRESHOLD_DAYS,
        help="days remaining considered 'expiring soon' (default: 30)",
    )
    parser.add_argument(
        "--timeout", type=float, default=DEFAULT_TIMEOUT,
        help="connection timeout in seconds (default: 5)",
    )
    parser.add_argument("--email", action="store_true", help="send an email alert if any target needs attention")
    parser.add_argument("--json-out", type=Path, help="write full results as JSON to this path")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    raw_targets = list(args.targets)
    if args.targets_file:
        raw_targets.extend(parse_targets_file(args.targets_file))

    if not raw_targets:
        parser.error("no targets given (pass targets as arguments or via --targets-file)")

    results = [
        check_target(*split_target(raw), timeout=args.timeout, threshold=args.threshold)
        for raw in raw_targets
    ]

    print_table(results)

    if args.json_out:
        args.json_out.write_text(json.dumps([asdict(r) for r in results], indent=2))
        print(f"[info] wrote results to {args.json_out}")

    needs_attention = [r for r in results if r.status in ALERT_STATUSES]
    if needs_attention and args.email:
        send_alert_email(needs_attention)

    if any(r.status in FAILURE_STATUSES for r in results):
        return 2
    if any(r.status == "EXPIRING_SOON" for r in results):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
