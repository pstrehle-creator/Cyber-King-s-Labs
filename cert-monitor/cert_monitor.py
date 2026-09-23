#!/usr/bin/env python3
"""
cert_monitor.py - CLI for the TLS/SSL certificate monitoring app.

Checks a list of host[:port] targets, records every result in SQLite, and
(optionally) alerts admins by email and/or Slack when a target newly needs
attention: it crosses an expiry tier, expires, becomes unreachable, or fails
chain validation. Also serves a read-only web dashboard over the history.

Usage:
    python cert_monitor.py check example.com github.com:443
    python cert_monitor.py check --targets-file targets.txt --email --slack
    python cert_monitor.py history
    python cert_monitor.py history example.com --limit 10
    python cert_monitor.py serve
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import smtplib
import socket
import sqlite3
import ssl
import sys
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path

from cryptography import x509

import dashboard
import storage

DEFAULT_PORT = 443
DEFAULT_THRESHOLD_DAYS = 30
DEFAULT_ALERT_TIERS = [30, 14, 7, 3, 1]
DEFAULT_TIMEOUT = 5.0
DEFAULT_DB_PATH = "cert_monitor.db"

FAILURE_STATUSES = {"EXPIRED", "UNREACHABLE", "INVALID_CHAIN"}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


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
    checked_at: str = field(default_factory=_utc_now_iso)

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
    """Retrieve the peer certificate without verifying it, so expired or
    untrusted certs can still be parsed. Trust is checked in _check_chain_valid()."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
            return tls_sock.getpeercert(binary_form=True)


def _check_chain_valid(hostname: str, port: int, timeout: float) -> tuple[bool, str | None]:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname):
                return True, None
    except ssl.SSLCertVerificationError as exc:
        return False, exc.verify_message or str(exc)


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
        chain_valid, chain_error = _check_chain_valid(hostname, port, timeout)
    except OSError as exc:
        return CertCheckResult(hostname=hostname, port=port, status="UNREACHABLE", error=str(exc))

    if der is None:
        return CertCheckResult(
            hostname=hostname, port=port, status="UNREACHABLE", error="peer presented no certificate"
        )

    cert = x509.load_der_x509_certificate(der)
    not_after = _cert_not_after_utc(cert)
    not_before = _cert_not_before_utc(cert)
    days_remaining = (not_after - datetime.now(timezone.utc)).days

    # Expired certs also fail chain verification, so check expiry first.
    if days_remaining < 0:
        status = "EXPIRED"
    elif not chain_valid:
        status = "INVALID_CHAIN"
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


def alert_key(result: CertCheckResult, tiers: list[int]) -> str | None:
    """Identify the alert state a result is in. An admin is emailed once each
    time a target's key changes, not on every run."""
    if result.status == "OK":
        return None
    if result.status == "EXPIRING_SOON":
        tier = min((t for t in tiers if result.days_remaining <= t), default=None)
        return f"EXPIRING_SOON:{tier}" if tier is not None else "EXPIRING_SOON"
    return result.status


def find_new_alerts(
    conn: sqlite3.Connection,
    checked: list[tuple[int, CertCheckResult]],
    tiers: list[int],
    channels: list[str],
) -> dict[str, list[tuple[int, CertCheckResult, str]]]:
    """Per channel, the alerts not yet delivered on that channel. Channels are
    tracked separately so a failed send is retried only where it failed."""
    new_alerts = {channel: [] for channel in channels}
    for target_id, result in checked:
        key = alert_key(result, tiers)
        if key is None:
            # Recovered (e.g. renewed): reset so the next problem alerts again.
            storage.clear_alert_state(conn, target_id)
            continue
        state = storage.get_alert_state(conn, target_id)
        for channel in channels:
            if state.get(channel) != key:
                new_alerts[channel].append((target_id, result, key))
    return new_alerts


def print_table(rows: list[dict], show_time: bool = False) -> None:
    targets = [f"{r['hostname']}:{r['port']}" for r in rows]
    width = max([len("TARGET"), *map(len, targets)])
    time_col = f"{'CHECKED AT':<26} " if show_time else ""
    header = f"{time_col}{'TARGET':<{width}} {'STATUS':<15} {'DAYS':>6}  {'NOT AFTER':<26} ISSUER / ERROR"
    print(header)
    print("-" * len(header))
    for target, r in zip(targets, rows):
        time_val = f"{r['checked_at']:<26} " if show_time else ""
        days = "?" if r["days_remaining"] is None else str(r["days_remaining"])
        detail = r["error"] if r["status"] != "OK" and r["error"] else (r["issuer"] or "-")
        print(
            f"{time_val}{target:<{width}} {r['status']:<15} {days:>6}  "
            f"{r['not_after'] or '-':<26} {detail}"
        )


def format_alert_lines(alerts: list[tuple[CertCheckResult, str]]) -> list[str]:
    lines = []
    for r, key in alerts:
        line = f"- {r.target}: {key}"
        if r.days_remaining is not None:
            line += f" ({r.days_remaining} days remaining, expires {r.not_after})"
        if r.error:
            line += f"\n    {r.error}"
        lines.append(line)
    return lines


def _slack_escape(text: str) -> str:
    # Cert fields and errors come from remote servers; unescaped, a crafted
    # value like "<!channel>" would ping the whole channel or inject a link.
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def send_alert_slack(alerts: list[tuple[CertCheckResult, str]]) -> bool:
    url = os.environ.get("SLACK_WEBHOOK_URL")
    if not url:
        print("[warn] skipping Slack alert, missing env var: SLACK_WEBHOOK_URL", file=sys.stderr)
        return False
    if not url.startswith("https://"):
        print("[warn] skipping Slack alert, SLACK_WEBHOOK_URL must be an https:// URL", file=sys.stderr)
        return False

    text = f"*cert-monitor: {len(alerts)} certificate(s) need attention*\n" + _slack_escape(
        "\n".join(format_alert_lines(alerts))
    )
    request = urllib.request.Request(
        url,
        data=json.dumps({"text": text}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            response.read()
    except (urllib.error.URLError, OSError) as exc:
        print(f"[error] failed to send Slack alert, will retry next run: {exc}", file=sys.stderr)
        return False

    print("[info] Slack alert sent")
    return True


def send_alert_email(alerts: list[tuple[CertCheckResult, str]]) -> bool:
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
        return False

    body = "The following certificates need attention:\n\n" + "\n".join(format_alert_lines(alerts))

    msg = EmailMessage()
    msg["Subject"] = f"[cert-monitor] {len(alerts)} certificate(s) need attention"
    msg["From"] = from_addr
    msg["To"] = ", ".join(to_addrs)
    msg.set_content(body)

    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
            server.starttls()
            if smtp_user and smtp_password:
                server.login(smtp_user, smtp_password)
            server.send_message(msg)
    except (smtplib.SMTPException, OSError) as exc:
        print(f"[error] failed to send alert email, will retry next run: {exc}", file=sys.stderr)
        return False

    print(f"[info] alert email sent to {', '.join(to_addrs)}")
    return True


NOTIFIERS = {"email": send_alert_email, "slack": send_alert_slack}


def cmd_check(args: argparse.Namespace, conn: sqlite3.Connection) -> int:
    raw_targets = list(args.targets)
    if args.targets_file:
        raw_targets.extend(parse_targets_file(args.targets_file))
    if not raw_targets:
        args.parser.error("no targets given (pass targets as arguments or via --targets-file)")

    checked = []
    for raw in raw_targets:
        hostname, port = split_target(raw)
        result = check_target(hostname, port, timeout=args.timeout, threshold=args.threshold)
        target_id = storage.upsert_target(conn, hostname, port)
        storage.record_check(conn, target_id, result)
        checked.append((target_id, result))
    conn.commit()

    results = sorted(
        (r for _, r in checked), key=lambda r: (r.days_remaining is None, r.days_remaining)
    )
    print_table([asdict(r) for r in results])

    if args.json_out:
        args.json_out.write_text(json.dumps([asdict(r) for r in results], indent=2))
        print(f"[info] wrote results to {args.json_out}")

    channels = [channel for channel in NOTIFIERS if getattr(args, channel)]
    new_alerts = find_new_alerts(conn, checked, args.alert_tiers, channels)
    conn.commit()
    for channel, alerts in new_alerts.items():
        if alerts and NOTIFIERS[channel]([(r, key) for _, r, key in alerts]):
            sent_at = _utc_now_iso()
            for target_id, _, key in alerts:
                storage.record_alert(conn, target_id, key, channel, sent_at)
            conn.commit()

    if any(r.status in FAILURE_STATUSES for r in results):
        return 2
    if any(r.status == "EXPIRING_SOON" for r in results):
        return 1
    return 0


def cmd_history(args: argparse.Namespace, conn: sqlite3.Connection) -> int:
    if args.target:
        hostname, port = split_target(args.target)
        rows = storage.target_history(conn, hostname, port, args.limit)
        if not rows:
            print(f"no checks recorded for {hostname}:{port}")
            return 0
        print_table([dict(r) for r in rows], show_time=True)
    else:
        rows = storage.latest_checks(conn)
        if not rows:
            print("no checks recorded yet; run the 'check' command first")
            return 0
        print_table([dict(r) for r in rows], show_time=True)
    return 0


def cmd_prune(args: argparse.Namespace, conn: sqlite3.Connection) -> int:
    cutoff = (datetime.now(timezone.utc) - timedelta(days=args.keep_days)).isoformat(timespec="seconds")
    deleted = storage.prune_checks(conn, cutoff)
    conn.commit()
    print(f"[info] deleted {deleted} check(s) older than {args.keep_days} days")
    return 0


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def cmd_serve(args: argparse.Namespace, conn: sqlite3.Connection) -> int:
    password = os.environ.get("DASHBOARD_PASSWORD") or None
    if password is None and not _is_loopback(args.host):
        print(
            f"[error] refusing to serve on {args.host} without a password; "
            "set DASHBOARD_PASSWORD or use --host 127.0.0.1",
            file=sys.stderr,
        )
        return 2
    app = dashboard.create_app(
        args.db,
        stale_hours=args.stale_hours,
        username=os.environ.get("DASHBOARD_USER", "admin"),
        password=password,
    )
    app.run(host=args.host, port=args.port)
    return 0


def _positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected a whole number, got {value!r}")
    if number < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return number


def _parse_tiers(value: str) -> list[int]:
    try:
        return sorted({int(v) for v in value.split(",") if v.strip()}, reverse=True)
    except ValueError:
        raise argparse.ArgumentTypeError("tiers must be comma-separated integers, e.g. 30,14,7")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Monitor TLS certificate expiry.")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--db", default=DEFAULT_DB_PATH, help=f"SQLite database path (default: {DEFAULT_DB_PATH})"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    check = subparsers.add_parser("check", parents=[common], help="check targets and record results")
    check.add_argument("targets", nargs="*", help="host or host:port targets to check")
    check.add_argument("--targets-file", type=Path, help="file with one host[:port] per line")
    check.add_argument(
        "--threshold", type=int, default=DEFAULT_THRESHOLD_DAYS,
        help="days remaining considered 'expiring soon' (default: 30)",
    )
    check.add_argument(
        "--alert-tiers", type=_parse_tiers, default=DEFAULT_ALERT_TIERS,
        help="days-remaining tiers that each trigger one email (default: 30,14,7,3,1)",
    )
    check.add_argument(
        "--timeout", type=float, default=DEFAULT_TIMEOUT,
        help="connection timeout in seconds (default: 5)",
    )
    check.add_argument("--email", action="store_true", help="email admins about new alerts")
    check.add_argument("--slack", action="store_true", help="post new alerts to a Slack webhook")
    check.add_argument("--json-out", type=Path, help="write full results as JSON to this path")
    check.set_defaults(func=cmd_check, parser=check)

    history = subparsers.add_parser(
        "history", parents=[common], help="show recorded results (latest per target, or one target's history)"
    )
    history.add_argument("target", nargs="?", help="host or host:port to show history for")
    history.add_argument("--limit", type=int, default=20, help="max rows for one target (default: 20)")
    history.set_defaults(func=cmd_history)

    prune = subparsers.add_parser(
        "prune", parents=[common], help="delete old check history (each target's latest check is kept)"
    )
    prune.add_argument(
        "--keep-days", type=_positive_int, default=90,
        help="keep checks from the last N days (default: 90)",
    )
    prune.set_defaults(func=cmd_prune)

    serve = subparsers.add_parser("serve", parents=[common], help="run the read-only web dashboard")
    serve.add_argument("--host", default="127.0.0.1", help="address to listen on (default: 127.0.0.1)")
    serve.add_argument("--port", type=int, default=8080, help="port to listen on (default: 8080)")
    serve.add_argument(
        "--stale-hours", type=float, default=24,
        help="flag targets whose latest check is older than this (default: 24)",
    )
    serve.set_defaults(func=cmd_serve)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    conn = storage.connect(args.db)
    try:
        return args.func(args, conn)
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
