#!/usr/bin/env python3
"""
cert_monitor.py - CLI for the TLS/SSL certificate monitoring app.

Checks a list of host[:port] targets, records every result in SQLite, and
(optionally) alerts admins by email and/or Slack when a target newly needs
attention: it crosses an expiry tier, expires, becomes unreachable, or fails
chain validation. Also serves a web dashboard over the history.

Usage:
    python cert_monitor.py targets add example.com github.com:443
    python cert_monitor.py check
    python cert_monitor.py check example.com github.com:443 smtp://mail.example.com:587
    python cert_monitor.py check --targets-file targets.txt --email --slack
    python cert_monitor.py history
    python cert_monitor.py history example.com --limit 10
    python cert_monitor.py discover example.com --targets-file targets.txt
    python cert_monitor.py ack example.com --note 'renewing today'
    python cert_monitor.py prune --keep-days 90
    python cert_monitor.py user add alice --role admin
    python cert_monitor.py serve
"""

from __future__ import annotations

import argparse
import functools
import getpass
import imaplib
import json
import os
import poplib
import re
import smtplib
import socket
import sqlite3
import ssl
import sys
import urllib.error
import urllib.request
from contextlib import contextmanager, suppress
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path

import waitress
from cryptography import x509

import ct
import dashboard
import storage
import targets

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
    protocol: str = "tls"

    @property
    def target(self) -> str:
        return targets.format_target(self.hostname, self.port, self.protocol)


def target_lines(text: str) -> list[str]:
    """Non-empty, non-comment lines of a targets file."""
    return [line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#")]


def parse_targets_file(path: Path) -> list[str]:
    return target_lines(path.read_text())


def parse_targets_or_report(raw_targets: list[str]) -> list[tuple[str, int, str]] | None:
    """Parse every target, printing each invalid one. Returns None if any
    were invalid, so a typo is fixed rather than silently skipped."""
    parsed, ok = [], True
    for raw in raw_targets:
        try:
            parsed.append(targets.parse_target(raw))
        except ValueError as exc:
            print(f"[error] {exc}", file=sys.stderr)
            ok = False
    return list(dict.fromkeys(parsed)) if ok else None


def _actor(args: argparse.Namespace) -> str | None:
    if args.by:
        return args.by
    try:
        return getpass.getuser()
    except (OSError, KeyError):
        print("[error] couldn't determine your login name; pass --by NAME", file=sys.stderr)
        return None


# Errors a mail server can answer with instead of upgrading to TLS.
STARTTLS_ERRORS = (smtplib.SMTPException, imaplib.IMAP4.error, poplib.error_proto)


class StartTLSError(Exception):
    pass


@contextmanager
def _tls_connection(hostname: str, port: int, timeout: float, ctx: ssl.SSLContext, protocol: str):
    """Yield a TLS socket to the target: directly, or by connecting in
    plaintext and upgrading with the protocol's STARTTLS command."""
    if protocol == "tls":
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                yield tls_sock
        return

    # These clients are closed without a polite QUIT/LOGOUT, and errors while
    # closing are ignored: after a failed handshake the client's socket is
    # already unusable, and a cleanup error would hide the real one.
    if protocol == "smtp":
        client = smtplib.SMTP(hostname, port, timeout=timeout)
        upgrade, close = functools.partial(client.starttls, context=ctx), client.close
    elif protocol == "imap":
        client = imaplib.IMAP4(hostname, port, timeout=timeout)
        upgrade, close = functools.partial(client.starttls, ssl_context=ctx), client.shutdown
    elif protocol == "pop3":
        client = poplib.POP3(hostname, port, timeout=timeout)
        upgrade, close = functools.partial(client.stls, context=ctx), client.close
    else:
        raise ValueError(f"unknown protocol {protocol!r}")
    try:
        try:
            upgrade()
        except STARTTLS_ERRORS as exc:
            raise StartTLSError(f"{protocol.upper()} STARTTLS failed: {exc}") from exc
        yield client.sock
    finally:
        with suppress(OSError):
            close()


def _fetch_cert_der(hostname: str, port: int, timeout: float, protocol: str = "tls") -> bytes:
    """Retrieve the peer certificate without verifying it, so expired or
    untrusted certs can still be parsed. Trust is checked in _check_chain_valid()."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with _tls_connection(hostname, port, timeout, ctx, protocol) as tls_sock:
        return tls_sock.getpeercert(binary_form=True)


def _check_chain_valid(
    hostname: str, port: int, timeout: float, protocol: str = "tls"
) -> tuple[bool, str | None]:
    ctx = ssl.create_default_context()
    try:
        with _tls_connection(hostname, port, timeout, ctx, protocol):
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


def check_target(
    hostname: str, port: int, timeout: float, threshold: int, protocol: str = "tls"
) -> CertCheckResult:
    try:
        der = _fetch_cert_der(hostname, port, timeout, protocol)
        chain_valid, chain_error = _check_chain_valid(hostname, port, timeout, protocol)
    except (OSError, StartTLSError, *STARTTLS_ERRORS) as exc:
        return CertCheckResult(
            hostname=hostname, port=port, protocol=protocol, status="UNREACHABLE",
            error=str(exc) or type(exc).__name__,
        )

    if der is None:
        return CertCheckResult(
            hostname=hostname, port=port, protocol=protocol, status="UNREACHABLE",
            error="peer presented no certificate",
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
        protocol=protocol,
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
    labels = [targets.format_target(r["hostname"], r["port"], r.get("protocol", "tls")) for r in rows]
    width = max([len("TARGET"), *map(len, labels)])
    time_col = f"{'CHECKED AT':<26} " if show_time else ""
    header = f"{time_col}{'TARGET':<{width}} {'STATUS':<15} {'DAYS':>6}  {'NOT AFTER':<26} ISSUER / ERROR"
    print(header)
    print("-" * len(header))
    for target, r in zip(labels, rows):
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


def send_slack(title: str, lines: list[str], url_var: str = "SLACK_WEBHOOK_URL") -> bool:
    url = os.environ.get(url_var)
    if not url:
        print(f"[warn] skipping Slack message, missing env var: {url_var}", file=sys.stderr)
        return False
    if not url.startswith("https://"):
        print(f"[warn] skipping Slack message, {url_var} must be an https:// URL", file=sys.stderr)
        return False

    text = f"*cert-monitor: {_slack_escape(title)}*\n" + _slack_escape("\n".join(lines))
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
        print(f"[error] failed to send Slack message, will retry next run: {exc}", file=sys.stderr)
        return False

    print("[info] Slack message sent")
    return True


def send_email(title: str, lines: list[str], to_var: str = "ALERT_TO_EMAILS") -> bool:
    smtp_host = os.environ.get("SMTP_HOST")
    smtp_port = int(os.environ.get("SMTP_PORT") or 587)
    smtp_user = os.environ.get("SMTP_USER")
    smtp_password = os.environ.get("SMTP_PASSWORD")
    from_addr = os.environ.get("ALERT_FROM_EMAIL")
    to_addrs = [a.strip() for a in os.environ.get(to_var, "").split(",") if a.strip()]

    missing = [
        name
        for name, val in [
            ("SMTP_HOST", smtp_host),
            ("ALERT_FROM_EMAIL", from_addr),
            (to_var, to_addrs),
        ]
        if not val
    ]
    if missing:
        print(f"[warn] skipping email, missing env vars: {', '.join(missing)}", file=sys.stderr)
        return False

    msg = EmailMessage()
    msg["Subject"] = f"[cert-monitor] {title}"
    msg["From"] = from_addr
    msg["To"] = ", ".join(to_addrs)
    msg.set_content(f"{title}:\n\n" + "\n".join(lines))

    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
            server.starttls()
            if smtp_user and smtp_password:
                server.login(smtp_user, smtp_password)
            server.send_message(msg)
    except (smtplib.SMTPException, OSError) as exc:
        print(f"[error] failed to send email, will retry next run: {exc}", file=sys.stderr)
        return False

    print(f"[info] email sent to {', '.join(to_addrs)}")
    return True


def _default_title(alerts: list) -> str:
    return f"{len(alerts)} certificate(s) need attention"


def send_alert_slack(
    alerts: list[tuple[CertCheckResult, str]],
    url_var: str = "SLACK_WEBHOOK_URL",
    title: str | None = None,
) -> bool:
    return send_slack(title or _default_title(alerts), format_alert_lines(alerts), url_var)


def send_alert_email(
    alerts: list[tuple[CertCheckResult, str]],
    to_var: str = "ALERT_TO_EMAILS",
    title: str | None = None,
) -> bool:
    return send_email(title or _default_title(alerts), format_alert_lines(alerts), to_var)


NOTIFIERS = {"email": send_alert_email, "slack": send_alert_slack}
ESCALATION_SUFFIX = ":escalation"
ESCALATION_NOTIFIERS = {
    "email": functools.partial(send_alert_email, to_var="ESCALATION_EMAILS"),
    "slack": functools.partial(send_alert_slack, url_var="ESCALATION_SLACK_WEBHOOK_URL"),
}


def is_urgent(key: str, within_days: int) -> bool:
    """Whether an unacknowledged alert is worth escalating: anything broken,
    or an expiry tier at or under `within_days`."""
    if key.startswith("EXPIRING_SOON"):
        tier = key.partition(":")[2]
        return tier.isdigit() and int(tier) <= within_days
    return True


def find_escalations(
    conn: sqlite3.Connection,
    checked: list[tuple[int, CertCheckResult]],
    tiers: list[int],
    channels: list[str],
    after_hours: float,
    within_days: int,
    now: datetime | None = None,
) -> dict[str, list[tuple[int, CertCheckResult, str]]]:
    """Per base channel, urgent alerts that were sent at least `after_hours`
    ago and haven't been acknowledged or escalated yet."""
    now = now or datetime.now(timezone.utc)
    escalations = {channel: [] for channel in channels}
    for target_id, result in checked:
        key = alert_key(result, tiers)
        if key is None or not is_urgent(key, within_days):
            continue
        active = storage.active_alert(conn, target_id)
        if active is None or active[0] != key:
            continue
        since = active[1]
        if now - datetime.fromisoformat(since) < timedelta(hours=after_hours):
            continue
        if storage.current_ack(conn, target_id, key, since) is not None:
            continue
        state = storage.get_alert_state(conn, target_id)
        for channel in channels:
            if state.get(channel + ESCALATION_SUFFIX) != key:
                escalations[channel].append((target_id, result, key))
    return escalations


def cmd_check(args: argparse.Namespace, conn: sqlite3.Connection) -> int:
    raw_targets = list(args.targets)
    if args.targets_file:
        raw_targets.extend(parse_targets_file(args.targets_file))
    if raw_targets:
        to_check = parse_targets_or_report(raw_targets)
        if to_check is None:
            return 2
    else:
        to_check = [(t["hostname"], t["port"], t["protocol"]) for t in storage.active_targets(conn)]
        if not to_check:
            print(
                "[error] no hosts to check: add some with 'targets add HOST', "
                "or pass hosts / --targets-file",
                file=sys.stderr,
            )
            return 2

    checked = []
    for hostname, port, protocol in to_check:
        result = check_target(hostname, port, args.timeout, args.threshold, protocol)
        target_id = storage.upsert_target(conn, hostname, port, protocol)
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

    if args.escalate_after is not None:
        escalations = find_escalations(
            conn, checked, args.alert_tiers, channels, args.escalate_after, args.escalate_within_days
        )
        for channel, alerts in escalations.items():
            if not alerts:
                continue
            title = (
                f"ESCALATION: {len(alerts)} alert(s) not acknowledged "
                f"after {args.escalate_after:g} hours"
            )
            if ESCALATION_NOTIFIERS[channel]([(r, key) for _, r, key in alerts], title=title):
                sent_at = _utc_now_iso()
                for target_id, _, key in alerts:
                    storage.record_alert(conn, target_id, key, channel + ESCALATION_SUFFIX, sent_at)
                conn.commit()

    if any(r.status in FAILURE_STATUSES for r in results):
        return 2
    if any(r.status == "EXPIRING_SOON" for r in results):
        return 1
    return 0


def cmd_history(args: argparse.Namespace, conn: sqlite3.Connection) -> int:
    if args.target:
        parsed = parse_targets_or_report([args.target])
        if parsed is None:
            return 2
        hostname, port, protocol = parsed[0]
        rows = storage.target_history(conn, hostname, port, args.limit)
        if not rows:
            print(f"no checks recorded for {targets.format_target(hostname, port, protocol)}")
            return 0
        print_table([dict(r) for r in rows], show_time=True)
    else:
        rows = storage.latest_checks(conn)
        if not rows:
            print("no checks recorded yet; run the 'check' command first")
            return 0
        print_table([dict(r) for r in rows], show_time=True)
    return 0


CT_NOTIFIERS = {"email": send_email, "slack": send_slack}


def format_ct_lines(rows) -> list[str]:
    return [
        f"- {', '.join(json.loads(row['names']))}\n"
        f"    issued by {row['issuer']}, valid from {row['not_before']}\n"
        f"    {ct.CRTSH_URL}?id={row['crtsh_id']}"
        for row in rows
    ]


def _print_ct_hostnames(certs: list[ct.CTCertificate], monitored: set[str]) -> None:
    latest: dict[str, ct.CTCertificate] = {}
    for cert in certs:
        for name in cert.names:
            if name not in latest or cert.not_after > latest[name].not_after:
                latest[name] = cert
    if not latest:
        return
    width = max(len("HOSTNAME"), *map(len, latest))
    print(f"{'HOSTNAME':<{width}}  {'STATUS':<13}  {'EXPIRES':<25}  ISSUER")
    for name in sorted(latest, key=lambda n: (n.removeprefix("*.").split(".")[::-1], n)):
        if name.startswith("*."):
            status = "wildcard"
        elif name in monitored:
            status = "monitored"
        else:
            status = "NOT MONITORED"
        cert = latest[name]
        print(f"{name:<{width}}  {status:<13}  {cert.not_after:<25}  {cert.issuer}")


def _append_targets(path: Path, hostnames: list[str]) -> None:
    existing = path.read_text() if path.exists() else ""
    separator = "" if not existing or existing.endswith("\n") else "\n"
    today = datetime.now(timezone.utc).date().isoformat()
    with path.open("a") as f:
        f.write(f"{separator}# added by 'discover' on {today}\n")
        f.writelines(f"{name}\n" for name in hostnames)


def cmd_discover(args: argparse.Namespace, conn: sqlite3.Connection) -> int:
    try:
        domains = list(dict.fromkeys(ct.normalize_domain(d) for d in args.domains))
    except ValueError as exc:
        args.parser.error(str(exc))
    monitored = storage.monitored_hostnames(conn)
    if args.targets_file and args.targets_file.exists():
        for raw in parse_targets_file(args.targets_file):
            try:
                monitored.add(targets.parse_target(raw)[0])
            except ValueError:
                pass

    lookup_failed = False
    found_new = False
    unmonitored: set[str] = set()
    for domain in domains:
        try:
            certs = ct.fetch_certificates(domain, timeout=args.timeout)
        except ct.CTLookupError as exc:
            print(f"[error] {exc}", file=sys.stderr)
            lookup_failed = True
            continue

        first_run = storage.ct_domain(conn, domain) is None
        new = storage.save_ct_certs(conn, domain, certs, _utc_now_iso(), in_baseline=first_run)
        conn.commit()

        print(f"{domain}: {len(certs)} unexpired certificate(s) in CT logs")
        _print_ct_hostnames(certs, monitored)
        if first_run:
            print(
                f"[info] first run for {domain}: these are now the baseline; "
                "later runs will report certificates issued after this one"
            )
        elif new:
            found_new = True
            print(f"[info] {len(new)} certificate(s) issued since the last run:")
            for _, cert in new:
                print(f"  {', '.join(cert.names)}  (issued by {cert.issuer}, {cert.url})")
        print()
        unmonitored |= {
            name for cert in certs for name in cert.names
            if not name.startswith("*.") and name not in monitored
        }

    if args.add and unmonitored:
        if args.targets_file:
            _append_targets(args.targets_file, sorted(unmonitored))
            print(f"[info] added {len(unmonitored)} hostname(s) to {args.targets_file}")
        else:
            now = _utc_now_iso()
            for name in sorted(unmonitored):
                storage.add_target(conn, name, targets.DEFAULT_PORT, "discover", now)
            conn.commit()
            print(f"[info] now monitoring {len(unmonitored)} more host(s): {', '.join(sorted(unmonitored))}")

    for channel in (c for c in CT_NOTIFIERS if getattr(args, c)):
        rows = storage.unnotified_ct_certs(conn, domains, channel)
        if not rows:
            continue
        title = f"{len(rows)} new certificate(s) issued for your domains"
        lines = [
            "Certificate Transparency logs show these certificates were issued since the last check.",
            "If you don't recognize one, investigate: it may have been issued without your approval.",
            "",
            *format_ct_lines(rows),
        ]
        if CT_NOTIFIERS[channel](title, lines):
            storage.mark_ct_notified(conn, [r["id"] for r in rows], channel, _utc_now_iso())
            conn.commit()

    if lookup_failed:
        return 2
    return 1 if found_new else 0


def cmd_ack(args: argparse.Namespace, conn: sqlite3.Connection) -> int:
    parsed = parse_targets_or_report([args.target])
    if parsed is None:
        return 2
    hostname, port, _ = parsed[0]
    target = storage.get_target(conn, hostname, port)
    label = targets.format_target(hostname, port, target["protocol"] if target else "tls")
    active = storage.active_alert(conn, target["id"]) if target else None
    if active is None:
        print(f"[error] {label} has no open alert to acknowledge", file=sys.stderr)
        return 2
    by = _actor(args)
    if by is None:
        return 2
    key, _ = active
    storage.record_ack(conn, target["id"], key, by, args.note, _utc_now_iso())
    conn.commit()
    print(f"[info] acknowledged {key} on {label} as {by}")
    return 0


def _add_targets(conn: sqlite3.Connection, raw_targets: list[str], by: str) -> int:
    parsed = parse_targets_or_report(raw_targets)
    if parsed is None:
        return 2
    now = _utc_now_iso()
    for hostname, port, protocol in parsed:
        outcome = storage.add_target(conn, hostname, port, by, now, protocol)
        label = targets.format_target(hostname, port, protocol)
        print({
            "added": f"[info] now monitoring {label}",
            "restored": f"[info] monitoring {label} again",
            "updated": f"[info] now checking {label}",
            "unchanged": f"[info] already monitoring {label}",
        }[outcome])
    conn.commit()
    return 0


def cmd_targets_add(args: argparse.Namespace, conn: sqlite3.Connection) -> int:
    by = _actor(args)
    return 2 if by is None else _add_targets(conn, args.targets, by)


def cmd_targets_import(args: argparse.Namespace, conn: sqlite3.Connection) -> int:
    by = _actor(args)
    if by is None:
        return 2
    text = sys.stdin.read() if args.file == "-" else Path(args.file).read_text()
    lines = target_lines(text)
    if not lines:
        print("[error] no targets found in the input", file=sys.stderr)
        return 2
    return _add_targets(conn, lines, by)


def cmd_targets_remove(args: argparse.Namespace, conn: sqlite3.Connection) -> int:
    by = _actor(args)
    parsed = parse_targets_or_report(args.targets)
    if by is None or parsed is None:
        return 2
    code = 0
    for hostname, port, _ in parsed:
        target = storage.get_target(conn, hostname, port)
        label = targets.format_target(hostname, port, target["protocol"] if target else "tls")
        if target is None or not storage.remove_target(conn, target["id"], by, _utc_now_iso()):
            print(f"[error] {label} isn't being monitored", file=sys.stderr)
            code = 2
            continue
        print(f"[info] stopped monitoring {label} (its history is kept)")
    conn.commit()
    return code


def cmd_targets_list(args: argparse.Namespace, conn: sqlite3.Connection) -> int:
    rows = [r for r in storage.targets_overview(conn) if r["active"] or args.all]
    if not rows:
        print("no hosts yet; add some with: python cert_monitor.py targets add example.com")
        return 0
    labels = [targets.format_target(r["hostname"], r["port"], r["protocol"]) for r in rows]
    width = max(len("TARGET"), *map(len, labels))
    print(f"{'TARGET':<{width}}  {'STATE':<9} {'LAST STATUS':<15} {'DAYS':>5}  LAST CHECKED")
    for label, r in zip(labels, rows):
        state = "active" if r["active"] else "removed"
        days = "" if r["days_remaining"] is None else str(r["days_remaining"])
        print(
            f"{label:<{width}}  {state:<9} {r['status'] or 'not checked':<15} {days:>5}  "
            f"{r['checked_at'] or '-'}"
        )
    return 0


def cmd_prune(args: argparse.Namespace, conn: sqlite3.Connection) -> int:
    cutoff = (datetime.now(timezone.utc) - timedelta(days=args.keep_days)).isoformat(timespec="seconds")
    deleted = storage.prune_checks(conn, cutoff)
    conn.commit()
    print(f"[info] deleted {deleted} check(s) older than {args.keep_days} days")
    return 0


def cmd_serve(args: argparse.Namespace, conn: sqlite3.Connection) -> int:
    if os.environ.get("DASHBOARD_PASSWORD"):
        print(
            "[warn] DASHBOARD_PASSWORD is no longer used; dashboard logins are managed with 'user add'",
            file=sys.stderr,
        )
    if storage.count_users(conn) == 0:
        print(
            "[error] no dashboard accounts exist yet; create one first:\n"
            f"  python cert_monitor.py user add YOUR_NAME --role admin --db {args.db}",
            file=sys.stderr,
        )
        return 2
    app = dashboard.create_app(
        args.db,
        stale_hours=args.stale_hours,
        secret_key=os.environ.get("DASHBOARD_SECRET_KEY") or None,
        secure_cookies=os.environ.get("DASHBOARD_SECURE_COOKIES") == "1",
    )
    print(f"[info] dashboard listening on http://{args.host}:{args.port}")
    waitress.serve(app, host=args.host, port=args.port)
    return 0


MIN_PASSWORD_LENGTH = 12
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9._@-]{1,64}$")


def _read_new_password(from_stdin: bool) -> str | None:
    if from_stdin:
        password = sys.stdin.readline().rstrip("\r\n")
    else:
        password = getpass.getpass("Password: ")
        if getpass.getpass("Repeat password: ") != password:
            print("[error] passwords don't match", file=sys.stderr)
            return None
    if len(password) < MIN_PASSWORD_LENGTH:
        print(f"[error] password must be at least {MIN_PASSWORD_LENGTH} characters", file=sys.stderr)
        return None
    return password


def cmd_user_add(args: argparse.Namespace, conn: sqlite3.Connection) -> int:
    if not USERNAME_PATTERN.match(args.username):
        print("[error] usernames may use letters, digits, and . _ @ - (max 64 characters)", file=sys.stderr)
        return 2
    password = _read_new_password(args.password_stdin)
    if password is None:
        return 2
    created = storage.save_user(conn, args.username, dashboard.hash_password(password), args.role)
    conn.commit()
    print(f"[info] {'created' if created else 'updated'} {args.role} account '{args.username}'")
    return 0


def cmd_user_remove(args: argparse.Namespace, conn: sqlite3.Connection) -> int:
    if not storage.remove_user(conn, args.username):
        print(f"[error] no account named '{args.username}'", file=sys.stderr)
        return 2
    conn.commit()
    print(f"[info] removed account '{args.username}'")
    return 0


def cmd_user_list(args: argparse.Namespace, conn: sqlite3.Connection) -> int:
    users = storage.list_users(conn)
    if not users:
        print("no accounts yet; create one with: python cert_monitor.py user add NAME --role admin")
        return 0
    width = max(len("USERNAME"), *(len(u["username"]) for u in users))
    print(f"{'USERNAME':<{width}}  {'ROLE':<7} CREATED")
    for u in users:
        print(f"{u['username']:<{width}}  {u['role']:<7} {u['created_at']}")
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
        "--db", default=os.environ.get("CERT_MONITOR_DB") or DEFAULT_DB_PATH,
        help=f"SQLite database path (default: $CERT_MONITOR_DB, or {DEFAULT_DB_PATH})",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    check = subparsers.add_parser("check", parents=[common], help="check targets and record results")
    check.add_argument(
        "targets", nargs="*",
        help="host or host:port to check (default: every host added with 'targets add')",
    )
    check.add_argument("--targets-file", type=Path, help="check the hosts in this file (one per line)")
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
    check.add_argument(
        "--escalate-after", type=float, metavar="HOURS",
        help="escalate urgent alerts nobody has acknowledged after this many hours (off by default)",
    )
    check.add_argument(
        "--escalate-within-days", type=int, default=7, metavar="DAYS",
        help="expiry alerts count as urgent at this many days left or fewer (default: 7)",
    )
    check.add_argument("--json-out", type=Path, help="write full results as JSON to this path")
    check.set_defaults(func=cmd_check, parser=check)

    history = subparsers.add_parser(
        "history", parents=[common], help="show recorded results (latest per target, or one target's history)"
    )
    history.add_argument("target", nargs="?", help="host or host:port to show history for")
    history.add_argument("--limit", type=int, default=20, help="max rows for one target (default: 20)")
    history.set_defaults(func=cmd_history)

    discover = subparsers.add_parser(
        "discover", parents=[common],
        help="find certificates for your domains in Certificate Transparency logs (via crt.sh)",
    )
    discover.add_argument("domains", nargs="+", metavar="DOMAIN", help="e.g. example.com")
    discover.add_argument(
        "--targets-file", type=Path, help="also count hostnames in this file as monitored"
    )
    discover.add_argument(
        "--add", action="store_true",
        help="start monitoring hostnames that aren't yet (appended to --targets-file if given)",
    )
    discover.add_argument(
        "--timeout", type=float, default=60, help="crt.sh request timeout in seconds (default: 60)"
    )
    discover.add_argument("--email", action="store_true", help="email a report of newly issued certificates")
    discover.add_argument("--slack", action="store_true", help="post newly issued certificates to Slack")
    discover.set_defaults(func=cmd_discover, parser=discover)

    hosts = subparsers.add_parser("targets", help="manage the hosts that 'check' monitors")
    host_commands = hosts.add_subparsers(dest="targets_command", required=True)
    hosts_list = host_commands.add_parser("list", parents=[common], help="list monitored hosts")
    hosts_list.add_argument("--all", action="store_true", help="include removed hosts")
    hosts_list.set_defaults(func=cmd_targets_list)
    hosts_add = host_commands.add_parser("add", parents=[common], help="start monitoring hosts")
    hosts_add.add_argument("targets", nargs="+", metavar="TARGET", help="host or host:port")
    hosts_add.add_argument("--by", help="who is making the change (default: your login name)")
    hosts_add.set_defaults(func=cmd_targets_add)
    hosts_remove = host_commands.add_parser(
        "remove", parents=[common], help="stop monitoring hosts (their history is kept)"
    )
    hosts_remove.add_argument("targets", nargs="+", metavar="TARGET", help="host or host:port")
    hosts_remove.add_argument("--by", help="who is making the change (default: your login name)")
    hosts_remove.set_defaults(func=cmd_targets_remove)
    hosts_import = host_commands.add_parser(
        "import", parents=[common], help="add every host in a targets file ('-' reads stdin)"
    )
    hosts_import.add_argument("file")
    hosts_import.add_argument("--by", help="who is making the change (default: your login name)")
    hosts_import.set_defaults(func=cmd_targets_import)

    ack = subparsers.add_parser(
        "ack", parents=[common], help="acknowledge a target's open alert so it isn't escalated"
    )
    ack.add_argument("target", help="host or host:port")
    ack.add_argument("--by", help="who is handling it (default: your login name)")
    ack.add_argument("--note", help="optional note, e.g. a ticket number")
    ack.set_defaults(func=cmd_ack)

    prune = subparsers.add_parser(
        "prune", parents=[common], help="delete old check history (each target's latest check is kept)"
    )
    prune.add_argument(
        "--keep-days", type=_positive_int, default=90,
        help="keep checks from the last N days (default: 90)",
    )
    prune.set_defaults(func=cmd_prune)

    user = subparsers.add_parser("user", help="manage dashboard accounts")
    user_commands = user.add_subparsers(dest="user_command", required=True)
    user_add = user_commands.add_parser(
        "add", parents=[common], help="create an account, or reset its password and role"
    )
    user_add.add_argument("username")
    user_add.add_argument(
        "--role", choices=storage.ROLES, required=True,
        help="admin: can view and acknowledge alerts; viewer: read-only",
    )
    user_add.add_argument(
        "--password-stdin", action="store_true",
        help="read the password from the first line of stdin instead of prompting",
    )
    user_add.set_defaults(func=cmd_user_add)
    user_remove = user_commands.add_parser("remove", parents=[common], help="delete an account")
    user_remove.add_argument("username")
    user_remove.set_defaults(func=cmd_user_remove)
    user_list = user_commands.add_parser("list", parents=[common], help="list accounts")
    user_list.set_defaults(func=cmd_user_list)

    serve = subparsers.add_parser("serve", parents=[common], help="run the web dashboard")
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
