"""SQLite persistence for cert-monitor: targets, check history, and sent alerts."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY,
    hostname TEXT NOT NULL,
    port INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    active INTEGER NOT NULL DEFAULT 1,
    changed_by TEXT,
    changed_at TEXT,
    protocol TEXT NOT NULL DEFAULT 'tls',
    UNIQUE (hostname, port)
);

CREATE TABLE IF NOT EXISTS checks (
    id INTEGER PRIMARY KEY,
    target_id INTEGER NOT NULL REFERENCES targets(id),
    checked_at TEXT NOT NULL,
    status TEXT NOT NULL,
    days_remaining INTEGER,
    not_before TEXT,
    not_after TEXT,
    issuer TEXT,
    subject TEXT,
    san TEXT,
    serial_number TEXT,
    chain_valid INTEGER NOT NULL,
    error TEXT
);
CREATE INDEX IF NOT EXISTS idx_checks_target ON checks (target_id, id);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY,
    target_id INTEGER NOT NULL REFERENCES targets(id),
    alert_key TEXT NOT NULL,
    channel TEXT NOT NULL,
    sent_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alert_state (
    target_id INTEGER NOT NULL REFERENCES targets(id),
    channel TEXT NOT NULL,
    alert_key TEXT NOT NULL,
    alerted_at TEXT,
    PRIMARY KEY (target_id, channel)
);

CREATE TABLE IF NOT EXISTS acks (
    id INTEGER PRIMARY KEY,
    target_id INTEGER NOT NULL REFERENCES targets(id),
    alert_key TEXT NOT NULL,
    acked_by TEXT NOT NULL,
    note TEXT,
    acked_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_acks_target ON acks (target_id, id);

CREATE TABLE IF NOT EXISTS ct_domains (
    domain TEXT PRIMARY KEY,
    baselined_at TEXT NOT NULL,
    last_run_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ct_certs (
    id INTEGER PRIMARY KEY,
    cert_key TEXT NOT NULL UNIQUE,
    domain TEXT NOT NULL,
    crtsh_id INTEGER NOT NULL,
    issuer TEXT,
    names TEXT NOT NULL,
    not_before TEXT NOT NULL,
    not_after TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    in_baseline INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS ct_notified (
    cert_id INTEGER NOT NULL REFERENCES ct_certs(id),
    channel TEXT NOT NULL,
    notified_at TEXT NOT NULL,
    PRIMARY KEY (cert_id, channel)
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'viewer')),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
"""

ROLES = ("admin", "viewer")


def connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    # WAL lets the dashboard read while a cron check is writing.
    conn.execute("PRAGMA journal_mode = WAL")
    conn.executescript(SCHEMA)
    _add_alerted_at_column(conn)
    _migrate_phase2_alert_state(conn)
    _add_target_management_columns(conn)
    return conn


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _add_alerted_at_column(conn: sqlite3.Connection) -> None:
    """Phase 3 databases didn't record when each alert was sent. Existing
    alerts are treated as sent now, so escalation timers start fresh."""
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(alert_state)")}
    if "alerted_at" in columns:
        return
    conn.execute("ALTER TABLE alert_state ADD COLUMN alerted_at TEXT")
    conn.execute("UPDATE alert_state SET alerted_at = ?", (_utc_now_iso(),))
    conn.commit()


def _add_target_management_columns(conn: sqlite3.Connection) -> None:
    """Databases from before hosts could be managed in the dashboard (every
    existing target stays active) or checked over STARTTLS (every existing
    target is direct TLS)."""
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(targets)")}
    for name, declaration in (
        ("active", "INTEGER NOT NULL DEFAULT 1"),
        ("changed_by", "TEXT"),
        ("changed_at", "TEXT"),
        ("protocol", "TEXT NOT NULL DEFAULT 'tls'"),
    ):
        if name not in columns:
            conn.execute(f"ALTER TABLE targets ADD COLUMN {name} {declaration}")
    conn.commit()


def _migrate_phase2_alert_state(conn: sqlite3.Connection) -> None:
    """Phase 2 databases tracked a single alert state per target (email only)
    in targets.last_alert_key. Move it into alert_state and null it out so this
    runs once; the column is left in place for older SQLite versions."""
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(targets)")}
    if "last_alert_key" not in columns:
        return
    conn.execute(
        """
        INSERT OR IGNORE INTO alert_state (target_id, channel, alert_key, alerted_at)
        SELECT id, 'email', last_alert_key, ? FROM targets WHERE last_alert_key IS NOT NULL
        """,
        (_utc_now_iso(),),
    )
    conn.execute("UPDATE targets SET last_alert_key = NULL")
    conn.commit()


def upsert_target(conn: sqlite3.Connection, hostname: str, port: int, protocol: str = "tls") -> int:
    """Get or create a target, making it active: a target someone explicitly
    asks to check is monitored again even if it was removed earlier."""
    conn.execute(
        """
        INSERT INTO targets (hostname, port, protocol) VALUES (?, ?, ?)
        ON CONFLICT (hostname, port) DO UPDATE SET active = 1, protocol = excluded.protocol
        """,
        (hostname, port, protocol),
    )
    row = conn.execute(
        "SELECT id FROM targets WHERE hostname = ? AND port = ?", (hostname, port)
    ).fetchone()
    return row["id"]


def add_target(
    conn: sqlite3.Connection, hostname: str, port: int, actor: str, at: str, protocol: str = "tls"
) -> str:
    """Start monitoring a target. Returns "added", "restored", "updated" (its
    protocol changed) or "unchanged"."""
    existing = get_target(conn, hostname, port)
    if existing is not None and existing["active"] and existing["protocol"] == protocol:
        return "unchanged"
    conn.execute(
        """
        INSERT INTO targets (hostname, port, protocol, active, changed_by, changed_at) VALUES (?, ?, ?, 1, ?, ?)
        ON CONFLICT (hostname, port) DO UPDATE SET
            active = 1, protocol = excluded.protocol,
            changed_by = excluded.changed_by, changed_at = excluded.changed_at
        """,
        (hostname, port, protocol, actor, at),
    )
    if existing is None:
        return "added"
    return "restored" if not existing["active"] else "updated"


def remove_target(conn: sqlite3.Connection, target_id: int, actor: str, at: str) -> bool:
    """Stop monitoring a target, keeping its history. Returns False if it
    wasn't being monitored."""
    cursor = conn.execute(
        "UPDATE targets SET active = 0, changed_by = ?, changed_at = ? WHERE id = ? AND active = 1",
        (actor, at, target_id),
    )
    if not cursor.rowcount:
        return False
    # A removed host shouldn't show an open alert or be escalated.
    clear_alert_state(conn, target_id)
    return True


def get_target_by_id(conn: sqlite3.Connection, target_id: int) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM targets WHERE id = ?", (target_id,)).fetchone()


def active_targets(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM targets WHERE active = 1 ORDER BY hostname, port"
    ).fetchall()


def targets_overview(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    """Every target, active first, with its latest check (if any)."""
    return conn.execute(
        """
        SELECT t.*, c.status, c.checked_at, c.days_remaining
        FROM targets t
        LEFT JOIN checks c ON c.id = (SELECT MAX(id) FROM checks WHERE target_id = t.id)
        ORDER BY t.active DESC, t.hostname, t.port
        """
    ).fetchall()


def unchecked_target_count(conn: sqlite3.Connection) -> int:
    return conn.execute(
        """
        SELECT COUNT(*) FROM targets t
        WHERE t.active = 1 AND NOT EXISTS (SELECT 1 FROM checks WHERE target_id = t.id)
        """
    ).fetchone()[0]


def get_target(conn: sqlite3.Connection, hostname: str, port: int) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM targets WHERE hostname = ? AND port = ?", (hostname, port)
    ).fetchone()


def record_check(conn: sqlite3.Connection, target_id: int, result) -> None:
    conn.execute(
        """
        INSERT INTO checks (
            target_id, checked_at, status, days_remaining, not_before, not_after,
            issuer, subject, san, serial_number, chain_valid, error
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            target_id,
            result.checked_at,
            result.status,
            result.days_remaining,
            result.not_before,
            result.not_after,
            result.issuer,
            result.subject,
            json.dumps(result.san),
            result.serial_number,
            int(result.chain_valid),
            result.error,
        ),
    )


def get_alert_state(conn: sqlite3.Connection, target_id: int) -> dict[str, str]:
    rows = conn.execute(
        "SELECT channel, alert_key FROM alert_state WHERE target_id = ?", (target_id,)
    ).fetchall()
    return {row["channel"]: row["alert_key"] for row in rows}


# A PagerDuty incident stays open until it's explicitly resolved, so when a
# target recovers (or is removed) its "pagerduty" state becomes a pending
# resolve that's retried until PagerDuty accepts it.
PAGERDUTY_RESOLVE = "pagerduty:resolve"


def clear_alert_state(conn: sqlite3.Connection, target_id: int) -> None:
    had_incident = conn.execute(
        "SELECT 1 FROM alert_state WHERE target_id = ? AND channel = 'pagerduty'", (target_id,)
    ).fetchone()
    conn.execute(
        "DELETE FROM alert_state WHERE target_id = ? AND channel != ?", (target_id, PAGERDUTY_RESOLVE)
    )
    if had_incident:
        conn.execute(
            "INSERT OR REPLACE INTO alert_state (target_id, channel, alert_key, alerted_at) VALUES (?, ?, 'RESOLVE', ?)",
            (target_id, PAGERDUTY_RESOLVE, _utc_now_iso()),
        )


def cancel_pagerduty_resolve(conn: sqlite3.Connection, target_id: int) -> None:
    conn.execute(
        "DELETE FROM alert_state WHERE target_id = ? AND channel = ?", (target_id, PAGERDUTY_RESOLVE)
    )


def pending_pagerduty_resolves(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        """
        SELECT t.id AS target_id, t.hostname, t.port, t.protocol
        FROM alert_state s JOIN targets t ON t.id = s.target_id
        WHERE s.channel = ?
        ORDER BY t.hostname, t.port
        """,
        (PAGERDUTY_RESOLVE,),
    ).fetchall()


def finish_pagerduty_resolve(conn: sqlite3.Connection, target_id: int, at: str) -> None:
    cancel_pagerduty_resolve(conn, target_id)
    conn.execute(
        "INSERT INTO alerts (target_id, alert_key, channel, sent_at) VALUES (?, 'RESOLVED', 'pagerduty', ?)",
        (target_id, at),
    )


def record_alert(
    conn: sqlite3.Connection, target_id: int, alert_key: str, channel: str, sent_at: str
) -> None:
    conn.execute(
        "INSERT INTO alerts (target_id, alert_key, channel, sent_at) VALUES (?, ?, ?, ?)",
        (target_id, alert_key, channel, sent_at),
    )
    conn.execute(
        "INSERT OR REPLACE INTO alert_state (target_id, channel, alert_key, alerted_at) VALUES (?, ?, ?, ?)",
        (target_id, channel, alert_key, sent_at),
    )


def active_alert(conn: sqlite3.Connection, target_id: int) -> tuple[str, str] | None:
    """The alert currently open for a target, as (alert_key, first sent at),
    based on the regular channels (not escalations or pending resolves)."""
    rows = conn.execute(
        """
        SELECT alert_key, alerted_at FROM alert_state
        WHERE target_id = ? AND channel NOT LIKE '%:%'
        ORDER BY alerted_at DESC
        """,
        (target_id,),
    ).fetchall()
    if not rows:
        return None
    key = rows[0]["alert_key"]
    return key, min(r["alerted_at"] for r in rows if r["alert_key"] == key)


def record_ack(
    conn: sqlite3.Connection, target_id: int, alert_key: str, acked_by: str, note: str | None, acked_at: str
) -> None:
    conn.execute(
        "INSERT INTO acks (target_id, alert_key, acked_by, note, acked_at) VALUES (?, ?, ?, ?, ?)",
        (target_id, alert_key, acked_by, note, acked_at),
    )


def current_ack(
    conn: sqlite3.Connection, target_id: int, alert_key: str, since: str
) -> sqlite3.Row | None:
    """The latest acknowledgement of this alert made since it was raised. An
    ack from an earlier occurrence of the same problem doesn't count."""
    return conn.execute(
        """
        SELECT * FROM acks
        WHERE target_id = ? AND alert_key = ? AND acked_at >= ?
        ORDER BY id DESC LIMIT 1
        """,
        (target_id, alert_key, since),
    ).fetchone()


def target_acks(conn: sqlite3.Connection, target_id: int, limit: int) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM acks WHERE target_id = ? ORDER BY id DESC LIMIT ?", (target_id, limit)
    ).fetchall()


def latest_checks(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        """
        SELECT t.hostname, t.port, t.protocol, c.*
        FROM checks c
        JOIN targets t ON t.id = c.target_id
        WHERE t.active = 1
          AND c.id = (SELECT MAX(id) FROM checks WHERE target_id = c.target_id)
        ORDER BY c.days_remaining IS NULL, c.days_remaining
        """
    ).fetchall()


def target_history(
    conn: sqlite3.Connection, hostname: str, port: int, limit: int
) -> list[sqlite3.Row]:
    return conn.execute(
        """
        SELECT t.hostname, t.port, t.protocol, c.*
        FROM checks c
        JOIN targets t ON t.id = c.target_id
        WHERE t.hostname = ? AND t.port = ?
        ORDER BY c.id DESC
        LIMIT ?
        """,
        (hostname, port, limit),
    ).fetchall()


def prune_checks(conn: sqlite3.Connection, older_than: str) -> int:
    """Delete checks recorded before `older_than` (ISO timestamp), always
    keeping each target's latest check so it stays on the dashboard."""
    cursor = conn.execute(
        """
        DELETE FROM checks
        WHERE checked_at < ?
          AND id NOT IN (SELECT MAX(id) FROM checks GROUP BY target_id)
        """,
        (older_than,),
    )
    return cursor.rowcount


def save_user(conn: sqlite3.Connection, username: str, password_hash: str, role: str) -> bool:
    """Create the user, or reset the password and role if it exists. Returns
    True if the user was created."""
    created = get_user(conn, username) is None
    conn.execute(
        """
        INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)
        ON CONFLICT (username) DO UPDATE SET password_hash = excluded.password_hash, role = excluded.role
        """,
        (username, password_hash, role),
    )
    return created


def get_user(conn: sqlite3.Connection, username: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()


def list_users(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute("SELECT username, role, created_at FROM users ORDER BY username").fetchall()


def remove_user(conn: sqlite3.Connection, username: str) -> bool:
    return conn.execute("DELETE FROM users WHERE username = ?", (username,)).rowcount > 0


def count_users(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]


def target_alerts(conn: sqlite3.Connection, target_id: int, limit: int) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM alerts WHERE target_id = ? ORDER BY id DESC LIMIT ?",
        (target_id, limit),
    ).fetchall()


def monitored_hostnames(conn: sqlite3.Connection) -> set[str]:
    return {row["hostname"].lower() for row in conn.execute("SELECT hostname FROM targets WHERE active = 1")}


def ct_domain(conn: sqlite3.Connection, domain: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM ct_domains WHERE domain = ?", (domain,)).fetchone()


def save_ct_certs(conn: sqlite3.Connection, domain: str, certs, seen_at: str, in_baseline: bool) -> list:
    """Record certificates not seen before; returns (id, cert) for each new one."""
    new = []
    for cert in certs:
        cursor = conn.execute(
            """
            INSERT OR IGNORE INTO ct_certs (
                cert_key, domain, crtsh_id, issuer, names, not_before, not_after, first_seen_at, in_baseline
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                cert.key, domain, cert.crtsh_id, cert.issuer, json.dumps(list(cert.names)),
                cert.not_before, cert.not_after, seen_at, int(in_baseline),
            ),
        )
        if cursor.rowcount:
            new.append((cursor.lastrowid, cert))
    conn.execute(
        """
        INSERT INTO ct_domains (domain, baselined_at, last_run_at) VALUES (?, ?, ?)
        ON CONFLICT (domain) DO UPDATE SET last_run_at = excluded.last_run_at
        """,
        (domain, seen_at, seen_at),
    )
    return new


def unnotified_ct_certs(conn: sqlite3.Connection, domains: list[str], channel: str) -> list[sqlite3.Row]:
    """Newly issued (non-baseline) certificates for these domains that haven't
    been reported on `channel` yet."""
    placeholders = ",".join("?" * len(domains))
    return conn.execute(
        f"""
        SELECT * FROM ct_certs c
        WHERE c.in_baseline = 0
          AND c.domain IN ({placeholders})
          AND NOT EXISTS (SELECT 1 FROM ct_notified n WHERE n.cert_id = c.id AND n.channel = ?)
        ORDER BY c.id
        """,
        (*domains, channel),
    ).fetchall()


def mark_ct_notified(conn: sqlite3.Connection, cert_ids: list[int], channel: str, notified_at: str) -> None:
    conn.executemany(
        "INSERT OR IGNORE INTO ct_notified (cert_id, channel, notified_at) VALUES (?, ?, ?)",
        [(cert_id, channel, notified_at) for cert_id in cert_ids],
    )
