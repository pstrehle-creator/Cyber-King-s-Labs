"""SQLite persistence for cert-monitor: targets, check history, and sent alerts."""

from __future__ import annotations

import json
import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY,
    hostname TEXT NOT NULL,
    port INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
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
    PRIMARY KEY (target_id, channel)
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
    _migrate_phase2_alert_state(conn)
    return conn


def _migrate_phase2_alert_state(conn: sqlite3.Connection) -> None:
    """Phase 2 databases tracked a single alert state per target (email only)
    in targets.last_alert_key. Move it into alert_state and null it out so this
    runs once; the column is left in place for older SQLite versions."""
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(targets)")}
    if "last_alert_key" not in columns:
        return
    conn.execute(
        """
        INSERT OR IGNORE INTO alert_state (target_id, channel, alert_key)
        SELECT id, 'email', last_alert_key FROM targets WHERE last_alert_key IS NOT NULL
        """
    )
    conn.execute("UPDATE targets SET last_alert_key = NULL")
    conn.commit()


def upsert_target(conn: sqlite3.Connection, hostname: str, port: int) -> int:
    conn.execute(
        "INSERT OR IGNORE INTO targets (hostname, port) VALUES (?, ?)", (hostname, port)
    )
    row = conn.execute(
        "SELECT id FROM targets WHERE hostname = ? AND port = ?", (hostname, port)
    ).fetchone()
    return row["id"]


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


def clear_alert_state(conn: sqlite3.Connection, target_id: int) -> None:
    conn.execute("DELETE FROM alert_state WHERE target_id = ?", (target_id,))


def record_alert(
    conn: sqlite3.Connection, target_id: int, alert_key: str, channel: str, sent_at: str
) -> None:
    conn.execute(
        "INSERT INTO alerts (target_id, alert_key, channel, sent_at) VALUES (?, ?, ?, ?)",
        (target_id, alert_key, channel, sent_at),
    )
    conn.execute(
        "INSERT OR REPLACE INTO alert_state (target_id, channel, alert_key) VALUES (?, ?, ?)",
        (target_id, channel, alert_key),
    )


def latest_checks(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        """
        SELECT t.hostname, t.port, c.*
        FROM checks c
        JOIN targets t ON t.id = c.target_id
        WHERE c.id = (SELECT MAX(id) FROM checks WHERE target_id = c.target_id)
        ORDER BY c.days_remaining IS NULL, c.days_remaining
        """
    ).fetchall()


def target_history(
    conn: sqlite3.Connection, hostname: str, port: int, limit: int
) -> list[sqlite3.Row]:
    return conn.execute(
        """
        SELECT t.hostname, t.port, c.*
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
