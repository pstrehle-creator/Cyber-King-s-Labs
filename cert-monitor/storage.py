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
    last_alert_key TEXT,
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
"""


def connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA)
    return conn


def upsert_target(conn: sqlite3.Connection, hostname: str, port: int) -> int:
    conn.execute(
        "INSERT OR IGNORE INTO targets (hostname, port) VALUES (?, ?)", (hostname, port)
    )
    row = conn.execute(
        "SELECT id FROM targets WHERE hostname = ? AND port = ?", (hostname, port)
    ).fetchone()
    return row["id"]


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


def get_last_alert_key(conn: sqlite3.Connection, target_id: int) -> str | None:
    row = conn.execute(
        "SELECT last_alert_key FROM targets WHERE id = ?", (target_id,)
    ).fetchone()
    return row["last_alert_key"]


def clear_last_alert_key(conn: sqlite3.Connection, target_id: int) -> None:
    conn.execute("UPDATE targets SET last_alert_key = NULL WHERE id = ?", (target_id,))


def record_alert(
    conn: sqlite3.Connection, target_id: int, alert_key: str, channel: str, sent_at: str
) -> None:
    conn.execute(
        "INSERT INTO alerts (target_id, alert_key, channel, sent_at) VALUES (?, ?, ?, ?)",
        (target_id, alert_key, channel, sent_at),
    )
    conn.execute(
        "UPDATE targets SET last_alert_key = ? WHERE id = ?", (alert_key, target_id)
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
