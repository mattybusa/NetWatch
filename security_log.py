# ══════════════════════════════════════════════════════════════════════════════
# NetWatch — security_log.py
# Records security events: logins, failures, lockouts, config changes, etc.
# ══════════════════════════════════════════════════════════════════════════════

import os
import sqlite3
import logging
import structlog
from datetime import datetime, timedelta

NETWATCH_DIR = os.path.dirname(os.path.abspath(__file__))

log = structlog.get_logger().bind(service="web")

DB_PATH = os.path.join(NETWATCH_DIR, "netwatch.db")

# Event types
LOGIN_OK       = "login_ok"
LOGIN_FAIL     = "login_fail"
LOGIN_DISABLED = "login_disabled"    # Valid creds but account disabled
LOGOUT         = "logout"
PASSWORD_CHANGE = "password_change"
PASSWORD_RESET  = "password_reset"   # Admin reset another user's password
USER_CREATED    = "user_created"
USER_DELETED    = "user_deleted"
RELAY_TRIGGER   = "relay_trigger"
CONFIG_CHANGE   = "config_change"
SESSION_EXPIRED = "session_expired"

BRUTE_FORCE_THRESHOLD = 5   # failures within window triggers alert
BRUTE_FORCE_WINDOW    = 300 # seconds (5 minutes)


def _connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_security_db():
    """Create security_events table. Safe to call on every startup."""
    conn = _connect()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            event_type  TEXT NOT NULL,
            username    TEXT,           -- Username involved (attempted or actual)
            ip_address  TEXT,           -- Client IP
            detail      TEXT,           -- Human-readable detail
            success     INTEGER         -- 1=success, 0=failure, NULL=N/A
        )
    """)
    conn.commit()
    conn.close()


def record(event_type, username=None, ip_address=None, detail=None, success=None):
    """Record a security event."""
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    try:
        conn = _connect()
        conn.execute("""
            INSERT INTO security_events (timestamp, event_type, username, ip_address, detail, success)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (ts, event_type, username, ip_address, detail, success))
        conn.commit()
        conn.close()
        log.info("Security event", event_type=event_type, username=username, ip_address=ip_address, detail=detail)
    except Exception as e:
        log.error("security_log.record failed", error=str(e))


def check_brute_force(username, ip_address):
    """
    Check if recent failures exceed threshold.
    Returns (is_brute_force, failure_count) tuple.
    Checks both per-username and per-IP.
    """
    window_start = (datetime.utcnow() - timedelta(seconds=BRUTE_FORCE_WINDOW)
                    ).strftime("%Y-%m-%d %H:%M:%S")
    try:
        conn = _connect()
        # Failures for this username OR this IP in the window
        count = conn.execute("""
            SELECT COUNT(*) FROM security_events
            WHERE event_type=? AND timestamp >= ?
            AND (username=? OR ip_address=?)
            AND success=0
        """, (LOGIN_FAIL, window_start, username, ip_address)).fetchone()[0]
        conn.close()
        return count >= BRUTE_FORCE_THRESHOLD, count
    except Exception as e:
        log.error("check_brute_force failed", error=str(e))
        return False, 0


def get_events(limit=100, event_types=None, since=None):
    """Return recent security events, newest first.
    since: optional ISO timestamp string — only return events at or after this time.
    """
    conn = _connect()
    conditions = []
    params = []

    if event_types:
        placeholders = ",".join("?" * len(event_types))
        conditions.append(f"event_type IN ({placeholders})")
        params.extend(event_types)

    if since:
        conditions.append("timestamp >= ?")
        params.append(since)

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    params.append(limit)

    rows = conn.execute(f"""
        SELECT * FROM security_events
        {where}
        ORDER BY timestamp DESC LIMIT ?
    """, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_recent_failures(minutes=60):
    """Return login failures in the last N minutes."""
    since = (datetime.utcnow() - timedelta(minutes=minutes)
             ).strftime("%Y-%m-%d %H:%M:%S")
    conn = _connect()
    rows = conn.execute("""
        SELECT * FROM security_events
        WHERE event_type=? AND timestamp>=? AND success=0
        ORDER BY timestamp DESC
    """, (LOGIN_FAIL, since)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def prune(days=90):
    """Remove security events older than N days."""
    cutoff = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    conn = _connect()
    conn.execute("DELETE FROM security_events WHERE timestamp<?", (cutoff,))
    conn.commit()
    conn.close()
