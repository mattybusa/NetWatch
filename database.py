# ══════════════════════════════════════════════════════════════════════════════
# NetWatch — database.py
# All SQLite database operations: initialization, logging, and queries.
# Other modules import from here — nothing else touches the DB directly.
# ══════════════════════════════════════════════════════════════════════════════

import sqlite3
import logging
import structlog
import os
from datetime import datetime

import config

NETWATCH_DIR = os.path.dirname(os.path.abspath(__file__))

log = structlog.get_logger().bind(service="monitor")

# Database file lives in the netwatch project directory
DB_PATH = os.path.join(NETWATCH_DIR, "netwatch.db")


# ══════════════════════════════════════════════════════════════════════════════
# INITIALIZATION
# ══════════════════════════════════════════════════════════════════════════════

def init_db():
    """
    Create all tables if they don't already exist.
    Safe to call on every startup — will not overwrite existing data.
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Health checks: one row per network check cycle
    c.execute("""
        CREATE TABLE IF NOT EXISTS network_health (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp    TEXT NOT NULL,
            lan_ok       INTEGER,        -- 1 = gateway reachable, 0 = not
            wan_ok       INTEGER,        -- 1 = internet reachable, 0 = not
            wifi_ok      INTEGER,        -- 1 = AP gateway reachable, 0 = not
            dns_ok       INTEGER,        -- 1 = DNS resolution works, 0 = not
            latency_ms   REAL,           -- Average WAN ping latency
            packet_loss  REAL,           -- WAN packet loss percentage
            healthy      INTEGER         -- 1 = fully healthy, 0 = any issue
        )
    """)

    # Reset events: one row each time a power cycle is performed
    c.execute("""
        CREATE TABLE IF NOT EXISTS reset_events (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp    TEXT NOT NULL,
            reset_type   TEXT,           -- 'full', 'modem_only', 'router_only'
            reason       TEXT,           -- Human-readable reason for the reset
            triggered_by TEXT,           -- 'auto', 'button', 'web'
            success      INTEGER         -- 1 = completed without error
        )
    """)

    # Speedtest results: one row per speedtest run
    c.execute("""
        CREATE TABLE IF NOT EXISTS speedtest_results (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp      TEXT NOT NULL,
            ping_ms        REAL,
            download_mbps  REAL,
            upload_mbps    REAL,
            server         TEXT           -- Name of the speedtest server used
        )
    """)

    # Alerts: log of all alerts generated, whether email succeeded or not
    c.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp    TEXT NOT NULL,
            alert_type   TEXT,           -- 'outage', 'restored', 'reset', etc.
            message      TEXT,
            sent         INTEGER DEFAULT 0  -- 1 = email successfully sent
        )
    """)

    # Per-user UI preferences (collapse state, row counts, etc.)
    c.execute("""
        CREATE TABLE IF NOT EXISTS user_prefs (
            user_id      INTEGER NOT NULL,
            pref_key     TEXT    NOT NULL,
            pref_value   TEXT,
            PRIMARY KEY (user_id, pref_key)
        )
    """)

    conn.commit()
    conn.close()
    log.info("Database initialized", path=DB_PATH)


# ══════════════════════════════════════════════════════════════════════════════
# WRITE OPERATIONS
# ══════════════════════════════════════════════════════════════════════════════

def log_health(lan_ok, wan_ok, wifi_ok, dns_ok, latency_ms, packet_loss):
    """Record the result of one network health check cycle."""
    healthy = 1 if (lan_ok and wan_ok and dns_ok) else 0
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("""
            INSERT INTO network_health
                (timestamp, lan_ok, wan_ok, wifi_ok, dns_ok, latency_ms, packet_loss, healthy)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f"),
            int(lan_ok), int(wan_ok), int(wifi_ok), int(dns_ok),
            latency_ms, packet_loss, healthy
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        log.error("Failed to log health record", error=str(e))


def log_reset(reset_type, reason, triggered_by="auto", success=True):
    """Record that a power cycle reset was performed."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("""
            INSERT INTO reset_events (timestamp, reset_type, reason, triggered_by, success)
            VALUES (?, ?, ?, ?, ?)
        """, (datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f"), reset_type, reason, triggered_by, int(success)))
        conn.commit()
        conn.close()
    except Exception as e:
        log.error("Failed to log reset event", error=str(e))


def log_speedtest(ping_ms, download_mbps, upload_mbps, server):
    """Record the results of a speedtest run."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("""
            INSERT INTO speedtest_results (timestamp, ping_ms, download_mbps, upload_mbps, server)
            VALUES (?, ?, ?, ?, ?)
        """, (datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f"), ping_ms, download_mbps, upload_mbps, server))
        conn.commit()
        conn.close()
    except Exception as e:
        log.error("Failed to log speedtest result", error=str(e))


def _redact_sensitive(message):
    """Strip credential values from alert messages before storage or display."""
    import re as _re
    # Redact temporary passwords from password reset alerts
    message = _re.sub(r'(Your temporary password is:\s*)\S+', r'\1[REDACTED]', message)
    # Redact MFA/verification codes — email format
    message = _re.sub(r'(Your NetWatch login verification code is:\s*)\S+', r'\1[REDACTED]', message)
    # Redact MFA/verification codes — SMS format
    message = _re.sub(r'(Your login code:\s*)\S+', r'\1[REDACTED]', message)
    return message


def log_alert(alert_type, message, sent=False):
    """Record an alert. Returns the row ID so it can be marked sent later."""
    try:
        message = _redact_sensitive(message)
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.execute("""
            INSERT INTO alerts (timestamp, alert_type, message, sent)
            VALUES (?, ?, ?, ?)
        """, (datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f"), alert_type, message, int(sent)))
        alert_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return alert_id
    except Exception as e:
        log.error("Failed to log alert", error=str(e))
        return None


def mark_alert_sent(alert_id):
    """Mark an alert record as successfully emailed."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("UPDATE alerts SET sent=1 WHERE id=?", (alert_id,))
        conn.commit()
        conn.close()
    except Exception as e:
        log.error("Failed to mark alert sent", error=str(e))


# ══════════════════════════════════════════════════════════════════════════════
# READ / QUERY OPERATIONS
# ══════════════════════════════════════════════════════════════════════════════

def get_latest_health():
    """Return the most recent health check record as a dict, or None."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM network_health ORDER BY timestamp DESC LIMIT 1"
        ).fetchone()
        conn.close()
        return dict(row) if row else None
    except Exception as e:
        log.error("Failed to get latest health", error=str(e))
        return None


def get_health_history(hours=24, start=None, end=None):
    """Return health records for the last N hours (or between start/end ISO timestamps), oldest first."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        if start and end:
            rows = conn.execute("""
                SELECT * FROM network_health
                WHERE timestamp >= ? AND timestamp <= ?
                ORDER BY timestamp ASC
            """, (start, end)).fetchall()
        else:
            rows = conn.execute("""
                SELECT * FROM network_health
                WHERE timestamp >= datetime('now', ?)
                ORDER BY timestamp ASC
            """, (f"-{hours} hours",)).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as e:
        log.error("Failed to get health history", error=str(e))
        return []


def get_reset_history(days=30):
    """Return reset events for the last N days, newest first."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT * FROM reset_events
            WHERE timestamp >= datetime('now', ?)
            ORDER BY timestamp DESC
        """, (f"-{days} days",)).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as e:
        log.error("Failed to get reset history", error=str(e))
        return []


def get_speedtest_history(days=7, hours=None, start=None, end=None):
    """Return speedtest results for the last N hours (or days, or between start/end), oldest first."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        if start and end:
            rows = conn.execute("""
                SELECT * FROM speedtest_results
                WHERE timestamp >= ? AND timestamp <= ?
                ORDER BY timestamp ASC
            """, (start, end)).fetchall()
        else:
            interval = f"-{hours} hours" if hours is not None else f"-{days} days"
            rows = conn.execute("""
                SELECT * FROM speedtest_results
                WHERE timestamp >= datetime('now', ?)
                ORDER BY timestamp ASC
            """, (interval,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as e:
        log.error("Failed to get speedtest history", error=str(e))
        return []


def get_alert_history(limit=50):
    """Return the most recent alerts, newest first."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?
        """, (limit,)).fetchall()
        conn.close()
        return [{**dict(r), "message": _redact_sensitive(r["message"] or "")} for r in rows]
    except Exception as e:
        log.error("Failed to get alert history", error=str(e))
        return []


def get_uptime_stats():
    """
    Return uptime percentage for four time windows.
    Result: {'1h': 99.5, '24h': 98.2, '7d': 97.1, '30d': 96.8}
    """
    results = {}
    try:
        conn = sqlite3.connect(DB_PATH)
        for label, hours in [("1h", 1), ("24h", 24), ("7d", 168), ("30d", 720)]:
            row = conn.execute("""
                SELECT
                    COUNT(*) as total,
                    SUM(CASE WHEN healthy=1 THEN 1 ELSE 0 END) as healthy
                FROM network_health
                WHERE timestamp >= datetime('now', ?)
            """, (f"-{hours} hours",)).fetchone()
            total   = row[0] or 0
            healthy = row[1] or 0
            results[label] = round((healthy / total * 100) if total > 0 else 0, 2)
        conn.close()
    except Exception as e:
        log.error("Failed to get uptime stats", error=str(e))
    return results


def get_reset_count_today():
    """Return the number of automatic resets performed today."""
    try:
        conn = sqlite3.connect(DB_PATH)
        today = datetime.now().date().isoformat()
        row = conn.execute("""
            SELECT COUNT(*) FROM reset_events
            WHERE timestamp LIKE ? AND triggered_by='auto'
        """, (today + "%",)).fetchone()
        conn.close()
        return row[0] if row else 0
    except Exception as e:
        log.error("Failed to get reset count", error=str(e))
        return 0


def get_last_reset():
    """Return the most recent reset event as a dict, or None."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM reset_events ORDER BY timestamp DESC LIMIT 1"
        ).fetchone()
        conn.close()
        return dict(row) if row else None
    except Exception as e:
        log.error("Failed to get last reset", error=str(e))
        return None


def get_last_speedtest():
    """Return the most recent speedtest result as a dict, or None."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM speedtest_results ORDER BY timestamp DESC LIMIT 1"
        ).fetchone()
        conn.close()
        return dict(row) if row else None
    except Exception as e:
        log.error("Failed to get last speedtest", error=str(e))
        return None


def get_speedtest_avg(days=None):
    """
    Return average download_mbps, upload_mbps, and ping_ms over the last N days.
    Pass days=None for all-time averages.
    Returns a dict with keys: download_mbps, upload_mbps, ping_ms, count.
    All values are None if no records exist in the window.
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        if days is None:
            row = conn.execute("""
                SELECT AVG(download_mbps), AVG(upload_mbps), AVG(ping_ms), COUNT(*)
                FROM speedtest_results
            """).fetchone()
        else:
            row = conn.execute("""
                SELECT AVG(download_mbps), AVG(upload_mbps), AVG(ping_ms), COUNT(*)
                FROM speedtest_results
                WHERE timestamp >= datetime('now', ?)
            """, (f"-{days} days",)).fetchone()
        conn.close()
        if not row or row[3] == 0:
            return {"download_mbps": None, "upload_mbps": None, "ping_ms": None, "count": 0}
        return {
            "download_mbps": round(row[0], 1) if row[0] is not None else None,
            "upload_mbps":   round(row[1], 1) if row[1] is not None else None,
            "ping_ms":       round(row[2], 0) if row[2] is not None else None,
            "count":         row[3],
        }
    except Exception as e:
        log.error("Failed to get speedtest avg", error=str(e))
        return {"download_mbps": None, "upload_mbps": None, "ping_ms": None, "count": 0}


def get_reset_count(days=None):
    """
    Return the count of auto resets over the last N days.
    Pass days=None for all-time count.
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        if days is None:
            row = conn.execute(
                "SELECT COUNT(*) FROM reset_events WHERE triggered_by='auto'"
            ).fetchone()
        else:
            row = conn.execute("""
                SELECT COUNT(*) FROM reset_events
                WHERE triggered_by='auto'
                AND timestamp >= datetime('now', ?)
            """, (f"-{days} days",)).fetchone()
        conn.close()
        return row[0] if row else 0
    except Exception as e:
        log.error("Failed to get reset count", error=str(e))
        return 0


# ══════════════════════════════════════════════════════════════════════════════
# MAINTENANCE
# ══════════════════════════════════════════════════════════════════════════════

def prune_old_records():
    """
    Delete records older than the retention limits set in config.py.
    Called periodically by the monitor to keep the database from growing forever.
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "DELETE FROM network_health WHERE timestamp < datetime('now', ?)",
            (f"-{config.KEEP_HEALTH_DAYS} days",)
        )
        conn.execute(
            "DELETE FROM reset_events WHERE timestamp < datetime('now', ?)",
            (f"-{config.KEEP_RESET_DAYS} days",)
        )
        conn.execute(
            "DELETE FROM speedtest_results WHERE timestamp < datetime('now', ?)",
            (f"-{config.KEEP_SPEEDTEST_DAYS} days",)
        )
        conn.commit()
        conn.close()
        log.debug("Old database records pruned")
    except Exception as e:
        log.error("Failed to prune old records", error=str(e))


def get_db_stats():
    """Return row counts and file size for admin dashboard."""
    stats = {}
    try:
        conn = sqlite3.connect(DB_PATH)
        for table in ["network_health", "reset_events", "speedtest_results", "alerts"]:
            row = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
            stats[table] = row[0]
        conn.close()
    except Exception as e:
        log.error("Failed to get DB stats", error=str(e))
    stats["db_size_kb"] = round(os.path.getsize(DB_PATH) / 1024, 1) if os.path.exists(DB_PATH) else 0
    return stats


def get_system_health_stats():
    """Return monitor heartbeat age and disk space for the system health card.

    Returns a dict with:
      last_record_ts  -- ISO timestamp of most recent network_health row, or None
      age_seconds     -- seconds since last record (float), or None if no records
      expected_interval -- config.CHECK_INTERVAL (seconds)
      overdue         -- True if age > 2.5× expected interval, False otherwise
      disk_free_gb    -- free disk space in GB on the netwatch partition
      disk_free_pct   -- free disk space as a percentage of total
    """
    import shutil
    stats = {
        "last_record_ts":   None,
        "age_seconds":      None,
        "expected_interval": getattr(config, "CHECK_INTERVAL", 30),
        "overdue":          False,
        "disk_free_gb":     None,
        "disk_free_pct":    None,
    }
    try:
        conn = sqlite3.connect(DB_PATH)
        row  = conn.execute(
            "SELECT timestamp FROM network_health ORDER BY timestamp DESC LIMIT 1"
        ).fetchone()
        conn.close()
        if row:
            stats["last_record_ts"] = row[0]
            # Parse stored UTC timestamp (space-separated, no 'T')
            last_dt = datetime.strptime(row[0], "%Y-%m-%d %H:%M:%S.%f")
            age = (datetime.utcnow() - last_dt).total_seconds()
            stats["age_seconds"] = round(age, 1)
            stats["overdue"] = age > 2.5 * stats["expected_interval"]
    except Exception as e:
        log.error("Failed to get monitor heartbeat", error=str(e))
    try:
        usage = shutil.disk_usage(NETWATCH_DIR)
        stats["disk_free_gb"]  = round(usage.free  / (1024 ** 3), 1)
        stats["disk_free_pct"] = round(usage.free  / usage.total * 100, 0)
    except Exception as e:
        log.error("Failed to get disk usage", error=str(e))
    return stats


def clear_health_records(older_than_days):
    """Delete health records older than specified days. Used by admin dashboard."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "DELETE FROM network_health WHERE timestamp < datetime('now', ?)",
            (f"-{older_than_days} days",)
        )
        conn.commit()
        conn.close()
        log.info("Cleared health records", older_than_days=older_than_days)
    except Exception as e:
        log.error("Failed to clear health records", error=str(e))

def get_user_pref(user_id, key):
    """Return the stored value for a user preference key, or None."""
    try:
        conn = sqlite3.connect(DB_PATH)
        row = conn.execute(
            "SELECT pref_value FROM user_prefs WHERE user_id=? AND pref_key=?",
            (user_id, key)
        ).fetchone()
        conn.close()
        return row[0] if row else None
    except Exception as e:
        log.error("get_user_pref failed", error=str(e))
        return None


def set_user_pref(user_id, key, value):
    """Upsert a user preference value. Pass value=None to delete the preference."""
    try:
        conn = sqlite3.connect(DB_PATH)
        if value is None:
            conn.execute(
                "DELETE FROM user_prefs WHERE user_id=? AND pref_key=?",
                (user_id, key)
            )
        else:
            conn.execute(
                """INSERT INTO user_prefs (user_id, pref_key, pref_value)
                   VALUES (?, ?, ?)
                   ON CONFLICT(user_id, pref_key) DO UPDATE SET pref_value=excluded.pref_value""",
                (user_id, key, value)
            )
        conn.commit()
        conn.close()
    except Exception as e:
        log.error("set_user_pref failed", error=str(e))
