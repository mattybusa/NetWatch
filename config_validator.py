# ══════════════════════════════════════════════════════════════════════════════
# NetWatch — config_validator.py
# Validates config.py against the master schema on startup.
# Adds any missing keys with safe defaults and records them so the
# dashboard can notify the user that new settings need attention.
# ══════════════════════════════════════════════════════════════════════════════

import os
import re
import logging
import structlog
import sqlite3
from datetime import datetime

NETWATCH_DIR = os.path.dirname(os.path.abspath(__file__))

log = structlog.get_logger().bind(service="web")

DB_PATH     = os.path.join(NETWATCH_DIR, "netwatch.db")
CONFIG_PATH = os.path.join(NETWATCH_DIR, "config.py")


def _init_notifications_table(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS config_notifications (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            key       TEXT NOT NULL,
            message   TEXT NOT NULL,
            created   TEXT NOT NULL,
            dismissed INTEGER NOT NULL DEFAULT 0
        )
    """)
    conn.commit()


def _get_config_keys():
    """Return a set of all keys currently defined in config.py."""
    if not os.path.exists(CONFIG_PATH):
        return set()
    with open(CONFIG_PATH, "r") as f:
        content = f.read()
    # Match top-level assignments: KEY = value
    return set(re.findall(r'^([A-Z_]+)\s*=', content, re.MULTILINE))


def _append_key_to_config(key, default, description):
    """Append a missing key to config.py with its default value and comment."""
    if isinstance(default, str):
        value_str = f'"{default}"'
    elif isinstance(default, bool):
        value_str = str(default)
    else:
        value_str = str(default)

    with open(CONFIG_PATH, "a") as f:
        f.write(f"\n\n# {description}\n# Added automatically by config validator\n")
        f.write(f"{key} = {value_str}\n")

    log.info("Config validator: added missing key", key=key, value=value_str)


def _record_notification(conn, key, message):
    """Record a config notification, avoiding duplicates."""
    existing = conn.execute(
        "SELECT id FROM config_notifications WHERE key=? AND dismissed=0",
        (key,)
    ).fetchone()
    if not existing:
        conn.execute(
            "INSERT INTO config_notifications (key, message, created, dismissed) VALUES (?,?,?,0)",
            (key, message, datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"))
        )


def validate():
    """
    Run config validation. Call this at webapp startup.
    Returns a list of notification messages for any issues found.
    """
    from config_schema import CONFIG_SCHEMA, SCHEMA_BY_KEY, UNCONFIGURED_VALUES

    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        _init_notifications_table(conn)
    except Exception as e:
        log.error("Config validator: cannot connect to DB", error=str(e))
        return []

    existing_keys = _get_config_keys()
    notifications = []

    for entry in CONFIG_SCHEMA:
        key         = entry["key"]
        default     = entry["default"]
        required    = entry["required"]
        description = entry["description"]
        label       = entry["label"]

        # Check if key is missing from config.py
        if key not in existing_keys:
            _append_key_to_config(key, default, description)
            msg = f"New setting added: {label} ({key}). Default value applied — review in Config Editor."
            _record_notification(conn, key, msg)
            notifications.append(msg)
            log.info("Config validator: added missing key", key=key)
            continue

        # Key exists — no further action needed here.
        # Placeholder/unconfigured detection is handled visually in the Config Editor.

    conn.commit()
    conn.close()
    return notifications


def get_pending_notifications():
    """Return all undismissed config notifications."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        _init_notifications_table(conn)
        rows = conn.execute(
            "SELECT * FROM config_notifications WHERE dismissed=0 ORDER BY created DESC"
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as e:
        log.error("Config validator: get_pending_notifications failed", error=str(e))
        return []


def dismiss_notification(notification_id):
    """Mark a notification as dismissed."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "UPDATE config_notifications SET dismissed=1 WHERE id=?",
            (notification_id,)
        )
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False


def dismiss_all_notifications():
    """Dismiss all pending config notifications."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("UPDATE config_notifications SET dismissed=1 WHERE dismissed=0")
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False


def remove_legacy_email_keys():
    """Remove old SMTP_*/ALERT_FROM/ALERT_EMAIL keys from config.py."""
    import re
    LEGACY_KEYS = {"SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASSWORD",
                   "ALERT_FROM", "ALERT_EMAIL"}
    if not os.path.exists(CONFIG_PATH):
        return
    with open(CONFIG_PATH, "r") as f:
        lines = f.readlines()

    new_lines = []
    skip_next_comment = False
    removed = []
    i = 0
    while i < len(lines):
        line = lines[i]
        # Check if this is a comment followed by a legacy key assignment
        stripped = line.strip()
        if stripped.startswith('#') and i + 1 < len(lines):
            next_line = lines[i + 1]
            next_key = next_line.split('=')[0].strip()
            if next_key in LEGACY_KEYS:
                removed.append(next_key)
                i += 2  # Skip comment + key line
                continue
        # Check if this line is a legacy key assignment (without preceding comment)
        key = stripped.split('=')[0].strip()
        if key in LEGACY_KEYS:
            removed.append(key)
            i += 1
            continue
        new_lines.append(line)
        i += 1

    if removed:
        with open(CONFIG_PATH, "w") as f:
            f.writelines(new_lines)
        log.info("Removed legacy email keys from config.py", keys=list(removed))


def migrate_email_keys():
    """
    One-time migration: consolidate legacy email keys to canonical ones.
    Reads SMTP_USER → writes to GMAIL_USER if GMAIL_USER is still placeholder.
    Reads SMTP_PASSWORD → writes to GMAIL_APP_PASSWORD if still placeholder.
    Reads ALERT_EMAIL → writes to ALERT_TO if ALERT_TO is still placeholder.
    Removes old keys from config.py.
    """
    import re
    PLACEHOLDER = {"your_email@gmail.com", "your_app_password_here", ""}

    if not os.path.exists(CONFIG_PATH):
        return

    with open(CONFIG_PATH, "r") as f:
        cfg = f.read()

    def get_val(key):
        m = re.search(r'^' + key + r'\s*=\s*["\']([^"\']*)["\']', cfg, re.MULTILINE)
        return m.group(1) if m else ""

    def set_val(content, key, value):
        return re.sub(r'^' + key + r'\s*=.*$', key + ' = "' + value + '"', content, flags=re.MULTILINE)

    def remove_key(content, key):
        # Remove the line and any comment line immediately before it
        pattern = r'(?m)^#[^\n]*\n' + key + r'\s*=.*\n?'
        return re.sub(pattern, '', content)

    changed = False

    # Migrate SMTP_USER → GMAIL_USER
    smtp_user  = get_val("SMTP_USER")
    gmail_user = get_val("GMAIL_USER")
    if smtp_user and smtp_user not in PLACEHOLDER and gmail_user in PLACEHOLDER:
        cfg = set_val(cfg, "GMAIL_USER", smtp_user)
        changed = True
        log.info("Migrated SMTP_USER to GMAIL_USER", smtp_user=smtp_user)

    # Migrate SMTP_PASSWORD → GMAIL_APP_PASSWORD
    smtp_pass  = get_val("SMTP_PASSWORD")
    gmail_pass = get_val("GMAIL_APP_PASSWORD")
    if smtp_pass and smtp_pass not in PLACEHOLDER and gmail_pass in PLACEHOLDER:
        cfg = set_val(cfg, "GMAIL_APP_PASSWORD", smtp_pass)
        changed = True
        log.info("Migrated SMTP_PASSWORD to GMAIL_APP_PASSWORD")

    # Migrate ALERT_EMAIL → ALERT_TO
    alert_email = get_val("ALERT_EMAIL")
    alert_to    = get_val("ALERT_TO")
    if alert_email and alert_email not in PLACEHOLDER and alert_to in PLACEHOLDER:
        cfg = set_val(cfg, "ALERT_TO", alert_email)
        changed = True
        log.info("Migrated ALERT_EMAIL to ALERT_TO", alert_email=alert_email)

    # Migrate ALERT_FROM → GMAIL_USER if still needed
    alert_from = get_val("ALERT_FROM")
    gmail_user2 = get_val("GMAIL_USER")
    if alert_from and alert_from not in PLACEHOLDER and gmail_user2 in PLACEHOLDER:
        cfg = set_val(cfg, "GMAIL_USER", alert_from)
        changed = True
        log.info("Migrated ALERT_FROM to GMAIL_USER", alert_from=alert_from)

    if changed:
        with open(CONFIG_PATH, "w") as f:
            f.write(cfg)
        log.info("Email key migration complete")


def cleanup_false_positives():
    """Remove incorrectly-flagged _unconfigured notifications."""
    try:
        conn = sqlite3.connect(DB_PATH)
        _init_notifications_table(conn)
        conn.execute("DELETE FROM config_notifications WHERE key LIKE '%_unconfigured'")
        conn.commit()
        conn.close()
    except Exception as e:
        log.error("cleanup_false_positives failed", error=str(e))


def get_unconfigured_keys():
    """
    Return a set of config keys that still have placeholder/default values
    AND are shown in the Config Editor. Used to display NEEDS SETUP badges.
    """
    from config_schema import UNCONFIGURED_VALUES
    import sys

    # Only flag keys that are actually shown in the Config Editor
    try:
        sys.path.insert(0, os.path.dirname(CONFIG_PATH))
        import configeditor
        editor_keys = {f["key"] for f in configeditor.FIELDS}
    except Exception:
        editor_keys = set()

    unconfigured = set()
    try:
        if not os.path.exists(CONFIG_PATH):
            return unconfigured
        with open(CONFIG_PATH, "r") as f:
            content = f.read()
        import re
        for match in re.finditer(r'^([A-Z_]+)\s*=\s*["\']([^"\']*)["\']', content, re.MULTILINE):
            key, value = match.group(1), match.group(2)
            if key in editor_keys and value in UNCONFIGURED_VALUES:
                unconfigured.add(key)
    except Exception as e:
        log.error("get_unconfigured_keys failed", error=str(e))
    return unconfigured
