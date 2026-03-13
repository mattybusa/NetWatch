# ══════════════════════════════════════════════════════════════════════════════
# NetWatch — alert_subscribers.py
# Manages who receives alerts, via which channel, and for which alert types.
# ══════════════════════════════════════════════════════════════════════════════

import os
import json
import logging
import sqlite3
from datetime import datetime

NETWATCH_DIR = os.path.dirname(os.path.abspath(__file__))

log = logging.getLogger("netwatch.subscribers")

DB_PATH = os.path.join(NETWATCH_DIR, "netwatch.db")

# ── SMS carrier gateways ───────────────────────────────────────────────────────
CARRIERS = [
    {"id": "verizon",   "name": "Verizon",    "domain": "vtext.com"},
    {"id": "att",       "name": "AT&T",        "domain": "txt.att.net"},
    {"id": "tmobile",   "name": "T-Mobile",    "domain": "tmomail.net"},
    {"id": "sprint",    "name": "Sprint",      "domain": "messaging.sprintpcs.com"},
    {"id": "uscellular","name": "US Cellular", "domain": "email.uscc.net"},
    {"id": "cricket",   "name": "Cricket",     "domain": "sms.cricketwireless.net"},
    {"id": "boost",     "name": "Boost",       "domain": "sms.myboostmobile.com"},
    {"id": "metropcs",  "name": "Metro PCS",   "domain": "mymetropcs.com"},
    {"id": "custom",    "name": "Other (custom domain)", "domain": ""},
]
CARRIER_BY_ID = {c["id"]: c for c in CARRIERS}

# ── Alert types and global defaults ───────────────────────────────────────────
ALERT_TYPES = [
    # ── Network alerts ─────────────────────────────────────────────────────────
    {"key": "outage",            "label": "Network Outage",       "group": "network",  "default_email": True,  "default_sms": True,  "critical": True},
    {"key": "restored",          "label": "Network Restored",     "group": "network",  "default_email": True,  "default_sms": True,  "critical": True},
    {"key": "reset_performed",   "label": "Device Reset",         "group": "network",  "default_email": True,  "default_sms": False, "critical": False},
    {"key": "degraded",          "label": "Degraded Performance", "group": "network",  "default_email": True,  "default_sms": False, "critical": False},
    {"key": "conservative_mode", "label": "Max Resets Reached",   "group": "network",  "default_email": True,  "default_sms": True,  "critical": True},
    {"key": "daily_summary",     "label": "Daily Summary",        "group": "network",  "default_email": True,  "default_sms": False, "critical": False},
    {"key": "test",              "label": "Test Alert",           "group": "network",  "default_email": True,  "default_sms": True,  "critical": False},
    # ── Security alerts — owner/admin only by default ──────────────────────────
    {"key": "brute_force",       "label": "Brute Force Attempt",  "group": "security",    "default_email": False, "default_sms": False, "critical": True},
    {"key": "lockout_changed",   "label": "Lockout Mode Changed", "group": "security",    "default_email": False, "default_sms": False, "critical": False},
    {"key": "security_event",    "label": "Security Event",       "group": "security",    "default_email": False, "default_sms": False, "critical": False},
    # ── Maintenance alerts ──────────────────────────────────────────────────────
    {"key": "pkg_update",        "label": "Pi Package Update",    "group": "maintenance", "default_email": False, "default_sms": False, "critical": False},
]
ALERT_TYPE_KEYS = [a["key"] for a in ALERT_TYPES]


def _connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_subscribers_db():
    """Create subscriber tables. Safe to call on every startup."""
    conn = _connect()
    c = conn.cursor()

    # Global alert type settings — which types go to email/SMS by default
    c.execute("""
        CREATE TABLE IF NOT EXISTS alert_type_settings (
            alert_type   TEXT PRIMARY KEY,
            email_enabled INTEGER DEFAULT 1,
            sms_enabled   INTEGER DEFAULT 0
        )
    """)

    # Per-user subscriber records
    c.execute("""
        CREATE TABLE IF NOT EXISTS alert_subscribers (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id         INTEGER,           -- NULL for non-user subscribers
            username        TEXT,              -- Display name
            email_address   TEXT,              -- Email delivery address (or NULL)
            email_enabled   INTEGER DEFAULT 0,
            sms_phone       TEXT,              -- 10-digit phone number (or NULL)
            sms_carrier     TEXT,              -- Carrier ID from CARRIERS list
            sms_custom_domain TEXT,            -- Used when carrier = 'custom'
            sms_enabled     INTEGER DEFAULT 0,
            alert_overrides TEXT DEFAULT '{}', -- JSON: {alert_type: {email, sms}}
            created_at      TEXT NOT NULL,
            is_owner        INTEGER DEFAULT 0  -- 1 = system owner (linked to config)
        )
    """)

    # Seed global alert type settings from defaults if not already present
    for atype in ALERT_TYPES:
        c.execute("""
            INSERT OR IGNORE INTO alert_type_settings (alert_type, email_enabled, sms_enabled)
            VALUES (?, ?, ?)
        """, (atype["key"], int(atype["default_email"]), int(atype["default_sms"])))

    # Add first_name/last_name columns to existing databases
    for col in ["first_name", "last_name"]:
        try:
            c.execute(f"ALTER TABLE alert_subscribers ADD COLUMN {col} TEXT DEFAULT NULL")
        except Exception:
            pass

    # Per-role alert defaults — seeded when roles are created, deleted when roles are deleted
    c.execute("""
        CREATE TABLE IF NOT EXISTS role_alert_defaults (
            role_id       INTEGER NOT NULL,
            alert_type    TEXT    NOT NULL,
            email_enabled INTEGER DEFAULT 1,
            sms_enabled   INTEGER DEFAULT 0,
            PRIMARY KEY (role_id, alert_type)
        )
    """)

    # Per-recipient delivery log — written by alerts.py for each send attempt
    c.execute("""
        CREATE TABLE IF NOT EXISTS alert_deliveries (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            sent_at       TEXT    NOT NULL,
            alert_type    TEXT    NOT NULL,
            alert_event   TEXT,             -- human-readable event message
            subscriber_id INTEGER,
            channel       TEXT    NOT NULL, -- 'email' or 'sms'
            address       TEXT    NOT NULL,
            success       INTEGER DEFAULT 0,
            error_msg     TEXT,
            is_test       INTEGER DEFAULT 0
        )
    """)

    conn.commit()
    conn.close()


def seed_owner(username, email_address, alert_to=None):
    """
    Ensure the system owner subscriber record exists and is current.
    Called at startup — always syncs username and email from config.
    """
    conn = _connect()
    existing = conn.execute(
        "SELECT id FROM alert_subscribers WHERE is_owner=1"
    ).fetchone()

    if existing:
        conn.execute("""
            UPDATE alert_subscribers
            SET username=?, email_address=?, email_enabled=1
            WHERE is_owner=1
        """, (username, alert_to or email_address))
    else:
        conn.execute("""
            INSERT INTO alert_subscribers
            (username, email_address, email_enabled, sms_enabled,
             alert_overrides, created_at, is_owner)
            VALUES (?, ?, 1, 0, '{}', ?, 1)
        """, (username, alert_to or email_address,
              datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")))

    conn.commit()
    conn.close()


def get_all_subscribers():
    """Return all subscriber records."""
    conn = _connect()
    rows = conn.execute(
        "SELECT * FROM alert_subscribers ORDER BY is_owner DESC, username"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_subscriber_by_user_id(user_id):
    """Return subscriber record for a given user_id."""
    conn = _connect()
    row = conn.execute(
        "SELECT * FROM alert_subscribers WHERE user_id=?", (user_id,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def get_subscriber_by_username(username):
    """Return subscriber record matched by username (used for owner fallback)."""
    conn = _connect()
    row = conn.execute(
        "SELECT * FROM alert_subscribers WHERE username=? ORDER BY is_owner DESC LIMIT 1",
        (username,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def get_subscriber_by_id(sub_id):
    conn = _connect()
    row = conn.execute(
        "SELECT * FROM alert_subscribers WHERE id=?", (sub_id,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def cleanup_duplicate_owner():
    """
    If a non-owner record exists for the same user as the owner,
    merge it into the owner record and delete the duplicate.
    Called at startup.
    """
    conn = _connect()
    owner = conn.execute(
        "SELECT * FROM alert_subscribers WHERE is_owner=1"
    ).fetchone()
    if not owner:
        conn.close()
        return

    owner = dict(owner)
    # Find any non-owner record with same username or user_id
    dup = conn.execute("""
        SELECT * FROM alert_subscribers
        WHERE is_owner=0 AND (username=? OR (user_id IS NOT NULL AND user_id=?))
    """, (owner["username"], owner.get("user_id"))).fetchone()

    if dup:
        dup = dict(dup)
        # Merge: prefer non-owner values if they're more complete
        update_fields = {}
        for field in ["user_id", "email_address", "email_enabled",
                      "sms_phone", "sms_carrier", "sms_custom_domain",
                      "sms_enabled", "alert_overrides"]:
            owner_val = owner.get(field)
            dup_val   = dup.get(field)
            # Use dup value if owner has none, otherwise keep owner
            if not owner_val and dup_val:
                update_fields[field] = dup_val
            else:
                update_fields[field] = owner_val

        conn.execute("""
            UPDATE alert_subscribers SET
                user_id=?, email_address=?, email_enabled=?,
                sms_phone=?, sms_carrier=?, sms_custom_domain=?,
                sms_enabled=?, alert_overrides=?
            WHERE is_owner=1
        """, (update_fields["user_id"], update_fields["email_address"],
              update_fields["email_enabled"], update_fields["sms_phone"],
              update_fields["sms_carrier"], update_fields["sms_custom_domain"],
              update_fields["sms_enabled"], update_fields["alert_overrides"]))

        conn.execute("DELETE FROM alert_subscribers WHERE id=? AND is_owner=0", (dup["id"],))
        conn.commit()
        log.info(f"Merged duplicate subscriber record for owner '{owner['username']}'")

    conn.close()


def get_display_name(subscriber):
    """Return the best available display name for a subscriber.
    Priority: first_name > username > 'there'
    """
    if subscriber.get("first_name"):
        return subscriber["first_name"]
    if subscriber.get("username"):
        return subscriber["username"]
    return "there"


def backfill_account_subscribers():
    """
    Ensure every user account has at least a stub subscriber record.
    Called at startup. Safe to run repeatedly — skips users who already have one.
    """
    import sqlite3 as _sq
    import os as _os
    from pathlib import Path as _Path

    # Resolve the users table from the auth DB (same directory as subscribers)
    db_path = _Path(__file__).parent / "netwatch.db"
    conn = _connect()

    users_conn = _sq.connect(str(db_path))
    users_conn.row_factory = _sq.Row
    users = users_conn.execute(
        "SELECT id, username, first_name, last_name FROM users WHERE is_active=1"
    ).fetchall()
    users_conn.close()

    seeded = 0
    for u in users:
        existing = conn.execute(
            "SELECT id FROM alert_subscribers WHERE user_id=?", (u["id"],)
        ).fetchone()
        if not existing:
            conn.execute("""
                INSERT INTO alert_subscribers
                    (user_id, username, first_name, last_name,
                     email_address, email_enabled,
                     sms_phone, sms_carrier, sms_custom_domain, sms_enabled,
                     alert_overrides, is_owner)
                VALUES (?, ?, ?, ?, '', 0, '', '', '', 0, '{}', 0)
            """, (u["id"], u["username"] or "", u["first_name"] or "", u["last_name"] or ""))
            seeded += 1

    if seeded:
        conn.commit()
        log.info(f"Backfilled {seeded} account subscriber record(s)")
    conn.close()


def upsert_subscriber(user_id, username, email_address, email_enabled,
                       sms_phone, sms_carrier, sms_custom_domain, sms_enabled,
                       alert_overrides=None, first_name=None, last_name=None):
    """Create or update a subscriber record for a user.
    If the user matches the owner record (by username), updates owner instead of creating duplicate.
    """
    overrides_json = json.dumps(alert_overrides or {})
    conn = _connect()

    # Check if this user is already the owner (match by username or user_id)
    owner = conn.execute(
        "SELECT id FROM alert_subscribers WHERE is_owner=1"
    ).fetchone()
    existing_by_uid = conn.execute(
        "SELECT id FROM alert_subscribers WHERE user_id=?", (user_id,)
    ).fetchone() if user_id else None

    # If owner exists and no separate user record yet, check if this is the owner user
    if owner and not existing_by_uid:
        owner_row = conn.execute(
            "SELECT username FROM alert_subscribers WHERE is_owner=1"
        ).fetchone()
        if owner_row and owner_row["username"] == username:
            # This user IS the owner — link and update the owner record
            conn.execute("""
                UPDATE alert_subscribers SET
                    user_id=?, email_address=?, email_enabled=?,
                    sms_phone=?, sms_carrier=?, sms_custom_domain=?,
                    sms_enabled=?, alert_overrides=?,
                    first_name=?, last_name=?
                WHERE is_owner=1
            """, (user_id, email_address, int(email_enabled),
                  sms_phone, sms_carrier, sms_custom_domain,
                  int(sms_enabled), overrides_json, first_name, last_name))
            conn.commit()
            conn.close()
            return

    if existing_by_uid:
        conn.execute("""
            UPDATE alert_subscribers SET
                username=?, email_address=?, email_enabled=?,
                sms_phone=?, sms_carrier=?, sms_custom_domain=?,
                sms_enabled=?, alert_overrides=?,
                first_name=?, last_name=?
            WHERE user_id=?
        """, (username, email_address, int(email_enabled),
              sms_phone, sms_carrier, sms_custom_domain,
              int(sms_enabled), overrides_json, first_name, last_name, user_id))
    else:
        conn.execute("""
            INSERT INTO alert_subscribers
            (user_id, username, email_address, email_enabled, sms_phone,
             sms_carrier, sms_custom_domain, sms_enabled, alert_overrides,
             first_name, last_name, created_at, is_owner)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
        """, (user_id, username, email_address, int(email_enabled),
              sms_phone, sms_carrier, sms_custom_domain,
              int(sms_enabled), overrides_json, first_name, last_name,
              datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")))

    conn.commit()
    conn.close()


def check_duplicate_contact(email_address=None, sms_phone=None, exclude_user_id=None):
    """
    Check if an email or phone already exists in ANY subscriber record.
    Returns (conflict_dict, conflict_type) where conflict_type is 'account' or 'standalone',
    or (None, None) if no conflict.
    """
    conn = _connect()
    conflict = None
    conflict_type = None

    email = (email_address or "").strip()
    if email:
        row = conn.execute(
            "SELECT * FROM alert_subscribers WHERE email_address=?", (email,)
        ).fetchone()
        if row:
            d = dict(row)
            if exclude_user_id is None or d.get("user_id") != exclude_user_id:
                conflict = d
                conflict_type = "account" if d.get("user_id") else "standalone"

    if not conflict and sms_phone:
        digits = ''.join(c for c in sms_phone if c.isdigit())[-10:]
        if len(digits) == 10:
            row = conn.execute(
                "SELECT * FROM alert_subscribers WHERE sms_phone=?", (digits,)
            ).fetchone()
            if row:
                d = dict(row)
                if exclude_user_id is None or d.get("user_id") != exclude_user_id:
                    conflict = d
                    conflict_type = "account" if d.get("user_id") else "standalone"

    conn.close()
    return conflict, conflict_type


def find_standalone_by_email(email_address):
    """Find a standalone (no user_id) subscriber record matching an email address."""
    if not email_address:
        return None
    conn = _connect()
    row = conn.execute("""
        SELECT * FROM alert_subscribers
        WHERE email_address=? AND user_id IS NULL AND is_owner=0
    """, (email_address.strip(),)).fetchone()
    conn.close()
    return dict(row) if row else None


def merge_standalone_into_account(account_user_id, standalone_id):
    """
    Merge a standalone subscriber record into an account holder's subscriber record.
    Account holder's alert_overrides win. Standalone record is deleted after merge.
    Called when an account holder verifies an email that matched a standalone subscriber.
    """
    conn = _connect()

    # Get both records
    account_sub = conn.execute(
        "SELECT * FROM alert_subscribers WHERE user_id=?", (account_user_id,)
    ).fetchone()
    standalone  = conn.execute(
        "SELECT * FROM alert_subscribers WHERE id=? AND user_id IS NULL AND is_owner=0",
        (standalone_id,)
    ).fetchone()

    if not standalone:
        conn.close()
        return False, "Standalone record not found"

    if account_sub:
        # Account holder already has a subscriber record — account holder's overrides win
        # Just delete the standalone record
        conn.execute("DELETE FROM alert_subscribers WHERE id=?", (standalone_id,))
        log.info(f"Merged standalone subscriber {standalone_id} into account user_id={account_user_id} (account record existed)")
    else:
        # No account subscriber record yet — upgrade the standalone record to be account-linked
        conn.execute("""
            UPDATE alert_subscribers SET user_id=? WHERE id=? AND user_id IS NULL AND is_owner=0
        """, (account_user_id, standalone_id))
        log.info(f"Upgraded standalone subscriber {standalone_id} to account user_id={account_user_id}")

    conn.commit()
    conn.close()
    return True, "Merged"


def update_owner_subscription(email_address, email_enabled,
                               sms_phone, sms_carrier, sms_custom_domain,
                               sms_enabled, alert_overrides=None):
    """Update the owner subscriber record."""
    overrides_json = json.dumps(alert_overrides or {})
    conn = _connect()
    conn.execute("""
        UPDATE alert_subscribers SET
            email_address=?, email_enabled=?,
            sms_phone=?, sms_carrier=?, sms_custom_domain=?,
            sms_enabled=?, alert_overrides=?
        WHERE is_owner=1
    """, (email_address, int(email_enabled), sms_phone, sms_carrier,
          sms_custom_domain, int(sms_enabled), overrides_json))
    conn.commit()
    conn.close()


def delete_subscriber(sub_id):
    """Delete a subscriber (cannot delete the owner)."""
    conn = _connect()
    conn.execute(
        "DELETE FROM alert_subscribers WHERE id=? AND is_owner=0", (sub_id,)
    )
    conn.commit()
    conn.close()


def get_alert_type_settings():
    """Return global alert type settings as a dict keyed by alert_type."""
    conn = _connect()
    rows = conn.execute("SELECT * FROM alert_type_settings").fetchall()
    conn.close()
    return {r["alert_type"]: dict(r) for r in rows}


def update_alert_type_settings(settings):
    """
    Update global alert type settings.
    settings: dict of {alert_type: {email_enabled, sms_enabled}}
    """
    conn = _connect()
    for atype, vals in settings.items():
        conn.execute("""
            UPDATE alert_type_settings
            SET email_enabled=?, sms_enabled=?
            WHERE alert_type=?
        """, (int(vals.get("email_enabled", 1)),
              int(vals.get("sms_enabled", 0)), atype))
    conn.commit()
    conn.close()


def get_role_alert_defaults(role_id):
    """Return per-role alert defaults as {alert_type: {email_enabled, sms_enabled}}."""
    conn = _connect()
    rows = conn.execute(
        "SELECT * FROM role_alert_defaults WHERE role_id=?", (role_id,)
    ).fetchall()
    conn.close()
    return {r["alert_type"]: dict(r) for r in rows}


def get_all_role_alert_defaults():
    """Return all role alert defaults as {role_id: {alert_type: {email_enabled, sms_enabled}}}."""
    conn = _connect()
    rows = conn.execute("SELECT * FROM role_alert_defaults").fetchall()
    conn.close()
    result = {}
    for r in rows:
        rid = r["role_id"]
        if rid not in result:
            result[rid] = {}
        result[rid][r["alert_type"]] = dict(r)
    return result


def seed_role_alert_defaults(role_id):
    """
    Seed a fresh set of per-role alert defaults for a newly created role.
    Uses the current global alert_type_settings as the baseline.
    Safe to call multiple times — uses INSERT OR IGNORE.
    """
    conn = _connect()
    global_settings = conn.execute("SELECT * FROM alert_type_settings").fetchall()
    for row in global_settings:
        conn.execute("""
            INSERT OR IGNORE INTO role_alert_defaults (role_id, alert_type, email_enabled, sms_enabled)
            VALUES (?, ?, ?, ?)
        """, (role_id, row["alert_type"], row["email_enabled"], row["sms_enabled"]))
    conn.commit()
    conn.close()


def update_role_alert_defaults(role_id, settings):
    """
    Update per-role alert defaults.
    settings: dict of {alert_type: {email_enabled, sms_enabled}}
    """
    conn = _connect()
    for atype, vals in settings.items():
        conn.execute("""
            INSERT INTO role_alert_defaults (role_id, alert_type, email_enabled, sms_enabled)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(role_id, alert_type) DO UPDATE SET
                email_enabled=excluded.email_enabled,
                sms_enabled=excluded.sms_enabled
        """, (role_id, atype,
              int(vals.get("email_enabled", 1)),
              int(vals.get("sms_enabled", 0))))
    conn.commit()
    conn.close()


def delete_role_alert_defaults(role_id):
    """Delete all per-role alert defaults for a role (called when role is deleted)."""
    conn = _connect()
    conn.execute("DELETE FROM role_alert_defaults WHERE role_id=?", (role_id,))
    conn.commit()
    conn.close()


def log_delivery(alert_type, alert_event, subscriber_id, channel, address, success, error_msg=None, is_test=False):
    """Record a single per-recipient delivery attempt."""
    from datetime import datetime
    conn = _connect()
    conn.execute("""
        INSERT INTO alert_deliveries
            (sent_at, alert_type, alert_event, subscriber_id, channel, address, success, error_msg, is_test)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        alert_type, alert_event, subscriber_id,
        channel, address, int(success),
        error_msg, int(is_test)
    ))
    conn.commit()
    conn.close()


def get_delivery_history(limit=100, alert_type=None, subscriber_id=None, hours=None):
    """
    Return recent delivery history, newest first.
    Optionally filter by alert_type, subscriber_id, or time window (hours).
    Joins subscriber name for display.
    """
    conn = _connect()
    clauses, params = [], []
    if alert_type:
        clauses.append("d.alert_type=?"); params.append(alert_type)
    if subscriber_id:
        clauses.append("d.subscriber_id=?"); params.append(subscriber_id)
    if hours:
        clauses.append("d.sent_at >= datetime('now', ? || ' hours')"); params.append(f"-{int(hours)}")
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    rows = conn.execute(f"""
        SELECT d.*, s.username, s.first_name, s.last_name
        FROM alert_deliveries d
        LEFT JOIN alert_subscribers s ON d.subscriber_id = s.id
        {where}
        ORDER BY d.id DESC
        LIMIT ?
    """, params + [limit]).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_sms_address(subscriber):
    """Build the SMS gateway email address from subscriber record."""
    phone  = (subscriber.get("sms_phone") or "").strip()
    carrier = subscriber.get("sms_carrier") or ""
    if not phone:
        return None
    if carrier == "custom":
        domain = (subscriber.get("sms_custom_domain") or "").strip()
    else:
        c = CARRIER_BY_ID.get(carrier, {})
        domain = c.get("domain", "")
    if not domain:
        return None
    # Strip any non-digits from phone
    digits = "".join(ch for ch in phone if ch.isdigit())
    if len(digits) < 10:
        return None
    # Use last 10 digits (strips country code if entered)
    return f"{digits[-10:]}@{domain}"


def get_active_recipients(alert_type):
    """
    Return list of delivery targets for a given alert type.
    Resolution order: subscriber overrides > role defaults > global defaults.
    """
    global_settings   = get_alert_type_settings()
    global_email      = bool(global_settings.get(alert_type, {}).get("email_enabled", True))
    global_sms        = bool(global_settings.get(alert_type, {}).get("sms_enabled", False))
    all_role_defaults = get_all_role_alert_defaults()

    conn = _connect()
    subscribers = conn.execute("""
        SELECT s.*, u.role_id
        FROM alert_subscribers s
        LEFT JOIN users u ON s.user_id = u.id
    """).fetchall()
    conn.close()

    recipients = []
    for sub in subscribers:
        sub = dict(sub)
        overrides     = json.loads(sub.get("alert_overrides") or "{}")
        type_override = overrides.get(alert_type, {})

        role_id       = sub.get("role_id")
        role_defaults = all_role_defaults.get(role_id, {}).get(alert_type, {}) if role_id else {}
        role_email    = bool(role_defaults["email_enabled"]) if role_defaults else global_email
        role_sms      = bool(role_defaults["sms_enabled"])   if role_defaults else global_sms

        send_email = type_override["email"] if "email" in type_override else role_email
        send_sms   = type_override["sms"]   if "sms"   in type_override else role_sms

        if send_email and sub.get("email_enabled") and sub.get("email_address"):
            recipients.append({
                "address":       sub["email_address"],
                "channel":       "email",
                "subscriber_id": sub["id"],
                "username":      sub.get("username", ""),
                "first_name":    sub.get("first_name", ""),
                "last_name":     sub.get("last_name", ""),
            })

        if send_sms and sub.get("sms_enabled"):
            sms_addr = get_sms_address(sub)
            if sms_addr:
                recipients.append({
                    "address":       sms_addr,
                    "channel":       "sms",
                    "subscriber_id": sub["id"],
                    "username":      sub.get("username", ""),
                    "first_name":    sub.get("first_name", ""),
                    "last_name":     sub.get("last_name", ""),
                })

    return recipients
