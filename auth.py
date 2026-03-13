# ══════════════════════════════════════════════════════════════════════════════
# NetWatch — auth.py
# User authentication, role management, and session control.
#
# Design:
#   - Roles define permissions and session timeout
#   - Users are assigned exactly one role
#   - Passwords are hashed with bcrypt — never stored in plain text
#   - A built-in 'admin' role cannot be deleted (but can be edited)
#   - Default admin account is created on first run with a temporary password
#
# Permissions (each is a boolean toggle per role):
#   view_logs     — can view the logs page
#   use_controls  — can trigger resets, speedtest, lockout toggle
#   manage_admin  — can access admin panel, export data, clear records
#   manage_users  — can create/edit/delete users and roles (implies manage_admin)
#
# Session timeout is stored per role in minutes. 0 = never expire.
# ══════════════════════════════════════════════════════════════════════════════

import sqlite3
import logging
import os
from datetime import datetime, timedelta
from functools import wraps
from flask import session, redirect, url_for, request, flash

NETWATCH_DIR = os.path.dirname(os.path.abspath(__file__))

log = logging.getLogger("netwatch.auth")

DB_PATH = os.path.join(NETWATCH_DIR, "netwatch.db")

# ── Default password shown on first login — user is forced to change it ───────
DEFAULT_ADMIN_PASSWORD = "netwatch123"


# ══════════════════════════════════════════════════════════════════════════════
# DATABASE SETUP
# ══════════════════════════════════════════════════════════════════════════════

def init_auth_db():
    """
    Create users and roles tables if they don't exist.
    Seeds the default roles and admin account on first run.
    Called from main.py and webapp.py at startup.
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Roles table — each role has a set of permission flags and a timeout
    c.execute("""
        CREATE TABLE IF NOT EXISTS roles (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            name             TEXT UNIQUE NOT NULL,
            description      TEXT,
            view_logs        INTEGER DEFAULT 1,   -- Can view logs page
            use_controls     INTEGER DEFAULT 0,   -- Can trigger resets/speedtest
            manage_admin     INTEGER DEFAULT 0,   -- Can access admin panel
            manage_users     INTEGER DEFAULT 0,   -- Can manage users and roles
            session_minutes  INTEGER DEFAULT 480, -- Session timeout (0 = never)
            is_system        INTEGER DEFAULT 0    -- System roles cannot be deleted
        )
    """)

    # Users table
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            username         TEXT UNIQUE NOT NULL,
            password_hash    TEXT NOT NULL,
            role_id          INTEGER NOT NULL,
            created_at       TEXT NOT NULL,
            last_login       TEXT,
            must_change_pass INTEGER DEFAULT 0,   -- Force password change on next login
            is_active        INTEGER DEFAULT 1,   -- Disabled users cannot log in
            locked_until     TEXT,                -- NULL or ISO timestamp; temporary lock
            lockout_count    INTEGER DEFAULT 0,   -- # of lockouts in current window
            lockout_window_start TEXT,            -- When the lockout count window started
            reset_token_hash TEXT,                -- Hashed temp password for self-service reset
            reset_expires_at TEXT,                -- When temp password expires
            theme            TEXT DEFAULT 'dark-blue',  -- color scheme preference (internal key; UI label is "Color Scheme")
            layout           TEXT DEFAULT 'comfortable', -- UI layout preference
            nav_style        TEXT DEFAULT 'icons-labels',
            content_align    TEXT DEFAULT 'left',        -- Content alignment: left or center
            FOREIGN KEY (role_id) REFERENCES roles(id)
        )
    """)

    # Add preference columns to existing databases that don't have them yet
    for col, default in [
        ("theme",                "'dark-blue'"),
        ("layout",               "'comfortable'"),
        ("nav_style",            "'icons-labels'"),
        ("content_align",        "'left'"),
        ("locked_until",         "NULL"),
        ("lockout_count",        "0"),
        ("lockout_window_start", "NULL"),
        ("reset_token_hash",     "NULL"),
        ("reset_expires_at",     "NULL"),
        ("first_name",           "NULL"),
        ("last_name",            "NULL"),
    ]:
        try:
            c.execute(f"ALTER TABLE users ADD COLUMN {col} TEXT DEFAULT {default}")
        except Exception:
            pass

    # Email verification table
    c.execute("""
        CREATE TABLE IF NOT EXISTS email_verifications (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            email       TEXT NOT NULL,
            code_hash   TEXT NOT NULL,
            expires_at  TEXT NOT NULL,
            verified_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # Phone verification table (mirrors email_verifications)
    c.execute("""
        CREATE TABLE IF NOT EXISTS phone_verifications (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            phone       TEXT NOT NULL,
            code_hash   TEXT NOT NULL,
            expires_at  TEXT NOT NULL,
            verified_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    conn.commit()

    # ── Seed default roles if they don't exist ────────────────────────────────
    existing_roles = [r[0] for r in conn.execute("SELECT name FROM roles").fetchall()]

    if "Admin" not in existing_roles:
        conn.execute("""
            INSERT INTO roles
                (name, description, view_logs, use_controls, manage_admin, manage_users, session_minutes, is_system)
            VALUES (?, ?, 1, 1, 1, 1, 480, 1)
        """, ("Admin", "Full access to all features. 8 hour session timeout."))

    if "Operator" not in existing_roles:
        conn.execute("""
            INSERT INTO roles
                (name, description, view_logs, use_controls, manage_admin, manage_users, session_minutes, is_system)
            VALUES (?, ?, 1, 1, 0, 0, 1440, 1)
        """, ("Operator", "Can view dashboard and trigger manual resets. No admin access. 24 hour timeout."))

    if "Monitor" not in existing_roles:
        conn.execute("""
            INSERT INTO roles
                (name, description, view_logs, use_controls, manage_admin, manage_users, session_minutes, is_system)
            VALUES (?, ?, 1, 0, 0, 0, 0, 1)
        """, ("Monitor", "Read-only access to dashboard and metrics. Session never expires. Good for wall displays."))

    # Migration: ensure Monitor, Operator, Admin always have is_system=1
    for system_name in ("Admin", "Monitor", "Operator"):
        conn.execute("UPDATE roles SET is_system=1 WHERE name=? AND is_system=0", (system_name,))

    conn.commit()

    # ── Seed default admin user if no users exist ─────────────────────────────
    user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if user_count == 0:
        admin_role_id = conn.execute("SELECT id FROM roles WHERE name='Admin'").fetchone()[0]
        password_hash = hash_password(DEFAULT_ADMIN_PASSWORD)
        conn.execute("""
            INSERT INTO users (username, password_hash, role_id, created_at, must_change_pass)
            VALUES (?, ?, ?, ?, 1)
        """, ("admin", password_hash, admin_role_id, datetime.now().isoformat()))
        conn.commit()
        log.info("Default admin account created. Username: admin, Password: netwatch123")
        log.warning("IMPORTANT: Change the admin password immediately after first login!")

    conn.close()


# ══════════════════════════════════════════════════════════════════════════════
# PASSWORD HASHING
# ══════════════════════════════════════════════════════════════════════════════

def hash_password(plain_text):
    """Hash a plain text password using bcrypt."""
    try:
        import bcrypt
        return bcrypt.hashpw(plain_text.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    except ImportError:
        # Fallback to werkzeug if bcrypt not available
        from werkzeug.security import generate_password_hash
        return generate_password_hash(plain_text)


def verify_password(plain_text, hashed):
    """Verify a plain text password against a stored hash."""
    try:
        import bcrypt
        return bcrypt.checkpw(plain_text.encode("utf-8"), hashed.encode("utf-8"))
    except ImportError:
        from werkzeug.security import check_password_hash
        return check_password_hash(hashed, plain_text)


# ══════════════════════════════════════════════════════════════════════════════
# AUTHENTICATION
# ══════════════════════════════════════════════════════════════════════════════

def authenticate(username, password, ip_address=None):
    """
    Verify credentials and return user dict if valid, None if not.
    Returns special dicts for locked/expired states so the caller can
    show appropriate messages without leaking account existence.
    """
    import security_log as seclog

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    user = conn.execute("""
        SELECT u.*, r.name as role_name, r.view_logs, r.use_controls,
               r.manage_admin, r.manage_users, r.session_minutes
        FROM users u
        JOIN roles r ON u.role_id = r.id
        WHERE u.username = ?
    """, (username,)).fetchone()
    conn.close()

    if not user:
        seclog.record(seclog.LOGIN_FAIL, username=username, ip_address=ip_address,
                      detail="Unknown username", success=0)
        return None

    if not user["is_active"]:
        seclog.record(seclog.LOGIN_DISABLED, username=username, ip_address=ip_address,
                      detail="Account disabled", success=0)
        return None

    # Check temporary lock
    if user["locked_until"]:
        try:
            locked_until_dt = datetime.fromisoformat(user["locked_until"])
            if datetime.now() < locked_until_dt:
                remaining = int((locked_until_dt - datetime.now()).total_seconds() / 60) + 1
                seclog.record(seclog.LOGIN_FAIL, username=username, ip_address=ip_address,
                              detail=f"Account locked ({remaining}m remaining)", success=0)
                return {"_locked": True, "locked_minutes_remaining": remaining}
            else:
                _clear_lock(user["id"])
        except Exception:
            _clear_lock(user["id"])

    # Check reset token expiry — only block if token is present but expired
    if user["reset_expires_at"] and user["reset_token_hash"]:
        try:
            if datetime.now() > datetime.fromisoformat(user["reset_expires_at"]):
                _clear_reset_token(user["id"])
                # Don't block — just fall through to real password check
        except Exception:
            pass

    # Determine which credential matched
    used_reset_token = False
    real_pw_match    = verify_password(password, user["password_hash"])
    token_match      = (
        user["reset_token_hash"] and
        user["reset_expires_at"] and
        _is_token_valid(user["reset_expires_at"]) and
        verify_password(password, user["reset_token_hash"])
    )

    if not real_pw_match and not token_match:
        seclog.record(seclog.LOGIN_FAIL, username=username, ip_address=ip_address,
                      detail="Wrong password", success=0)
        is_brute, count = seclog.check_brute_force(username, ip_address or "")
        if is_brute:
            _apply_lock(user["id"], username, ip_address, count)
            lock = get_lock_status(user["id"])
            return {"_locked": True, "locked_minutes_remaining": lock.get("minutes_remaining", 30)}
        return None

    if token_match and not real_pw_match:
        used_reset_token = True

    # Successful login
    conn = sqlite3.connect(DB_PATH)
    if used_reset_token:
        # Logged in with temp password — clear token, keep must_change_pass=1
        conn.execute("""
            UPDATE users SET last_login=?, locked_until=NULL, lockout_count=0,
                             lockout_window_start=NULL, reset_token_hash=NULL,
                             reset_expires_at=NULL
            WHERE id=?
        """, (datetime.now().isoformat(), user["id"]))
    else:
        # Logged in with real password — clear everything including must_change_pass
        conn.execute("""
            UPDATE users SET last_login=?, locked_until=NULL, lockout_count=0,
                             lockout_window_start=NULL, reset_token_hash=NULL,
                             reset_expires_at=NULL, must_change_pass=0
            WHERE id=?
        """, (datetime.now().isoformat(), user["id"]))
    conn.commit()
    conn.close()

    seclog.record(seclog.LOGIN_OK, username=username, ip_address=ip_address,
                  detail=f"Role: {user['role_name']}", success=1)
    return dict(user)


def _clear_lock(user_id):
    """Remove temporary lock from a user account."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("UPDATE users SET locked_until=NULL WHERE id=?", (user_id,))
        conn.commit()
        conn.close()
    except Exception:
        pass


def _is_token_valid(expires_at):
    """Return True if the reset token has not yet expired."""
    try:
        return datetime.now() < datetime.fromisoformat(expires_at)
    except Exception:
        return False


def _clear_reset_token(user_id):
    """Remove reset token from a user account."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("UPDATE users SET reset_token_hash=NULL, reset_expires_at=NULL WHERE id=?",
                     (user_id,))
        conn.commit()
        conn.close()
    except Exception:
        pass


def _apply_lock(user_id, username, ip_address, fail_count):
    """Lock account after brute-force threshold. Auto-disable after repeated lockouts."""
    import config as _cfg
    import security_log as seclog

    lock_minutes = getattr(_cfg, "LOCKOUT_DURATION_MINUTES", 30)
    max_lockouts = getattr(_cfg, "LOCKOUT_MAX_COUNT", 3)
    window_hours = getattr(_cfg, "LOCKOUT_WINDOW_HOURS", 24)

    locked_until = (datetime.now() + timedelta(minutes=lock_minutes)).isoformat()

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT lockout_count, lockout_window_start FROM users WHERE id=?", (user_id,)
    ).fetchone()

    current_count = 0
    window_start  = None
    if row and row["lockout_window_start"]:
        try:
            ws = datetime.fromisoformat(row["lockout_window_start"])
            if datetime.now() - ws < timedelta(hours=window_hours):
                current_count = row["lockout_count"] or 0
                window_start  = ws.isoformat()
        except Exception:
            pass
    if window_start is None:
        window_start = datetime.now().isoformat()

    new_count = current_count + 1
    conn.execute("""
        UPDATE users SET locked_until=?, lockout_count=?, lockout_window_start=? WHERE id=?
    """, (locked_until, new_count, window_start, user_id))
    conn.commit()
    conn.close()

    log.warning(f"Account '{username}' locked until {locked_until} (lockout #{new_count})")
    seclog.record("ACCOUNT_LOCKED", username=username, ip_address=ip_address,
                  detail=f"Locked {lock_minutes}m after {fail_count} failures (lockout #{new_count})",
                  success=0)
    try:
        import alerts
        alerts.send_alert("brute_force",
            f"Account '{username}' locked {lock_minutes}m after {fail_count} failed attempts "
            f"from {ip_address or 'unknown IP'}.")
    except Exception:
        pass

    if new_count >= max_lockouts:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("UPDATE users SET is_active=0 WHERE id=?", (user_id,))
        conn.commit()
        conn.close()
        log.warning(f"Account '{username}' AUTO-DISABLED after {new_count} lockouts")
        seclog.record("ACCOUNT_DISABLED", username=username, ip_address=ip_address,
                      detail=f"Auto-disabled after {new_count} lockouts in {window_hours}h",
                      success=0)
        try:
            import alerts
            alerts.send_alert("security_event",
                f"Account '{username}' auto-disabled after {new_count} lockouts in {window_hours}h.")
        except Exception:
            pass


def unlock_account(user_id):
    """Admin action: remove lock and reset lockout counter."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("""
            UPDATE users SET locked_until=NULL, lockout_count=0, lockout_window_start=NULL
            WHERE id=?
        """, (user_id,))
        conn.commit()
        conn.close()
        return True, None
    except Exception as e:
        return False, str(e)


def get_lock_status(user_id):
    """Return lock info for a user: dict with is_locked, locked_until, lockout_count."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT locked_until, lockout_count, is_active FROM users WHERE id=?", (user_id,)
        ).fetchone()
        conn.close()
        if not row:
            return {}
        is_locked = False
        minutes_remaining = 0
        if row["locked_until"]:
            try:
                lu = datetime.fromisoformat(row["locked_until"])
                if datetime.now() < lu:
                    is_locked = True
                    minutes_remaining = int((lu - datetime.now()).total_seconds() / 60) + 1
            except Exception:
                pass
        return {
            "is_locked":         is_locked,
            "locked_until":      row["locked_until"],
            "minutes_remaining": minutes_remaining,
            "lockout_count":     row["lockout_count"] or 0,
            "is_active":         bool(row["is_active"]),
        }
    except Exception:
        return {}


# ── Email verification ────────────────────────────────────────────────────────

def request_email_verification(user_id, email):
    """
    Generate a 6-digit verification code, store hashed, send email.
    Returns (True, code) on success so caller can send the email,
    or (False, error_message).
    """
    import random, string
    code = "".join(random.choices(string.digits, k=6))
    code_hash = hash_password(code)
    expires_at = (datetime.now() + timedelta(hours=24)).isoformat()

    try:
        conn = sqlite3.connect(DB_PATH)
        # Invalidate any previous unverified codes for this user+email
        conn.execute("""
            DELETE FROM email_verifications
            WHERE user_id=? AND verified_at IS NULL
        """, (user_id,))
        conn.execute("""
            INSERT INTO email_verifications (user_id, email, code_hash, expires_at)
            VALUES (?, ?, ?, ?)
        """, (user_id, email, code_hash, expires_at))
        conn.commit()
        conn.close()
        return True, code
    except Exception as e:
        return False, str(e)


def verify_email_code(user_id, email, code):
    """
    Verify a submitted email verification code.
    Returns (True, None) on success, (False, reason) on failure.
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        row = conn.execute("""
            SELECT * FROM email_verifications
            WHERE user_id=? AND email=? AND verified_at IS NULL
            ORDER BY id DESC LIMIT 1
        """, (user_id, email)).fetchone()
        conn.close()

        if not row:
            return False, "No pending verification found"
        if datetime.now() > datetime.fromisoformat(row["expires_at"]):
            return False, "Verification code expired"
        if not verify_password(code, row["code_hash"]):
            return False, "Incorrect code"

        # Mark verified
        conn = sqlite3.connect(DB_PATH)
        conn.execute("""
            UPDATE email_verifications SET verified_at=? WHERE id=?
        """, (datetime.now().isoformat(), row["id"]))
        conn.commit()
        conn.close()
        return True, None
    except Exception as e:
        return False, str(e)


def get_email_verification_status(user_id, email):
    """
    Return verification status for a user+email combination.
    Returns: 'verified', 'pending', or 'unverified'
    """
    if not email:
        return "unverified"
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        row = conn.execute("""
            SELECT verified_at, expires_at FROM email_verifications
            WHERE user_id=? AND email=?
            ORDER BY id DESC LIMIT 1
        """, (user_id, email)).fetchone()
        conn.close()
        if not row:
            return "unverified"
        if row["verified_at"]:
            return "verified"
        # Pending but might be expired
        try:
            if datetime.now() > datetime.fromisoformat(row["expires_at"]):
                return "unverified"
        except Exception:
            pass
        return "pending"
    except Exception:
        return "unverified"


def request_phone_verification(user_id, phone):
    """
    Generate a 6-digit code, store hashed, return code for caller to send via SMS.
    Returns (True, code) on success, (False, error) on failure.
    Phone stored as last 10 digits.
    """
    import random, string
    digits = ''.join(c for c in str(phone) if c.isdigit())[-10:]
    if len(digits) != 10:
        return False, "Invalid phone number — must be 10 digits"
    code = "".join(random.choices(string.digits, k=6))
    code_hash  = hash_password(code)
    expires_at = (datetime.now() + timedelta(hours=1)).isoformat()
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("""
            DELETE FROM phone_verifications
            WHERE user_id=? AND verified_at IS NULL
        """, (user_id,))
        conn.execute("""
            INSERT INTO phone_verifications (user_id, phone, code_hash, expires_at)
            VALUES (?, ?, ?, ?)
        """, (user_id, digits, code_hash, expires_at))
        conn.commit()
        conn.close()
        return True, code
    except Exception as e:
        return False, str(e)


def verify_phone_code(user_id, phone, code):
    """
    Verify a submitted SMS verification code.
    Returns (True, None) on success, (False, reason) on failure.
    """
    digits = ''.join(c for c in str(phone) if c.isdigit())[-10:]
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        row = conn.execute("""
            SELECT * FROM phone_verifications
            WHERE user_id=? AND phone=? AND verified_at IS NULL
            ORDER BY id DESC LIMIT 1
        """, (user_id, digits)).fetchone()
        conn.close()
        if not row:
            return False, "No pending verification found for this number"
        if datetime.now() > datetime.fromisoformat(row["expires_at"]):
            return False, "Verification code expired — request a new one"
        if not verify_password(code, row["code_hash"]):
            return False, "Incorrect code"
        conn = sqlite3.connect(DB_PATH)
        conn.execute("""
            UPDATE phone_verifications SET verified_at=? WHERE id=?
        """, (datetime.now().isoformat(), row["id"]))
        conn.commit()
        conn.close()
        return True, None
    except Exception as e:
        return False, str(e)


def get_phone_verification_status(user_id, phone):
    """
    Return verification status for a user+phone combination.
    Returns: 'verified', 'pending', or 'unverified'
    """
    if not phone:
        return "unverified"
    digits = ''.join(c for c in str(phone) if c.isdigit())[-10:]
    if len(digits) != 10:
        return "unverified"
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        row = conn.execute("""
            SELECT verified_at, expires_at FROM phone_verifications
            WHERE user_id=? AND phone=?
            ORDER BY id DESC LIMIT 1
        """, (user_id, digits)).fetchone()
        conn.close()
        if not row:
            return "unverified"
        if row["verified_at"]:
            return "verified"
        try:
            if datetime.now() > datetime.fromisoformat(row["expires_at"]):
                return "unverified"
        except Exception:
            pass
        return "pending"
    except Exception:
        return "unverified"


# ── Self-service password reset ───────────────────────────────────────────────

def request_password_reset(username):
    """
    Initiate self-service password reset.
    Returns (True, {"email": email, "sms_address": sms_address}, temp_password)
      if user has at least one verified contact method.
    Returns (False, reason, None) otherwise.
    sms_address may be None if no verified phone.
    """
    import random, string

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    user = conn.execute(
        "SELECT id, username, is_active FROM users WHERE username=?", (username,)
    ).fetchone()
    conn.close()

    if not user:
        return False, "no_user", None
    if not user["is_active"]:
        return False, "disabled", None

    user_id = user["id"]

    # Check verified email
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    verif = conn.execute("""
        SELECT email FROM email_verifications
        WHERE user_id=? AND verified_at IS NOT NULL
        ORDER BY id DESC LIMIT 1
    """, (user_id,)).fetchone()
    conn.close()
    email = verif["email"] if verif else None

    # Check verified phone — look up subscriber record for carrier/domain
    sms_address = None
    try:
        import alert_subscribers as _subs
        sub = _subs.get_subscriber_by_user_id(user_id)
        if sub and sub.get("sms_phone"):
            digits = ''.join(c for c in str(sub["sms_phone"]) if c.isdigit())[-10:]
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            phone_row = conn.execute("""
                SELECT verified_at FROM phone_verifications
                WHERE user_id=? AND phone=? AND verified_at IS NOT NULL
                ORDER BY id DESC LIMIT 1
            """, (user_id, digits)).fetchone()
            conn.close()
            if phone_row:
                sms_address = _subs.get_sms_address(sub)
    except Exception:
        pass

    if not email and not sms_address:
        return False, "no_verified_contact", None

    # Generate temp password — store in reset_token_hash ONLY, never overwrite real password
    chars = string.ascii_letters + string.digits
    temp_password = "".join(random.choices(chars, k=10))
    token_hash    = hash_password(temp_password)
    expires_at    = (datetime.now() + timedelta(minutes=15)).isoformat()

    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        UPDATE users SET reset_token_hash=?, reset_expires_at=?, must_change_pass=1
        WHERE id=?
    """, (token_hash, expires_at, user_id))
    conn.commit()
    conn.close()

    return True, {"email": email, "sms_address": sms_address}, temp_password


def login_user(user):
    """Store user info in Flask session after successful authentication."""
    session.permanent = True
    session["user_id"]        = user["id"]
    session["username"]       = user["username"]
    session["first_name"]     = user.get("first_name") or ""
    session["last_name"]      = user.get("last_name") or ""
    session["role_name"]      = user["role_name"]
    session["view_logs"]      = bool(user["view_logs"])
    session["use_controls"]   = bool(user["use_controls"])
    session["manage_admin"]   = bool(user["manage_admin"])
    session["manage_users"]   = bool(user["manage_users"])
    session["session_minutes"]= user.get("session_minutes", 480)
    session["login_time"]     = datetime.now().isoformat()
    session["last_activity"]  = datetime.now().isoformat()
    session["theme"]          = user.get("theme")  or "dark-blue"
    session["layout"]         = user.get("layout") or "comfortable"
    session["nav_style"]      = user.get("nav_style") or "icons-labels"
    session["content_align"]  = user.get("content_align") or "left"
    log.info(f"User '{user['username']}' logged in — theme:{user.get('theme')} layout:{user.get('layout')} nav:{user.get('nav_style')}")


def logout_user():
    """Clear the Flask session."""
    session.clear()


def get_current_user():
    """
    Return the current session user dict.
    If not logged in, returns a guest context with Monitor-level permissions.
    Guest users can view dashboard and metrics only — no logs, controls, or admin.
    """
    if "user_id" not in session:
        # Return guest context — read from session for theme/layout preferences
        # stored via localStorage-sync on the client, or defaults
        return {
            "id":               None,
            "username":         "Guest",
            "role_name":        "Guest",
            "is_guest":         True,
            "view_logs":        False,
            "use_controls":     False,
            "manage_admin":     False,
            "manage_users":     False,
            "must_change_pass": False,
            "theme":            session.get("guest_theme",  "dark-blue"),
            "layout":           session.get("guest_layout", "comfortable"),
            "nav_style":        session.get("guest_nav_style", "icons-labels"),
        }

    # Check session timeout — based on last_activity (idle timeout, not login time)
    minutes = session.get("session_minutes", 480)
    if minutes > 0:  # 0 = never expire
        last_act = session.get("last_activity") or session.get("login_time") or datetime.now().isoformat()
        idle_elapsed = (datetime.now() - datetime.fromisoformat(last_act)).total_seconds() / 60
        if idle_elapsed > minutes:
            logout_user()
            return {
                "id": None, "username": "Guest", "role_name": "Guest",
                "is_guest": True, "view_logs": False, "use_controls": False,
                "manage_admin": False, "manage_users": False,
                "must_change_pass": False,
                "theme": "dark-blue", "layout": "comfortable", "nav_style": "icons-labels",
            }

    # Always read must_change_pass from DB — session cookie may be stale
    # (e.g. tab closed before redirect delivered updated cookie)
    user_id = session.get("user_id")
    try:
        _conn = sqlite3.connect(DB_PATH)
        _row  = _conn.execute(
            "SELECT must_change_pass FROM users WHERE id=?", (user_id,)
        ).fetchone()
        _conn.close()
        must_change = bool(_row[0]) if _row else False
    except Exception:
        must_change = session.get("must_change_pass", False)

    return {
        "id":            session.get("user_id"),
        "username":      session.get("username"),
        "first_name":    session.get("first_name", ""),
        "last_name":     session.get("last_name", ""),
        "role_name":     session.get("role_name"),
        "is_guest":      False,
        "view_logs":     session.get("view_logs", False),
        "use_controls":  session.get("use_controls", False),
        "manage_admin":  session.get("manage_admin", False),
        "manage_users":  session.get("manage_users", False),
        "must_change_pass": must_change,
        "theme":          session.get("theme", "dark-blue"),
        "layout":         session.get("layout", "comfortable"),
        "nav_style":      session.get("nav_style", "icons-labels"),
        "content_align":  session.get("content_align", "left"),
    }


# ══════════════════════════════════════════════════════════════════════════════
# ROUTE DECORATORS
# ══════════════════════════════════════════════════════════════════════════════

def login_required(f):
    """Decorator: redirect to login if not a real authenticated user (guests are redirected)."""
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user or user.get("is_guest"):
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return decorated


def guest_allowed(f):
    """
    Decorator: allows guest access. Use instead of login_required for pages
    that guests can view (dashboard, metrics).
    No redirect — guests see these pages with limited data.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        return f(*args, **kwargs)
    return decorated


def requires_permission(permission):
    """
    Decorator factory: require a specific permission or redirect with error.
    Usage: @requires_permission("use_controls")
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user = get_current_user()
            if not user:
                return redirect(url_for("login", next=request.path))
            if not user.get(permission):
                log.warning(f"User '{user['username']}' denied access to {request.path} (needs {permission})")
                from flask import jsonify
                # Return JSON error for API routes, redirect for page routes
                if request.path.startswith("/api/"):
                    return jsonify({"status": "error", "message": "Permission denied"}), 403
                flash(f"Your role ({user['role_name']}) does not have permission for that action.", "warning")
                return redirect(url_for("index"))
            return f(*args, **kwargs)
        return decorated
    return decorator


# ══════════════════════════════════════════════════════════════════════════════
# USER MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════

def get_all_users():
    """Return all users with their role names and current lock status."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("""
        SELECT u.id, u.username, u.created_at, u.last_login,
               u.must_change_pass, u.is_active,
               u.locked_until, u.lockout_count,
               u.first_name, u.last_name,
               r.name as role_name, r.id as role_id
        FROM users u
        JOIN roles r ON u.role_id = r.id
        ORDER BY u.username
    """).fetchall()
    conn.close()
    now = datetime.now()
    result = []
    for r in rows:
        d = dict(r)
        is_locked = False
        minutes_remaining = 0
        if d.get("locked_until"):
            try:
                lu = datetime.fromisoformat(d["locked_until"])
                if now < lu:
                    is_locked = True
                    minutes_remaining = int((lu - now).total_seconds() / 60) + 1
            except Exception:
                pass
        d["is_locked"]          = is_locked
        d["minutes_remaining"]  = minutes_remaining
        result.append(d)
    return result


def get_user_by_id(user_id):
    """Return a single user dict by ID."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_user_by_username(username):
    """Return a single user dict by username."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    return dict(row) if row else None


def set_password(user_id, new_password):
    """Set a new password for a user (no old password required)."""
    return change_password(user_id, new_password)


def get_role_by_name(name):
    """Return a role dict by name."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM roles WHERE name=?", (name,)).fetchone()
    conn.close()
    return dict(row) if row else None


def create_user(username, password, role_id, must_change_pass=True):
    """
    Create a new user. Returns (True, None) on success or (False, error_message).
    New users are flagged to change their password on first login by default.
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("""
            INSERT INTO users (username, password_hash, role_id, created_at, must_change_pass)
            VALUES (?, ?, ?, ?, ?)
        """, (username, hash_password(password), role_id,
              datetime.now().isoformat(), int(must_change_pass)))
        conn.commit()
        conn.close()
        log.info(f"User '{username}' created")
        return True, None
    except sqlite3.IntegrityError:
        return False, f"Username '{username}' already exists"
    except Exception as e:
        return False, str(e)


def update_user(user_id, username=None, role_id=None, is_active=None, must_change_pass=None):
    """Update user properties. Pass None for fields you don't want to change."""
    try:
        conn = sqlite3.connect(DB_PATH)
        if username is not None:
            existing = conn.execute(
                "SELECT id FROM users WHERE username=? AND id!=?", (username, user_id)
            ).fetchone()
            if existing:
                conn.close()
                return False, f"Username '{username}' is already taken"
            conn.execute("UPDATE users SET username=? WHERE id=?", (username, user_id))
            if session.get("user_id") == user_id:
                session["username"] = username
            log.info(f"Username changed to '{username}' for user ID {user_id}")
        if role_id is not None:
            conn.execute("UPDATE users SET role_id=? WHERE id=?", (role_id, user_id))
        if is_active is not None:
            conn.execute("UPDATE users SET is_active=? WHERE id=?", (int(is_active), user_id))
        if must_change_pass is not None:
            conn.execute("UPDATE users SET must_change_pass=? WHERE id=?", (int(must_change_pass), user_id))
        conn.commit()
        conn.close()
        return True, None
    except Exception as e:
        return False, str(e)


def update_identity(user_id, first_name, last_name):
    """Update a user's first and last name. Syncs session if it's the current user."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "UPDATE users SET first_name=?, last_name=? WHERE id=?",
            (first_name or None, last_name or None, user_id)
        )
        conn.commit()
        conn.close()
        if session.get("user_id") == user_id:
            session["first_name"] = first_name or ""
            session["last_name"]  = last_name or ""
        return True, None
    except Exception as e:
        return False, str(e)


def change_password(user_id, new_password):
    """Change a user's password and clear the must_change_pass flag."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("""
            UPDATE users SET password_hash=?, must_change_pass=0 WHERE id=?
        """, (hash_password(new_password), user_id))
        conn.commit()
        conn.close()
        log.info(f"Password changed for user ID {user_id}")
        # Update session flag if changing own password
        if session.get("user_id") == user_id:
            session["must_change_pass"] = False
        return True, None
    except Exception as e:
        return False, str(e)


def delete_user(user_id, delete_subscription=False):
    """
    Delete a user. Cannot delete the last admin or yourself.
    If delete_subscription=True, also deletes linked subscriber record.
    If delete_subscription=False, subscriber record is kept but user_id is cleared (becomes standalone).
    Returns (True, None) on success or (False, error_message).
    """
    # Prevent deleting yourself
    if session.get("user_id") == user_id:
        return False, "You cannot delete your own account"

    # Prevent deleting the last active admin
    conn = sqlite3.connect(DB_PATH)
    admin_count = conn.execute("""
        SELECT COUNT(*) FROM users u
        JOIN roles r ON u.role_id = r.id
        WHERE r.manage_users = 1 AND u.is_active = 1
    """).fetchone()[0]
    user = conn.execute("SELECT username FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()

    if admin_count <= 1:
        target_role = get_user_by_id(user_id)
        if target_role:
            role = get_role_by_id(target_role["role_id"])
            if role and role["manage_users"]:
                return False, "Cannot delete the last admin account"

    try:
        import alert_subscribers as _subs
        conn = sqlite3.connect(DB_PATH)
        if delete_subscription:
            conn.execute(
                "DELETE FROM alert_subscribers WHERE user_id=? AND is_owner=0",
                (user_id,)
            )
        else:
            # Keep subscriber record but detach from account (becomes standalone)
            conn.execute(
                "UPDATE alert_subscribers SET user_id=NULL WHERE user_id=? AND is_owner=0",
                (user_id,)
            )
        conn.execute("DELETE FROM users WHERE id=?", (user_id,))
        conn.commit()
        conn.close()
        log.info(f"User '{user[0] if user else user_id}' deleted (sub_deleted={delete_subscription})")
        return True, None
    except Exception as e:
        return False, str(e)


def delete_own_account(user_id, password, delete_subscription=False):
    """
    Allow a user to delete their own account after confirming their password.
    Logs them out. If delete_subscription=False, subscriber record is kept as standalone.
    Returns (True, None) or (False, error_message).
    The system owner (linked to config) cannot delete their account.
    """
    user = get_user_by_id(user_id)
    if not user:
        return False, "Account not found"

    # Prevent the system owner from deleting their account
    try:
        import alert_subscribers as _subs
        sub = _subs.get_subscriber_by_user_id(user_id) or \
              _subs.get_subscriber_by_username(user["username"])
        if sub and sub.get("is_owner"):
            return False, "The system owner account cannot be deleted. Transfer ownership in config first."
    except Exception:
        pass

    # Prevent deleting the last admin
    conn = sqlite3.connect(DB_PATH)
    admin_count = conn.execute("""
        SELECT COUNT(*) FROM users u
        JOIN roles r ON u.role_id = r.id
        WHERE r.manage_users = 1 AND u.is_active = 1
    """).fetchone()[0]
    conn.close()
    if admin_count <= 1:
        role = get_role_by_id(user["role_id"])
        if role and role.get("manage_users"):
            return False, "Cannot delete the last admin account"

    # Verify password
    if not verify_password(password, user["password_hash"]):
        return False, "Incorrect password"

    try:
        conn = sqlite3.connect(DB_PATH)
        if delete_subscription:
            conn.execute(
                "DELETE FROM alert_subscribers WHERE user_id=? AND is_owner=0",
                (user_id,)
            )
        else:
            conn.execute(
                "UPDATE alert_subscribers SET user_id=NULL WHERE user_id=? AND is_owner=0",
                (user_id,)
            )
        conn.execute("DELETE FROM users WHERE id=?", (user_id,))
        conn.commit()
        conn.close()
        logout_user()
        log.info(f"User '{user['username']}' deleted their own account (sub_deleted={delete_subscription})")
        return True, None
    except Exception as e:
        return False, str(e)


# ══════════════════════════════════════════════════════════════════════════════
# ROLE MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════

def get_all_roles():
    """Return all roles as a list of dicts."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM roles ORDER BY name").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_role_by_id(role_id):
    """Return a single role dict by ID."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM roles WHERE id=?", (role_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def create_role(name, description, view_logs, use_controls, manage_admin,
                manage_users, session_minutes):
    """Create a new role. Returns (True, None) or (False, error_message)."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("""
            INSERT INTO roles
                (name, description, view_logs, use_controls, manage_admin, manage_users, session_minutes)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (name, description, int(view_logs), int(use_controls),
              int(manage_admin), int(manage_users), int(session_minutes)))
        conn.commit()
        conn.close()
        log.info(f"Role '{name}' created")
        return True, None
    except sqlite3.IntegrityError:
        return False, f"Role '{name}' already exists"
    except Exception as e:
        return False, str(e)


def update_role(role_id, name, description, view_logs, use_controls,
                manage_admin, manage_users, session_minutes):
    """Update an existing role."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("""
            UPDATE roles SET name=?, description=?, view_logs=?, use_controls=?,
                             manage_admin=?, manage_users=?, session_minutes=?
            WHERE id=?
        """, (name, description, int(view_logs), int(use_controls),
              int(manage_admin), int(manage_users), int(session_minutes), role_id))
        conn.commit()
        conn.close()
        log.info(f"Role ID {role_id} updated")
        return True, None
    except sqlite3.IntegrityError:
        return False, f"Role name '{name}' already exists"
    except Exception as e:
        return False, str(e)


def delete_role(role_id):
    """
    Delete a role. Cannot delete system roles.
    If users are assigned, returns (False, 'has_users') so caller can trigger reassignment dialog.
    Returns (True, None) or (False, error_message).
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    role = conn.execute("SELECT * FROM roles WHERE id=?", (role_id,)).fetchone()

    if not role:
        conn.close()
        return False, "Role not found"

    if role["is_system"]:
        conn.close()
        return False, f"'{role['name']}' is a system role and cannot be deleted"

    user_count = conn.execute(
        "SELECT COUNT(*) FROM users WHERE role_id=?", (role_id,)
    ).fetchone()[0]
    conn.close()

    if user_count > 0:
        return False, "has_users"

    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM roles WHERE id=?", (role_id,))
    conn.commit()
    conn.close()

    # Clean up role alert defaults
    try:
        import alert_subscribers as _subs
        _subs.delete_role_alert_defaults(role_id)
    except Exception:
        pass

    log.info(f"Role '{role['name']}' deleted")
    return True, None


def get_users_by_role(role_id):
    """Return all users assigned to a given role_id."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("""
        SELECT u.id, u.username, u.first_name, u.last_name, u.role_id,
               r.name as role_name
        FROM users u JOIN roles r ON u.role_id = r.id
        WHERE u.role_id=?
    """, (role_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def delete_role_with_reassignment(role_id, user_role_map):
    """
    Reassign users in user_role_map {user_id: new_role_id} then delete the role.
    Returns (True, None) or (False, error_message).
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    role = conn.execute("SELECT * FROM roles WHERE id=?", (role_id,)).fetchone()
    if not role:
        conn.close()
        return False, "Role not found"
    if role["is_system"]:
        conn.close()
        return False, f"'{role['name']}' is a system role and cannot be deleted"

    try:
        for user_id, new_role_id in user_role_map.items():
            conn.execute(
                "UPDATE users SET role_id=? WHERE id=? AND role_id=?",
                (int(new_role_id), int(user_id), role_id)
            )
        conn.execute("DELETE FROM roles WHERE id=?", (role_id,))
        conn.commit()
        conn.close()
    except Exception as e:
        conn.close()
        return False, str(e)

    # Clean up role alert defaults
    try:
        import alert_subscribers as _subs
        _subs.delete_role_alert_defaults(role_id)
    except Exception:
        pass

    log.info(f"Role '{role['name']}' deleted after user reassignment")
    return True, None


# ══════════════════════════════════════════════════════════════════════════════
# PREFERENCE MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════

def save_preferences(user_id, theme=None, layout=None, nav_style=None, content_align=None):
    """Save theme, layout, nav_style and/or content_align preference for a user."""
    try:
        conn = sqlite3.connect(DB_PATH)
        if theme:         conn.execute("UPDATE users SET theme=? WHERE id=?",         (theme, user_id))
        if layout:        conn.execute("UPDATE users SET layout=? WHERE id=?",        (layout, user_id))
        if nav_style:     conn.execute("UPDATE users SET nav_style=? WHERE id=?",     (nav_style, user_id))
        if content_align: conn.execute("UPDATE users SET content_align=? WHERE id=?", (content_align, user_id))
        conn.commit()
        conn.close()
        if theme:         session["theme"]         = theme
        if layout:        session["layout"]        = layout
        if nav_style:     session["nav_style"]     = nav_style
        if content_align: session["content_align"] = content_align
        return True
    except Exception as e:
        log.error(f"Failed to save preferences: {e}")
        return False
