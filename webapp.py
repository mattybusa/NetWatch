#!/usr/bin/env python3
# ══════════════════════════════════════════════════════════════════════════════
# NetWatch — webapp.py  (full replacement with authentication)
# Flask web dashboard with login, session management, roles, and permissions.
# ══════════════════════════════════════════════════════════════════════════════

import os
import re
import json
import csv
import io
import logging
import structlog
from datetime import datetime, timedelta
from flask import (Flask, render_template, jsonify, request,
                   send_file, redirect, url_for, flash, session)

NETWATCH_DIR = os.path.dirname(os.path.abspath(__file__))

import config
import database
import auth
import updater
import configeditor
import patcher
import certmanager
import config_validator
import alert_subscribers
import security_log
import theme_manager

# requests is used for update checking — fail gracefully if not installed
try:
    import requests as _requests
except ImportError:
    _requests = None

log = structlog.get_logger().bind(service="web")

app = Flask(__name__)
app.secret_key = config.SECRET_KEY

# Session cookie settings
app.config["SESSION_COOKIE_HTTPONLY"] = True   # JS cannot read session cookie
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"  # CSRF protection
app.config["SESSION_COOKIE_SECURE"]   = True   # HTTPS only
# Cap browser cookie lifetime at 2 days — idle timeout logic handles normal
# expiry; this is a hard ceiling so cookies don't persist for Flask's 31-day default.
from datetime import timedelta
app.permanent_session_lifetime = timedelta(days=2)


@app.after_request
def set_cache_headers(response):
    """Prevent browsers from caching authenticated pages.
    Stops back-button showing stale pages from previous users."""
    # Only apply to HTML pages, not static assets or API responses
    if response.content_type and "text/html" in response.content_type:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"]        = "no-cache"
        response.headers["Expires"]       = "0"
    return response

CMD_FILE   = os.path.join(NETWATCH_DIR, "pending_command.json")
STATE_FILE = os.path.join(NETWATCH_DIR, "state.json")
LOG_FILE   = os.path.join(NETWATCH_DIR, "logs/netwatch.log")

# ── First-run detection ────────────────────────────────────────────────────────
def is_first_run():
    """Returns True if the system has not been configured yet."""
    return config.SECRET_KEY in ("NOT_MY_SECRET_KEY", "CHANGE_THIS_TO_A_RANDOM_SECRET_KEY")

# ── Template context ───────────────────────────────────────────────────────────
def _read_version():
    try:
        with open(os.path.join(NETWATCH_DIR, "VERSION")) as f:
            return f.read().strip()
    except Exception:
        return "?"

@app.context_processor
def inject_globals():
    return {"app_version": _read_version()}

@app.route("/static/site.webmanifest")
def web_manifest():
    """PWA web manifest for home screen icon support."""
    manifest = {
        "name": "NetWatch",
        "short_name": "NetWatch",
        "description": "Network Monitor & Auto-Reset",
        "start_url": "/",
        "display": "standalone",
        "background_color": "#0d1117",
        "theme_color": "#0d1117",
        "icons": [
            {"src": "/static/favicon-32.png",       "sizes": "32x32",   "type": "image/png"},
            {"src": "/static/apple-touch-icon.png",  "sizes": "180x180", "type": "image/png"},
            {"src": "/static/favicon.svg",           "sizes": "any",     "type": "image/svg+xml"}
        ]
    }
    from flask import Response
    import json
    return Response(json.dumps(manifest), mimetype="application/manifest+json")

@app.before_request
def check_first_run():
    """Intercept all requests and redirect to setup wizard if not configured."""
    if is_first_run() and not request.path.startswith("/setup") and \
       not request.path.startswith("/static") and \
       not request.path.startswith("/api/setup"):
        return redirect(url_for("setup_wizard"))

# ── Setup Wizard Routes ────────────────────────────────────────────────────────

@app.route("/setup")
def setup_wizard():
    return render_template("setup.html")

@app.route("/api/setup/interfaces")
def setup_interfaces():
    """Detect active network interfaces and their IPs for wizard pre-population."""
    import subprocess
    interfaces = []
    try:
        result = subprocess.run(["ip", "-o", "addr", "show"],
                                capture_output=True, text=True, timeout=5)
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            iface = parts[1]
            family = parts[2]
            if family != "inet":  # IPv4 only
                continue
            if iface == "lo":     # skip loopback
                continue
            ip = parts[3].split("/")[0]
            interfaces.append({"name": iface, "ip": ip})
    except Exception as e:
        log.warning("interface_detection_failed", error=str(e))
    return jsonify({"interfaces": interfaces})

@app.route("/setup/skip")
def setup_skip():
    """Mark setup as done by writing a minimal config, redirect to login."""
    # Write a random secret key so first-run check passes
    import secrets as _secrets
    _write_config_value("SECRET_KEY", _secrets.token_hex(32))
    return redirect(url_for("login"))

@app.route("/setup/apply", methods=["POST"])
def setup_apply():
    """Apply wizard settings — write config.py and restart services."""
    import secrets as _secrets, subprocess, bcrypt
    data = request.get_json() or {}

    try:
        # Generate a secure secret key
        secret_key = _secrets.token_hex(32)

        # Read current config.py
        config_path = os.path.join(NETWATCH_DIR, "config.py")
        with open(config_path, "r") as f:
            cfg = f.read()

        def replace_cfg(content, key, value):
            import re
            if isinstance(value, str):
                pattern = rf'^{key}\s*=.*$'
                replacement = f'{key} = "{value}"'
            elif isinstance(value, bool):
                pattern = rf'^{key}\s*=.*$'
                replacement = f'{key} = {str(value)}'
            else:
                pattern = rf'^{key}\s*=.*$'
                replacement = f'{key} = {value}'
            return re.sub(pattern, replacement, content, flags=re.MULTILINE)

        cfg = replace_cfg(cfg, "SECRET_KEY",      secret_key)
        cfg = replace_cfg(cfg, "LAN_GATEWAY",     data.get("lan_gateway", "192.168.1.1"))
        cfg = replace_cfg(cfg, "WIFI_GATEWAY",    data.get("wifi_gateway", ""))
        cfg = replace_cfg(cfg, "LAN_INTERFACE",   data.get("lan_interface", ""))
        cfg = replace_cfg(cfg, "WIFI_INTERFACE",  data.get("wifi_interface", ""))
        cfg = replace_cfg(cfg, "WAN_PRIMARY",     data.get("wan_primary", "8.8.8.8"))
        cfg = replace_cfg(cfg, "WAN_SECONDARY",   data.get("wan_secondary", "8.8.4.4"))
        cfg = replace_cfg(cfg, "RELAY_MODEM",     data.get("relay_modem", 17))
        cfg = replace_cfg(cfg, "RELAY_ROUTER",    data.get("relay_router", 27))
        cfg = replace_cfg(cfg, "BUTTON_PIN",      data.get("button_pin", 22))
        cfg = replace_cfg(cfg, "RELAY_ACTIVE_LOW", data.get("relay_active_low", False))
        cfg = replace_cfg(cfg, "ALERTS_ENABLED",  data.get("alerts_enabled", False))

        if data.get("gmail_user"):
            cfg = replace_cfg(cfg, "GMAIL_USER",          data["gmail_user"])
        if data.get("gmail_pass"):
            cfg = replace_cfg(cfg, "GMAIL_APP_PASSWORD",  data["gmail_pass"])
        if data.get("alert_to"):
            cfg = replace_cfg(cfg, "ALERT_TO",            data["alert_to"])

        # Write site name as a comment/variable if present
        site_name = data.get("site_name", "NetWatch")
        if "SITE_NAME" in cfg:
            cfg = replace_cfg(cfg, "SITE_NAME", site_name)
        else:
            cfg = f'SITE_NAME = "{site_name}"\n' + cfg

        with open(config_path, "w") as f:
            f.write(cfg)

        # Update admin account
        admin_user = data.get("admin_username", "admin")
        admin_pass = data.get("admin_password", "")

        # Write owner username to config
        with open(config_path, "r") as f:
            cfg2 = f.read()
        if "OWNER_USERNAME" in cfg2:
            cfg2 = replace_cfg(cfg2, "OWNER_USERNAME", admin_user)
        else:
            cfg2 += f'\nOWNER_USERNAME = "{admin_user}"\n'
        with open(config_path, "w") as f:
            f.write(cfg2)

        if admin_pass:
            # Update or create admin user in database
            existing = auth.get_user_by_username("admin")
            if existing:
                if admin_user != "admin":
                    auth.update_user(existing["id"], username=admin_user)
                auth.set_password(existing["id"], admin_pass)
            else:
                admin_role = auth.get_role_by_name("Admin")
                if admin_role:
                    auth.create_user(admin_user, admin_pass, admin_role["id"], must_change_pass=False)

        # Restart services (two separate commands -- sudoers requires exact match)
        subprocess.Popen(["bash", "-c",
            "sleep 1 && sudo systemctl restart netwatch-monitor && sleep 2 && sudo systemctl restart netwatch-web"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        return jsonify({"status": "ok"})

    except Exception as e:
        log.error("setup_apply_failed", error=str(e))
        return jsonify({"status": "error", "message": str(e)})


# ══════════════════════════════════════════════════════════════════════════════
# STARTUP
# ══════════════════════════════════════════════════════════════════════════════

def init():
    """Initialize auth database tables and run config validation. Called at startup."""
    auth.init_auth_db()
    security_log.init_security_db()
    alert_subscribers.init_subscribers_db()
    alert_subscribers.cleanup_duplicate_owner()
    # Backfill: ensure every user account has a subscriber record
    try:
        alert_subscribers.backfill_account_subscribers()
    except Exception as e:
        log.error("subscriber_backfill_failed", error=str(e))
    # Backfill: ensure every role has alert defaults seeded
    try:
        for role in auth.get_all_roles():
            alert_subscribers.seed_role_alert_defaults(role["id"])
    except Exception as e:
        log.error("role_defaults_backfill_failed", error=str(e))
    if not is_first_run():
        try:
            # Seed owner subscriber from config
            gmail_user   = getattr(config, "GMAIL_USER",      "") or ""
            alert_to     = getattr(config, "ALERT_TO",        "") or ""
            owner_username = getattr(config, "OWNER_USERNAME", "") or ""
            # Fall back to first admin user if OWNER_USERNAME not set
            if not owner_username:
                import sqlite3 as _sq
                _conn = _sq.connect(os.path.join(NETWATCH_DIR, "netwatch.db"))
                _conn.row_factory = _sq.Row
                _row = _conn.execute("""
                    SELECT u.username FROM users u
                    JOIN roles r ON u.role_id = r.id
                    WHERE r.name='Admin' ORDER BY u.id LIMIT 1
                """).fetchone()
                _conn.close()
                owner_username = _row["username"] if _row else "admin"
            if gmail_user:
                alert_subscribers.seed_owner(owner_username, gmail_user, alert_to or gmail_user)
        except Exception as e:
            log.error("owner_seed_failed", error=str(e))
        try:
            config_validator.remove_legacy_email_keys()
            config_validator.migrate_email_keys()
            config_validator.cleanup_false_positives()
            notifications = config_validator.validate()
            if notifications:
                log.info("config_validator_new_keys", count=len(notifications))
        except Exception as e:
            log.error("config_validator_failed", error=str(e))


# ══════════════════════════════════════════════════════════════════════════════
# CONTEXT PROCESSOR — makes current_user available in all templates
# ══════════════════════════════════════════════════════════════════════════════

@app.context_processor
def inject_user():
    """Inject current_user, config notifications, and custom theme CSS into every template."""
    notifications = []
    try:
        if not is_first_run():
            notifications = config_validator.get_pending_notifications()
    except Exception:
        pass

    # Build inline CSS for any active custom color scheme or layout
    custom_css = ""
    active_custom_color  = None
    active_custom_layout = None
    try:
        user = auth.get_current_user()
        active_custom_color  = database.get_user_pref(user["id"], "custom_color_scheme") if user and not user["is_guest"] else None
        active_custom_layout = database.get_user_pref(user["id"], "custom_layout")        if user and not user["is_guest"] else None
        if active_custom_color:
            t = theme_manager.get_theme(active_custom_color)
            if t:
                custom_css += theme_manager.generate_css(t, "color_scheme") + "\n"
        if active_custom_layout:
            t = theme_manager.get_theme(active_custom_layout)
            if t:
                custom_css += theme_manager.generate_css(t, "layout") + "\n"
    except Exception:
        pass

    # Load custom themes for appearance UI — exclude disabled ones for user-facing selectors
    custom_themes = []
    try:
        all_themes   = theme_manager.load_themes()
        custom_themes = [t for t in all_themes if not t.get("_disabled")]
    except Exception:
        pass

    # MFA grace period warning — injected into every page for mandatory roles
    # Suppressed for the session if the user clicked dismiss (unless expired)
    mfa_warning = None
    try:
        u = auth.get_current_user()
        if u and not u.get("is_guest") and u.get("role_name") in auth.MFA_MANDATORY_ROLES:
            mfa_status = auth.get_mfa_status(u["id"])
            if not mfa_status["enabled"]:
                if mfa_status["grace_expired"]:
                    # Expired — always show, cannot dismiss
                    mfa_warning = {"expired": True, "days_left": 0}
                elif mfa_status["grace_deadline"] and not session.get("mfa_banner_dismissed"):
                    try:
                        deadline    = datetime.fromisoformat(mfa_status["grace_deadline"])
                        days_left   = max(0, (deadline - datetime.now()).days + 1)
                        mfa_warning = {"expired": False, "days_left": days_left}
                    except Exception:
                        mfa_warning = {"expired": False, "days_left": 0}
    except Exception:
        pass

    # Update availability — injected into every page for the notification banner.
    # Only fetched for logged-in manage_admin users to avoid unnecessary DB reads.
    update_available = None
    try:
        u = auth.get_current_user()
        if u and not u.get("is_guest") and u.get("manage_admin"):
            avail_ver = database.get_system_setting("update_available_version", "")
            if avail_ver:
                dismissed = database.get_system_setting("update_dismissed_version", "")
                if avail_ver != dismissed:
                    update_available = {
                        "version":     avail_ver,
                        "description": database.get_system_setting("update_available_description", ""),
                    }
    except Exception:
        pass

    return {
        "current_user":           auth.get_current_user(),
        "config_notifications":   notifications,
        "custom_theme_css":       custom_css,
        "custom_themes":          custom_themes,
        "active_custom_color":    active_custom_color,
        "active_custom_layout":   active_custom_layout,
        "mfa_warning":            mfa_warning,
        "update_available":       update_available,
        "is_dev_system":          bool(getattr(config, "DEVELOPMENT_SYSTEM", False)),
    }


# ── Config Notification API ───────────────────────────────────────────────────

@app.route("/api/config/notifications")
@auth.login_required
@auth.requires_permission("manage_admin")
def api_config_notifications():
    return jsonify(config_validator.get_pending_notifications())


@app.route("/api/config/unconfigured")
@auth.login_required
@auth.requires_permission("manage_admin")
def api_config_unconfigured():
    """Return list of config keys that still have placeholder values."""
    return jsonify(list(config_validator.get_unconfigured_keys()))


@app.route("/api/config/notifications/dismiss/<int:nid>", methods=["POST"])
@auth.login_required
@auth.requires_permission("manage_admin")
def api_dismiss_notification(nid):
    config_validator.dismiss_notification(nid)
    return jsonify({"status": "ok"})


@app.route("/api/config/notifications/dismiss_all", methods=["POST"])
@auth.login_required
@auth.requires_permission("manage_admin")
def api_dismiss_all_notifications():
    config_validator.dismiss_all_notifications()
    return jsonify({"status": "ok"})


@app.route("/api/mfa/dismiss_banner", methods=["POST"])
@auth.login_required
def api_mfa_dismiss_banner():
    """Set a session flag so the MFA grace period banner stays hidden for this session."""
    session["mfa_banner_dismissed"] = True
    return jsonify({"status": "ok"})


# ══════════════════════════════════════════════════════════════════════════════
# ALERT SUBSCRIBER ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/admin/alerts")
@auth.login_required
@auth.requires_permission("manage_admin")
def alert_settings_page():
    """Alert settings — global defaults and subscriber management."""
    return render_template("alert_settings.html",
                           carriers=alert_subscribers.CARRIERS,
                           alert_types=alert_subscribers.ALERT_TYPES)


@app.route("/api/alerts/subscribers")
@auth.login_required
@auth.requires_permission("manage_admin")
def api_alert_subscribers():
    subs = alert_subscribers.get_all_subscribers()
    # Attach role_name for account-linked subscribers
    roles_by_id = {r["id"]: r["name"] for r in auth.get_all_roles()}
    for sub in subs:
        user_id = sub.get("user_id")
        if user_id:
            user = auth.get_user_by_id(user_id)
            sub["role_name"] = roles_by_id.get(user["role_id"], "") if user else ""
        else:
            sub["role_name"] = ""
    return jsonify(subs)


@app.route("/api/alerts/type_settings")
@auth.login_required
@auth.requires_permission("manage_admin")
def api_alert_type_settings():
    settings = alert_subscribers.get_alert_type_settings()
    # Merge with ALERT_TYPES metadata (label, group) for UI use
    result = {}
    for atype in alert_subscribers.ALERT_TYPES:
        key = atype["key"]
        db_row = settings.get(key, {})
        result[key] = {
            "alert_type":    key,
            "label":         atype["label"],
            "group":         atype.get("group", "network"),
            "critical":      atype.get("critical", False),
            "email_enabled": db_row.get("email_enabled", int(atype["default_email"])),
            "sms_enabled":   db_row.get("sms_enabled",   int(atype["default_sms"])),
        }
    return jsonify(result)


@app.route("/api/alerts/type_settings_user")
@auth.login_required
def api_alert_type_settings_user():
    """Same as type_settings but accessible to all logged-in users for preferences page.
    Includes per-type availability based on the current user's role."""
    settings = alert_subscribers.get_alert_type_settings()
    user = auth.get_current_user()
    # Look up the current user's role_id to check per-role availability
    role_id = None
    if user.get("id"):
        import sqlite3 as _sq
        import database as _db
        try:
            _conn = _sq.connect(_db.DB_PATH)
            row = _conn.execute("SELECT role_id FROM users WHERE id=?", (user["id"],)).fetchone()
            _conn.close()
            role_id = row[0] if row else None
        except Exception:
            pass
    all_role_defaults = alert_subscribers.get_all_role_alert_defaults()
    role_defaults = all_role_defaults.get(role_id, {}) if role_id else {}
    result = {}
    for atype in alert_subscribers.ALERT_TYPES:
        key = atype["key"]
        db_row = settings.get(key, {})
        rd = role_defaults.get(key, {})
        result[key] = {
            "alert_type":    key,
            "label":         atype["label"],
            "group":         atype.get("group", "network"),
            "critical":      atype.get("critical", False),
            "email_enabled": db_row.get("email_enabled", int(atype["default_email"])),
            "sms_enabled":   db_row.get("sms_enabled",   int(atype["default_sms"])),
            "available":     int(rd.get("available", 1)) if rd else 1,
        }
    return jsonify(result)


@app.route("/api/alerts/type_settings", methods=["POST"])
@auth.login_required
@auth.requires_permission("manage_admin")
def api_save_alert_type_settings():
    data = request.get_json()
    alert_subscribers.update_alert_type_settings(data)
    return jsonify({"status": "ok"})


@app.route("/api/alerts/subscribers/<int:sub_id>", methods=["DELETE"])
@auth.login_required
@auth.requires_permission("manage_admin")
def api_delete_subscriber(sub_id):
    sub = alert_subscribers.get_subscriber_by_id(sub_id)
    if not sub:
        return jsonify({"status": "error", "message": "Subscriber not found"}), 404
    if sub.get("user_id"):
        return jsonify({
            "status": "error",
            "message": "Cannot delete a subscriber with an active account. Delete the account from Users & Roles instead."
        }), 400
    alert_subscribers.delete_subscriber(sub_id)
    return jsonify({"status": "ok"})


@app.route("/api/alerts/subscribers/add", methods=["POST"])
@auth.login_required
@auth.requires_permission("manage_admin")
def api_add_subscriber():
    data = request.get_json()
    email_address = data.get("email_address", "").strip()
    sms_phone     = data.get("sms_phone", "").strip()

    # Check for duplicate contact info in any existing subscriber record
    conflict, conflict_type = alert_subscribers.check_duplicate_contact(
        email_address=email_address,
        sms_phone=sms_phone
    )
    if conflict:
        field = "email address" if (email_address and conflict.get("email_address") == email_address) else "phone number"
        if conflict_type == "account":
            username  = conflict.get("username") or "unknown"
            full_name = " ".join(filter(None, [conflict.get("first_name"), conflict.get("last_name")]))
            name_part = f" ({full_name})" if full_name else ""
            msg = f"An account already exists with this {field}: '{username}'{name_part}."
        else:
            full_name = " ".join(filter(None, [conflict.get("first_name"), conflict.get("last_name")]))
            label = full_name or conflict.get("email_address") or "Unknown"
            msg = f"A subscriber already exists with this {field}: {label}."
        return jsonify({"status": "conflict", "message": msg})

    alert_subscribers.upsert_subscriber(
        user_id=None,
        username=data.get("username", ""),
        first_name=data.get("first_name", ""),
        last_name=data.get("last_name", ""),
        email_address=email_address,
        email_enabled=data.get("email_enabled", False),
        sms_phone=sms_phone,
        sms_carrier=data.get("sms_carrier", ""),
        sms_custom_domain=data.get("sms_custom_domain", ""),
        sms_enabled=data.get("sms_enabled", False),
        alert_overrides=data.get("alert_overrides", {}),
    )
    return jsonify({"status": "ok"})


@app.route("/api/alerts/subscribers/<int:sub_id>", methods=["PUT"])
@auth.login_required
@auth.requires_permission("manage_admin")
def api_update_subscriber(sub_id):
    data = request.get_json()
    sub = alert_subscribers.get_subscriber_by_id(sub_id)
    if not sub:
        return jsonify({"status": "error", "message": "Not found"}), 404
    alert_subscribers.upsert_subscriber(
        user_id=sub.get("user_id"),
        username=data.get("username", sub.get("username", "")),
        first_name=data.get("first_name", sub.get("first_name", "")),
        last_name=data.get("last_name", sub.get("last_name", "")),
        email_address=data.get("email_address", ""),
        email_enabled=data.get("email_enabled", False),
        sms_phone=data.get("sms_phone", ""),
        sms_carrier=data.get("sms_carrier", ""),
        sms_custom_domain=data.get("sms_custom_domain", ""),
        sms_enabled=data.get("sms_enabled", False),
        alert_overrides=data.get("alert_overrides", {}),
    )
    return jsonify({"status": "ok"})


@app.route("/api/alerts/carriers")
@auth.guest_allowed
def api_alert_carriers():
    return jsonify(alert_subscribers.CARRIERS)


# ── Alerts infrastructure guard ───────────────────────────────────────────────

def _alerts_disabled_json(user=None):
    """Standardised response when ALERTS_ENABLED=False.
    Admins get a link to the config editor; other users get a softer message."""
    is_admin = user and user.get("manage_admin")
    if is_admin:
        msg = ("Alerts are currently disabled. You can re-enable them in the "
               "Config Editor (/admin/config).")
    else:
        msg = ("Alerts are currently disabled by the administrator. "
               "Please try again later.")
    return jsonify({"status": "alerts_disabled", "message": msg})


# ── User self-service alert subscription (in their profile) ───────────────────

@app.route("/api/alerts/my_subscription")
@auth.login_required
def api_my_subscription():
    user = auth.get_current_user()
    sub  = alert_subscribers.get_subscriber_by_user_id(user["id"])
    if not sub:
        # Fall back to owner record matched by username (owner may not have user_id set)
        sub = alert_subscribers.get_subscriber_by_username(user["username"])
    return jsonify(sub or {})


@app.route("/api/alerts/my_subscription", methods=["POST"])
@auth.login_required
def api_save_my_subscription():
    user = auth.get_current_user()
    data = request.get_json()
    db_user = auth.get_user_by_id(user["id"])
    alert_subscribers.upsert_subscriber(
        user_id=user["id"],
        username=user["username"],
        first_name=db_user.get("first_name") or "",
        last_name=db_user.get("last_name") or "",
        email_address=data.get("email_address", ""),
        email_enabled=data.get("email_enabled", False),
        sms_phone=data.get("sms_phone", ""),
        sms_carrier=data.get("sms_carrier", ""),
        sms_custom_domain=data.get("sms_custom_domain", ""),
        sms_enabled=data.get("sms_enabled", False),
        alert_overrides=data.get("alert_overrides", {}),
    )
    return jsonify({"status": "ok"})

@app.route("/login", methods=["GET", "POST"])
def login():
    # Already logged in (real user, not guest) — go home
    user = auth.get_current_user()
    if user and not user.get("is_guest"):
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        next_url = request.form.get("next", "")

        user = auth.authenticate(username, password, ip_address=request.remote_addr)

        if not user:
            return render_template("login.html", error="Invalid username or password.")

        # Account locked
        if isinstance(user, dict) and user.get("_locked"):
            mins = user.get("locked_minutes_remaining", "?")
            return render_template("login.html",
                error=f"Account is temporarily locked. Try again in {mins} minute(s).")

        # Reset token expired
        if isinstance(user, dict) and user.get("_reset_expired"):
            return render_template("login.html",
                error="Your password reset link has expired. Please request a new one.")

        # ── MFA / grace period handling ────────────────────────────────────────
        role_name  = user.get("role_name", "")
        mfa_status = auth.get_mfa_status(user["id"])

        if mfa_status["enabled"]:
            # MFA is configured — require challenge before completing login
            session["mfa_pending"]      = user["id"]
            session["mfa_next_url"]     = next_url or url_for("index")
            session["mfa_must_change"]  = bool(user.get("must_change_pass"))
            return redirect(url_for("mfa_challenge"))

        if role_name in auth.MFA_MANDATORY_ROLES and not mfa_status["enabled"]:
            # Role requires MFA but user hasn't set it up yet
            if mfa_status["grace_expired"]:
                # Grace period over — must set up MFA before doing anything else
                auth.login_user(user)
                session.pop("_flashes", None)
                return redirect(url_for("mfa_setup", forced=1))
            elif not mfa_status["grace_deadline"]:
                # First login without MFA — set grace deadline
                auth.set_mfa_grace_deadline(user["id"])
        # ── End MFA handling ──────────────────────────────────────────────────

        auth.login_user(user)

        # Clear any flash messages from previous session so they don't show to this user
        session.pop("_flashes", None)

        # Force password change before anything else
        if user.get("must_change_pass"):
            import config as _cfg
            timeout_mins = getattr(_cfg, "FORCED_CHANGE_TIMEOUT_MINUTES", 10)
            from datetime import timedelta
            deadline = (datetime.now() + timedelta(minutes=timeout_mins)).isoformat()
            session["forced_change_deadline"]   = deadline
            session["must_change_pass_pending"] = True
            return redirect(url_for("change_password", forced=1))

        return redirect(next_url or url_for("index"))

    prefill_username = request.args.get("username", "").strip()
    return render_template("login.html", username=prefill_username)


# ══════════════════════════════════════════════════════════════════════════════
# MFA ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/mfa", methods=["GET", "POST"])
def mfa_challenge():
    """
    Second-factor challenge page. Shown after credentials pass but before
    login_user() fires. Accepts TOTP code, backup code, or email/SMS OTP.
    Session must have mfa_pending set — otherwise redirect to login.
    """
    user_id = session.get("mfa_pending")
    if not user_id:
        return redirect(url_for("login"))

    error   = None
    mode    = request.args.get("mode", "totp")   # totp | backup | email | sms

    if request.method == "POST":
        action = request.form.get("action", "verify")

        if action == "verify_totp":
            code = request.form.get("code", "").strip().replace(" ", "")
            if auth.verify_totp(user_id, code):
                return _complete_mfa_login(user_id)
            error = "Invalid code. Check your authenticator app and try again."
            mode  = "totp"

        elif action == "verify_backup":
            code = request.form.get("code", "").strip()
            if auth.verify_backup_code(user_id, code):
                return _complete_mfa_login(user_id)
            error = "Invalid or already-used backup code."
            mode  = "backup"

        elif action == "verify_challenge":
            channel = request.form.get("channel", "email")
            code    = request.form.get("code", "").strip()
            ok, reason = auth.verify_mfa_challenge_code(user_id, channel, code)
            if ok:
                return _complete_mfa_login(user_id)
            error = reason
            mode  = channel

        # Note: send_code action is handled directly by /mfa/send_code route
        # (template forms post there); this branch is a safety fallback only

    # Determine available fallback channels for this user
    import alert_subscribers as subs_mod
    sub = subs_mod.get_subscriber_by_user_id(user_id)
    has_email = bool(sub and sub.get("email_address") and
                     auth.get_email_verification_status(user_id, sub["email_address"]) == "verified")
    has_sms   = bool(sub and sub.get("sms_phone") and
                     auth.get_phone_verification_status(user_id, sub["sms_phone"]) == "verified")

    # Pop flash-style session values so they don't persist on reload
    code_sent  = session.pop("mfa_code_sent",  None)
    send_error = session.pop("mfa_send_error", None)

    return render_template("mfa_challenge.html",
        mode=mode, error=error, has_email=has_email, has_sms=has_sms,
        mfa_expiry=auth.MFA_CHALLENGE_EXPIRY_MINUTES,
        code_sent=code_sent, send_error=send_error)


@app.route("/mfa/send_code", methods=["GET", "POST"])
def mfa_send_code():
    """
    Send a one-time code via email or SMS for the MFA challenge fallback.
    Redirects back to /mfa?mode=<channel> with a status message.
    """
    user_id = session.get("mfa_pending")
    if not user_id:
        return redirect(url_for("login"))

    channel = (request.form.get("channel") or request.args.get("channel", "email"))
    if channel not in ("email", "sms"):
        return redirect(url_for("mfa_challenge"))

    ok, plain_code = auth.generate_mfa_challenge_code(user_id, channel)
    if not ok:
        session["mfa_send_error"] = plain_code
        return redirect(url_for("mfa_challenge", mode=channel))

    # Deliver the code via the alert system
    import alerts
    import alert_subscribers as subs_mod
    sub = subs_mod.get_subscriber_by_user_id(user_id)
    sent = False
    if channel == "email" and sub and sub.get("email_address"):
        msg  = (f"Your NetWatch login verification code is: {plain_code}\n\n"
                f"This code expires in {auth.MFA_CHALLENGE_EXPIRY_MINUTES} minutes. Do not share it.")
        sent = alerts.send_alert("mfa_code", msg,
                                 force_email=sub["email_address"],
                                 subject="🔐  NetWatch: Login Verification Code")
    elif channel == "sms" and sub:
        sms_addr = subs_mod.get_sms_address(sub)
        if sms_addr:
            sent = alerts._send_one(sms_addr,
                             f"{alerts._site_name()}: MFA CODE",
                             f"Your login code: {plain_code} (expires in {auth.MFA_CHALLENGE_EXPIRY_MINUTES} min)",
                             f"Your login code: {plain_code} (expires in {auth.MFA_CHALLENGE_EXPIRY_MINUTES} min)")

    if sent:
        session["mfa_code_sent"] = channel
    else:
        session["mfa_send_error"] = f"Failed to send code via {channel}. Try another method."

    return redirect(url_for("mfa_challenge", mode=channel))


def _complete_mfa_login(user_id):
    """
    Internal helper: called when MFA challenge passes.
    Loads the full user record, calls login_user(), clears mfa_pending,
    and redirects to the intended destination.
    """
    next_url     = session.pop("mfa_next_url", None) or url_for("index")
    must_change  = session.pop("mfa_must_change", False)
    session.pop("mfa_pending", None)
    session.pop("mfa_code_sent", None)
    session.pop("mfa_send_error", None)

    user = auth.get_user_by_id(user_id)
    if not user:
        return redirect(url_for("login"))

    auth.login_user(user)
    session.pop("_flashes", None)

    if must_change:
        import config as _cfg
        timeout_mins = getattr(_cfg, "FORCED_CHANGE_TIMEOUT_MINUTES", 10)
        from datetime import timedelta
        deadline = (datetime.now() + timedelta(minutes=timeout_mins)).isoformat()
        session["forced_change_deadline"]   = deadline
        session["must_change_pass_pending"] = True
        return redirect(url_for("change_password", forced=1))

    return redirect(next_url)


@app.route("/account/mfa/setup", methods=["GET", "POST"])
@auth.login_required
def mfa_setup():
    """
    MFA setup page. GET: shows QR code for scanning.
    Pending secret is stored in session only — never written to DB until confirmed.
    POST (action=confirm): verifies code, writes secret to DB, enables MFA.
    POST (action=cancel): clears session secret, existing DB secret untouched.
    """
    user    = auth.get_current_user()
    forced  = request.args.get("forced", "0") == "1"
    error   = None

    # Forced setup just completed — redirect to dashboard
    if request.args.get("forced_done") == "1":
        return redirect(url_for("index"))

    if request.method == "POST":
        action = request.form.get("action", "confirm")

        if action == "confirm":
            code           = request.form.get("totp_code", "").strip().replace(" ", "")
            pending_secret = session.get("mfa_setup_secret")
            ok, result     = auth.confirm_mfa_setup(user["id"], code, pending_secret)
            if not ok:
                # Re-render with same session secret — never touch the DB secret
                if pending_secret:
                    _, uri  = auth.get_mfa_setup_uri_from_secret(pending_secret, user["username"])
                    qr_data = _mfa_qr_base64(uri)
                else:
                    qr_data = None
                return render_template("mfa_setup.html",
                    secret=pending_secret, qr_data=qr_data, error=result, forced=forced)
            # Success — clear pending secret and show backup codes
            session.pop("mfa_setup_secret", None)
            backup_codes = result
            return render_template("mfa_setup_complete.html",
                backup_codes=backup_codes, forced=forced)

        elif action == "cancel" and not forced:
            session.pop("mfa_setup_secret", None)
            return redirect(url_for("preferences"))

    # GET — use session-stored pending secret if present; generate new only if
    # explicitly requested (?new=1) or none exists in session yet.
    # Never read mfa_secret from DB here — that is the live confirmed secret.
    pending_secret = session.get("mfa_setup_secret")
    if not pending_secret or request.args.get("new") == "1":
        secret, uri = auth.setup_mfa(user["id"])
        session["mfa_setup_secret"] = secret
    else:
        secret = pending_secret
        _, uri = auth.get_mfa_setup_uri_from_secret(secret, user["username"])
    if not secret:
        return redirect(url_for("preferences"))
    qr_data = _mfa_qr_base64(uri)
    return render_template("mfa_setup.html",
        secret=secret, qr_data=qr_data, error=error, forced=forced)


@app.route("/account/mfa/setup/confirm", methods=["POST"])
@auth.login_required
def mfa_setup_confirm():
    """Confirm TOTP code during setup — called from mfa_setup.html form."""
    user           = auth.get_current_user()
    forced         = request.form.get("forced", "0") == "1"
    code           = request.form.get("totp_code", "").strip().replace(" ", "")
    pending_secret = session.get("mfa_setup_secret")

    ok, result = auth.confirm_mfa_setup(user["id"], code, pending_secret)
    if not ok:
        if pending_secret:
            _, uri  = auth.get_mfa_setup_uri_from_secret(pending_secret, user["username"])
            qr_data = _mfa_qr_base64(uri)
        else:
            qr_data = None
        return render_template("mfa_setup.html",
            secret=pending_secret, qr_data=qr_data, error=result, forced=forced)

    session.pop("mfa_setup_secret", None)
    backup_codes = result
    return render_template("mfa_setup_complete.html",
        backup_codes=backup_codes, forced=forced)


@app.route("/account/mfa/disable", methods=["POST"])
@auth.login_required
def mfa_disable():
    """
    Disable MFA for the current user. Requires current password for confirmation.
    Sets a grace deadline if role requires MFA, so the enforcement banner shows.
    """
    user     = auth.get_current_user()
    password = request.form.get("password", "")
    verified = auth.authenticate(user["username"], password)
    if not verified or not verified.get("id"):
        return jsonify({"status": "error", "message": "Incorrect password"}), 403

    auth.disable_mfa(user["id"])

    # If role requires MFA, set grace deadline so banner appears on next page load
    if user["role_name"] in auth.MFA_MANDATORY_ROLES:
        auth.set_mfa_grace_deadline(user["id"])

    log.info("MFA disabled by user", username=user["username"])
    return jsonify({"status": "ok"})


@app.route("/account/mfa/backup_codes/regenerate", methods=["POST"])
@auth.login_required
def mfa_regenerate_backup_codes():
    """Regenerate all backup codes for the current user. Returns new codes as JSON."""
    user     = auth.get_current_user()
    password = request.form.get("password", "")
    verified = auth.authenticate(user["username"], password)
    if not verified or not verified.get("id"):
        return jsonify({"status": "error", "message": "Incorrect password"}), 403

    codes = auth.regenerate_backup_codes(user["id"])
    return jsonify({"status": "ok", "codes": codes})


@app.route("/api/admin/mfa_reset/<int:target_user_id>", methods=["POST"])
@auth.login_required
@auth.requires_permission("manage_users")
def api_admin_mfa_reset(target_user_id):
    """Admin: reset MFA for a user (e.g. locked out). Sets fresh grace deadline."""
    auth.admin_reset_mfa(target_user_id)
    log.info("Admin MFA reset", admin=auth.get_current_user()["username"],
             target_user_id=target_user_id)
    return jsonify({"status": "ok"})


def _mfa_qr_base64(uri):
    """Generate a QR code SVG from an otpauth URI and return as a base64 data URL.
    Uses the pure-Python SVG factory so Pillow is not required."""
    import qrcode
    import qrcode.image.svg
    import io, base64
    factory = qrcode.image.svg.SvgPathImage
    qr  = qrcode.QRCode(image_factory=factory, box_size=6, border=2)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image()
    buf = io.BytesIO()
    img.save(buf)
    b64 = base64.b64encode(buf.getvalue()).decode()
    return f"data:image/svg+xml;base64,{b64}"


@app.before_request
def enforce_forced_change_deadline():
    """
    If user has must_change_pass set, enforce the deadline on every request.
    If deadline has passed or was never set, log them out and send to login.
    Exempts the change_password, login, logout, and static routes.
    """
    exempt = {"change_password", "login", "logout", "forgot_password",
              "static", "first_run_wizard",
              "mfa_challenge", "mfa_send_code", "mfa_setup", "mfa_setup_confirm"}
    if request.endpoint in exempt or request.endpoint is None:
        return

    user = session.get("user_id")
    if not user:
        return

    # Only applies to users with must_change_pass — read from session to avoid
    # a DB hit on every request (auth.get_current_user handles the DB read)
    if not session.get("must_change_pass_pending"):
        return

    deadline_str = session.get("forced_change_deadline")
    if not deadline_str:
        # No deadline set — session was restored without going through login
        # (e.g. tab restored after browser crash). Treat as expired.
        auth.logout_user()
        flash("Your password change session expired. Please log in again.", "warning")
        return redirect(url_for("login"))

    try:
        if datetime.now() > datetime.fromisoformat(deadline_str):
            auth.logout_user()
            flash("Your password change session expired. Please log in again.", "warning")
            return redirect(url_for("login"))
    except Exception:
        auth.logout_user()
        return redirect(url_for("login"))


# last_activity is updated only via /api/session/ping (called on real user events:
# mousedown, keydown, touchstart, scroll, wheel). Auto-refresh polling on any page
# must NOT update last_activity — doing so from before_request would require
# maintaining a complete blocklist of every polling endpoint, which is fragile.
# The ping-only approach means idle time is measured from the last real interaction.


@app.route("/logout")
def logout():
    user = auth.get_current_user()
    if user and not user.get("is_guest"):
        import security_log as seclog
        seclog.record(seclog.LOGOUT, username=user["username"],
                      ip_address=request.remote_addr, success=1)
    auth.logout_user()
    return redirect(url_for("login"))


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    """Self-service password reset via verified email."""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        if not username:
            flash("Please enter your username.", "warning")
            return render_template("forgot_password.html")

        ok, result, temp_pw = auth.request_password_reset(username)

        if not ok:
            # Don't reveal whether the account exists or has verified contact methods
            flash("If that username has a verified contact method, a reset code has been sent.", "info")
            return render_template("forgot_password.html", submitted=True)

        import alerts
        import alert_subscribers as _subs
        sub = _subs.get_subscriber_by_username(username)
        sub_id = sub["id"] if sub else None

        email       = result.get("email")
        sms_address = result.get("sms_address")
        channels_sent = []

        reset_msg = (
            f"Password reset requested for account '{username}'.\n\n"
            f"Your temporary password is: {temp_pw}\n\n"
            f"Log in at https://{request.host}/login?username={username} with this password. "
            f"It expires in 15 minutes and you will be prompted to set a new password."
        )
        sms_msg = f"NetWatch reset code for {username}: {temp_pw} (expires 15 min)"

        if email:
            try:
                alerts.send_alert("password_reset", reset_msg,
                                  force_email=email, subscriber_id=sub_id)
                channels_sent.append(f"email ({email[:3]}***)")
            except Exception as e:
                log.error("password_reset_email_failed", error=str(e))

        if sms_address:
            try:
                from alerts import _send_one, SUBJECTS
                ok_sms = _send_one(sms_address, f"NetWatch: Password Reset", sms_msg, sms_msg)
                import alert_subscribers as _subs2
                _subs2.log_delivery(
                    alert_type="password_reset", alert_event=reset_msg,
                    subscriber_id=sub_id, channel="sms", address=sms_address,
                    success=ok_sms, is_test=False
                )
                if ok_sms:
                    channels_sent.append(f"SMS ({sms_address[:6]}***)")
            except Exception as e:
                log.error("password_reset_sms_failed", error=str(e))

        import security_log as seclog
        seclog.record("PASSWORD_RESET_REQUESTED", username=username,
                      ip_address=request.remote_addr,
                      detail=f"Reset code sent via {' + '.join(channels_sent) if channels_sent else 'no channel'}",
                      success=1)

        flash("If that username has a verified contact method, a reset code has been sent.", "info")
        return render_template("forgot_password.html", submitted=True)

    return render_template("forgot_password.html")


@app.route("/api/email/verify/request", methods=["POST"])
@auth.login_required
def api_request_email_verification():
    """Send a verification code to the user's email address."""
    user  = auth.get_current_user()
    if not config.ALERTS_ENABLED:
        return _alerts_disabled_json(user)
    email = (request.get_json() or {}).get("email", "").strip()
    if not email:
        return jsonify({"status": "error", "message": "Email address required"})

    ok, code_or_err = auth.request_email_verification(user["id"], email)
    if not ok:
        return jsonify({"status": "error", "message": code_or_err})

    # Send the code by email
    try:
        import alerts
        import alert_subscribers as _subs
        sub = _subs.get_subscriber_by_user_id(user["id"])
        sub_id = sub["id"] if sub else None
        alerts.send_alert("email_verification",
            f"NetWatch email verification\n\nYour verification code is: {code_or_err}\n\n"
            f"Enter this code in the NetWatch My Account page. It expires in 24 hours.",
            force_email=email, subscriber_id=sub_id)
    except Exception as e:
        log.error("verification_email_failed", error=str(e))
        return jsonify({"status": "error", "message": "Failed to send email. Check email config."})

    return jsonify({"status": "ok", "message": f"Verification code sent to {email}"})


@app.route("/api/email/verify/confirm", methods=["POST"])
@auth.login_required
def api_confirm_email_verification():
    """Confirm a verification code submitted by the user."""
    user  = auth.get_current_user()
    data  = request.get_json() or {}
    email = data.get("email", "").strip()
    code  = data.get("code", "").strip()

    ok, err = auth.verify_email_code(user["id"], email, code)
    if not ok:
        return jsonify({"status": "error", "message": err})

    # Check if a standalone subscriber record exists with this email — merge if so
    standalone = alert_subscribers.find_standalone_by_email(email)
    if standalone:
        alert_subscribers.merge_standalone_into_account(user["id"], standalone["id"])
        log.info("subscriber_merged_on_verify", subscriber_id=standalone['id'], username=user['username'])

    return jsonify({"status": "ok", "message": "Email verified successfully"})


@app.route("/api/email/verify/status")
@auth.login_required
def api_email_verification_status():
    """Get verification status for the current user's email."""
    user  = auth.get_current_user()
    email = (request.args.get("email") or "").strip()
    status = auth.get_email_verification_status(user["id"], email)
    return jsonify({"status": status, "email": email})


@app.route("/api/admin/users/<int:user_id>/unlock", methods=["POST"])
@auth.login_required
@auth.requires_permission("manage_users")
def api_unlock_user(user_id):
    """Admin: remove temporary lock from a user account."""
    ok, err = auth.unlock_account(user_id)
    if not ok:
        return jsonify({"status": "error", "message": err})
    import security_log as seclog
    admin = auth.get_current_user()
    seclog.record("ACCOUNT_UNLOCKED", username=f"user_id:{user_id}",
                  ip_address=request.remote_addr,
                  detail=f"Unlocked by {admin['username']}", success=1)
    return jsonify({"status": "ok"})


@app.route("/api/admin/users/<int:user_id>/set_active", methods=["POST"])
@auth.login_required
@auth.requires_permission("manage_users")
def api_set_user_active(user_id):
    """Admin: enable or disable a user account."""
    data      = request.get_json() or {}
    is_active = bool(data.get("is_active", True))
    ok, err   = auth.update_user(user_id, is_active=is_active)
    if not ok:
        return jsonify({"status": "error", "message": err})
    import security_log as seclog
    admin  = auth.get_current_user()
    target = auth.get_user_by_id(user_id)
    action = "ACCOUNT_ENABLED" if is_active else "ACCOUNT_DISABLED"
    seclog.record(action, username=target["username"] if target else f"id:{user_id}",
                  ip_address=request.remote_addr,
                  detail=f"{'Enabled' if is_active else 'Disabled'} by {admin['username']}", success=1)
    return jsonify({"status": "ok"})


@app.route("/api/admin/users/<int:user_id>/lock_status")
@auth.login_required
@auth.requires_permission("manage_users")
def api_user_lock_status(user_id):
    """Admin: get lock status for a user."""
    return jsonify(auth.get_lock_status(user_id))


@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    user = auth.get_current_user()
    if not user:
        return redirect(url_for("login"))

    forced = (request.args.get("forced", "0") in ("1", "True", "true") or
              request.form.get("forced", "0") in ("1", "True", "true"))

    # Security: only allow forced mode if this user actually requires a password change.
    if forced and not user.get("must_change_pass"):
        return redirect(url_for("index"))

    if request.method == "POST":
        new_password     = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")
        current_password = request.form.get("current_password", "")

        if len(new_password) < 8:
            flash("Password must be at least 8 characters.", "danger")
            return render_template("change_password.html", forced=forced)

        if new_password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("change_password.html", forced=forced)

        # If not forced change, verify current password
        if not forced:
            verified = auth.authenticate(user["username"], current_password)
            if not verified:
                flash("Current password is incorrect.", "danger")
                return render_template("change_password.html", forced=forced)

        success, error = auth.change_password(user["id"], new_password)
        if success:
            import security_log as seclog
            seclog.record(seclog.PASSWORD_CHANGE, username=user["username"],
                          ip_address=request.remote_addr,
                          detail="Forced change" if forced else "User-initiated", success=1)
            # Clear forced-change session flags
            session.pop("forced_change_deadline",   None)
            session.pop("must_change_pass_pending", None)
            flash("Password changed successfully.", "success")
            return redirect(url_for("index"))
        else:
            flash(f"Error: {error}", "danger")

    return render_template("change_password.html", forced=forced)


# ══════════════════════════════════════════════════════════════════════════════
# PAGE ROUTES — all protected by login_required
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/")
@auth.guest_allowed
def index():
    user = auth.get_current_user()
    if user and user.get("must_change_pass"):
        return redirect(url_for("change_password", forced=1))
    return render_template("index.html")


@app.route("/metrics")
@auth.guest_allowed
def metrics():
    check_interval = getattr(config, "CHECK_INTERVAL", 30)
    return render_template("metrics.html", check_interval=check_interval)


@app.route("/logs")
@auth.login_required
@auth.requires_permission("view_logs")
def logs_page():
    return render_template("logs.html")


@app.route("/security")
@auth.login_required
@auth.requires_permission("manage_admin")
def security_log_page():
    return render_template("security_log.html")


@app.route("/api/security/events")
@auth.login_required
@auth.requires_permission("manage_admin")
def api_security_events():
    limit       = int(request.args.get("limit", 100))
    event_types = request.args.getlist("type") or None
    since       = request.args.get("since") or None
    return jsonify(security_log.get_events(limit=limit, event_types=event_types, since=since))


@app.route("/api/security/recent_failures")
@auth.login_required
@auth.requires_permission("manage_admin")
def api_security_failures():
    minutes = int(request.args.get("minutes", 60))
    return jsonify(security_log.get_recent_failures(minutes=minutes))


@app.route("/controls")
@auth.login_required
@auth.requires_permission("use_controls")
def controls():
    return render_template("controls.html")


@app.route("/admin")
@auth.login_required
@auth.requires_permission("manage_admin")
def admin():
    return render_template("admin.html",
        keep_health_days=getattr(config, "KEEP_HEALTH_DAYS", 30),
        keep_reset_days=getattr(config, "KEEP_RESET_DAYS", 90),
    )


@app.route("/admin/users")
@auth.login_required
@auth.requires_permission("manage_users")
def admin_users():
    return render_template("admin_users.html")


@app.route("/preferences")
@auth.login_required
def preferences():
    user       = auth.get_current_user()
    mfa_status = auth.get_mfa_status(user["id"])

    # Calculate days remaining in grace period
    mfa_grace_days_left = None
    if mfa_status["grace_deadline"] and not mfa_status["enabled"]:
        try:
            from datetime import timedelta
            deadline = datetime.fromisoformat(mfa_status["grace_deadline"])
            remaining = (deadline - datetime.now()).days + 1
            mfa_grace_days_left = max(0, remaining)
        except Exception:
            mfa_grace_days_left = 0

    return render_template("preferences.html",
        mfa_status=mfa_status,
        mfa_grace_days_left=mfa_grace_days_left,
        current_user=user)


@app.route("/api/preferences", methods=["POST"])
@auth.login_required
def api_save_preferences():
    """Save the current user's color scheme and/or layout preference."""
    data         = request.get_json() or {}
    theme        = data.get("theme")       # internal key stays 'theme'; UI calls it 'color scheme'
    layout       = data.get("layout")
    nav_style    = data.get("nav_style")
    content_align = data.get("content_align")
    user         = auth.get_current_user()
    is_guest     = user.get("is_guest", False)
    valid_themes   = ["dark-blue", "dark-green", "light", "high-contrast"]  # system color schemes
    valid_layouts  = ["comfortable", "compact", "dashboard-first", "sidebar"]
    valid_navstyles = ["icons-labels", "icons-only", "labels-only", "compact"]
    valid_aligns    = ["left", "center"]

    if theme  and theme  not in valid_themes:
        return jsonify({"status": "error", "message": "Invalid theme"})
    if layout and layout not in valid_layouts:
        return jsonify({"status": "error", "message": "Invalid layout"})
    if content_align and content_align not in valid_aligns:
        return jsonify({"status": "error", "message": "Invalid content_align"})

    user = auth.get_current_user()
    if is_guest:
        if theme:         session["guest_theme"]        = theme
        if layout:        session["guest_layout"]       = layout
        if nav_style:     session["guest_nav_style"]    = nav_style
        if content_align: session["guest_content_align"] = content_align
        return jsonify({"status": "ok"})
    auth.save_preferences(user["id"], theme=theme, layout=layout,
                          nav_style=nav_style, content_align=content_align)
    return jsonify({"status": "ok"})


# ── Custom theme preference routes ────────────────────────────────────────────

@app.route("/api/preferences/custom_scheme", methods=["POST"])
@auth.login_required
def api_set_custom_color_scheme():
    """Set the active custom color scheme for the current user. Pass name='' to clear."""
    data = request.get_json() or {}
    name = data.get("name", "").strip()
    user = auth.get_current_user()
    if user["is_guest"]:
        return jsonify({"status": "error", "message": "Guests cannot save custom schemes"})
    if name:
        # Verify the theme exists and has a color_scheme
        t = theme_manager.get_theme(name)
        if not t:
            return jsonify({"status": "error", "message": "Theme not found"})
        if not t.get("color_scheme"):
            return jsonify({"status": "error", "message": "That theme has no color scheme"})
    database.set_user_pref(user["id"], "custom_color_scheme", name if name else None)
    return jsonify({"status": "ok"})


@app.route("/api/preferences/custom_layout", methods=["POST"])
@auth.login_required
def api_set_custom_layout():
    """Set the active custom layout for the current user. Pass name='' to clear."""
    data = request.get_json() or {}
    name = data.get("name", "").strip()
    user = auth.get_current_user()
    if user["is_guest"]:
        return jsonify({"status": "error", "message": "Guests cannot save custom layouts"})
    if name:
        t = theme_manager.get_theme(name)
        if not t:
            return jsonify({"status": "error", "message": "Theme not found"})
        if not t.get("layout"):
            return jsonify({"status": "error", "message": "That theme has no layout"})
    database.set_user_pref(user["id"], "custom_layout", name if name else None)
    return jsonify({"status": "ok"})


# ── Dashboard preference routes ───────────────────────────────────────────────

VALID_SPEEDTEST_RANGES = ["latest", "1", "7", "30", "all"]
VALID_RESET_RANGES     = ["1", "7", "30", "all"]

@app.route("/api/preferences/dashboard", methods=["GET"])
@auth.guest_allowed
def api_get_dashboard_prefs():
    """Return the current user's dashboard display preferences."""
    user = auth.get_current_user()
    if user["is_guest"]:
        return jsonify({"speedtest_range": "latest", "resets_range": "1"})
    spd = database.get_user_pref(user["id"], "dashboard_speedtest_range") or "latest"
    rst = database.get_user_pref(user["id"], "dashboard_resets_range")    or "1"
    return jsonify({"speedtest_range": spd, "resets_range": rst})


@app.route("/api/preferences/dashboard", methods=["POST"])
@auth.login_required
def api_save_dashboard_prefs():
    """Save the current user's dashboard display preferences."""
    data  = request.get_json() or {}
    user  = auth.get_current_user()
    spd   = data.get("speedtest_range")
    rst   = data.get("resets_range")
    if spd and spd not in VALID_SPEEDTEST_RANGES:
        return jsonify({"status": "error", "message": "Invalid speedtest_range"})
    if rst and rst not in VALID_RESET_RANGES:
        return jsonify({"status": "error", "message": "Invalid resets_range"})
    if spd:
        database.set_user_pref(user["id"], "dashboard_speedtest_range", spd)
    if rst:
        database.set_user_pref(user["id"], "dashboard_resets_range", rst)
    return jsonify({"status": "ok"})


# ── Theme Manager API (admin only) ────────────────────────────────────────────

@app.route("/api/themes", methods=["GET"])
@auth.login_required
def api_list_themes():
    """List all available custom themes."""
    themes = theme_manager.load_themes()
    result = []
    for t in themes:
        result.append({
            "name":             t.get("name"),
            "description":      t.get("description", ""),
            "author":           t.get("author", ""),
            "version":          t.get("version", ""),
            "has_color_scheme": bool(t.get("color_scheme")),
            "has_layout":       bool(t.get("layout")),
            "disabled":         bool(t.get("_disabled")),
        })
    return jsonify({"status": "ok", "themes": result})


@app.route("/api/themes/toggle_disabled", methods=["POST"])
@auth.login_required
@auth.requires_permission("manage_admin")
def api_toggle_theme_disabled():
    """Enable or disable a custom theme. Admin only."""
    data     = request.get_json() or {}
    name     = data.get("name", "").strip()
    disabled = bool(data.get("disabled", False))
    if not name:
        return jsonify({"status": "error", "message": "No theme name provided"}), 400
    ok, err = theme_manager.set_theme_disabled(name, disabled)
    if ok:
        return jsonify({"status": "ok"})
    return jsonify({"status": "error", "message": err}), 400


@app.route("/api/themes/import", methods=["POST"])
@auth.login_required
@auth.requires_permission("manage_admin")
def api_import_theme():
    """Upload and install a .nwtheme file. Admin only."""
    f = request.files.get("file")
    if not f:
        return jsonify({"status": "error", "message": "No file provided"}), 400
    if not f.filename.endswith(".nwtheme"):
        return jsonify({"status": "error", "message": "File must have .nwtheme extension"}), 400
    data_bytes = f.read()
    if len(data_bytes) > 64 * 1024:  # 64 KB max
        return jsonify({"status": "error", "message": "File too large (64 KB max)"}), 400
    ok, result = theme_manager.save_theme(data_bytes)
    if ok:
        return jsonify({"status": "ok", "name": result})
    return jsonify({"status": "error", "message": result}), 400


@app.route("/api/themes/export/<path:name>", methods=["GET"])
@auth.login_required
@auth.requires_permission("manage_admin")
def api_export_theme(name):
    """Download a custom theme as a .nwtheme file. Admin only."""
    t = theme_manager.get_theme(name)
    if not t:
        return jsonify({"status": "error", "message": "Theme not found"}), 404
    # Build clean export dict (no internal keys)
    export = {k: v for k, v in t.items() if not k.startswith("_")}
    import io
    buf = io.BytesIO(json.dumps(export, indent=2, ensure_ascii=False).encode("utf-8"))
    safe_name = re.sub(r'[^\w\-]', '_', name.strip())
    return send_file(buf, mimetype="application/json",
                     as_attachment=True, download_name=f"{safe_name}.nwtheme")


@app.route("/api/themes/delete", methods=["POST"])
@auth.login_required
@auth.requires_permission("manage_admin")
def api_delete_theme():
    """Delete a custom theme by name. Admin only."""
    data = request.get_json() or {}
    name = data.get("name", "").strip()
    if not name:
        return jsonify({"status": "error", "message": "No theme name provided"}), 400
    ok, err = theme_manager.delete_theme(name)
    if ok:
        return jsonify({"status": "ok"})
    return jsonify({"status": "error", "message": err}), 400


@app.route("/admin/themes/kit")
@auth.login_required
@auth.requires_permission("manage_admin")
def admin_themes_kit():
    """Serve the Theme Creation Kit as a downloadable markdown file."""
    from flask import Response as _Resp
    kit = theme_manager.get_theme_kit_markdown()
    return _Resp(
        kit,
        mimetype="text/markdown",
        headers={"Content-Disposition": "attachment; filename=\"netwatch_theme_kit.md\""}
    )


# ══════════════════════════════════════════════════════════════════════════════
# AUTH API — User management endpoints
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/auth/users", methods=["GET"])
@auth.login_required
@auth.requires_permission("manage_users")
def api_get_users():
    return jsonify(auth.get_all_users())


@app.route("/api/auth/users", methods=["POST"])
@auth.login_required
@auth.requires_permission("manage_users")
def api_create_user():
    data     = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    role_id  = data.get("role_id")

    if not username or not password or not role_id:
        return jsonify({"status": "error", "message": "Username, password and role are required"})

    must_change = bool(data.get("must_change_pass", True))  # default True if not specified
    success, error = auth.create_user(username, password, role_id, must_change_pass=must_change)
    if success:
        # Seed a blank subscriber record so the user always appears in the Alerts subscriber list
        new_user = auth.get_user_by_username(username)
        if new_user:
            alert_subscribers.upsert_subscriber(
                user_id=new_user["id"], username=username,
                first_name="", last_name="",
                email_address="", email_enabled=False,
                sms_phone="", sms_carrier="", sms_custom_domain="", sms_enabled=False,
                alert_overrides={},
            )
        return jsonify({"status": "ok", "message": f"User '{username}' created"})
    return jsonify({"status": "error", "message": error})


@app.route("/api/auth/users/<int:user_id>", methods=["PATCH"])
@auth.login_required
@auth.requires_permission("manage_users")
def api_update_user(user_id):
    data = request.get_json() or {}
    username = (data.get("username") or "").strip()
    success, error = auth.update_user(
        user_id,
        username=username if username else None,
        role_id=data.get("role_id"),
        is_active=data.get("is_active"),
        must_change_pass=data.get("must_change_pass")
    )
    if success:
        return jsonify({"status": "ok"})
    return jsonify({"status": "error", "message": error})


@app.route("/api/auth/users/<int:user_id>", methods=["DELETE"])
@auth.login_required
@auth.requires_permission("manage_users")
def api_delete_user(user_id):
    data = request.get_json(silent=True) or {}
    delete_sub = bool(data.get("delete_subscription", False))
    success, error = auth.delete_user(user_id, delete_subscription=delete_sub)
    if success:
        return jsonify({"status": "ok"})
    return jsonify({"status": "error", "message": error})


@app.route("/api/auth/me/delete", methods=["POST"])
@auth.login_required
def api_delete_own_account():
    """Allow a user to delete their own account after password confirmation."""
    user = auth.get_current_user()
    data = request.get_json() or {}
    password = data.get("password", "")
    delete_sub = bool(data.get("delete_subscription", False))
    if not password:
        return jsonify({"status": "error", "message": "Password is required"})
    success, error = auth.delete_own_account(user["id"], password, delete_subscription=delete_sub)
    if success:
        return jsonify({"status": "ok"})
    return jsonify({"status": "error", "message": error})


@app.route("/api/sms/verify/request", methods=["POST"])
@auth.login_required
def api_request_sms_verification():
    """Send a 6-digit SMS verification code to the user's phone."""
    user = auth.get_current_user()
    if not config.ALERTS_ENABLED:
        return _alerts_disabled_json(user)
    data  = request.get_json() or {}
    phone = data.get("phone", "").strip()
    if not phone:
        return jsonify({"status": "error", "message": "Phone number required"})

    # Get SMS address from subscriber record for this phone + carrier
    sub = alert_subscribers.get_subscriber_by_user_id(user["id"]) or \
          alert_subscribers.get_subscriber_by_username(user["username"]) or {}
    carrier     = data.get("carrier", sub.get("sms_carrier", ""))
    custom_dom  = data.get("custom_domain", sub.get("sms_custom_domain", ""))
    temp_sub    = {"sms_phone": phone, "sms_carrier": carrier, "sms_custom_domain": custom_dom}
    sms_address = alert_subscribers.get_sms_address(temp_sub)
    if not sms_address:
        return jsonify({"status": "error", "message": "Could not determine SMS address — check carrier"})

    ok, result = auth.request_phone_verification(user["id"], phone)
    if not ok:
        return jsonify({"status": "error", "message": result})

    # Send code via SMS gateway (same mechanism as alerts)
    from alerts import _send_one, _site_name
    subject = f"{_site_name()} Phone Verification"
    body    = f"Your NetWatch phone verification code is: {result}\n\nExpires in 1 hour."
    sent    = _send_one(sms_address, subject, body, body)
    if not sent:
        return jsonify({"status": "error", "message": "Failed to send SMS — check SMTP config"})

    return jsonify({"status": "ok", "message": f"Verification code sent to {sms_address}"})


@app.route("/api/sms/verify/confirm", methods=["POST"])
@auth.login_required
def api_confirm_sms_verification():
    """Confirm a SMS verification code."""
    user  = auth.get_current_user()
    data  = request.get_json() or {}
    phone = data.get("phone", "").strip()
    code  = data.get("code", "").strip()
    ok, err = auth.verify_phone_code(user["id"], phone, code)
    if not ok:
        return jsonify({"status": "error", "message": err})
    return jsonify({"status": "ok", "message": "Phone number verified"})


@app.route("/api/sms/verify/status")
@auth.login_required
def api_sms_verification_status():
    """Get phone verification status for the current user."""
    user  = auth.get_current_user()
    phone = (request.args.get("phone") or "").strip()
    status = auth.get_phone_verification_status(user["id"], phone)
    return jsonify({"status": status, "phone": phone})


@app.route("/api/auth/users/<int:user_id>/password", methods=["POST"])
@auth.login_required
@auth.requires_permission("manage_users")
def api_reset_user_password(user_id):
    data = request.get_json() or {}
    new_password = data.get("new_password", "")
    if len(new_password) < 8:
        return jsonify({"status": "error", "message": "Password must be at least 8 characters"})
    # force_change defaults to True; admin may uncheck to set a permanent password
    force_change = bool(data.get("force_change", True))
    success, error = auth.admin_reset_password(user_id, new_password, force_change=force_change)
    if success:
        return jsonify({"status": "ok"})
    return jsonify({"status": "error", "message": error})


@app.route("/api/session/ping", methods=["POST"])
def api_session_ping():
    """
    Called by client JS on real user interaction to reset idle timer.
    Returns remaining seconds before timeout (or null if no timeout).
    Returns remaining=0 if session has expired — client JS redirects to login.
    No @auth.login_required: must return JSON even when session is expired,
    not a redirect, so the client can handle expiry correctly.
    """
    from flask import session as _sess
    from datetime import datetime as _dt
    if not _sess.get("user_id"):
        return jsonify({"status": "expired", "remaining": 0})
    _sess["last_activity"] = _dt.now().isoformat()
    _sess.modified = True
    minutes = _sess.get("session_minutes", 480)
    if minutes <= 0:
        return jsonify({"status": "ok", "remaining": None})
    return jsonify({"status": "ok", "remaining": minutes * 60})


@app.route("/api/session/status")
def api_session_status():
    """
    Return seconds remaining in current session for client-side countdown.
    Returns remaining=0 if session has expired — client JS redirects to login.
    No @auth.login_required: must return JSON even when session is expired,
    not a redirect, so the client can handle expiry correctly.
    """
    from flask import session as _sess
    from datetime import datetime as _dt
    if not _sess.get("user_id"):
        return jsonify({"remaining": 0})
    # Call get_current_user() to trigger server-side idle expiry check
    user = auth.get_current_user()
    if not user or user.get("is_guest"):
        return jsonify({"remaining": 0})
    minutes = _sess.get("session_minutes", 480)
    if minutes <= 0:
        return jsonify({"remaining": None})
    last_act = _sess.get("last_activity") or _sess.get("login_time") or _dt.now().isoformat()
    idle = (_dt.now() - _dt.fromisoformat(last_act)).total_seconds()
    remaining = max(0, minutes * 60 - idle)
    return jsonify({"remaining": int(remaining)})


@app.route("/api/auth/me")
@auth.login_required
def api_me():
    """Return current user's identity info."""
    user = auth.get_current_user()
    db_user = auth.get_user_by_id(user["id"])
    sub = alert_subscribers.get_subscriber_by_user_id(user["id"]) or \
          alert_subscribers.get_subscriber_by_username(user["username"]) or {}
    return jsonify({
        "username":      user["username"],
        "first_name":    db_user.get("first_name") or "",
        "last_name":     db_user.get("last_name") or "",
        "email_address": sub.get("email_address") or "",
        "sms_phone":     sub.get("sms_phone") or "",
        "sms_carrier":   sub.get("sms_carrier") or "",
        "is_owner":      bool(sub.get("is_owner", False)),
    })


@app.route("/api/auth/me/identity", methods=["POST"])
@auth.login_required
def api_update_identity():
    """Update current user's first name, last name. Syncs to subscriber record."""
    user = auth.get_current_user()
    data = request.get_json() or {}
    first_name = (data.get("first_name") or "").strip()
    last_name  = (data.get("last_name") or "").strip()

    # Update users table + session
    success, error = auth.update_identity(user["id"], first_name, last_name)
    if not success:
        return jsonify({"status": "error", "message": error})

    # Sync first/last name to subscriber record if one exists
    sub = alert_subscribers.get_subscriber_by_user_id(user["id"]) or \
          alert_subscribers.get_subscriber_by_username(user["username"])
    if sub:
        alert_subscribers.upsert_subscriber(
            user_id=user["id"],
            username=user["username"],
            email_address=sub.get("email_address", ""),
            email_enabled=sub.get("email_enabled", False),
            sms_phone=sub.get("sms_phone", ""),
            sms_carrier=sub.get("sms_carrier", ""),
            sms_custom_domain=sub.get("sms_custom_domain", ""),
            sms_enabled=sub.get("sms_enabled", False),
            alert_overrides=json.loads(sub.get("alert_overrides", "{}")),
            first_name=first_name,
            last_name=last_name,
        )

    return jsonify({"status": "ok"})


@app.route("/api/auth/me/username", methods=["POST"])
@auth.login_required
def api_update_own_username():
    """Allow a user to change their own username. Checks for duplicates, syncs session."""
    user = auth.get_current_user()
    data = request.get_json() or {}
    new_username = (data.get("username") or "").strip()

    if not new_username:
        return jsonify({"status": "error", "message": "Username cannot be empty"})
    if len(new_username) < 2:
        return jsonify({"status": "error", "message": "Username must be at least 2 characters"})

    success, error = auth.update_user(user["id"], username=new_username)
    if not success:
        return jsonify({"status": "error", "message": error})

    # Sync username to subscriber record
    sub = alert_subscribers.get_subscriber_by_user_id(user["id"])
    if sub:
        db_user = auth.get_user_by_id(user["id"])
        alert_subscribers.upsert_subscriber(
            user_id=user["id"],
            username=new_username,
            first_name=db_user.get("first_name") or "",
            last_name=db_user.get("last_name") or "",
            email_address=sub.get("email_address", ""),
            email_enabled=sub.get("email_enabled", False),
            sms_phone=sub.get("sms_phone", ""),
            sms_carrier=sub.get("sms_carrier", ""),
            sms_custom_domain=sub.get("sms_custom_domain", ""),
            sms_enabled=sub.get("sms_enabled", False),
            alert_overrides=json.loads(sub.get("alert_overrides", "{}")),
        )

    return jsonify({"status": "ok", "username": new_username})


@app.route("/api/auth/me/password", methods=["POST"])
@auth.login_required
def api_change_own_password():
    """Allow any logged-in user to change their own password."""
    user = auth.get_current_user()
    data = request.get_json() or {}
    current  = data.get("current_password", "")
    new_pwd  = data.get("new_password", "")
    forced   = data.get("forced", False)

    if len(new_pwd) < 8:
        return jsonify({"status": "error", "message": "Password must be at least 8 characters"})

    # Skip current password check on forced change — user just authenticated
    if not forced:
        verified = auth.authenticate(user["username"], current)
        if not verified:
            return jsonify({"status": "error", "message": "Current password is incorrect"})

    success, error = auth.change_password(user["id"], new_pwd)
    if success:
        return jsonify({"status": "ok"})
    return jsonify({"status": "error", "message": error})


@app.route("/api/auth/register", methods=["POST"])
def api_register():
    """Public registration endpoint — creates a Monitor-role account."""
    data     = request.get_json() or {}
    username = (data.get("username") or "").strip()
    password = data.get("password", "")

    if not username:
        return jsonify({"status": "error", "message": "Username is required"})
    if len(password) < 8:
        return jsonify({"status": "error", "message": "Password must be at least 8 characters"})

    # Find Monitor role ID
    conn = __import__('sqlite3').connect(auth.DB_PATH)
    monitor_role = conn.execute(
        "SELECT id FROM roles WHERE name='Monitor'"
    ).fetchone()
    conn.close()

    if not monitor_role:
        return jsonify({"status": "error", "message": "Monitor role not found — contact an admin"})

    success, error = auth.create_user(
        username=username,
        password=password,
        role_id=monitor_role[0],
        must_change_pass=False
    )
    if success:
        log.info("self_registration", username=username)
        new_user = auth.get_user_by_username(username)
        if new_user:
            alert_subscribers.upsert_subscriber(
                user_id=new_user["id"], username=username,
                first_name="", last_name="",
                email_address="", email_enabled=False,
                sms_phone="", sms_carrier="", sms_custom_domain="", sms_enabled=False,
                alert_overrides={},
            )
        return jsonify({"status": "ok", "message": "Account created"})
    return jsonify({"status": "error", "message": error})


# ══════════════════════════════════════════════════════════════════════════════
# AUTH API — Role management endpoints
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/auth/roles", methods=["GET"])
@auth.login_required
@auth.requires_permission("manage_users")
def api_get_roles():
    return jsonify(auth.get_all_roles())


@app.route("/api/auth/roles", methods=["POST"])
@auth.login_required
@auth.requires_permission("manage_users")
def api_create_role():
    data = request.get_json() or {}
    success, error = auth.create_role(
        name=data.get("name", ""),
        description=data.get("description", ""),
        view_logs=data.get("view_logs", True),
        use_controls=data.get("use_controls", False),
        manage_admin=data.get("manage_admin", False),
        manage_users=data.get("manage_users", False),
        session_minutes=data.get("session_minutes", 480)
    )
    if success:
        new_role = next((r for r in auth.get_all_roles() if r["name"] == data.get("name", "")), None)
        if new_role:
            alert_subscribers.seed_role_alert_defaults(new_role["id"])
        return jsonify({"status": "ok"})
    return jsonify({"status": "error", "message": error})


@app.route("/api/auth/roles/<int:role_id>", methods=["PATCH"])
@auth.login_required
@auth.requires_permission("manage_users")
def api_update_role(role_id):
    data = request.get_json() or {}
    success, error = auth.update_role(
        role_id=role_id,
        name=data.get("name", ""),
        description=data.get("description", ""),
        view_logs=data.get("view_logs", True),
        use_controls=data.get("use_controls", False),
        manage_admin=data.get("manage_admin", False),
        manage_users=data.get("manage_users", False),
        session_minutes=data.get("session_minutes", 480)
    )
    if success:
        return jsonify({"status": "ok"})
    return jsonify({"status": "error", "message": error})


@app.route("/api/auth/roles/<int:role_id>", methods=["DELETE"])
@auth.login_required
@auth.requires_permission("manage_users")
def api_delete_role(role_id):
    success, error = auth.delete_role(role_id)
    if success:
        return jsonify({"status": "ok"})
    if error == "has_users":
        affected     = auth.get_users_by_role(role_id)
        all_roles    = auth.get_all_roles()
        deleted_role = next((r for r in all_roles if r["id"] == role_id), None)
        avail_roles  = [r for r in all_roles if r["id"] != role_id]
        return jsonify({"status": "has_users", "affected_users": affected,
                        "available_roles": avail_roles, "deleted_role": deleted_role})
    return jsonify({"status": "error", "message": error})


@app.route("/api/auth/roles/<int:role_id>/delete-with-reassignment", methods=["POST"])
@auth.login_required
@auth.requires_permission("manage_users")
def api_delete_role_with_reassignment(role_id):
    data = request.get_json() or {}
    user_role_map = {int(k): int(v) for k, v in data.get("user_role_map", {}).items()}
    success, error = auth.delete_role_with_reassignment(role_id, user_role_map)
    if success:
        return jsonify({"status": "ok"})
    return jsonify({"status": "error", "message": error})


@app.route("/api/alerts/role_defaults", methods=["GET"])
@auth.login_required
@auth.requires_permission("manage_admin")
def api_get_role_alert_defaults():
    return jsonify(alert_subscribers.get_all_role_alert_defaults())


@app.route("/api/alerts/role_defaults/<int:role_id>", methods=["POST"])
@auth.login_required
@auth.requires_permission("manage_admin")
def api_update_role_alert_defaults(role_id):
    data = request.get_json() or {}
    alert_subscribers.update_role_alert_defaults(role_id, data)
    return jsonify({"status": "ok"})


# ══════════════════════════════════════════════════════════════════════════════
# STATE FILE HELPERS (unchanged from original)
# ══════════════════════════════════════════════════════════════════════════════

def read_state():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {"lockout": False, "conservative_mode": False}


def write_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)


def queue_command(command, triggered_by="web"):
    with open(CMD_FILE, "w") as f:
        json.dump({
            "command":      command,
            "triggered_by": triggered_by,
            "timestamp":    datetime.now().isoformat()
        }, f)


# ══════════════════════════════════════════════════════════════════════════════
# API — STATUS (login required, no special permission needed)
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/config/network")
@auth.guest_allowed
def api_config_network():
    """Expose non-sensitive network config values for the dashboard."""
    return jsonify({
        "lan_gateway":   getattr(config, "LAN_GATEWAY",   ""),
        "wan_primary":   getattr(config, "WAN_PRIMARY",   "8.8.8.8"),
        "wan_secondary": getattr(config, "WAN_SECONDARY", "8.8.4.4"),
        "wifi_gateway":  getattr(config, "WIFI_GATEWAY",  ""),
        "dns_test_host": getattr(config, "DNS_TEST_HOST", "google.com"),
        "site_name":     getattr(config, "SITE_NAME",     "NetWatch"),
    })


@app.route("/api/status")
@auth.guest_allowed
def api_status():
    latest       = database.get_latest_health()
    last_reset   = database.get_last_reset()
    last_speed   = database.get_last_speedtest()
    resets_today = database.get_reset_count_today()
    state        = read_state()

    return jsonify({
        "timestamp":    latest["timestamp"]    if latest else None,
        "lan_ok":       bool(latest["lan_ok"]) if latest else None,
        "wan_ok":       bool(latest["wan_ok"]) if latest else None,
        "wifi_ok":      bool(latest["wifi_ok"]) if latest else None,
        "dns_ok":       bool(latest["dns_ok"]) if latest else None,
        "latency_ms":   latest["latency_ms"]   if latest else None,
        "packet_loss":  latest["packet_loss"]  if latest else None,
        "healthy":      bool(latest["healthy"]) if latest else None,
        "lockout":           state.get("lockout", False),
        "conservative_mode": state.get("conservative_mode", False),
        "resets_today":      resets_today,
        "last_reset": {
            "timestamp":    last_reset["timestamp"],
            "type":         last_reset["reset_type"],
            "reason":       last_reset["reason"],
            "triggered_by": last_reset["triggered_by"],
        } if last_reset else None,
        "last_speedtest": {
            "timestamp":     last_speed["timestamp"],
            "download_mbps": last_speed["download_mbps"],
            "upload_mbps":   last_speed["upload_mbps"],
            "ping_ms":       last_speed["ping_ms"],
            "server":        last_speed["server"],
        } if last_speed else None,
    })


@app.route("/api/health_history")
@auth.guest_allowed
def api_health_history():
    hours = int(request.args.get("hours", 24))
    start = request.args.get("start")
    end   = request.args.get("end")
    return jsonify(database.get_health_history(hours=hours, start=start, end=end))


@app.route("/api/speedtest_history")
@auth.guest_allowed
def api_speedtest_history():
    hours = int(request.args.get("hours", 168))
    start = request.args.get("start")
    end   = request.args.get("end")
    return jsonify(database.get_speedtest_history(hours=hours, start=start, end=end))


@app.route("/api/speedtest_avg")
@auth.guest_allowed
def api_speedtest_avg():
    """Return average speedtest stats for a time range.
    Query param: days=1|7|30 or days=all for all-time. Defaults to 1."""
    days_param = request.args.get("days", "1")
    days = None if days_param == "all" else int(days_param)
    return jsonify(database.get_speedtest_avg(days=days))


@app.route("/api/reset_history")
@auth.guest_allowed
def api_reset_history():
    days = int(request.args.get("days", 30))
    return jsonify(database.get_reset_history(days=days))


@app.route("/api/reset_count")
@auth.guest_allowed
def api_reset_count():
    """Return auto-reset count for a time range.
    Query param: days=1|7|30 or days=all for all-time. Defaults to 1."""
    days_param = request.args.get("days", "1")
    days = None if days_param == "all" else int(days_param)
    return jsonify({"count": database.get_reset_count(days=days)})


@app.route("/api/alerts")
@auth.login_required
@auth.requires_permission("view_logs")
def api_alerts():
    limit = int(request.args.get("limit", 50))
    return jsonify(database.get_alert_history(limit=limit))


@app.route("/api/uptime_stats")
@auth.guest_allowed
def api_uptime_stats():
    return jsonify(database.get_uptime_stats())


@app.route("/api/logs")
@auth.login_required
@auth.requires_permission("view_logs")
def api_logs():
    lines = int(request.args.get("lines", 200))
    try:
        with open(LOG_FILE, "r") as f:
            all_lines = f.readlines()
        return jsonify({"lines": all_lines[-lines:]})
    except FileNotFoundError:
        return jsonify({"lines": [], "error": "Log file not found"})


# ══════════════════════════════════════════════════════════════════════════════
# API — CONTROLS (requires use_controls permission)
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/control/reset_full", methods=["POST"])
@auth.login_required
@auth.requires_permission("use_controls")
def control_reset_full():
    queue_command("full_reset")
    return jsonify({"status": "ok", "message": "Full reset queued"})


@app.route("/api/control/reset_modem", methods=["POST"])
@auth.login_required
@auth.requires_permission("use_controls")
def control_reset_modem():
    queue_command("modem_reset")
    return jsonify({"status": "ok", "message": "Modem reset queued"})


@app.route("/api/control/reset_router", methods=["POST"])
@auth.login_required
@auth.requires_permission("use_controls")
def control_reset_router():
    queue_command("router_reset")
    return jsonify({"status": "ok", "message": "Router/AP reset queued"})


@app.route("/api/control/lockout", methods=["POST"])
@auth.login_required
@auth.requires_permission("use_controls")
def control_lockout():
    state = read_state()
    state["lockout"] = not state.get("lockout", False)
    write_state(state)
    queue_command("toggle_lockout")
    return jsonify({"status": "ok", "lockout": state["lockout"]})


@app.route("/api/control/run_speedtest", methods=["POST"])
@auth.login_required
@auth.requires_permission("use_controls")
def control_run_speedtest():
    queue_command("speedtest")
    return jsonify({"status": "ok", "message": "Speedtest queued"})


@app.route("/api/alerts/test/<int:sub_id>/<channel>", methods=["POST"])
@auth.login_required
@auth.requires_permission("manage_admin")
def api_test_alert_admin(sub_id, channel):
    """Admin: test a specific subscriber's email or SMS channel."""
    if not config.ALERTS_ENABLED:
        return _alerts_disabled_json(auth.get_current_user())
    try:
        import alerts
        ok, message = alerts.send_test(sub_id, channel)
        return jsonify({"status": "ok" if ok else "error", "message": message})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


@app.route("/api/alerts/test/broadcast", methods=["POST"])
@auth.login_required
@auth.requires_permission("manage_admin")
def api_test_alert_broadcast():
    """Admin: send a test alert to all active subscribers. Respects ?channel= (email/sms/all)."""
    if not config.ALERTS_ENABLED:
        return _alerts_disabled_json(auth.get_current_user())
    try:
        import alerts as alerts_mod
        channel_filter = request.args.get("channel", "all")  # email | sms | all
        subs = alert_subscribers.get_all_subscribers()
        results = []
        for sub in subs:
            if channel_filter in ("all", "email"):
                if sub.get("email_enabled") and sub.get("email_address"):
                    ok, msg = alerts_mod.send_test(sub["id"], "email")
                    results.append({"subscriber": sub.get("username") or sub["id"],
                                    "channel": "email", "ok": ok, "message": msg})
            if channel_filter in ("all", "sms"):
                if sub.get("sms_enabled") and alert_subscribers.get_sms_address(sub):
                    ok, msg = alerts_mod.send_test(sub["id"], "sms")
                    results.append({"subscriber": sub.get("username") or sub["id"],
                                    "channel": "sms", "ok": ok, "message": msg})
        sent = sum(1 for r in results if r["ok"])
        return jsonify({"status": "ok", "sent": sent, "total": len(results), "results": results})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


@app.route("/api/alerts/delivery_history")
@auth.login_required
@auth.requires_permission("manage_admin")
def api_delivery_history():
    """Return recent per-recipient delivery history."""
    limit        = min(int(request.args.get("limit", 1000)), 2000)
    alert_type   = request.args.get("alert_type") or None
    subscriber_id = request.args.get("subscriber_id")
    hours        = request.args.get("hours") or None
    if subscriber_id:
        subscriber_id = int(subscriber_id)
    if hours:
        hours = int(hours)
    rows = alert_subscribers.get_delivery_history(limit=limit, alert_type=alert_type,
                                                   subscriber_id=subscriber_id, hours=hours)
    return jsonify(rows)


@app.route("/api/alerts/test_my/<channel>", methods=["POST"])
@auth.login_required
def api_test_alert_my(channel):
    """User: test their own email or SMS channel."""
    user = auth.get_current_user()
    if not config.ALERTS_ENABLED:
        return _alerts_disabled_json(user)
    try:
        import alerts
        import alert_subscribers as subs_mod
        user = auth.get_current_user()
        sub  = subs_mod.get_subscriber_by_user_id(user["id"])
        if not sub:
            sub = subs_mod.get_subscriber_by_username(user["username"])
        if not sub:
            return jsonify({"status": "error", "message": "No subscription configured yet"})
        ok, message = alerts.send_test(sub["id"], channel)
        return jsonify({"status": "ok" if ok else "error", "message": message})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


# Legacy route — kept so any bookmarks/existing calls don't 404
@app.route("/api/control/test_email", methods=["POST"])
@auth.login_required
@auth.requires_permission("manage_admin")
def control_test_email():
    if not config.ALERTS_ENABLED:
        return _alerts_disabled_json(auth.get_current_user())
    try:
        import alerts, alert_subscribers as subs_mod
        owner = subs_mod.get_all_subscribers()
        owner = next((s for s in owner if s["is_owner"]), None)
        if not owner:
            return jsonify({"status": "error", "message": "No owner subscriber configured"})
        ok, message = alerts.send_test(owner["id"], "email")
        return jsonify({"status": "ok" if ok else "error", "message": message})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


# ══════════════════════════════════════════════════════════════════════════════
# API — ADMIN (requires manage_admin permission)
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/admin/db_stats")
@auth.login_required
@auth.requires_permission("manage_admin")
def admin_db_stats():
    return jsonify(database.get_db_stats())


@app.route("/api/system_health")
@auth.guest_allowed
def api_system_health():
    """Return monitor heartbeat age and disk stats for the dashboard system health card."""
    return jsonify(database.get_system_health_stats())


@app.route("/api/admin/export_health")
@auth.login_required
@auth.requires_permission("manage_admin")
def admin_export_health():
    rows   = database.get_health_history(hours=720)
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        "timestamp","lan_ok","wan_ok","wifi_ok","dns_ok","latency_ms","packet_loss","healthy"
    ])
    writer.writeheader()
    writer.writerows(rows)
    output.seek(0)
    filename = f"netwatch_health_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return send_file(io.BytesIO(output.getvalue().encode()),
                     mimetype="text/csv", as_attachment=True, download_name=filename)


@app.route("/api/admin/export_resets")
@auth.login_required
@auth.requires_permission("manage_admin")
def admin_export_resets():
    rows   = database.get_reset_history(days=90)
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        "timestamp","reset_type","reason","triggered_by","success"
    ])
    writer.writeheader()
    writer.writerows(rows)
    output.seek(0)
    filename = f"netwatch_resets_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return send_file(io.BytesIO(output.getvalue().encode()),
                     mimetype="text/csv", as_attachment=True, download_name=filename)


@app.route("/api/admin/clear_health", methods=["POST"])
@auth.login_required
@auth.requires_permission("manage_admin")
def admin_clear_health():
    data = request.get_json() or {}
    days = int(data.get("older_than_days", 30))
    database.clear_health_records(days)
    return jsonify({"status": "ok", "message": f"Deleted health records older than {days} days"})


@app.route("/api/admin/backup_full", methods=["POST"])
@auth.login_required
@auth.requires_permission("manage_admin")
def admin_backup_full():
    """Run backup.sh and return the filename for download."""
    import subprocess, glob
    backup_script = os.path.join(NETWATCH_DIR, "backup.sh")
    backup_dir    = os.path.join(os.path.dirname(NETWATCH_DIR), "backups")
    if not os.path.exists(backup_script):
        return jsonify({"status": "error", "message": "backup.sh not found"})
    try:
        result = subprocess.run(
            ["bash", backup_script],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode != 0:
            log.error("backup_failed", stderr=result.stderr)
            return jsonify({"status": "error", "message": result.stderr or "Backup failed"})
        # Find the most recent backup file
        files = sorted(glob.glob(f"{backup_dir}/netwatch_backup_*.tar.gz.gpg"))
        if not files:
            return jsonify({"status": "error", "message": "Backup file not found after run"})
        latest = files[-1]
        size_mb = round(os.path.getsize(latest) / 1024 / 1024, 1)
        return jsonify({"status": "ok", "filename": os.path.basename(latest), "size_mb": size_mb})
    except subprocess.TimeoutExpired:
        return jsonify({"status": "error", "message": "Backup timed out"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


@app.route("/api/admin/backup_full_download")
@auth.login_required
@auth.requires_permission("manage_admin")
def admin_backup_full_download():
    """Download the most recently generated full backup file."""
    filename = request.args.get("file", "")
    backup_dir = os.path.join(os.path.dirname(NETWATCH_DIR), "backups")
    # Sanitize — only allow our backup filenames
    if not filename.startswith("netwatch_backup_") or ".." in filename:
        return jsonify({"status": "error", "message": "Invalid filename"}), 400
    filepath = os.path.join(backup_dir, filename)
    if not os.path.exists(filepath):
        return jsonify({"status": "error", "message": "File not found"}), 404
    return send_file(filepath, mimetype="application/octet-stream",
                     as_attachment=True, download_name=filename)


@app.route("/api/prefs/admin_collapsed", methods=["GET"])
@auth.login_required
def get_admin_collapsed():
    """Return the admin page collapsed-sections list for the current user."""
    user_id = auth.get_current_user()["id"]
    row = database.get_user_pref(user_id, "admin_collapsed")
    try:
        collapsed = json.loads(row) if row else []
    except Exception:
        collapsed = []
    return jsonify({"collapsed": collapsed})


@app.route("/api/prefs/admin_collapsed", methods=["POST"])
@auth.login_required
def set_admin_collapsed():
    """Persist the admin page collapsed-sections list for the current user."""
    user_id = auth.get_current_user()["id"]
    data = request.get_json(silent=True) or {}
    collapsed = data.get("collapsed", [])
    if not isinstance(collapsed, list):
        return jsonify({"status": "error", "message": "Invalid payload"}), 400
    database.set_user_pref(user_id, "admin_collapsed", json.dumps(collapsed))
    return jsonify({"status": "ok"})


@app.route("/api/prefs/history_limit", methods=["GET"])
@auth.login_required
def get_history_limit():
    """Return the saved package history row limit for the current user."""
    user_id = auth.get_current_user()["id"]
    val = database.get_user_pref(user_id, "history_limit") or "20"
    return jsonify({"value": val})


@app.route("/api/prefs/history_limit", methods=["POST"])
@auth.login_required
def set_history_limit():
    """Persist the package history row limit for the current user."""
    user_id = auth.get_current_user()["id"]
    data = request.get_json(silent=True) or {}
    val = str(data.get("value", "20"))
    database.set_user_pref(user_id, "history_limit", val)
    return jsonify({"status": "ok"})


@app.route("/api/admin/export_code")
@auth.login_required
@auth.requires_permission("manage_admin")
def admin_export_code():
    """Stream a zip of current code files (no DB, certs, logs, venv, snapshots)."""
    import zipfile, io
    from datetime import datetime

    EXCLUDE_DIRS  = {"__pycache__", "venv", "certs", "logs", "data", "backups", "snapshots", ".gnupg"}
    EXCLUDE_EXTS  = {".pyc", ".bak", ".gpg", ".gz"}
    # Exclude DB files by prefix regardless of extension variant
    EXCLUDE_PREFIXES = {"netwatch.db"}
    EXCLUDE_FILES = {"config.py", "gunicorn.ctl",   # config has credentials; gunicorn.ctl is a runtime socket
                     "pkg_update.log"}               # runtime log — Pi-specific, should not transfer to other installs

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(NETWATCH_DIR):
            # Prune excluded dirs in-place so os.walk doesn't descend
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
            for fname in sorted(files):
                if fname in EXCLUDE_FILES:
                    continue
                if os.path.splitext(fname)[1] in EXCLUDE_EXTS:
                    continue
                if any(fname.startswith(p) for p in EXCLUDE_PREFIXES):
                    continue
                full_path = os.path.join(root, fname)
                arc_name  = os.path.relpath(full_path, NETWATCH_DIR)
                zf.write(full_path, arc_name)
    buf.seek(0)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    download_name = f"netwatch_code_{ts}.zip"
    return send_file(buf, mimetype="application/zip",
                     as_attachment=True, download_name=download_name)


@app.route("/api/admin/build_release", methods=["POST"])
@auth.login_required
@auth.requires_permission("manage_users")
def admin_build_release():
    """
    Build a release zip using build_release.sh.
    Only available when DEVELOPMENT_SYSTEM = True in config.py.
    Runs the script as netwatch-svc (already the running user), captures output,
    and returns the zip path, SHA-256, and log output.
    """
    import subprocess, re

    if not getattr(config, "DEVELOPMENT_SYSTEM", False):
        return jsonify({"status": "error", "message": "Not a development system"}), 403

    version = request.json.get("version", "").strip() if request.is_json else ""

    script = os.path.join(NETWATCH_DIR, "build_release.sh")
    if not os.path.isfile(script):
        return jsonify({"status": "error", "message": "build_release.sh not found — install v3.4.2+"}), 500

    try:
        cmd = ["bash", script]
        if version:
            cmd.append(version)

        result = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=120,
            cwd=NETWATCH_DIR
        )
        output = result.stdout + result.stderr

        if result.returncode != 0:
            return jsonify({"status": "error", "message": "Build script failed", "output": output}), 500

        # Extract SHA-256 and zip path from output
        sha_match  = re.search(r"SHA-256:\s*([0-9a-f]{64})", output)
        path_match = re.search(r"Output\s*:\s*(\S+\.zip)", output)
        ver_match  = re.search(r"Version\s*:\s*(\S+)", output)

        sha256   = sha_match.group(1)  if sha_match  else ""
        zip_path = path_match.group(1) if path_match else ""
        built_ver = ver_match.group(1) if ver_match  else version

        log.info("release_built", version=built_ver, sha256=sha256[:12],
                 user=auth.get_current_user().get("username"))

        return jsonify({
            "status":    "ok",
            "version":   built_ver,
            "sha256":    sha256,
            "zip_path":  zip_path,
            "filename":  os.path.basename(zip_path) if zip_path else "",
            "output":    output,
        })

    except subprocess.TimeoutExpired:
        return jsonify({"status": "error", "message": "Build timed out (>120s)"}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/admin/publish_release", methods=["POST"])
@auth.login_required
@auth.requires_permission("manage_users")
def admin_publish_release():
    """
    Publish a built release zip to GitHub:
      1. Create a GitHub Release tagged vVERSION
      2. Upload the zip as a release asset
      3. Update releases/latest.json with version, asset URL, and SHA-256
      4. Commit and push latest.json to both Gitea (origin) and GitHub remotes

    Requires DEVELOPMENT_SYSTEM = True and a GitHub PAT with:
      - contents: write  (for pushing commits)
      - releases: write  (for creating releases and uploading assets)
    The PAT must be embedded in the github remote URL.
    """
    import subprocess, re

    if not getattr(config, "DEVELOPMENT_SYSTEM", False):
        return jsonify({"status": "error", "message": "Not a development system"}), 403

    try:
        import requests as req_lib
    except ImportError:
        return jsonify({"status": "error", "message": "requests library not available"}), 500

    data        = request.json or {}
    version     = data.get("version", "").strip()
    sha256      = data.get("sha256",  "").strip()
    zip_path    = data.get("zip_path", "").strip()
    description = data.get("description", f"NetWatch v{version} release.").strip()

    if not version or not sha256 or not zip_path:
        return jsonify({"status": "error", "message": "version, sha256, and zip_path are required"}), 400

    if not os.path.isfile(zip_path):
        return jsonify({"status": "error", "message": f"Zip not found: {zip_path}"}), 400

    # -- Extract GitHub owner/repo and PAT from the github remote URL ----------
    try:
        result = subprocess.run(
            ["git", "-C", NETWATCH_DIR, "remote", "get-url", "github"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            return jsonify({"status": "error",
                            "message": "github remote not configured — add it first"}), 400

        remote_url = result.stdout.strip()
        # Supports both formats:
        #   https://TOKEN@github.com/OWNER/REPO.git
        #   https://USERNAME:TOKEN@github.com/OWNER/REPO.git
        m = re.match(r"https://(?:[^:@]+:)?([^@]+)@github\.com/([^/]+)/([^/]+?)(?:\.git)?$", remote_url)
        if not m:
            return jsonify({"status": "error",
                            "message": f"Cannot parse github remote URL: {remote_url}"}), 400

        pat   = m.group(1)
        owner = m.group(2)
        repo  = m.group(3)
    except Exception as e:
        return jsonify({"status": "error", "message": f"Failed to read github remote: {e}"}), 500

    headers = {
        "Authorization": f"token {pat}",
        "Accept":        "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    tag = f"v{version}"
    steps = []

    # -- Step 1: Create GitHub Release (or fetch existing one) ----------------
    try:
        resp = req_lib.post(
            f"https://api.github.com/repos/{owner}/{repo}/releases",
            headers=headers,
            json={
                "tag_name":   tag,
                "name":       f"NetWatch {tag}",
                "body":       description,
                "draft":      False,
                "prerelease": False,
            },
            timeout=30
        )
        if resp.status_code in (200, 201):
            release_data = resp.json()
            steps.append(f"✓ GitHub Release created: {tag} (id {release_data['id']})")
        elif resp.status_code == 422 and "already_exists" in resp.text:
            # Release already exists — fetch it instead
            fetch = req_lib.get(
                f"https://api.github.com/repos/{owner}/{repo}/releases/tags/{tag}",
                headers=headers, timeout=15
            )
            if fetch.status_code != 200:
                return jsonify({"status": "error",
                                "message": f"Release exists but could not fetch it: {fetch.status_code}",
                                "steps": steps}), 500
            release_data = fetch.json()
            steps.append(f"✓ GitHub Release already exists: {tag} (id {release_data['id']}) — reusing")
        else:
            return jsonify({"status": "error",
                            "message": f"GitHub release creation failed: {resp.status_code} {resp.text}",
                            "steps": steps}), 500

        release_id = release_data["id"]
        upload_url = release_data["upload_url"].split("{")[0]
    except Exception as e:
        return jsonify({"status": "error", "message": f"Release creation error: {e}",
                        "steps": steps}), 500

    # -- Step 2: Upload zip asset (delete existing if present) ----------------
    zip_filename = os.path.basename(zip_path)
    try:
        # Check for existing asset with same name and delete it first
        existing_assets = req_lib.get(
            f"https://api.github.com/repos/{owner}/{repo}/releases/{release_id}/assets",
            headers=headers, timeout=15
        ).json()
        for asset in existing_assets:
            if asset.get("name") == zip_filename:
                del_resp = req_lib.delete(
                    f"https://api.github.com/repos/{owner}/{repo}/releases/assets/{asset['id']}",
                    headers=headers, timeout=15
                )
                if del_resp.status_code in (204, 200):
                    steps.append(f"✓ Existing asset deleted: {zip_filename}")
                else:
                    steps.append(f"⚠ Could not delete existing asset: {del_resp.status_code}")

        with open(zip_path, "rb") as f:
            zip_bytes = f.read()

        asset_resp = req_lib.post(
            f"{upload_url}?name={zip_filename}&label={zip_filename}",
            headers={**headers, "Content-Type": "application/zip"},
            data=zip_bytes,
            timeout=120
        )
        if asset_resp.status_code not in (200, 201):
            return jsonify({"status": "error",
                            "message": f"Asset upload failed: {asset_resp.status_code} {asset_resp.text}",
                            "steps": steps}), 500

        asset_url = asset_resp.json()["browser_download_url"]
        steps.append(f"✓ Asset uploaded: {asset_url}")
    except Exception as e:
        return jsonify({"status": "error", "message": f"Asset upload error: {e}",
                        "steps": steps}), 500

    # -- Step 3: Update releases/latest.json ----------------------------------
    try:
        from datetime import date
        manifest = {
            "version":        version,
            "description":    description,
            "package_url":    asset_url,
            "changelog_url":  "",
            "package_sha256": sha256,
            "min_version":    "",
            "critical":       False,
            "released":       date.today().isoformat(),
        }
        manifest_path = os.path.join(NETWATCH_DIR, "releases", "latest.json")
        os.makedirs(os.path.dirname(manifest_path), exist_ok=True)
        with open(manifest_path, "w") as f:
            import json as json_lib
            json_lib.dump(manifest, f, indent=2)
            f.write("\n")
        # Ensure netwatch-svc owns the file so future writes succeed
        import pwd
        try:
            pw = pwd.getpwnam("netwatch-svc")
            os.chown(manifest_path, pw.pw_uid, pw.pw_gid)
        except (KeyError, PermissionError):
            pass  # Best effort — non-fatal if chown fails
        steps.append("✓ releases/latest.json updated")
    except Exception as e:
        return jsonify({"status": "error", "message": f"Manifest update error: {e}",
                        "steps": steps}), 500

    # -- Step 4: Commit and push to both remotes ------------------------------
    git = ["git", "-C", NETWATCH_DIR]
    try:
        subprocess.run([*git, "add", "releases/latest.json"],
                       check=True, capture_output=True, timeout=15)
        subprocess.run([*git, "commit", "-m",
                        f"{tag}: publish release — update latest.json"],
                       check=True, capture_output=True, timeout=15)
        steps.append("✓ Committed releases/latest.json")

        subprocess.run([*git, "push", "origin", "main"],
                       check=True, capture_output=True, timeout=60)
        steps.append("✓ Pushed to Gitea (origin)")

        subprocess.run([*git, "push", "github", "main"],
                       check=True, capture_output=True, timeout=60)
        steps.append("✓ Pushed to GitHub")
    except subprocess.CalledProcessError as e:
        err = e.stderr.decode() if e.stderr else str(e)
        return jsonify({"status": "error",
                        "message": f"Git push failed: {err}",
                        "steps": steps}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": f"Git error: {e}",
                        "steps": steps}), 500

    log.info("release_published", version=version, asset_url=asset_url,
             user=auth.get_current_user().get("username"))

    return jsonify({
        "status":     "ok",
        "version":    version,
        "asset_url":  asset_url,
        "steps":      steps,
    })


@app.route("/api/admin/release_download")
@auth.login_required
@auth.requires_permission("manage_users")
def admin_release_download():
    """Download a built release zip from ~/backups/releases/."""
    if not getattr(config, "DEVELOPMENT_SYSTEM", False):
        return jsonify({"status": "error", "message": "Not a development system"}), 403

    filename   = request.args.get("file", "")
    release_dir = os.path.join(os.path.dirname(NETWATCH_DIR), "backups", "releases")

    # Safety: filename must look like a release zip and contain no traversal
    if not filename.startswith("netwatch-") or not filename.endswith(".zip") or ".." in filename:
        return jsonify({"status": "error", "message": "Invalid filename"}), 400

    filepath = os.path.join(release_dir, filename)
    if not os.path.isfile(filepath):
        return jsonify({"status": "error", "message": "File not found"}), 404

    return send_file(filepath, mimetype="application/zip",
                     as_attachment=True, download_name=filename)


@app.route("/api/admin/backup_schedule", methods=["GET", "POST"])
@auth.login_required
@auth.requires_permission("manage_admin")
def admin_backup_schedule():
    """Get or set backup cron schedules for daily DB and weekly full backups."""
    import subprocess, re, glob as globmod

    CRON_TAG_DB   = "# netwatch-backup-db"
    CRON_TAG_FULL = "# netwatch-backup-full"
    backup_script    = os.path.join(NETWATCH_DIR, "backup.sh")
    backup_db_script = os.path.join(NETWATCH_DIR, "backup_db.sh")
    backup_dir       = os.path.join(os.path.dirname(NETWATCH_DIR), "backups")

    def parse_cron(crontab, tag):
        match = re.search(
            r'^(\d+)\s+(\d+)\s+\S+\s+\S+\s+(\S+)\s+.*?(\s+--email)?\s+--quiet\s+' + re.escape(tag),
            crontab, re.MULTILINE)
        if not match:
            return {"enabled": False, "hour": 2, "dow": 0, "email": False, "last_run": None}
        hour, dow, has_email = int(match.group(2)), match.group(3), bool(match.group(4))
        pattern = "netwatch_db_" if "db" in tag else "netwatch_backup_"
        files = sorted(globmod.glob(f"{backup_dir}/{pattern}*.gpg"))
        last_run = None
        if files:
            from datetime import datetime as dt
            mtime = os.path.getmtime(files[-1])
            last_run = dt.utcfromtimestamp(mtime).strftime("%Y-%m-%d %H:%M UTC")
        return {"enabled": True, "hour": hour, "dow": int(dow) if dow != "*" else 0,
                "email": has_email, "last_run": last_run}

    if request.method == "GET":
        try:
            result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
            crontab = result.stdout
            return jsonify({
                "status": "ok",
                "db":   parse_cron(crontab, CRON_TAG_DB),
                "full": parse_cron(crontab, CRON_TAG_FULL)
            })
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)})

    # POST — save one schedule at a time
    data     = request.get_json() or {}
    btype    = data.get("type", "db")
    hour     = int(data.get("hour", 2))
    enabled  = bool(data.get("enabled", True))
    do_email = bool(data.get("email", False))
    dow      = int(data.get("dow", 0))

    try:
        result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
        tag    = CRON_TAG_DB if btype == "db" else CRON_TAG_FULL
        script = backup_db_script if btype == "db" else backup_script
        lines  = [l for l in result.stdout.splitlines() if tag not in l]

        if enabled:
            email_flag = " --email" if do_email else ""
            cron_dow   = "*" if btype == "db" else str(dow)
            lines.append(f"0 {hour} * * {cron_dow} /bin/bash {script}{email_flag} --quiet {tag}")

        subprocess.run(["crontab", "-"], input="\n".join(lines) + "\n", text=True, check=True)

        days = ['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday']
        if not enabled:
            msg = f"{'Daily database' if btype == 'db' else 'Weekly full'} backup disabled"
        elif btype == "db":
            msg = f"Daily database backup scheduled at {hour:02d}:00{' with email' if do_email else ''}"
        else:
            msg = f"Weekly full backup scheduled every {days[dow]} at {hour:02d}:00{' with email' if do_email else ''}"
        return jsonify({"status": "ok", "message": msg})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


@app.route("/api/admin/pkg_update_schedule", methods=["GET", "POST"])
@auth.login_required
@auth.requires_permission("manage_admin")
def admin_pkg_update_schedule():
    """Get or set the scheduled Pi package update cron job.
    GET  — returns current schedule state.
    POST — saves schedule; payload: {enabled, dow, hour, send_alert}."""
    import subprocess, re

    CRON_TAG  = "# netwatch-pkg-update"
    script    = os.path.join(NETWATCH_DIR, "pkg_update.sh")

    def parse_cron(crontab):
        """Parse the pkg-update cron line; return state dict."""
        match = re.search(
            r'^(\d+)\s+(\d+)\s+\S+\s+\S+\s+(\S+)\s+.*?(\s+--alert)?\s+--quiet\s+' + re.escape(CRON_TAG),
            crontab, re.MULTILINE)
        if not match:
            return {"enabled": False, "hour": 3, "dow": 0, "send_alert": False, "last_run": None}
        hour       = int(match.group(2))
        dow        = int(match.group(3)) if match.group(3) != "*" else 0
        send_alert = bool(match.group(4))
        # Approximate last run from script log file if present
        log_path = os.path.join(NETWATCH_DIR, "pkg_update.log")
        last_run = None
        if os.path.exists(log_path):
            from datetime import datetime as dt
            mtime    = os.path.getmtime(log_path)
            last_run = dt.utcfromtimestamp(mtime).strftime("%Y-%m-%d %H:%M UTC")
        return {"enabled": True, "hour": hour, "dow": dow,
                "send_alert": send_alert, "last_run": last_run}

    if request.method == "GET":
        try:
            result  = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
            return jsonify({"status": "ok", "schedule": parse_cron(result.stdout)})
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)})

    # POST — save schedule
    data       = request.get_json() or {}
    enabled    = bool(data.get("enabled", False))
    dow        = int(data.get("dow", 0))
    hour       = int(data.get("hour", 3))
    send_alert = bool(data.get("send_alert", False))

    try:
        result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
        lines  = [l for l in result.stdout.splitlines() if CRON_TAG not in l]
        if enabled:
            alert_flag = " --alert" if send_alert else ""
            lines.append(
                f"0 {hour} * * {dow} /bin/bash {script}{alert_flag} --quiet {CRON_TAG}")
        subprocess.run(["crontab", "-"], input="\n".join(lines) + "\n", text=True, check=True)
        days = ['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday']
        if not enabled:
            msg = "Pi package updates disabled"
        else:
            msg = (f"Pi package updates scheduled every {days[dow]} at {hour:02d}:00"
                   f"{' — alert on completion' if send_alert else ''}")
        return jsonify({"status": "ok", "message": msg})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


@app.route("/api/admin/pkg_update_log")
@auth.login_required
@auth.requires_permission("manage_admin")
def admin_pkg_update_log():
    """Return the last N lines of pkg_update.log.
    Query param: lines (int, default 50, max 500).
    Returns {status, lines: [str], last_modified: str|null}."""
    log_path = os.path.join(NETWATCH_DIR, "pkg_update.log")
    try:
        n = min(int(request.args.get("lines", 50)), 500)
    except (ValueError, TypeError):
        n = 50
    if not os.path.exists(log_path):
        return jsonify({"status": "ok", "lines": [], "last_modified": None,
                        "message": "pkg_update.log does not exist yet. "
                                   "It will be created after the first scheduled run."})
    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            all_lines = f.readlines()
        last_n = [l.rstrip("\n") for l in all_lines[-n:]]
        mtime = os.path.getmtime(log_path)
        last_modified = datetime.utcfromtimestamp(mtime).strftime("%Y-%m-%d %H:%M UTC")
        return jsonify({"status": "ok", "lines": last_n,
                        "last_modified": last_modified})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/admin/backup_db")
@auth.login_required
@auth.requires_permission("manage_admin")
def admin_backup_db():
    """Download a complete backup of the NetWatch database."""
    import shutil, tempfile
    db_path = os.path.join(NETWATCH_DIR, "netwatch.db")
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    # Use SQLite backup API for a safe consistent snapshot
    import sqlite3
    src  = sqlite3.connect(db_path)
    dst  = sqlite3.connect(tmp.name)
    src.backup(dst)
    src.close()
    dst.close()
    filename = f"netwatch_backup_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.db"
    return send_file(tmp.name, mimetype="application/octet-stream",
                     as_attachment=True, download_name=filename)


@app.route("/api/admin/backup_db_now", methods=["POST"])
@auth.login_required
@auth.requires_permission("manage_admin")
def admin_backup_db_now():
    """Run backup_db.sh and return filename/size — does not stream a download.

    Used by the Backup Manager "Backup DB Now" button. Distinct from the
    legacy /api/admin/backup_db GET route which streams an on-the-fly snapshot.
    """
    import subprocess, glob as _glob
    backup_script = os.path.join(NETWATCH_DIR, "backup_db.sh")
    backup_dir    = os.path.join(os.path.dirname(NETWATCH_DIR), "backups")
    if not os.path.exists(backup_script):
        return jsonify({"status": "error", "message": "backup_db.sh not found"})
    try:
        result = subprocess.run(
            ["bash", backup_script],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode != 0:
            log.error("backup_db_failed", stderr=result.stderr)
            return jsonify({"status": "error", "message": result.stderr or "Backup failed"})
        files = sorted(_glob.glob(f"{backup_dir}/netwatch_db_*.db.gpg"))
        if not files:
            return jsonify({"status": "error", "message": "Backup script ran but no output file found"})
        latest = files[-1]
        size_mb = round(os.path.getsize(latest) / (1024 * 1024), 1)
        log.info("backup_db_created", filename=os.path.basename(latest))
        return jsonify({"status": "ok", "filename": os.path.basename(latest), "size_mb": size_mb})
    except subprocess.TimeoutExpired:
        return jsonify({"status": "error", "message": "Backup timed out"}), 500
    except Exception as e:
        log.error("backup_db_failed", error=str(e))
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/admin/restore_db", methods=["POST"])
@auth.login_required
@auth.requires_permission("manage_admin")
def admin_restore_db():
    """Restore the NetWatch database from an uploaded .db file."""
    import shutil, tempfile, sqlite3
    if "file" not in request.files:
        return jsonify({"status": "error", "message": "No file uploaded"})
    f = request.files["file"]
    if not f.filename.endswith(".db"):
        return jsonify({"status": "error", "message": "File must be a .db file"})

    # Save upload to temp file
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    f.save(tmp.name)
    tmp.close()

    # Validate it's a real SQLite database
    try:
        conn = sqlite3.connect(tmp.name)
        conn.execute("SELECT COUNT(*) FROM network_health")
        conn.close()
    except Exception as e:
        os.unlink(tmp.name)
        return jsonify({"status": "error", "message": f"Invalid database file: {e}"})

    # Back up current database before overwriting
    db_path = os.path.join(NETWATCH_DIR, "netwatch.db")
    bak_path = db_path + ".pre_restore"
    shutil.copy2(db_path, bak_path)

    # Restore using SQLite backup API
    try:
        src = sqlite3.connect(tmp.name)
        dst = sqlite3.connect(db_path)
        src.backup(dst)
        src.close()
        dst.close()
        os.unlink(tmp.name)
        log.info("database_restored")
        return jsonify({"status": "ok", "message": "Database restored successfully. Previous database saved as netwatch.db.pre_restore"})
    except Exception as e:
        # Rollback
        shutil.copy2(bak_path, db_path)
        os.unlink(tmp.name)
        return jsonify({"status": "error", "message": f"Restore failed: {e}"})


@app.route("/api/admin/backup_list")
@auth.login_required
@auth.requires_permission("manage_admin")
def admin_backup_list():
    """List all backup files stored locally on the Pi.

    Returns two lists — db_backups (netwatch_db_*.db.gpg) and
    full_backups (netwatch_backup_*.tar.gz.gpg) — each sorted newest first.
    Each entry includes filename, size_mb, and timestamp (parsed from filename).
    """
    import glob as _glob
    backup_dir = os.path.join(os.path.dirname(NETWATCH_DIR), "backups")

    def _file_info(path):
        fname = os.path.basename(path)
        size_mb = round(os.path.getsize(path) / (1024 * 1024), 1)
        return {"filename": fname, "size_mb": size_mb}

    db_files   = sorted(_glob.glob(os.path.join(backup_dir, "netwatch_db_*.db.gpg")), reverse=True)
    full_files = sorted(_glob.glob(os.path.join(backup_dir, "netwatch_backup_*.tar.gz.gpg")), reverse=True)

    return jsonify({
        "status":       "ok",
        "backup_dir":   backup_dir,
        "db_backups":   [_file_info(f) for f in db_files],
        "full_backups": [_file_info(f) for f in full_files],
    })


@app.route("/api/admin/backup_download")
@auth.login_required
@auth.requires_permission("manage_admin")
def admin_backup_download():
    """Download a stored backup file by filename.

    Filename is validated to only allow known backup patterns and
    blocks path traversal. Serves the file as an attachment.
    """
    filename = request.args.get("filename", "")
    backup_dir = os.path.join(os.path.dirname(NETWATCH_DIR), "backups")

    # Validate filename — only allow our known backup patterns, no path separators
    is_db   = filename.startswith("netwatch_db_")   and filename.endswith(".db.gpg")
    is_full = filename.startswith("netwatch_backup_") and filename.endswith(".tar.gz.gpg")
    if not (is_db or is_full) or ".." in filename or "/" in filename or "\\" in filename:
        return jsonify({"status": "error", "message": "Invalid filename"}), 400

    filepath = os.path.join(backup_dir, filename)
    if not os.path.isfile(filepath):
        return jsonify({"status": "error", "message": "File not found"}), 404

    log.info("backup_downloaded", filename=filename)
    return send_file(filepath, as_attachment=True, download_name=filename)


@app.route("/api/admin/backup_delete", methods=["POST"])
@auth.login_required
@auth.requires_permission("manage_admin")
def admin_backup_delete():
    """Delete a stored backup file by filename.

    Filename is validated to only allow known backup patterns and
    blocks path traversal.
    """
    data     = request.get_json() or {}
    filename = data.get("filename", "")
    backup_dir = os.path.join(os.path.dirname(NETWATCH_DIR), "backups")

    # Validate filename — only allow our known backup patterns, no path separators
    is_db   = filename.startswith("netwatch_db_")   and filename.endswith(".db.gpg")
    is_full = filename.startswith("netwatch_backup_") and filename.endswith(".tar.gz.gpg")
    if not (is_db or is_full) or ".." in filename or "/" in filename or "\\" in filename:
        return jsonify({"status": "error", "message": "Invalid filename"}), 400

    filepath = os.path.join(backup_dir, filename)
    if not os.path.isfile(filepath):
        return jsonify({"status": "error", "message": "File not found"}), 404

    try:
        os.unlink(filepath)
        log.info("backup_deleted", filename=filename)
        return jsonify({"status": "ok", "message": f"Deleted {filename}"})
    except Exception as e:
        log.error("backup_delete_failed", filename=filename, error=str(e))
        return jsonify({"status": "error", "message": str(e)}), 500


# ══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════



# ══════════════════════════════════════════════════════════════════════════════
# PREFERENCES
# ══════════════════════════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════════════════════════════
# FILE UPDATE MANAGER
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/admin/update")
@auth.login_required
@auth.requires_permission("manage_admin")
def update_manager():
    return render_template("deployed_files.html")


@app.route("/admin/deployed_files")
@auth.login_required
@auth.requires_permission("manage_admin")
def deployed_files():
    return render_template("deployed_files.html")


@app.route("/api/update/apply", methods=["POST"])
@auth.login_required
@auth.requires_permission("manage_admin")
def api_update_apply():
    if "file" not in request.files:
        return jsonify({"success": False, "message": "No file in request"})
    file    = request.files["file"]
    user    = auth.get_current_user()
    content = file.read()
    result  = updater.apply_file(file.filename, content, uploaded_by=user["username"])
    return jsonify(result)


@app.route("/api/update/files")
@auth.login_required
@auth.requires_permission("manage_admin")
def api_update_files():
    return jsonify(updater.list_netwatch_files())


@app.route("/api/update/file_info")
@auth.login_required
@auth.requires_permission("manage_admin")
def api_update_file_info():
    filename = request.args.get("filename", "")
    return jsonify(updater.get_file_info(filename))


@app.route("/api/update/rollback", methods=["POST"])
@auth.login_required
@auth.requires_permission("manage_admin")
def api_update_rollback():
    data     = request.get_json() or {}
    filename = data.get("filename", "")
    success, message = updater.rollback_file(filename)
    return jsonify({"success": success, "message": message})


@app.route("/api/update/history")
@auth.login_required
@auth.requires_permission("manage_admin")
def api_update_history():
    return jsonify(updater.get_upload_history())


# ── Dev Docs routes ───────────────────────────────────────────────────────────

@app.route("/api/devdocs/list")
@auth.login_required
@auth.requires_permission("manage_admin")
def api_devdocs_list():
    return jsonify(updater.list_dev_docs())


@app.route("/api/devdocs/upload", methods=["POST"])
@auth.login_required
@auth.requires_permission("manage_admin")
def api_devdocs_upload():
    if "file" not in request.files:
        return jsonify({"success": False, "message": "No file in request"})
    file = request.files["file"]
    content = file.read()
    success, error = updater.save_dev_doc(file.filename, content)
    if success:
        return jsonify({"success": True, "message": f"'{file.filename}' saved to Dev Documents."})
    return jsonify({"success": False, "message": error}), 400


@app.route("/api/devdocs/delete", methods=["POST"])
@auth.login_required
@auth.requires_permission("manage_admin")
def api_devdocs_delete():
    data = request.get_json() or {}
    filename = data.get("filename", "")
    success, error = updater.delete_dev_doc(filename)
    if success:
        return jsonify({"success": True, "message": f"'{filename}' deleted."})
    return jsonify({"success": False, "message": error}), 400


@app.route("/api/devdocs/rename", methods=["POST"])
@auth.login_required
@auth.requires_permission("manage_admin")
def api_devdocs_rename():
    data = request.get_json() or {}
    old_name = data.get("old_filename", "")
    new_name = data.get("new_filename", "")
    success, error = updater.rename_dev_doc(old_name, new_name)
    if success:
        return jsonify({"success": True, "message": f"Renamed to '{new_name}'."})
    return jsonify({"success": False, "message": error}), 400


@app.route("/api/devdocs/download")
@auth.login_required
@auth.requires_permission("manage_admin")
def api_devdocs_download():
    filename = request.args.get("filename", "")
    path = updater.get_dev_doc_path(filename)
    if not path:
        return jsonify({"error": "File not found"}), 404
    return send_file(path, as_attachment=True, download_name=os.path.basename(path))


@app.route("/api/admin/export_code_full")
@auth.login_required
@auth.requires_permission("manage_admin")
def admin_export_code_full():
    """Stream a zip of current code files + dev_docs directory contents."""
    import zipfile, io

    # dev_docs excluded from walk and handled separately below to avoid double-inclusion
    # (os.walk descends into dev_docs/ as a NETWATCH_DIR subdirectory without this exclusion)
    EXCLUDE_DIRS     = {"__pycache__", "venv", "certs", "logs", "data", "backups", "snapshots", "dev_docs", ".gnupg"}
    EXCLUDE_EXTS     = {".pyc", ".bak", ".gpg", ".gz", ".zip", ".tar"}
    EXCLUDE_PREFIXES = {"netwatch.db"}
    EXCLUDE_FILES    = {"config.py", "gunicorn.ctl"}

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # Code files — walk NETWATCH_DIR, skipping dev_docs (handled separately below)
        for root, dirs, files in os.walk(NETWATCH_DIR):
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
            for fname in sorted(files):
                if fname in EXCLUDE_FILES:
                    continue
                if os.path.splitext(fname)[1] in EXCLUDE_EXTS:
                    continue
                if any(fname.startswith(p) for p in EXCLUDE_PREFIXES):
                    continue
                full_path = os.path.join(root, fname)
                arc_name  = os.path.relpath(full_path, NETWATCH_DIR)
                zf.write(full_path, arc_name)
        # Dev docs — single explicit loop; skip .bak files (dated summaries are the real backup)
        dev_docs_dir = updater.DEV_DOCS_DIR
        if os.path.isdir(dev_docs_dir):
            for fname in sorted(os.listdir(dev_docs_dir)):
                if os.path.splitext(fname)[1] == ".bak":
                    continue
                fpath = os.path.join(dev_docs_dir, fname)
                if os.path.isfile(fpath):
                    zf.write(fpath, os.path.join("dev_docs", fname))
    buf.seek(0)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return send_file(buf, mimetype="application/zip",
                     as_attachment=True, download_name=f"netwatch_full_{ts}.zip")


# ══════════════════════════════════════════════════════════════════════════════
# CONFIG EDITOR
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/admin/config")
@auth.login_required
@auth.requires_permission("manage_admin")
def config_editor():
    sections              = configeditor.get_sections()
    values                = configeditor.read_config()
    fields_json           = json.dumps(configeditor.FIELDS)
    unconfigured_keys     = config_validator.get_unconfigured_keys()
    pending_notifications = config_validator.get_pending_notifications()
    return render_template("config_editor.html", sections=sections,
                           values=values, fields_json=fields_json,
                           unconfigured_keys=unconfigured_keys,
                           pending_notifications=pending_notifications)


@app.route("/api/config/save", methods=["POST"])
@auth.login_required
@auth.requires_permission("manage_admin")
def api_config_save():
    data = request.get_json() or {}
    user = auth.get_current_user()

    success, error = configeditor.save_config(data, saved_by=user["username"])

    if success:
        import subprocess as sp
        sp.run(["sudo", "systemctl", "restart", "netwatch-monitor"],
               stdout=sp.DEVNULL, stderr=sp.DEVNULL)
        sp.Popen(["bash", "-c", "sleep 2 && sudo systemctl restart netwatch-web"],
                 stdout=sp.DEVNULL, stderr=sp.DEVNULL,
                 start_new_session=True)
        return jsonify({"success": True, "message": "Config saved. Services restarting — page will reload automatically."})
    return jsonify({"success": False, "message": error})


@app.route("/api/config/rollback", methods=["POST"])
@auth.login_required
@auth.requires_permission("manage_admin")
def api_config_rollback():
    success, message = configeditor.rollback_config()
    if success:
        import subprocess as sp
        sp.Popen(["bash", "-c", "sleep 1 && sudo systemctl restart netwatch-monitor"],
                 stdout=sp.DEVNULL, stderr=sp.DEVNULL)
    return jsonify({"success": success, "message": message})


@app.route("/api/config/export")
@auth.login_required
@auth.requires_permission("manage_admin")
def api_config_export():
    """Return all config values as JSON for client-side encrypted export."""
    values = configeditor.read_config()
    payload = {
        "_netwatch": True,
        "_version": getattr(config, "VERSION", "unknown"),
        "_exported": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "values": values
    }
    return jsonify(payload)


# ══════════════════════════════════════════════════════════════════════════════
# UPDATE CHECKER
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/update/status")
@auth.login_required
@auth.requires_permission("manage_admin")
def api_update_status():
    """Return current update availability from system_settings."""
    avail_ver   = database.get_system_setting("update_available_version", "")
    dismissed   = database.get_system_setting("update_dismissed_version", "")
    last_checked = database.get_system_setting("update_last_checked", "")
    return jsonify({
        "available_version": avail_ver,
        "description":       database.get_system_setting("update_available_description", ""),
        "dismissed_version": dismissed,
        "last_checked":      last_checked,
        "update_pending":    bool(avail_ver and avail_ver != dismissed),
    })


@app.route("/api/update/check_now", methods=["POST"])
@auth.login_required
@auth.requires_permission("manage_admin")
def api_update_check_now():
    """
    Immediately poll UPDATE_CHECK_URL and update system_settings with the result.

    Runs the same logic as the monitor's daily _check_for_updates(), but
    synchronously from the web service so the user doesn't have to wait up to
    24 hours after changing the manifest or for testing purposes.

    Returns JSON with success, message, available_version (if any), and last_checked.
    """
    if _requests is None:
        return jsonify({"success": False, "message": "requests library not available — install it in the venv"}), 500

    check_url = getattr(config, "UPDATE_CHECK_URL", "").strip()
    if not check_url:
        return jsonify({"success": False, "message": "UPDATE_CHECK_URL is not configured"}), 400

    try:
        from packaging import version as pkg_version

        resp = _requests.get(check_url, timeout=10)
        resp.raise_for_status()
        manifest = resp.json()

        available_ver = manifest.get("version", "").strip()
        description   = manifest.get("description", "").strip()

        version_file = os.path.join(NETWATCH_DIR, "VERSION")
        try:
            with open(version_file) as f:
                installed_ver = f.read().strip()
        except FileNotFoundError:
            installed_ver = "0.0.0"

        now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        database.set_system_setting("update_last_checked", now_str)

        if available_ver and pkg_version.parse(available_ver) > pkg_version.parse(installed_ver):
            database.set_system_setting("update_available_version",     available_ver)
            database.set_system_setting("update_available_description", description)
            log.info("update_check_now_found", available=available_ver,
                     installed=installed_ver,
                     user=auth.get_current_user().get("username"))
            return jsonify({
                "success":           True,
                "message":           f"Update available: v{available_ver}",
                "available_version": available_ver,
                "last_checked":      now_str,
            })
        else:
            # No newer version — clear any stale available entry
            database.set_system_setting("update_available_version",     "")
            database.set_system_setting("update_available_description", "")
            log.info("update_check_now_current", installed=installed_ver,
                     available=available_ver,
                     user=auth.get_current_user().get("username"))
            return jsonify({
                "success":           True,
                "message":           f"Already up to date (v{installed_ver})",
                "available_version": "",
                "last_checked":      now_str,
            })

    except Exception as e:
        log.warning("update_check_now_failed", error=str(e))
        return jsonify({"success": False, "message": f"Check failed: {e}"}), 502


@app.route("/api/update/dismiss", methods=["POST"])
@auth.login_required
@auth.requires_permission("manage_admin")
def api_update_dismiss():
    """
    Dismiss the update banner for the currently available version.
    The banner will reappear if a newer version becomes available.
    The banner always shows on /admin/patch regardless of dismiss state.
    """
    avail_ver = database.get_system_setting("update_available_version", "")
    if avail_ver:
        database.set_system_setting("update_dismissed_version", avail_ver)
        log.info("update_banner_dismissed", version=avail_ver,
                 user=auth.get_current_user().get("username"))
    return jsonify({"status": "ok"})


@app.route("/api/update/download", methods=["POST"])
@auth.login_required
@auth.requires_permission("manage_admin")
def api_update_download():
    """
    Download the available update package from GitHub and store it locally.
    Verifies the SHA-256 checksum against the manifest before saving.

    This is step 1 of 2 — download first, install separately.
    Stores the zip in ~/netwatch/updates/ once verified.

    Returns JSON with success, message, and filename on success.
    """
    import hashlib
    try:
        import requests as req_lib
    except ImportError:
        return jsonify({"success": False, "message": "requests library not available"}), 500

    check_url = getattr(config, "UPDATE_CHECK_URL", "").strip()
    if not check_url:
        return jsonify({"success": False, "message": "UPDATE_CHECK_URL is not configured"}), 400

    try:
        # Fetch the manifest to get package_url and sha256
        resp = req_lib.get(check_url, timeout=10)
        resp.raise_for_status()
        manifest = resp.json()
    except Exception as e:
        return jsonify({"success": False, "message": f"Failed to fetch update manifest: {e}"}), 502

    package_url  = manifest.get("package_url", "").strip()
    expected_sha = manifest.get("package_sha256", "").strip()
    avail_ver    = manifest.get("version", "").strip()

    if not package_url:
        return jsonify({"success": False,
                        "message": "No package URL in manifest — release may not be published yet"}), 400
    if not expected_sha:
        return jsonify({"success": False,
                        "message": "No SHA-256 checksum in manifest — cannot verify download"}), 400

    # Download the package zip
    try:
        dl_resp = req_lib.get(package_url, timeout=120)
        dl_resp.raise_for_status()
        zip_bytes = dl_resp.content
    except Exception as e:
        return jsonify({"success": False, "message": f"Download failed: {e}"}), 502

    # Verify SHA-256
    actual_sha = hashlib.sha256(zip_bytes).hexdigest()
    if actual_sha.lower() != expected_sha.lower():
        return jsonify({
            "success": False,
            "message": f"Checksum mismatch — download may be corrupt. Expected {expected_sha[:12]}…, got {actual_sha[:12]}…"
        }), 400

    # Save to ~/netwatch/updates/
    updates_dir = os.path.join(NETWATCH_DIR, "updates")
    os.makedirs(updates_dir, exist_ok=True)

    # Clean filename from version string (e.g. netwatch-3.4.0.zip)
    safe_ver  = avail_ver.replace("/", "-").replace("..", "")
    filename  = f"netwatch-{safe_ver}.zip"
    dest_path = os.path.join(updates_dir, filename)

    with open(dest_path, "wb") as f:
        f.write(zip_bytes)

    # Record what we downloaded so the install endpoint can find it
    database.set_system_setting("update_downloaded_version", avail_ver)
    database.set_system_setting("update_downloaded_file",    dest_path)

    log.info("update_downloaded",
             version=avail_ver, filename=filename, size_bytes=len(zip_bytes))

    return jsonify({
        "success":  True,
        "message":  f"NetWatch v{avail_ver} downloaded and verified ({len(zip_bytes)//1024} KB)",
        "version":  avail_ver,
        "filename": filename,
    })


@app.route("/api/update/install", methods=["POST"])
@auth.login_required
@auth.requires_permission("manage_users")
def api_update_install():
    """
    Install a previously downloaded update package.

    Step 1: Apply MIGRATIONS.md entries for versions newer than installed.
    Step 2: Pass the zip to patcher.apply_package() — identical path to
            manual Package Installer. Gets snapshots, backups, git push, etc.
    Step 3: Clear update_available_* system settings on success.
    Step 4: Delete the downloaded zip file.

    Only Admin can install (manage_users permission).
    """
    dl_file = database.get_system_setting("update_downloaded_file", "")
    dl_ver  = database.get_system_setting("update_downloaded_version", "")

    if not dl_file or not os.path.isfile(dl_file):
        return jsonify({
            "success": False,
            "message": "No downloaded update found — download the update first"
        }), 400

    try:
        with open(dl_file, "rb") as f:
            zip_bytes = f.read()
    except Exception as e:
        return jsonify({"success": False, "message": f"Could not read update file: {e}"}), 500

    installed_ver = patcher.get_installed_version()
    user          = auth.get_current_user()

    # ── Step 1: Apply schema migrations ──────────────────────────────────────
    mig_result = patcher.apply_migrations(zip_bytes, installed_ver)
    if not mig_result["success"]:
        return jsonify({
            "success": False,
            "message": f"Migration failed: {mig_result['error']}",
            "migration_result": mig_result,
        }), 500

    if mig_result["applied"]:
        log.info("migrations_applied",
                 versions=mig_result["applied"], user=user.get("username"))

    # ── Step 2: Apply the package via patcher ─────────────────────────────────
    result = patcher.apply_package(zip_bytes, applied_by=user.get("username", "web"))

    # ── Step 3: Clean up system_settings on success ───────────────────────────
    if result["success"]:
        database.set_system_setting("update_available_version",    "")
        database.set_system_setting("update_available_description","")
        database.set_system_setting("update_dismissed_version",    "")
        database.set_system_setting("update_downloaded_version",   "")
        database.set_system_setting("update_downloaded_file",      "")
        log.info("update_installed",
                 version=dl_ver, user=user.get("username"),
                 migrations_applied=mig_result["applied"])

    # ── Step 4: Delete the downloaded zip (success or failure) ────────────────
    try:
        os.remove(dl_file)
    except Exception:
        pass  # Non-fatal — stale file in updates/ is harmless

    # Attach migration info to result for the UI
    result["migration_result"] = mig_result
    return jsonify(result)


# PACKAGE INSTALLER (PATCHER)
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/admin/patch")
@auth.login_required
@auth.requires_permission("manage_admin")
def patch_manager():
    # On the Package Installer page, always show the update banner if an update
    # exists — even if the user previously dismissed it. This ensures they don't
    # forget an available update while browsing packages.
    avail_ver = database.get_system_setting("update_available_version", "")
    update_always = None
    if avail_ver:
        update_always = {
            "version":     avail_ver,
            "description": database.get_system_setting("update_available_description", ""),
        }
    check_url_configured = bool(getattr(config, "UPDATE_CHECK_URL", "").strip())
    last_checked         = database.get_system_setting("update_last_checked", "")
    git_configured       = patcher.get_git_configured()
    return render_template("patch_manager.html",
                           update_always=update_always,
                           check_url_configured=check_url_configured,
                           last_checked=last_checked,
                           git_configured=git_configured)


@app.route("/api/patch/preview", methods=["POST"])
@auth.login_required
@auth.requires_permission("manage_admin")
def api_patch_preview():
    if "file" not in request.files:
        return jsonify({"valid": False, "error": "No file uploaded", "preview": []})
    file = request.files["file"]
    result = patcher.validate_and_preview(file.read())
    return jsonify(result)


@app.route("/api/patch/apply", methods=["POST"])
@auth.login_required
@auth.requires_permission("manage_admin")
def api_patch_apply():
    if "file" not in request.files:
        return jsonify({"success": False, "message": "No file uploaded"})
    file   = request.files["file"]
    user   = auth.get_current_user()
    result = patcher.apply_package(file.read(), applied_by=user["username"])
    return jsonify(result)


@app.route("/api/patch/git_status")
@auth.login_required
@auth.requires_permission("manage_admin")
def api_patch_git_status():
    """Return git push state for the most recent install, plus whether git is configured."""
    return jsonify({
        "configured": patcher.get_git_configured(),
        "last":       patcher.get_last_git_state(),
    })


@app.route("/api/patch/git_retry", methods=["POST"])
@auth.login_required
@auth.requires_permission("manage_admin")
def api_patch_git_retry():
    """Retry the git push for the most recent install without reinstalling."""
    result = patcher.retry_git_push()
    return jsonify(result)


@app.route("/api/patch/history")
@auth.login_required
@auth.requires_permission("manage_admin")
def api_patch_history():
    try:
        limit = int(request.args.get("limit", 20))
    except ValueError:
        limit = 20
    if limit <= 0:
        limit = 9999  # "All"
    return jsonify(patcher.get_patch_history(limit=limit))


@app.route("/api/changelog")
@auth.login_required
@auth.requires_permission("manage_admin")
def api_changelog():
    """Return all changelog entries. Admin only."""
    return jsonify(patcher.get_changelog())


@app.route("/api/changelog/<int:entry_id>", methods=["PATCH"])
@auth.login_required
@auth.requires_permission("manage_admin")
def api_changelog_update(entry_id):
    """Save admin notes for a changelog entry."""
    data  = request.get_json() or {}
    notes = data.get("admin_notes", "")
    ok    = patcher.update_changelog_notes(entry_id, notes)
    return jsonify({"status": "ok" if ok else "error"})


def _build_changelog_palette():
    """Build a palette override dict for changelog HTML generation when the user
    has a custom color scheme active. Maps .nwtheme CSS variable names to the
    palette keys used by generate_release_notes_html / generate_combined_changelog_html.
    Returns None if no custom color scheme is active or if loading fails."""
    try:
        user = auth.get_current_user()
        if not user or user["is_guest"]:
            return None
        scheme_name = database.get_user_pref(user["id"], "custom_color_scheme")
        if not scheme_name:
            return None
        t = theme_manager.get_theme(scheme_name)
        if not t:
            return None
        cs = t.get("color_scheme", {})
        if not cs:
            return None
        # Map CSS variable names to patcher palette keys
        mapping = {
            "--bg-page":      "bg_page",
            "--bg-card":      "bg_card",
            "--bg-input":     "bg_input",
            "--border-color": "border",
            "--accent":       "accent",
            "--text-primary": "text_primary",
            "--text-muted":   "text_muted",
            "--text-label":   "text_label",
            "--ok":           "ok",
            "--warn":         "warn",
            "--fail":         "fail",
            "--font-body":    "font",
            "--font-mono":    "font_mono",
        }
        palette = {}
        for css_var, palette_key in mapping.items():
            if css_var in cs:
                palette[palette_key] = cs[css_var]
        return palette if palette else None
    except Exception:
        return None


@app.route("/admin/patch/changelog")
@auth.login_required
@auth.requires_permission("manage_admin")
def changelog_full():
    """Serve a combined printable HTML changelog for all installed packages."""
    from flask import session as _sess
    try:
        entries   = patcher.get_changelog(limit=9999)
        site_name = getattr(config, "SITE_NAME", "NetWatch") or "NetWatch"
        theme     = _sess.get("theme", "dark-blue")
        custom_palette = _build_changelog_palette()
        html      = patcher.generate_combined_changelog_html(entries, site_name=site_name, theme=theme, custom_palette=custom_palette)
        return html, 200, {"Content-Type": "text/html; charset=utf-8"}
    except Exception as e:
        return f"Error generating changelog: {e}", 500


@app.route("/admin/patch/release-notes/<int:entry_id>")
@auth.login_required
@auth.requires_permission("manage_admin")
def changelog_release_notes(entry_id):
    """Serve a printable HTML release notes page for a single package install."""
    from flask import Response as _Resp, session as _sess
    entry     = patcher.get_changelog_entry(entry_id)
    site_name = getattr(config, "SITE_NAME", "NetWatch") or "NetWatch"
    theme     = _sess.get("theme", "dark-blue")
    if not entry:
        return "Release notes not found.", 404
    try:
        custom_palette = _build_changelog_palette()
        html = patcher.generate_release_notes_html(entry, site_name=site_name, theme=theme, custom_palette=custom_palette)
        return _Resp(html, mimetype="text/html")
    except Exception as e:
        log.error("release_notes_failed", error=str(e))
        return f"Error generating release notes: {e}", 500


@app.route("/api/update/preview_single", methods=["POST"])
@auth.login_required
@auth.requires_permission("manage_admin")
def api_update_preview_single():
    if "file" not in request.files:
        return jsonify({"valid": False, "error": "No file uploaded", "preview": []})
    file     = request.files["file"]
    filename = file.filename
    content  = file.read()
    ext      = os.path.splitext(filename)[1].lower()
    item     = {"index": 0, "action": "replace", "detail": f"Replace {filename}",
                "status": "ok", "warning": None}
    if ext == ".py":
        import py_compile, tempfile as tf
        try:
            with tf.NamedTemporaryFile(suffix=".py", delete=False) as tmp:
                tmp.write(content)
                tmp_path = tmp.name
            py_compile.compile(tmp_path, doraise=True)
            os.unlink(tmp_path)
        except py_compile.PyCompileError as e:
            item["status"]  = "error"
            item["warning"] = str(e)
            try: os.unlink(tmp_path)
            except Exception: pass
    target = updater.get_target_path(filename)
    item["exists"] = os.path.exists(target)
    item["is_new"] = not item["exists"]
    return jsonify({"valid": item["status"] == "ok", "error": item.get("warning"),
                    "manifest": None, "version_warning": None,
                    "package_version": None,
                    "installed_version": patcher.get_installed_version(),
                    "preview": [item]})


# ══════════════════════════════════════════════════════════════════════════════
# CERTIFICATE MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/admin/certs")
@auth.login_required
@auth.requires_permission("manage_admin")
def certs_page():
    return render_template("certs.html")


@app.route("/ca-cert")
def ca_cert_download():
    ca_cert_path = os.path.join(NETWATCH_DIR, "certs/netwatch-ca.crt")
    if not os.path.exists(ca_cert_path):
        return "CA certificate not found. Run generate_certs.sh first.", 404
    return send_file(ca_cert_path, mimetype="application/x-x509-ca-cert",
                     as_attachment=True, download_name="netwatch-ca.crt")


@app.route("/api/certs/info")
@auth.login_required
@auth.requires_permission("manage_admin")
def api_certs_info():
    return jsonify(certmanager.get_cert_info())


@app.route("/api/certs/backup")
@auth.login_required
@auth.requires_permission("manage_admin")
def api_certs_backup():
    backup_path = os.path.join(NETWATCH_DIR, "certs/netwatch-ca-backup.zip")
    if not os.path.exists(backup_path):
        return jsonify({"error": "Backup not found"}), 404
    return send_file(backup_path, mimetype="application/zip",
                     as_attachment=True, download_name="netwatch-ca-backup.zip")


@app.route("/api/certs/regenerate", methods=["POST"])
@auth.login_required
@auth.requires_permission("manage_admin")
def api_certs_regenerate():
    success, message = certmanager.regenerate_server_cert()
    if success:
        import subprocess as sp
        sp.Popen(["bash", "-c", "sleep 2 && sudo systemctl restart netwatch-web"],
                 stdout=sp.DEVNULL, stderr=sp.DEVNULL)
    return jsonify({"success": success, "message": message})

if __name__ == "__main__":
    init()
    ssl_context = certmanager.get_ssl_context()
    app.run(
        host=config.DASHBOARD_HOST,
        port=config.DASHBOARD_PORT,
        debug=False,
        threaded=True,
        ssl_context=ssl_context
    )
