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

log = logging.getLogger("netwatch.webapp")

app = Flask(__name__)
app.secret_key = config.SECRET_KEY

# Session cookie settings
app.config["SESSION_COOKIE_HTTPONLY"] = True   # JS cannot read session cookie
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"  # CSRF protection


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
       not request.path.startswith("/static"):
        return redirect(url_for("setup_wizard"))

# ── Setup Wizard Routes ────────────────────────────────────────────────────────

@app.route("/setup")
def setup_wizard():
    return render_template("setup.html")

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

        # Restart services
        subprocess.Popen(["bash", "-c",
            "sleep 1 && sudo systemctl restart netwatch-monitor netwatch-web"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        return jsonify({"status": "ok"})

    except Exception as e:
        log.error(f"Setup apply failed: {e}")
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
        log.error(f"Subscriber backfill failed: {e}")
    # Backfill: ensure every role has alert defaults seeded
    try:
        for role in auth.get_all_roles():
            alert_subscribers.seed_role_alert_defaults(role["id"])
    except Exception as e:
        log.error(f"Role alert defaults backfill failed: {e}")
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
            log.error(f"Owner seed failed: {e}")
        try:
            config_validator.remove_legacy_email_keys()
            config_validator.migrate_email_keys()
            config_validator.cleanup_false_positives()
            notifications = config_validator.validate()
            if notifications:
                log.info(f"Config validator: {len(notifications)} new setting(s) added")
        except Exception as e:
            log.error(f"Config validator failed: {e}")


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

    return {
        "current_user":           auth.get_current_user(),
        "config_notifications":   notifications,
        "custom_theme_css":       custom_css,
        "custom_themes":          custom_themes,
        "active_custom_color":    active_custom_color,
        "active_custom_layout":   active_custom_layout,
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
    """Same as type_settings but accessible to all logged-in users for preferences page."""
    settings = alert_subscribers.get_alert_type_settings()
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

        auth.login_user(user)

        # Clear any flash messages from previous session so they don't show to this user
        session.pop('_flashes', None)

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


@app.before_request
def enforce_forced_change_deadline():
    """
    If user has must_change_pass set, enforce the deadline on every request.
    If deadline has passed or was never set, log them out and send to login.
    Exempts the change_password, login, logout, and static routes.
    """
    exempt = {"change_password", "login", "logout", "forgot_password",
              "static", "first_run_wizard"}
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


# Auto-refresh polling paths that must NOT count as user activity
_POLLING_PATHS = frozenset({
    "/api/metrics", "/api/alerts/status", "/api/network/status",
    "/api/speedtest/latest", "/api/monitor/status", "/api/monitor/history",
    "/api/dashboard/stats", "/api/events/recent",
})

@app.before_request
def update_last_activity():
    """Reset idle-timeout clock on real user requests. Excludes polling endpoints."""
    from flask import session as _sess
    if not _sess.get("user_id"):
        return
    path = request.path
    if path.startswith("/static"):
        return
    base = path.rstrip("/") or "/"
    if base in _POLLING_PATHS:
        return
    for p in _POLLING_PATHS:
        if base.startswith(p):
            return
    from datetime import datetime as _dt
    _sess["last_activity"] = _dt.now().isoformat()
    _sess.modified = True


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
                log.error(f"Failed to send reset email: {e}")

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
                log.error(f"Failed to send reset SMS: {e}")

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
        log.error(f"Failed to send verification email: {e}")
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
        log.info(f"Merged standalone subscriber {standalone['id']} into account {user['username']} on email verify")

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
    limit = int(request.args.get("limit", 100))
    event_types = request.args.getlist("type") or None
    return jsonify(security_log.get_events(limit=limit, event_types=event_types))


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
    return render_template("admin.html")


@app.route("/admin/users")
@auth.login_required
@auth.requires_permission("manage_users")
def admin_users():
    return render_template("admin_users.html")


@app.route("/preferences")
@auth.login_required
def preferences():
    return render_template("preferences.html")


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
    success, error = auth.change_password(user_id, new_password)
    if success:
        # Flag user to change on next login
        auth.update_user(user_id, must_change_pass=True)
        return jsonify({"status": "ok"})
    return jsonify({"status": "error", "message": error})


@app.route("/api/session/ping", methods=["POST"])
@auth.login_required
def api_session_ping():
    """
    Called by client JS on real user interaction to reset idle timer.
    Returns remaining seconds before timeout (or null if no timeout).
    """
    from flask import session as _sess
    from datetime import datetime as _dt
    _sess["last_activity"] = _dt.now().isoformat()
    _sess.modified = True
    minutes = _sess.get("session_minutes", 480)
    if minutes <= 0:
        return jsonify({"status": "ok", "remaining": None})
    return jsonify({"status": "ok", "remaining": minutes * 60})


@app.route("/api/session/status")
@auth.login_required
def api_session_status():
    """Return seconds remaining in current session for client-side countdown."""
    from flask import session as _sess
    from datetime import datetime as _dt
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
        log.info(f"Self-registration: new account '{username}' created")
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


@app.route("/api/reset_history")
@auth.guest_allowed
def api_reset_history():
    days = int(request.args.get("days", 30))
    return jsonify(database.get_reset_history(days=days))


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
            log.error(f"Backup failed: {result.stderr}")
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

    EXCLUDE_DIRS  = {"__pycache__", "venv", "certs", "logs", "data", "backups", "snapshots"}
    EXCLUDE_EXTS  = {".pyc", ".bak", ".gpg", ".gz"}
    # Exclude DB files by prefix regardless of extension variant
    EXCLUDE_PREFIXES = {"netwatch.db"}
    EXCLUDE_FILES = {"config.py", "gunicorn.ctl"}   # config has credentials; gunicorn.ctl is a runtime socket

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


@app.route("/api/admin/generate_update_pkg", methods=["POST"])
@auth.login_required
@auth.requires_permission("manage_admin")
def admin_generate_update_pkg():
    """
    Generate an update package — contains all current code but NO config/data.
    Recipient installs via Package Installer. Their config.py, netwatch.db,
    and certs/ are left untouched. Config validator runs on restart and adds
    any new settings with safe defaults, triggering the notification banner.
    """
    import shutil, tempfile

    netwatch_dir = NETWATCH_DIR
    output_dir   = os.path.join(os.path.dirname(NETWATCH_DIR), "backups")
    timestamp    = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    # Read current version
    try:
        with open(os.path.join(netwatch_dir, "VERSION")) as f:
            version = f.read().strip()
    except Exception:
        version = "unknown"

    pkg_name = f"netwatch_update_v{version}_{timestamp}"

    try:
        staging = tempfile.mkdtemp()
        dest    = os.path.join(staging, pkg_name)
        os.makedirs(dest)

        # Files to include — all code, templates, static
        # Explicitly exclude anything personal or environment-specific
        exclude_files = {
            "config.py", "netwatch.db", "netwatch.db.bak",
            "netwatch.db.pre_restore", "netwatch-backup-public.asc",
        }
        exclude_dirs = {
            "venv", "__pycache__", "logs", "certs", "backups", "data",
        }

        for item in os.listdir(netwatch_dir):
            if item in exclude_files or item.endswith(".pyc") or \
               item.endswith(".bak") or item.endswith(".gpg"):
                continue
            src = os.path.join(netwatch_dir, item)
            dst = os.path.join(dest, item)
            if os.path.isdir(src):
                if item in exclude_dirs:
                    continue
                shutil.copytree(src, dst, ignore=shutil.ignore_patterns(
                    "*.pyc", "__pycache__", "*.db", "*.gpg", "*.bak"))
            else:
                shutil.copy2(src, dst)

        # Write a manifest.json so the Package Installer knows what to do
        import json
        # Build action list — replace all code files, skip config/db/certs
        actions = []
        for item in os.listdir(dest):
            if item == "manifest.json":
                continue
            src_path = os.path.join(dest, item)
            if os.path.isfile(src_path):
                actions.append({"action": "replace", "file": item})
            elif os.path.isdir(src_path):
                # Add all files in subdirs
                for root, dirs, files in os.walk(src_path):
                    dirs[:] = [d for d in dirs if d != "__pycache__"]
                    for f in files:
                        rel = os.path.relpath(os.path.join(root, f), dest)
                        actions.append({"action": "replace", "file": rel})

        actions.append({"action": "restart", "services": ["web", "monitor"]})

        manifest = {
            "version":      version,
            "description":  f"NetWatch update to v{version}. Preserves your config.py, database, and certificates. New config settings added automatically.",
            "min_version":  "2.0",
            "actions":      actions,
        }
        with open(os.path.join(dest, "manifest.json"), "w") as f:
            json.dump(manifest, f, indent=2)

        # Package it
        os.makedirs(output_dir, exist_ok=True)
        zip_path  = os.path.join(output_dir, pkg_name)
        shutil.make_archive(zip_path, "zip", staging, pkg_name)
        final_zip = zip_path + ".zip"
        shutil.rmtree(staging)

        size_mb = round(os.path.getsize(final_zip) / 1024 / 1024, 1)
        log.info(f"Update package generated: {final_zip} ({size_mb}MB)")
        return jsonify({"status": "ok", "filename": os.path.basename(final_zip), "size_mb": size_mb})

    except Exception as e:
        log.error(f"Update package generation failed: {e}")
        return jsonify({"status": "error", "message": str(e)})


@app.route("/api/admin/generate_distrib", methods=["POST"])
@auth.login_required
@auth.requires_permission("manage_admin")
def admin_generate_distrib():
    """Generate a blank distributable zip with personal data stripped."""
    import shutil, tempfile, re, sqlite3

    netwatch_dir = NETWATCH_DIR
    output_dir   = os.path.join(os.path.dirname(NETWATCH_DIR), "backups")
    timestamp    = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    distrib_name = f"netwatch_distributable_{timestamp}"

    try:
        staging = tempfile.mkdtemp()
        dest    = os.path.join(staging, "netwatch_distributable")
        os.makedirs(dest)

        # 1. Copy all code and template files
        skip = {"venv", "__pycache__", "logs", "data", "certs",
                "netwatch.db", "netwatch.db.bak", "netwatch.db.pre_restore",
                "*.pyc", "*.gpg"}
        for item in os.listdir(netwatch_dir):
            if item in skip or item.endswith(".pyc") or item.endswith(".bak"):
                continue
            src = os.path.join(netwatch_dir, item)
            dst = os.path.join(dest, item)
            if os.path.isdir(src):
                shutil.copytree(src, dst, ignore=shutil.ignore_patterns(
                    "*.pyc", "__pycache__", "*.db", "*.gpg", "*.bak"))
            else:
                shutil.copy2(src, dst)

        # 2. Strip personal data from config.py
        config_path = os.path.join(dest, "config.py")
        if os.path.exists(config_path):
            with open(config_path, "r") as f:
                cfg = f.read()

            replacements = {
                r'^SECRET_KEY\s*=.*$':         'SECRET_KEY          = "CHANGE_THIS_TO_A_RANDOM_SECRET_KEY"',
                r'^GMAIL_USER\s*=.*$':          'GMAIL_USER          = "your_email@gmail.com"',
                r'^GMAIL_APP_PASSWORD\s*=.*$':  'GMAIL_APP_PASSWORD  = "your_app_password_here"',
                r'^ALERT_TO\s*=.*$':            'ALERT_TO            = "your_email@gmail.com"',
                r'^ALERTS_ENABLED\s*=.*$':      'ALERTS_ENABLED      = False',
                r'^LAN_GATEWAY\s*=.*$':         'LAN_GATEWAY         = "192.168.1.1"',
                r'^WIFI_GATEWAY\s*=.*$':        'WIFI_GATEWAY        = ""',
                r'^SITE_NAME\s*=.*$':           'SITE_NAME           = "NetWatch"',
            }
            for pattern, replacement in replacements.items():
                cfg = re.sub(pattern, replacement, cfg, flags=re.MULTILINE)

            with open(config_path, "w") as f:
                f.write(cfg)

        # 3. Create a blank initialized database
        db_path = os.path.join(dest, "netwatch.db")
        conn = sqlite3.connect(db_path)
        conn.close()
        # Initialize schema by importing database module
        import sys
        sys.path.insert(0, netwatch_dir)
        import importlib
        db_mod = importlib.import_module("database")
        # Point database to the blank db
        orig_path = db_mod.DB_PATH
        db_mod.DB_PATH = db_path
        db_mod.init_db()
        db_mod.DB_PATH = orig_path

        # 4. Remove certs directory contents (keep the dir)
        certs_dest = os.path.join(dest, "certs")
        if os.path.exists(certs_dest):
            shutil.rmtree(certs_dest)
        os.makedirs(certs_dest)

        # 5. Add README
        readme_src = os.path.join(netwatch_dir, "README.md")
        if os.path.exists(readme_src):
            shutil.copy2(readme_src, os.path.join(dest, "README.md"))
        else:
            with open(os.path.join(dest, "README.md"), "w") as f:
                f.write("# NetWatch\nSee https://github.com/your-repo for documentation.\n")

        # 6. Create the zip
        os.makedirs(output_dir, exist_ok=True)
        zip_path = os.path.join(output_dir, distrib_name)
        shutil.make_archive(zip_path, "zip", staging, "netwatch_distributable")
        final_zip = zip_path + ".zip"

        shutil.rmtree(staging)

        size_mb = round(os.path.getsize(final_zip) / 1024 / 1024, 1)
        log.info(f"Distributable generated: {final_zip} ({size_mb}MB)")
        return jsonify({"status": "ok", "filename": os.path.basename(final_zip), "size_mb": size_mb})

    except Exception as e:
        log.error(f"Distributable generation failed: {e}")
        return jsonify({"status": "error", "message": str(e)})


@app.route("/api/admin/distrib_download")
@auth.login_required
@auth.requires_permission("manage_admin")
def admin_distrib_download():
    """Download a generated distributable zip."""
    filename  = request.args.get("file", "")
    backup_dir = os.path.join(os.path.dirname(NETWATCH_DIR), "backups")
    if not (filename.startswith("netwatch_distributable_") or filename.startswith("netwatch_update_")) or ".." in filename:
        return jsonify({"status": "error", "message": "Invalid filename"}), 400
    filepath = os.path.join(backup_dir, filename)
    if not os.path.exists(filepath):
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
        log.info("Database restored from upload")
        return jsonify({"status": "ok", "message": "Database restored successfully. Previous database saved as netwatch.db.pre_restore"})
    except Exception as e:
        # Rollback
        shutil.copy2(bak_path, db_path)
        os.unlink(tmp.name)
        return jsonify({"status": "error", "message": f"Restore failed: {e}"})


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
    EXCLUDE_DIRS     = {"__pycache__", "venv", "certs", "logs", "data", "backups", "snapshots", "dev_docs"}
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
    sections         = configeditor.get_sections()
    values           = configeditor.read_config()
    fields_json      = json.dumps(configeditor.FIELDS)
    unconfigured_keys = config_validator.get_unconfigured_keys()
    return render_template("config_editor.html", sections=sections,
                           values=values, fields_json=fields_json,
                           unconfigured_keys=unconfigured_keys)


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
# PACKAGE INSTALLER (PATCHER)
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/admin/patch")
@auth.login_required
@auth.requires_permission("manage_admin")
def patch_manager():
    return render_template("patch_manager.html")


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
        html      = patcher.generate_combined_changelog_html(entries, site_name=site_name, theme=theme)
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
        html = patcher.generate_release_notes_html(entry, site_name=site_name, theme=theme)
        return _Resp(html, mimetype="text/html")
    except Exception as e:
        log.error(f"Release notes failed: {e}")
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
