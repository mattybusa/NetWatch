# ══════════════════════════════════════════════════════════════════════════════
# NetWatch — alerts.py
# Email and SMS alert delivery using the subscriber system.
# ══════════════════════════════════════════════════════════════════════════════

import os
import re
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

import config
import database
import alert_subscribers as subs

NETWATCH_DIR = os.path.dirname(os.path.abspath(__file__))

log = logging.getLogger("netwatch.alerts")

SUBJECTS = {
    "outage":            "⚠️  NetWatch: Network Outage Detected",
    "restored":          "✅  NetWatch: Network Restored",
    "reset_performed":   "🔄  NetWatch: Device Reset Performed",
    "degraded":          "📉  NetWatch: Network Degradation Alert",
    "conservative_mode": "🛑  NetWatch: Max Daily Resets Reached",
    "lockout_changed":   "🔒  NetWatch: Lockout Mode Changed",
    "daily_summary":     "📊  NetWatch: Daily Network Summary",
    "test":              "🧪  NetWatch: Test Alert",
    "brute_force":       "🚨  NetWatch: Brute Force Login Attempt",
    "security_event":    "🔐  NetWatch: Security Event",
    "email_verification":"✉️  NetWatch: Email Verification Code",
    "password_reset":    "🔑  NetWatch: Password Reset",
    "pkg_update":        "🔧  NetWatch: Pi Package Update Complete",
}

COLORS = {
    "outage":            "#c0392b",
    "restored":          "#27ae60",
    "reset_performed":   "#2980b9",
    "degraded":          "#d35400",
    "conservative_mode": "#c0392b",
    "lockout_changed":   "#8e44ad",
    "daily_summary":     "#16a085",
    "test":              "#7f8c8d",
    "brute_force":       "#c0392b",
    "security_event":    "#8e44ad",
    "pkg_update":        "#1a7f4b",
}

SMS_LABELS = {
    "outage":            "OUTAGE",
    "restored":          "RESTORED",
    "reset_performed":   "RESET",
    "degraded":          "DEGRADED",
    "conservative_mode": "MAX RESETS",
    "lockout_changed":   "LOCKOUT",
    "daily_summary":     "SUMMARY",
    "test":              "TEST",
    "brute_force":       "BRUTE FORCE",
    "security_event":    "SECURITY",
    "pkg_update":        "PKG UPDATE",
}


def _gmail_user():
    return getattr(config, "GMAIL_USER", "") or ""

def _gmail_pass():
    return getattr(config, "GMAIL_APP_PASSWORD", "") or ""

def _site_name():
    return getattr(config, "SITE_NAME", "NetWatch") or "NetWatch"


def _send_one(to_address, subject, html_body, plain_body):
    gmail_user = _gmail_user()
    gmail_password = _gmail_pass()
    if not gmail_user or not gmail_password:
        log.error("Cannot send: GMAIL_USER or GMAIL_APP_PASSWORD not configured")
        return False
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = gmail_user
        msg["To"]      = to_address
        msg.attach(MIMEText(plain_body, "plain"))
        msg.attach(MIMEText(html_body,  "html"))
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=15) as server:
            server.login(gmail_user, gmail_password)
            server.sendmail(gmail_user, to_address, msg.as_string())
        return True
    except smtplib.SMTPAuthenticationError as e:
        log.error(f"Alert failed auth ({e.smtp_code}): {e.smtp_error}")
        return False
    except Exception as e:
        log.error(f"Alert failed: {e}")
        return False


def _get_owner_sub_id():
    try:
        import sqlite3
        conn = sqlite3.connect(os.path.join(NETWATCH_DIR, "netwatch.db"))
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT id FROM alert_subscribers WHERE is_owner=1").fetchone()
        conn.close()
        return row["id"] if row else None
    except Exception:
        return None


def _get_theme_for_subscriber(subscriber):
    """
    Resolve the best UI theme string for a subscriber.
    - Account subscriber (user_id set): use their saved theme from users table.
    - Standalone subscriber (no user_id): use the owner's theme.
    - Fallback: dark-blue.
    """
    try:
        import sqlite3 as _sq
        conn = _sq.connect(os.path.join(NETWATCH_DIR, "netwatch.db"))
        conn.row_factory = _sq.Row

        if subscriber and subscriber.get("user_id"):
            row = conn.execute(
                "SELECT theme FROM users WHERE id=?", (subscriber["user_id"],)
            ).fetchone()
            if row and row["theme"]:
                conn.close()
                return row["theme"]

        # Fall back to owner's theme
        owner = conn.execute(
            "SELECT s.username FROM alert_subscribers s WHERE s.is_owner=1"
        ).fetchone()
        if owner:
            row = conn.execute(
                "SELECT theme FROM users WHERE username=?", (owner["username"],)
            ).fetchone()
            if row and row["theme"]:
                conn.close()
                return row["theme"]

        conn.close()
    except Exception:
        pass
    return "dark-blue"


# ── Theme palettes (mirrors patcher.py) ───────────────────────────────────────
_THEMES = {
    "dark-blue": {
        "bg_page":      "#0f1923",
        "bg_card":      "#152330",
        "bg_input":     "#0a1520",
        "border":       "#1e3a5f",
        "accent":       "#4fc3f7",
        "text_primary": "#e0e0e0",
        "text_muted":   "#546e7a",
        "header_text":  "#e0e0e0",
        "ok":           "#4caf50",
        "fail":         "#f44336",
        "font":         "'Exo 2','Segoe UI',Arial,sans-serif",
    },
    "dark-green": {
        "bg_page":      "#030a03",
        "bg_card":      "#071407",
        "bg_input":     "#020802",
        "border":       "#0d3b0d",
        "accent":       "#00cc44",
        "text_primary": "#ccffcc",
        "text_muted":   "#2d6b2d",
        "header_text":  "#ccffcc",
        "ok":           "#00ff55",
        "fail":         "#ff3300",
        "font":         "'IBM Plex Mono','Courier New',monospace",
    },
    "light": {
        "bg_page":      "#f0f4f8",
        "bg_card":      "#ffffff",
        "bg_input":     "#f8fafc",
        "border":       "#d1dde8",
        "accent":       "#1565c0",
        "text_primary": "#1a2332",
        "text_muted":   "#6b7c93",
        "header_text":  "#ffffff",
        "ok":           "#2e7d32",
        "fail":         "#c62828",
        "font":         "'Inter','Segoe UI',Arial,sans-serif",
    },
    "high-contrast": {
        "bg_page":      "#000000",
        "bg_card":      "#0a0a0a",
        "bg_input":     "#111111",
        "border":       "#555555",
        "accent":       "#ffff00",
        "text_primary": "#ffffff",
        "text_muted":   "#aaaaaa",
        "header_text":  "#000000",
        "ok":           "#00ff00",
        "fail":         "#ff0000",
        "font":         "'Inter',Arial,sans-serif",
    },
}


def send_alert(alert_type, message, force=False, force_email=None, subject=None, subscriber_id=None):
    """Log alert and deliver to all active subscribers.
    force_email: if set, send directly to this address only (for transactional emails).
    subject: optional subject line override.
    subscriber_id: optional subscriber id to associate with force_email delivery log."""
    alert_id = database.log_alert(alert_type, message, sent=False)

    # Direct transactional email (verification codes, password resets)
    if force_email:
        subj       = subject or SUBJECTS.get(alert_type, f"NetWatch: {alert_type}")
        owner_sub  = None
        try:
            owner_id = _get_owner_sub_id()
            if owner_id:
                owner_sub = subs.get_subscriber_by_id(owner_id)
        except Exception:
            pass
        theme      = _get_theme_for_subscriber(owner_sub)
        html_body  = _build_html_body(alert_type, message, theme=theme)
        plain_body = _build_plain_body(alert_type, message)
        ok = _send_one(force_email, subj, html_body, plain_body)
        if ok and alert_id:
            database.mark_alert_sent(alert_id)
        try:
            subs.log_delivery(
                alert_type=alert_type, alert_event=message,
                subscriber_id=subscriber_id,
                channel="email", address=force_email,
                success=ok, is_test=False
            )
        except Exception:
            pass
        return ok

    if not config.ALERTS_ENABLED and not force:
        log.info(f"Alert logged (disabled): [{alert_type}] {message}")
        return False

    if force:
        owner_id = _get_owner_sub_id()
        recipients = [r for r in subs.get_active_recipients("test")
                      if r["subscriber_id"] == owner_id]
        if not recipients:
            alert_to = getattr(config, "ALERT_TO", "") or ""
            if alert_to:
                recipients = [{"address": alert_to, "channel": "email",
                               "subscriber_id": None, "username": "owner"}]
    else:
        recipients = subs.get_active_recipients(alert_type)

    if not recipients:
        log.warning(f"No recipients for alert: {alert_type}")
        return False

    subject  = SUBJECTS.get(alert_type, f"NetWatch: {alert_type}")
    sms_body = _build_sms_body(alert_type, message)

    any_sent = False
    for recipient in recipients:
        if recipient["channel"] == "sms":
            sms_subj = f"{_site_name()}: {SMS_LABELS.get(alert_type, alert_type)}"
            ok = _send_one(recipient["address"], sms_subj, sms_body, sms_body)
        else:
            sub_record   = subs.get_subscriber_by_id(recipient["subscriber_id"]) if recipient.get("subscriber_id") else None
            theme        = _get_theme_for_subscriber(sub_record)
            display_name = subs.get_display_name(recipient)
            html_body  = _build_html_body(alert_type, message, display_name, theme=theme)
            plain_body = _build_plain_body(alert_type, message, display_name)
            ok = _send_one(recipient["address"], subject, html_body, plain_body)
        try:
            subs.log_delivery(
                alert_type=alert_type, alert_event=message,
                subscriber_id=recipient.get("subscriber_id"),
                channel=recipient["channel"], address=recipient["address"],
                success=ok, is_test=False
            )
        except Exception:
            pass
        if ok:
            any_sent = True
            log.info(f"Alert [{alert_type}] -> {recipient['channel']}:{recipient['address']}")

    if any_sent and alert_id:
        database.mark_alert_sent(alert_id)
    return any_sent


def send_test(subscriber_id, channel):
    """
    Send a test alert to a specific subscriber on a specific channel.
    Used by both the Alerts admin page and the Preferences page.
    Returns (success, message).
    """
    import alert_subscribers as subs_mod
    sub = subs_mod.get_subscriber_by_id(subscriber_id)
    if not sub:
        return False, "Subscriber not found"

    theme        = _get_theme_for_subscriber(sub)
    display_name = subs_mod.get_display_name(sub)
    subject  = SUBJECTS["test"]
    html     = _build_html_body("test", "This is a test alert from your NetWatch monitor. If you received this, your alert delivery is working correctly.", display_name, theme=theme)
    plain    = _build_plain_body("test", "This is a test alert from your NetWatch monitor.", display_name)
    sms_body = _build_sms_body("test",  "Test alert — delivery confirmed.")

    if channel == "email":
        address = sub.get("email_address", "")
        if not address:
            return False, "No email address configured"
        ok = _send_one(address, subject, html, plain)
        database.log_alert("test", f"Test email sent to {address} for {display_name}", sent=ok)
        try:
            subs_mod.log_delivery("test", "Test alert", subscriber_id, "email", address, ok, is_test=True)
        except Exception:
            pass
        return ok, f"Test email sent to {address}" if ok else f"Failed to send to {address}"

    elif channel == "sms":
        sms_addr = subs_mod.get_sms_address(sub)
        if not sms_addr:
            return False, "No SMS address configured — check phone number and carrier"
        sms_subj = f"{_site_name()}: TEST"
        ok = _send_one(sms_addr, sms_subj, sms_body, sms_body)
        database.log_alert("test", f"Test SMS sent to {sms_addr} for {display_name}", sent=ok)
        try:
            subs_mod.log_delivery("test", "Test alert", subscriber_id, "sms", sms_addr, ok, is_test=True)
        except Exception:
            pass
        return ok, f"Test SMS sent to {sms_addr}" if ok else f"Failed to send to {sms_addr}"

    return False, f"Unknown channel: {channel}"

def _strip_html(text):
    clean = re.sub(r'<[^>]+>', ' ', text)
    return re.sub(r'\s+', ' ', clean).strip()


def _build_sms_body(alert_type, message):
    site  = _site_name()
    label = SMS_LABELS.get(alert_type, alert_type.upper())
    ts    = datetime.utcnow().strftime("%H:%MZ")
    clean = _strip_html(message)
    prefix = f"{site} {label} {ts}: "
    max_msg = 160 - len(prefix)
    if len(clean) > max_msg:
        clean = clean[:max_msg - 1] + "..."
    return prefix + clean


def _build_plain_body(alert_type, message, display_name="there"):
    site  = _site_name()
    label = SMS_LABELS.get(alert_type, alert_type.upper())
    ts    = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    clean = _strip_html(message)
    return f"Hi {display_name},\n\n{site} — {label}\n{ts}\n\n{clean}"


def _build_html_body(alert_type, message, display_name="there", theme="dark-blue"):
    t         = _THEMES.get(theme, _THEMES["dark-blue"])
    color     = COLORS.get(alert_type, t["accent"])
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    site_name = _site_name()
    font      = t["font"]
    bg_page   = t["bg_page"]
    bg_card   = t["bg_card"]
    bg_input  = t["bg_input"]
    border    = t["border"]
    text_primary = t["text_primary"]
    text_muted   = t["text_muted"]
    header_text  = t["header_text"]

    return f"""<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:{bg_page};font-family:{font};">
  <div style="max-width:580px;margin:40px auto;background:{bg_card};
              border-radius:10px;border:1px solid {border};
              box-shadow:0 4px 20px rgba(0,0,0,0.4);overflow:hidden;">

    <!-- Header bar -->
    <div style="background:{color};padding:22px 28px;">
      <div style="display:flex;align-items:center;gap:10px;">
        <div style="font-size:22px;line-height:1;">📡</div>
        <div>
          <div style="margin:0;color:{header_text};font-size:18px;font-weight:700;
                      letter-spacing:0.5px;">{site_name}</div>
          <div style="margin:3px 0 0;color:{header_text};opacity:0.8;font-size:12px;">{timestamp}</div>
        </div>
      </div>
    </div>

    <!-- Body -->
    <div style="padding:28px;">
      <p style="font-size:14px;color:{text_muted};margin:0 0 18px;">Hi {display_name},</p>
      <div style="background:{bg_input};border-left:3px solid {color};
                  border-radius:0 6px 6px 0;padding:14px 18px;margin-bottom:20px;">
        <p style="font-size:15px;color:{text_primary};line-height:1.65;margin:0;">{message}</p>
      </div>
      <hr style="border:none;border-top:1px solid {border};margin:20px 0;">
      <p style="font-size:11px;color:{text_muted};margin:0;letter-spacing:0.3px;">
        Sent by your {site_name} network monitor. Do not reply to this email.
      </p>
    </div>

  </div>
</body>
</html>"""
