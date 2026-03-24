#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
# NetWatch — backup_db.sh
# Creates an encrypted backup of the database only (no code/certs).
# Designed for daily scheduled runs — small file, safe to email.
#
# Usage:
#   ./backup_db.sh              — backup only, save to ~/backups/
#   ./backup_db.sh --email      — backup and email via Gmail
#   ./backup_db.sh --email --quiet  — for cron (suppress non-error output)
#
# Requirements:
#   gpg must be installed, GPG public key must be imported
# ══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
# Derive NETWATCH_DIR from script location -- do not use $HOME (resolves to
# /nonexistent for netwatch-svc which has no home directory).
NETWATCH_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKUP_DIR="/home/mboynton/backups"
GPG_RECIPIENT="mattybusa@gmail.com"
MAX_EMAIL_SIZE_MB=20
KEEP_COPIES=$(python3 -c "import sys; sys.path.insert(0,'$NETWATCH_DIR'); import config; print(getattr(config, 'DB_BACKUP_RETENTION', 14))" 2>/dev/null || echo 14)

# Load email settings from config.py
GMAIL_USER=$(python3 -c "import sys; sys.path.insert(0,'$NETWATCH_DIR'); import config; print(config.GMAIL_USER)" 2>/dev/null || echo "")
GMAIL_PASS=$(python3 -c "import sys; sys.path.insert(0,'$NETWATCH_DIR'); import config; print(config.GMAIL_APP_PASSWORD)" 2>/dev/null || echo "")
ALERT_EMAIL=$(python3 -c "import sys; sys.path.insert(0,'$NETWATCH_DIR'); import config; print(config.ALERT_TO)" 2>/dev/null || echo "$GMAIL_USER")

# ── Parse arguments ───────────────────────────────────────────────────────────
DO_EMAIL=false
QUIET=false
for arg in "$@"; do
    case $arg in
        --email)  DO_EMAIL=true ;;
        --quiet)  QUIET=true ;;
    esac
done

# ── Helpers ───────────────────────────────────────────────────────────────────
log() { $QUIET || echo "[$(date '+%H:%M:%S')] $*"; }
err() { echo "[ERROR] $*" >&2; }

send_alert() {
    local subject="$1"
    local body="$2"
    [[ -z "$GMAIL_USER" || -z "$GMAIL_PASS" ]] && { err "Email not configured"; return; }
    python3 - << PYEOF
import smtplib
from email.mime.text import MIMEText
msg = MIMEText("""$body""")
msg['Subject'] = "$subject"
msg['From']    = "$GMAIL_USER"
msg['To']      = "$ALERT_EMAIL"
try:
    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as s:
        s.login("$GMAIL_USER", "$GMAIL_PASS")
        s.send_message(msg)
except Exception as e:
    print(f"Alert failed: {e}")
PYEOF
}

send_backup_email() {
    local backup_file="$1"
    local filesize_mb="$2"
    [[ -z "$GMAIL_USER" || -z "$GMAIL_PASS" ]] && { err "Email not configured"; return 1; }
    python3 - << PYEOF
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime

msg = MIMEMultipart()
msg['Subject'] = f"NetWatch Daily Database Backup — {datetime.utcnow().strftime('%Y-%m-%d')} UTC"
msg['From']    = "$GMAIL_USER"
msg['To']      = "$ALERT_EMAIL"

body = MIMEText("""NetWatch daily database backup.

File: $(basename $backup_file)
Size: ${filesize_mb}MB
Time: $(date -u '+%Y-%m-%d %H:%M:%S') UTC

This backup contains all health checks, speedtest results, and reset events.
It is encrypted and can only be decrypted with your GPG private key.

To restore:
  1. Decrypt on your PC: gpg --decrypt netwatch_db_*.db.gpg > netwatch.db
  2. Upload via Admin page: Admin → Database Backup & Restore → Restore
""")
msg.attach(body)

with open("$backup_file", 'rb') as f:
    part = MIMEBase('application', 'octet-stream')
    part.set_payload(f.read())
    encoders.encode_base64(part)
    part.add_header('Content-Disposition', f'attachment; filename="$(basename $backup_file)"')
    msg.attach(part)

try:
    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as s:
        s.login("$GMAIL_USER", "$GMAIL_PASS")
        s.send_message(msg)
    print("Backup email sent")
except Exception as e:
    print(f"Email failed: {e}")
    exit(1)
PYEOF
}

# ── Main ──────────────────────────────────────────────────────────────────────
TIMESTAMP=$(date -u '+%Y%m%d_%H%M%S')
STAGING_DIR=$(mktemp -d)

log "Starting NetWatch database backup..."
mkdir -p "$BACKUP_DIR"

# 1. Safe database snapshot using SQLite backup API
log "Snapshotting database..."
python3 - << PYEOF
import sqlite3
src = sqlite3.connect("$NETWATCH_DIR/netwatch.db")
dst = sqlite3.connect("$STAGING_DIR/netwatch.db")
src.backup(dst)
src.close()
dst.close()
print("  Database snapshot complete")
PYEOF

# 2. Encrypt directly — no intermediate tar needed for single file
log "Encrypting..."
ENCRYPTED_FILE="$BACKUP_DIR/netwatch_db_${TIMESTAMP}.db.gpg"
gpg --batch --yes --trust-model always \
    --homedir /home/mboynton/netwatch/.gnupg \
    --recipient "$GPG_RECIPIENT" \
    --output "$ENCRYPTED_FILE" \
    --encrypt "$STAGING_DIR/netwatch.db"

rm -rf "$STAGING_DIR"

FINAL_SIZE=$(du -m "$ENCRYPTED_FILE" | cut -f1)
log "Encrypted database backup: ${FINAL_SIZE}MB → $ENCRYPTED_FILE"

# 3. Keep only last N local copies
ls -t "$BACKUP_DIR"/netwatch_db_*.db.gpg 2>/dev/null | tail -n +$((KEEP_COPIES + 1)) | xargs rm -f 2>/dev/null || true

# 4. Email if requested
if $DO_EMAIL; then
    if (( FINAL_SIZE > MAX_EMAIL_SIZE_MB )); then
        err "Database backup too large to email (${FINAL_SIZE}MB > ${MAX_EMAIL_SIZE_MB}MB limit)"
        send_alert \
            "⚠ NetWatch Database Backup Too Large to Email" \
            "The NetWatch database backup (${FINAL_SIZE}MB) exceeds the email size limit (${MAX_EMAIL_SIZE_MB}MB).

The backup was saved locally to:
  $ENCRYPTED_FILE

Your database has grown large. Consider:
  1. Setting up an alternative destination (Google Drive, OneDrive)
  2. Running a data cleanup from the Admin page
  3. Increasing the MAX_EMAIL_SIZE_MB limit in backup_db.sh

This alert will repeat on every scheduled run until resolved."
        exit 1
    fi
    log "Emailing database backup..."
    send_backup_email "$ENCRYPTED_FILE" "$FINAL_SIZE"
    if [[ $? -eq 0 ]]; then
        "$NETWATCH_DIR/venv/bin/python3" "$NETWATCH_DIR/backup_notify.py" OK db "$(basename $ENCRYPTED_FILE)" "$ALERT_EMAIL"
    else
        "$NETWATCH_DIR/venv/bin/python3" "$NETWATCH_DIR/backup_notify.py" FAIL db "$(basename $ENCRYPTED_FILE)" "$ALERT_EMAIL" "Email send failed"
    fi
fi

log "Database backup complete: $(basename $ENCRYPTED_FILE)"
