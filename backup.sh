#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
# NetWatch — backup.sh
# Creates an encrypted full system backup using the GPG public key.
# Safe to run while NetWatch is running — uses SQLite's backup API.
#
# Usage:
#   ./backup.sh              — backup only, save to ~/backups/
#   ./backup.sh --email      — backup and email via Gmail
#   ./backup.sh --email --quiet  — for cron (suppress non-error output)
#
# Requirements:
#   gpg, sqlite3 must be installed (sudo apt install gpg sqlite3)
#   GPG public key must be imported (run setup once)
# ══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
# Derive NETWATCH_DIR from script location -- do not use $HOME (resolves to
# /nonexistent for netwatch-svc which has no home directory).
NETWATCH_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKUP_DIR="/home/mboynton/backups"
GPG_RECIPIENT="mattybusa@gmail.com"   # Must match imported public key
MAX_EMAIL_SIZE_MB=20                   # Alert if backup exceeds this size

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
    if [[ -z "$GMAIL_USER" || -z "$GMAIL_PASS" ]]; then
        err "Email not configured — cannot send alert"
        return
    fi
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
    print("Alert sent")
except Exception as e:
    print(f"Alert failed: {e}")
PYEOF
}

send_backup_email() {
    local backup_file="$1"
    local filesize_mb="$2"
    if [[ -z "$GMAIL_USER" || -z "$GMAIL_PASS" ]]; then
        err "Email not configured — cannot send backup"
        return 1
    fi
    python3 - << PYEOF
import smtplib, os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime

msg = MIMEMultipart()
msg['Subject'] = f"NetWatch Backup — {datetime.now().strftime('%Y-%m-%d %H:%M')} UTC"
msg['From']    = "$GMAIL_USER"
msg['To']      = "$ALERT_EMAIL"

body = MIMEText("""NetWatch automated backup.

File: $(basename $backup_file)
Size: ${filesize_mb}MB
Time: $(date -u '+%Y-%m-%d %H:%M:%S') UTC

To restore:
  1. Decrypt on your PC: gpg --decrypt netwatch_backup_*.tar.gz.gpg > backup.tar.gz
  2. SCP to Pi: scp backup.tar.gz mboynton@192.168.100.10:~/
  3. On Pi: bash ~/netwatch/restore.sh ~/backup.tar.gz
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
    print("Backup email sent successfully")
except Exception as e:
    print(f"Email failed: {e}")
    exit(1)
PYEOF
}

# ── Main ──────────────────────────────────────────────────────────────────────
TIMESTAMP=$(date -u '+%Y%m%d_%H%M%S')
STAGING_DIR=$(mktemp -d)
BACKUP_NAME="netwatch_backup_${TIMESTAMP}"

log "Starting NetWatch backup..."
mkdir -p "$BACKUP_DIR"

# 1. Safe database snapshot using SQLite backup API
log "Snapshotting database..."
python3 - << PYEOF
import sqlite3, os
src = sqlite3.connect("$NETWATCH_DIR/netwatch.db")
dst = sqlite3.connect("$STAGING_DIR/netwatch.db")
src.backup(dst)
src.close()
dst.close()
print("  Database snapshot complete")
PYEOF

# 2. Copy all code and config files
log "Copying application files..."
mkdir -p "$STAGING_DIR/netwatch"
rsync -a --exclude='*.pyc' --exclude='__pycache__' --exclude='*.db' \
    --exclude='venv/' --exclude='logs/' --exclude='data/' \
    "$NETWATCH_DIR/" "$STAGING_DIR/netwatch/"

# 3. Copy systemd service files
log "Copying service files..."
mkdir -p "$STAGING_DIR/systemd"
cp /etc/systemd/system/netwatch-monitor.service "$STAGING_DIR/systemd/" 2>/dev/null || true
cp /etc/systemd/system/netwatch-web.service     "$STAGING_DIR/systemd/" 2>/dev/null || true

# 4. Write backup metadata
cat > "$STAGING_DIR/BACKUP_INFO" << INFO
NetWatch Backup
===============
Created:    $(date -u '+%Y-%m-%d %H:%M:%S UTC')
Hostname:   $(hostname)
Version:    $(cat "$NETWATCH_DIR/VERSION" 2>/dev/null || echo "unknown")
Pi User:    $(whoami)
Home Dir:   $HOME
NetWatch:   $NETWATCH_DIR
INFO

log "Metadata written"

# 5. Create compressed tarball
log "Compressing..."
TAR_FILE="$BACKUP_DIR/${BACKUP_NAME}.tar.gz"
tar -czf "$TAR_FILE" -C "$STAGING_DIR" .
rm -rf "$STAGING_DIR"

TAR_SIZE=$(du -m "$TAR_FILE" | cut -f1)
log "Compressed archive: ${TAR_SIZE}MB"

# 6. Encrypt with GPG public key
log "Encrypting with GPG public key..."
ENCRYPTED_FILE="${TAR_FILE}.gpg"
gpg --batch --yes --trust-model always \
    --homedir /home/mboynton/netwatch/.gnupg \
    --recipient "$GPG_RECIPIENT" \
    --output "$ENCRYPTED_FILE" \
    --encrypt "$TAR_FILE"

# Remove unencrypted archive
rm -f "$TAR_FILE"

FINAL_SIZE=$(du -m "$ENCRYPTED_FILE" | cut -f1)
log "Encrypted backup: ${FINAL_SIZE}MB → $ENCRYPTED_FILE"

# 7. Keep only last N local backups (FULL_BACKUP_RETENTION from config.py, default 7)
KEEP_FULL=$(python3 -c "import sys; sys.path.insert(0,'$NETWATCH_DIR'); import config; print(getattr(config, 'FULL_BACKUP_RETENTION', 7))" 2>/dev/null || echo 7)
ls -t "$BACKUP_DIR"/netwatch_backup_*.tar.gz.gpg 2>/dev/null | tail -n +$((KEEP_FULL + 1)) | xargs rm -f 2>/dev/null || true

# 8. Email if requested
if $DO_EMAIL; then
    if (( FINAL_SIZE > MAX_EMAIL_SIZE_MB )); then
        err "Backup too large to email (${FINAL_SIZE}MB > ${MAX_EMAIL_SIZE_MB}MB limit)"
        send_alert \
            "⚠ NetWatch Backup Too Large to Email" \
            "The NetWatch backup (${FINAL_SIZE}MB) exceeds the email size limit (${MAX_EMAIL_SIZE_MB}MB).

The backup was saved locally to:
  $ENCRYPTED_FILE

Please set up an alternative backup destination (Google Drive, OneDrive, USB).

This alert will repeat on every scheduled backup run until resolved."
        exit 1
    fi
    log "Emailing backup..."
    send_backup_email "$ENCRYPTED_FILE" "$FINAL_SIZE"
    if [[ $? -eq 0 ]]; then
        "$NETWATCH_DIR/venv/bin/python3" "$NETWATCH_DIR/backup_notify.py" OK full "$(basename $ENCRYPTED_FILE)" "$ALERT_EMAIL"
    else
        "$NETWATCH_DIR/venv/bin/python3" "$NETWATCH_DIR/backup_notify.py" FAIL full "$(basename $ENCRYPTED_FILE)" "$ALERT_EMAIL" "Email send failed"
    fi
fi

log "Backup complete: $(basename $ENCRYPTED_FILE)"
