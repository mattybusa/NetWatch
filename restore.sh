#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
# NetWatch — restore.sh
# Restores a NetWatch backup from an encrypted .tar.gz.gpg file.
# Run this on a Pi that already has the OS and Python venv set up.
#
# Usage:
#   bash restore.sh /path/to/netwatch_backup_20260301_120000.tar.gz.gpg
#
# Requirements:
#   - GPG private key must be available (import with: gpg --import private.asc)
#   - NetWatch venv must exist at ~/netwatch/venv (run install.sh first if not)
# ══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

NETWATCH_DIR="$HOME/netwatch"
BACKUP_DIR="$HOME/backups"

# ── Helpers ───────────────────────────────────────────────────────────────────
log()  { echo "[$(date '+%H:%M:%S')] $*"; }
err()  { echo "[ERROR] $*" >&2; exit 1; }
warn() { echo "[WARN]  $*" >&2; }

# ── Argument check ────────────────────────────────────────────────────────────
if [[ $# -lt 1 ]]; then
    echo "Usage: bash restore.sh <backup_file.tar.gz.gpg>"
    echo "       bash restore.sh <backup_file.tar.gz>    (already decrypted)"
    exit 1
fi

BACKUP_FILE="$1"
[[ -f "$BACKUP_FILE" ]] || err "Backup file not found: $BACKUP_FILE"

# ── Confirm ───────────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║           NetWatch — System Restore                  ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
echo "  Backup file : $BACKUP_FILE"
echo "  Restore to  : $NETWATCH_DIR"
echo ""
echo "  ⚠  This will REPLACE the current NetWatch installation."
echo "     The existing installation will be backed up first."
echo ""
read -rp "  Type 'restore' to confirm: " CONFIRM
[[ "$CONFIRM" == "restore" ]] || { echo "Cancelled."; exit 0; }
echo ""

# ── Stop services ─────────────────────────────────────────────────────────────
log "Stopping NetWatch services..."
sudo systemctl stop netwatch-web.service    2>/dev/null || true
sudo systemctl stop netwatch-monitor.service 2>/dev/null || true

# ── Decrypt if needed ─────────────────────────────────────────────────────────
STAGING_DIR=$(mktemp -d)
TAR_FILE=""

if [[ "$BACKUP_FILE" == *.gpg ]]; then
    log "Decrypting backup (you may be prompted for your GPG key passphrase)..."
    TAR_FILE="$STAGING_DIR/backup.tar.gz"
    gpg --batch --yes --output "$TAR_FILE" --decrypt "$BACKUP_FILE"
    log "Decryption complete"
else
    TAR_FILE="$BACKUP_FILE"
    log "Using unencrypted archive directly"
fi

# ── Preview backup contents ───────────────────────────────────────────────────
log "Backup info:"
tar -xzf "$TAR_FILE" -C "$STAGING_DIR" ./BACKUP_INFO 2>/dev/null && cat "$STAGING_DIR/BACKUP_INFO" || true
echo ""

# ── Back up current installation ─────────────────────────────────────────────
if [[ -d "$NETWATCH_DIR" ]]; then
    PRE_BACKUP="$BACKUP_DIR/pre_restore_$(date -u '+%Y%m%d_%H%M%S').tar.gz"
    mkdir -p "$BACKUP_DIR"
    log "Backing up current installation to $PRE_BACKUP..."
    tar -czf "$PRE_BACKUP" --exclude='*.pyc' --exclude='__pycache__' \
        --exclude='venv/' -C "$HOME" netwatch/ 2>/dev/null || true
fi

# ── Extract backup ────────────────────────────────────────────────────────────
log "Extracting backup..."
EXTRACT_DIR=$(mktemp -d)
tar -xzf "$TAR_FILE" -C "$EXTRACT_DIR"

# ── Restore database ──────────────────────────────────────────────────────────
if [[ -f "$EXTRACT_DIR/netwatch.db" ]]; then
    log "Restoring database..."
    python3 - << PYEOF
import sqlite3
src = sqlite3.connect("$EXTRACT_DIR/netwatch.db")
dst = sqlite3.connect("$NETWATCH_DIR/netwatch.db")
src.backup(dst)
src.close()
dst.close()
print("  Database restored")
PYEOF
fi

# ── Restore application files ─────────────────────────────────────────────────
if [[ -d "$EXTRACT_DIR/netwatch" ]]; then
    log "Restoring application files..."
    rsync -a --exclude='venv/' --exclude='*.pyc' --exclude='__pycache__' \
        --exclude='netwatch.db' --exclude='logs/' \
        "$EXTRACT_DIR/netwatch/" "$NETWATCH_DIR/"
    log "  Application files restored"
fi

# ── Restore systemd services ──────────────────────────────────────────────────
if [[ -d "$EXTRACT_DIR/systemd" ]]; then
    log "Restoring systemd service files..."
    sudo cp "$EXTRACT_DIR/systemd/"*.service /etc/systemd/system/ 2>/dev/null || true
    sudo systemctl daemon-reload
    log "  Service files restored"
fi

# ── Set permissions ───────────────────────────────────────────────────────────
log "Setting permissions..."
chmod 600 "$NETWATCH_DIR/config.py" 2>/dev/null || true
chmod +x "$NETWATCH_DIR/backup.sh" "$NETWATCH_DIR/restore.sh" 2>/dev/null || true

# ── Clean up ──────────────────────────────────────────────────────────────────
rm -rf "$STAGING_DIR" "$EXTRACT_DIR"

# ── Restart services ──────────────────────────────────────────────────────────
log "Starting NetWatch services..."
sudo systemctl start netwatch-monitor.service
sudo systemctl start netwatch-web.service
sleep 3

# Check services came up
MONITOR_OK=$(systemctl is-active netwatch-monitor.service 2>/dev/null || echo "failed")
WEB_OK=$(systemctl is-active netwatch-web.service 2>/dev/null || echo "failed")

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║              Restore Complete                        ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
echo "  Monitor service : $MONITOR_OK"
echo "  Web service     : $WEB_OK"
echo ""
if [[ "$MONITOR_OK" == "active" && "$WEB_OK" == "active" ]]; then
    echo "  ✓ NetWatch is running"
    echo "  → https://$(hostname -I | awk '{print $1}'):5000"
else
    echo "  ✗ One or more services failed to start"
    echo "    Check logs: sudo journalctl -fu netwatch-web"
fi
echo ""
[[ -f "$PRE_BACKUP" ]] && echo "  Pre-restore backup saved to: $PRE_BACKUP"
echo ""
