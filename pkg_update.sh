#!/bin/bash
# ==============================================================================
# NetWatch -- pkg_update.sh
# Runs apt-get update and apt-get upgrade -y on the Pi.
# Logs output to pkg_update.log in the NetWatch directory.
# Also writes summary lines to journald via logger (picked up by Promtail/Loki).
# Optionally fires a NetWatch alert on completion listing all changed packages.
#
# Usage:
#   ./pkg_update.sh              -- update only, log result
#   ./pkg_update.sh --alert      -- update and send completion alert
#   ./pkg_update.sh --alert --quiet  -- for cron (suppress terminal output)
#
# Crontab entry (recommended -- pipes all output to journald as well):
#   0 3 * * 0 systemd-cat -t pkg_update /home/mboynton/netwatch/pkg_update.sh --alert --quiet
#
# Sudo requirement:
#   Add to /etc/sudoers.d/netwatch-apt:
#     netwatch-svc ALL=(ALL) NOPASSWD: /usr/bin/apt-get update
#     netwatch-svc ALL=(ALL) NOPASSWD: /usr/bin/apt-get upgrade -y
#     netwatch-svc ALL=(ALL) NOPASSWD: /usr/bin/apt-get upgrade --dry-run
# ==============================================================================

# Derive NETWATCH_DIR from script location -- do not use $HOME (resolves to
# /nonexistent for netwatch-svc which has no home directory).
NETWATCH_DIR="$(cd "$(dirname "$0")" && pwd)"
LOG_FILE="$NETWATCH_DIR/pkg_update.log"
DRY_TMP="$NETWATCH_DIR/pkg_update_dry.tmp"
TIMESTAMP=$(date -u +"%Y-%m-%d %H:%M:%S UTC")

DO_ALERT=false
QUIET=false
for arg in "$@"; do
    case $arg in
        --alert) DO_ALERT=true ;;
        --quiet) QUIET=true ;;
    esac
done

log() {
    echo "$1" >> "$LOG_FILE"
    if [ "$QUIET" = "false" ]; then
        echo "$1"
    fi
}

# -- Start log entry ----------------------------------------------------------
echo "" >> "$LOG_FILE"
log "=== Pi Package Update: $TIMESTAMP ==="
logger -t pkg_update "Pi package update started at $TIMESTAMP"

# -- Run apt-get update -------------------------------------------------------
log "Running apt-get update..."
UPDATE_OUT=$(sudo /usr/bin/apt-get update 2>&1)
UPDATE_RC=$?
if [ $UPDATE_RC -ne 0 ]; then
    log "apt-get update FAILED (exit $UPDATE_RC)"
    log "$UPDATE_OUT"
    logger -t pkg_update "FAILED: apt-get update exited $UPDATE_RC"
    if [ "$DO_ALERT" = "true" ]; then
        "$NETWATCH_DIR/venv/bin/python3" "$NETWATCH_DIR/pkg_update_alert.py" FAILED \
            "Pi package update FAILED during apt-get update. Check pkg_update.log for details."
    fi
    exit 1
fi

# -- Dry run: write raw apt output to temp file; Python helper parses it ------
log "Checking available upgrades..."
sudo /usr/bin/apt-get upgrade --dry-run > "$DRY_TMP" 2>&1
PKG_COUNT=$(grep -c "^Inst " "$DRY_TMP" || true)

if [ "$PKG_COUNT" = "0" ]; then
    log "System already up to date -- no packages to upgrade."
    log "=== Done ==="
    logger -t pkg_update "Complete: system already up to date"
    rm -f "$DRY_TMP"
    if [ "$DO_ALERT" = "true" ]; then
        "$NETWATCH_DIR/venv/bin/python3" "$NETWATCH_DIR/pkg_update_alert.py" OK \
            "Pi package update complete -- system already up to date."
    fi
    exit 0
fi

log "Found $PKG_COUNT package(s) to upgrade."

# -- Run actual upgrade -------------------------------------------------------
log "Running apt-get upgrade -y..."
UPGRADE_OUT=$(sudo /usr/bin/apt-get upgrade -y 2>&1)
UPGRADE_RC=$?

if [ $UPGRADE_RC -ne 0 ]; then
    log "apt-get upgrade FAILED (exit $UPGRADE_RC)"
    log "$UPGRADE_OUT"
    logger -t pkg_update "FAILED: apt-get upgrade exited $UPGRADE_RC"
    rm -f "$DRY_TMP"
    if [ "$DO_ALERT" = "true" ]; then
        "$NETWATCH_DIR/venv/bin/python3" "$NETWATCH_DIR/pkg_update_alert.py" FAILED \
            "Pi package update FAILED during apt-get upgrade. Check pkg_update.log for details."
    fi
    exit 1
fi

# -- Log package list (Python helper parses DRY_TMP and writes to log) --------
SUMMARY="Pi package update complete -- $PKG_COUNT package(s) upgraded."
log "$SUMMARY"
logger -t pkg_update "Complete: $PKG_COUNT package(s) upgraded"
"$NETWATCH_DIR/venv/bin/python3" "$NETWATCH_DIR/pkg_update_alert.py" LOG "$DRY_TMP" >> "$LOG_FILE" 2>&1
log "=== Done ==="

# -- Send alert if requested --------------------------------------------------
if [ "$DO_ALERT" = "true" ]; then
    "$NETWATCH_DIR/venv/bin/python3" "$NETWATCH_DIR/pkg_update_alert.py" OK "$SUMMARY" "$DRY_TMP"
fi

rm -f "$DRY_TMP"
exit 0
