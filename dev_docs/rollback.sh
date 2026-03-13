#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
# NetWatch Emergency Rollback Script
# Restores the most recent pre-install snapshot (taken automatically before
# each package install). Includes all Python files, templates, static files,
# and the database.
#
# Usage:  bash ~/netwatch/rollback.sh
#
# Run this any time NetWatch is down after an update. It will restore the
# exact state from before the last package was installed.
# ══════════════════════════════════════════════════════════════════════════════

NETWATCH_DIR="$HOME/netwatch"
SNAP_BASE="$NETWATCH_DIR/snapshots"

echo ""
echo "══════════════════════════════════════════"
echo "  NetWatch Emergency Rollback"
echo "══════════════════════════════════════════"
echo ""

# ── Find available snapshots ──────────────────────────────────────────────────
if [ ! -d "$SNAP_BASE" ] || [ -z "$(ls -A "$SNAP_BASE" 2>/dev/null)" ]; then
    echo "  No snapshots found in $SNAP_BASE"
    echo ""
    echo "  Snapshots are created automatically when packages are installed"
    echo "  via the NetWatch package installer (Admin → File Updates)."
    echo ""
    echo "  If this is the first install or snapshots were deleted,"
    echo "  you will need to restore from a full system backup."
    echo ""
    exit 1
fi

# Build ordered list of snapshots (newest first)
mapfile -t SNAP_DIRS < <(ls -1d "$SNAP_BASE"/*/ 2>/dev/null | sort -r | sed 's|/$||')

if [ ${#SNAP_DIRS[@]} -eq 0 ]; then
    echo "  ERROR: Could not find snapshot directories."
    exit 1
fi

# ── List snapshots and prompt for selection ───────────────────────────────────
echo "  Available snapshots (newest first):"
echo ""
for i in "${!SNAP_DIRS[@]}"; do
    d="${SNAP_DIRS[$i]}"
    dname=$(basename "$d")
    if [ -f "$d/snapshot_meta.json" ]; then
        ver=$(python3 -c "import json; d=json.load(open('$d/snapshot_meta.json')); print(d.get('version_before','unknown'))" 2>/dev/null)
    else
        ver="unknown"
    fi
    label=""
    [ $i -eq 0 ] && label=" (most recent)"
    printf "  [%d] %s  →  v%s%s\n" "$((i+1))" "$dname" "$ver" "$label"
done
echo ""
read -p "  Select snapshot to restore [1-${#SNAP_DIRS[@]}] (default: 1): " SELECTION
echo ""

# Default to most recent if no input
SELECTION="${SELECTION:-1}"

# Validate input
if ! [[ "$SELECTION" =~ ^[0-9]+$ ]] || [ "$SELECTION" -lt 1 ] || [ "$SELECTION" -gt ${#SNAP_DIRS[@]} ]; then
    echo "  Invalid selection. Rollback cancelled."
    echo ""
    exit 1
fi

SNAP_DIR="${SNAP_DIRS[$((SELECTION-1))]}"
SNAP_NAME=$(basename "$SNAP_DIR")

# Read metadata
if [ -f "$SNAP_DIR/snapshot_meta.json" ]; then
    META_VERSION=$(python3 -c "import json; d=json.load(open('$SNAP_DIR/snapshot_meta.json')); print(d.get('version_before','unknown'))" 2>/dev/null)
    META_FILES=$(python3 -c "import json; d=json.load(open('$SNAP_DIR/snapshot_meta.json')); print(d.get('files_copied',0))" 2>/dev/null)
else
    META_VERSION="unknown"
    META_FILES="?"
fi

echo "  Snapshot: $SNAP_NAME"
echo "  Restoring to version: $META_VERSION"
echo "  Files in snapshot: $META_FILES"
echo ""
read -p "  Proceed with rollback? (y/N) " CONFIRM
echo ""

if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
    echo "  Rollback cancelled."
    echo ""
    exit 0
fi

RESTORED=0
FAILED=0

# ── Stop services before restoring ───────────────────────────────────────────
echo "Stopping services..."
sudo systemctl stop netwatch-web.service 2>/dev/null && echo "  ✓ netwatch-web stopped" || echo "  ! netwatch-web was not running"
if systemctl is-enabled netwatch-monitor.service &>/dev/null; then
    sudo systemctl stop netwatch-monitor.service 2>/dev/null && echo "  ✓ netwatch-monitor stopped"
fi
echo ""

# ── Restore Python and config files (root of netwatch dir) ───────────────────
echo "Restoring files..."
for f in "$SNAP_DIR"/*.py "$SNAP_DIR"/*.sh "$SNAP_DIR"/*.json "$SNAP_DIR"/*.txt "$SNAP_DIR"/*.md; do
    [ -f "$f" ] || continue
    fname=$(basename "$f")
    # Skip snapshot metadata itself
    [ "$fname" = "snapshot_meta.json" ] && continue
    if cp "$f" "$NETWATCH_DIR/$fname" 2>/dev/null; then
        echo "  ✓ $fname"
        RESTORED=$((RESTORED + 1))
    else
        echo "  ✗ FAILED: $fname"
        FAILED=$((FAILED + 1))
    fi
done

# ── Restore templates ─────────────────────────────────────────────────────────
if [ -d "$SNAP_DIR/templates" ]; then
    for f in "$SNAP_DIR/templates"/*.html; do
        [ -f "$f" ] || continue
        fname=$(basename "$f")
        if cp "$f" "$NETWATCH_DIR/templates/$fname" 2>/dev/null; then
            echo "  ✓ templates/$fname"
            RESTORED=$((RESTORED + 1))
        else
            echo "  ✗ FAILED: templates/$fname"
            FAILED=$((FAILED + 1))
        fi
    done
fi

# ── Restore static files ──────────────────────────────────────────────────────
if [ -d "$SNAP_DIR/static" ]; then
    for f in "$SNAP_DIR/static"/*.css "$SNAP_DIR/static"/*.js; do
        [ -f "$f" ] || continue
        fname=$(basename "$f")
        if cp "$f" "$NETWATCH_DIR/static/$fname" 2>/dev/null; then
            echo "  ✓ static/$fname"
            RESTORED=$((RESTORED + 1))
        else
            echo "  ✗ FAILED: static/$fname"
            FAILED=$((FAILED + 1))
        fi
    done
fi

# ── Restore VERSION ───────────────────────────────────────────────────────────
if [ -f "$SNAP_DIR/VERSION" ]; then
    cp "$SNAP_DIR/VERSION" "$NETWATCH_DIR/VERSION"
    echo "  ✓ VERSION → $META_VERSION"
fi

# ── Restore database ──────────────────────────────────────────────────────────
echo ""
if [ -f "$SNAP_DIR/netwatch.db" ]; then
    DB_DEST="$NETWATCH_DIR/netwatch.db"
    DB_SNAP="$SNAP_DIR/netwatch.db"

    # Keep a safety copy of the current DB just in case
    cp "$DB_DEST" "$DB_DEST.rollback_safety" 2>/dev/null

    # Write restore script to a temp file — avoids heredoc quoting issues
    TMPPY=$(mktemp /tmp/nw_restore_XXXXXX.py)
    printf 'import sqlite3, sys\n' > "$TMPPY"
    printf 'try:\n' >> "$TMPPY"
    printf '    src  = sqlite3.connect(sys.argv[1])\n' >> "$TMPPY"
    printf '    dest = sqlite3.connect(sys.argv[2])\n' >> "$TMPPY"
    printf '    src.backup(dest)\n' >> "$TMPPY"
    printf '    dest.close()\n' >> "$TMPPY"
    printf '    src.close()\n' >> "$TMPPY"
    printf '    print("  \u2713 Database restored from snapshot")\n' >> "$TMPPY"
    printf '    sys.exit(0)\n' >> "$TMPPY"
    printf 'except Exception as e:\n' >> "$TMPPY"
    printf '    print(f"  \u2717 Database restore FAILED: {e}")\n' >> "$TMPPY"
    printf '    sys.exit(1)\n' >> "$TMPPY"

    if python3 "$TMPPY" "$DB_SNAP" "$DB_DEST"; then
        RESTORED=$((RESTORED + 1))
    else
        FAILED=$((FAILED + 1))
        echo "    (Current DB preserved at netwatch.db.rollback_safety)"
    fi
    rm -f "$TMPPY"
else
    echo "  ! No database snapshot found — database not restored"
    echo "    (DB schema changes from the failed update may still be present)"
fi

# ── Restart services ──────────────────────────────────────────────────────────
echo ""
echo "Starting services..."
if sudo systemctl start netwatch-web.service 2>/dev/null; then
    echo "  ✓ netwatch-web started"
else
    echo "  ✗ netwatch-web failed to start"
    FAILED=$((FAILED + 1))
fi

if systemctl is-enabled netwatch-monitor.service &>/dev/null; then
    if sudo systemctl start netwatch-monitor.service 2>/dev/null; then
        echo "  ✓ netwatch-monitor started"
    fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════"
if [ $FAILED -eq 0 ]; then
    echo "  ✓ Rollback complete"
    echo "  Restored: $RESTORED files + database"
    echo "  Version:  $META_VERSION"
else
    echo "  ⚠ Rollback finished with $FAILED failure(s)"
    echo "  Restored: $RESTORED files"
fi
echo "══════════════════════════════════════════"
echo ""
echo "  Dashboard: https://192.168.100.10:5000"
echo ""
echo "  Check status:  sudo systemctl status netwatch-web.service"
echo "  Check logs:    sudo journalctl -u netwatch-web.service -n 30 --no-pager"
echo ""
