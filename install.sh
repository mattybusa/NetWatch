#!/bin/bash
# ==========================
# NetWatch = install.sh
# Fresh Pi installation script.
# Installs all dependencies, sets up the environment, and optionally
# restores from a backup file.
#
# Usage:
#   bash install.sh                          = fresh blank install
#   bash install.sh netwatch_backup.tar.gz.gpg  = install + restore from backup
#
# Run as your normal Pi user (not root). Script will use sudo where needed.
# ==========================

set -euo pipefail

NETWATCH_DIR="$HOME/netwatch"
BACKUP_FILE="${1:-}"

# = Helpers ======================
log()     { echo "[$(date '+%H:%M:%S')] $*"; }
err()     { echo "[ERROR] $*" >&2; exit 1; }
section() { echo ""; echo "= $* =============="; }

# = Banner ======================
echo ""
echo "=================="
echo "=           NetWatch = Installation                    ="
echo "=================="
echo ""
if [[ -n "$BACKUP_FILE" ]]; then
    echo "  Mode    : Restore from backup"
    echo "  Backup  : $BACKUP_FILE"
else
    echo "  Mode    : Fresh installation"
fi
echo "  Install : $NETWATCH_DIR"
echo "  User    : $(whoami)"
echo ""
read -rp "  Press Enter to continue or Ctrl+C to cancel..." _

# = System packages ===================
section "Installing system packages"
sudo apt-get update -qq
sudo apt-get install -y \
    python3 python3-pip python3-venv \
    sqlite3 gpg rsync curl \
    libgpiod2 python3-lgpio \
    speedtest-cli 2>/dev/null || \
sudo apt-get install -y speedtest-cli || \
    log "speedtest-cli not available = install manually if needed"

log "System packages installed"

# = Service account ===================
section "Creating netwatch-svc service account"
SVC_USER="netwatch-svc"
if id "$SVC_USER" &>/dev/null; then
    log "Service account $SVC_USER already exists -- skipping"
else
    sudo useradd --system --shell /usr/sbin/nologin --home-dir /nonexistent --no-create-home "$SVC_USER"
    log "Service account $SVC_USER created"
fi

# Add the installing user to the netwatch-svc group for shell access to scripts
INSTALL_USER=$(whoami)
sudo usermod -aG "$SVC_USER" "$INSTALL_USER"
log "Added $INSTALL_USER to $SVC_USER group"

# = Sudoers ======================
section "Configuring sudoers for netwatch-svc"
sudo tee /etc/sudoers.d/netwatch-svc > /dev/null << 'SUDOEOF'
# NetWatch service account -- minimum required privileges only
# Both .service suffix and suffix-less forms required -- patcher.py calls
# "systemctl restart netwatch-web" (no suffix); sudoers does exact string matching.
netwatch-svc ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart netwatch-web.service
netwatch-svc ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart netwatch-monitor.service
netwatch-svc ALL=(ALL) NOPASSWD: /usr/bin/systemctl stop netwatch-web.service
netwatch-svc ALL=(ALL) NOPASSWD: /usr/bin/systemctl stop netwatch-monitor.service
netwatch-svc ALL=(ALL) NOPASSWD: /usr/bin/systemctl start netwatch-web.service
netwatch-svc ALL=(ALL) NOPASSWD: /usr/bin/systemctl start netwatch-monitor.service
netwatch-svc ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart netwatch-web
netwatch-svc ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart netwatch-monitor
netwatch-svc ALL=(ALL) NOPASSWD: /usr/bin/systemctl stop netwatch-web
netwatch-svc ALL=(ALL) NOPASSWD: /usr/bin/systemctl stop netwatch-monitor
netwatch-svc ALL=(ALL) NOPASSWD: /usr/bin/systemctl start netwatch-web
netwatch-svc ALL=(ALL) NOPASSWD: /usr/bin/systemctl start netwatch-monitor
netwatch-svc ALL=(ALL) NOPASSWD: /usr/bin/apt-get update
netwatch-svc ALL=(ALL) NOPASSWD: /usr/bin/apt-get upgrade -y
netwatch-svc ALL=(ALL) NOPASSWD: /usr/bin/apt-get upgrade --dry-run
SUDOEOF
sudo chmod 440 /etc/sudoers.d/netwatch-svc
log "Sudoers written to /etc/sudoers.d/netwatch-svc"

# netwatch-svc needs execute permission on the parent home directory to traverse
# into WorkingDirectory=/home/<user>/netwatch. Default 700 blocks it.
sudo chmod 751 "$HOME"
log "Home directory set to 751 for service account traversal"

# = NetWatch directory ==================
section "Setting up directories"
mkdir -p "$NETWATCH_DIR"/{logs,data,certs,static,templates,scripts}
mkdir -p "$HOME/backups"
# Backup scripts run as netwatch-svc -- give it write access to the backup dir
sudo chown "$SVC_USER:$SVC_USER" "$HOME/backups"
log "Directories created"

# = Python virtual environment ================
section "Creating Python virtual environment"
if [[ ! -d "$NETWATCH_DIR/venv" ]]; then
    python3 -m venv "$NETWATCH_DIR/venv"
    log "Virtual environment created"
else
    log "Virtual environment already exists = skipping"
fi

"$NETWATCH_DIR/venv/bin/pip" install --upgrade pip -q
"$NETWATCH_DIR/venv/bin/pip" install \
    flask flask-session bcrypt \
    speedtest-cli RPi.GPIO lgpio \
    requests cryptography gunicorn \
    structlog packaging \
    pyotp qrcode -q

log "Python packages installed"

# = If restoring from backup ================
if [[ -n "$BACKUP_FILE" ]]; then
    section "Restoring from backup"
    [[ -f "$BACKUP_FILE" ]] || err "Backup file not found: $BACKUP_FILE"

    # Check for GPG private key
    if ! gpg --list-secret-keys 2>/dev/null | grep -q 'sec'; then
        echo ""
        echo "  =  No GPG private key found."
        echo "     To restore an encrypted backup you need to import your private key:"
        echo ""
        echo "     gpg --import netwatch-backup-private.asc"
        echo ""
        read -rp "  Press Enter after importing your key, or Ctrl+C to cancel..." _
    fi

    # Copy restore.sh if not already there
    if [[ ! -f "$NETWATCH_DIR/restore.sh" ]]; then
        # Extract restore.sh from backup first
        TMPDIR_EXTRACT=$(mktemp -d)
        if [[ "$BACKUP_FILE" == *.gpg ]]; then
            gpg --batch --yes --output "$TMPDIR_EXTRACT/backup.tar.gz" --decrypt "$BACKUP_FILE"
            tar -xzf "$TMPDIR_EXTRACT/backup.tar.gz" -C "$TMPDIR_EXTRACT" ./netwatch/restore.sh 2>/dev/null || true
        else
            tar -xzf "$BACKUP_FILE" -C "$TMPDIR_EXTRACT" ./netwatch/restore.sh 2>/dev/null || true
        fi
        cp "$TMPDIR_EXTRACT/netwatch/restore.sh" "$NETWATCH_DIR/" 2>/dev/null || true
        rm -rf "$TMPDIR_EXTRACT"
    fi

    bash "$NETWATCH_DIR/restore.sh" "$BACKUP_FILE"
    exit 0
fi

# = Fresh install = copy files ================
section "Copying NetWatch files"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Copy all files from the directory containing this install.sh
rsync -a --exclude='venv/' --exclude='*.pyc' --exclude='__pycache__' \
    --exclude='install.sh' \
    "$SCRIPT_DIR/" "$NETWATCH_DIR/"

chmod +x "$NETWATCH_DIR/backup.sh" "$NETWATCH_DIR/restore.sh" 2>/dev/null || true
chmod 600 "$NETWATCH_DIR/config.py" 2>/dev/null || true
# Transfer ownership to service account; installing user retains access via group
sudo chown -R "$SVC_USER:$SVC_USER" "$NETWATCH_DIR"
sudo chmod -R 750 "$NETWATCH_DIR"
log "Files copied and ownership transferred to $SVC_USER"

# = Systemd services ===================
section "Installing systemd services"

PYTHON_PATH="$NETWATCH_DIR/venv/bin/python3"
USER="$SVC_USER"

sudo tee /etc/systemd/system/netwatch-monitor.service > /dev/null << SVCEOF
[Unit]
Description=NetWatch Network Monitor Daemon
After=network.target
Wants=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$NETWATCH_DIR
ExecStart=$PYTHON_PATH $NETWATCH_DIR/main.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SVCEOF

sudo tee /etc/systemd/system/netwatch-web.service > /dev/null << SVCEOF
[Unit]
Description=NetWatch Web Dashboard
After=network.target netwatch-monitor.service

[Service]
Type=simple
User=$USER
WorkingDirectory=$NETWATCH_DIR
ExecStart=$NETWATCH_DIR/venv/bin/gunicorn --config $NETWATCH_DIR/gunicorn.conf.py wsgi:app
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SVCEOF

sudo systemctl daemon-reload
sudo systemctl enable netwatch-monitor.service netwatch-web.service
log "Services installed and enabled"

# = Initialize database ==================
section "Initializing database"
"$NETWATCH_DIR/venv/bin/python3" -c "
import sys; sys.path.insert(0, '$NETWATCH_DIR')
import database; database.init_db()
print('  Database initialized')
"

# = Import GPG public key =================
section "Setting up GPG encryption"
if [[ -f "$SCRIPT_DIR/netwatch-backup-public.asc" ]]; then
    gpg --import "$SCRIPT_DIR/netwatch-backup-public.asc" 2>/dev/null || true
    # Trust the key
    KEY_ID=$(gpg --list-keys --with-colons 2>/dev/null | grep '^pub' | head -1 | cut -d: -f5)
    echo "$KEY_ID:6:" | gpg --import-ownertrust 2>/dev/null || true
    log "GPG public key imported and trusted"
else
    log "No GPG public key found = backup encryption not configured"
    log "Copy netwatch-backup-public.asc to $SCRIPT_DIR and run: gpg --import netwatch-backup-public.asc"
fi

# = Start services ====================
section "Starting services"
sudo systemctl start netwatch-monitor.service
sudo systemctl start netwatch-web.service
sleep 3

MONITOR_OK=$(systemctl is-active netwatch-monitor.service 2>/dev/null || echo "failed")
WEB_OK=$(systemctl is-active netwatch-web.service 2>/dev/null || echo "failed")

# = Done =======================
echo ""
echo "=================="
echo "=           Installation Complete                      ="
echo "=================="
echo ""
echo "  Monitor service : $MONITOR_OK"
echo "  Web service     : $WEB_OK"
echo ""
if [[ "$MONITOR_OK" == "active" && "$WEB_OK" == "active" ]]; then
    echo "  = NetWatch is running"
    echo "  = https://$(hostname -I | awk '{print $1}'):5000"
    echo ""
    echo "  Next steps:"
    echo "  1. Visit the dashboard and complete setup"
    echo "  2. Edit ~/netwatch/config.py with your settings"
    echo "  3. Generate SSL certificates from the Admin page"
else
    echo "  = One or more services failed to start"
    echo "    Check: sudo journalctl -fu netwatch-web"
fi
echo ""
