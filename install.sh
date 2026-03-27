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
trap 'echo "[ERROR] Installation failed at line $LINENO. Command: $BASH_COMMAND" >&2' ERR

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

# Resolve version-unstable package names dynamically from the Debian archive API.
# The source package name (e.g. "libgpiod") is stable across renames; the binary
# package name (e.g. libgpiod2 → libgpiod3) changes between Debian releases.
# We ask Debian what the current binary is for "stable" at install time rather
# than hardcoding a name that may be wrong on future OS releases.
resolve_debian_package() {
    local source="$1"      # Debian source package name
    local pattern="$2"     # grep -E pattern to identify the right binary
    local fallback="$3"    # use this name if API is unreachable

    local api_url="https://api.ftp-master.debian.org/madison?package=${source}&f=json&S=true"
    local result

    result=$(curl -sf --max-time 10 "$api_url" 2>/dev/null | \
        python3 -c "
import sys, json, re
try:
    data = json.load(sys.stdin)
    pattern = sys.argv[1]
    for pkg_name, suites in data[0].items():
        if re.match(pattern, pkg_name) and 'stable' in suites:
            print(pkg_name)
            sys.exit(0)
    sys.exit(1)
except Exception:
    sys.exit(1)
" "$pattern" 2>/dev/null) || true

    if [[ -n "$result" ]]; then
        log "Resolved $source → $result" >&2
        echo "$result"
    else
        log "Warning: could not resolve $source from Debian API, using fallback: $fallback" >&2
        echo "$fallback"
    fi
}

LIBGPIOD_PKG=$(resolve_debian_package "libgpiod" "^libgpiod[0-9]+$" "libgpiod3")

sudo apt-get update -qq
sudo apt-get install -y \
    python3 python3-pip python3-venv python3-dev \
    sqlite3 gpg rsync curl \
    "$LIBGPIOD_PKG" python3-lgpio liblgpio-dev swig

sudo apt-get install -y speedtest-cli || \
    log "speedtest-cli not available -- install manually if needed"

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

# Add netwatch-svc to gpio group for GPIO hardware access
if getent group gpio &>/dev/null; then
    sudo usermod -aG gpio "$SVC_USER"
    log "Added $SVC_USER to gpio group"
else
    log "Warning: gpio group not found -- GPIO access may fail"
fi

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
# Use sudo for mkdir in case a previous install left the directory owned by netwatch-svc
sudo mkdir -p "$NETWATCH_DIR"/{logs,data,certs,static,templates,scripts}
sudo mkdir -p "$HOME/backups"
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
MANIFEST_URL="https://raw.githubusercontent.com/mattybusa/NetWatch/main/releases/latest.json"

# Detect whether we are running standalone (curl install) or from an extracted
# release zip. If database.py exists alongside install.sh, use it directly.
# Otherwise download the release zip from GitHub and extract from that.
if [[ -f "$SCRIPT_DIR/database.py" ]]; then
    log "Codebase found alongside install.sh -- using local files"
    SOURCE_DIR="$SCRIPT_DIR"
    TEMP_DIR=""
else
    log "Running standalone -- downloading NetWatch codebase from GitHub..."
    TEMP_DIR=$(mktemp -d)
    trap 'rm -rf "$TEMP_DIR"' EXIT

    PACKAGE_URL=$(curl -sf --max-time 10 "$MANIFEST_URL" | \
        python3 -c "import sys,json; d=json.load(sys.stdin); print(d['package_url'])" 2>/dev/null) || true

    if [[ -z "$PACKAGE_URL" ]]; then
        err "Could not retrieve release manifest from GitHub. Check your internet connection and try again."
    fi

    log "Downloading release zip..."
    curl -fL --max-time 120 -o "$TEMP_DIR/netwatch.zip" "$PACKAGE_URL" || \
        err "Failed to download NetWatch release zip from $PACKAGE_URL"

    log "Extracting release..."
    unzip -q "$TEMP_DIR/netwatch.zip" -d "$TEMP_DIR/extracted" || \
        err "Failed to extract release zip"

    SOURCE_DIR="$TEMP_DIR/extracted"
    log "Codebase downloaded and extracted successfully"
fi

# Copy all NetWatch files into place
rsync -a --exclude='venv/' --exclude='*.pyc' --exclude='__pycache__' \
    --exclude='install.sh' --exclude='dev_docs/' \
    --exclude='build_release.sh' \
    "$SOURCE_DIR/" "$NETWATCH_DIR/"

chmod +x "$NETWATCH_DIR/backup.sh" "$NETWATCH_DIR/restore.sh" 2>/dev/null || true
# Transfer ownership to service account; installing user retains access via group
sudo chown -R "$SVC_USER:$SVC_USER" "$NETWATCH_DIR"
sudo chmod -R 750 "$NETWATCH_DIR"
log "Files copied and ownership transferred to $SVC_USER"

# = Bootstrap config.py ==================
section "Creating bootstrap configuration"
if [[ -f "$NETWATCH_DIR/config.py" ]]; then
    log "config.py already exists -- skipping (existing install or restore)"
else
    sudo -u "$SVC_USER" tee "$NETWATCH_DIR/config.py" > /dev/null << CFGEOF
# NetWatch configuration
# Generated by install.sh -- edit via the Config Editor in the Admin page
# or directly in this file. Restart both services after manual edits.

SITE_NAME = "NetWatch"
OWNER_USERNAME = "admin"
SECRET_KEY = "CHANGE_THIS_TO_A_RANDOM_SECRET_KEY"

ALERTS_ENABLED = False
GMAIL_USER = "your_email@gmail.com"
GMAIL_APP_PASSWORD = "your_app_password_here"
ALERT_TO = "your_email@gmail.com"

LAN_GATEWAY = "192.168.1.1"
WAN_PRIMARY = "8.8.8.8"
WAN_SECONDARY = "8.8.4.4"
DNS_TEST_HOST = "google.com"
WIFI_GATEWAY = ""
LAN_INTERFACE = ""
WIFI_INTERFACE = ""

RELAY_MODEM = 17
RELAY_ROUTER = 27
BUTTON_PIN = 22
RELAY_ACTIVE_LOW = False

CHECK_INTERVAL = 30
CONFIRM_WINDOW = 180
RESET_COOLDOWN = 1800
MODEM_BOOT_DELAY = 60
ROUTER_BOOT_DELAY = 30
POWER_CYCLE_OFF_TIME = 5
MAX_RESETS_PER_DAY = 5
SPEEDTEST_INTERVAL = 7200

LATENCY_WARN_MS = 150
PACKET_LOSS_WARN = 10
DEGRADED_ALERT_TIME = 900

SNAPSHOT_RETENTION = 10
KEEP_HEALTH_DAYS = 30
KEEP_RESET_DAYS = 90
KEEP_SPEEDTEST_DAYS = 90
DB_BACKUP_RETENTION = 14
FULL_BACKUP_RETENTION = 7

LOCKOUT_FAIL_THRESHOLD = 5
LOCKOUT_DURATION_MINUTES = 30
LOCKOUT_MAX_COUNT = 3
LOCKOUT_WINDOW_HOURS = 24
FORCED_CHANGE_TIMEOUT_MINUTES = 10
MFA_ISSUER = "NetWatch"

LOG_FORMAT = "pretty"
DASHBOARD_HOST = "0.0.0.0"
DASHBOARD_PORT = 5000
CFGEOF
    sudo chmod 600 "$NETWATCH_DIR/config.py"
    log "Bootstrap config.py created (SECRET_KEY auto-generated)"
fi

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
sudo -u "$SVC_USER" "$NETWATCH_DIR/venv/bin/python3" -c "
import sys; sys.path.insert(0, '$NETWATCH_DIR')
import database; database.init_db()
print('  Database initialized')
"

# = Generate TLS certificates ==================
section "Generating TLS certificates"
CERTS_DIR="$NETWATCH_DIR/certs"
CA_DIR="$CERTS_DIR/ca"
PI_IP=$(hostname -I | awk '{print $1}')
HOSTNAME_VAL=$(hostname)

if [[ -f "$CERTS_DIR/netwatch.crt" && -f "$CERTS_DIR/netwatch.key" ]]; then
    log "Certificates already exist -- skipping"
else
    # Clean up any partial cert state from a previous failed run
    sudo -u "$SVC_USER" rm -f "$CERTS_DIR/netwatch.csr" "$CERTS_DIR/netwatch.crt" "$CERTS_DIR/netwatch.key" "$CERTS_DIR/netwatch-ca.crt" 2>/dev/null || true
    sudo rm -rf "$CA_DIR" 2>/dev/null || true
    sudo -u "$SVC_USER" bash -c "mkdir -p '$CA_DIR' && chmod 700 '$CA_DIR' && chmod 700 '$CERTS_DIR'"

    # Generate root CA
    sudo -u "$SVC_USER" openssl genrsa -out "$CA_DIR/netwatch-ca.key" 4096 2>/dev/null
    sudo -u "$SVC_USER" chmod 600 "$CA_DIR/netwatch-ca.key"
    sudo -u "$SVC_USER" openssl req -new -x509 -key "$CA_DIR/netwatch-ca.key" -out "$CA_DIR/netwatch-ca.crt" -days 7300 -subj "/C=US/ST=Home/L=HomeNetwork/O=NetWatch Home CA/CN=NetWatch Root CA" 2>/dev/null
    sudo -u "$SVC_USER" chmod 644 "$CA_DIR/netwatch-ca.crt"
    sudo -u "$SVC_USER" cp "$CA_DIR/netwatch-ca.crt" "$CERTS_DIR/netwatch-ca.crt"

    # Generate server key and CSR
    sudo -u "$SVC_USER" openssl genrsa -out "$CERTS_DIR/netwatch.key" 2048 2>/dev/null
    sudo -u "$SVC_USER" chmod 600 "$CERTS_DIR/netwatch.key"
    sudo -u "$SVC_USER" openssl req -new -key "$CERTS_DIR/netwatch.key" -out "$CERTS_DIR/netwatch.csr" -subj "/C=US/ST=Home/L=HomeNetwork/O=NetWatch/CN=netwatch.home" 2>/dev/null

    # Build SAN extension file (no heredoc -- use printf)
    EXT_FILE=$(mktemp)
    printf "authorityKeyIdentifier=keyid,issuer\n" > "$EXT_FILE"
    printf "basicConstraints=CA:FALSE\n" >> "$EXT_FILE"
    printf "keyUsage=digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment\n" >> "$EXT_FILE"
    printf "extendedKeyUsage=serverAuth\n" >> "$EXT_FILE"
    printf "subjectAltName=@alt_names\n\n" >> "$EXT_FILE"
    printf "[alt_names]\n" >> "$EXT_FILE"
    printf "DNS.1 = netwatch\n" >> "$EXT_FILE"
    printf "DNS.2 = netwatch.home\n" >> "$EXT_FILE"
    printf "DNS.3 = netwatch.local\n" >> "$EXT_FILE"
    printf "DNS.4 = %s\n" "$HOSTNAME_VAL" >> "$EXT_FILE"
    printf "DNS.5 = %s.local\n" "$HOSTNAME_VAL" >> "$EXT_FILE"
    printf "IP.1  = %s\n" "$PI_IP" >> "$EXT_FILE"
    printf "IP.2  = 127.0.0.1\n" >> "$EXT_FILE"
    chmod 644 "$EXT_FILE"

    # Add wlan0 IP if present and different
    WLAN_IP=$(ip addr show wlan0 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1 || true)
    if [[ -n "$WLAN_IP" && "$WLAN_IP" != "$PI_IP" ]]; then
        echo "IP.3  = $WLAN_IP" | sudo -u "$SVC_USER" tee -a "$EXT_FILE" > /dev/null
    fi

    # Sign server certificate
    sudo chmod 664 "$CA_DIR/netwatch-ca.srl" 2>/dev/null || true
    sudo -u "$SVC_USER" openssl x509 -req -in "$CERTS_DIR/netwatch.csr" -CA "$CA_DIR/netwatch-ca.crt" -CAkey "$CA_DIR/netwatch-ca.key" -CAcreateserial -out "$CERTS_DIR/netwatch.crt" -days 3650 -extfile "$EXT_FILE"
    sudo -u "$SVC_USER" chmod 644 "$CERTS_DIR/netwatch.crt"
    sudo -u "$SVC_USER" rm -f "$CERTS_DIR/netwatch.csr"
    rm -f "$EXT_FILE"
    log "TLS certificates generated (self-signed, 10 years)"
    log "CA cert available at $CERTS_DIR/netwatch-ca.crt for browser import"
fi

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
