#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
# NetWatch — gunicorn_upgrade.sh
# Run once after installing the gunicorn package to update the systemd service.
# ══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

NETWATCH_DIR="$HOME/netwatch"
PYTHON_PATH="$NETWATCH_DIR/venv/bin/python3"
GUNICORN_PATH="$NETWATCH_DIR/venv/bin/gunicorn"
USER=$(whoami)
CERT="$NETWATCH_DIR/certs/netwatch.crt"
KEY="$NETWATCH_DIR/certs/netwatch.key"

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║         NetWatch — Gunicorn Upgrade                  ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# Install gunicorn into venv
echo "► Installing gunicorn into venv..."
"$NETWATCH_DIR/venv/bin/pip" install gunicorn -q
echo "  ✓ gunicorn installed"

# Update the web service to use gunicorn
echo "► Updating netwatch-web.service..."
sudo tee /etc/systemd/system/netwatch-web.service > /dev/null << SVCEOF
[Unit]
Description=NetWatch Web Dashboard
After=network.target netwatch-monitor.service

[Service]
Type=simple
User=$USER
WorkingDirectory=$NETWATCH_DIR
ExecStart=$GUNICORN_PATH --config $NETWATCH_DIR/gunicorn.conf.py wsgi:app
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SVCEOF

echo "  ✓ Service file updated"

# Reload and restart
echo "► Reloading systemd and restarting web service..."
sudo systemctl daemon-reload
sudo systemctl restart netwatch-web.service
sleep 3

STATUS=$(systemctl is-active netwatch-web.service 2>/dev/null || echo "failed")

echo ""
if [[ "$STATUS" == "active" ]]; then
    echo "  ✓ NetWatch web service is running with gunicorn"
    echo "  → https://$(hostname -I | awk '{print $1}'):5000"
else
    echo "  ✗ Service failed to start — check: sudo journalctl -fu netwatch-web"
fi
echo ""
