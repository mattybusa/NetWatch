# ══════════════════════════════════════════════════════════════════════════════
# NetWatch — gunicorn.conf.py
# Gunicorn configuration for the NetWatch web service.
# ══════════════════════════════════════════════════════════════════════════════

import os

NETWATCH_DIR = os.path.dirname(os.path.abspath(__file__))

# Server socket
bind        = "0.0.0.0:5000"
certfile    = os.path.join(NETWATCH_DIR, "certs", "netwatch.crt")
keyfile     = os.path.join(NETWATCH_DIR, "certs", "netwatch.key")

# Workers
workers     = 2
worker_class = "sync"
timeout     = 30

# Load the app in the master process before forking workers.
# This means init() runs once, not once per worker, avoiding
# simultaneous DB writes on startup.
preload_app = True

# Logging — send to stdout so systemd/journald captures it
accesslog   = "-"
errorlog    = "-"
loglevel    = "info"
