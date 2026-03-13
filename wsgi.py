#!/usr/bin/env python3
# ══════════════════════════════════════════════════════════════════════════════
# NetWatch — wsgi.py
# Gunicorn entry point. Initialises all subsystems then exposes the Flask app.
# ══════════════════════════════════════════════════════════════════════════════

import os
import sys

# Ensure the netwatch directory is on the path
NETWATCH_DIR = os.path.dirname(os.path.abspath(__file__))
if NETWATCH_DIR not in sys.path:
    sys.path.insert(0, NETWATCH_DIR)

from webapp import app, init

# Run initialisation (DB, auth, backfill, etc.)
init()
