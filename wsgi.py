#!/usr/bin/env python3
# ==============================================================================
# NetWatch -- wsgi.py
# Gunicorn entry point. Initialises logging then exposes the Flask app.
#
# Logging is configured here before any other import so all modules share
# the same structlog setup. LOG_FORMAT in config.py controls the output:
#   pretty -- human-readable, for SSH / journalctl
#   json   -- structured JSON, for Promtail / Loki ingestion
# ==============================================================================

import os
import sys
import logging

# Ensure the netwatch directory is on the path
NETWATCH_DIR = os.path.dirname(os.path.abspath(__file__))
if NETWATCH_DIR not in sys.path:
    sys.path.insert(0, NETWATCH_DIR)

# -- Read LOG_FORMAT from config before full app import ------------------------
# Import config directly so logging is fully configured before webapp.py loads.
import config
LOG_FORMAT = getattr(config, "LOG_FORMAT", "pretty")

# -- Configure logging backend (stdlib) ----------------------------------------
LOG_PATH = os.path.join(NETWATCH_DIR, "logs", "netwatch.log")
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",   # structlog renders the full line; stdlib just passes it through
    handlers=[
        logging.FileHandler(LOG_PATH),
        logging.StreamHandler(sys.stdout),
    ]
)

# -- Configure structlog -------------------------------------------------------
import structlog

def _configure_structlog(log_format):
    """
    Configure structlog shared processors and final renderer.
    Called once at startup. log_format is "pretty" or "json".
    """
    shared_processors = [
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    if log_format == "json":
        # JSON renderer -- for Promtail / Loki ingestion
        renderer = structlog.processors.JSONRenderer()
    else:
        # Human-readable renderer -- for SSH / journalctl
        renderer = structlog.dev.ConsoleRenderer(colors=False)

    structlog.configure(
        processors=shared_processors + [renderer],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

_configure_structlog(LOG_FORMAT)

# -- Web service startup logger ------------------------------------------------
# Bound with service="web" so all lines from this entry point are identifiable.
# webapp.py and other modules call structlog.get_logger().bind(service="web")
# for their own loggers.
_startup_log = structlog.get_logger().bind(service="web")
_startup_log.info("web_service_starting", log_format=LOG_FORMAT)

from webapp import app, init

# Run initialisation (DB, auth, backfill, etc.)
init()
