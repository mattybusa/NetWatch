#!/usr/bin/env python3
# ==============================================================================
# NetWatch -- main.py
# Entry point. Initializes all subsystems and runs the main monitor loop.
#
# Start order:
#   1. Logging (structlog, configured before any other import)
#   2. Database
#   3. GPIO / Relays
#   4. Button handler
#   5. Main monitor loop (runs forever, handles Ctrl+C and SIGTERM cleanly)
# ==============================================================================

import time
import signal
import sys
import os
import logging
from datetime import datetime, time as dt_time

# -- Set up logging before importing anything else ----------------------------
NETWATCH_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.join(NETWATCH_DIR, "logs", "netwatch.log")
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

import config
LOG_FORMAT = getattr(config, "LOG_FORMAT", "pretty")

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",   # structlog renders the full line; stdlib just passes it through
    handlers=[
        logging.FileHandler(LOG_PATH),
        logging.StreamHandler(sys.stdout),
    ]
)

import structlog

def _configure_structlog(log_format):
    """
    Configure structlog shared processors and final renderer.
    Called once at startup. log_format is "pretty" or "json".
    Mirrors the identical function in wsgi.py -- both services must configure
    structlog the same way so log output is consistent.
    """
    shared_processors = [
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    if log_format == "json":
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=False)

    structlog.configure(
        processors=shared_processors + [renderer],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

_configure_structlog(LOG_FORMAT)

# All monitor service log lines are bound with service="monitor"
log = structlog.get_logger().bind(service="monitor")

# -- Now import our modules ---------------------------------------------------
import database
import relay
import network
import monitor
import button
import alerts


# ==============================================================================
# GRACEFUL SHUTDOWN
# ==============================================================================

def shutdown(sig, frame):
    """Handle SIGINT (Ctrl+C) and SIGTERM (systemd stop) gracefully."""
    log.info("shutdown_signal_received", action="cleanup")
    relay.cleanup()   # Release GPIO resources
    log.info("netwatch_stopped")
    sys.exit(0)

signal.signal(signal.SIGINT,  shutdown)
signal.signal(signal.SIGTERM, shutdown)


# ==============================================================================
# STARTUP
# ==============================================================================

def startup():
    """Initialize all subsystems in the correct order."""
    log.info("netwatch_starting",
             check_interval=config.CHECK_INTERVAL,
             confirm_window=config.CONFIRM_WINDOW,
             reset_cooldown=config.RESET_COOLDOWN,
             max_resets_per_day=config.MAX_RESETS_PER_DAY,
             speedtest_interval_min=config.SPEEDTEST_INTERVAL // 60,
             alerts_enabled=config.ALERTS_ENABLED,
             log_format=LOG_FORMAT)

    # Initialize database tables
    database.init_db()

    # Initialize GPIO relay pins
    relay.init()

    log.info("all_subsystems_initialized")


# ==============================================================================
# MAIN LOOP
# ==============================================================================

def main():
    startup()

    # Create shared state (passed to both monitor and button handler)
    state = monitor.MonitorState()

    # Start button handler (interrupt-driven, runs in background)
    btn = button.ButtonHandler(state)
    btn.start()

    # Create the monitor/decision engine
    net_monitor = monitor.NetworkMonitor(state)

    # Track when to send daily summary
    last_summary_date = None

    log.info("monitor_loop_started")

    while True:
        try:
            # -- Network health check -----------------------------------------
            status = network.check_network()

            log.info("health_check",
                     lan=status["lan_ok"],
                     wan=status["wan_ok"],
                     wifi=status["wifi_ok"],
                     dns=status["dns_ok"],
                     latency_ms=status["latency_ms"],
                     packet_loss=status["packet_loss"],
                     healthy=status["healthy"])

            # -- State machine processes result --------------------------------
            net_monitor.process_status(status)

            # -- Speedtest on schedule ----------------------------------------
            net_monitor.check_speedtest_schedule()

            # -- Daily database pruning ---------------------------------------
            # Prune old records once per day to keep DB size in check
            today = datetime.now().date()
            if today != getattr(main, "_last_prune_date", None):
                database.prune_old_records()
                main._last_prune_date = today

            # -- Daily summary email ------------------------------------------
            # Send at approximately 8:00 AM each day
            now = datetime.now()
            summary_hour = 8
            if (now.hour == summary_hour and
                    now.date() != last_summary_date and
                    config.ALERTS_ENABLED):
                alerts.send_daily_summary()
                last_summary_date = now.date()

            # -- Check for web-triggered commands -----------------------------
            _check_pending_command(state, net_monitor)

        except Exception as e:
            log.error("monitor_loop_error", error=str(e), exc_info=True)
            # Don't crash -- log and continue

        time.sleep(config.CHECK_INTERVAL)


# ==============================================================================
# WEB COMMAND HANDLER
# ==============================================================================

def _check_pending_command(state, net_monitor):
    """
    Check for commands sent from the web dashboard.
    webapp.py writes a command file when a control button is pressed.
    main.py picks it up here and executes it.

    This file-based IPC approach is simple and reliable -- no sockets needed.
    """
    import json
    cmd_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pending_command.json")

    if not os.path.exists(cmd_file):
        return

    try:
        with open(cmd_file) as f:
            cmd = json.load(f)

        # Remove the file immediately so we don't process it twice
        os.remove(cmd_file)

        command      = cmd.get("command")
        triggered_by = cmd.get("triggered_by", "web")

        log.info("web_command_received", command=command, triggered_by=triggered_by)

        if command == "full_reset":
            relay.cycle_full(triggered_by=triggered_by, reason="Manual web dashboard reset")
            state.last_reset_time = datetime.now()

        elif command == "modem_reset":
            relay.cycle_modem(triggered_by=triggered_by)
            state.last_reset_time = datetime.now()

        elif command == "router_reset":
            relay.cycle_router(triggered_by=triggered_by)
            state.last_reset_time = datetime.now()

        elif command == "toggle_lockout":
            state.lockout = not state.lockout
            log.info("lockout_toggled", lockout=state.lockout, triggered_by="web")

        elif command == "speedtest":
            network.run_speedtest_async()

    except json.JSONDecodeError:
        log.warning("pending_command_parse_error", action="ignored")
        try:
            os.remove(cmd_file)
        except Exception:
            pass
    except Exception as e:
        log.error("web_command_error", error=str(e))


# ==============================================================================
# ENTRY POINT
# ==============================================================================

if __name__ == "__main__":
    main()
