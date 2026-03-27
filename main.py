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
import random
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
try:
    import requests as _requests
except ImportError:
    _requests = None


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

    # Track when to run update check. Jitter (0–3600s) spreads check times
    # across installs so all Pis don't hit GitHub at the same second each day.
    last_update_check_date = None
    update_check_jitter_s  = random.randint(0, 3600)

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

            # -- Summary email (daily or weekly) ------------------------------
            # Frequency/day/hour are runtime config — read each loop iteration
            # so changes take effect after a monitor restart without redeploying.
            now = datetime.now()
            summary_hour = int(getattr(config, "SUMMARY_HOUR", 8))
            summary_freq = (getattr(config, "SUMMARY_FREQUENCY", "daily") or "daily").strip().lower()
            summary_day  = int(getattr(config, "SUMMARY_DAY",  0))   # 0=Mon … 6=Sun

            _hour_match = (now.hour == summary_hour)
            _not_sent   = (now.date() != last_summary_date)
            _freq_match = (
                summary_freq == "daily" or
                (summary_freq == "weekly" and now.weekday() == summary_day)
            )
            if _hour_match and _not_sent and _freq_match and config.ALERTS_ENABLED:
                alerts.send_daily_summary()
                last_summary_date = now.date()

            # -- Daily update check -------------------------------------------
            # Poll UPDATE_CHECK_URL once per day (with jitter) to detect new
            # versions. Writes result to system_settings so the web service
            # can show a notification banner. Fails silently on any error.
            _check_for_updates(now, last_update_check_date, update_check_jitter_s)
            if now.date() != last_update_check_date:
                # Only advance the date tracker once the jitter window has passed
                elapsed_today_s = now.hour * 3600 + now.minute * 60 + now.second
                if elapsed_today_s >= update_check_jitter_s:
                    last_update_check_date = now.date()

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
# UPDATE CHECKER
# ==============================================================================

def _check_for_updates(now, last_check_date, jitter_s):
    """
    Poll UPDATE_CHECK_URL once per day (after the jitter offset) to check
    whether a newer version of NetWatch is available.

    Reads releases/latest.json from GitHub (or whatever URL is configured),
    compares the available version to the installed version, and writes the
    result to system_settings so the web service can show a notification banner.

    Fails silently on any network or parsing error — never crashes the monitor.

    Args:
        now:             datetime.now() from the current loop iteration
        last_check_date: date of the last completed check (or None)
        jitter_s:        random offset in seconds (0-3600) so all installs
                         don't hit the manifest URL at the same time each day
    """
    check_url = getattr(config, "UPDATE_CHECK_URL", "").strip()
    if not check_url:
        return  # Disabled

    if _requests is None:
        return  # requests library not available

    # Run once per day, after the jitter offset has elapsed
    elapsed_today_s = now.hour * 3600 + now.minute * 60 + now.second
    if now.date() == last_check_date or elapsed_today_s < jitter_s:
        return

    try:
        from packaging import version as pkg_version

        resp = _requests.get(check_url, timeout=10)
        resp.raise_for_status()
        manifest = resp.json()

        available_ver = manifest.get("version", "").strip()
        description   = manifest.get("description", "").strip()

        # Read installed version from VERSION file (same source patcher uses)
        version_file = os.path.join(NETWATCH_DIR, "VERSION")
        try:
            with open(version_file) as f:
                installed_ver = f.read().strip()
        except FileNotFoundError:
            installed_ver = "0.0.0"

        if available_ver and pkg_version.parse(available_ver) > pkg_version.parse(installed_ver):
            database.set_system_setting("update_available_version",    available_ver)
            database.set_system_setting("update_available_description", description)
            log.info("update_available",
                     installed=installed_ver,
                     available=available_ver)
        else:
            # Current or check produced no usable version — clear any stale banner
            database.set_system_setting("update_available_version",    "")
            database.set_system_setting("update_available_description", "")
            log.info("update_check_current", installed=installed_ver, available=available_ver)

        database.set_system_setting("update_last_checked", now.strftime("%Y-%m-%d %H:%M:%S"))

    except Exception as e:
        # Fail silently — network errors, timeouts, bad JSON, anything
        log.warning("update_check_failed", error=str(e))


# ==============================================================================
# ENTRY POINT
# ==============================================================================

if __name__ == "__main__":
    main()
