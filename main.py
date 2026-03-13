#!/usr/bin/env python3
# ══════════════════════════════════════════════════════════════════════════════
# NetWatch — main.py
# Entry point. Initializes all subsystems and runs the main monitor loop.
#
# Start order:
#   1. Logging
#   2. Database
#   3. GPIO / Relays
#   4. Button handler
#   5. Main monitor loop (runs forever, handles Ctrl+C and SIGTERM cleanly)
# ══════════════════════════════════════════════════════════════════════════════

import time
import logging
import signal
import sys
import os
from datetime import datetime, time as dt_time

# ─── Set up logging before importing anything else ────────────────────────────
LOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs", "netwatch.log")
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.FileHandler(LOG_PATH),
        logging.StreamHandler(sys.stdout)   # Also print to terminal / journalctl
    ]
)
log = logging.getLogger("netwatch.main")

# ─── Now import our modules ───────────────────────────────────────────────────
import config
import database
import relay
import network
import monitor
import button
import alerts


# ══════════════════════════════════════════════════════════════════════════════
# GRACEFUL SHUTDOWN
# ══════════════════════════════════════════════════════════════════════════════

def shutdown(sig, frame):
    """Handle SIGINT (Ctrl+C) and SIGTERM (systemd stop) gracefully."""
    log.info("Shutdown signal received — cleaning up...")
    relay.cleanup()   # Release GPIO resources
    log.info("NetWatch stopped")
    sys.exit(0)

signal.signal(signal.SIGINT,  shutdown)
signal.signal(signal.SIGTERM, shutdown)


# ══════════════════════════════════════════════════════════════════════════════
# STARTUP
# ══════════════════════════════════════════════════════════════════════════════

def startup():
    """Initialize all subsystems in the correct order."""
    log.info("=" * 60)
    log.info("  NetWatch Network Monitor — Starting up")
    log.info("=" * 60)
    log.info(f"  Check interval:    {config.CHECK_INTERVAL}s")
    log.info(f"  Confirm window:    {config.CONFIRM_WINDOW}s")
    log.info(f"  Reset cooldown:    {config.RESET_COOLDOWN}s")
    log.info(f"  Max resets/day:    {config.MAX_RESETS_PER_DAY}")
    log.info(f"  Speedtest every:   {config.SPEEDTEST_INTERVAL // 60} minutes")
    log.info(f"  Email alerts:      {'ENABLED' if config.ALERTS_ENABLED else 'DISABLED'}")
    log.info("=" * 60)

    # Initialize database tables
    database.init_db()

    # Initialize GPIO relay pins
    relay.init()

    log.info("All subsystems initialized — monitor starting")


# ══════════════════════════════════════════════════════════════════════════════
# MAIN LOOP
# ══════════════════════════════════════════════════════════════════════════════

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

    log.info("Entering main monitor loop")

    while True:
        try:
            # ── Network health check ──────────────────────────────────────────
            status = network.check_network()

            log.info(
                f"LAN:{'✓' if status['lan_ok'] else '✗'}  "
                f"WAN:{'✓' if status['wan_ok'] else '✗'}  "
                f"WiFi:{'✓' if status['wifi_ok'] else '✗'}  "
                f"DNS:{'✓' if status['dns_ok'] else '✗'}  "
                f"Latency:{status['latency_ms']}ms  "
                f"Loss:{status['packet_loss']}%  "
                f"{'[HEALTHY]' if status['healthy'] else '[ISSUE]'}"
            )

            # ── State machine processes result ────────────────────────────────
            net_monitor.process_status(status)

            # ── Speedtest on schedule ─────────────────────────────────────────
            net_monitor.check_speedtest_schedule()

            # ── Daily database pruning ────────────────────────────────────────
            # Prune old records once per day to keep DB size in check
            today = datetime.now().date()
            if today != getattr(main, "_last_prune_date", None):
                database.prune_old_records()
                main._last_prune_date = today

            # ── Daily summary email ───────────────────────────────────────────
            # Send at approximately 8:00 AM each day
            now = datetime.now()
            summary_hour = 8
            if (now.hour == summary_hour and
                    now.date() != last_summary_date and
                    config.ALERTS_ENABLED):
                alerts.send_daily_summary()
                last_summary_date = now.date()

            # ── Check for web-triggered commands ─────────────────────────────
            _check_pending_command(state, net_monitor)

        except Exception as e:
            log.error(f"Unexpected error in monitor loop: {e}", exc_info=True)
            # Don't crash — log and continue

        time.sleep(config.CHECK_INTERVAL)


# ══════════════════════════════════════════════════════════════════════════════
# WEB COMMAND HANDLER
# ══════════════════════════════════════════════════════════════════════════════

def _check_pending_command(state, net_monitor):
    """
    Check for commands sent from the web dashboard.
    webapp.py writes a command file when a control button is pressed.
    main.py picks it up here and executes it.

    This file-based IPC approach is simple and reliable — no sockets needed.
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

        log.info(f"Processing web command: {command} (from {triggered_by})")

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
            log.info(f"Lockout {'ENABLED' if state.lockout else 'DISABLED'} via web")

        elif command == "speedtest":
            network.run_speedtest_async()

    except json.JSONDecodeError:
        log.warning("Could not parse pending_command.json — ignoring")
        try:
            os.remove(cmd_file)
        except Exception:
            pass
    except Exception as e:
        log.error(f"Error processing web command: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    main()
