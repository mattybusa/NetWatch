# ==============================================================================
# NetWatch -- monitor.py
# The brain of the system. Contains the state machine that decides when and
# what to reset based on network health check results.
#
# This module does NOT do the actual checking (network.py) or resetting (relay.py).
# It receives results, tracks state over time, and decides what to do.
# ==============================================================================

import structlog
from datetime import datetime

import config
import database
import relay
import network
import alerts

log = structlog.get_logger().bind(service="monitor")


class MonitorState:
    """
    Holds all the runtime state that the monitor needs to track between checks.
    This is passed to button.py so the button can also read/modify state (lockout).
    """

    def __init__(self):
        # -- Mode flags -------------------------------------------------------
        self.lockout          = False   # When True, no automatic resets are performed
        self.conservative_mode = False  # When True, max resets exceeded for today

        # -- Issue tracking ---------------------------------------------------
        # When did we first notice the current problem?
        # Set to None when network recovers.
        self.issue_first_seen = None

        # When did we first notice degraded (but not down) service?
        self.degraded_since   = None

        # -- Reset tracking ---------------------------------------------------
        self.last_reset_time  = None    # datetime of the most recent reset

        # -- Speedtest tracking -----------------------------------------------
        self.last_speedtest   = None    # datetime of the most recent speedtest

        # -- Previous status (for detecting transitions) ----------------------
        self.was_healthy      = True    # Was the network healthy last check?


class NetworkMonitor:
    """
    The main monitoring state machine.

    Each call to process_status() receives the latest health check result
    and decides whether to: wait, alert, or perform a reset.

    Key design decisions:
      - Issues must persist for CONFIRM_WINDOW seconds before any action
        (prevents reacting to brief blips that resolve themselves)
      - A RESET_COOLDOWN must pass between auto-resets
        (prevents reboot loops when there's an external ISP problem)
      - After MAX_RESETS_PER_DAY resets, enter conservative mode
        (sends alert and stops auto-resetting until manually cleared)
    """

    def __init__(self, state: MonitorState):
        self.state = state

    # ==========================================================================
    # GUARD CHECKS
    # ==========================================================================

    def _can_reset(self):
        """
        Returns True if an auto-reset is allowed right now.
        Checks lockout, conservative mode, and cooldown timer.
        """
        if self.state.lockout:
            log.info("reset_suppressed", reason="lockout_active")
            return False

        if self.state.conservative_mode:
            log.warning("reset_suppressed", reason="conservative_mode")
            return False

        if self.state.last_reset_time:
            elapsed = (datetime.now() - self.state.last_reset_time).total_seconds()
            if elapsed < config.RESET_COOLDOWN:
                remaining = int(config.RESET_COOLDOWN - elapsed)
                log.info("reset_suppressed", reason="cooldown_active", remaining_s=remaining)
                return False

        return True

    def _issue_confirmed(self):
        """
        Returns True if the current issue has persisted long enough to act on.
        We don't reset on the first sign of trouble -- the problem must be
        consistently present for CONFIRM_WINDOW seconds.
        """
        if not self.state.issue_first_seen:
            return False
        elapsed = (datetime.now() - self.state.issue_first_seen).total_seconds()
        return elapsed >= config.CONFIRM_WINDOW

    # ==========================================================================
    # RESET EXECUTION
    # ==========================================================================

    def _perform_reset(self, reset_type, reason):
        """
        Execute a reset after checking daily limits.
        Updates state and sends alert after reset completes.
        """
        # Check daily reset limit
        reset_count = database.get_reset_count_today()
        if reset_count >= config.MAX_RESETS_PER_DAY:
            self.state.conservative_mode = True
            log.warning("conservative_mode_entered",
                        resets_today=reset_count,
                        max_resets=config.MAX_RESETS_PER_DAY)
            alerts.send_alert(
                "conservative_mode",
                f"NetWatch has performed {config.MAX_RESETS_PER_DAY} automatic resets today "
                f"without resolving the issue. Manual intervention may be required. "
                f"Auto-resets are suspended until midnight."
            )
            return

        # Execute the appropriate reset type
        if reset_type == "full":
            relay.cycle_full(triggered_by="auto", reason=reason)
        elif reset_type == "modem":
            relay.cycle_modem(triggered_by="auto")
        elif reset_type == "router":
            relay.cycle_router(triggered_by="auto")

        log.info("reset_performed", reset_type=reset_type, reason=reason)

        # Update state
        self.state.last_reset_time  = datetime.now()
        self.state.issue_first_seen = None   # Reset confirmation timer

        # Send alert
        alerts.send_alert(
            "reset_performed",
            f"Automatic reset performed: <b>{reset_type}</b><br>Reason: {reason}"
        )

    # ==========================================================================
    # STATUS PROCESSING -- the main decision logic
    # ==========================================================================

    def process_status(self, status):
        """
        Evaluate the latest network health check and decide what to do.

        Called every CHECK_INTERVAL seconds from main.py.

        Decision tree:
          Network healthy -> check for degradation, clear issue timers
          Network degraded but connected -> track degradation duration, maybe alert
          Network down:
            -> Start confirmation timer if not already started
            -> If confirmed (persisted long enough):
                LAN down        -> full reset
                WAN down        -> modem reset
                WiFi AP down    -> router reset
        """
        healthy  = status["healthy"]
        degraded = status["degraded"]

        # -- Case 1: Network is healthy ----------------------------------------
        if healthy and not degraded:
            self._handle_healthy(status)
            return

        # -- Case 2: Connected but degraded quality ----------------------------
        if healthy and degraded:
            self._handle_degraded(status)
            return

        # -- Case 3: Network is down ------------------------------------------
        self._handle_down(status)

    def _handle_healthy(self, status):
        """Handle a clean healthy status -- clear timers, detect recovery."""
        # Detect recovery from a previous outage
        if not self.state.was_healthy:
            log.info("network_restored")
            alerts.send_alert("restored", "Network connectivity has been fully restored.")

        # Clear all issue timers
        self.state.issue_first_seen = None
        self.state.degraded_since   = None
        self.state.was_healthy      = True

    def _handle_degraded(self, status):
        """Handle degraded-but-connected status -- track duration, send alert if prolonged."""
        if not self.state.degraded_since:
            self.state.degraded_since = datetime.now()
            log.warning("network_degraded",
                        latency_ms=status["latency_ms"],
                        packet_loss=status["packet_loss"])
        else:
            elapsed = (datetime.now() - self.state.degraded_since).total_seconds()
            if elapsed >= config.DEGRADED_ALERT_TIME:
                elapsed_min = int(elapsed / 60)
                log.warning("sustained_degradation",
                            duration_min=elapsed_min,
                            latency_ms=status["latency_ms"],
                            packet_loss=status["packet_loss"])
                alerts.send_alert(
                    "degraded",
                    f"Network has been degraded for <b>{elapsed_min} minutes</b>.<br>"
                    f"Latency: {status['latency_ms']}ms &nbsp;|&nbsp; "
                    f"Packet loss: {status['packet_loss']}%<br>"
                    f"No reset has been triggered -- connection is still active."
                )
                # Reset timer so we don't send this alert repeatedly
                self.state.degraded_since = datetime.now()

        self.state.was_healthy = True   # Still connected, just slow

    def _handle_down(self, status):
        """Handle a down network -- start confirmation timer, then reset if confirmed."""
        lan_ok  = status["lan_ok"]
        wan_ok  = status["wan_ok"]
        wifi_ok = status["wifi_ok"]

        # First time we're seeing this issue -- start the confirmation clock
        if not self.state.issue_first_seen:
            self.state.issue_first_seen = datetime.now()
            self.state.was_healthy      = False
            self.state.degraded_since   = None

            log.warning("network_issue_detected",
                        lan=lan_ok, wan=wan_ok, wifi=wifi_ok,
                        confirm_window_s=config.CONFIRM_WINDOW)
            alerts.send_alert(
                "outage",
                f"Network issue detected.<br>"
                f"LAN: {'checkmark' if lan_ok else 'X'} &nbsp;"
                f"WAN: {'checkmark' if wan_ok else 'X'} &nbsp;"
                f"WiFi AP: {'checkmark' if wifi_ok else 'X'}<br>"
                f"Monitoring for {config.CONFIRM_WINDOW // 60} minutes before taking action."
            )
            return

        # Still seeing the issue -- check if we've waited long enough
        elapsed = (datetime.now() - self.state.issue_first_seen).total_seconds()

        if not self._issue_confirmed():
            log.info("issue_persisting",
                     elapsed_s=int(elapsed),
                     confirm_window_s=config.CONFIRM_WINDOW,
                     lan=lan_ok, wan=wan_ok, wifi=wifi_ok)
            return

        # Issue confirmed -- check if we're allowed to reset
        if not self._can_reset():
            return

        # Decide what to reset based on what's actually broken
        if not lan_ok:
            # Can't reach our own router -- full reset required
            log.warning("initiating_reset", reset_type="full", trigger="lan_unreachable")
            self._perform_reset("full", "LAN gateway unreachable")

        elif not wan_ok:
            # Router is fine (LAN ok) but internet is down -- modem problem
            log.warning("initiating_reset", reset_type="modem", trigger="wan_unreachable_lan_ok")
            self._perform_reset("modem", "WAN unreachable with LAN intact (modem suspected)")

        elif not wifi_ok:
            # Both LAN and WAN work, but WiFi AP gateway is unreachable
            # Cycle the router to reset the AP via PoE
            log.warning("initiating_reset", reset_type="router", trigger="wifi_ap_unreachable")
            self._perform_reset("router", "WiFi AP unreachable with LAN/WAN intact")

    # ==========================================================================
    # SPEEDTEST SCHEDULING
    # ==========================================================================

    def check_speedtest_schedule(self):
        """
        Trigger a speedtest if enough time has passed and the network is healthy.
        Called each loop iteration from main.py.
        Speedtest runs in a background thread (see network.py).
        """
        from datetime import datetime as dt
        now = dt.now()

        # Don't run if we've never run one yet, or if interval hasn't elapsed
        if self.state.last_speedtest:
            elapsed = (now - self.state.last_speedtest).total_seconds()
            if elapsed < config.SPEEDTEST_INTERVAL:
                return

        # Only run speedtest when network is healthy -- bad results during an
        # outage would pollute the historical data
        latest = database.get_latest_health()
        if latest and latest.get("healthy"):
            log.info("speedtest_scheduled")
            network.run_speedtest_async()
            self.state.last_speedtest = now
