# ══════════════════════════════════════════════════════════════════════════════
# NetWatch — button.py
# Handles the momentary pushbutton with three distinct press patterns.
#
# Button behaviors:
#   Single press          → Full reset (modem + router)
#   Long press (3+ sec)   → Modem only reset
#   Triple press (3x <2s) → Toggle lockout mode (disables auto-resets)
#
# Wiring:
#   One leg of button → GPIO 22 (physical pin 15)
#   Other leg         → GND    (physical pin 14)
#   Internal pull-up resistor is enabled, so no external resistor needed.
#   Button reads LOW when pressed, HIGH when released.
#
# Uses lgpio instead of RPi.GPIO — lgpio uses /dev/gpiochip and works correctly
# under the netwatch-svc account without requiring /dev/mem access.
# ══════════════════════════════════════════════════════════════════════════════

import time
import threading
import structlog

import config

log = structlog.get_logger().bind(service="monitor")

try:
    import lgpio
    LGPIO_AVAILABLE = True
except ImportError:
    LGPIO_AVAILABLE = False
    log.warning("lgpio not available: button handler in simulation mode")


class ButtonHandler:
    """
    Interrupt-driven button handler that detects single, long, and triple presses.

    Uses lgpio's callback system (gpio_claim_alert + callback) on BOTH_EDGES so
    it can measure how long the button is held. A short timer after each press
    evaluates the press pattern before deciding what action to take.
    """

    # How long to hold for a "long press" (seconds)
    LONG_PRESS_DURATION = 3.0

    # Window in which multiple presses are counted as a sequence (seconds)
    MULTI_PRESS_WINDOW = 2.0

    # Debounce time in microseconds (50ms)
    DEBOUNCE_MICROS = 50000

    def __init__(self, monitor_state):
        """
        Args:
            monitor_state: Reference to the MonitorState object in monitor.py.
                           Button actions update lockout mode and trigger resets.
        """
        self.state       = monitor_state
        self.press_count = 0          # Number of presses in current sequence
        self.hold_start  = None       # Time the button was pressed down
        self.eval_timer  = None       # Timer that fires after MULTI_PRESS_WINDOW
        self._lock       = threading.Lock()
        self._handle     = None       # lgpio chip handle
        self._cb         = None       # lgpio callback object (must be kept alive)

    def start(self):
        """Open GPIO chip, claim button pin with pull-up, register edge callback."""
        if not LGPIO_AVAILABLE:
            log.info("Button handler not started (simulation)")
            return

        try:
            # Open gpiochip0 — the main GPIO controller on Pi 3B+
            self._handle = lgpio.gpiochip_open(0)

            # Claim pin as input with internal pull-up
            # Pin reads HIGH normally, LOW when button pressed
            lgpio.gpio_claim_input(self._handle, config.BUTTON_PIN, lgpio.SET_PULL_UP)

            # Set debounce — filters out contact bounce on press/release
            lgpio.gpio_set_debounce_micros(
                self._handle, config.BUTTON_PIN, self.DEBOUNCE_MICROS
            )

            # Claim alert on both edges (press=FALLING, release=RISING)
            lgpio.gpio_claim_alert(
                self._handle, config.BUTTON_PIN, lgpio.BOTH_EDGES
            )

            # Register callback — must store reference or it gets garbage collected
            self._cb = lgpio.callback(
                self._handle, config.BUTTON_PIN, lgpio.BOTH_EDGES, self._on_edge
            )

            log.info("Button handler started", gpio=config.BUTTON_PIN)

        except Exception as e:
            # Edge detection can fail if the pin is already in use or not ready.
            # Log a warning but allow the monitor to continue — network monitoring
            # is more important than the button, and this can be debugged separately.
            log.warning(
                "Button edge detection failed: button unavailable, monitor continues",
                error=str(e)
            )
            self._cleanup_handle()

    def stop(self):
        """Cancel callback and release GPIO resources."""
        if self._cb is not None:
            try:
                self._cb.cancel()
            except Exception:
                pass
            self._cb = None
        self._cleanup_handle()

    def _cleanup_handle(self):
        """Close the lgpio chip handle if open."""
        if self._handle is not None:
            try:
                lgpio.gpiochip_close(self._handle)
            except Exception:
                pass
            self._handle = None

    # ── Internal event handling ───────────────────────────────────────────────

    def _on_edge(self, chip, gpio, level, timestamp):
        """
        Called by lgpio on both press (level=0/LOW) and release (level=1/HIGH).

        Args:
            chip:      lgpio chip handle
            gpio:      GPIO pin number
            level:     0 = LOW (pressed), 1 = HIGH (released), 2 = watchdog
            timestamp: microsecond timestamp from lgpio
        """
        with self._lock:
            if level == 0:
                # Button pressed (FALLING edge) — record the time
                self.hold_start = time.time()
                self.press_count += 1
                log.debug("Button pressed", press_count=self.press_count)

            elif level == 1:
                # Button released (RISING edge) — check if it was a long press
                if self.hold_start is None:
                    return

                hold_duration = time.time() - self.hold_start
                self.hold_start = None

                if hold_duration >= self.LONG_PRESS_DURATION:
                    # Long press detected — act immediately, clear press count
                    log.info(
                        "Long press detected: modem reset",
                        hold_duration_s=round(hold_duration, 1)
                    )
                    self.press_count = 0
                    if self.eval_timer:
                        self.eval_timer.cancel()
                    threading.Thread(
                        target=self._do_modem_reset,
                        daemon=True
                    ).start()
                    return

                # Short press released — start/restart the evaluation window
                if self.eval_timer:
                    self.eval_timer.cancel()
                self.eval_timer = threading.Timer(
                    self.MULTI_PRESS_WINDOW,
                    self._evaluate_presses
                )
                self.eval_timer.start()

    def _evaluate_presses(self):
        """
        Called after MULTI_PRESS_WINDOW seconds of no new presses.
        Determines what action to take based on press count.
        """
        with self._lock:
            count = self.press_count
            self.press_count = 0
            self.eval_timer  = None

        log.debug("Evaluating button presses", count=count)

        if count == 0:
            return
        elif count == 1:
            log.info("Single press: full reset")
            threading.Thread(target=self._do_full_reset, daemon=True).start()
        elif count == 2:
            log.info("Double press: no action assigned")
        elif count >= 3:
            log.info("Triple press: toggling lockout mode")
            self._toggle_lockout()

    # ── Actions ───────────────────────────────────────────────────────────────

    def _do_full_reset(self):
        """Trigger a full modem + router reset via relay module."""
        import relay
        import alerts
        relay.cycle_full(triggered_by="button", reason="Manual button press")
        alerts.send_alert("reset_performed", "Full reset triggered by button press.")

    def _do_modem_reset(self):
        """Trigger a modem-only reset via relay module."""
        import relay
        import alerts
        relay.cycle_modem(triggered_by="button")
        alerts.send_alert("reset_performed", "Modem reset triggered by long button press.")

    def _toggle_lockout(self):
        """Toggle lockout mode on the shared monitor state."""
        self.state.lockout = not self.state.lockout
        status = "ENABLED" if self.state.lockout else "DISABLED"
        log.info("Lockout mode toggled via button", status=status)

        import alerts
        alerts.send_alert(
            "lockout_changed",
            f"Auto-reset lockout {status} via physical button."
        )
