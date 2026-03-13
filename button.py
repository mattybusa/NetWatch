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
#   One leg of button → GPIO 22
#   Other leg         → GND
#   Internal pull-up resistor is enabled, so no external resistor needed.
#   Button reads LOW when pressed, HIGH when released.
# ══════════════════════════════════════════════════════════════════════════════

import time
import threading
import logging

import config

log = logging.getLogger("netwatch.button")

try:
    import RPi.GPIO as GPIO
    GPIO_AVAILABLE = True
except ImportError:
    GPIO_AVAILABLE = False
    log.warning("RPi.GPIO not available — button handler in SIMULATION mode")


class ButtonHandler:
    """
    Interrupt-driven button handler that detects single, long, and triple presses.

    The handler uses GPIO edge detection on both RISING and FALLING edges so it
    can measure how long the button is held. A short timer after each press
    evaluates the press pattern before deciding what action to take.
    """

    # How long to hold for a "long press" (seconds)
    LONG_PRESS_DURATION = 3.0

    # Window in which multiple presses are counted as a sequence (seconds)
    MULTI_PRESS_WINDOW = 2.0

    # Debounce time passed to GPIO (milliseconds)
    DEBOUNCE_MS = 50

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

    def start(self):
        """Register GPIO interrupt and begin listening for button presses."""
        if not GPIO_AVAILABLE:
            log.info("[SIM] Button handler not started (no GPIO)")
            return

        # Set up the button pin with internal pull-up resistor
        # No external resistor needed — pin reads HIGH normally, LOW when pressed
        GPIO.setup(config.BUTTON_PIN, GPIO.IN, pull_up_down=GPIO.PUD_UP)

        # Small delay to let the pin voltage settle before registering edge detection
        time.sleep(0.1)

        try:
            GPIO.add_event_detect(
                config.BUTTON_PIN,
                GPIO.BOTH,                         # Detect both press and release
                callback=self._on_edge,
                bouncetime=self.DEBOUNCE_MS
            )
            log.info(f"Button handler started on GPIO {config.BUTTON_PIN}")
        except RuntimeError as e:
            # Edge detection can fail if the pin is already in use or not ready.
            # Log a warning but allow the monitor to continue — network monitoring
            # is more important than the button, and this can be debugged separately.
            log.warning(
                f"Button edge detection failed: {e} — "
                f"button will be unavailable but monitor continues normally"
            )

    def stop(self):
        """Remove GPIO event detection."""
        if GPIO_AVAILABLE:
            try:
                GPIO.remove_event_detect(config.BUTTON_PIN)
            except Exception:
                pass

    # ── Internal event handling ───────────────────────────────────────────────

    def _on_edge(self, channel):
        """Called by GPIO on both press (FALLING) and release (RISING)."""
        with self._lock:
            if GPIO.input(config.BUTTON_PIN) == GPIO.LOW:
                # Button pressed — record the time
                self.hold_start = time.time()
                self.press_count += 1
                log.debug(f"Button pressed (count: {self.press_count})")

            else:
                # Button released — check if it was a long press
                if self.hold_start is None:
                    return

                hold_duration = time.time() - self.hold_start
                self.hold_start = None

                if hold_duration >= self.LONG_PRESS_DURATION:
                    # Long press detected — act immediately, clear press count
                    log.info(f"Long press detected ({hold_duration:.1f}s) → modem reset")
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

        log.debug(f"Evaluating {count} press(es)")

        if count == 0:
            return
        elif count == 1:
            log.info("Single press → full reset")
            threading.Thread(target=self._do_full_reset, daemon=True).start()
        elif count == 2:
            # Two presses — no defined action, log it
            log.info("Double press detected (no action assigned)")
        elif count >= 3:
            log.info("Triple press → toggling lockout mode")
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
        log.info(f"Lockout mode {status} via button triple-press")

        import alerts
        alerts.send_alert(
            "lockout_changed",
            f"Auto-reset lockout {status} via physical button."
        )
