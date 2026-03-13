# ══════════════════════════════════════════════════════════════════════════════
# NetWatch — relay.py
# Controls the two relay boards that cut/restore power to modem and router.
#
# Hardware notes:
#   - Most single-relay boards are active-LOW: GPIO LOW = relay energized
#   - When relay is energized, the Normally Open (NO) contact closes
#   - Devices should be wired to the NO terminal so they lose power when relay fires
#   - If devices power off when they should be on, check RELAY_ACTIVE_LOW in config.py
# ══════════════════════════════════════════════════════════════════════════════

import time
import logging

import config
import database

log = logging.getLogger("netwatch.relay")

# Try to import GPIO. If unavailable (e.g. not on a Pi), run in simulation mode.
try:
    import RPi.GPIO as GPIO
    GPIO_AVAILABLE = True
except ImportError:
    GPIO_AVAILABLE = False
    log.warning("RPi.GPIO not available — relay module running in SIMULATION mode")


# ══════════════════════════════════════════════════════════════════════════════
# INITIALIZATION
# ══════════════════════════════════════════════════════════════════════════════

def init():
    """
    Set up GPIO pins for both relays.
    Relays default to OFF (devices keep power) on startup.
    Called once at program start from main.py.
    """
    if not GPIO_AVAILABLE:
        log.info("[SIM] GPIO init skipped")
        return

    GPIO.setmode(GPIO.BCM)
    GPIO.setwarnings(False)

    # Initialize both relay pins to OFF state
    # For active-LOW boards, HIGH = relay off = device has power
    off_state = GPIO.HIGH if config.RELAY_ACTIVE_LOW else GPIO.LOW
    GPIO.setup(config.RELAY_MODEM,  GPIO.OUT, initial=off_state)
    GPIO.setup(config.RELAY_ROUTER, GPIO.OUT, initial=off_state)

    log.info(f"Relay GPIO initialized — Modem: GPIO{config.RELAY_MODEM}, Router: GPIO{config.RELAY_ROUTER}")


def cleanup():
    """Release GPIO resources. Called on shutdown."""
    if GPIO_AVAILABLE:
        GPIO.cleanup()
        log.info("GPIO cleaned up")


# ══════════════════════════════════════════════════════════════════════════════
# LOW-LEVEL RELAY CONTROL
# ══════════════════════════════════════════════════════════════════════════════

def _relay_on(pin):
    """
    Energize a relay — cuts power to the connected device.
    'On' means the relay coil is active, NOT that the device has power.
    """
    if GPIO_AVAILABLE:
        state = GPIO.LOW if config.RELAY_ACTIVE_LOW else GPIO.HIGH
        GPIO.output(pin, state)
    log.debug(f"Relay energized: GPIO {pin} (device power CUT)")


def _relay_off(pin):
    """
    De-energize a relay — restores power to the connected device.
    """
    if GPIO_AVAILABLE:
        state = GPIO.HIGH if config.RELAY_ACTIVE_LOW else GPIO.LOW
        GPIO.output(pin, state)
    log.debug(f"Relay de-energized: GPIO {pin} (device power RESTORED)")


# ══════════════════════════════════════════════════════════════════════════════
# HIGH-LEVEL RESET SEQUENCES
# ══════════════════════════════════════════════════════════════════════════════

def cycle_modem(triggered_by="auto"):
    """
    Power cycle the modem only.
    Used when WAN is down but LAN is still up (router is fine, modem is not).

    Sequence:
      1. Cut modem power
      2. Wait POWER_CYCLE_OFF_TIME seconds
      3. Restore modem power
      4. Wait MODEM_BOOT_DELAY for modem to authenticate with ISP
    """
    log.info(f"=== MODEM RESET (triggered by: {triggered_by}) ===")

    _relay_on(config.RELAY_MODEM)
    time.sleep(config.POWER_CYCLE_OFF_TIME)
    _relay_off(config.RELAY_MODEM)

    log.info(f"Modem power restored. Waiting {config.MODEM_BOOT_DELAY}s for ISP authentication...")
    time.sleep(config.MODEM_BOOT_DELAY)

    database.log_reset("modem_only", "Modem power cycle", triggered_by, success=True)
    log.info("Modem reset complete")


def cycle_router(triggered_by="auto"):
    """
    Power cycle the router only.
    Used when LAN and WAN are fine but the WiFi AP (powered via PoE from router)
    is not responding. Cycling the router cuts PoE to the AP, resetting it.

    Sequence:
      1. Cut router power (also kills AP via PoE)
      2. Wait POWER_CYCLE_OFF_TIME seconds
      3. Restore router power
      4. Wait ROUTER_BOOT_DELAY for router and AP to come back up
    """
    log.info(f"=== ROUTER/AP RESET (triggered by: {triggered_by}) ===")

    _relay_on(config.RELAY_ROUTER)
    time.sleep(config.POWER_CYCLE_OFF_TIME)
    _relay_off(config.RELAY_ROUTER)

    log.info(f"Router power restored. Waiting {config.ROUTER_BOOT_DELAY}s for router and AP to boot...")
    time.sleep(config.ROUTER_BOOT_DELAY)

    database.log_reset("router_only", "Router/AP power cycle", triggered_by, success=True)
    log.info("Router/AP reset complete")


def cycle_full(triggered_by="auto", reason="Network down"):
    """
    Full reset: power cycle both modem and router in the correct order.
    Used when LAN is down or both LAN and WAN are unreachable.

    Sequence:
      1. Cut modem power
      2. Wait 2 seconds, then cut router power too
         (staggered so router doesn't try to reconnect to a dead modem)
      3. Wait POWER_CYCLE_OFF_TIME
      4. Restore modem power first
      5. Wait MODEM_BOOT_DELAY for modem to authenticate with ISP
      6. Restore router power
      7. Wait ROUTER_BOOT_DELAY for router and AP to come back up
    """
    log.info(f"=== FULL RESET (triggered by: {triggered_by}) — Reason: {reason} ===")

    # Cut modem first, then router
    _relay_on(config.RELAY_MODEM)
    time.sleep(2)
    _relay_on(config.RELAY_ROUTER)
    time.sleep(config.POWER_CYCLE_OFF_TIME)

    # Restore modem first — must be online before router tries to use it
    _relay_off(config.RELAY_MODEM)
    log.info(f"Modem power restored. Waiting {config.MODEM_BOOT_DELAY}s for ISP authentication...")
    time.sleep(config.MODEM_BOOT_DELAY)

    # Then restore router
    _relay_off(config.RELAY_ROUTER)
    log.info(f"Router power restored. Waiting {config.ROUTER_BOOT_DELAY}s for full boot...")
    time.sleep(config.ROUTER_BOOT_DELAY)

    database.log_reset("full_reset", reason, triggered_by, success=True)
    log.info("Full reset complete")
