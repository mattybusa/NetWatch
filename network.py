# ══════════════════════════════════════════════════════════════════════════════
# NetWatch — network.py
# All network health checking functions: ping, DNS, speedtest.
# Returns structured results that monitor.py uses to make decisions.
#
# Interface-bound checks (v3.3.22+):
#   If LAN_INTERFACE or WIFI_INTERFACE are set in config, pings for those
#   checks are forced out the specified interface via `ping -I <iface>`.
#   If the interface has no IP address, the check fails immediately with a
#   clear log message rather than falling through to a generic ping failure.
#   If the interface config key is blank, behavior is unbound (OS chooses),
#   which preserves backwards compatibility for simple single-interface setups.
# ══════════════════════════════════════════════════════════════════════════════

import subprocess
import socket
import logging
import threading
from datetime import datetime

import config
import database

log = logging.getLogger("netwatch.network")


# ══════════════════════════════════════════════════════════════════════════════
# INTERFACE HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def get_interface_ip(iface):
    """
    Return the first assigned IPv4 address for a network interface, or None.

    Uses `ip addr show <iface>` to inspect the interface. Returns None if:
      - The interface does not exist
      - The interface exists but is down or has no IPv4 assigned

    Args:
        iface: Interface name string, e.g. "eth0" or "wlan0"

    Returns:
        str IP address (e.g. "192.168.100.10") or None
    """
    try:
        result = subprocess.run(
            ["ip", "addr", "show", iface],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode != 0:
            # Interface does not exist
            return None
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet ") and not line.startswith("inet6"):
                # Line format: "inet 192.168.100.10/24 brd ..."
                parts = line.split()
                if len(parts) >= 2:
                    return parts[1].split("/")[0]   # Strip CIDR prefix
        return None   # Interface exists but has no IPv4
    except Exception as e:
        log.debug(f"get_interface_ip({iface}) error: {e}")
        return None


# ══════════════════════════════════════════════════════════════════════════════
# LOW-LEVEL CHECKS
# ══════════════════════════════════════════════════════════════════════════════

def ping(host, count=3, timeout=4, interface=None):
    """
    Ping a host and return (success, avg_latency_ms, packet_loss_pct).

    Args:
        host:      IP address or hostname to ping
        count:     Number of ping packets to send
        timeout:   Seconds to wait for each reply
        interface: If set, forces packets out this interface via -I flag.
                   Caller is responsible for verifying the interface is up
                   before calling with interface set.

    Returns:
        Tuple: (bool success, float|None latency_ms, float packet_loss_pct)
    """
    try:
        cmd = ["ping", "-c", str(count), "-W", str(timeout), host]
        if interface:
            cmd = ["ping", "-c", str(count), "-W", str(timeout), "-I", interface, host]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=(timeout * count) + 5
        )

        if result.returncode == 0:
            # Parse average latency from the summary line
            # Linux ping output: rtt min/avg/max/mdev = 10.123/12.456/15.789/1.234 ms
            for line in result.stdout.splitlines():
                if "avg" in line or "rtt" in line:
                    try:
                        parts = line.split("/")
                        if len(parts) >= 5:
                            avg_ms = float(parts[4])
                            return True, avg_ms, 0.0
                    except (ValueError, IndexError):
                        pass
            # Ping succeeded but couldn't parse latency
            return True, None, 0.0
        else:
            # Try to parse packet loss percentage from output
            for line in result.stdout.splitlines():
                if "packet loss" in line:
                    try:
                        loss = float(line.split("%")[0].split()[-1])
                        return False, None, loss
                    except (ValueError, IndexError):
                        pass
            return False, None, 100.0

    except subprocess.TimeoutExpired:
        log.debug(f"Ping timeout: {host}" + (f" via {interface}" if interface else ""))
        return False, None, 100.0
    except Exception as e:
        log.debug(f"Ping error ({host})" + (f" via {interface}" if interface else "") + f": {e}")
        return False, None, 100.0


def check_dns():
    """
    Verify DNS resolution is working by resolving a known hostname.
    Uses Google's DNS server directly to avoid testing our own router's DNS.

    Returns: bool — True if resolution succeeded
    """
    try:
        # Resolve against Google's DNS directly
        socket.setdefaulttimeout(10)
        socket.getaddrinfo(config.DNS_TEST_HOST, 80)
        return True
    except socket.gaierror:
        return False
    except Exception as e:
        log.debug(f"DNS check error: {e}")
        return False


# ══════════════════════════════════════════════════════════════════════════════
# INTERFACE-AWARE PING HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _bound_ping(host, iface, count, label):
    """
    Pre-flight check an interface then run a bound ping.

    Checks that the interface has an IP before attempting the ping.
    If the interface has no IP, returns (False, None, 100.0) and logs a
    clear message distinguishing "no IP" from "ping failed".

    Args:
        host:   Target IP to ping
        iface:  Interface name to bind to (e.g. "eth0")
        count:  Ping packet count
        label:  Log label for this check (e.g. "LAN", "WiFi")

    Returns:
        Tuple: (bool success, float|None latency_ms, float packet_loss_pct)
    """
    ip = get_interface_ip(iface)
    if ip is None:
        log.warning(
            f"{label} interface {iface} has no IP address — marking {label} down"
        )
        return False, None, 100.0

    log.debug(f"{label} ping via {iface} ({ip}) → {host}")
    return ping(host, count=count, interface=iface)


# ══════════════════════════════════════════════════════════════════════════════
# COMPOSITE HEALTH CHECK
# ══════════════════════════════════════════════════════════════════════════════

def check_network():
    """
    Run a full network health check and return a structured status dictionary.

    Check order (inside-out):
      1. LAN gateway  — can we reach our router?
      2. WAN primary  — can we reach the internet? (Google DNS 8.8.8.8)
      3. WAN secondary — cross-check with second target (8.8.4.4)
      4. WiFi gateway — can we reach the AP gateway?
      5. DNS          — can we resolve hostnames?

    Interface binding (v3.3.22+):
      - LAN check: bound to LAN_INTERFACE if configured, else unbound
      - WiFi check: bound to WIFI_INTERFACE if configured, else unbound
      - WAN checks: always unbound (testing internet reachability, not a
        specific interface — default route is the correct path)

    The 'healthy' flag is True only when LAN, WAN, and DNS all pass.
    The 'degraded' flag is True when connected but quality is poor.

    Returns:
        dict with keys: timestamp, lan_ok, wan_ok, wifi_ok, dns_ok,
                        latency_ms, packet_loss, healthy, degraded
    """
    log.debug("Running network health check...")

    lan_iface  = getattr(config, "LAN_INTERFACE",  "").strip()
    wifi_iface = getattr(config, "WIFI_INTERFACE", "").strip()

    # ── LAN check ─────────────────────────────────────────────────────────────
    if lan_iface:
        lan_ok, lan_ms, lan_loss = _bound_ping(
            config.LAN_GATEWAY, lan_iface, count=3, label="LAN"
        )
    else:
        lan_ok, lan_ms, lan_loss = ping(config.LAN_GATEWAY, count=3)

    # ── WAN checks (always unbound — testing internet, not a specific NIC) ────
    wan_ok,  wan_ms,  wan_loss  = ping(config.WAN_PRIMARY,   count=4)
    wan2_ok, wan2_ms, wan2_loss = ping(config.WAN_SECONDARY, count=2)

    # Accept WAN as up if either external target responds
    wan_success  = wan_ok or wan2_ok
    wan_latency  = wan_ms if wan_ms else wan2_ms
    wan_pkt_loss = wan_loss if wan_ok else wan2_loss

    # ── WiFi check ────────────────────────────────────────────────────────────
    wifi_gateway = getattr(config, "WIFI_GATEWAY", "").strip()

    if not wifi_gateway:
        # No WiFi gateway configured — skip entirely
        wifi_ok = None
    elif wifi_iface:
        wifi_ok, _, _ = _bound_ping(
            wifi_gateway, wifi_iface, count=2, label="WiFi"
        )
    else:
        wifi_ok, _, _ = ping(wifi_gateway, count=2)

    # ── DNS resolution check ──────────────────────────────────────────────────
    dns_ok = check_dns()

    # ── Derive overall latency and health ─────────────────────────────────────
    latency = wan_latency if wan_latency else lan_ms

    # Healthy = all critical paths working (LAN + WAN + DNS)
    healthy = lan_ok and wan_success and dns_ok

    # Degraded = connected but quality is poor (high latency or packet loss)
    degraded = (
        healthy and (
            (wan_pkt_loss is not None and wan_pkt_loss > config.PACKET_LOSS_WARN) or
            (latency is not None and latency > config.LATENCY_WARN_MS)
        )
    )

    status = {
        "timestamp":   datetime.now(),
        "lan_ok":      lan_ok,
        "wan_ok":      wan_success,
        "wifi_ok":     wifi_ok,
        "dns_ok":      dns_ok,
        "latency_ms":  round(latency, 1) if latency else None,
        "packet_loss": round(wan_pkt_loss, 1) if wan_pkt_loss is not None else 0.0,
        "healthy":     healthy,
        "degraded":    degraded,
    }

    # Persist to database
    database.log_health(
        lan_ok, wan_success, wifi_ok, dns_ok,
        status["latency_ms"], status["packet_loss"]
    )

    return status


# ══════════════════════════════════════════════════════════════════════════════
# SPEEDTEST
# ══════════════════════════════════════════════════════════════════════════════

def run_speedtest():
    """
    Run a speedtest and store results in the database.
    This is called in a background thread so it doesn't block the monitor loop.
    Speedtest can take 30-60 seconds to complete.

    Returns: (ping_ms, download_mbps, upload_mbps) or (None, None, None) on failure
    """
    log.info("Starting speedtest (running in background)...")
    try:
        import speedtest as st

        s = st.Speedtest()
        s.get_best_server()
        s.download(threads=None)
        s.upload(threads=None)

        results  = s.results.dict()
        ping_ms  = results["ping"]
        dl_mbps  = results["download"] / 1_000_000   # Convert bps to Mbps
        ul_mbps  = results["upload"]   / 1_000_000
        server   = results["server"]["name"]

        database.log_speedtest(ping_ms, dl_mbps, ul_mbps, server)

        log.info(
            f"Speedtest complete: ↓{dl_mbps:.1f} Mbps  ↑{ul_mbps:.1f} Mbps  "
            f"ping {ping_ms:.0f}ms  ({server})"
        )
        return ping_ms, dl_mbps, ul_mbps

    except ImportError:
        log.error("speedtest-cli not installed. Run: pip install speedtest-cli")
        return None, None, None
    except Exception as e:
        log.error(f"Speedtest failed: {e}")
        return None, None, None


def run_speedtest_async():
    """
    Launch a speedtest in a background thread.
    Returns immediately — results are written to DB when complete.
    """
    thread = threading.Thread(target=run_speedtest, name="speedtest", daemon=True)
    thread.start()


