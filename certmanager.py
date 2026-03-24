# ══════════════════════════════════════════════════════════════════════════════
# NetWatch — certmanager.py
# Certificate management: reads cert info, serves backup, regenerates server cert.
# ══════════════════════════════════════════════════════════════════════════════

import os
import subprocess
import logging
import structlog
from datetime import datetime

NETWATCH_DIR = os.path.dirname(os.path.abspath(__file__))

log = structlog.get_logger().bind(service="web")

CERTS_DIR   = os.path.join(NETWATCH_DIR, "certs")
CA_DIR      = os.path.join(CERTS_DIR, "ca")
CA_KEY      = os.path.join(CA_DIR,   "netwatch-ca.key")
CA_CERT     = os.path.join(CA_DIR,   "netwatch-ca.crt")
SERVER_KEY  = os.path.join(CERTS_DIR, "netwatch.key")
SERVER_CERT = os.path.join(CERTS_DIR, "netwatch.crt")
BACKUP_ZIP  = os.path.join(CERTS_DIR, "netwatch-ca-backup.zip")
CA_COPY     = os.path.join(CERTS_DIR, "netwatch-ca.crt")
HTTPS_CONF  = os.path.join(NETWATCH_DIR, "https.conf")


def https_enabled():
    """Return True if HTTPS is configured and cert files exist."""
    if not os.path.exists(HTTPS_CONF):
        return False
    if not os.path.exists(SERVER_CERT) or not os.path.exists(SERVER_KEY):
        return False
    return True


def get_ssl_context():
    """
    Return (cert_path, key_path) for Flask's ssl_context if HTTPS is enabled,
    or None if running in plain HTTP mode.
    """
    if https_enabled():
        return (SERVER_CERT, SERVER_KEY)
    return None


def get_cert_info():
    """
    Read certificate metadata using openssl and return a summary dict.
    """
    info = {
        "https_active":  https_enabled(),
        "cert_exists":   os.path.exists(SERVER_CERT),
        "ca_exists":     os.path.exists(CA_CERT),
        "backup_exists": os.path.exists(BACKUP_ZIP),
        "cert_expires":  None,
        "ca_expires":    None,
        "ip_count":      0,
        "sans":          [],
    }

    if info["cert_exists"]:
        try:
            result = subprocess.run(
                ["openssl", "x509", "-in", SERVER_CERT, "-noout",
                 "-enddate", "-ext", "subjectAltName"],
                capture_output=True, text=True
            )
            for line in result.stdout.splitlines():
                if line.startswith("notAfter="):
                    raw = line.replace("notAfter=", "").strip()
                    try:
                        dt = datetime.strptime(raw, "%b %d %H:%M:%S %Y %Z")
                        info["cert_expires"] = dt.strftime("%Y-%m-%d")
                    except ValueError:
                        info["cert_expires"] = raw
                if "IP Address:" in line:
                    ips = [p.strip().replace("IP Address:", "").strip()
                           for p in line.split(",") if "IP Address:" in p]
                    info["sans"].extend(ips)
                    info["ip_count"] += len(ips)
        except Exception as e:
            log.warning("Could not read cert info", error=str(e))

    if info["ca_exists"]:
        try:
            result = subprocess.run(
                ["openssl", "x509", "-in", CA_CERT, "-noout", "-enddate"],
                capture_output=True, text=True
            )
            for line in result.stdout.splitlines():
                if line.startswith("notAfter="):
                    raw = line.replace("notAfter=", "").strip()
                    try:
                        dt = datetime.strptime(raw, "%b %d %H:%M:%S %Y %Z")
                        info["ca_expires"] = dt.strftime("%Y-%m-%d")
                    except ValueError:
                        info["ca_expires"] = raw
        except Exception as e:
            log.warning("Could not read CA cert info", error=str(e))

    return info


def regenerate_server_cert():
    """
    Regenerate the server certificate using the existing CA.
    Does NOT touch the CA key or cert — devices don't need to reinstall anything.
    Returns (True, message) or (False, error).
    """
    if not os.path.exists(CA_KEY) or not os.path.exists(CA_CERT):
        return False, "CA key or certificate not found. Run generate_certs.sh first."

    try:
        pi_ip    = _get_pi_ips()
        hostname = subprocess.run(["hostname"], capture_output=True, text=True).stdout.strip()

        # Generate new server key
        subprocess.run(
            ["openssl", "genrsa", "-out", SERVER_KEY, "2048"],
            capture_output=True, check=True
        )
        os.chmod(SERVER_KEY, 0o600)

        # Generate CSR
        csr_path = os.path.join(CERTS_DIR, "netwatch.csr")
        subprocess.run([
            "openssl", "req", "-new",
            "-key", SERVER_KEY,
            "-out", csr_path,
            "-subj", "/C=US/ST=Home/L=HomeNetwork/O=NetWatch/CN=netwatch.home"
        ], capture_output=True, check=True)

        # Build SAN extension
        ext_path = os.path.join(CERTS_DIR, "netwatch.ext")
        san_lines = ["DNS.1 = netwatch", "DNS.2 = netwatch.home",
                     f"DNS.3 = {hostname}", f"DNS.4 = {hostname}.local"]
        for i, ip in enumerate(pi_ip, 1):
            san_lines.append(f"IP.{i}  = {ip}")
        san_lines.append("IP.99 = 127.0.0.1")

        with open(ext_path, "w") as f:
            f.write("authorityKeyIdentifier=keyid,issuer\n")
            f.write("basicConstraints=CA:FALSE\n")
            f.write("keyUsage=digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment\n")
            f.write("extendedKeyUsage=serverAuth\n")
            f.write("subjectAltName=@alt_names\n\n[alt_names]\n")
            f.write("\n".join(san_lines) + "\n")

        # Sign with CA
        subprocess.run([
            "openssl", "x509", "-req",
            "-in", csr_path,
            "-CA", CA_CERT,
            "-CAkey", CA_KEY,
            "-CAcreateserial",
            "-out", SERVER_CERT,
            "-days", "3650",
            "-extfile", ext_path
        ], capture_output=True, check=True)

        os.chmod(SERVER_CERT, 0o644)
        os.unlink(csr_path)
        os.unlink(ext_path)

        log.info("Server certificate regenerated successfully")
        return True, "Server certificate regenerated. NetWatch is restarting..."

    except subprocess.CalledProcessError as e:
        log.error("Certificate regeneration failed", stderr=str(e.stderr))
        return False, f"OpenSSL error: {e.stderr.decode() if e.stderr else str(e)}"
    except Exception as e:
        log.error("Certificate regeneration failed", error=str(e))
        return False, str(e)


def _get_pi_ips():
    """Return a list of all non-loopback IPv4 addresses on this Pi."""
    try:
        result = subprocess.run(
            ["hostname", "-I"], capture_output=True, text=True
        )
        return [ip for ip in result.stdout.strip().split() if ip and ip != "127.0.0.1"]
    except Exception:
        return []
