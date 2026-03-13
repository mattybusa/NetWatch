#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
# NetWatch — generate_certs.sh
# Generates a private CA and a server certificate for NetWatch HTTPS.
#
# Run this ONCE on the Pi:
#   bash ~/netwatch/scripts/generate_certs.sh
#
# What it creates:
#   ~/netwatch/certs/ca/netwatch-ca.key   — root CA private key (protect this)
#   ~/netwatch/certs/ca/netwatch-ca.crt   — root CA certificate (install on devices)
#   ~/netwatch/certs/netwatch.key         — server private key
#   ~/netwatch/certs/netwatch.crt         — server certificate (signed by CA)
#   ~/netwatch/certs/netwatch-ca.crt      — copy of CA cert for easy web download
# ══════════════════════════════════════════════════════════════════════════════

set -e

CERTS_DIR="$HOME/netwatch/certs"
CA_DIR="$CERTS_DIR/ca"
PI_IP=$(hostname -I | awk '{print $1}')
HOSTNAME=$(hostname)

echo ""
echo "══════════════════════════════════════════════════════"
echo "  NetWatch Certificate Authority Setup"
echo "══════════════════════════════════════════════════════"
echo ""
echo "This will create a private CA and HTTPS certificate for NetWatch."
echo "Detected Pi IP: $PI_IP"
echo "Detected hostname: $HOSTNAME"
echo ""

# ── Prompt for backup password ────────────────────────────────────────────────
echo "Choose a password for your CA backup archive."
echo "You'll need this if you ever need to restore from backup."
echo "(This is NOT your NetWatch login password — it's only for the backup file)"
echo ""
read -s -p "Backup password: " BACKUP_PASS
echo ""
read -s -p "Confirm backup password: " BACKUP_PASS2
echo ""

if [ "$BACKUP_PASS" != "$BACKUP_PASS2" ]; then
    echo "Passwords do not match. Exiting."
    exit 1
fi

if [ -z "$BACKUP_PASS" ]; then
    echo "Password cannot be empty. Exiting."
    exit 1
fi

echo ""
echo "Creating certificate directories..."
mkdir -p "$CA_DIR"
chmod 700 "$CA_DIR"
chmod 700 "$CERTS_DIR"

# ── Generate root CA key and certificate ─────────────────────────────────────
echo "Generating root CA key..."
openssl genrsa -out "$CA_DIR/netwatch-ca.key" 4096 2>/dev/null
chmod 600 "$CA_DIR/netwatch-ca.key"

echo "Generating root CA certificate (valid 20 years)..."
openssl req -new -x509 \
    -key "$CA_DIR/netwatch-ca.key" \
    -out "$CA_DIR/netwatch-ca.crt" \
    -days 7300 \
    -subj "/C=US/ST=Home/L=HomeNetwork/O=NetWatch Home CA/CN=NetWatch Root CA" \
    2>/dev/null

chmod 644 "$CA_DIR/netwatch-ca.crt"

# Copy CA cert to certs root for easy web serving
cp "$CA_DIR/netwatch-ca.crt" "$CERTS_DIR/netwatch-ca.crt"

echo "✓ Root CA created"

# ── Generate server key and CSR ───────────────────────────────────────────────
echo "Generating server key..."
openssl genrsa -out "$CERTS_DIR/netwatch.key" 2048 2>/dev/null
chmod 600 "$CERTS_DIR/netwatch.key"

echo "Generating certificate signing request..."
openssl req -new \
    -key "$CERTS_DIR/netwatch.key" \
    -out "$CERTS_DIR/netwatch.csr" \
    -subj "/C=US/ST=Home/L=HomeNetwork/O=NetWatch/CN=netwatch.home" \
    2>/dev/null

# ── Create SAN extension file ─────────────────────────────────────────────────
# Subject Alternative Names allow the cert to be valid for multiple IPs/hostnames
cat > "$CERTS_DIR/netwatch.ext" << EXTEOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage=serverAuth
subjectAltName=@alt_names

[alt_names]
DNS.1 = netwatch
DNS.2 = netwatch.home
DNS.3 = netwatch.local
DNS.4 = $HOSTNAME
DNS.5 = $HOSTNAME.local
IP.1  = $PI_IP
IP.2  = 127.0.0.1
EXTEOF

# Add wlan0 IP if different from primary
WLAN_IP=$(ip addr show wlan0 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
if [ -n "$WLAN_IP" ] && [ "$WLAN_IP" != "$PI_IP" ]; then
    echo "IP.3  = $WLAN_IP" >> "$CERTS_DIR/netwatch.ext"
    echo "Detected WiFi IP: $WLAN_IP — added to certificate"
fi

ETH_IP=$(ip addr show eth0 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
if [ -n "$ETH_IP" ] && [ "$ETH_IP" != "$PI_IP" ] && [ "$ETH_IP" != "$WLAN_IP" ]; then
    echo "IP.4  = $ETH_IP" >> "$CERTS_DIR/netwatch.ext"
    echo "Detected wired IP: $ETH_IP — added to certificate"
fi

# ── Sign server certificate with CA ──────────────────────────────────────────
echo "Signing server certificate (valid 10 years)..."
openssl x509 -req \
    -in "$CERTS_DIR/netwatch.csr" \
    -CA "$CA_DIR/netwatch-ca.crt" \
    -CAkey "$CA_DIR/netwatch-ca.key" \
    -CAcreateserial \
    -out "$CERTS_DIR/netwatch.crt" \
    -days 3650 \
    -extfile "$CERTS_DIR/netwatch.ext" \
    2>/dev/null

chmod 644 "$CERTS_DIR/netwatch.crt"

# Clean up CSR and ext (not needed after signing)
rm -f "$CERTS_DIR/netwatch.csr" "$CERTS_DIR/netwatch.ext"

echo "✓ Server certificate created and signed"

# ── Create encrypted backup archive ──────────────────────────────────────────
echo "Creating encrypted CA backup..."
BACKUP_PATH="$CERTS_DIR/netwatch-ca-backup.zip"

# Create a temp dir with just the CA files
TMPDIR=$(mktemp -d)
cp "$CA_DIR/netwatch-ca.key" "$TMPDIR/"
cp "$CA_DIR/netwatch-ca.crt" "$TMPDIR/"
cat > "$TMPDIR/README.txt" << READMEEOF
NetWatch CA Backup
==================
Generated: $(date)
Pi hostname: $HOSTNAME
Pi IP: $PI_IP

Contents:
  netwatch-ca.key  — Root CA private key (KEEP THIS SAFE)
  netwatch-ca.crt  — Root CA certificate

To restore:
  1. Copy netwatch-ca.key and netwatch-ca.crt to ~/netwatch/certs/ca/
  2. Re-run generate_certs.sh to regenerate the server certificate
READMEEOF

cd "$TMPDIR"
zip -q --password "$BACKUP_PASS" "$BACKUP_PATH" netwatch-ca.key netwatch-ca.crt README.txt
cd -
rm -rf "$TMPDIR"
chmod 600 "$BACKUP_PATH"

echo "✓ Encrypted backup created at $BACKUP_PATH"

# ── Update Flask to use HTTPS ─────────────────────────────────────────────────
echo ""
echo "Updating NetWatch configuration for HTTPS..."

# Write HTTPS config to a separate file that webapp.py will read
cat > "$HOME/netwatch/https.conf" << CONFEOF
# NetWatch HTTPS configuration
# Generated by generate_certs.sh on $(date)
SSL_CERT=$CERTS_DIR/netwatch.crt
SSL_KEY=$CERTS_DIR/netwatch.key
SSL_ENABLED=true
CONFEOF

echo "✓ HTTPS configuration written"

# ── Restart services ──────────────────────────────────────────────────────────
echo "Restarting NetWatch web service..."
sudo systemctl restart netwatch-web

echo ""
echo "══════════════════════════════════════════════════════"
echo "  Setup Complete!"
echo "══════════════════════════════════════════════════════"
echo ""
echo "  NetWatch is now available at:"
echo "  https://$PI_IP:5000"
if [ -n "$WLAN_IP" ] && [ "$WLAN_IP" != "$PI_IP" ]; then
echo "  https://$WLAN_IP:5000"
fi
echo ""
echo "  Next steps:"
echo "  1. Open https://$PI_IP:5000 in your browser"
echo "  2. Click Advanced → Proceed (one-time warning)"
echo "  3. Go to Admin → Certificates to install the CA on your devices"
echo "     OR download it directly from:"
echo "     https://$PI_IP:5000/ca-cert"
echo ""
echo "  CA backup saved to: $BACKUP_PATH"
echo "  Keep your backup password safe — you'll need it to restore."
echo ""
