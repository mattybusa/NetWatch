# NetWatch — Network Monitor & Auto-Reset System

NetWatch monitors your home network and automatically power-cycles your modem
and router when it detects an outage. It runs on a Raspberry Pi with two relay
channels and provides a web dashboard for monitoring and control.

## Features

- Continuous network health monitoring (LAN, WAN, WiFi, DNS)
- Automatic modem/router power cycling on outage detection
- Web dashboard with real-time status, charts, and history
- Speedtest integration
- Email alerts via Gmail
- Role-based access (Admin, Operator, Monitor, Guest)
- Encrypted backups with scheduled delivery

## Requirements

- Raspberry Pi (any model with GPIO — tested on Pi 4)
- 2-channel relay board (active HIGH or LOW)
- Python 3.9+
- Internet connection for initial setup

## Quick Install

### 1. Prepare your Pi
Flash a fresh Raspberry Pi OS (Lite or Desktop) to your SD card.
Boot up and ensure you have SSH access.

### 2. Copy files to your Pi
```bash
scp netwatch_distributable.zip pi@<your-pi-ip>:~/
```

### 3. Unzip and run the installer
```bash
unzip netwatch_distributable.zip
cd netwatch_distributable
bash install.sh
```

The installer will:
- Install all required system packages
- Set up a Python virtual environment
- Install NetWatch as a system service
- Start the web dashboard

### 4. Complete setup via the web wizard
Open a browser and navigate to:
```
https://<your-pi-ip>:5000
```

You'll be guided through a setup wizard to configure:
- Network gateway IPs
- GPIO relay pins
- Email alerts (optional)
- Admin password

### 5. Generate SSL certificates
After setup, go to **Admin → Certificate Management** to generate
a self-signed certificate for HTTPS access.

## Backup & Recovery

NetWatch includes encrypted backup support using GPG public key encryption.

To enable backups:
1. Install [Gpg4win](https://gpg4win.org) on your PC
2. Generate a key pair in Kleopatra
3. Export your public key as a `.asc` file
4. Import it on the Pi: `gpg --import your-key.asc`
5. Configure scheduled backups from **Admin → Full System Backup**

## Default Credentials

- Username: `admin`
- Password: set during setup wizard

## Hardware Wiring

```
Pi GPIO 17 → Relay 1 IN → controls Modem power
Pi GPIO 27 → Relay 2 IN → controls Router power
Pi GPIO 22 → Pushbutton (optional manual reset)
Pi GND     → Relay GND, Button GND
Pi 5V      → Relay VCC (check your board)
```

Relay NC (Normally Closed) terminals connect to the power leads of your
modem and router. This means devices stay powered even if the Pi fails.

## Support

This is an open-source project. Configure it to suit your network setup
using the built-in Config Editor at **Admin → Configuration Editor**.
