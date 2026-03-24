# ==============================================================================
# NetWatch -- backup_notify.py
# Called by backup.sh and backup_db.sh after the backup email is sent.
# Logs the delivery attempt to the alert_deliveries table so it appears in
# Delivery History in the UI.
#
# Usage:
#   python3 backup_notify.py OK   full  "netwatch_backup_20260321.tar.gz.gpg" "recipient@example.com"
#   python3 backup_notify.py OK   db    "netwatch_db_20260321.db.gpg"         "recipient@example.com"
#   python3 backup_notify.py FAIL full  "netwatch_backup_20260321.tar.gz.gpg" "recipient@example.com" "error message"
#   python3 backup_notify.py FAIL db    "netwatch_db_20260321.db.gpg"         "recipient@example.com" "error message"
#
# Arguments:
#   1: status   — OK or FAIL
#   2: type     — full or db
#   3: filename — basename of the backup file (for display in event message)
#   4: address  — email address the backup was sent to (from config.ALERT_TO)
#   5: error    — (optional, FAIL only) error message
#
# Not a web route — invoked directly by shell scripts via python3.
# ==============================================================================

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import alert_subscribers


def main():
    if len(sys.argv) < 5:
        print("Usage: backup_notify.py OK|FAIL full|db FILENAME ADDRESS [ERROR]")
        sys.exit(1)

    status    = sys.argv[1].upper()
    btype     = sys.argv[2].lower()
    filename  = sys.argv[3]
    address   = sys.argv[4]
    error_msg = sys.argv[5] if len(sys.argv) > 5 else None

    success = (status == "OK")

    alert_type = "backup_full" if btype == "full" else "backup_db"
    label      = "Full System Backup" if btype == "full" else "Daily DB Backup"

    event_msg = f"{label}: {filename}"
    if not success and error_msg:
        event_msg += f" — {error_msg}"

    try:
        alert_subscribers.log_delivery(
            alert_type=alert_type,
            alert_event=event_msg,
            subscriber_id=None,   # sent to owner address directly, not via subscriber record
            channel="email",
            address=address,
            success=success,
            error_msg=error_msg if not success else None,
            is_test=False,
        )
        print(f"Backup delivery logged: {alert_type} success={success}")
    except Exception as e:
        print(f"Warning: could not log backup delivery: {e}")
        # Non-fatal — the backup itself succeeded or failed independently


if __name__ == "__main__":
    main()
