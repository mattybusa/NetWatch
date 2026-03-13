# ==============================================================================
# NetWatch -- pkg_update_alert.py
# Called by pkg_update.sh. Handles three modes:
#
#   LOG  DRY_TMP_FILE
#       Parse apt dry-run output and print a readable package list to stdout.
#       Used to write the package list into pkg_update.log.
#
#   OK   SUMMARY  [DRY_TMP_FILE]
#       Fire a pkg_update alert with the summary and optional package detail.
#
#   FAILED  MESSAGE
#       Fire a pkg_update alert with a failure message.
#
# Not a web route -- invoked directly by pkg_update.sh via python3.
# ==============================================================================

import sys
import os
import re

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import alerts


def parse_dry_run(dry_file):
    """Parse apt-get upgrade --dry-run output into readable version strings.
    Each Inst line looks like:
      Inst curl [7.88.1-10+deb12u5] (7.88.1-10+deb12u8 Raspberry Pi Foundation:stable [arm64])
    Returns list of strings like '  curl: 7.88.1-10+deb12u5 -> 7.88.1-10+deb12u8'
    """
    lines = []
    if not dry_file or not os.path.exists(dry_file):
        return lines
    with open(dry_file) as f:
        for line in f:
            line = line.strip()
            if not line.startswith("Inst "):
                continue
            parts   = line.split()
            name    = parts[1]
            old_m   = re.search(r'\[([^\]]+)\]', line)
            new_m   = re.search(r'\((\S+)', line)
            old_ver = old_m.group(1) if old_m else ""
            new_ver = new_m.group(1).rstrip(")") if new_m else ""
            if old_ver:
                lines.append("  {}: {} -> {}".format(name, old_ver, new_ver))
            else:
                lines.append("  {}: (new install) {}".format(name, new_ver))
    return lines


def main():
    if len(sys.argv) < 2:
        print("Usage: pkg_update_alert.py LOG|OK|FAILED [args...]")
        sys.exit(1)

    mode = sys.argv[1].upper()

    if mode == "LOG":
        # Print parsed package list to stdout (captured into log by shell)
        dry_file  = sys.argv[2] if len(sys.argv) > 2 else ""
        pkg_lines = parse_dry_run(dry_file)
        if pkg_lines:
            print("Packages changed:")
            for line in pkg_lines:
                print(line)
        return

    if mode == "FAILED":
        message = sys.argv[2] if len(sys.argv) > 2 else "Pi package update failed."
        alerts.send_alert("pkg_update", message)
        return

    if mode == "OK":
        summary   = sys.argv[2] if len(sys.argv) > 2 else "Pi package update complete."
        dry_file  = sys.argv[3] if len(sys.argv) > 3 else ""
        pkg_lines = parse_dry_run(dry_file)
        if pkg_lines:
            detail  = "\n".join(pkg_lines)
            message = "{}\n\nPackages changed:\n{}".format(summary, detail)
        else:
            message = summary
        alerts.send_alert("pkg_update", message)
        return

    print("Unknown mode: {}".format(mode))
    sys.exit(1)


if __name__ == "__main__":
    main()
