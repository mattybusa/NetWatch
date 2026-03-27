# ══════════════════════════════════════════════════════════════════════════════
# NetWatch — configeditor.py
# Reads config.py as structured data for the web config editor,
# and writes changes back safely (validates types, backs up first).
#
# Field definitions are driven by config_schema.py — do not add fields here.
# To add a new config key, add it to config_schema.py with all required fields
# (key, label, type, section, group, description, sensitive, ui_hidden, and
# optionally min/max). It will appear in the Config Editor automatically.
# ══════════════════════════════════════════════════════════════════════════════

import os
import re
import shutil
import logging
import structlog
from datetime import datetime

NETWATCH_DIR = os.path.dirname(os.path.abspath(__file__))

log = structlog.get_logger().bind(service="web")

CONFIG_PATH = os.path.join(NETWATCH_DIR, "config.py")
BACKUP_PATH = os.path.join(NETWATCH_DIR, "config.py.bak")


# ── Build FIELDS from config_schema ──────────────────────────────────────────
# FIELDS is the list of config entries shown in the Config Editor UI.
# It is derived from CONFIG_SCHEMA at import time, excluding ui_hidden entries.
# Each entry exposes: key, label, type, section, desc, sensitive, and
# optionally min/max for int fields.

def _build_fields():
    from config_schema import CONFIG_SCHEMA
    fields = []
    for entry in CONFIG_SCHEMA:
        if entry.get("ui_hidden", False):
            continue
        field = {
            "key":       entry["key"],
            "label":     entry["label"],
            "type":      entry["type"],
            "section":   entry["section"],
            "desc":      entry["description"],
            "sensitive": entry.get("sensitive", False),
        }
        if "min" in entry:
            field["min"] = entry["min"]
        if "max" in entry:
            field["max"] = entry["max"]
        if "allowed_values" in entry:
            field["allowed_values"] = entry["allowed_values"]
        if "day_names" in entry:
            field["day_names"] = entry["day_names"]
        fields.append(field)
    return fields

FIELDS = _build_fields()


def read_config():
    """
    Read config.py and return a dict of {key: current_value}.
    Values are returned as Python native types (bool, int, str).
    """
    values = {}
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            content = f.read()

        for field in FIELDS:
            key   = field["key"]
            ftype = field["type"]

            # Match: KEY = value  (ignoring comment lines and inline comments)
            pattern = rf"^(?!#){key}\s*=\s*(.+?)(?:\s*#.*)?$"
            match   = re.search(pattern, content, re.MULTILINE)

            if not match:
                values[key] = None
                continue

            raw = match.group(1).strip()

            try:
                if ftype == "bool":
                    values[key] = raw == "True"
                elif ftype == "int":
                    values[key] = int(raw)
                elif ftype in ("str", "password"):
                    # Strip surrounding quotes
                    values[key] = raw.strip('"').strip("'")
                else:
                    values[key] = raw
            except (ValueError, AttributeError):
                values[key] = raw

    except FileNotFoundError:
        log.error("config.py not found", path=CONFIG_PATH)
    except Exception as e:
        log.error("Failed to read config.py", error=str(e))

    return values


def save_config(new_values, saved_by="web"):
    """
    Write updated values back to config.py.
    Backs up the current config first.
    Validates types and ranges before writing.

    Args:
        new_values: dict of {key: new_value_string} from form submission
        saved_by:   username who saved (for log)

    Returns:
        (True, None) on success or (False, error_message)
    """
    # ── Validate all values first ────────────────────────────────────────────
    errors = []
    validated = {}

    for field in FIELDS:
        key   = field["key"]
        ftype = field["type"]

        if key not in new_values:
            continue

        raw = str(new_values[key]).strip()

        try:
            if ftype == "bool":
                validated[key] = raw in ("True", "true", "1", "on", "yes")

            elif ftype == "int":
                val = int(raw)
                if "min" in field and val < field["min"]:
                    errors.append(f"{field['label']}: minimum value is {field['min']}")
                elif "max" in field and val > field["max"]:
                    errors.append(f"{field['label']}: maximum value is {field['max']}")
                else:
                    validated[key] = val

            elif ftype in ("str", "password"):
                if "allowed_values" in field and raw not in field["allowed_values"]:
                    errors.append(
                        f"{field['label']}: must be one of: {', '.join(field['allowed_values'])}"
                    )
                else:
                    validated[key] = raw

        except ValueError:
            errors.append(f"{field['label']}: must be a valid {ftype}")

    if errors:
        return False, "Validation errors:\n• " + "\n• ".join(errors)

    # ── Back up current config ────────────────────────────────────────────────
    try:
        if os.path.exists(CONFIG_PATH):
            shutil.copy2(CONFIG_PATH, BACKUP_PATH)
            log.info("Config backed up", path=BACKUP_PATH)
    except Exception as e:
        log.warning("Could not back up config", error=str(e))

    # ── Read current file content ─────────────────────────────────────────────
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception as e:
        return False, f"Could not read config.py: {e}"

    # ── Apply each change using regex replacement ─────────────────────────────
    for key, value in validated.items():
        # Find the field definition to know its type
        field = next((f for f in FIELDS if f["key"] == key), None)
        if not field:
            continue

        ftype = field["type"]

        # Format the value for Python source
        if ftype == "bool":
            py_value = "True" if value else "False"
        elif ftype == "int":
            py_value = str(value)
        elif ftype in ("str", "password"):
            # Use double quotes, escape any existing double quotes
            escaped = str(value).replace('"', '\\"')
            py_value = f'"{escaped}"'
        else:
            py_value = str(value)

        # Replace: KEY = old_value  →  KEY = new_value
        # Excludes comment lines (starting with #), preserves inline comments
        pattern = rf"^(?!#)({key}\s*=\s*)[^\n#]*(#?[^\n]*)$"
        replacement = rf"\g<1>{py_value}  \g<2>"
        new_content = re.sub(pattern, replacement, content, flags=re.MULTILINE)

        if new_content == content:
            # Check whether the pattern matched at all
            if re.search(pattern, content, flags=re.MULTILINE):
                # Pattern matched but replacement produced identical content —
                # value was already set to the submitted value. Not an error.
                log.debug("Config key already at submitted value, no change needed", key=key)
            else:
                # Pattern didn't match at all — key missing or format unexpected
                log.warning("Could not find/replace key in config.py", key=key)
        else:
            content = new_content

    # ── Write updated config ──────────────────────────────────────────────────
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            f.write(content)
        log.info("config.py saved", saved_by=saved_by, values_updated=len(validated))
        return True, None
    except Exception as e:
        log.error("Failed to write config.py", error=str(e))
        return False, f"Failed to write config.py: {e}"


def get_sections():
    """Return the config fields organized by section for the template."""
    sections = {}
    for field in FIELDS:
        section = field["section"]
        if section not in sections:
            sections[section] = []
        sections[section].append(field)
    return sections


def rollback_config():
    """Restore config.py from the backup. Returns (True, msg) or (False, err)."""
    if not os.path.exists(BACKUP_PATH):
        return False, "No backup config found"
    try:
        shutil.copy2(BACKUP_PATH, CONFIG_PATH)
        log.info("config.py restored from backup")
        return True, "Config restored from backup"
    except Exception as e:
        return False, f"Rollback failed: {e}"
