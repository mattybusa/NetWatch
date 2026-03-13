# ══════════════════════════════════════════════════════════════════════════════
# NetWatch — updater.py
# Handles file uploads, backups, syntax validation, service restarts,
# and rollback. Used by the File Update Manager page in the web dashboard.
#
# Safety features:
#   - Python files are syntax-checked before being applied
#   - Previous version is backed up as filename.bak before overwriting
#   - Upload history is logged to the database
#   - Smart service detection: only restarts what's needed
# ══════════════════════════════════════════════════════════════════════════════

import os
import shutil
import subprocess
import logging
import sqlite3
import py_compile
import tempfile
from datetime import datetime

NETWATCH_DIR = os.path.dirname(os.path.abspath(__file__))

log = logging.getLogger("netwatch.updater")

# Base directory where NetWatch files live
NETWATCH_DIR = NETWATCH_DIR
DB_PATH      = os.path.join(NETWATCH_DIR, "netwatch.db")

# ── Service restart mapping ───────────────────────────────────────────────────
# Maps filename patterns to which services need restarting after an update.
# 'both' means both netwatch-monitor and netwatch-web.

SERVICE_MAP = {
    # Monitor daemon files
    "main.py":          "monitor",
    "monitor.py":       "monitor",
    "network.py":       "monitor",
    "relay.py":         "monitor",
    "button.py":        "monitor",

    # Shared by both services
    "alerts.py":        "both",   # monitor daemon + webapp test emails
    "alert_subscribers.py": "both",  # monitor daemon + webapp subscriber management
    "database.py":      "both",
    "auth.py":          "both",   # webapp auth + monitor imports via alerts

    # Web app files
    "webapp.py":        "web",
    "updater.py":       "web",
    "configeditor.py":  "web",
    "patcher.py":       "web",
    "certmanager.py":   "web",
    "config_validator.py": "web",
    "security_log.py":  "web",

    # Config — both services read it
    "config.py":        "both",

    # Templates and static assets — web only
    ".html":            "web",    # Matched by extension
    ".css":             "web",
    ".js":              "web",
}


def get_service_for_file(filename):
    """
    Determine which service(s) need restarting after updating a given file.
    Returns: 'monitor', 'web', 'both', or None (no restart needed).
    """
    basename = os.path.basename(filename)

    # Check exact filename match first
    if basename in SERVICE_MAP:
        return SERVICE_MAP[basename]

    # Check by file extension
    ext = os.path.splitext(basename)[1].lower()
    if ext in SERVICE_MAP:
        return SERVICE_MAP[ext]

    return None


def get_target_path(filename):
    """
    Determine the correct full path for a file being uploaded.
    HTML files go into templates/, CSS/JS into static/, others into root.
    """
    basename = os.path.basename(filename)
    ext      = os.path.splitext(basename)[1].lower()

    if ext == ".html":
        return os.path.join(NETWATCH_DIR, "templates", basename)
    elif ext in (".css", ".js"):
        return os.path.join(NETWATCH_DIR, "static", basename)
    else:
        return os.path.join(NETWATCH_DIR, basename)


def validate_python(content_bytes):
    """
    Syntax-check Python source code without executing it.
    Returns (True, None) if valid, (False, error_message) if not.
    """
    try:
        # Write to a temp file and run py_compile on it
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as tmp:
            tmp.write(content_bytes)
            tmp_path = tmp.name

        py_compile.compile(tmp_path, doraise=True)
        os.unlink(tmp_path)
        return True, None

    except py_compile.PyCompileError as e:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass
        # Extract just the useful part of the error message
        msg = str(e).replace(tmp_path, "<uploaded file>")
        return False, msg
    except Exception as e:
        return False, str(e)


def backup_file(target_path):
    """
    Create a .bak copy of the existing file before overwriting.
    Returns the backup path, or None if the original didn't exist.
    """
    if not os.path.exists(target_path):
        return None

    backup_path = target_path + ".bak"
    try:
        shutil.copy2(target_path, backup_path)
        log.info(f"Backup created: {backup_path}")
        return backup_path
    except Exception as e:
        log.warning(f"Could not create backup of {target_path}: {e}")
        return None


def apply_file(filename, content_bytes, uploaded_by="web"):
    """
    Validate, backup, write, and restart services for an uploaded file.

    Args:
        filename:      Original filename from the upload
        content_bytes: Raw file content as bytes
        uploaded_by:   Username who performed the upload (for audit log)

    Returns:
        dict with keys: success (bool), message (str), service_restarted (str|None),
                        backup_created (bool), syntax_error (str|None)
    """
    basename    = os.path.basename(filename)
    target_path = get_target_path(filename)
    ext         = os.path.splitext(basename)[1].lower()

    log.info(f"Applying update: {basename} → {target_path} (uploaded by {uploaded_by})")

    # ── Step 1: Validate Python syntax ──────────────────────────────────────
    if ext == ".py":
        valid, syntax_error = validate_python(content_bytes)
        if not valid:
            log.warning(f"Syntax error in {basename}: {syntax_error}")
            _log_upload(basename, uploaded_by, success=False, notes=f"Syntax error: {syntax_error}")
            return {
                "success":           False,
                "message":           f"Syntax error — file was NOT applied",
                "syntax_error":      syntax_error,
                "backup_created":    False,
                "service_restarted": None,
            }

    # ── Step 2: Back up existing file ────────────────────────────────────────
    backup_path   = backup_file(target_path)
    backup_created = backup_path is not None

    # ── Step 3: Write new file ───────────────────────────────────────────────
    try:
        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        with open(target_path, "wb") as f:
            f.write(content_bytes)
        log.info(f"File written: {target_path} ({len(content_bytes)} bytes)")
    except Exception as e:
        log.error(f"Failed to write {target_path}: {e}")
        _log_upload(basename, uploaded_by, success=False, notes=str(e))
        return {
            "success":           False,
            "message":           f"Failed to write file: {e}",
            "syntax_error":      None,
            "backup_created":    backup_created,
            "service_restarted": None,
        }

    # ── Step 4: Restart services ─────────────────────────────────────────────
    service      = get_service_for_file(basename)
    restarted    = []
    restart_errs = []

    if service in ("monitor", "both"):
        ok, err = _restart_service("netwatch-monitor")
        if ok:
            restarted.append("netwatch-monitor")
        else:
            restart_errs.append(f"monitor: {err}")

    if service in ("web", "both"):
        ok, err = _restart_service("netwatch-web")
        if ok:
            restarted.append("netwatch-web")
        else:
            restart_errs.append(f"web: {err}")

    service_label = ", ".join(restarted) if restarted else "none"
    notes = f"Services restarted: {service_label}"
    if restart_errs:
        notes += f" | Restart errors: {'; '.join(restart_errs)}"

    _log_upload(basename, uploaded_by, success=True, notes=notes)

    msg = f"'{basename}' applied successfully."
    if restarted:
        msg += f" Restarted: {service_label}."
    if restart_errs:
        msg += f" Warning — restart errors: {'; '.join(restart_errs)}"

    return {
        "success":           True,
        "message":           msg,
        "syntax_error":      None,
        "backup_created":    backup_created,
        "service_restarted": service_label,
    }


def rollback_file(filename):
    """
    Restore the .bak version of a file and restart affected services.
    Returns (True, message) or (False, error).
    """
    target_path = get_target_path(filename)
    backup_path = target_path + ".bak"

    if not os.path.exists(backup_path):
        return False, f"No backup found for '{filename}'"

    try:
        shutil.copy2(backup_path, target_path)
        log.info(f"Rolled back {filename} from {backup_path}")
    except Exception as e:
        return False, f"Rollback failed: {e}"

    service = get_service_for_file(os.path.basename(filename))
    restarted = []

    if service in ("monitor", "both"):
        ok, _ = _restart_service("netwatch-monitor")
        if ok:
            restarted.append("netwatch-monitor")

    if service in ("web", "both"):
        ok, _ = _restart_service("netwatch-web")
        if ok:
            restarted.append("netwatch-web")

    return True, f"Rolled back to previous version. Restarted: {', '.join(restarted) or 'none'}"


def _restart_service(service_name):
    """
    Restart a systemd service. Returns (True, None) or (False, error_message).
    Uses a short delay so the web response can complete before the web service restarts.
    """
    try:
        if service_name == "netwatch-web":
            # Restart web service in background after a short delay
            # so the HTTP response can finish being sent first
            subprocess.Popen(
                ["bash", "-c", f"sleep 2 && sudo systemctl restart {service_name}"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        else:
            result = subprocess.run(
                ["sudo", "systemctl", "restart", service_name],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode != 0:
                return False, result.stderr.strip()

        log.info(f"Service restarted: {service_name}")
        return True, None
    except subprocess.TimeoutExpired:
        return False, "Restart timed out"
    except Exception as e:
        return False, str(e)


def get_file_info(filename):
    """
    Return metadata about a file currently on disk.
    Used by the upload page to show what's currently deployed.
    """
    target_path = get_target_path(filename)
    backup_path = target_path + ".bak"

    info = {
        "filename":      filename,
        "path":          target_path,
        "exists":        os.path.exists(target_path),
        "size_bytes":    None,
        "modified":      None,
        "has_backup":    os.path.exists(backup_path),
        "backup_modified": None,
    }

    if info["exists"]:
        stat = os.stat(target_path)
        info["size_bytes"] = stat.st_size
        info["modified"]   = datetime.fromtimestamp(stat.st_mtime).isoformat()

    if info["has_backup"]:
        stat = os.stat(backup_path)
        info["backup_modified"] = datetime.fromtimestamp(stat.st_mtime).isoformat()

    return info


def get_upload_history(limit=50):
    """Return the upload/update history log from the database."""
    try:
        _ensure_upload_log_table()
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT * FROM upload_log ORDER BY timestamp DESC LIMIT ?
        """, (limit,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as e:
        log.error(f"Failed to get upload history: {e}")
        return []


def _log_upload(filename, uploaded_by, success, notes=""):
    """Write an entry to the upload history log."""
    try:
        _ensure_upload_log_table()
        conn = sqlite3.connect(DB_PATH)
        conn.execute("""
            INSERT INTO upload_log (timestamp, filename, uploaded_by, success, notes)
            VALUES (?, ?, ?, ?, ?)
        """, (datetime.now().isoformat(), filename, uploaded_by, int(success), notes))
        conn.commit()
        conn.close()
    except Exception as e:
        log.error(f"Failed to log upload: {e}")


def _ensure_upload_log_table():
    """Create upload_log table if it doesn't exist."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS upload_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            filename    TEXT NOT NULL,
            uploaded_by TEXT,
            success     INTEGER DEFAULT 1,
            notes       TEXT
        )
    """)
    conn.commit()
    conn.close()


DEV_DOCS_DIR = os.path.join(NETWATCH_DIR, "dev_docs")


def _ensure_dev_docs_dir():
    """Create dev_docs directory if it doesn't exist."""
    os.makedirs(DEV_DOCS_DIR, exist_ok=True)


def list_dev_docs():
    """
    List all files in the dev_docs directory with metadata.
    Returns a list of dicts with filename, size_bytes, modified.
    """
    _ensure_dev_docs_dir()
    files = []
    for fname in sorted(os.listdir(DEV_DOCS_DIR)):
        fpath = os.path.join(DEV_DOCS_DIR, fname)
        if not os.path.isfile(fpath):
            continue
        stat = os.stat(fpath)
        files.append({
            "filename": fname,
            "size_bytes": stat.st_size,
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
        })
    return files


def save_dev_doc(filename, content_bytes):
    """
    Save a file to dev_docs. Accepts any file type — no syntax check, no service restart.
    Returns (True, None) or (False, error_message).
    """
    _ensure_dev_docs_dir()
    # Basic safety: no path traversal
    basename = os.path.basename(filename)
    if not basename or basename.startswith("."):
        return False, "Invalid filename"
    target = os.path.join(DEV_DOCS_DIR, basename)
    try:
        with open(target, "wb") as f:
            f.write(content_bytes)
        log.info(f"Dev doc saved: {target} ({len(content_bytes)} bytes)")
        return True, None
    except Exception as e:
        return False, str(e)


def delete_dev_doc(filename):
    """
    Delete a file from dev_docs.
    Returns (True, None) or (False, error_message).
    """
    _ensure_dev_docs_dir()
    basename = os.path.basename(filename)
    target = os.path.join(DEV_DOCS_DIR, basename)
    if not os.path.exists(target):
        return False, f"File not found: {basename}"
    try:
        os.remove(target)
        log.info(f"Dev doc deleted: {target}")
        return True, None
    except Exception as e:
        return False, str(e)


def rename_dev_doc(old_filename, new_filename):
    """
    Rename a file in dev_docs.
    Returns (True, None) or (False, error_message).
    """
    _ensure_dev_docs_dir()
    old_base = os.path.basename(old_filename)
    new_base = os.path.basename(new_filename)
    if not old_base or not new_base or new_base.startswith("."):
        return False, "Invalid filename"
    old_path = os.path.join(DEV_DOCS_DIR, old_base)
    new_path = os.path.join(DEV_DOCS_DIR, new_base)
    if not os.path.exists(old_path):
        return False, f"File not found: {old_base}"
    if os.path.exists(new_path):
        return False, f"A file named '{new_base}' already exists"
    try:
        os.rename(old_path, new_path)
        log.info(f"Dev doc renamed: {old_base} → {new_base}")
        return True, None
    except Exception as e:
        return False, str(e)


def get_dev_doc_path(filename):
    """Return the full path to a dev_doc file, or None if it doesn't exist / is unsafe."""
    _ensure_dev_docs_dir()
    basename = os.path.basename(filename)
    target = os.path.join(DEV_DOCS_DIR, basename)
    if os.path.isfile(target):
        return target
    return None


def list_netwatch_files():
    """
    List all deployed NetWatch files with their metadata.
    Returns a structured dict of categories → files.
    """
    categories = {
        "Core Python": [
            "main.py", "monitor.py", "network.py", "relay.py",
            "button.py", "database.py", "alerts.py", "config.py",
            "alert_subscribers.py", "security_log.py", "auth.py",
            "config_schema.py", "config_validator.py", "certmanager.py",
            "patcher.py",
        ],
        "Web App":     ["webapp.py", "updater.py", "configeditor.py"],
        "Templates":   [],
        "Static":      [],
    }

    # Discover templates — exclude .bak files (handled by snapshot system)
    tmpl_dir = os.path.join(NETWATCH_DIR, "templates")
    if os.path.isdir(tmpl_dir):
        categories["Templates"] = sorted([
            f for f in os.listdir(tmpl_dir)
            if os.path.isfile(os.path.join(tmpl_dir, f))
            and not f.endswith(".bak")
        ])

    # Discover static files — exclude .bak files
    static_dir = os.path.join(NETWATCH_DIR, "static")
    if os.path.isdir(static_dir):
        categories["Static"] = sorted([
            f for f in os.listdir(static_dir)
            if os.path.isfile(os.path.join(static_dir, f))
            and not f.endswith(".bak")
        ])

    result = {}
    for category, files in categories.items():
        result[category] = [get_file_info(f) for f in files]

    return result
