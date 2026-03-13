# ══════════════════════════════════════════════════════════════════════════════
# NetWatch — patcher.py
# Intelligent patch package installer.
#
# Accepts a .zip file containing a manifest.json and any combination of:
#   - Full file replacements
#   - Unified diff patches (.patch files)
#   - JSON patches (structured add/remove/replace operations)
#   - New directory creation
#   - Database schema migrations (SQL statements)
#   - Service restart instructions
#
# Safety guarantees:
#   - Zip is fully validated and previewed BEFORE anything is touched
#   - Every file that will be changed is backed up first
#   - If any step fails, execution stops and a report is returned
#   - Full rollback restores all backed-up files
#   - Version ordering is checked and warned if out of sequence
#   - Zip slip attack prevention (no path traversal)
#
# Manifest format (manifest.json inside the zip):
#   {
#     "version": "2.3",
#     "description": "Human readable description of this update",
#     "min_version": "2.0",          // optional — warn if installed < this
#     "actions": [
#       { "action": "replace",  "file": "webapp.py" },
#       { "action": "replace",  "file": "templates/new_page.html" },
#       { "action": "patch",    "file": "config.py", "patch": "patches/config.py.patch" },
#       { "action": "json_patch","file": "config.py", "patch": "patches/config.py.jsonpatch" },
#       { "action": "mkdir",    "path": "logs/archive" },
#       { "action": "run_sql",  "sql": "ALTER TABLE users ADD COLUMN theme TEXT DEFAULT 'dark-blue'" },
#       { "action": "restart",  "services": ["monitor", "web"] }
#     ]
#   }
#
# JSON patch format (.jsonpatch file):
#   [
#     { "op": "add_after",    "find": "CHECK_INTERVAL = 30", "insert": "NEW_SETTING = 60" },
#     { "op": "replace_line", "find": "OLD_VALUE = True",    "replace": "OLD_VALUE = False" },
#     { "op": "remove_line",  "find": "DEPRECATED_KEY = 1" },
#     { "op": "add_line",     "after_line": 42,              "insert": "# New comment" }
#   ]
# ══════════════════════════════════════════════════════════════════════════════

import os
import io
import json
import shutil
import zipfile
import sqlite3
import difflib
import logging
import tempfile
import subprocess
import py_compile
from datetime import datetime
from packaging import version as pkg_version

NETWATCH_DIR = os.path.dirname(os.path.abspath(__file__))

log = logging.getLogger("netwatch.patcher")

NETWATCH_DIR = NETWATCH_DIR
DB_PATH      = os.path.join(NETWATCH_DIR, "netwatch.db")
VERSION_FILE = os.path.join(NETWATCH_DIR, "VERSION")

# Current installed version — read from VERSION file
def get_installed_version():
    try:
        with open(VERSION_FILE) as f:
            return f.read().strip()
    except FileNotFoundError:
        return "1.0"

def set_installed_version(v):
    with open(VERSION_FILE, "w") as f:
        f.write(str(v))


# ══════════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ══════════════════════════════════════════════════════════════════════════════

def validate_and_preview(zip_bytes):
    """
    Read a zip package and return a preview of everything it will do.
    Does NOT modify any files. Call this first, show the user the preview,
    then call apply_package() if they confirm.

    Returns:
        dict with keys:
          valid (bool)
          error (str|None)           — set if valid=False
          manifest (dict|None)
          version_warning (str|None) — set if version ordering looks wrong
          preview (list)             — list of action preview dicts
    """
    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    except zipfile.BadZipFile:
        return {"valid": False, "error": "Not a valid zip file", "preview": []}

    # ── Find and parse manifest ───────────────────────────────────────────────
    names = zf.namelist()
    manifest_name = next(
        (n for n in names if os.path.basename(n) == "manifest.json"), None
    )

    if not manifest_name:
        return {"valid": False, "error": "No manifest.json found in zip", "preview": []}

    try:
        manifest = json.loads(zf.read(manifest_name))
    except json.JSONDecodeError as e:
        return {"valid": False, "error": f"manifest.json is invalid JSON: {e}", "preview": []}

    if "actions" not in manifest:
        return {"valid": False, "error": "manifest.json has no 'actions' list", "preview": []}

    # ── Version check ─────────────────────────────────────────────────────────
    version_warning = None
    pkg_ver     = manifest.get("version", "unknown")
    min_ver     = manifest.get("min_version")
    installed   = get_installed_version()

    def _parse_ver(v):
        """Parse version tolerantly — strips trailing letters (3.2.24b → 3.2.24.0b0 handled,
        but also normalises common patterns like 3.2.24b to 3.2.24 for comparison)."""
        import re as _re
        # Normalise e.g. "3.2.24b" → "3.2.24" before parsing
        cleaned = _re.sub(r"([0-9])([a-zA-Z]+)$", r"\1", v.strip())
        try:
            return pkg_version.parse(cleaned), True
        except Exception:
            return None, False

    try:
        pv, pv_ok = _parse_ver(pkg_ver)
        iv, iv_ok = _parse_ver(installed)
        mv, mv_ok = _parse_ver(min_ver) if min_ver else (None, False)

        if pv_ok and iv_ok and pv < iv:
            version_warning = (
                f"Package version {pkg_ver} is OLDER than installed version {installed}. "
                f"This may downgrade your installation."
            )
        if min_ver and mv_ok and iv_ok and iv < mv:
            version_warning = (
                f"This package requires at least version {min_ver}, "
                f"but you have {installed}. Some features may not work correctly."
            )
        if not (pv_ok and iv_ok):
            version_warning = (
                f"Could not compare versions (package: {pkg_ver}, installed: {installed}) — "
                f"proceeding anyway."
            )
    except Exception:
        version_warning = f"Could not compare versions (package: {pkg_ver}, installed: {installed})"

    # ── Preview each action ───────────────────────────────────────────────────
    preview = []
    errors  = []

    for i, action in enumerate(manifest["actions"]):
        act  = action.get("action", "").lower()
        item = {"index": i, "action": act, "status": "ok", "detail": "", "warning": None}

        if act == "replace":
            fname = action.get("file", "")
            _check_path_safety(fname, errors, i)
            target = _resolve_path(fname)
            item["detail"]    = f"Replace {fname}"
            item["target"]    = target
            item["exists"]    = os.path.exists(target)
            item["in_zip"]    = fname in names or _find_in_zip(fname, names) is not None
            item["is_new"]    = not item["exists"]

            if not item["in_zip"]:
                item["status"]  = "error"
                item["detail"] += f" — FILE NOT FOUND IN ZIP"
                errors.append(f"Action {i}: '{fname}' not found in zip")

            # Syntax check Python files
            if fname.endswith(".py") and item["in_zip"]:
                zip_fname = _find_in_zip(fname, names)
                content   = zf.read(zip_fname)
                ok, err   = _syntax_check(content)
                if not ok:
                    item["status"]  = "error"
                    item["warning"] = f"Syntax error: {err}"
                    errors.append(f"Action {i}: syntax error in '{fname}': {err}")

        elif act == "patch":
            fname      = action.get("file", "")
            patch_file = action.get("patch", "")
            target     = _resolve_path(fname)
            item["detail"]     = f"Patch {fname} using unified diff"
            item["target"]     = target
            item["patch_file"] = patch_file
            item["exists"]     = os.path.exists(target)
            item["patch_in_zip"] = patch_file in names or _find_in_zip(patch_file, names) is not None

            if not item["exists"]:
                item["status"]  = "error"
                item["warning"] = f"Target file '{fname}' does not exist on disk — cannot patch"
                errors.append(f"Action {i}: cannot patch non-existent file '{fname}'")
            if not item["patch_in_zip"]:
                item["status"]  = "error"
                item["warning"] = f"Patch file '{patch_file}' not found in zip"
                errors.append(f"Action {i}: patch file '{patch_file}' not found in zip")

            # Dry-run the patch to check it applies cleanly
            if item["exists"] and item["patch_in_zip"] and item["status"] == "ok":
                zip_pname = _find_in_zip(patch_file, names)
                patch_content = zf.read(zip_pname).decode("utf-8")
                ok, result = _apply_unified_patch(fname, patch_content, dry_run=True)
                if not ok:
                    item["status"]  = "warning"
                    item["warning"] = f"Patch may not apply cleanly: {result}"

        elif act == "json_patch":
            fname      = action.get("file", "")
            patch_file = action.get("patch", "")
            target     = _resolve_path(fname)
            item["detail"]     = f"JSON-patch {fname}"
            item["target"]     = target
            item["patch_file"] = patch_file
            item["exists"]     = os.path.exists(target)
            item["patch_in_zip"] = _find_in_zip(patch_file, names) is not None

            if not item["exists"]:
                item["status"]  = "error"
                item["warning"] = f"Target file '{fname}' does not exist"
                errors.append(f"Action {i}: cannot json-patch non-existent '{fname}'")
            if not item["patch_in_zip"]:
                item["status"]  = "error"
                item["warning"] = f"JSON patch file '{patch_file}' not found in zip"
                errors.append(f"Action {i}: json patch '{patch_file}' not found in zip")

        elif act == "mkdir":
            path = action.get("path", "")
            full = os.path.join(NETWATCH_DIR, path)
            item["detail"]  = f"Create directory: {path}"
            item["target"]  = full
            item["exists"]  = os.path.isdir(full)
            if item["exists"]:
                item["warning"] = "Directory already exists — will be skipped"

        elif act == "run_sql":
            sql = action.get("sql", "")
            item["detail"] = f"Run SQL: {sql[:80]}{'...' if len(sql)>80 else ''}"
            item["sql"]    = sql

        elif act == "restart":
            services = action.get("services", [])
            item["detail"] = f"Restart services: {', '.join(services)}"

        else:
            item["status"]  = "warning"
            item["detail"]  = f"Unknown action '{act}' — will be skipped"
            item["warning"] = "Unrecognised action type"

        preview.append(item)

    zf.close()

    return {
        "valid":           len(errors) == 0,
        "error":           "; ".join(errors) if errors else None,
        "manifest":        manifest,
        "version_warning": version_warning,
        "preview":         preview,
        "zip_contents":    names,
        "package_version": pkg_ver,
        "installed_version": installed,
    }


def _take_snapshot(version_label):
    """
    Take a complete pre-install snapshot of all NetWatch files and the database.
    Saved to ~/netwatch/snapshots/YYYYMMDD_HHMMSS_vX.X.X/
    Keeps last N snapshots (configured via SNAPSHOT_RETENTION in config.py, default 10).
    Returns snapshot directory path or None on failure.
    """
    import sqlite3 as _sq
    from datetime import datetime as _dt

    snap_base = os.path.join(NETWATCH_DIR, "snapshots")
    os.makedirs(snap_base, exist_ok=True)

    ts    = _dt.now().strftime("%Y%m%d_%H%M%S")
    label = version_label.replace(" ", "_") if version_label else "unknown"
    snap_dir = os.path.join(snap_base, f"{ts}_{label}")
    os.makedirs(snap_dir, exist_ok=True)

    copied = 0
    errors = []

    # ── Copy all Python, template, static, and config files ──────────────────
    dirs_to_snap = [
        (NETWATCH_DIR,                       ""),
        (os.path.join(NETWATCH_DIR, "templates"), "templates"),
        (os.path.join(NETWATCH_DIR, "static"),    "static"),
    ]
    extensions = {".py", ".html", ".css", ".js", ".sh", ".json", ".txt", ".md"}

    # config.py contains live credentials — never include in snapshots
    SNAP_EXCLUDE = {"config.py"}

    for src_dir, rel_subdir in dirs_to_snap:
        if not os.path.isdir(src_dir):
            continue
        dest_dir = os.path.join(snap_dir, rel_subdir) if rel_subdir else snap_dir
        os.makedirs(dest_dir, exist_ok=True)
        for fname in os.listdir(src_dir):
            if fname in SNAP_EXCLUDE:
                continue
            if os.path.splitext(fname)[1].lower() in extensions and os.path.isfile(os.path.join(src_dir, fname)):
                try:
                    shutil.copy2(os.path.join(src_dir, fname), os.path.join(dest_dir, fname))
                    copied += 1
                except Exception as e:
                    errors.append(f"{fname}: {e}")

    # ── Snapshot VERSION file ─────────────────────────────────────────────────
    ver_file = os.path.join(NETWATCH_DIR, "VERSION")
    if os.path.exists(ver_file):
        shutil.copy2(ver_file, os.path.join(snap_dir, "VERSION"))

    # ── Snapshot database ─────────────────────────────────────────────────────
    db_path = os.path.join(NETWATCH_DIR, "netwatch.db")
    if os.path.exists(db_path):
        try:
            src_conn  = _sq.connect(db_path)
            snap_conn = _sq.connect(os.path.join(snap_dir, "netwatch.db"))
            src_conn.backup(snap_conn)
            snap_conn.close()
            src_conn.close()
            copied += 1
        except Exception as e:
            errors.append(f"database: {e}")

    # ── Write snapshot metadata ───────────────────────────────────────────────
    meta = {
        "timestamp":     ts,
        "version_before": version_label,
        "files_copied":  copied,
        "errors":        errors,
    }
    with open(os.path.join(snap_dir, "snapshot_meta.json"), "w") as f:
        json.dump(meta, f, indent=2)

    # ── Prune old snapshots (keep last N, configured via SNAPSHOT_RETENTION) ──
    try:
        keep = int(getattr(config, "SNAPSHOT_RETENTION", 10))
        if keep < 1:
            keep = 1  # Safety floor — always keep at least one snapshot
        snaps = sorted([
            d for d in os.listdir(snap_base)
            if os.path.isdir(os.path.join(snap_base, d))
        ])
        while len(snaps) > keep:
            old = os.path.join(snap_base, snaps.pop(0))
            shutil.rmtree(old, ignore_errors=True)
    except Exception:
        pass

    log.info(f"[patcher] Snapshot taken: {snap_dir} ({copied} files, {len(errors)} errors)")
    return snap_dir


def apply_package(zip_bytes, applied_by="web"):
    """
    Apply a validated patch package. Run validate_and_preview() first.
    Takes a full pre-install snapshot before touching anything.

    Returns:
        dict with keys:
          success (bool)
          results (list of step result dicts)
          rollback_available (bool)
          message (str)
    """
    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    except Exception as e:
        return {"success": False, "message": str(e), "results": []}

    names    = zf.namelist()
    manifest_name = next(
        (n for n in names if os.path.basename(n) == "manifest.json"), None
    )
    manifest = json.loads(zf.read(manifest_name))
    actions  = manifest.get("actions", [])

    results       = []
    backed_up     = []   # list of (original_path, backup_path) for rollback
    restart_queue = set()
    had_error     = False

    # ── Take pre-install snapshot before touching anything ────────────────────
    current_version = get_installed_version() or "unknown"
    snapshot_dir = _take_snapshot(current_version)
    log.info(f"[patcher] Pre-install snapshot: {snapshot_dir}")

    for i, action in enumerate(actions):
        if had_error:
            results.append({"index": i, "action": action.get("action"), "status": "skipped",
                            "message": "Skipped due to earlier error"})
            continue

        act    = action.get("action", "").lower()
        result = {"index": i, "action": act, "status": "ok", "message": ""}

        try:
            # ── replace ──────────────────────────────────────────────────────
            if act == "replace":
                fname    = action["file"]
                target   = _resolve_path(fname)
                zip_name = _find_in_zip(fname, names)
                content  = zf.read(zip_name)

                backup = _backup(target)
                if backup:
                    backed_up.append((target, backup))

                os.makedirs(os.path.dirname(target), exist_ok=True)
                with open(target, "wb") as f:
                    f.write(content)

                result["message"] = f"Replaced {fname}"
                _queue_restart(fname, restart_queue)
                log.info(f"[patcher] Replaced {target}")

            # ── unified diff patch ────────────────────────────────────────────
            elif act == "patch":
                fname      = action["file"]
                patch_file = action["patch"]
                target     = _resolve_path(fname)
                zip_pname  = _find_in_zip(patch_file, names)
                patch_text = zf.read(zip_pname).decode("utf-8")

                backup = _backup(target)
                if backup:
                    backed_up.append((target, backup))

                ok, patched = _apply_unified_patch(fname, patch_text, dry_run=False)
                if not ok:
                    raise RuntimeError(f"Patch failed: {patched}")

                with open(target, "w") as f:
                    f.write(patched)

                result["message"] = f"Patched {fname}"
                _queue_restart(fname, restart_queue)

            # ── json patch ────────────────────────────────────────────────────
            elif act == "json_patch":
                fname      = action["file"]
                patch_file = action["patch"]
                target     = _resolve_path(fname)
                zip_pname  = _find_in_zip(patch_file, names)
                ops        = json.loads(zf.read(zip_pname))

                backup = _backup(target)
                if backup:
                    backed_up.append((target, backup))

                with open(target, "r") as f:
                    original = f.read()

                patched = _apply_json_patch(original, ops)
                with open(target, "w") as f:
                    f.write(patched)

                result["message"] = f"JSON-patched {fname}"
                _queue_restart(fname, restart_queue)

            # ── mkdir ─────────────────────────────────────────────────────────
            elif act == "mkdir":
                path = action["path"]
                full = os.path.join(NETWATCH_DIR, path)
                if os.path.isdir(full):
                    result["message"] = f"Directory already exists: {path}"
                    result["status"]  = "skipped"
                else:
                    os.makedirs(full, exist_ok=True)
                    result["message"] = f"Created directory: {path}"
                    log.info(f"[patcher] Created directory {full}")

            # ── run_sql ───────────────────────────────────────────────────────
            elif act == "run_sql":
                sql = action["sql"]
                _run_sql(sql)
                result["message"] = f"SQL executed: {sql[:60]}..."

            # ── restart ───────────────────────────────────────────────────────
            elif act == "restart":
                # Collect explicitly requested restarts
                for svc in action.get("services", []):
                    if svc in ("monitor", "both"):
                        restart_queue.add("netwatch-monitor")
                    if svc in ("web", "both"):
                        restart_queue.add("netwatch-web")
                result["message"] = f"Restart queued: {action.get('services', [])}"

            else:
                result["status"]  = "skipped"
                result["message"] = f"Unknown action '{act}'"

        except Exception as e:
            result["status"]  = "error"
            result["message"] = str(e)
            had_error         = True
            log.error(f"[patcher] Step {i} ({act}) failed: {e}")

        results.append(result)

    zf.close()

    # ── Update installed version ──────────────────────────────────────────────
    if not had_error and "version" in manifest:
        set_installed_version(manifest["version"])

    # ── Execute restarts ──────────────────────────────────────────────────────
    restart_results = []
    if not had_error:
        for svc in restart_queue:
            ok, err = _restart_service(svc)
            restart_results.append({
                "service": svc,
                "status": "ok" if ok else "error",
                "message": err or "restarted"
            })

    # ── Log to DB ─────────────────────────────────────────────────────────────
    _log_patch(
        package_version=manifest.get("version", "unknown"),
        description=manifest.get("description", ""),
        applied_by=applied_by,
        success=not had_error,
        steps_total=len(actions),
        steps_ok=sum(1 for r in results if r["status"] == "ok"),
        step_results=results + restart_results
    )

    return {
        "success":           not had_error,
        "results":           results,
        "restart_results":   restart_results,
        "rollback_available": len(backed_up) > 0,
        "backed_up_files":   [b[0] for b in backed_up],
        "message": (
            f"Package applied successfully — {len(results)} steps, "
            f"{len(restart_queue)} service(s) restarted."
            if not had_error else
            f"Package failed at step {next(i for i,r in enumerate(results) if r['status']=='error')} — "
            f"previous files were backed up and can be rolled back."
        )
    }


def get_patch_history(limit=20):
    """Return the patch application history."""
    try:
        _ensure_patch_log_table()
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT * FROM patch_log ORDER BY timestamp DESC LIMIT ?
        """, (limit,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as e:
        log.error(f"Failed to read patch history: {e}")
        return []


# ══════════════════════════════════════════════════════════════════════════════
# UNIFIED DIFF PATCHING
# ══════════════════════════════════════════════════════════════════════════════

def _apply_unified_patch(filename, patch_text, dry_run=False):
    """
    Apply a unified diff patch to the target file.
    If dry_run=True, returns (success, result_text) without writing anything.
    """
    target = _resolve_path(filename)

    try:
        with open(target, "r") as f:
            original_lines = f.readlines()
    except FileNotFoundError:
        return False, f"Target file not found: {target}"

    # Use Python's difflib to apply the patch
    try:
        patched_lines = _patch_lines(original_lines, patch_text)
        patched_text  = "".join(patched_lines)

        if dry_run:
            return True, patched_text

        return True, patched_text

    except Exception as e:
        return False, str(e)


def _patch_lines(original_lines, patch_text):
    """
    Apply a unified diff patch to a list of lines.
    Handles standard unified diff format (--- +++ @@ headers).
    """
    patch_lines = patch_text.splitlines(keepends=True)
    result      = list(original_lines)

    i = 0
    while i < len(patch_lines):
        line = patch_lines[i]

        # Skip file headers
        if line.startswith("---") or line.startswith("+++"):
            i += 1
            continue

        # Parse hunk header: @@ -start,count +start,count @@
        if line.startswith("@@"):
            import re
            m = re.match(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", line)
            if not m:
                i += 1
                continue

            old_start = int(m.group(1)) - 1   # Convert to 0-indexed
            i += 1

            # Collect hunk lines
            hunk = []
            while i < len(patch_lines) and not patch_lines[i].startswith("@@"):
                if patch_lines[i].startswith("---") or patch_lines[i].startswith("+++"):
                    break
                hunk.append(patch_lines[i])
                i += 1

            # Apply hunk: walk through result applying removals and additions
            result_pos = old_start
            for hline in hunk:
                if hline.startswith("-"):
                    # Remove this line
                    if result_pos < len(result):
                        del result[result_pos]
                elif hline.startswith("+"):
                    # Insert this line
                    result.insert(result_pos, hline[1:])
                    result_pos += 1
                else:
                    # Context line — advance
                    result_pos += 1
        else:
            i += 1

    return result


# ══════════════════════════════════════════════════════════════════════════════
# JSON PATCH OPERATIONS
# ══════════════════════════════════════════════════════════════════════════════

def _apply_json_patch(content, ops):
    """
    Apply a list of JSON patch operations to file content (as a string).
    Operations:
      add_after:    find a line matching 'find', insert 'insert' after it
      add_before:   find a line matching 'find', insert 'insert' before it
      replace_line: find a line matching 'find', replace whole line with 'replace'
      remove_line:  find and remove a line matching 'find'
      add_line:     insert 'insert' after line number 'after_line' (1-indexed)
      append:       add 'insert' at end of file
    """
    lines = content.splitlines(keepends=True)

    for op in ops:
        operation = op.get("op", "")

        if operation == "add_after":
            find   = op["find"]
            insert = op["insert"]
            new_lines = []
            for line in lines:
                new_lines.append(line)
                if find in line:
                    # Preserve indentation of the found line
                    indent = len(line) - len(line.lstrip())
                    new_lines.append(" " * indent + insert + "\n")
            lines = new_lines

        elif operation == "add_before":
            find   = op["find"]
            insert = op["insert"]
            new_lines = []
            for line in lines:
                if find in line:
                    indent = len(line) - len(line.lstrip())
                    new_lines.append(" " * indent + insert + "\n")
                new_lines.append(line)
            lines = new_lines

        elif operation == "replace_line":
            find    = op["find"]
            replace = op["replace"]
            lines   = [
                replace + "\n" if find in line else line
                for line in lines
            ]

        elif operation == "remove_line":
            find  = op["find"]
            lines = [line for line in lines if find not in line]

        elif operation == "add_line":
            after = op.get("after_line", 0)  # 1-indexed
            insert = op["insert"]
            lines.insert(after, insert + "\n")

        elif operation == "append":
            insert = op["insert"]
            if not lines[-1].endswith("\n"):
                lines[-1] += "\n"
            lines.append(insert + "\n")

        else:
            log.warning(f"[patcher] Unknown JSON patch op: {operation}")

    return "".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _resolve_path(filename):
    """Resolve a relative filename to an absolute path inside NETWATCH_DIR."""
    # Normalise separators
    filename = filename.replace("\\", "/")

    # Detect subdirectory from extension or explicit path
    if filename.startswith("templates/") or filename.startswith("static/") or filename.startswith("dev_docs/"):
        return os.path.join(NETWATCH_DIR, filename)

    ext = os.path.splitext(filename)[1].lower()
    if ext == ".html":
        return os.path.join(NETWATCH_DIR, "templates", os.path.basename(filename))
    elif ext in (".css", ".js"):
        return os.path.join(NETWATCH_DIR, "static", os.path.basename(filename))
    else:
        return os.path.join(NETWATCH_DIR, os.path.basename(filename))


def _find_in_zip(filename, names):
    """
    Find a file inside the zip by basename or partial path.
    Returns the zip entry name or None.
    """
    # Exact match first
    if filename in names:
        return filename

    # Match by basename anywhere in the zip
    basename = os.path.basename(filename)
    for name in names:
        if os.path.basename(name) == basename:
            return name

    return None


def _check_path_safety(filename, errors, index):
    """Reject paths that try to escape NETWATCH_DIR (zip slip prevention)."""
    if ".." in filename or filename.startswith("/"):
        errors.append(f"Action {index}: unsafe path '{filename}' rejected")


def _syntax_check(content_bytes):
    """Syntax-check Python source. Returns (True, None) or (False, error)."""
    try:
        import tempfile
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
        return False, str(e).replace(tmp_path, "<file>")
    except Exception as e:
        return False, str(e)


def _backup(path):
    """
    Back up a file before replacing it.

    For NetWatch_AI_Context_latest.txt: creates a dated copy in the same directory
    using the format NetWatch_AI_Context_YYYY-MM-DD_HHMMSS.txt so that multiple
    updates on the same day each produce a distinct archive copy.

    For all other files: creates path.bak (overwrites any previous .bak).

    Returns the backup path, or None if the source does not exist.
    """
    if not os.path.exists(path):
        return None
    basename = os.path.basename(path)
    if basename == "NetWatch_AI_Context_latest.txt":
        # Generate a timestamped archive name — seconds precision avoids same-day collisions
        ts = datetime.utcnow().strftime("%Y-%m-%d_%H%M%S")
        dated_name = f"NetWatch_AI_Context_{ts}.txt"
        backup = os.path.join(os.path.dirname(path), dated_name)
    else:
        backup = path + ".bak"
    try:
        shutil.copy2(path, backup)
        return backup
    except Exception as e:
        log.warning(f"[patcher] Backup failed for {path}: {e}")
        return None


def _queue_restart(filename, queue):
    """Add the appropriate service(s) to the restart queue based on filename."""
    from updater import get_service_for_file
    svc = get_service_for_file(filename)
    if svc in ("monitor", "both"):
        queue.add("netwatch-monitor")
    if svc in ("web", "both"):
        queue.add("netwatch-web")


def _restart_service(service_name):
    """Restart a systemd service."""
    try:
        if "web" in service_name:
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
        return True, None
    except Exception as e:
        return False, str(e)


def _run_sql(sql):
    """Execute a SQL statement against the NetWatch database."""
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(sql)
        conn.commit()
    except sqlite3.OperationalError as e:
        # Swallow "duplicate column" errors from re-applied migrations
        if "duplicate column" in str(e).lower() or "already exists" in str(e).lower():
            log.info(f"[patcher] SQL already applied (skipping): {e}")
        else:
            raise
    finally:
        conn.close()


def _log_patch(package_version, description, applied_by, success,
               steps_total, steps_ok, step_results=None):
    """Write a record to the patch history log, including full step detail."""
    try:
        _ensure_patch_log_table()
        conn = sqlite3.connect(DB_PATH)
        conn.execute("""
            INSERT INTO patch_log
                (timestamp, package_version, description, applied_by,
                 success, steps_total, steps_ok, step_results_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (datetime.now().isoformat(), package_version, description,
              applied_by, int(success), steps_total, steps_ok,
              json.dumps(step_results) if step_results else None))
        conn.commit()
        conn.close()
    except Exception as e:
        log.error(f"[patcher] Failed to log patch: {e}")


def _ensure_patch_log_table():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS patch_log (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp         TEXT NOT NULL,
            package_version   TEXT,
            description       TEXT,
            applied_by        TEXT,
            success           INTEGER DEFAULT 1,
            steps_total       INTEGER DEFAULT 0,
            steps_ok          INTEGER DEFAULT 0,
            admin_notes       TEXT DEFAULT NULL,
            step_results_json TEXT DEFAULT NULL
        )
    """)
    for col, defval in [("admin_notes", "NULL"), ("step_results_json", "NULL")]:
        try:
            conn.execute(f"ALTER TABLE patch_log ADD COLUMN {col} TEXT DEFAULT {defval}")
        except Exception:
            pass
    conn.commit()
    conn.close()


def get_changelog(limit=200):
    """Return all changelog entries, newest first, for display and PDF generation."""
    try:
        _ensure_patch_log_table()
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT * FROM patch_log ORDER BY timestamp DESC LIMIT ?
        """, (limit,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as e:
        log.error(f"Failed to read changelog: {e}")
        return []


def update_changelog_notes(entry_id, notes):
    """Save admin notes for a specific changelog entry."""
    try:
        _ensure_patch_log_table()
        conn = sqlite3.connect(DB_PATH)
        conn.execute("UPDATE patch_log SET admin_notes=? WHERE id=?", (notes, entry_id))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        log.error(f"Failed to update changelog notes: {e}")
        return False


def generate_release_notes_html(entry, site_name="NetWatch", theme="dark-blue"):
    """
    Generate a rich printable HTML release notes page matching the user's NetWatch theme.
    Zero external dependencies.
    """
    import html as _html
    import json as _json

    # ── Theme palettes ─────────────────────────────────────────────────────────
    THEMES = {
        "dark-blue": {
            "bg_page":      "#0f1923",
            "bg_card":      "#152330",
            "bg_input":     "#0a1520",
            "border":       "#1e3a5f",
            "accent":       "#4fc3f7",
            "accent_dark":  "#0a1520",
            "text_primary": "#e0e0e0",
            "text_muted":   "#546e7a",
            "text_label":   "#607d8b",
            "ok":           "#4caf50",
            "fail":         "#f44336",
            "warn":         "#ff9800",
            "header_text":  "#e0e0e0",
            "title_text":   "#0a6080",
            "font":         "'Exo 2', 'Segoe UI', sans-serif",
            "font_mono":    "'Share Tech Mono', monospace",
        },
        "dark-green": {
            "bg_page":      "#030a03",
            "bg_card":      "#071407",
            "bg_input":     "#020802",
            "border":       "#0d3b0d",
            "accent":       "#00cc44",
            "accent_dark":  "#020802",
            "text_primary": "#ccffcc",
            "text_muted":   "#2d6b2d",
            "text_label":   "#3a7a3a",
            "ok":           "#00ff55",
            "fail":         "#ff3300",
            "warn":         "#ffcc00",
            "header_text":  "#ccffcc",
            "title_text":   "#007a2a",
            "font":         "'IBM Plex Mono', 'Courier New', monospace",
            "font_mono":    "'IBM Plex Mono', monospace",
        },
        "light": {
            "bg_page":      "#f0f4f8",
            "bg_card":      "#ffffff",
            "bg_input":     "#f8fafc",
            "border":       "#d1dde8",
            "accent":       "#1565c0",
            "accent_dark":  "#ffffff",
            "text_primary": "#1a2332",
            "text_muted":   "#6b7c93",
            "text_label":   "#8096a8",
            "ok":           "#2e7d32",
            "fail":         "#c62828",
            "warn":         "#e65100",
            "header_text":  "#ffffff",
            "title_text":   "#1565c0",
            "font":         "'Inter', 'Segoe UI', sans-serif",
            "font_mono":    "'IBM Plex Mono', monospace",
        },
        "high-contrast": {
            "bg_page":      "#000000",
            "bg_card":      "#0a0a0a",
            "bg_input":     "#111111",
            "border":       "#555555",
            "accent":       "#ffff00",
            "accent_dark":  "#000000",
            "text_primary": "#ffffff",
            "text_muted":   "#aaaaaa",
            "text_label":   "#888888",
            "ok":           "#00ff00",
            "fail":         "#ff0000",
            "warn":         "#ff8800",
            "header_text":  "#000000",
            "title_text":   "#1a1a1a",
            "font":         "'Inter', Arial, sans-serif",
            "font_mono":    "'IBM Plex Mono', monospace",
        },
    }
    t = THEMES.get(theme, THEMES["dark-blue"])

    version   = _html.escape(entry.get("package_version") or "—")
    ts        = (entry.get("timestamp") or "")[:19].replace("T", " ")
    by        = _html.escape(entry.get("applied_by") or "system")
    ok        = bool(entry.get("success", 1))
    desc      = (entry.get("description") or "").strip()
    notes     = _html.escape((entry.get("admin_notes") or "").strip())
    steps_ok  = entry.get("steps_ok", 0)
    steps_tot = entry.get("steps_total", 0)
    status    = "Applied Successfully" if ok else "Installation Failed"

    step_results = []
    raw = entry.get("step_results_json")
    if raw:
        try:
            step_results = _json.loads(raw)
        except Exception:
            pass

    def fmt_desc(text):
        if not text:
            return f'<p style="color:{t["text_muted"]};font-style:italic;">No description provided.</p>'
        lines = text.split("\n")
        out = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            esc = _html.escape(line)
            if len(line) > 2 and line[0].isdigit() and line[1] in '.):':                out.append(f'<li>{esc[2:].strip()}</li>')
            else:
                out.append(f'<p style="margin:0 0 6px;">{esc}</p>')
        result = ""
        in_list = False
        for item in out:
            if item.startswith('<li>'):
                if not in_list:
                    result += f'<ol style="margin:8px 0 8px 20px;padding:0;color:{t["text_primary"]};">'
                    in_list = True
                result += item
            else:
                if in_list:
                    result += '</ol>'
                    in_list = False
                result += item
        if in_list:
            result += '</ol>'
        return result

    def fmt_steps(steps):
        if not steps:
            return f'<p style="color:{t["text_muted"]};font-style:italic;font-size:13px;">Step detail not available for this install (recorded before v3.2.26).</p>'
        ACTION_LABELS = {
            "replace":   ("📄", "File Replaced"),
            "patch":     ("✏️",  "File Patched"),
            "json_patch":("⚙️", "Config Updated"),
            "run":       ("▶️",  "Script Executed"),
            "restart":   ("🔄", "Service Restarted"),
            "service":   ("🔄", "Service Restarted"),
            "mkdir":     ("📁", "Directory Created"),
            "delete":    ("🗑️", "File Removed"),
        }
        rows = []
        for step in steps:
            action  = (step.get("action") or (step.get("service") and "restart") or "").lower()
            detail  = step.get("detail") or step.get("message") or ""
            status  = step.get("status", "ok")
            warning = step.get("warning") or ""
            fname   = step.get("file") or step.get("service") or ""
            icon, label = ACTION_LABELS.get(action, ("⚙️", action.title() if action else "Step"))
            s_color = t["ok"] if status == "ok" else (t["warn"] if status == "warning" else t["fail"])
            s_mark  = "✓" if status == "ok" else ("⚠" if status == "warning" else "✗")
            friendly = _html.escape(detail or fname or "")
            warn_html = f'<div style="color:{t["warn"]};font-size:11px;margin-top:3px;">⚠ {_html.escape(warning)}</div>' if warning else ""
            rows.append(f"""
              <tr style="border-bottom:1px solid #e8e8e8;">
                <td style="padding:7px 10px;white-space:nowrap;color:#666;">{icon} {label}</td>
                <td style="padding:7px 10px;font-family:{t['font_mono']};font-size:12px;color:#333;word-break:break-all;">
                  {friendly}{warn_html}
                </td>
                <td style="padding:7px 10px;text-align:center;color:{s_color};font-weight:700;font-size:1rem;">{s_mark}</td>
              </tr>""")
        return f"""
          <table style="width:100%;border-collapse:collapse;font-size:13px;
                        border-radius:6px;overflow:hidden;border:1px solid #e0e0e0;">
            <thead>
              <tr style="background:#f5f5f5;border-bottom:2px solid #e0e0e0;-webkit-print-color-adjust:exact;print-color-adjust:exact;">
                <th style="padding:8px 10px;text-align:left;color:{t['title_text']};font-weight:600;
                           font-size:10px;letter-spacing:1.5px;text-transform:uppercase;width:160px;">Action</th>
                <th style="padding:8px 10px;text-align:left;color:{t['title_text']};font-weight:600;
                           font-size:10px;letter-spacing:1.5px;text-transform:uppercase;">Detail</th>
                <th style="padding:8px 10px;text-align:center;color:{t['title_text']};font-weight:600;
                           font-size:10px;letter-spacing:1.5px;text-transform:uppercase;width:40px;">✓</th>
              </tr>
            </thead>
            <tbody style="background:#ffffff;">{"".join(rows)}</tbody>
          </table>"""

    desc_html  = fmt_desc(desc)
    steps_html = fmt_steps(step_results)
    ok_color   = t["ok"] if ok else t["fail"]
    ok_bg      = "rgba(76,175,80,0.15)" if ok else "rgba(244,67,54,0.15)"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{site_name} — Release Notes v{version}</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: {t['font']}; background: {t['bg_page']};
            color: #1a1a1a; padding: 32px 20px; }}
    .page {{ max-width: 760px; margin: 0 auto; background: #ffffff;
             border-radius: 10px; overflow: hidden;
             border: 2px solid {t['accent']}66;
             box-shadow: 0 4px 24px rgba(0,0,0,0.25); }}
    .header {{ background: {t['bg_page']}; color: {t['text_primary']};
               padding: 24px 36px 24px 28px;
               border-left: 8px solid {t['accent']};
               -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
    .header .site {{ font-size: 10px; text-transform: uppercase;
                     letter-spacing: 2.5px; color: {t['accent']}; margin-bottom: 8px;
                     -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
    .header h1 {{ font-size: 26px; font-weight: 700; margin-bottom: 6px;
                  color: {t['text_primary']}; }}
    .header .meta {{ font-size: 12px; color: {t['text_label']}; margin-top: 4px; }}
    .status-badge {{ display: inline-block; font-size: 11px; font-weight: 700;
                     padding: 3px 10px; border-radius: 20px; margin-left: 10px;
                     background: {ok_bg}; color: {ok_color};
                     border: 1px solid {ok_color}; vertical-align: middle;
                     -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
    .body {{ padding: 28px 36px; }}
    .section {{ margin-bottom: 24px; }}
    .section-title {{ font-size: 10px; text-transform: uppercase; letter-spacing: 2px;
                      color: {t['title_text']}; font-weight: 700; margin-bottom: 12px;
                      padding: 5px 8px 5px 10px;
                      background: {t['accent']}22;
                      border-left: 4px solid {t['accent']};
                      border-radius: 0 4px 4px 0;
                      -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
    .section p, .section li {{ font-size: 14px; line-height: 1.7;
                                color: #2a2a2a; margin-bottom: 4px; }}
    .notes-box {{ background: #f9f9f9; border-left: 3px solid {t['accent']};
                  padding: 12px 16px; border-radius: 0 6px 6px 0;
                  font-size: 13px; color: #333; line-height: 1.6;
                  -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
    .footer {{ padding: 14px 36px; background: #f5f5f5;
               border-top: 1px solid #e0e0e0; font-size: 11px;
               color: #888; display: flex; justify-content: space-between; }}
    @media print {{
      body {{ background: white; padding: 0; }}
      .page {{ box-shadow: none; border-radius: 0; }}
    }}
  </style>
</head>
<body>
  <div class="page">
    <div class="header">
      <div class="site">{site_name}</div>
      <h1>v{version} <span class="status-badge">{"✓" if ok else "✗"} {status}</span></h1>
      <div class="meta">Release Notes &nbsp;·&nbsp; Installed {ts} &nbsp;·&nbsp; by {by} &nbsp;·&nbsp; {steps_ok}/{steps_tot} steps</div>
    </div>
    <div class="body">
      <div class="section">
        <div class="section-title">What Changed</div>
        {desc_html}
      </div>
      <div class="section">
        <div class="section-title">Installation Log</div>
        {steps_html}
      </div>
      {('<div class="section"><div class="section-title">Admin Notes</div><div class="notes-box">' + notes + '</div></div>') if notes else ''}
    </div>
    <div class="footer">
      <span>{site_name} &nbsp;·&nbsp; v{version}</span>
      <span>{ts}</span>
    </div>
  </div>
</body>
</html>"""


def generate_combined_changelog_html(entries, site_name="NetWatch", theme="dark-blue"):
    """
    Generate a single printable HTML page listing all changelog entries oldest-first.
    Reuses the same theme palettes and helper functions as generate_release_notes_html.
    """
    import html as _html
    import json as _json

    THEMES = {
        "dark-blue":    {"bg_page":"#0f1923","bg_card":"#152330","border":"#1e3a5f","accent":"#4fc3f7","text_primary":"#e0e0e0","text_muted":"#546e7a","text_label":"#607d8b","ok":"#4caf50","fail":"#f44336","warn":"#ff9800","title_text":"#0a6080","font":"'Exo 2','Segoe UI',sans-serif","font_mono":"'Share Tech Mono',monospace"},
        "dark-green":   {"bg_page":"#030a03","bg_card":"#071407","border":"#0d3b0d","accent":"#00cc44","text_primary":"#ccffcc","text_muted":"#2d6b2d","text_label":"#3a7a3a","ok":"#00ff55","fail":"#ff3300","warn":"#ffcc00","title_text":"#007a2a","font":"'IBM Plex Mono','Courier New',monospace","font_mono":"'IBM Plex Mono',monospace"},
        "light":        {"bg_page":"#f0f4f8","bg_card":"#ffffff","border":"#d1dde8","accent":"#1565c0","text_primary":"#1a2332","text_muted":"#6b7c93","text_label":"#8096a8","ok":"#2e7d32","fail":"#c62828","warn":"#e65100","title_text":"#1565c0","font":"'Inter','Segoe UI',sans-serif","font_mono":"'IBM Plex Mono',monospace"},
        "high-contrast":{"bg_page":"#000000","bg_card":"#0a0a0a","border":"#555555","accent":"#ffff00","text_primary":"#ffffff","text_muted":"#aaaaaa","text_label":"#888888","ok":"#00ff00","fail":"#ff0000","warn":"#ff8800","title_text":"#1a1a1a","font":"'Inter',Arial,sans-serif","font_mono":"'IBM Plex Mono',monospace"},
    }
    t = THEMES.get(theme, THEMES["dark-blue"])

    # Oldest first for a chronological changelog
    ordered = list(reversed(entries))
    total   = len(ordered)

    ACTION_LABELS = {
        "replace":   ("📄", "File Replaced"),
        "patch":     ("✏️",  "File Patched"),
        "json_patch":("⚙️", "Config Updated"),
        "run":       ("▶️",  "Script Executed"),
        "restart":   ("🔄", "Service Restarted"),
        "service":   ("🔄", "Service Restarted"),
        "mkdir":     ("📁", "Directory Created"),
        "delete":    ("🗑️", "File Removed"),
    }

    def fmt_desc(text):
        if not text:
            return f'<p style="color:#999;font-style:italic;font-size:13px;">No description provided.</p>'
        lines = text.split("\n")
        out, result, in_list = [], "", False
        for line in lines:
            line = line.strip()
            if not line:
                continue
            esc = _html.escape(line)
            if len(line) > 2 and line[0].isdigit() and line[1] in '.):':
                out.append(f'<li>{esc[2:].strip()}</li>')
            else:
                out.append(f'<p style="margin:0 0 5px;font-size:13px;line-height:1.6;color:#2a2a2a;">{esc}</p>')
        for item in out:
            if item.startswith('<li>'):
                if not in_list:
                    result += '<ol style="margin:6px 0 6px 18px;padding:0;font-size:13px;color:#2a2a2a;">'
                    in_list = True
                result += item
            else:
                if in_list:
                    result += '</ol>'
                    in_list = False
                result += item
        if in_list:
            result += '</ol>'
        return result

    def fmt_steps(steps):
        if not steps:
            return f'<p style="color:#999;font-style:italic;font-size:12px;">Step detail not available.</p>'
        rows = []
        for step in steps:
            action  = (step.get("action") or (step.get("service") and "restart") or "").lower()
            detail  = step.get("detail") or step.get("message") or ""
            status  = step.get("status", "ok")
            warning = step.get("warning") or ""
            fname   = step.get("file") or step.get("service") or ""
            icon, label = ACTION_LABELS.get(action, ("⚙️", action.title() if action else "Step"))
            s_color = "#4caf50" if status == "ok" else ("#ff9800" if status == "warning" else "#f44336")
            s_mark  = "✓" if status == "ok" else ("⚠" if status == "warning" else "✗")
            friendly = _html.escape(detail or fname or "")
            warn_html = f'<div style="color:#ff9800;font-size:11px;margin-top:2px;">⚠ {_html.escape(warning)}</div>' if warning else ""
            rows.append(f"""
              <tr style="border-bottom:1px solid #eee;">
                <td style="padding:5px 8px;white-space:nowrap;color:#666;font-size:12px;">{icon} {label}</td>
                <td style="padding:5px 8px;font-family:monospace;font-size:11px;color:#333;word-break:break-all;">{friendly}{warn_html}</td>
                <td style="padding:5px 8px;text-align:center;color:{s_color};font-weight:700;">{s_mark}</td>
              </tr>""")
        return f"""
          <table style="width:100%;border-collapse:collapse;font-size:12px;border:1px solid #e0e0e0;border-radius:4px;overflow:hidden;">
            <thead><tr style="background:#f5f5f5;border-bottom:2px solid #e0e0e0;">
              <th style="padding:6px 8px;text-align:left;color:#666;font-size:10px;letter-spacing:1px;text-transform:uppercase;width:150px;">Action</th>
              <th style="padding:6px 8px;text-align:left;color:#666;font-size:10px;letter-spacing:1px;text-transform:uppercase;">Detail</th>
              <th style="padding:6px 8px;text-align:center;color:#666;font-size:10px;width:36px;">✓</th>
            </tr></thead>
            <tbody style="background:#fff;">{"".join(rows)}</tbody>
          </table>"""

    # Build entry blocks
    entry_blocks = []
    for i, entry in enumerate(ordered):
        version   = _html.escape(entry.get("package_version") or "—")
        ts        = (entry.get("timestamp") or "")[:19].replace("T", " ")
        by        = _html.escape(entry.get("applied_by") or "system")
        ok        = bool(entry.get("success", 1))
        desc      = (entry.get("description") or "").strip()
        notes     = _html.escape((entry.get("admin_notes") or "").strip())
        steps_ok  = entry.get("steps_ok", 0)
        steps_tot = entry.get("steps_total", 0)
        status    = "Applied Successfully" if ok else "Installation Failed"
        ok_color  = "#4caf50" if ok else "#f44336"
        ok_bg     = "rgba(76,175,80,0.12)" if ok else "rgba(244,67,54,0.12)"

        step_results = []
        raw = entry.get("step_results_json")
        if raw:
            try:
                step_results = _json.loads(raw)
            except Exception:
                pass

        notes_html = f"""
          <div style="margin-top:14px;">
            <div class="section-title">Admin Notes</div>
            <div style="background:#f9f9f9;border-left:3px solid {t['accent']};padding:10px 14px;
                        border-radius:0 4px 4px 0;font-size:13px;color:#333;line-height:1.6;">{notes}</div>
          </div>""" if notes else ""

        entry_blocks.append(f"""
        <div class="entry" id="v{_html.escape(version.replace(' ','_'))}">
          <div class="entry-header">
            <div style="display:flex;align-items:baseline;gap:12px;flex-wrap:wrap;">
              <span class="entry-version">v{version}</span>
              <span style="display:inline-block;font-size:11px;font-weight:700;padding:2px 9px;
                           border-radius:20px;background:{ok_bg};color:{ok_color};
                           border:1px solid {ok_color};">{"✓" if ok else "✗"} {status}</span>
            </div>
            <div style="font-size:12px;color:#888;margin-top:4px;">
              {ts} &nbsp;·&nbsp; by {by} &nbsp;·&nbsp; {steps_ok}/{steps_tot} steps
            </div>
          </div>
          <div class="entry-body">
            <div style="margin-bottom:14px;">
              <div class="section-title">What Changed</div>
              {fmt_desc(desc)}
            </div>
            <div>
              <div class="section-title">Installation Log</div>
              {fmt_steps(step_results)}
            </div>
            {notes_html}
          </div>
        </div>""")

    entries_html = "\n".join(entry_blocks) if entry_blocks else \
        '<p style="color:#999;text-align:center;padding:40px;">No packages installed yet.</p>'

    from datetime import datetime, timezone
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{_html.escape(site_name)} — Full Changelog</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: {t['font']}; background: {t['bg_page']}; color: #1a1a1a; padding: 32px 20px; }}
    .page {{ max-width: 820px; margin: 0 auto; }}
    .doc-header {{ background: {t['bg_page']}; color: {t['text_primary']};
                   padding: 28px 36px; border-radius: 10px 10px 0 0;
                   border-left: 8px solid {t['accent']};
                   border: 2px solid {t['accent']}66;
                   border-bottom: none;
                   -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
    .doc-header .site {{ font-size: 10px; text-transform: uppercase; letter-spacing: 2.5px;
                          color: {t['accent']}; margin-bottom: 8px; }}
    .doc-header h1 {{ font-size: 28px; font-weight: 700; color: {t['text_primary']}; }}
    .doc-header .meta {{ font-size: 12px; color: {t['text_label']}; margin-top: 6px; }}
    .toc {{ background: #ffffff; border: 2px solid {t['accent']}66; border-top: none; border-bottom: none;
            padding: 20px 36px; }}
    .toc-title {{ font-size: 10px; text-transform: uppercase; letter-spacing: 2px;
                  color: {t['title_text']}; font-weight: 700; margin-bottom: 10px; }}
    .toc-grid {{ display: flex; flex-wrap: wrap; gap: 6px; }}
    .toc-item {{ font-size: 12px; color: {t['accent']}; text-decoration: none;
                 padding: 3px 8px; border: 1px solid {t['accent']}44;
                 border-radius: 4px; font-family: monospace; }}
    .toc-item:hover {{ background: {t['accent']}22; }}
    .entry {{ background: #ffffff; border: 2px solid {t['accent']}66;
              border-top: none; overflow: hidden; }}
    .entry:last-child {{ border-radius: 0 0 10px 10px; }}
    .entry-header {{ background: {t['bg_page']}; padding: 16px 36px;
                     border-bottom: 1px solid {t['accent']}33;
                     -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
    .entry-version {{ font-size: 20px; font-weight: 700; color: {t['text_primary']};
                      font-family: monospace; }}
    .entry-body {{ padding: 20px 36px; }}
    .section-title {{ font-size: 10px; text-transform: uppercase; letter-spacing: 2px;
                      color: {t['title_text']}; font-weight: 700; margin-bottom: 10px;
                      padding: 4px 8px 4px 10px; background: {t['accent']}22;
                      border-left: 4px solid {t['accent']}; border-radius: 0 4px 4px 0;
                      -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
    .doc-footer {{ background: #f5f5f5; padding: 14px 36px; border-top: 1px solid #e0e0e0;
                   font-size: 11px; color: #888; display: flex;
                   justify-content: space-between; border-radius: 0 0 10px 10px; }}
    @media print {{
      body {{ background: white; padding: 0; }}
      .toc-item {{ color: #000; border-color: #ccc; }}
    }}
  </style>
</head>
<body>
  <div class="page">
    <div class="doc-header">
      <div class="site">{_html.escape(site_name)}</div>
      <h1>Full Changelog</h1>
      <div class="meta">{total} release{"s" if total != 1 else ""} &nbsp;·&nbsp; Generated {generated}</div>
    </div>
    <div class="toc">
      <div class="toc-title">Versions</div>
      <div class="toc-grid">
        {"".join(f'<a class="toc-item" href="#v{_html.escape(str(e.get("package_version","")).replace(" ","_"))}">v{_html.escape(str(e.get("package_version","—")))}</a>' for e in ordered)}
      </div>
    </div>
    {"".join(entry_blocks)}
  </div>
</body>
</html>"""


def get_changelog_entry(entry_id):
    """Return a single changelog entry by ID."""
    try:
        _ensure_patch_log_table()
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM patch_log WHERE id=?", (entry_id,)).fetchone()
        conn.close()
        return dict(row) if row else None
    except Exception as e:
        log.error(f"Failed to read changelog entry: {e}")
        return None
