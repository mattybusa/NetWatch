"""
theme_manager.py — NetWatch Custom Theme Manager
=================================================
Manages custom themes stored as .nwtheme (JSON) files in ~/netwatch/themes/.

A custom theme is a named bundle that may contain:
  - color_scheme: a dict of CSS custom property values (replaces the system theme)
  - layout:       a dict of CSS layout property values (replaces the system layout)
  - Either or both may be present; a theme with neither is invalid.

System themes (dark-blue, dark-green, light, high-contrast) are defined in themes.css
and are never stored here. Custom themes supplement — they do not replace — system themes.

File format: themes/<name>.nwtheme (JSON)
  {
    "name":        "My Theme",           -- display name (required)
    "description": "Optional blurb",    -- optional
    "author":      "Optional name",      -- optional
    "version":     "1.0",               -- optional
    "color_scheme": {                    -- optional; omit if layout-only
      "--bg-page":        "#1a1a2e",
      "--bg-card":        "#16213e",
      ... (all required CSS variable keys)
    },
    "layout": {                          -- optional; omit if color-scheme-only
      "--content-padding": "20px",
      "--card-padding":    "18px",
      "--gap":             "14px"
    }
  }

Public API:
  load_themes()                -> list of theme dicts (all valid themes)
  get_theme(name)              -> single theme dict or None
  save_theme(data_bytes)       -> (True, name) or (False, error_message)
  delete_theme(name)           -> (True, None) or (False, error_message)
  generate_css(theme, part)    -> CSS string for inline injection
  THEMES_DIR                   -> path to themes directory
"""

import os
import json
import re
import logging

log = logging.getLogger(__name__)

# ── Paths ─────────────────────────────────────────────────────────────────────

NETWATCH_DIR = os.path.dirname(os.path.abspath(__file__))
THEMES_DIR   = os.path.join(NETWATCH_DIR, "themes")

# ── Required CSS variable keys for a color_scheme ────────────────────────────
# Any custom color scheme must supply all of these.

REQUIRED_COLOR_KEYS = [
    "--bg-page", "--bg-card", "--bg-input", "--bg-nav", "--bg-hover",
    "--border-color", "--border-focus",
    "--accent", "--accent-dim", "--accent-glow",
    "--text-primary", "--text-secondary", "--text-muted", "--text-label",
    "--ok", "--warn", "--fail", "--ok-glow", "--fail-glow",
    "--font-body", "--font-mono", "--font-base",
    "--nav-border", "--card-radius", "--shadow",
]

# Required CSS variable keys for a layout override
REQUIRED_LAYOUT_KEYS = [
    "--content-padding", "--card-padding", "--gap",
]

# Allowed value pattern: CSS values only — no semicolons, braces, or quotes
# Permits: hex colours, rgb/rgba, px/em/rem/%, named fonts, shadows, radii, etc.
_SAFE_VALUE_RE = re.compile(
    r'^[a-zA-Z0-9 ,.()\-_%#/\'\"]+$'
)

# Maximum length for any single value
_MAX_VALUE_LEN = 200


# ── Internal helpers ──────────────────────────────────────────────────────────

def _ensure_themes_dir():
    """Create the themes directory if it does not exist."""
    os.makedirs(THEMES_DIR, exist_ok=True)


def _safe_filename(name):
    """Convert a theme display name to a safe filename stem."""
    stem = re.sub(r'[^\w\-]', '_', name.strip()).strip('_')
    return stem[:64] or "custom_theme"


def _validate_css_value(value):
    """
    Return True if value is an acceptable CSS property value.
    Rejects anything that looks like it could escape the style block.
    """
    if not isinstance(value, str):
        return False
    if len(value) > _MAX_VALUE_LEN:
        return False
    # Reject characters used to close style blocks or inject selectors
    if any(c in value for c in ('{', '}', '<', '>', ';', '\n', '\r')):
        return False
    return True


def _validate_theme_data(data):
    """
    Validate a parsed theme dict. Returns (True, None) or (False, error_str).
    Checks structure, required keys, and sanitizes all CSS values.
    """
    if not isinstance(data, dict):
        return False, "Theme file must be a JSON object"

    name = data.get("name", "").strip()
    if not name:
        return False, "Theme must have a 'name' field"
    if len(name) > 80:
        return False, "Theme name must be 80 characters or fewer"

    color_scheme = data.get("color_scheme")
    layout       = data.get("layout")

    if color_scheme is None and layout is None:
        return False, "Theme must include 'color_scheme', 'layout', or both"

    # Validate color_scheme block
    if color_scheme is not None:
        if not isinstance(color_scheme, dict):
            return False, "'color_scheme' must be a JSON object"
        missing = [k for k in REQUIRED_COLOR_KEYS if k not in color_scheme]
        if missing:
            return False, f"'color_scheme' is missing required keys: {', '.join(missing)}"
        for key, val in color_scheme.items():
            if not key.startswith("--"):
                return False, f"Invalid color_scheme key '{key}': must start with '--'"
            if not _validate_css_value(val):
                return False, f"Invalid value for '{key}': contains unsafe characters or is too long"

    # Validate layout block
    if layout is not None:
        if not isinstance(layout, dict):
            return False, "'layout' must be a JSON object"
        missing = [k for k in REQUIRED_LAYOUT_KEYS if k not in layout]
        if missing:
            return False, f"'layout' is missing required keys: {', '.join(missing)}"
        for key, val in layout.items():
            if not key.startswith("--"):
                return False, f"Invalid layout key '{key}': must start with '--'"
            if not _validate_css_value(val):
                return False, f"Invalid value for '{key}': contains unsafe characters or is too long"

    return True, None


# ── Public API ────────────────────────────────────────────────────────────────

def load_themes():
    """
    Scan THEMES_DIR for .nwtheme files, parse and validate each one.
    Returns a list of valid theme dicts, sorted by display name.
    Invalid files are logged and skipped.
    A theme is marked disabled if a corresponding .disabled sidecar file exists.
    """
    _ensure_themes_dir()
    themes = []
    try:
        for fname in os.listdir(THEMES_DIR):
            if not fname.endswith(".nwtheme"):
                continue
            fpath = os.path.join(THEMES_DIR, fname)
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                ok, err = _validate_theme_data(data)
                if ok:
                    data["_filename"] = fname  # internal: which file on disk
                    # Check for .disabled sidecar
                    disabled_path = fpath + ".disabled"
                    data["_disabled"] = os.path.exists(disabled_path)
                    themes.append(data)
                else:
                    log.warning(f"Skipping invalid theme file '{fname}': {err}")
            except Exception as e:
                log.warning(f"Could not load theme file '{fname}': {e}")
    except Exception as e:
        log.error(f"Could not scan themes directory: {e}")
    return sorted(themes, key=lambda t: t.get("name", "").lower())


def get_theme(name):
    """
    Return the theme dict for the given display name, or None if not found.
    Compares case-insensitively against loaded themes.
    """
    name_lower = name.lower()
    for theme in load_themes():
        if theme.get("name", "").lower() == name_lower:
            return theme
    return None


def save_theme(data_bytes):
    """
    Parse, validate, and save an uploaded .nwtheme file.
    data_bytes: raw bytes from the uploaded file.
    Returns (True, theme_name) on success, (False, error_message) on failure.
    Rejects a theme whose name conflicts with an existing file (case-insensitive).
    """
    _ensure_themes_dir()
    try:
        data = json.loads(data_bytes.decode("utf-8"))
    except Exception:
        return False, "File is not valid JSON"

    ok, err = _validate_theme_data(data)
    if not ok:
        return False, err

    theme_name = data["name"].strip()

    # Check for name collision with existing themes
    existing = {t.get("name", "").lower() for t in load_themes()}
    if theme_name.lower() in existing:
        return False, f"A theme named '{theme_name}' already exists. Delete it first."

    stem  = _safe_filename(theme_name)
    fname = stem + ".nwtheme"
    fpath = os.path.join(THEMES_DIR, fname)

    # Avoid filename collision even if names are different
    counter = 1
    while os.path.exists(fpath):
        fname = f"{stem}_{counter}.nwtheme"
        fpath = os.path.join(THEMES_DIR, fname)
        counter += 1

    try:
        with open(fpath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        log.info(f"Custom theme '{theme_name}' saved as '{fname}'")
        return True, theme_name
    except Exception as e:
        return False, f"Could not write theme file: {e}"


def set_theme_disabled(name, disabled):
    """
    Enable or disable a theme by name.
    Uses a .disabled sidecar file alongside the .nwtheme file.
    Returns (True, None) on success, (False, error_str) on failure.
    """
    _ensure_themes_dir()
    theme = get_theme(name)
    if not theme:
        return False, f"Theme '{name}' not found"
    fpath        = os.path.join(THEMES_DIR, theme["_filename"])
    disabled_path = fpath + ".disabled"
    try:
        if disabled:
            open(disabled_path, "w").close()
        else:
            if os.path.exists(disabled_path):
                os.remove(disabled_path)
        return True, None
    except Exception as e:
        return False, str(e)


def delete_theme(name):
    """
    Delete the .nwtheme file for the named theme.
    Returns (True, None) on success, (False, error_message) on failure.
    """
    theme = get_theme(name)
    if not theme:
        return False, f"Theme '{name}' not found"
    fpath = os.path.join(THEMES_DIR, theme["_filename"])
    try:
        os.remove(fpath)
        log.info(f"Custom theme '{name}' deleted")
        return True, None
    except Exception as e:
        return False, f"Could not delete theme file: {e}"


def generate_css(theme, part="color_scheme"):
    """
    Generate a CSS variable override block from the given theme dict.
    part: "color_scheme" or "layout" — which section of the theme to render.

    Returns a CSS string suitable for embedding in a <style> block in <head>,
    placed AFTER themes.css so it wins the cascade without any class switching.

    Uses `body { ... }` as the selector — this overrides the system theme
    variables (set on body.theme-dark-blue etc.) because the inline <style>
    block appears later in the document than the themes.css <link>. The system
    theme class stays on <body> so structural CSS (nav, sidebar, spacing) still
    applies; only the CSS variables are overridden. This avoids any flash-of-
    unstyled-content from class switching.

    If the theme does not contain the requested part, returns an empty string.
    """
    data = theme.get(part)
    if not data:
        return ""

    # We need to match the specificity of body.theme-* selectors used by themes.css.
    # CSS custom properties inherit from the nearest ancestor — body.theme-* sets them
    # on body, which wins over :root. We beat it by matching the same specificity level
    # with a selector that applies regardless of which theme class is active.
    # Using body[class] matches any body with a class attribute (always true) and has
    # the same specificity as body.theme-* (one element + one attribute/class).
    # Placing our <style> after themes.css in <head> means we win on source order too.
    selector = "body[class]"
    lines = [f"{selector} {{"]
    for key, val in data.items():
        # Re-validate at render time — belt and suspenders
        if _validate_css_value(val) and key.startswith("--"):
            lines.append(f"  {key}: {val};")
    lines.append("}")
    return "\n".join(lines)


def get_theme_kit_markdown():
    """
    Return the NetWatch Theme Creation Kit as a markdown string.
    This documents all CSS variable names, their purpose, accepted value
    formats, and the exact JSON structure of a .nwtheme file.
    Served as a downloadable file from /admin/themes/kit.
    """
    color_vars = "\n".join(
        f"  \"{k}\": \"<value>\"  # {desc}"
        for k, desc in [
            ("--bg-page",         "Page background"),
            ("--bg-card",         "Card / panel background"),
            ("--bg-input",        "Input field / secondary surface background"),
            ("--bg-nav",          "Navigation bar background"),
            ("--bg-hover",        "Hover state background"),
            ("--border-color",    "Default border colour"),
            ("--border-focus",    "Input focus ring colour"),
            ("--accent",          "Primary accent colour (links, active states)"),
            ("--accent-dim",      "Dimmed / secondary accent"),
            ("--accent-glow",     "Accent glow / shadow (e.g. box-shadow value)"),
            ("--text-primary",    "Primary body text"),
            ("--text-secondary",  "Secondary / subheading text"),
            ("--text-muted",      "Muted / placeholder text"),
            ("--text-label",      "Label text (small caps labels)"),
            ("--ok",              "Success / OK colour"),
            ("--warn",            "Warning colour"),
            ("--fail",            "Error / failure colour"),
            ("--ok-glow",         "Success glow (box-shadow value)"),
            ("--fail-glow",       "Failure glow (box-shadow value)"),
            ("--font-body",       "Body font stack (e.g. 'Inter, sans-serif')"),
            ("--font-mono",       "Monospace font stack"),
            ("--font-base",       "Base font size (e.g. '14px')"),
            ("--nav-border",      "Nav bottom border (e.g. '1px solid #333')"),
            ("--card-radius",     "Card border radius (e.g. '8px')"),
            ("--shadow",          "Card box-shadow value"),
        ]
    )

    layout_vars = "\n".join(
        f"  \"{k}\": \"<value>\"  # {desc}"
        for k, desc in [
            ("--content-padding", "Outer page padding (e.g. '24px')"),
            ("--card-padding",    "Card inner padding (e.g. '20px')"),
            ("--gap",             "Grid / flex gap between cards (e.g. '16px')"),
        ]
    )

    return f"""\
# NetWatch Theme Creation Kit

A `.nwtheme` file is a JSON file that defines a custom color scheme,
a custom layout, or both. Once imported via Admin → Theme Manager,
any user can select it from their appearance settings.

---

## File Format

```json
{{
  "name": "My Theme",
  "description": "Optional short description",
  "author": "Your Name",
  "version": "1.0",

  "color_scheme": {{
    "--bg-page":        "#0d1117",
    "--bg-card":        "#161b22",
    "--bg-input":       "#1c2128",
    "--bg-nav":         "#0d1117",
    "--bg-hover":       "#21262d",
    "--border-color":   "#30363d",
    "--border-focus":   "#4fc3f7",
    "--accent":         "#4fc3f7",
    "--accent-dim":     "#1a4a5c",
    "--accent-glow":    "0 0 8px rgba(79,195,247,0.4)",
    "--text-primary":   "#e6edf3",
    "--text-secondary": "#8b949e",
    "--text-muted":     "#6e7681",
    "--text-label":     "#8b949e",
    "--ok":             "#3fb950",
    "--warn":           "#d29922",
    "--fail":           "#f85149",
    "--ok-glow":        "0 0 6px rgba(63,185,80,0.4)",
    "--fail-glow":      "0 0 6px rgba(248,81,73,0.4)",
    "--font-body":      "'Inter', 'Segoe UI', sans-serif",
    "--font-mono":      "'JetBrains Mono', 'Courier New', monospace",
    "--font-base":      "14px",
    "--nav-border":     "1px solid #30363d",
    "--card-radius":    "8px",
    "--shadow":         "0 1px 3px rgba(0,0,0,0.4)"
  }},

  "layout": {{
    "--content-padding": "24px",
    "--card-padding":    "20px",
    "--gap":             "16px"
  }}
}}
```

`color_scheme` and `layout` are both optional, but at least one must be present.

---

## Color Scheme Variables

All 25 variables are required when including a `color_scheme` section:

```
{color_vars}
```

**Value rules:**
- Hex colours: `#rrggbb` or `#rgb`
- RGB/RGBA: `rgba(r, g, b, a)`
- Font stacks: quoted comma-separated list, e.g. `'Inter', sans-serif`
- Sizes: CSS length values, e.g. `14px`, `1rem`, `8px`
- Borders: shorthand, e.g. `1px solid #333`
- Box shadows: standard `box-shadow` value, e.g. `0 0 8px rgba(79,195,247,0.4)`
- No `{{`, `}}`, `<`, `>`, `;`, or newlines in any value
- Maximum 200 characters per value

---

## Layout Variables

All 3 variables are required when including a `layout` section:

```
{layout_vars}
```

Layout only controls spacing — it does not change which navigation
style (top bar / sidebar) is active. Navigation style is set separately
by each user in their appearance preferences.

---

## Tips

- Start from an existing system theme and adjust colours one at a time.
- The system themes (Dark Blue, Terminal, Light, High Contrast) are defined
  in `static/themes.css` on the Pi — you can read those values as a starting
  point.
- Color scheme and layout can be in the same file or split across two files.
  A user can apply a color scheme from one theme and a layout from another.
- The theme `name` field is used as the display name and filename on disk.
  Keep it short, descriptive, and unique.
- Import via Admin → Theme Manager. A validation error will explain exactly
  which variable is missing or has an invalid value.

---

*NetWatch Theme Kit — generated by NetWatch*
"""
