# ══════════════════════════════════════════════════════════════════════════════
# NetWatch — gunicorn.conf.py
# Gunicorn configuration for the NetWatch web service.
# ══════════════════════════════════════════════════════════════════════════════

import os
import structlog
from gunicorn.glogging import Logger

NETWATCH_DIR = os.path.dirname(os.path.abspath(__file__))

# Server socket
bind        = "0.0.0.0:5000"
certfile    = os.path.join(NETWATCH_DIR, "certs", "netwatch.crt")
keyfile     = os.path.join(NETWATCH_DIR, "certs", "netwatch.key")

# Workers
workers     = 2
worker_class = "sync"
timeout     = 30

# Load the app in the master process before forking workers.
# This means init() runs once, not once per worker, avoiding
# simultaneous DB writes on startup.
preload_app = True

# Logging — send to stdout so systemd/journald captures it
accesslog   = "-"
errorlog    = "-"
loglevel    = "info"


class StructlogAccessLogger(Logger):
    """
    Custom gunicorn logger that routes ALL gunicorn log output through structlog
    instead of gunicorn's default plain-text formatter. This ensures every log
    line — HTTP access entries AND gunicorn lifecycle messages (startup, worker
    boot/exit, errors) — shares the same JSON schema when LOG_FORMAT=json,
    making Loki queries consistent across all log lines.

    Two override layers:
      access()  -- HTTP request log (one entry per request)
      now/error/warning/info/debug/critical/exception()
                -- gunicorn internal error logger (startup, worker lifecycle,
                   crash traces). Previously emitted plain text; now JSON.

    Schema for access entries:
      service, event, method, path, status, bytes, duration_ms,
      remote_addr, referer, user_agent, level, timestamp

    Schema for lifecycle entries:
      service, event="gunicorn", message, level, timestamp
    """

    # -- Error logger overrides (gunicorn lifecycle messages) ------------------

    def _emit(self, level, msg, *args):
        """Route a gunicorn internal log message to stdout as JSON.

        gunicorn passes printf-style format strings (e.g. "Worker %s booted" % pid).
        We cannot use structlog here because gunicorn.conf.py is loaded before wsgi.py
        calls _configure_structlog(), so structlog is unconfigured at startup time.
        Instead we write a JSON line directly to stdout — journalctl captures stdout
        regardless of logging configuration, and the format matches the structlog
        JSON schema so Loki queries work consistently.
        """
        import json as _json
        from datetime import datetime as _dt
        try:
            message = msg % args if args else str(msg)
        except Exception:
            message = str(msg)
        line = _json.dumps({
            "service":   "web",
            "event":     "gunicorn",
            "message":   message,
            "level":     level,
            "timestamp": _dt.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        })
        print(line, flush=True)

    def debug(self, msg, *args, **kwargs):
        self._emit("debug", msg, *args)

    def info(self, msg, *args, **kwargs):
        self._emit("info", msg, *args)

    def warning(self, msg, *args, **kwargs):
        self._emit("warning", msg, *args)

    def error(self, msg, *args, **kwargs):
        self._emit("error", msg, *args)

    def critical(self, msg, *args, **kwargs):
        self._emit("critical", msg, *args)

    def exception(self, msg, *args, **kwargs):
        self._emit("error", msg, *args)

    # -- Access log override (HTTP request entries) ----------------------------

    def access(self, resp, req, environ, request_time):
        """Override gunicorn's access log to emit structured JSON via structlog."""
        log = structlog.get_logger().bind(service="web")

        # request_time is a datetime.timedelta
        duration_ms = round(request_time.total_seconds() * 1000, 1)

        # Response length — gunicorn uses '-' when unknown
        try:
            response_bytes = int(resp.response_length)
        except (TypeError, ValueError):
            response_bytes = 0

        # Status — streaming responses use resp.status (int), regular use resp.status_code
        status = getattr(resp, "status_code", None) or getattr(resp, "status", 0)
        if isinstance(status, str):
            status = int(status.split()[0])

        method  = environ.get("REQUEST_METHOD", "-")
        path    = environ.get("PATH_INFO", "-")
        qs      = environ.get("QUERY_STRING", "")
        full_path = f"{path}?{qs}" if qs else path
        referer = environ.get("HTTP_REFERER", "")
        ua      = environ.get("HTTP_USER_AGENT", "")
        remote  = environ.get("REMOTE_ADDR", "-")

        # Log level based on status code: 5xx=error, 4xx=warning, else info
        if status >= 500:
            log.error("http_request", method=method, path=full_path,
                      status=status, bytes=response_bytes,
                      duration_ms=duration_ms, remote_addr=remote,
                      referer=referer, user_agent=ua)
        elif status >= 400:
            log.warning("http_request", method=method, path=full_path,
                        status=status, bytes=response_bytes,
                        duration_ms=duration_ms, remote_addr=remote,
                        referer=referer, user_agent=ua)
        else:
            log.info("http_request", method=method, path=full_path,
                     status=status, bytes=response_bytes,
                     duration_ms=duration_ms, remote_addr=remote,
                     referer=referer, user_agent=ua)


logger_class = StructlogAccessLogger
