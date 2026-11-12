"""
Structured JSON logging with request IDs and secret redaction.

Usage:
    from .logging_config import configure_logging, get_logger
    configure_logging()
    logger = get_logger(__name__)
    logger.info("user_login", user_id=str(user.id), device_id=str(device.id))
"""

from __future__ import annotations

import logging
import re
import uuid
from typing import Any

_REDACTED = "[REDACTED]"

# Patterns whose values must never appear in logs
_SECRET_KEYS = re.compile(
    r"(password|secret|token|key|vrk|dek|hash|salt|pin|auth|nonce|credential|jwt|bearer)",
    re.IGNORECASE,
)

# JWT / base64-encoded token shape — redact standalone opaque strings > 32 chars
_OPAQUE_VALUE = re.compile(r"^[A-Za-z0-9+/=_\-]{33,}$")


def _scrub(value: Any) -> Any:
    """Recursively redact sensitive fields from dicts / strings."""
    if isinstance(value, dict):
        return {k: (_REDACTED if _SECRET_KEYS.search(str(k)) else _scrub(v)) for k, v in value.items()}
    if isinstance(value, str) and _OPAQUE_VALUE.match(value):
        return _REDACTED
    if isinstance(value, (list, tuple)):
        return type(value)(_scrub(item) for item in value)
    return value


class _RedactingFormatter(logging.Formatter):
    """JSON-lines formatter that scrubs secrets from the log record."""

    def format(self, record: logging.LogRecord) -> str:
        import json
        from datetime import datetime, timezone

        msg = record.getMessage()
        # Redact free-form message strings containing secret-like sub-strings
        scrubbed_msg = re.sub(
            r'(?i)(password|token|secret|key|salt|nonce|bearer|pin)[=:\s"\']+\S+',
            lambda m: m.group(0).split(m.group(1))[0] + m.group(1) + "=" + _REDACTED,
            msg,
        )

        payload: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": scrubbed_msg,
        }

        # Attach structured kwargs stored in record.__dict__ by SecureLogger
        extras = {
            k: _scrub(v)
            for k, v in record.__dict__.items()
            if k not in logging.LogRecord.__dict__ and not k.startswith("_")
            and k not in ("args", "msg", "exc_info", "exc_text", "stack_info",
                          "lineno", "funcName", "filename", "module", "pathname",
                          "name", "levelname", "levelno", "created", "msecs",
                          "relativeCreated", "thread", "threadName", "processName",
                          "process", "taskName", "message")
        }
        if extras:
            payload["ctx"] = extras

        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)

        return json.dumps(payload, default=str)


class SecureLogger:
    """Thin wrapper around stdlib Logger that attaches structured key-value context."""

    def __init__(self, logger: logging.Logger) -> None:
        self._logger = logger

    def _emit(self, level: int, msg: str, **kwargs: Any) -> None:
        if self._logger.isEnabledFor(level):
            extra = {k: _scrub(v) for k, v in kwargs.items()}
            self._logger.log(level, msg, extra=extra, stacklevel=3)

    def debug(self, msg: str, **kwargs: Any) -> None:
        self._emit(logging.DEBUG, msg, **kwargs)

    def info(self, msg: str, **kwargs: Any) -> None:
        self._emit(logging.INFO, msg, **kwargs)

    def warning(self, msg: str, **kwargs: Any) -> None:
        self._emit(logging.WARNING, msg, **kwargs)

    def error(self, msg: str, **kwargs: Any) -> None:
        self._emit(logging.ERROR, msg, **kwargs)

    def critical(self, msg: str, **kwargs: Any) -> None:
        self._emit(logging.CRITICAL, msg, **kwargs)


def configure_logging(level: str = "INFO", json_logs: bool = True) -> None:
    """Configure root logger with JSON-structured, secret-redacting output."""
    handler = logging.StreamHandler()
    if json_logs:
        handler.setFormatter(_RedactingFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))

    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    root.handlers.clear()
    root.addHandler(handler)

    # Quiet noisy third-party loggers
    for noisy in ("uvicorn.access", "sqlalchemy.engine", "httpx"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def get_logger(name: str) -> SecureLogger:
    return SecureLogger(logging.getLogger(name))


def new_request_id() -> str:
    return str(uuid.uuid4())
