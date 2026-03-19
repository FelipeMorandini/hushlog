"""JSON-aware redacting formatter for structured logging."""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hushlog._registry import PatternRegistry

try:
    from pythonjsonlogger.json import JsonFormatter as _BaseJsonFormatter

    _HAS_JSON_LOGGER = True
except ImportError:
    _BaseJsonFormatter = None  # type: ignore[assignment,misc]
    _HAS_JSON_LOGGER = False


_STANDARD_ATTRS: frozenset[str] | None = None


def _get_standard_attrs() -> frozenset[str]:
    """Cache standard LogRecord attribute names (computed once)."""
    global _STANDARD_ATTRS  # noqa: PLW0603
    if _STANDARD_ATTRS is None:
        _STANDARD_ATTRS = frozenset(logging.LogRecord("", 0, "", 0, None, None, None).__dict__)
    return _STANDARD_ATTRS


class RedactingJsonFormatter(logging.Formatter):
    """A JSON log formatter that redacts PII in structured log records.

    Builds a dict from the log record, redacts all string values via
    ``PatternRegistry.redact_dict()``, then serializes to JSON.

    Usage::

        from hushlog import Config, RedactingJsonFormatter
        from hushlog._registry import PatternRegistry

        registry = PatternRegistry.from_config(Config())
        formatter = RedactingJsonFormatter(registry)
        handler.setFormatter(formatter)
    """

    def __init__(
        self,
        registry: PatternRegistry,
        *,
        fmt: str | None = None,
        datefmt: str | None = None,
        json_indent: int | None = None,
    ) -> None:
        super().__init__(fmt=fmt, datefmt=datefmt)
        self._registry = registry
        self._json_indent = json_indent
        if _HAS_JSON_LOGGER and _BaseJsonFormatter is not None:
            self._json_formatter: _BaseJsonFormatter | None = _BaseJsonFormatter(
                fmt=fmt, datefmt=datefmt
            )
        else:
            self._json_formatter = None

    def format(self, record: logging.LogRecord) -> str:
        """Format the log record as redacted JSON."""
        if self._json_formatter is not None:
            log_dict = self._build_log_dict_jsonlogger(record)
        else:
            log_dict = self._build_log_dict_builtin(record)

        redacted = self._registry.redact_dict(log_dict)
        try:
            return json.dumps(redacted, default=str, indent=self._json_indent)
        except (TypeError, ValueError):
            # Fallback: redact the string representation
            return self._registry.redact(str(log_dict))

    def _build_log_dict_jsonlogger(self, record: logging.LogRecord) -> dict[str, object]:
        """Build log dict using python-json-logger's field selection."""
        assert self._json_formatter is not None
        record.message = record.getMessage()
        if self.usesTime():
            record.asctime = self.formatTime(record, self.datefmt)
        if record.exc_info and not record.exc_text:
            record.exc_text = self.formatException(record.exc_info)

        log_dict: dict[str, object] = {}
        log_dict["message"] = record.message
        log_dict["levelname"] = record.levelname
        log_dict["name"] = record.name
        log_dict["timestamp"] = record.asctime if hasattr(record, "asctime") else None
        if record.exc_text:
            log_dict["exc_info"] = record.exc_text
        if record.stack_info:
            log_dict["stack_info"] = record.stack_info
        # Include any extra fields
        standard_attrs = _get_standard_attrs()
        for key, value in record.__dict__.items():
            if key not in standard_attrs and key not in log_dict:
                log_dict[key] = value
        return log_dict

    def _build_log_dict_builtin(self, record: logging.LogRecord) -> dict[str, object]:
        """Build log dict using a simple built-in approach."""
        record.message = record.getMessage()
        if record.exc_info and not record.exc_text:
            record.exc_text = self.formatException(record.exc_info)

        log_dict: dict[str, object] = {
            "message": record.message,
            "levelname": record.levelname,
            "name": record.name,
            "timestamp": self.formatTime(record, self.datefmt),
        }
        if record.exc_text:
            log_dict["exc_info"] = record.exc_text
        if record.stack_info:
            log_dict["stack_info"] = record.stack_info
        # Include extra fields
        standard_attrs = _get_standard_attrs()
        for key, value in record.__dict__.items():
            if key not in standard_attrs and key not in log_dict:
                log_dict[key] = value
        return log_dict
