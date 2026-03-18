"""HushLog — Zero-config PII redaction for Python logging."""

from __future__ import annotations

import logging
import threading

from hushlog._config import Config
from hushlog._formatter import RedactingFormatter
from hushlog._registry import PatternRegistry

__version__ = "0.1.0a2"

__all__ = ["Config", "patch", "unpatch"]

_patched_formatters: dict[int, logging.Formatter | None] = {}
_is_patched: bool = False
_patch_lock = threading.Lock()


def patch(config: Config | None = None) -> None:
    """Zero-config entry point. Wraps existing formatters with RedactingFormatter.

    Call this once at application startup to automatically redact PII and
    credentials from all log output. No logger rewrites needed.

    Calling ``patch()`` multiple times is safe (idempotent) — subsequent calls
    are no-ops. To change the configuration, call ``unpatch()`` first, then
    ``patch(new_config)``.
    """
    global _is_patched  # noqa: PLW0603
    with _patch_lock:
        if _is_patched:
            return None

        registry = PatternRegistry.from_config(config) if config is not None else PatternRegistry()

        for handler in logging.root.handlers:
            handler_id = id(handler)
            _patched_formatters[handler_id] = handler.formatter
            handler.setFormatter(RedactingFormatter(handler.formatter, registry))

        _is_patched = True
    return None


def unpatch() -> None:
    """Remove HushLog's RedactingFormatter wrappers and restore original formatters."""
    global _is_patched  # noqa: PLW0603
    with _patch_lock:
        if not _is_patched:
            return None

        for handler in logging.root.handlers:
            handler_id = id(handler)
            if handler_id in _patched_formatters:
                handler.setFormatter(_patched_formatters[handler_id])

        _patched_formatters.clear()
        _is_patched = False
    return None
