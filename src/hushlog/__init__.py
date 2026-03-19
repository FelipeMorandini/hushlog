"""HushLog — Zero-config PII redaction for Python logging."""

from __future__ import annotations

import logging
import threading
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hushlog._config import Config

__version__ = "0.3.0a2"

__all__ = [
    "Config",
    "RedactingJsonFormatter",
    "patch",
    "redact_dict",
    "structlog_processor",
    "unpatch",
]

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

    Note: Only handlers present on the root logger at call time are wrapped.
    Handlers added later will not be redacted.
    """
    from hushlog._config import Config as _Config
    from hushlog._formatter import RedactingFormatter
    from hushlog._registry import PatternRegistry

    global _is_patched  # noqa: PLW0603
    with _patch_lock:
        if _is_patched:
            return None

        resolved_config = config if config is not None else _Config()
        registry = PatternRegistry.from_config(resolved_config)

        wrapped = False
        for handler in logging.root.handlers:
            handler_id = id(handler)
            _patched_formatters[handler_id] = handler.formatter
            handler.setFormatter(RedactingFormatter(handler.formatter, registry))
            wrapped = True

        if wrapped:
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


def redact_dict(data: object, config: Config | None = None) -> object:
    """Redact PII in a dict/list/string structure.

    Convenience wrapper around ``PatternRegistry.redact_dict()``.

    .. note::

        This creates a new ``PatternRegistry`` on every call. For repeated use,
        create a registry once via ``PatternRegistry.from_config()`` and call
        ``registry.redact_dict()`` directly.
    """
    from hushlog._config import Config as _Config
    from hushlog._registry import PatternRegistry

    resolved_config = config if config is not None else _Config()
    registry = PatternRegistry.from_config(resolved_config)
    return registry.redact_dict(data)


# Lazy imports for public API symbols
def __getattr__(name: str) -> object:
    if name == "Config":
        from hushlog._config import Config

        return Config
    if name == "RedactingJsonFormatter":
        from hushlog._json_formatter import RedactingJsonFormatter

        return RedactingJsonFormatter
    if name == "structlog_processor":
        from hushlog._structlog import structlog_processor

        return structlog_processor
    msg = f"module {__name__!r} has no attribute {name!r}"
    raise AttributeError(msg)
