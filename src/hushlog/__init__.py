"""HushLog — Zero-config PII redaction for Python logging."""

from __future__ import annotations

import logging
import threading
import weakref
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hushlog._config import Config as Config
    from hushlog._json_formatter import RedactingJsonFormatter as RedactingJsonFormatter
    from hushlog._loguru import loguru_sink as loguru_sink
    from hushlog._registry import PatternRegistry as PatternRegistry
    from hushlog._structlog import structlog_processor as structlog_processor

__version__ = "1.4.0"

__all__ = [
    "Config",
    "PatternRegistry",
    "RedactingJsonFormatter",
    "loguru_sink",
    "patch",
    "redact_dict",
    "structlog_processor",
    "unpatch",
]

_patched_formatters: weakref.WeakKeyDictionary[logging.Handler, logging.Formatter | None] = (
    weakref.WeakKeyDictionary()
)
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
            _patched_formatters[handler] = handler.formatter
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
            if handler in _patched_formatters:
                handler.setFormatter(_patched_formatters[handler])

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
    if name == "PatternRegistry":
        from hushlog._registry import PatternRegistry

        return PatternRegistry
    if name == "RedactingJsonFormatter":
        from hushlog._json_formatter import RedactingJsonFormatter

        return RedactingJsonFormatter
    if name == "structlog_processor":
        from hushlog._structlog import structlog_processor

        return structlog_processor
    if name == "loguru_sink":
        from hushlog._loguru import loguru_sink

        return loguru_sink
    msg = f"module {__name__!r} has no attribute {name!r}"
    raise AttributeError(msg)
