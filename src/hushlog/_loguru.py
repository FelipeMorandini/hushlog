"""loguru sink wrapper for HushLog PII redaction."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

    from hushlog._config import Config


def loguru_sink(
    sink: Callable[[str], object],
    config: Config | None = None,
) -> Callable[[object], None]:
    """Wrap a loguru sink with PII redaction.

    Returns a sink function that redacts PII in log messages before
    forwarding them to the wrapped sink.

    Usage::

        from loguru import logger
        from hushlog import loguru_sink

        logger.add(loguru_sink(print))
        logger.info("User email: john@example.com")
        # Output: User email: [EMAIL REDACTED]

    For file sinks, wrap a file-writing function::

        f = open("app.log", "a")
        logger.add(loguru_sink(f.write), format="{message}")

    Args:
        sink: The underlying sink callable (receives a string).
        config: Optional HushLog configuration. If None, uses default Config.

    Returns:
        A loguru-compatible sink function.
    """
    from hushlog._config import Config as _Config
    from hushlog._registry import PatternRegistry

    resolved_config = config if config is not None else _Config()
    registry = PatternRegistry.from_config(resolved_config)

    def _redacting_sink(message: object) -> None:
        redacted = registry.redact(str(message))
        sink(redacted)

    return _redacting_sink
