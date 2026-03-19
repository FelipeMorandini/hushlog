"""structlog processor for HushLog PII redaction."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

    from hushlog._config import Config


def structlog_processor(
    config: Config | None = None,
) -> Callable[[object, str, dict[str, object]], dict[str, object]]:
    """Create a structlog processor that redacts PII in event dicts.

    Returns a processor function compatible with structlog's processor chain.
    The processor applies ``PatternRegistry.redact_dict()`` to the event dict,
    redacting all string values while leaving keys and non-string values intact.

    Usage::

        import structlog
        from hushlog import structlog_processor

        structlog.configure(
            processors=[
                structlog.stdlib.add_log_level,
                structlog_processor(),
                structlog.dev.ConsoleRenderer(),
            ],
        )

    Args:
        config: Optional HushLog configuration. If None, uses default Config.

    Returns:
        A structlog processor function.
    """
    from hushlog._config import Config as _Config
    from hushlog._registry import PatternRegistry

    resolved_config = config if config is not None else _Config()
    registry = PatternRegistry.from_config(resolved_config)

    def _processor(
        logger: object,
        method_name: str,
        event_dict: dict[str, object],
    ) -> dict[str, object]:
        redacted = registry.redact_dict(event_dict)
        if not isinstance(redacted, dict):
            return event_dict
        return redacted

    return _processor
