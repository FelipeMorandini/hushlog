"""Redacting formatter for Python's logging module."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hushlog._registry import PatternRegistry

_logger = logging.getLogger("hushlog._formatter")


class RedactingFormatter(logging.Formatter):
    """Wraps an existing formatter, redacting the final output string."""

    def __init__(self, base_formatter: logging.Formatter | None, registry: PatternRegistry) -> None:
        super().__init__()
        self._base_formatter = base_formatter
        self._registry = registry

    def format(self, record: logging.LogRecord) -> str:
        """Format the record using the base formatter, then redact the result."""
        if self._base_formatter is not None:
            result = self._base_formatter.format(record)
        else:
            result = logging.Formatter.format(self, record)

        # Redact exc_text if the base formatter cached it on the record
        original_exc_text = record.exc_text
        if record.exc_text is not None:
            record.exc_text = self._registry.redact(record.exc_text)

        try:
            return self._registry.redact(result)
        except Exception:
            _logger.debug("Redaction failed, returning unredacted output", exc_info=True)
            return result
        finally:
            # Restore original exc_text to avoid permanent mutation
            record.exc_text = original_exc_text
