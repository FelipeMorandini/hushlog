"""Unit tests for hushlog._formatter.RedactingFormatter."""

from __future__ import annotations

import copy
import logging
import re

import pytest

from hushlog._formatter import RedactingFormatter
from hushlog._registry import PatternRegistry
from hushlog._types import PatternEntry

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def _make_entry(
    name: str = "test",
    pattern: str = r"secret",
    mask: str = "[REDACTED]",
) -> PatternEntry:
    """Factory for PatternEntry objects used in tests."""
    return PatternEntry(
        name=name,
        regex=re.compile(pattern),
        heuristic=None,
        mask=mask,
    )


def _make_record(
    msg: str = "hello",
    args: tuple[object, ...] | None = None,
    level: int = logging.INFO,
    logger_name: str = "test",
) -> logging.LogRecord:
    """Create a LogRecord for testing."""
    record = logging.LogRecord(
        name=logger_name,
        level=level,
        pathname="test.py",
        lineno=1,
        msg=msg,
        args=args if args is not None else (),
        exc_info=None,
    )
    return record


@pytest.fixture()
def populated_registry() -> PatternRegistry:
    """Registry with a single pattern that redacts 'secret'."""
    registry = PatternRegistry()
    registry.register(_make_entry())
    return registry


@pytest.fixture()
def empty_registry() -> PatternRegistry:
    """Empty registry (no patterns)."""
    return PatternRegistry()


# ---------------------------------------------------------------------------
# Wrapping a base formatter
# ---------------------------------------------------------------------------


class TestWithBaseFormatter:
    """RedactingFormatter wrapping an explicit base formatter."""

    def test_output_is_redacted(self, populated_registry: PatternRegistry) -> None:
        """The formatted output should have 'secret' replaced."""
        base = logging.Formatter("%(message)s")
        fmt = RedactingFormatter(base, populated_registry)
        record = _make_record(msg="my secret value")
        result = fmt.format(record)
        assert result == "my [REDACTED] value"

    def test_base_formatter_format_string_preserved(
        self, populated_registry: PatternRegistry
    ) -> None:
        """The base formatter's format string should be respected."""
        base = logging.Formatter("[%(levelname)s] %(message)s")
        fmt = RedactingFormatter(base, populated_registry)
        record = _make_record(msg="secret data", level=logging.WARNING)
        result = fmt.format(record)
        assert result == "[WARNING] [REDACTED] data"

    def test_percent_style_args_redacted(self, populated_registry: PatternRegistry) -> None:
        """%-style message args should be formatted then redacted."""
        base = logging.Formatter("%(message)s")
        fmt = RedactingFormatter(base, populated_registry)
        record = _make_record(msg="value is %s", args=("secret",))
        result = fmt.format(record)
        assert result == "value is [REDACTED]"


# ---------------------------------------------------------------------------
# None base formatter (default formatting)
# ---------------------------------------------------------------------------


class TestWithNoneBaseFormatter:
    """RedactingFormatter with base_formatter=None uses default formatting."""

    def test_default_formatting_works(self, populated_registry: PatternRegistry) -> None:
        """With None base, formatting should still produce output and redact it."""
        fmt = RedactingFormatter(None, populated_registry)
        record = _make_record(msg="my secret")
        result = fmt.format(record)
        assert "[REDACTED]" in result
        assert "secret" not in result

    def test_default_formatting_includes_message(self, empty_registry: PatternRegistry) -> None:
        """With None base and empty registry, output should contain the message."""
        fmt = RedactingFormatter(None, empty_registry)
        record = _make_record(msg="plain message")
        result = fmt.format(record)
        assert "plain message" in result


# ---------------------------------------------------------------------------
# Record is NOT mutated
# ---------------------------------------------------------------------------


class TestRecordNotMutated:
    """RedactingFormatter must not mutate record.msg or record.args."""

    def test_msg_unchanged(self, populated_registry: PatternRegistry) -> None:
        """record.msg should be identical before and after format()."""
        base = logging.Formatter("%(message)s")
        fmt = RedactingFormatter(base, populated_registry)
        record = _make_record(msg="my secret value")
        original_msg = record.msg
        fmt.format(record)
        assert record.msg == original_msg

    def test_args_unchanged(self, populated_registry: PatternRegistry) -> None:
        """record.args should be identical before and after format()."""
        base = logging.Formatter("%(message)s")
        fmt = RedactingFormatter(base, populated_registry)
        args = ("secret",)
        record = _make_record(msg="val=%s", args=args)
        original_args = record.args
        fmt.format(record)
        assert record.args == original_args


# ---------------------------------------------------------------------------
# Empty registry
# ---------------------------------------------------------------------------


class TestWithEmptyRegistry:
    """With no patterns, output should match the base formatter exactly."""

    def test_output_identical_to_base(self, empty_registry: PatternRegistry) -> None:
        """RedactingFormatter with empty registry should produce same output as base."""
        base = logging.Formatter("[%(levelname)s] %(message)s")
        fmt = RedactingFormatter(base, empty_registry)
        record = _make_record(msg="hello world", level=logging.ERROR)

        # Format with base directly for comparison
        record_copy = copy.copy(record)
        expected = base.format(record_copy)

        result = fmt.format(record)
        assert result == expected


# ---------------------------------------------------------------------------
# Exception text redaction
# ---------------------------------------------------------------------------


class TestExceptionTextRedaction:
    """Exception info in the formatted output should also be redacted."""

    def test_exc_text_is_redacted(self, populated_registry: PatternRegistry) -> None:
        """If the record has exception info, the traceback text should be redacted."""
        base = logging.Formatter("%(message)s")
        fmt = RedactingFormatter(base, populated_registry)

        try:
            raise ValueError("secret error details")
        except ValueError:
            import sys

            exc_info = sys.exc_info()

        record = _make_record(msg="an error occurred")
        record.exc_info = exc_info
        result = fmt.format(record)

        # The word "secret" from the exception message should be redacted
        assert "[REDACTED]" in result
        assert "secret" not in result
        # The formatted output should still contain traceback structure
        assert "ValueError" in result
