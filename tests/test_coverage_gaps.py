"""Tests targeting uncovered lines across the codebase."""

from __future__ import annotations

import json
import logging
import re
from unittest.mock import patch as mock_patch

from hushlog._config import Config
from hushlog._formatter import RedactingFormatter
from hushlog._json_formatter import RedactingJsonFormatter
from hushlog._patterns import (
    _partial_mask_aws_secret_key,
    _partial_mask_email,
    _partial_mask_gcp_key,
    _partial_mask_generic_secret,
    _partial_mask_github_token,
    _partial_mask_stripe_key,
)
from hushlog._registry import PatternRegistry
from hushlog._structlog import structlog_processor
from hushlog._types import PatternEntry

# ---------------------------------------------------------------------------
# _formatter.py lines 30-32: redact() raises an exception
# ---------------------------------------------------------------------------


class TestFormatterRedactException:
    """When registry.redact() raises, format() returns unredacted output."""

    def test_redact_exception_returns_unredacted(self) -> None:
        registry = PatternRegistry.from_config(Config())
        formatter = RedactingFormatter(logging.Formatter("%(message)s"), registry)

        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="user@example.com",
            args=(),
            exc_info=None,
        )

        with mock_patch.object(registry, "redact", side_effect=RuntimeError("boom")):
            result = formatter.format(record)

        # Should return unredacted output since redact() raised
        assert "user@example.com" in result


# ---------------------------------------------------------------------------
# _json_formatter.py: exc_info, stack_info, json dumps fallback
# ---------------------------------------------------------------------------


class TestJsonFormatterBranches:
    """Cover exc_info, stack_info, and JSON dumps fallback in RedactingJsonFormatter."""

    def test_exc_info_included_in_output(self) -> None:
        registry = PatternRegistry.from_config(Config())
        formatter = RedactingJsonFormatter(registry)

        try:
            raise ValueError("secret error with user@example.com")
        except ValueError:
            import sys

            exc_info = sys.exc_info()

        record = logging.LogRecord(
            name="test",
            level=logging.ERROR,
            pathname="",
            lineno=0,
            msg="An error occurred",
            args=(),
            exc_info=exc_info,
        )

        output = formatter.format(record)
        parsed = json.loads(output)
        assert "exc_info" in parsed
        # Email in exception should be redacted
        assert "user@example.com" not in output
        assert "[EMAIL REDACTED]" in output

    def test_stack_info_included_in_output(self) -> None:
        registry = PatternRegistry.from_config(Config())
        formatter = RedactingJsonFormatter(registry)

        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="A message",
            args=(),
            exc_info=None,
        )
        record.stack_info = "Stack trace with user@example.com"

        output = formatter.format(record)
        parsed = json.loads(output)
        assert "stack_info" in parsed
        assert "user@example.com" not in output

    def test_exc_info_in_builtin_path(self) -> None:
        """Cover exc_info branch in _build_log_dict_builtin."""
        registry = PatternRegistry.from_config(Config())
        formatter = RedactingJsonFormatter(registry)
        # Force builtin path by setting _json_formatter to None
        formatter._json_formatter = None

        try:
            raise ValueError("error with user@example.com")
        except ValueError:
            import sys

            exc_info = sys.exc_info()

        record = logging.LogRecord(
            name="test",
            level=logging.ERROR,
            pathname="",
            lineno=0,
            msg="An error",
            args=(),
            exc_info=exc_info,
        )

        output = formatter.format(record)
        parsed = json.loads(output)
        assert "exc_info" in parsed
        assert "user@example.com" not in output

    def test_stack_info_in_builtin_path(self) -> None:
        """Cover stack_info branch in _build_log_dict_builtin."""
        registry = PatternRegistry.from_config(Config())
        formatter = RedactingJsonFormatter(registry)
        formatter._json_formatter = None

        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="A message",
            args=(),
            exc_info=None,
        )
        record.stack_info = "Stack trace with user@example.com"

        output = formatter.format(record)
        parsed = json.loads(output)
        assert "stack_info" in parsed
        assert "user@example.com" not in output

    def test_extra_fields_in_builtin_path(self) -> None:
        """Cover extra fields loop in _build_log_dict_builtin."""
        registry = PatternRegistry.from_config(Config())
        formatter = RedactingJsonFormatter(registry)
        formatter._json_formatter = None

        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="A message",
            args=(),
            exc_info=None,
        )
        record.custom_field = "user@example.com"  # type: ignore[attr-defined]

        output = formatter.format(record)
        parsed = json.loads(output)
        assert "custom_field" in parsed
        assert "user@example.com" not in output

    def test_json_dumps_fallback_on_unserializable(self) -> None:
        """When json.dumps raises, fallback to string redaction."""
        registry = PatternRegistry.from_config(Config())
        formatter = RedactingJsonFormatter(registry)

        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="user@example.com",
            args=(),
            exc_info=None,
        )

        # Mock redact_dict to return something that json.dumps can't serialize
        # even with default=str
        with (
            mock_patch.object(
                registry,
                "redact_dict",
                return_value={"key": float("nan")},
            ),
            mock_patch("json.dumps", side_effect=ValueError("bad")),
        ):
            result = formatter.format(record)

        assert isinstance(result, str)


# ---------------------------------------------------------------------------
# _patterns.py: partial maskers with short/edge-case values
# ---------------------------------------------------------------------------


class TestPartialMaskerEdgeCases:
    """Cover edge-case branches in partial masker functions."""

    def test_stripe_key_short_value(self) -> None:
        """Stripe key <= 8 chars uses full masking."""
        m = re.search(r".+", "sk_live_")
        assert m is not None
        result = _partial_mask_stripe_key(m, "*")
        assert result == "********"

    def test_aws_secret_key_no_separator(self) -> None:
        """AWS secret key without = or : separator falls back to full masking."""
        text = "noseparatorjusttext"
        m = re.search(r".+", text)
        assert m is not None
        result = _partial_mask_aws_secret_key(m, "*")
        assert result == "*" * len(text)

    def test_generic_secret_no_separator(self) -> None:
        """Generic secret without = or : separator falls back to full masking."""
        text = "noseparatorjusttext"
        m = re.search(r".+", text)
        assert m is not None
        result = _partial_mask_generic_secret(m, "*")
        assert result == "*" * len(text)

    def test_email_no_dot_in_domain(self) -> None:
        """Email with no dot in domain uses fallback partial mask."""
        m = re.search(r".+", "user@localhost")
        assert m is not None
        result = _partial_mask_email(m, "*")
        assert result == "u***@***"

    def test_github_token_short_value(self) -> None:
        """GitHub token <= 8 chars uses full masking."""
        m = re.search(r".+", "ghp_1234")
        assert m is not None
        result = _partial_mask_github_token(m, "*")
        assert result == "********"

    def test_gcp_key_short_value(self) -> None:
        """GCP key <= 8 chars uses full masking."""
        m = re.search(r".+", "AIza1234")
        assert m is not None
        result = _partial_mask_gcp_key(m, "*")
        assert result == "********"

    def test_aws_secret_key_with_equals_separator(self) -> None:
        """AWS secret key with = separator keeps label, masks value."""
        text = "aws_secret_key=ABCDEFGHIJKLMNOP"
        m = re.search(r".+", text)
        assert m is not None
        result = _partial_mask_aws_secret_key(m, "*")
        assert result.startswith("aws_secret_key=")
        assert "****" in result

    def test_generic_secret_with_colon_separator(self) -> None:
        """Generic secret with : separator keeps label, masks value."""
        text = "password:mysecretvalue"
        m = re.search(r".+", text)
        assert m is not None
        result = _partial_mask_generic_secret(m, "*")
        assert result.startswith("password:")
        assert "****" in result


# ---------------------------------------------------------------------------
# _structlog.py line 54: redact_dict returns non-dict
# ---------------------------------------------------------------------------


class TestStructlogNonDictReturn:
    """Cover the branch where redact_dict returns a non-dict (plain string input)."""

    def test_structlog_processor_with_string_event_dict(self) -> None:
        """When redact_dict gets a string, it returns a string, so processor returns original."""
        processor_fn = structlog_processor()
        # Normally event_dict is a dict, but test the safety guard
        # by mocking redact_dict to return a string
        original_dict: dict[str, object] = {"event": "test", "email": "user@example.com"}

        # The actual processor calls registry.redact_dict which always returns dict for dict input
        # To trigger line 54, we mock redact_dict to return a non-dict
        with mock_patch.object(PatternRegistry, "redact_dict", return_value="not a dict"):
            result = processor_fn(None, "info", original_dict)

        # Should return the original event_dict since redact_dict returned non-dict
        assert result is original_dict


# ---------------------------------------------------------------------------
# _registry.py: partial redact lambda fallback path (no validator, with partial_masker)
# ---------------------------------------------------------------------------


class TestPartialRedactLambdaFallback:
    """Cover the partial redact path where partial_masker exists but validator is None."""

    def test_partial_masker_without_validator(self) -> None:
        """Pattern with partial_masker but no validator uses lambda path."""

        def simple_masker(m: re.Match[str], mc: str) -> str:
            return mc * len(m.group())

        entry = PatternEntry(
            name="test_pattern",
            regex=re.compile(r"SECRET\w+"),
            heuristic=None,
            mask="[TEST REDACTED]",
            validator=None,
            partial_masker=simple_masker,
        )

        registry = PatternRegistry()
        registry._mask_style = "partial"
        registry._mask_char = "*"
        registry.register(entry)

        result = registry.redact("Found SECRETabc123 here")
        assert "SECRETabc123" not in result
        assert "************" in result

    def test_partial_fallback_no_masker_no_validator(self) -> None:
        """Pattern with no partial_masker and no validator falls back to full mask."""
        entry = PatternEntry(
            name="test_pattern",
            regex=re.compile(r"SECRET\w+"),
            heuristic=None,
            mask="[TEST REDACTED]",
            validator=None,
            partial_masker=None,
        )

        registry = PatternRegistry()
        registry._mask_style = "partial"
        registry._mask_char = "*"
        registry.register(entry)

        result = registry.redact("Found SECRETabc123 here")
        assert "[TEST REDACTED]" in result

    def test_partial_fallback_no_masker_with_validator(self) -> None:
        """Pattern with no partial_masker but with validator falls back to validated full mask."""
        entry = PatternEntry(
            name="test_pattern",
            regex=re.compile(r"SECRET\w+"),
            heuristic=None,
            mask="[TEST REDACTED]",
            validator=lambda text: text.startswith("SECRET"),
            partial_masker=None,
        )

        registry = PatternRegistry()
        registry._mask_style = "partial"
        registry._mask_char = "*"
        registry.register(entry)

        result = registry.redact("Found SECRETabc123 here")
        assert "[TEST REDACTED]" in result


# ---------------------------------------------------------------------------
# Unicode NFC normalization
# ---------------------------------------------------------------------------


class TestUnicodeNormalization:
    """Verify NFC normalization prevents decomposed-form bypasses."""

    def test_nfc_normalization_email(self) -> None:
        """ASCII email is redacted normally (baseline)."""
        registry = PatternRegistry.from_config(Config())
        result = registry.redact("user@example.com")
        assert "[EMAIL REDACTED]" in result

    def test_nfc_decomposed_email(self) -> None:
        """Email with NFD-decomposed characters is normalized before matching."""
        import unicodedata

        registry = PatternRegistry.from_config(Config())
        # "ü" can be composed (U+00FC) or decomposed (U+0075 + U+0308)
        composed = "us\u00fcr@example.com"  # üser
        decomposed = unicodedata.normalize("NFD", composed)
        assert composed != decomposed  # They differ in byte representation
        # Both should produce the same redaction result after NFC
        result_composed = registry.redact(f"email: {composed}")
        result_decomposed = registry.redact(f"email: {decomposed}")
        assert result_composed == result_decomposed
