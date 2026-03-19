"""Tests targeting uncovered lines across the codebase."""

from __future__ import annotations

import gc
import json
import logging
import re
import weakref
from unittest.mock import patch as mock_patch

import hushlog
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


# ---------------------------------------------------------------------------
# Weakref handler tracking (v1.0.0-rc.2)
# ---------------------------------------------------------------------------


class TestWeakrefHandlerTracking:
    """Verify WeakKeyDictionary-based handler tracking."""

    def test_gc_handler_does_not_break_unpatch(self) -> None:
        """After patch(), removing and GC-ing a handler doesn't break unpatch()."""
        root = logging.getLogger()
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(message)s"))
        root.addHandler(handler)

        try:
            hushlog.patch()

            # Remove handler from root and drop all references
            root.removeHandler(handler)
            handler_ref = weakref.ref(handler)
            del handler
            gc.collect()

            # Handler should be garbage-collected
            assert handler_ref() is None

            # unpatch should not raise even though the handler is gone
            hushlog.unpatch()
        finally:
            hushlog.unpatch()

    def test_patched_formatters_uses_weakref(self) -> None:
        """_patched_formatters should be a WeakKeyDictionary."""
        assert isinstance(hushlog._patched_formatters, weakref.WeakKeyDictionary)


# ---------------------------------------------------------------------------
# exc_text protection (v1.0.0-rc.2)
# ---------------------------------------------------------------------------


class TestExcTextProtection:
    """Verify that record.exc_text is restored after formatting."""

    def test_exc_text_restored_after_format(self) -> None:
        """After format(), record.exc_text should be restored to its original value."""
        registry = PatternRegistry.from_config(Config())
        formatter = RedactingFormatter(logging.Formatter("%(message)s"), registry)

        record = logging.LogRecord(
            name="test",
            level=logging.ERROR,
            pathname="",
            lineno=0,
            msg="An error occurred",
            args=(),
            exc_info=None,
        )
        # Simulate a cached exc_text with PII
        record.exc_text = "ValueError: user@example.com leaked"

        formatter.format(record)

        # exc_text should be restored to the original value (not the redacted one)
        assert record.exc_text == "ValueError: user@example.com leaked"

    def test_exc_text_none_stays_none(self) -> None:
        """When exc_text is None, it stays None after format()."""
        registry = PatternRegistry.from_config(Config())
        formatter = RedactingFormatter(logging.Formatter("%(message)s"), registry)

        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Normal message",
            args=(),
            exc_info=None,
        )
        assert record.exc_text is None

        formatter.format(record)

        assert record.exc_text is None

    def test_exc_text_restored_even_on_redaction_failure(self) -> None:
        """exc_text is restored even when the main redact() call fails."""
        registry = PatternRegistry.from_config(Config())
        formatter = RedactingFormatter(logging.Formatter("%(message)s"), registry)

        record = logging.LogRecord(
            name="test",
            level=logging.ERROR,
            pathname="",
            lineno=0,
            msg="message",
            args=(),
            exc_info=None,
        )
        record.exc_text = "original exc_text with user@example.com"

        # Make the main redact call fail (the second call to redact)
        call_count = 0
        original_redact = registry.redact

        def failing_redact(text: str) -> str:
            nonlocal call_count
            call_count += 1
            if call_count == 2:  # The main result redaction (second call)
                raise RuntimeError("boom")
            return original_redact(text)

        with mock_patch.object(registry, "redact", side_effect=failing_redact):
            formatter.format(record)

        # exc_text should still be restored
        assert record.exc_text == "original exc_text with user@example.com"


# ---------------------------------------------------------------------------
# Mask validation (v1.0.0-rc.2)
# ---------------------------------------------------------------------------


class TestMaskValidation:
    """Verify that invalid mask backreferences are rejected at registration time."""

    def test_invalid_backreference_raises_valueerror(self) -> None:
        """Registering a pattern with an invalid backreference in the mask raises ValueError."""
        entry = PatternEntry(
            name="bad_mask",
            regex=re.compile(r"foo"),
            heuristic=None,
            mask=r"\1",  # Invalid: no capture group in the regex
        )
        registry = PatternRegistry()
        try:
            registry.register(entry)
            # If we get here, the dry-run didn't raise — that's a test failure
            assert False, "Expected ValueError for invalid backreference"  # noqa: B011
        except ValueError as exc:
            assert "Invalid mask for pattern 'bad_mask'" in str(exc)

    def test_valid_mask_accepted(self) -> None:
        """A valid mask string (no backreferences) is accepted without error."""
        entry = PatternEntry(
            name="good_mask",
            regex=re.compile(r"foo"),
            heuristic=None,
            mask="[FOO REDACTED]",
        )
        registry = PatternRegistry()
        registry.register(entry)
        assert "good_mask" in registry


# ---------------------------------------------------------------------------
# Immutable Config.custom_patterns (v1.0.0-rc.2)
# ---------------------------------------------------------------------------


class TestImmutableCustomPatterns:
    """Verify that Config.custom_patterns cannot be mutated after construction."""

    def test_custom_patterns_is_immutable(self) -> None:
        """Attempting to mutate custom_patterns raises TypeError."""
        config = Config(custom_patterns={"my_pattern": r"secret\d+"})
        try:
            config.custom_patterns["new"] = "value"  # type: ignore[index]
            assert False, "Expected TypeError"  # noqa: B011
        except TypeError:
            pass

    def test_original_dict_mutation_does_not_affect_config(self) -> None:
        """Mutating the original dict after Config construction has no effect."""
        original = {"my_pattern": r"secret\d+"}
        config = Config(custom_patterns=original)
        original["injected"] = r"evil"
        assert "injected" not in config.custom_patterns

    def test_empty_custom_patterns_is_immutable(self) -> None:
        """Even an empty custom_patterns dict becomes immutable."""
        config = Config()
        try:
            config.custom_patterns["new"] = "value"  # type: ignore[index]
            assert False, "Expected TypeError"  # noqa: B011
        except TypeError:
            pass
