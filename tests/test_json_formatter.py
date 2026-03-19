"""Unit tests for RedactingJsonFormatter."""

from __future__ import annotations

import json
import logging

from hushlog._config import Config
from hushlog._json_formatter import RedactingJsonFormatter
from hushlog._registry import PatternRegistry


def _make_formatter(**kwargs: object) -> RedactingJsonFormatter:
    """Create a RedactingJsonFormatter with default config."""
    registry = PatternRegistry.from_config(Config())
    return RedactingJsonFormatter(registry, **kwargs)  # type: ignore[arg-type]


def _make_record(
    msg: str,
    level: int = logging.INFO,
    name: str = "test.json",
    **extra: object,
) -> logging.LogRecord:
    """Create a LogRecord, optionally with extra fields."""
    logger = logging.getLogger(name)
    record = logger.makeRecord(name, level, "", 0, msg, (), None)
    for key, value in extra.items():
        setattr(record, key, value)
    return record


class TestOutputIsValidJson:
    """Verify output is always valid JSON."""

    def test_basic_message_is_valid_json(self) -> None:
        formatter = _make_formatter()
        record = _make_record("Hello world")
        output = formatter.format(record)
        parsed = json.loads(output)
        assert isinstance(parsed, dict)
        assert parsed["message"] == "Hello world"

    def test_message_with_special_chars(self) -> None:
        formatter = _make_formatter()
        record = _make_record('He said "hello" & <world>')
        output = formatter.format(record)
        parsed = json.loads(output)
        assert parsed["message"] == 'He said "hello" & <world>'


class TestPiiRedactionInMessage:
    """Verify PII in the message field is redacted."""

    def test_email_in_message_redacted(self) -> None:
        formatter = _make_formatter()
        record = _make_record("Contact user@example.com for help")
        output = formatter.format(record)
        parsed = json.loads(output)
        assert "[EMAIL REDACTED]" in parsed["message"]
        assert "user@example.com" not in parsed["message"]

    def test_ssn_in_message_redacted(self) -> None:
        formatter = _make_formatter()
        record = _make_record("SSN: 078-05-1120")
        output = formatter.format(record)
        parsed = json.loads(output)
        assert "[SSN REDACTED]" in parsed["message"]
        assert "078-05-1120" not in parsed["message"]

    def test_multiple_pii_in_message(self) -> None:
        formatter = _make_formatter()
        record = _make_record("Email alice@corp.io SSN 078-05-1120")
        output = formatter.format(record)
        parsed = json.loads(output)
        assert "[EMAIL REDACTED]" in parsed["message"]
        assert "[SSN REDACTED]" in parsed["message"]


class TestPiiRedactionInExtraFields:
    """Verify PII in extra fields is redacted."""

    def test_email_in_extra_field(self) -> None:
        formatter = _make_formatter()
        record = _make_record("Processing user", user_email="alice@corp.io")
        output = formatter.format(record)
        parsed = json.loads(output)
        assert parsed.get("user_email") == "[EMAIL REDACTED]"

    def test_nested_extra_field(self) -> None:
        formatter = _make_formatter()
        record = _make_record(
            "User data",
            user_data={"email": "bob@test.org", "name": "Bob"},
        )
        output = formatter.format(record)
        parsed = json.loads(output)
        user_data = parsed.get("user_data")
        assert isinstance(user_data, dict)
        assert user_data["email"] == "[EMAIL REDACTED]"
        assert user_data["name"] == "Bob"


class TestNonPiiPassesThrough:
    """Verify non-PII data is preserved."""

    def test_clean_message_unchanged(self) -> None:
        formatter = _make_formatter()
        record = _make_record("Processing request 42 complete")
        output = formatter.format(record)
        parsed = json.loads(output)
        assert parsed["message"] == "Processing request 42 complete"

    def test_standard_fields_present(self) -> None:
        formatter = _make_formatter()
        record = _make_record("test message", level=logging.WARNING, name="myapp")
        output = formatter.format(record)
        parsed = json.loads(output)
        assert parsed["levelname"] == "WARNING"
        assert parsed["name"] == "myapp"
        assert "timestamp" in parsed

    def test_numeric_extra_fields_unchanged(self) -> None:
        formatter = _make_formatter()
        record = _make_record("metrics", request_count=42, latency=0.5)
        output = formatter.format(record)
        parsed = json.loads(output)
        assert parsed.get("request_count") == 42
        assert parsed.get("latency") == 0.5


class TestJsonIndent:
    """Verify json_indent option works."""

    def test_indented_output(self) -> None:
        formatter = _make_formatter(json_indent=2)
        record = _make_record("Hello")
        output = formatter.format(record)
        # Indented JSON has newlines
        assert "\n" in output
        parsed = json.loads(output)
        assert parsed["message"] == "Hello"


class TestWorksWithoutPythonJsonLogger:
    """Verify formatter works with built-in serializer."""

    def test_builtin_serializer_produces_valid_json(self) -> None:
        """Even if python-json-logger is installed, the builtin path should work."""
        registry = PatternRegistry.from_config(Config())
        formatter = RedactingJsonFormatter(registry)
        # Force the builtin path
        formatter._json_formatter = None  # noqa: SLF001
        record = _make_record("Contact user@example.com")
        output = formatter.format(record)
        parsed = json.loads(output)
        assert "[EMAIL REDACTED]" in parsed["message"]
        assert "user@example.com" not in parsed["message"]


class TestFromConfig:
    """Verify RedactingJsonFormatter.from_config() convenience constructor."""

    def test_from_config_default(self) -> None:
        """from_config() with no args creates a working formatter."""
        formatter = RedactingJsonFormatter.from_config()
        record = _make_record("Contact user@example.com")
        output = formatter.format(record)
        parsed = json.loads(output)
        assert "[EMAIL REDACTED]" in parsed["message"]
        assert "user@example.com" not in parsed["message"]

    def test_from_config_with_config(self) -> None:
        """from_config(config) respects the provided config."""
        config = Config(disable_patterns=frozenset({"email"}))
        formatter = RedactingJsonFormatter.from_config(config)
        record = _make_record("Contact user@example.com")
        output = formatter.format(record)
        parsed = json.loads(output)
        assert "user@example.com" in parsed["message"]

    def test_from_config_with_json_indent(self) -> None:
        """from_config() passes json_indent through."""
        formatter = RedactingJsonFormatter.from_config(json_indent=2)
        record = _make_record("Hello")
        output = formatter.format(record)
        assert "\n" in output
        parsed = json.loads(output)
        assert parsed["message"] == "Hello"


class TestImportFromHushlog:
    """Verify RedactingJsonFormatter is importable from hushlog."""

    def test_import(self) -> None:
        from hushlog import RedactingJsonFormatter as RJF

        assert RJF is RedactingJsonFormatter
