"""Integration tests for JSON log redaction through the full logging pipeline."""

from __future__ import annotations

import io
import json
import logging

from hushlog._config import Config
from hushlog._json_formatter import RedactingJsonFormatter
from hushlog._registry import PatternRegistry


def _make_json_handler(
    **formatter_kwargs: object,
) -> tuple[logging.StreamHandler, io.StringIO]:
    """Create a StreamHandler with a RedactingJsonFormatter backed by StringIO."""
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    registry = PatternRegistry.from_config(Config())
    formatter = RedactingJsonFormatter(registry, **formatter_kwargs)  # type: ignore[arg-type]
    handler.setFormatter(formatter)
    return handler, buf


class TestJsonPipelineEndToEnd:
    """Full pipeline: handler with RedactingJsonFormatter -> log PII -> verify."""

    def test_email_redacted_in_json_output(self) -> None:
        """Log a message with an email via a JSON-formatted handler."""
        root = logging.getLogger()
        handler, buf = _make_json_handler()
        root.addHandler(handler)
        original_level = root.level
        root.setLevel(logging.DEBUG)

        try:
            logger = logging.getLogger("test.json.pipeline.email")
            logger.info("Contact user@example.com for details")
            handler.flush()
            output = buf.getvalue().strip()
            parsed = json.loads(output)
            assert "[EMAIL REDACTED]" in parsed["message"]
            assert "user@example.com" not in parsed["message"]
        finally:
            root.removeHandler(handler)
            root.setLevel(original_level)

    def test_pii_in_extra_fields_redacted(self) -> None:
        """Log with extra fields containing PII."""
        root = logging.getLogger()
        handler, buf = _make_json_handler()
        root.addHandler(handler)
        original_level = root.level
        root.setLevel(logging.DEBUG)

        try:
            logger = logging.getLogger("test.json.pipeline.extra")
            logger.info(
                "User processed",
                extra={"user_email": "alice@corp.io", "user_ssn": "078-05-1120"},
            )
            handler.flush()
            output = buf.getvalue().strip()
            parsed = json.loads(output)
            assert parsed["user_email"] == "[EMAIL REDACTED]"
            assert parsed["user_ssn"] == "[SSN REDACTED]"
        finally:
            root.removeHandler(handler)
            root.setLevel(original_level)

    def test_clean_message_passes_through(self) -> None:
        """A clean message with no PII should be preserved."""
        root = logging.getLogger()
        handler, buf = _make_json_handler()
        root.addHandler(handler)
        original_level = root.level
        root.setLevel(logging.DEBUG)

        try:
            logger = logging.getLogger("test.json.pipeline.clean")
            logger.info("Request 42 completed successfully")
            handler.flush()
            output = buf.getvalue().strip()
            parsed = json.loads(output)
            assert parsed["message"] == "Request 42 completed successfully"
        finally:
            root.removeHandler(handler)
            root.setLevel(original_level)

    def test_multiple_log_lines_all_valid_json(self) -> None:
        """Multiple log calls all produce valid JSON lines."""
        root = logging.getLogger()
        handler, buf = _make_json_handler()
        root.addHandler(handler)
        original_level = root.level
        root.setLevel(logging.DEBUG)

        try:
            logger = logging.getLogger("test.json.pipeline.multi")
            logger.info("First message with user@example.com")
            logger.warning("Second message with SSN 078-05-1120")
            logger.error("Third clean message")
            handler.flush()
            lines = buf.getvalue().strip().split("\n")
            assert len(lines) == 3
            for line in lines:
                parsed = json.loads(line)
                assert "message" in parsed
                assert "user@example.com" not in parsed["message"]
                assert "078-05-1120" not in parsed["message"]
        finally:
            root.removeHandler(handler)
            root.setLevel(original_level)

    def test_mixed_pii_and_secrets(self) -> None:
        """Log message with email, AWS key, and clean data all handled correctly."""
        root = logging.getLogger()
        handler, buf = _make_json_handler()
        root.addHandler(handler)
        original_level = root.level
        root.setLevel(logging.DEBUG)

        try:
            logger = logging.getLogger("test.json.pipeline.mixed")
            logger.info(
                "User admin@corp.com key=AKIAIOSFODNN7EXAMPLE processed",
                extra={"request_id": "abc-123", "count": 5},
            )
            handler.flush()
            output = buf.getvalue().strip()
            parsed = json.loads(output)
            assert "admin@corp.com" not in parsed["message"]
            assert "AKIAIOSFODNN7EXAMPLE" not in parsed["message"]
            assert parsed.get("request_id") == "abc-123"
            assert parsed.get("count") == 5
        finally:
            root.removeHandler(handler)
            root.setLevel(original_level)
