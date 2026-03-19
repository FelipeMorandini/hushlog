"""Tests for loguru sink wrapper integration."""

from __future__ import annotations

import hushlog
from hushlog import Config
from hushlog._loguru import loguru_sink


class TestLoguruSinkFactory:
    """Test the loguru_sink() factory function."""

    def test_returns_callable(self) -> None:
        sink = loguru_sink(print)
        assert callable(sink)

    def test_redacts_email_in_message(self) -> None:
        output: list[str] = []
        sink = loguru_sink(output.append)
        sink("User email: john@example.com logged in")
        assert len(output) == 1
        assert "[EMAIL REDACTED]" in output[0]
        assert "john@example.com" not in output[0]

    def test_redacts_ssn(self) -> None:
        output: list[str] = []
        sink = loguru_sink(output.append)
        sink("SSN: 078-05-1120")
        assert "[SSN REDACTED]" in output[0]

    def test_redacts_credit_card(self) -> None:
        output: list[str] = []
        sink = loguru_sink(output.append)
        sink("Card: 4111111111111111")
        assert "[CREDIT_CARD REDACTED]" in output[0]

    def test_clean_message_passes_through(self) -> None:
        output: list[str] = []
        sink = loguru_sink(output.append)
        sink("Normal log message without PII")
        assert output[0] == "Normal log message without PII"

    def test_with_custom_config(self) -> None:
        output: list[str] = []
        config = Config(disable_patterns=frozenset({"email"}))
        sink = loguru_sink(output.append, config=config)
        sink("email: john@example.com, SSN: 078-05-1120")
        assert "john@example.com" in output[0]  # Email not redacted
        assert "[SSN REDACTED]" in output[0]  # SSN still redacted

    def test_with_partial_masking(self) -> None:
        output: list[str] = []
        config = Config(mask_style="partial")
        sink = loguru_sink(output.append, config=config)
        sink("email: john@example.com")
        assert "j***@e***.com" in output[0]

    def test_multiple_pii_types(self) -> None:
        output: list[str] = []
        sink = loguru_sink(output.append)
        sink("email: john@example.com phone: (555) 234-5678")
        assert "[EMAIL REDACTED]" in output[0]
        assert "[PHONE REDACTED]" in output[0]


class TestLoguruSinkPublicAPI:
    """Test that loguru_sink is accessible from hushlog module."""

    def test_import_from_hushlog(self) -> None:
        assert hasattr(hushlog, "loguru_sink")
        assert callable(hushlog.loguru_sink)

    def test_in_all(self) -> None:
        assert "loguru_sink" in hushlog.__all__


class TestLoguruIntegration:
    """Integration test with actual loguru pipeline."""

    def test_full_loguru_pipeline(self) -> None:
        """Run a full loguru pipeline with hushlog sink wrapper."""
        try:
            from loguru import logger
        except ImportError:
            import pytest

            pytest.skip("loguru not installed")

        output: list[str] = []

        # Remove default stderr sink
        logger.remove()

        # Add hushlog-wrapped sink
        sink_id = logger.add(
            loguru_sink(output.append),
            format="{message}",
        )

        try:
            logger.info("User alice@corp.com from 192.168.1.100")

            assert len(output) == 1
            assert "alice@corp.com" not in output[0]
            assert "[EMAIL REDACTED]" in output[0]
            assert "192.168.1.100" not in output[0]
            assert "[IPV4 REDACTED]" in output[0]
        finally:
            logger.remove(sink_id)
