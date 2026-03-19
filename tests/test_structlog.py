"""Tests for structlog processor integration."""

from __future__ import annotations

import hushlog
from hushlog import Config
from hushlog._structlog import structlog_processor


class TestStructlogProcessorFactory:
    """Test the structlog_processor() factory function."""

    def test_returns_callable(self) -> None:
        processor = structlog_processor()
        assert callable(processor)

    def test_with_default_config(self) -> None:
        processor = structlog_processor()
        event_dict: dict[str, object] = {"event": "User email: john@example.com"}
        result = processor(None, "info", event_dict)
        assert "[EMAIL REDACTED]" in str(result["event"])
        assert "john@example.com" not in str(result["event"])

    def test_with_custom_config(self) -> None:
        config = Config(disable_patterns=frozenset({"email"}))
        processor = structlog_processor(config=config)
        event_dict: dict[str, object] = {"event": "User email: john@example.com"}
        result = processor(None, "info", event_dict)
        # Email pattern disabled — should pass through
        assert "john@example.com" in str(result["event"])

    def test_with_partial_masking(self) -> None:
        config = Config(mask_style="partial")
        processor = structlog_processor(config=config)
        event_dict: dict[str, object] = {"event": "User email: john@example.com"}
        result = processor(None, "info", event_dict)
        assert "j***@e***.com" in str(result["event"])

    def test_redacts_nested_values(self) -> None:
        processor = structlog_processor()
        event_dict: dict[str, object] = {
            "event": "request",
            "user": {"email": "john@example.com", "id": 42},
        }
        result = processor(None, "info", event_dict)
        user = result["user"]
        assert isinstance(user, dict)
        assert "[EMAIL REDACTED]" in str(user["email"])
        assert user["id"] == 42

    def test_non_string_values_untouched(self) -> None:
        processor = structlog_processor()
        event_dict: dict[str, object] = {
            "event": "test",
            "count": 42,
            "active": True,
            "rate": 3.14,
            "nothing": None,
        }
        result = processor(None, "info", event_dict)
        assert result["count"] == 42
        assert result["active"] is True
        assert result["rate"] == 3.14
        assert result["nothing"] is None

    def test_keys_not_redacted(self) -> None:
        processor = structlog_processor()
        event_dict: dict[str, object] = {"john@example.com": "some value"}
        result = processor(None, "info", event_dict)
        assert "john@example.com" in result

    def test_multiple_pii_types(self) -> None:
        processor = structlog_processor()
        event_dict: dict[str, object] = {
            "event": "user login",
            "email": "john@example.com",
            "phone": "(555) 234-5678",
            "ssn": "078-05-1120",
        }
        result = processor(None, "info", event_dict)
        assert "[EMAIL REDACTED]" in str(result["email"])
        assert "[PHONE REDACTED]" in str(result["phone"])
        assert "[SSN REDACTED]" in str(result["ssn"])


class TestStructlogProcessorPublicAPI:
    """Test that structlog_processor is accessible from hushlog module."""

    def test_import_from_hushlog(self) -> None:
        assert hasattr(hushlog, "structlog_processor")
        assert callable(hushlog.structlog_processor)

    def test_in_all(self) -> None:
        assert "structlog_processor" in hushlog.__all__


class TestStructlogIntegration:
    """Integration test with actual structlog pipeline."""

    def test_full_structlog_pipeline(self) -> None:
        """Run a full structlog pipeline with hushlog processor."""
        try:
            import structlog
        except ImportError:
            import pytest

            pytest.skip("structlog not installed")

        output: list[str] = []

        def capture_renderer(
            logger: object, method_name: str, event_dict: dict[str, object]
        ) -> str:
            rendered = str(event_dict)
            output.append(rendered)
            return rendered

        structlog.configure(
            processors=[
                structlog_processor(),
                capture_renderer,
            ],
            wrapper_class=structlog.BoundLogger,
            logger_factory=structlog.PrintLoggerFactory(),
            cache_logger_on_first_use=False,
        )

        logger = structlog.get_logger()
        logger.info("User login", email="alice@corp.com", ip="192.168.1.100")

        assert len(output) == 1
        assert "alice@corp.com" not in output[0]
        assert "[EMAIL REDACTED]" in output[0]
        assert "192.168.1.100" not in output[0]
        assert "[IPV4 REDACTED]" in output[0]
