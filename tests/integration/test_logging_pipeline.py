"""Integration tests for hushlog logging pipeline.

Verifies that the package installs correctly, the logging pipeline remains
intact after patch/unpatch, redaction flows through correctly, and the
package structure is well-formed.
"""

from __future__ import annotations

import importlib
import logging
import pathlib
from typing import TYPE_CHECKING

import hushlog
from hushlog import Config
from hushlog._formatter import RedactingFormatter

if TYPE_CHECKING:
    import pytest


class TestPackageStructure:
    """Verify the installed package is properly structured."""

    def test_import_hushlog(self) -> None:
        """Package can be imported after install."""
        mod = importlib.import_module("hushlog")
        assert mod is hushlog

    def test_version_matches_pep440(self) -> None:
        """Version string is present and looks like a PEP 440 version."""
        assert hushlog.__version__ == "0.1.0a2"

    def test_all_exports(self) -> None:
        """__all__ lists exactly the public API surface."""
        assert set(hushlog.__all__) == {"patch", "unpatch", "Config"}

    def test_py_typed_marker_exists(self) -> None:
        """py.typed marker file exists for PEP 561 compliance."""
        package_dir = pathlib.Path(hushlog.__file__).parent
        py_typed = package_dir / "py.typed"
        assert py_typed.exists(), "py.typed marker missing — PEP 561 typing won't work"


class TestLoggingPipelineAfterPatch:
    """Ensure patch/unpatch don't break the standard logging pipeline."""

    def test_patch_then_log(self, caplog: pytest.LogCaptureFixture) -> None:
        """Calling patch() then logging should not raise."""
        hushlog.patch()
        try:
            logger = logging.getLogger("hushlog.test.pipeline")
            with caplog.at_level(logging.INFO, logger="hushlog.test.pipeline"):
                logger.info("Hello %s, your id is %d", "world", 42)

            assert len(caplog.records) == 1
            assert "Hello world, your id is 42" in caplog.text
        finally:
            hushlog.unpatch()

    def test_patch_preserves_log_levels(self) -> None:
        """patch() should not alter the root logger's effective level."""
        root = logging.getLogger()
        level_before = root.level
        hushlog.patch()
        try:
            assert root.level == level_before
        finally:
            hushlog.unpatch()

    def test_patch_preserves_handlers(self) -> None:
        """patch() should not add or remove handlers on the root logger."""
        root = logging.getLogger()
        handlers_before = list(root.handlers)
        hushlog.patch()
        try:
            assert root.handlers == handlers_before
        finally:
            hushlog.unpatch()

    def test_multiple_log_calls_after_patch(self, caplog: pytest.LogCaptureFixture) -> None:
        """Multiple log calls at various levels should all succeed after patch."""
        hushlog.patch()
        try:
            logger = logging.getLogger("hushlog.test.multi")
            with caplog.at_level(logging.DEBUG, logger="hushlog.test.multi"):
                logger.debug("debug message")
                logger.info("info message")
                logger.warning("warning message")
                logger.error("error message")

            messages = [r.message for r in caplog.records]
            assert "debug message" in messages
            assert "info message" in messages
            assert "warning message" in messages
            assert "error message" in messages
        finally:
            hushlog.unpatch()


class TestUnpatch:
    """Ensure unpatch() is safe to call in all scenarios."""

    def test_unpatch_without_patch(self) -> None:
        """Calling unpatch() without a prior patch() should not raise."""
        hushlog.unpatch()

    def test_double_unpatch(self) -> None:
        """Calling unpatch() twice should not raise."""
        hushlog.patch()
        hushlog.unpatch()
        hushlog.unpatch()

    def test_patch_unpatch_cycle(self, caplog: pytest.LogCaptureFixture) -> None:
        """A full patch -> log -> unpatch -> log cycle should work cleanly."""
        logger = logging.getLogger("hushlog.test.cycle")

        hushlog.patch()
        with caplog.at_level(logging.INFO, logger="hushlog.test.cycle"):
            logger.info("while patched")
        hushlog.unpatch()

        with caplog.at_level(logging.INFO, logger="hushlog.test.cycle"):
            logger.info("after unpatch")

        messages = [r.message for r in caplog.records]
        assert "while patched" in messages
        assert "after unpatch" in messages


class TestRedactionFlowsThroughPipeline:
    """Verify that redaction actually happens end-to-end through the logging pipeline."""

    def test_custom_pattern_redacted_then_unpatched(self) -> None:
        """Register a custom pattern, patch, log, verify redaction, unpatch, verify no redaction."""
        root = logging.getLogger()
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(message)s"))
        root.addHandler(handler)
        root.setLevel(logging.DEBUG)

        try:
            config = Config(custom_patterns={"secret_token": r"tok_[A-Za-z0-9]+"})
            hushlog.patch(config=config)

            logger = logging.getLogger("hushlog.test.redact_flow")
            record = logger.makeRecord(
                "hushlog.test.redact_flow",
                logging.INFO,
                "",
                0,
                "My token is tok_abc123XYZ",
                (),
                None,
            )
            output = handler.format(record)
            assert "tok_abc123XYZ" not in output
            assert "[SECRET_TOKEN REDACTED]" in output

            hushlog.unpatch()

            record2 = logger.makeRecord(
                "hushlog.test.redact_flow",
                logging.INFO,
                "",
                0,
                "My token is tok_abc123XYZ",
                (),
                None,
            )
            output2 = handler.format(record2)
            assert "tok_abc123XYZ" in output2
        finally:
            hushlog.unpatch()
            root.removeHandler(handler)


class TestPatchWithConfig:
    """Verify patch() works correctly with various Config options."""

    def test_patch_with_default_config(self) -> None:
        """patch(Config()) — zero-config should work same as patch()."""
        root = logging.getLogger()
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(message)s"))
        root.addHandler(handler)
        root.setLevel(logging.DEBUG)

        try:
            hushlog.patch(Config())

            logger = logging.getLogger("hushlog.test.default_config")
            record = logger.makeRecord(
                "hushlog.test.default_config",
                logging.INFO,
                "",
                0,
                "A normal log message",
                (),
                None,
            )
            output = handler.format(record)
            assert "A normal log message" in output
            assert isinstance(handler.formatter, RedactingFormatter)
        finally:
            hushlog.unpatch()
            root.removeHandler(handler)

    def test_patch_with_custom_pattern(self) -> None:
        """patch(Config(custom_patterns=...)) — custom pattern should redact matching text."""
        root = logging.getLogger()
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(message)s"))
        root.addHandler(handler)
        root.setLevel(logging.DEBUG)

        try:
            config = Config(custom_patterns={"test": r"secret\w+"})
            hushlog.patch(config=config)

            logger = logging.getLogger("hushlog.test.custom_pattern")
            record = logger.makeRecord(
                "hushlog.test.custom_pattern",
                logging.INFO,
                "",
                0,
                "The password is secretABC123 ok?",
                (),
                None,
            )
            output = handler.format(record)
            assert "secretABC123" not in output
            assert "[TEST REDACTED]" in output
        finally:
            hushlog.unpatch()
            root.removeHandler(handler)


class TestFormatterWrappingIsTransparent:
    """Verify that RedactingFormatter preserves the original format string."""

    def test_custom_format_preserved_after_patch(self) -> None:
        """A handler with a custom format string should retain formatting after patch."""
        root = logging.getLogger()
        custom_fmt = "%(levelname)s - %(message)s"
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(custom_fmt))
        root.addHandler(handler)
        root.setLevel(logging.DEBUG)

        try:
            config = Config(custom_patterns={"ssn": r"\d{3}-\d{2}-\d{4}"})
            hushlog.patch(config=config)

            logger = logging.getLogger("hushlog.test.format_preserved")
            record = logger.makeRecord(
                "hushlog.test.format_preserved",
                logging.WARNING,
                "",
                0,
                "SSN is 123-45-6789",
                (),
                None,
            )
            output = handler.format(record)

            # Format string should be respected: levelname prefix present
            assert output.startswith("WARNING - ")
            # Redaction should still happen
            assert "123-45-6789" not in output
            assert "[SSN REDACTED]" in output
        finally:
            hushlog.unpatch()
            root.removeHandler(handler)


class TestUnpatchRestoresOriginalState:
    """Verify unpatch() fully restores original formatter objects."""

    def test_formatter_identity_restored(self) -> None:
        """After patch/unpatch, handler.formatter should be the exact same object as before."""
        root = logging.getLogger()
        handler = logging.StreamHandler()
        original_formatter = logging.Formatter("%(message)s")
        handler.setFormatter(original_formatter)
        root.addHandler(handler)

        try:
            formatter_before = handler.formatter
            assert formatter_before is original_formatter

            hushlog.patch()
            # During patch, formatter should be a RedactingFormatter
            assert isinstance(handler.formatter, RedactingFormatter)

            hushlog.unpatch()
            # After unpatch, formatter should be the exact same object
            assert handler.formatter is formatter_before
        finally:
            hushlog.unpatch()
            root.removeHandler(handler)


class TestMultipleHandlers:
    """Verify patch/unpatch works correctly with multiple handlers."""

    def test_patch_wraps_all_handlers(self) -> None:
        """patch() should wrap formatters on all root logger handlers."""
        root = logging.getLogger()
        handler1 = logging.StreamHandler()
        handler1.setFormatter(logging.Formatter("H1: %(message)s"))
        handler2 = logging.StreamHandler()
        handler2.setFormatter(logging.Formatter("H2: %(message)s"))
        root.addHandler(handler1)
        root.addHandler(handler2)

        try:
            hushlog.patch()
            assert isinstance(handler1.formatter, RedactingFormatter)
            assert isinstance(handler2.formatter, RedactingFormatter)
        finally:
            hushlog.unpatch()
            root.removeHandler(handler1)
            root.removeHandler(handler2)

    def test_unpatch_restores_all_handlers(self) -> None:
        """unpatch() should restore original formatters on all handlers."""
        root = logging.getLogger()
        handler1 = logging.StreamHandler()
        fmt1 = logging.Formatter("H1: %(message)s")
        handler1.setFormatter(fmt1)
        handler2 = logging.StreamHandler()
        fmt2 = logging.Formatter("H2: %(message)s")
        handler2.setFormatter(fmt2)
        root.addHandler(handler1)
        root.addHandler(handler2)

        try:
            hushlog.patch()
            hushlog.unpatch()
            assert handler1.formatter is fmt1
            assert handler2.formatter is fmt2
        finally:
            hushlog.unpatch()
            root.removeHandler(handler1)
            root.removeHandler(handler2)

    def test_redaction_applies_to_all_handlers(self) -> None:
        """Redaction should apply through all handlers' formatters."""
        root = logging.getLogger()
        handler1 = logging.StreamHandler()
        handler1.setFormatter(logging.Formatter("%(message)s"))
        handler2 = logging.StreamHandler()
        handler2.setFormatter(logging.Formatter("%(message)s"))
        root.addHandler(handler1)
        root.addHandler(handler2)

        try:
            config = Config(custom_patterns={"apikey": r"key_[A-Za-z0-9]+"})
            hushlog.patch(config=config)

            logger = logging.getLogger("hushlog.test.multi_handler")
            record = logger.makeRecord(
                "hushlog.test.multi_handler",
                logging.INFO,
                "",
                0,
                "API key is key_abc123",
                (),
                None,
            )

            out1 = handler1.format(record)
            out2 = handler2.format(record)

            assert "key_abc123" not in out1
            assert "[APIKEY REDACTED]" in out1
            assert "key_abc123" not in out2
            assert "[APIKEY REDACTED]" in out2
        finally:
            hushlog.unpatch()
            root.removeHandler(handler1)
            root.removeHandler(handler2)


class TestExceptionLogging:
    """Verify that exception information is also redacted."""

    def test_exception_text_redacted(self) -> None:
        """Log an exception containing a pattern-matching string; verify it's redacted."""
        root = logging.getLogger()
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(message)s"))
        root.addHandler(handler)
        root.setLevel(logging.DEBUG)

        try:
            config = Config(custom_patterns={"password": r"pwd_[A-Za-z0-9]+"})
            hushlog.patch(config=config)

            logger = logging.getLogger("hushlog.test.exception")
            try:
                raise ValueError("Connection failed with pwd_SuperSecret99")
            except ValueError:
                import sys

                exc_info = sys.exc_info()
                record = logger.makeRecord(
                    "hushlog.test.exception",
                    logging.ERROR,
                    "",
                    0,
                    "Error occurred with pwd_SuperSecret99",
                    (),
                    exc_info,
                )

            output = handler.format(record)

            # The message portion should be redacted
            assert "pwd_SuperSecret99" not in output.split("\n")[0]
            assert "[PASSWORD REDACTED]" in output

            # The exception traceback portion should also be redacted
            # (the full output includes the traceback with the ValueError message)
            assert "pwd_SuperSecret99" not in output
        finally:
            hushlog.unpatch()
            root.removeHandler(handler)
