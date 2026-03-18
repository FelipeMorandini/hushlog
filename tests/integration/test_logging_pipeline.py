"""Integration tests for hushlog scaffolding.

Verifies that the package installs correctly, the logging pipeline remains
intact after patch/unpatch, and the package structure is well-formed.
"""

from __future__ import annotations

import importlib
import logging
import pathlib

import hushlog


class TestPackageStructure:
    """Verify the installed package is properly structured."""

    def test_import_hushlog(self) -> None:
        """Package can be imported after install."""
        mod = importlib.import_module("hushlog")
        assert mod is hushlog

    def test_version_matches_pep440(self) -> None:
        """Version string is present and looks like a PEP 440 version."""
        assert hushlog.__version__ == "0.1.0a1"

    def test_all_exports(self) -> None:
        """__all__ lists exactly the public API surface."""
        assert set(hushlog.__all__) == {"patch", "unpatch"}

    def test_py_typed_marker_exists(self) -> None:
        """py.typed marker file exists for PEP 561 compliance."""
        package_dir = pathlib.Path(hushlog.__file__).parent
        py_typed = package_dir / "py.typed"
        assert py_typed.exists(), "py.typed marker missing — PEP 561 typing won't work"


class TestLoggingPipelineAfterPatch:
    """Ensure patch/unpatch don't break the standard logging pipeline."""

    def test_patch_then_log(self, caplog: logging.LogRecord) -> None:  # type: ignore[type-arg]
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

    def test_multiple_log_calls_after_patch(self, caplog: logging.LogRecord) -> None:  # type: ignore[type-arg]
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

    def test_patch_unpatch_cycle(self, caplog: logging.LogRecord) -> None:  # type: ignore[type-arg]
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
