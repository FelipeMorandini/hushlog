"""End-to-end scenario tests for HushLog.

Tests real-world usage patterns including basicConfig integration, concurrent
logging, named logger propagation, and output fidelity for clean messages.
"""

from __future__ import annotations

import concurrent.futures
import io
import logging
import threading

import hushlog
from hushlog import Config


def _make_handler() -> tuple[logging.StreamHandler, io.StringIO]:
    """Create a StreamHandler backed by a StringIO buffer."""
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    handler.setFormatter(logging.Formatter("%(message)s"))
    return handler, buf


class TestBasicConfigThenPatch:
    """Verify the correct order of operations: basicConfig() then patch()."""

    def test_basicconfig_then_patch(self) -> None:
        """Call logging.basicConfig() first, then hushlog.patch(), then log PII."""
        root = logging.getLogger()
        original_handlers = list(root.handlers)
        original_level = root.level

        try:
            # Remove existing handlers so basicConfig actually adds one
            for h in root.handlers[:]:
                root.removeHandler(h)

            logging.basicConfig(level=logging.INFO, format="%(message)s", force=True)

            hushlog.patch()

            logger = logging.getLogger("test.basicconfig")
            logger.info("Contact alice@example.com for help")

            # Capture output from the handler basicConfig created
            handler = root.handlers[0]
            handler.flush()
            # basicConfig uses stderr by default; verify redaction via capfd or
            # check that the formatter is a RedactingFormatter
            from hushlog._formatter import RedactingFormatter

            assert isinstance(handler.formatter, RedactingFormatter)
        finally:
            hushlog.unpatch()
            for h in root.handlers[:]:
                root.removeHandler(h)
            for h in original_handlers:
                root.addHandler(h)
            root.setLevel(original_level)


class TestPatchWithNoHandlers:
    """Verify patch() behavior when no handlers are present."""

    def test_patch_with_no_handlers_wraps_nothing(self) -> None:
        """Clear root handlers, call patch(), verify _is_patched is False."""
        root = logging.getLogger()
        original_handlers = list(root.handlers)
        original_level = root.level

        try:
            # Remove all handlers
            for h in root.handlers[:]:
                root.removeHandler(h)

            hushlog.patch()
            # Access private flag to verify no-handler edge case behavior
            assert hushlog._is_patched is False  # noqa: SLF001

            # Now add a handler via manual setup and patch again
            handler, buf = _make_handler()
            root.addHandler(handler)
            root.setLevel(logging.INFO)

            hushlog.patch()
            assert hushlog._is_patched is True  # noqa: SLF001

            logger = logging.getLogger("test.no_handlers")
            logger.info("SSN: 078-05-1120")
            handler.flush()
            output = buf.getvalue()

            assert "[SSN REDACTED]" in output
            assert "078-05-1120" not in output
        finally:
            hushlog.unpatch()
            for h in root.handlers[:]:
                root.removeHandler(h)
            for h in original_handlers:
                root.addHandler(h)
            root.setLevel(original_level)


class TestConcurrentLoggingRedaction:
    """Verify thread-safe redaction under concurrent load."""

    def test_concurrent_logging_redaction(self) -> None:
        """Multiple threads logging PII concurrently — all output must be redacted."""
        root = logging.getLogger()
        original_handlers = list(root.handlers)
        original_level = root.level

        lock = threading.Lock()
        buf = io.StringIO()

        class ThreadSafeHandler(logging.StreamHandler):
            """StreamHandler that synchronizes writes to the shared buffer."""

            def emit(self, record: logging.LogRecord) -> None:
                msg = self.format(record)
                with lock:
                    buf.write(msg + self.terminator)

        handler = ThreadSafeHandler(buf)
        handler.setFormatter(logging.Formatter("%(message)s"))

        try:
            for h in root.handlers[:]:
                root.removeHandler(h)
            root.addHandler(handler)
            root.setLevel(logging.DEBUG)

            hushlog.patch()

            def log_pii(worker_id: int) -> None:
                logger = logging.getLogger(f"test.concurrent.{worker_id}")
                for i in range(50):
                    logger.info(
                        "User email: user%d_%d@example.com SSN: 078-05-1120",
                        worker_id,
                        i,
                    )

            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
                futures = [executor.submit(log_pii, w) for w in range(4)]
                concurrent.futures.wait(futures)
                # Re-raise any exceptions from workers
                for f in futures:
                    f.result()

            handler.flush()
            output = buf.getvalue()

            # Verify no raw PII leaked
            assert "078-05-1120" not in output
            assert "@example.com" not in output
            # Verify redaction markers are present
            assert "[EMAIL REDACTED]" in output
            assert "[SSN REDACTED]" in output
        finally:
            hushlog.unpatch()
            for h in root.handlers[:]:
                root.removeHandler(h)
            for h in original_handlers:
                root.addHandler(h)
            root.setLevel(original_level)


class TestNamedLoggerPropagation:
    """Verify named logger behavior with root logger patching."""

    def test_named_logger_propagates_to_patched_root(self) -> None:
        """A named logger with propagate=True should have PII redacted at the root."""
        root = logging.getLogger()
        original_handlers = list(root.handlers)
        original_level = root.level

        handler, buf = _make_handler()

        try:
            for h in root.handlers[:]:
                root.removeHandler(h)
            root.addHandler(handler)
            root.setLevel(logging.DEBUG)

            hushlog.patch()

            logger = logging.getLogger("myapp")
            assert logger.propagate is True
            logger.info("Customer phone: (555) 234-5678")
            handler.flush()
            output = buf.getvalue()

            assert "[PHONE REDACTED]" in output
            assert "(555) 234-5678" not in output
        finally:
            hushlog.unpatch()
            for h in root.handlers[:]:
                root.removeHandler(h)
            for h in original_handlers:
                root.addHandler(h)
            root.setLevel(original_level)

    def test_named_logger_no_propagate_not_redacted(self) -> None:
        """A named logger with propagate=False and its own handler bypasses root redaction."""
        root = logging.getLogger()
        original_handlers = list(root.handlers)
        original_level = root.level

        root_handler, root_buf = _make_handler()
        child_handler, child_buf = _make_handler()

        logger = logging.getLogger("myapp.isolated")
        original_propagate = logger.propagate
        original_child_level = logger.level
        original_child_handlers = list(logger.handlers)

        try:
            for h in root.handlers[:]:
                root.removeHandler(h)
            root.addHandler(root_handler)
            root.setLevel(logging.DEBUG)

            hushlog.patch()

            logger.propagate = False
            logger.addHandler(child_handler)
            logger.setLevel(logging.DEBUG)

            logger.info("Customer email: secret@corp.com")
            child_handler.flush()
            child_output = child_buf.getvalue()

            # The child handler is NOT wrapped by patch (known limitation)
            assert "secret@corp.com" in child_output

            # Root handler should have no output since propagate=False
            root_handler.flush()
            root_output = root_buf.getvalue()
            assert root_output == ""
        finally:
            hushlog.unpatch()
            # Restore child logger state
            for h in logger.handlers[:]:
                logger.removeHandler(h)
            for h in original_child_handlers:
                logger.addHandler(h)
            logger.propagate = original_propagate
            logger.setLevel(original_child_level)
            # Restore root state
            for h in root.handlers[:]:
                root.removeHandler(h)
            for h in original_handlers:
                root.addHandler(h)
            root.setLevel(original_level)


class TestCleanMessageByteIdentical:
    """Verify that clean messages pass through without modification."""

    def test_clean_message_byte_identical(self) -> None:
        """A message with no PII should produce identical output whether patched or not."""
        root = logging.getLogger()
        original_handlers = list(root.handlers)
        original_level = root.level
        message = "Processing request 42 complete"

        try:
            # --- Patched run ---
            for h in root.handlers[:]:
                root.removeHandler(h)
            handler1, buf1 = _make_handler()
            root.addHandler(handler1)
            root.setLevel(logging.DEBUG)

            hushlog.patch()
            logger = logging.getLogger("test.clean.patched")
            logger.info(message)
            handler1.flush()
            patched_output = buf1.getvalue()

            hushlog.unpatch()
            root.removeHandler(handler1)

            # --- Unpatched run ---
            handler2, buf2 = _make_handler()
            root.addHandler(handler2)

            logger2 = logging.getLogger("test.clean.unpatched")
            logger2.info(message)
            handler2.flush()
            unpatched_output = buf2.getvalue()

            root.removeHandler(handler2)

            assert patched_output == unpatched_output
        finally:
            hushlog.unpatch()
            for h in root.handlers[:]:
                root.removeHandler(h)
            for h in original_handlers:
                root.addHandler(h)
            root.setLevel(original_level)


class TestApiKeyRedactionThroughPipeline:
    """Verify AWS access key redaction through the full logging pipeline."""

    def test_api_key_redaction_through_pipeline(self) -> None:
        """Log a message containing an AWS access key and verify it is redacted."""
        root = logging.getLogger()
        original_handlers = list(root.handlers)
        original_level = root.level

        handler, buf = _make_handler()

        try:
            for h in root.handlers[:]:
                root.removeHandler(h)
            root.addHandler(handler)
            root.setLevel(logging.DEBUG)

            hushlog.patch()

            logger = logging.getLogger("test.aws_key")
            logger.info("Connecting with key AKIAIOSFODNN7EXAMPLE")
            handler.flush()
            output = buf.getvalue()

            assert "[AWS_ACCESS_KEY REDACTED]" in output
            assert "AKIAIOSFODNN7EXAMPLE" not in output
        finally:
            hushlog.unpatch()
            for h in root.handlers[:]:
                root.removeHandler(h)
            for h in original_handlers:
                root.addHandler(h)
            root.setLevel(original_level)


class TestJwtRedactionThroughPipeline:
    """Verify JWT token redaction through the full logging pipeline."""

    def test_jwt_redaction_through_pipeline(self) -> None:
        """Log a message containing a JWT token and verify it is redacted."""
        root = logging.getLogger()
        original_handlers = list(root.handlers)
        original_level = root.level

        handler, buf = _make_handler()

        try:
            for h in root.handlers[:]:
                root.removeHandler(h)
            root.addHandler(handler)
            root.setLevel(logging.DEBUG)

            hushlog.patch()

            jwt_token = (
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0."
                "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
            )
            logger = logging.getLogger("test.jwt")
            logger.info("Auth token: %s", jwt_token)
            handler.flush()
            output = buf.getvalue()

            assert "[JWT REDACTED]" in output
            assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in output
        finally:
            hushlog.unpatch()
            for h in root.handlers[:]:
                root.removeHandler(h)
            for h in original_handlers:
                root.addHandler(h)
            root.setLevel(original_level)


class TestMixedSecretsAndPii:
    """Verify multiple secret types and PII are all redacted in one message."""

    def test_mixed_secrets_and_pii(self) -> None:
        """Log email + AWS key + Stripe key in one message, verify all three redacted."""
        root = logging.getLogger()
        original_handlers = list(root.handlers)
        original_level = root.level

        handler, buf = _make_handler()

        try:
            for h in root.handlers[:]:
                root.removeHandler(h)
            root.addHandler(handler)
            root.setLevel(logging.DEBUG)

            hushlog.patch()

            logger = logging.getLogger("test.mixed_secrets")
            logger.info(
                "User admin@corp.com aws=AKIAIOSFODNN7EXAMPLE"
                " stripe=sk_test_00000000000000000000000000"
            )
            handler.flush()
            output = buf.getvalue()

            assert "[EMAIL REDACTED]" in output
            assert "admin@corp.com" not in output
            assert "[AWS_ACCESS_KEY REDACTED]" in output
            assert "AKIAIOSFODNN7EXAMPLE" not in output
            assert "[STRIPE_KEY REDACTED]" in output
            assert "sk_test_00000000000000000000000000" not in output
        finally:
            hushlog.unpatch()
            for h in root.handlers[:]:
                root.removeHandler(h)
            for h in original_handlers:
                root.addHandler(h)
            root.setLevel(original_level)


class TestGenericSecretThroughPipeline:
    """Verify generic secret pattern redaction through the logging pipeline."""

    def test_generic_secret_through_pipeline(self) -> None:
        """Log a password=value pattern and verify it is redacted."""
        root = logging.getLogger()
        original_handlers = list(root.handlers)
        original_level = root.level

        handler, buf = _make_handler()

        try:
            for h in root.handlers[:]:
                root.removeHandler(h)
            root.addHandler(handler)
            root.setLevel(logging.DEBUG)

            hushlog.patch()

            logger = logging.getLogger("test.generic_secret")
            logger.info("Config: password=MyS3cr3tValue123")
            handler.flush()
            output = buf.getvalue()

            assert "[SECRET REDACTED]" in output
            assert "MyS3cr3tValue123" not in output
        finally:
            hushlog.unpatch()
            for h in root.handlers[:]:
                root.removeHandler(h)
            for h in original_handlers:
                root.addHandler(h)
            root.setLevel(original_level)


class TestDisableApiKeyPatterns:
    """Verify disable_patterns correctly skips API key and JWT patterns."""

    def test_disable_api_key_patterns(self) -> None:
        """Disable aws_access_key and jwt patterns; verify they are NOT redacted but email IS."""
        root = logging.getLogger()
        original_handlers = list(root.handlers)
        original_level = root.level

        handler, buf = _make_handler()

        try:
            for h in root.handlers[:]:
                root.removeHandler(h)
            root.addHandler(handler)
            root.setLevel(logging.DEBUG)

            config = Config(disable_patterns=frozenset({"aws_access_key", "jwt"}))
            hushlog.patch(config=config)

            jwt_token = (
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0."
                "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
            )
            logger = logging.getLogger("test.disable_api_keys")
            logger.info(
                "User admin@corp.com key=AKIAIOSFODNN7EXAMPLE token=%s",
                jwt_token,
            )
            handler.flush()
            output = buf.getvalue()

            # Email SHOULD be redacted
            assert "[EMAIL REDACTED]" in output
            assert "admin@corp.com" not in output

            # AWS key should NOT be redacted (pattern disabled)
            assert "AKIAIOSFODNN7EXAMPLE" in output
            assert "[AWS_ACCESS_KEY REDACTED]" not in output

            # JWT should NOT be redacted (pattern disabled)
            assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" in output
            assert "[JWT REDACTED]" not in output
        finally:
            hushlog.unpatch()
            for h in root.handlers[:]:
                root.removeHandler(h)
            for h in original_handlers:
                root.addHandler(h)
            root.setLevel(original_level)
