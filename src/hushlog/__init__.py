"""HushLog — Zero-config PII redaction for Python logging."""

from __future__ import annotations

__version__ = "0.1.0a1"

__all__ = ["patch", "unpatch"]


def patch() -> None:
    """Zero-config entry point. Wraps existing formatters with RedactingFormatter.

    Call this once at application startup to automatically redact PII and
    credentials from all log output.  No logger rewrites needed.
    """


def unpatch() -> None:
    """Remove HushLog's RedactingFormatter wrappers and restore original formatters."""
