"""Performance benchmarks for HushLog redaction."""

from __future__ import annotations

import io
import logging

import pytest

from hushlog import Config
from hushlog._registry import PatternRegistry


@pytest.fixture()
def registry() -> PatternRegistry:
    """Pre-built registry with default patterns."""
    return PatternRegistry.from_config(Config())


# --- Direct redaction benchmarks ---


def test_bench_no_pii_short(benchmark, registry: PatternRegistry) -> None:  # type: ignore[no-untyped-def]
    """Baseline: short message with no PII."""
    text = "Processing request completed successfully in 42ms"
    benchmark(registry.redact, text)


def test_bench_no_pii_long(benchmark, registry: PatternRegistry) -> None:  # type: ignore[no-untyped-def]
    """Baseline: long message with no PII."""
    text = "DEBUG: " + "Processing request data chunk " * 20 + "completed"
    benchmark(registry.redact, text)


def test_bench_single_email(benchmark, registry: PatternRegistry) -> None:  # type: ignore[no-untyped-def]
    """Single email redaction."""
    text = "User logged in: john.doe@example.com from web client"
    benchmark(registry.redact, text)


def test_bench_single_credit_card(benchmark, registry: PatternRegistry) -> None:  # type: ignore[no-untyped-def]
    """Single credit card redaction (includes Luhn validation)."""
    text = "Payment processed with card 4111111111111111 for $99.99"
    benchmark(registry.redact, text)


def test_bench_multi_pii(benchmark, registry: PatternRegistry) -> None:  # type: ignore[no-untyped-def]
    """Worst case: message with all PII types."""
    text = (
        "User john@example.com (SSN: 078-05-1120) called from (555) 234-5678 "
        "and paid with card 4111111111111111"
    )
    benchmark(registry.redact, text)


def test_bench_full_pipeline(benchmark) -> None:  # type: ignore[no-untyped-def]
    """Full logging pipeline: logger.info() through patched handler."""
    import hushlog

    root = logging.getLogger()
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    handler.setFormatter(logging.Formatter("%(message)s"))
    root.addHandler(handler)
    original_level = root.level
    root.setLevel(logging.DEBUG)

    hushlog.patch()

    def log_with_pii() -> None:
        logger = logging.getLogger("bench.pipeline")
        logger.info("User john@example.com paid with 4111111111111111")
        buf.truncate(0)
        buf.seek(0)

    try:
        benchmark(log_with_pii)
    finally:
        hushlog.unpatch()
        root.removeHandler(handler)
        root.setLevel(original_level)
