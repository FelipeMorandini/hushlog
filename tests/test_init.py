"""Smoke tests for the hushlog package."""

from __future__ import annotations

import re

import hushlog


def test_importable() -> None:
    """Package is importable and exposes the expected module attributes."""
    assert hasattr(hushlog, "__version__")
    assert hasattr(hushlog, "patch")
    assert hasattr(hushlog, "unpatch")


def test_version_is_string() -> None:
    """__version__ is a non-empty string."""
    assert isinstance(hushlog.__version__, str)
    assert len(hushlog.__version__) > 0


def test_patch_is_callable() -> None:
    """patch() is callable and returns None (no-op stub)."""
    assert callable(hushlog.patch)
    assert hushlog.patch() is None


def test_unpatch_is_callable() -> None:
    """unpatch() is callable and returns None (no-op stub)."""
    assert callable(hushlog.unpatch)
    assert hushlog.unpatch() is None


def test_all_exports_are_complete() -> None:
    """__all__ lists exactly the intended public API."""
    assert set(hushlog.__all__) == {"patch", "unpatch", "Config"}


def test_all_exports_resolve() -> None:
    """Every name in __all__ is actually defined in the module."""
    for name in hushlog.__all__:
        assert hasattr(hushlog, name), f"{name!r} listed in __all__ but not defined"


def test_no_unexpected_public_exports() -> None:
    """Module does not leak private implementation names as public attributes."""
    public_attrs = {n for n in dir(hushlog) if not n.startswith("_")}
    expected = {"patch", "unpatch", "Config"}
    # Allow standard module-level names that Python or packaging may add
    allowed_extras = {
        "annotations",
        "logging",
        "threading",
        "RedactingFormatter",
        "PatternRegistry",
    }
    unexpected = public_attrs - expected - allowed_extras
    assert not unexpected, f"Unexpected public names: {unexpected}"


def test_version_is_pep440() -> None:
    """__version__ conforms to PEP 440."""
    # Simplified PEP 440 pattern covering release, pre, post, dev segments
    pep440 = re.compile(
        r"^\d+\.\d+\.\d+"
        r"((a|b|rc)\d+)?"
        r"(\.post\d+)?"
        r"(\.dev\d+)?$"
    )
    assert pep440.match(hushlog.__version__), (
        f"Version {hushlog.__version__!r} does not match PEP 440"
    )


def test_patch_idempotent() -> None:
    """Calling patch() multiple times does not raise."""
    hushlog.patch()
    hushlog.patch()


def test_unpatch_idempotent() -> None:
    """Calling unpatch() multiple times (even without prior patch) does not raise."""
    hushlog.unpatch()
    hushlog.unpatch()
