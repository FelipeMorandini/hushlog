"""Unit tests for hushlog._registry.PatternRegistry."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

import pytest

from hushlog._config import Config
from hushlog._registry import PatternRegistry
from hushlog._types import PatternEntry

if TYPE_CHECKING:
    from collections.abc import Callable


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def _make_entry(
    name: str = "test",
    pattern: str = r"secret",
    mask: str = "[REDACTED]",
    heuristic: Callable[[str], bool] | None = None,
) -> PatternEntry:
    """Factory for PatternEntry objects used in tests."""
    return PatternEntry(
        name=name,
        regex=re.compile(pattern),
        heuristic=heuristic,
        mask=mask,
    )


@pytest.fixture()
def registry() -> PatternRegistry:
    """Return a fresh empty PatternRegistry."""
    return PatternRegistry()


# ---------------------------------------------------------------------------
# Empty registry
# ---------------------------------------------------------------------------


class TestEmptyRegistry:
    """An empty registry should be a no-op."""

    def test_redact_returns_text_unchanged(self, registry: PatternRegistry) -> None:
        text = "nothing to see here"
        assert registry.redact(text) == text

    def test_len_is_zero(self, registry: PatternRegistry) -> None:
        assert len(registry) == 0

    def test_contains_is_false(self, registry: PatternRegistry) -> None:
        assert "anything" not in registry


# ---------------------------------------------------------------------------
# Register & redact
# ---------------------------------------------------------------------------


class TestRegisterAndRedact:
    """Register patterns and verify redact() works."""

    def test_trivial_pattern(self, registry: PatternRegistry) -> None:
        """Register a pattern matching 'secret', verify it gets redacted."""
        registry.register(_make_entry(name="secret_word", pattern=r"secret", mask="[REDACTED]"))
        assert registry.redact("my secret value") == "my [REDACTED] value"

    def test_pattern_replaces_all_occurrences(self, registry: PatternRegistry) -> None:
        """Regex sub should replace ALL occurrences, not just the first."""
        registry.register(_make_entry(pattern=r"\d{3}", mask="[NUM]"))
        assert registry.redact("abc 123 def 456") == "abc [NUM] def [NUM]"

    def test_registered_pattern_in_contains(self, registry: PatternRegistry) -> None:
        entry = _make_entry(name="email")
        registry.register(entry)
        assert "email" in registry

    def test_len_after_register(self, registry: PatternRegistry) -> None:
        registry.register(_make_entry(name="a"))
        registry.register(_make_entry(name="b"))
        assert len(registry) == 2

    def test_register_same_name_overwrites(self, registry: PatternRegistry) -> None:
        """Registering with the same name should overwrite the previous entry."""
        registry.register(_make_entry(name="x", pattern=r"old", mask="[OLD]"))
        registry.register(_make_entry(name="x", pattern=r"new", mask="[NEW]"))
        assert len(registry) == 1
        assert registry.redact("new old") == "[NEW] old"


# ---------------------------------------------------------------------------
# Heuristic early-exit
# ---------------------------------------------------------------------------


class TestHeuristic:
    """Heuristic pre-checks control whether regex runs."""

    def test_heuristic_false_skips_regex(self, registry: PatternRegistry) -> None:
        """If heuristic returns False the regex should NOT run."""
        entry = _make_entry(
            name="guarded",
            pattern=r"secret",
            mask="[REDACTED]",
            heuristic=lambda text: False,
        )
        registry.register(entry)
        assert registry.redact("my secret value") == "my secret value"

    def test_heuristic_true_runs_regex(self, registry: PatternRegistry) -> None:
        """If heuristic returns True the regex SHOULD run."""
        entry = _make_entry(
            name="guarded",
            pattern=r"secret",
            mask="[REDACTED]",
            heuristic=lambda text: True,
        )
        registry.register(entry)
        assert registry.redact("my secret value") == "my [REDACTED] value"

    def test_heuristic_none_runs_regex(self, registry: PatternRegistry) -> None:
        """If heuristic is None the regex should always run (no guard)."""
        entry = _make_entry(name="no_guard", pattern=r"secret", mask="[REDACTED]", heuristic=None)
        registry.register(entry)
        assert registry.redact("my secret value") == "my [REDACTED] value"

    def test_heuristic_receives_current_text(self, registry: PatternRegistry) -> None:
        """Heuristic should receive the (possibly already-redacted) text."""
        seen: list[str] = []

        def spy(text: str) -> bool:
            seen.append(text)
            return True

        registry.register(_make_entry(name="first", pattern=r"aaa", mask="XXX", heuristic=None))
        registry.register(_make_entry(name="second", pattern=r"bbb", mask="YYY", heuristic=spy))
        registry.redact("aaa bbb")
        # After first pattern, text is "XXX bbb", so heuristic sees that
        assert seen == ["XXX bbb"]


# ---------------------------------------------------------------------------
# Unregister
# ---------------------------------------------------------------------------


class TestUnregister:
    """Unregister patterns."""

    def test_unregister_removes_pattern(self, registry: PatternRegistry) -> None:
        registry.register(_make_entry(name="temp", pattern=r"temp", mask="[GONE]"))
        registry.unregister("temp")
        assert "temp" not in registry
        assert len(registry) == 0
        assert registry.redact("temp data") == "temp data"

    def test_unregister_nonexistent_raises_keyerror(self, registry: PatternRegistry) -> None:
        with pytest.raises(KeyError):
            registry.unregister("does_not_exist")


# ---------------------------------------------------------------------------
# from_config
# ---------------------------------------------------------------------------


class TestFromConfig:
    """Build a registry from Config."""

    def test_from_config_custom_patterns(self) -> None:
        """Custom patterns in Config should be registered in the resulting registry."""
        config = Config(custom_patterns={"digits": r"\d+"})
        registry = PatternRegistry.from_config(config)
        assert "digits" in registry
        assert len(registry) == 5  # 4 builtins + 1 custom

    def test_from_config_disable_patterns_code_path(self) -> None:
        """disable_patterns should remove matching built-in patterns."""
        config = Config(disable_patterns=frozenset({"email", "ssn"}))
        registry = PatternRegistry.from_config(config)
        assert len(registry) == 2  # 4 builtins - 2 disabled
        assert "email" not in registry
        assert "ssn" not in registry

    def test_from_config_empty(self) -> None:
        """Default Config should produce a registry with 4 built-in patterns."""
        config = Config()
        registry = PatternRegistry.from_config(config)
        assert len(registry) == 4

    def test_from_config_multiple_custom_patterns(self) -> None:
        """Multiple custom patterns should all be registered."""
        config = Config(
            custom_patterns={
                "digits": r"\d+",
                "vowels": r"[aeiou]",
            }
        )
        registry = PatternRegistry.from_config(config)
        assert len(registry) == 6  # 4 builtins + 2 custom
        assert "digits" in registry
        assert "vowels" in registry


# ---------------------------------------------------------------------------
# Multiple patterns ordering
# ---------------------------------------------------------------------------


class TestMultiplePatterns:
    """Multiple patterns are applied sequentially."""

    def test_patterns_applied_in_order(self, registry: PatternRegistry) -> None:
        """Patterns run in insertion order; later patterns see earlier redactions."""
        registry.register(_make_entry(name="first", pattern=r"foo", mask="[A]"))
        registry.register(_make_entry(name="second", pattern=r"bar", mask="[B]"))
        assert registry.redact("foo and bar") == "[A] and [B]"

    def test_second_pattern_sees_first_redaction(self, registry: PatternRegistry) -> None:
        """A later pattern can match text introduced by an earlier pattern's mask."""
        registry.register(_make_entry(name="first", pattern=r"secret", mask="MARKER"))
        registry.register(_make_entry(name="second", pattern=r"MARKER", mask="[FINAL]"))
        assert registry.redact("secret") == "[FINAL]"
