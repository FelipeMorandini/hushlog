"""Unit tests for hushlog._config.Config."""

from __future__ import annotations

import pytest

from hushlog._config import Config


class TestConfigDefaults:
    """Test zero-config construction and default values."""

    def test_default_construction(self) -> None:
        """Config() with no arguments should succeed (zero-config)."""
        config = Config()
        assert isinstance(config, Config)

    def test_default_custom_patterns_is_empty_mapping(self) -> None:
        """Default custom_patterns should be an empty immutable mapping."""
        config = Config()
        assert config.custom_patterns == {}
        assert len(config.custom_patterns) == 0

    def test_default_disable_patterns_is_empty_frozenset(self) -> None:
        """Default disable_patterns should be an empty frozenset."""
        config = Config()
        assert config.disable_patterns == frozenset()
        assert isinstance(config.disable_patterns, frozenset)

    def test_default_mask_style_is_full(self) -> None:
        """Default mask_style should be 'full'."""
        config = Config()
        assert config.mask_style == "full"


class TestConfigCustomConstruction:
    """Test construction with all fields explicitly provided."""

    def test_custom_patterns(self) -> None:
        """Config accepts custom_patterns dict."""
        patterns = {"email": r"\S+@\S+", "ssn": r"\d{3}-\d{2}-\d{4}"}
        config = Config(custom_patterns=patterns)
        assert config.custom_patterns == patterns

    def test_disable_patterns(self) -> None:
        """Config accepts disable_patterns frozenset."""
        disabled = frozenset({"email", "phone"})
        config = Config(disable_patterns=disabled)
        assert config.disable_patterns == disabled

    def test_mask_style(self) -> None:
        """Config accepts custom mask_style."""
        config = Config(mask_style="partial")
        assert config.mask_style == "partial"

    def test_all_fields_together(self) -> None:
        """Config with all fields set at once."""
        config = Config(
            custom_patterns={"token": r"tok_\w+"},
            disable_patterns=frozenset({"credit_card"}),
            mask_style="partial",
        )
        assert config.custom_patterns == {"token": r"tok_\w+"}
        assert config.disable_patterns == frozenset({"credit_card"})
        assert config.mask_style == "partial"


class TestConfigImmutability:
    """Test that Config is frozen (immutable)."""

    def test_cannot_set_custom_patterns(self) -> None:
        """Assigning to custom_patterns should raise FrozenInstanceError."""
        config = Config()
        with pytest.raises((AttributeError, TypeError)):
            config.custom_patterns = {"new": "pattern"}  # type: ignore[misc]

    def test_cannot_set_disable_patterns(self) -> None:
        """Assigning to disable_patterns should raise FrozenInstanceError."""
        config = Config()
        with pytest.raises((AttributeError, TypeError)):
            config.disable_patterns = frozenset({"email"})  # type: ignore[misc]

    def test_cannot_set_mask_style(self) -> None:
        """Assigning to mask_style should raise FrozenInstanceError."""
        config = Config()
        with pytest.raises((AttributeError, TypeError)):
            config.mask_style = "other"  # type: ignore[misc]

    def test_cannot_set_arbitrary_attribute(self) -> None:
        """Assigning an undefined attribute should raise (frozen + slots)."""
        config = Config()
        # With frozen=True and slots=True, setting an unknown attribute raises
        # TypeError on Python 3.13+, AttributeError on earlier versions.
        with pytest.raises((AttributeError, TypeError)):
            config.unknown = "value"  # type: ignore[attr-defined]


class TestConfigPatternValidation:
    """Test that custom_patterns regex strings are validated at construction."""

    def test_valid_regex_accepted(self) -> None:
        """Config accepts valid regex patterns."""
        config = Config(custom_patterns={"test": r"\d+", "email": r"\S+@\S+"})
        assert len(config.custom_patterns) == 2

    def test_invalid_regex_raises_valueerror(self) -> None:
        """Config rejects invalid regex with a clear ValueError."""
        with pytest.raises(ValueError, match="Invalid regex for custom pattern 'bad'"):
            Config(custom_patterns={"bad": r"[invalid"})

    def test_invalid_regex_includes_pattern_name(self) -> None:
        """The error message includes which pattern failed."""
        with pytest.raises(ValueError, match="'broken_pattern'"):
            Config(custom_patterns={"broken_pattern": r"(unclosed"})

    def test_multiple_patterns_first_invalid_raises(self) -> None:
        """If any pattern is invalid, construction fails."""
        with pytest.raises(ValueError, match="Invalid regex"):
            Config(custom_patterns={"good": r"\d+", "bad": r"[oops"})

    def test_empty_regex_accepted(self) -> None:
        """An empty regex string is technically valid."""
        config = Config(custom_patterns={"empty": ""})
        assert config.custom_patterns == {"empty": ""}


class TestConfigEquality:
    """Test dataclass-generated equality."""

    def test_equal_configs(self) -> None:
        """Two default configs should be equal."""
        assert Config() == Config()

    def test_unequal_configs(self) -> None:
        """Configs with different values should not be equal."""
        assert Config(mask_style="full") != Config(mask_style="partial")
