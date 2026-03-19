"""Unit tests for PatternRegistry.redact_dict()."""

from __future__ import annotations

from hushlog._config import Config
from hushlog._registry import PatternRegistry


def _make_registry() -> PatternRegistry:
    """Create a default registry with built-in patterns."""
    return PatternRegistry.from_config(Config())


class TestRedactDictFlatDict:
    """Test redaction of flat dictionaries."""

    def test_email_in_value_redacted(self) -> None:
        registry = _make_registry()
        data = {"contact": "user@example.com"}
        result = registry.redact_dict(data)
        assert isinstance(result, dict)
        assert result["contact"] == "[EMAIL REDACTED]"

    def test_ssn_in_value_redacted(self) -> None:
        registry = _make_registry()
        data = {"ssn": "078-05-1120"}
        result = registry.redact_dict(data)
        assert isinstance(result, dict)
        assert result["ssn"] == "[SSN REDACTED]"

    def test_multiple_pii_values(self) -> None:
        registry = _make_registry()
        data = {"email": "alice@corp.io", "phone": "(212) 555-1234"}
        result = registry.redact_dict(data)
        assert isinstance(result, dict)
        assert result["email"] == "[EMAIL REDACTED]"
        assert result["phone"] == "[PHONE REDACTED]"


class TestRedactDictNested:
    """Test redaction of nested structures."""

    def test_nested_dict_two_levels(self) -> None:
        registry = _make_registry()
        data = {"user": {"email": "john@example.com", "name": "John"}}
        result = registry.redact_dict(data)
        assert isinstance(result, dict)
        inner = result["user"]
        assert isinstance(inner, dict)
        assert inner["email"] == "[EMAIL REDACTED]"
        assert inner["name"] == "John"

    def test_nested_dict_three_levels(self) -> None:
        registry = _make_registry()
        data = {"level1": {"level2": {"ssn": "078-05-1120"}}}
        result = registry.redact_dict(data)
        assert isinstance(result, dict)
        assert result["level1"]["level2"]["ssn"] == "[SSN REDACTED]"  # type: ignore[index]


class TestRedactDictLists:
    """Test redaction of list values."""

    def test_list_of_strings_with_pii(self) -> None:
        registry = _make_registry()
        data = ["user@example.com", "078-05-1120", "safe text"]
        result = registry.redact_dict(data)
        assert isinstance(result, list)
        assert result[0] == "[EMAIL REDACTED]"
        assert result[1] == "[SSN REDACTED]"
        assert result[2] == "safe text"

    def test_list_inside_dict(self) -> None:
        registry = _make_registry()
        data = {"emails": ["alice@corp.io", "bob@test.org"]}
        result = registry.redact_dict(data)
        assert isinstance(result, dict)
        assert isinstance(result["emails"], list)
        assert result["emails"][0] == "[EMAIL REDACTED]"
        assert result["emails"][1] == "[EMAIL REDACTED]"


class TestRedactDictMixedTypes:
    """Test that non-string scalars are left untouched."""

    def test_int_unchanged(self) -> None:
        registry = _make_registry()
        assert registry.redact_dict(42) == 42

    def test_float_unchanged(self) -> None:
        registry = _make_registry()
        assert registry.redact_dict(3.14) == 3.14

    def test_bool_unchanged(self) -> None:
        registry = _make_registry()
        assert registry.redact_dict(True) is True

    def test_none_unchanged(self) -> None:
        registry = _make_registry()
        assert registry.redact_dict(None) is None

    def test_mixed_dict(self) -> None:
        registry = _make_registry()
        data = {
            "count": 5,
            "active": True,
            "email": "user@example.com",
            "ratio": 0.75,
            "empty": None,
        }
        result = registry.redact_dict(data)
        assert isinstance(result, dict)
        assert result["count"] == 5
        assert result["active"] is True
        assert result["email"] == "[EMAIL REDACTED]"
        assert result["ratio"] == 0.75
        assert result["empty"] is None


class TestRedactDictEdgeCases:
    """Test edge cases."""

    def test_empty_dict(self) -> None:
        registry = _make_registry()
        assert registry.redact_dict({}) == {}

    def test_empty_list(self) -> None:
        registry = _make_registry()
        assert registry.redact_dict([]) == []

    def test_plain_string_delegates_to_redact(self) -> None:
        registry = _make_registry()
        result = registry.redact_dict("Contact user@example.com")
        assert isinstance(result, str)
        assert "[EMAIL REDACTED]" in result
        assert "user@example.com" not in result

    def test_dict_keys_not_redacted(self) -> None:
        registry = _make_registry()
        data = {"john@example.com": "some value"}
        result = registry.redact_dict(data)
        assert isinstance(result, dict)
        assert "john@example.com" in result
        assert result["john@example.com"] == "some value"

    def test_max_depth_guard(self) -> None:
        """Data nested deeper than 20 levels is returned unchanged."""
        registry = _make_registry()
        # Build a structure 25 levels deep with PII at the bottom
        data: object = "user@example.com"
        for _ in range(25):
            data = {"nested": data}
        result = registry.redact_dict(data)
        # Walk down to the bottom -- beyond depth 20, the email should be unchanged
        current = result
        for _ in range(25):
            assert isinstance(current, dict)
            current = current["nested"]
        # At depth 25, the string was not redacted because depth > 20
        assert current == "user@example.com"

    def test_tuple_treated_as_list(self) -> None:
        registry = _make_registry()
        data = ("user@example.com", "safe")
        result = registry.redact_dict(data)
        assert isinstance(result, list)
        assert result[0] == "[EMAIL REDACTED]"
        assert result[1] == "safe"


class TestRedactDictConvenience:
    """Test the module-level redact_dict() convenience function."""

    def test_convenience_function(self) -> None:
        import hushlog

        data = {"email": "user@example.com"}
        result = hushlog.redact_dict(data)
        assert isinstance(result, dict)
        assert result["email"] == "[EMAIL REDACTED]"

    def test_convenience_function_with_config(self) -> None:
        import hushlog

        config = Config(disable_patterns=frozenset({"email"}))
        data = {"email": "user@example.com"}
        result = hushlog.redact_dict(data, config=config)
        assert isinstance(result, dict)
        # Email should NOT be redacted because the pattern is disabled
        assert result["email"] == "user@example.com"
