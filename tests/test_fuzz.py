"""Fuzz tests for regex pattern safety."""

from __future__ import annotations

from typing import TYPE_CHECKING

from hypothesis import given, settings
from hypothesis import strategies as st

if TYPE_CHECKING:
    from hushlog._registry import PatternRegistry


@settings(max_examples=500, deadline=500)  # 500ms per example
@given(text=st.text(min_size=0, max_size=2000))
def test_redact_never_crashes_on_random_input(text: str, default_registry: PatternRegistry) -> None:
    """redact() must never raise on any input."""
    result = default_registry.redact(text)
    assert isinstance(result, str)


@settings(max_examples=500, deadline=500)
@given(text=st.text(min_size=0, max_size=2000))
def test_redact_dict_never_crashes(text: str, default_registry: PatternRegistry) -> None:
    """redact_dict() with string input must never raise."""
    result = default_registry.redact_dict(text)
    assert isinstance(result, str)


@settings(max_examples=200, deadline=500)
@given(
    data=st.dictionaries(
        keys=st.text(min_size=1, max_size=50),
        values=st.text(min_size=0, max_size=500),
        max_size=10,
    )
)
def test_redact_dict_with_random_dicts(
    data: dict[str, str], default_registry: PatternRegistry
) -> None:
    """redact_dict() with random dicts must never raise."""
    result = default_registry.redact_dict(data)
    assert isinstance(result, dict)


@settings(max_examples=200, deadline=500)
@given(text=st.text(min_size=0, max_size=2000))
def test_partial_redact_never_crashes(text: str, partial_registry: PatternRegistry) -> None:
    """Partial masking mode must never crash on any input."""
    result = partial_registry.redact(text)
    assert isinstance(result, str)
