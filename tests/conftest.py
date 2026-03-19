"""Shared test fixtures for hushlog tests."""

from __future__ import annotations

import pytest

from hushlog._config import Config
from hushlog._registry import PatternRegistry


@pytest.fixture(scope="session")
def default_registry() -> PatternRegistry:
    """Session-scoped default PatternRegistry to avoid per-example creation in fuzz tests."""
    return PatternRegistry.from_config(Config())


@pytest.fixture(scope="session")
def partial_registry() -> PatternRegistry:
    """Session-scoped partial-masking PatternRegistry for fuzz tests."""
    return PatternRegistry.from_config(Config(mask_style="partial"))
