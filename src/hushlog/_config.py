"""Configuration for HushLog."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class Config:
    """Optional configuration for HushLog redaction behavior.

    All fields have sensible defaults — constructing Config() gives zero-config behavior.
    """

    custom_patterns: dict[str, str] = field(default_factory=dict)
    disable_patterns: frozenset[str] = field(default_factory=frozenset)
    mask_style: str = "full"
