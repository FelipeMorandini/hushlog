"""Configuration for HushLog."""

from __future__ import annotations

import re
import types
from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class Config:
    """Optional configuration for HushLog redaction behavior.

    All fields have sensible defaults — constructing Config() gives zero-config behavior.
    """

    custom_patterns: dict[str, str] = field(default_factory=dict)
    disable_patterns: frozenset[str] = field(default_factory=frozenset)
    mask_style: str = "full"
    mask_character: str = "*"
    normalize_form: str = "NFC"

    def __post_init__(self) -> None:
        if self.mask_style not in ("full", "partial"):
            msg = f"mask_style must be 'full' or 'partial', got {self.mask_style!r}"
            raise ValueError(msg)
        if len(self.mask_character) != 1:
            msg = f"mask_character must be a single character, got {self.mask_character!r}"
            raise ValueError(msg)
        if self.normalize_form not in ("NFC", "NFKC", "none"):
            msg = f"normalize_form must be 'NFC', 'NFKC', or 'none', got {self.normalize_form!r}"
            raise ValueError(msg)
        for name, pattern_str in self.custom_patterns.items():
            try:
                re.compile(pattern_str)
            except re.error as exc:
                msg = f"Invalid regex for custom pattern {name!r}: {exc}"
                raise ValueError(msg) from exc
        # Make custom_patterns immutable to prevent external mutation
        if isinstance(self.custom_patterns, dict):
            object.__setattr__(
                self, "custom_patterns", types.MappingProxyType(dict(self.custom_patterns))
            )
