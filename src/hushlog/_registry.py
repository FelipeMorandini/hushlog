"""Pattern registry for HushLog."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from hushlog._types import PatternEntry

if TYPE_CHECKING:
    from hushlog._config import Config


class PatternRegistry:
    """Central store of pre-compiled regex patterns with heuristic pre-checks."""

    def __init__(self) -> None:
        self._patterns: dict[str, PatternEntry] = {}

    def register(self, entry: PatternEntry) -> None:
        """Register a redaction pattern."""
        self._patterns[entry.name] = entry

    def unregister(self, name: str) -> None:
        """Remove a pattern by name. Raises KeyError if not found."""
        del self._patterns[name]

    def redact(self, text: str) -> str:
        """Apply all registered patterns to the text, returning the redacted result.

        This is the hot path — performance matters. For each pattern:
        1. If a heuristic is defined and returns False, skip (early exit).
        2. Otherwise, run regex substitution.
        """
        for entry in self._patterns.values():
            if entry.heuristic is not None and not entry.heuristic(text):
                continue
            text = entry.regex.sub(entry.mask, text)
        return text

    @classmethod
    def from_config(cls, config: Config) -> PatternRegistry:
        """Build a registry from a Config, applying disable/custom pattern overrides."""
        registry = cls()
        # Start with built-in patterns (none for alpha.2, will be populated in alpha.3)
        # Remove disabled patterns
        for name in config.disable_patterns:
            if name in registry._patterns:
                registry.unregister(name)
        # Add custom patterns
        for name, pattern_str in config.custom_patterns.items():
            entry = PatternEntry(
                name=name,
                regex=re.compile(pattern_str),
                heuristic=None,
                mask=f"[{name.upper()} REDACTED]",
            )
            registry.register(entry)
        return registry

    def __len__(self) -> int:
        return len(self._patterns)

    def __contains__(self, name: object) -> bool:
        return name in self._patterns
