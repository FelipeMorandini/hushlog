"""Pattern registry for HushLog."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from hushlog._types import PatternEntry

if TYPE_CHECKING:
    from collections.abc import Callable

    from hushlog._config import Config


def _make_validated_replacer(
    validator: Callable[[str], bool],
    mask: str,
) -> Callable[[re.Match[str]], str]:
    """Create a replacement function that applies a validator before masking."""

    def _replacer(m: re.Match[str]) -> str:
        return mask if validator(m.group()) else m.group()

    return _replacer


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
            if entry.validator is not None:
                text = entry.regex.sub(
                    _make_validated_replacer(entry.validator, entry.mask),
                    text,
                )
            else:
                text = entry.regex.sub(entry.mask, text)
        return text

    @classmethod
    def from_config(cls, config: Config) -> PatternRegistry:
        """Build a registry from a Config, applying disable/custom pattern overrides."""
        from hushlog._patterns import get_builtin_patterns

        registry = cls()
        # Load built-in patterns
        for entry in get_builtin_patterns():
            registry.register(entry)
        # Remove disabled patterns
        for name in config.disable_patterns:
            if name in registry._patterns:
                registry.unregister(name)
        # Add custom patterns (override builtins if same name)
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
