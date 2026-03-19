"""Pattern registry for HushLog."""

from __future__ import annotations

import re
import unicodedata
from typing import TYPE_CHECKING, Literal, cast

from hushlog._types import PatternEntry

_NormForm = Literal["NFC", "NFD", "NFKC", "NFKD"]

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


def _make_partial_validated_replacer(
    validator: Callable[[str], bool],
    partial_masker: Callable[[re.Match[str], str], str],
    mask_char: str,
) -> Callable[[re.Match[str]], str]:
    """Create a replacement function that validates before applying partial masking."""

    def _replacer(m: re.Match[str]) -> str:
        return partial_masker(m, mask_char) if validator(m.group()) else m.group()

    return _replacer


def _make_partial_replacer(
    partial_masker: Callable[[re.Match[str], str], str],
    mask_char: str,
) -> Callable[[re.Match[str]], str]:
    """Create a replacement function that applies partial masking without validation."""

    def _replacer(m: re.Match[str]) -> str:
        return partial_masker(m, mask_char)

    return _replacer


class PatternRegistry:
    """Central store of pre-compiled regex patterns with heuristic pre-checks."""

    def __init__(self) -> None:
        self._patterns: dict[str, PatternEntry] = {}
        self._mask_style: str = "full"
        self._mask_char: str = "*"
        self._normalize_form: str = "NFC"

    def register(self, entry: PatternEntry) -> None:
        """Register a redaction pattern."""
        # Validate mask doesn't contain invalid backreferences
        try:
            entry.regex.sub(entry.mask, "")
        except re.error as exc:
            msg = f"Invalid mask for pattern {entry.name!r}: {exc}"
            raise ValueError(msg) from exc
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
        if self._mask_style == "partial":
            return self._redact_partial(text)
        return self._redact_full(text)

    def _redact_full(self, text: str) -> str:
        """Full redaction: replace matches with mask labels like [EMAIL REDACTED]."""
        nf = self._normalize_form
        if nf != "none":
            nf_lit = cast("_NormForm", nf)
            if not unicodedata.is_normalized(nf_lit, text):
                text = unicodedata.normalize(nf_lit, text)
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

    def _redact_partial(self, text: str) -> str:
        """Partial redaction: preserve parts of matched values for readability."""
        nf = self._normalize_form
        if nf != "none":
            nf_lit = cast("_NormForm", nf)
            if not unicodedata.is_normalized(nf_lit, text):
                text = unicodedata.normalize(nf_lit, text)
        mc = self._mask_char
        for entry in self._patterns.values():
            if entry.heuristic is not None and not entry.heuristic(text):
                continue
            if entry.partial_masker is not None:
                if entry.validator is not None:
                    text = entry.regex.sub(
                        _make_partial_validated_replacer(entry.validator, entry.partial_masker, mc),
                        text,
                    )
                else:
                    text = entry.regex.sub(
                        _make_partial_replacer(entry.partial_masker, mc),
                        text,
                    )
            else:
                # No partial masker — fall back to full mask
                if entry.validator is not None:
                    text = entry.regex.sub(
                        _make_validated_replacer(entry.validator, entry.mask),
                        text,
                    )
                else:
                    text = entry.regex.sub(entry.mask, text)
        return text

    def redact_dict(self, data: object, *, _depth: int = 0) -> object:
        """Recursively redact string values in dicts, lists, and tuples.

        Non-string scalars (int, float, bool, None) are returned as-is.
        Keys in dicts are not redacted — only values.
        Max recursion depth of 20 prevents stack overflow on pathological input.
        """
        if _depth > 20:
            return data
        if isinstance(data, str):
            return self.redact(data)
        if isinstance(data, dict):
            return {k: self.redact_dict(v, _depth=_depth + 1) for k, v in data.items()}
        if isinstance(data, (list, tuple)):
            return [self.redact_dict(item, _depth=_depth + 1) for item in data]
        return data

    @classmethod
    def from_config(cls, config: Config) -> PatternRegistry:
        """Build a registry from a Config, applying disable/custom pattern overrides."""
        from hushlog._patterns import get_builtin_patterns

        registry = cls()
        registry._mask_style = config.mask_style
        registry._mask_char = config.mask_character
        registry._normalize_form = config.normalize_form
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
