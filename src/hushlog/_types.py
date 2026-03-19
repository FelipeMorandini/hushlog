"""Internal type definitions for HushLog."""

from __future__ import annotations

from typing import TYPE_CHECKING, NamedTuple

if TYPE_CHECKING:
    import re
    from collections.abc import Callable


class PatternEntry(NamedTuple):
    """A single redaction pattern with optional heuristic pre-check and validator."""

    name: str
    regex: re.Pattern[str]
    heuristic: Callable[[str], bool] | None
    mask: str
    validator: Callable[[str], bool] | None = None
