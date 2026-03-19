# Contributing to HushLog

Thank you for your interest in contributing to HushLog! This guide will help you get started.

## Getting Started

1. Fork and clone the repository:

   ```bash
   git clone https://github.com/FelipeMorandini/hushlog.git
   cd hushlog
   ```

2. Install dependencies using [uv](https://docs.astral.sh/uv/):

   ```bash
   uv sync --extra dev
   ```

3. Verify everything works:

   ```bash
   uv run pytest
   ```

## Development Workflow

Create a branch from `main` using the following naming conventions:

- `feat/<description>` for new features
- `fix/<description>` for bug fixes
- `chore/<description>` for maintenance tasks

## Code Quality

All code must pass linting, formatting, and type checks before merging.

```bash
# Lint
uv run ruff check .

# Format
uv run ruff format .

# Type check
uv run mypy src/hushlog
```

## Testing

Run the full test suite with:

```bash
uv run pytest
```

Run a specific test:

```bash
uv run pytest tests/test_init.py::test_version_is_string -v
```

All new code must include tests. Aim for high coverage on any new patterns or logic.

## Pre-commit Hooks

Install pre-commit hooks to automatically check code on each commit:

```bash
uv run pre-commit install
```

This runs Ruff (lint + format) and mypy automatically before every commit.

## Submitting a New Pattern

To add a new built-in PII/secret detection pattern, include all of the following in your PR:

### Pattern Definition (`src/hushlog/_patterns.py`)

```python
# --- Pattern Name ---
# Brief description of what this matches.
# Uses [0-9] instead of \d to prevent Unicode digit bypass.
_PATTERN_NAME_RE = re.compile(r"your-regex-here")

_PATTERN_NAME = PatternEntry(
    name="pattern_name",
    regex=_PATTERN_NAME_RE,
    heuristic=lambda text: "quick_check" in text,  # or None
    mask="[PATTERN_NAME REDACTED]",
    validator=None,  # or a validation function
    partial_masker=_partial_mask_pattern_name,  # for partial masking support
)
```

### Required checklist:

- [ ] Regex uses `[0-9]` instead of `\d` and `[A-Za-z]` instead of `\w`
- [ ] Heuristic pre-check function (or `None` with justification)
- [ ] Partial masker function (preserves first/last characters)
- [ ] Validator function if needed (like Luhn for credit cards)
- [ ] Added to `get_builtin_patterns()` in correct order (specific before general)
- [ ] Unit tests: at least 5 true positives, 3 false positive rejections
- [ ] Integration test through the logging pipeline
- [ ] Updated pattern count in `test_patterns.py` and `test_registry.py`
- [ ] Updated "What Gets Redacted" table in README.md
- [ ] Documented in `docs/configuration.md` disable_patterns table

## Pull Request Process

1. Target the `main` branch.
2. Ensure all CI checks pass (GitHub Actions).
3. Copilot review is required before merging.
4. Keep PRs focused — one logical change per PR.
5. Write clear commit messages describing *why*, not just *what*.
