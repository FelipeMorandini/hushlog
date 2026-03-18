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

## Pull Request Process

1. Target the `main` branch.
2. Ensure all CI checks pass (GitHub Actions).
3. Copilot review is required before merging.
4. Keep PRs focused — one logical change per PR.
5. Write clear commit messages describing *why*, not just *what*.
