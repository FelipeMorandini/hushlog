# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

HushLog is a zero-config Python library that automatically redacts PII and credentials from standard Python logs. Users call `hushlog.patch()` to hook into Python's `logging` module — no logger rewrites needed.

## Build & Development Commands

```bash
# Install dependencies
uv sync --extra dev

# Run all tests
uv run pytest

# Run a single test
uv run pytest tests/test_patterns.py::test_email_redaction -v

# Lint
uv run ruff check .

# Format
uv run ruff format .

# Type check
uv run mypy src/hushlog
```

## Architecture

The library is built around Python's `logging.Formatter` and `logging.Filter`:

- **`PatternRegistry`** — Central store of pre-compiled regex patterns. All regexes are compiled at module load time via `re.compile()`. Implements early-exit heuristic checks (e.g., check for `@` before running full email regex) to minimize overhead on hot logging paths.

- **`RedactingFormatter(logging.Formatter)`** — Wraps any existing formatter. Intercepts `record.msg` and `record.args`, runs them through the `PatternRegistry`, then delegates to the base formatter.

- **`hushlog.patch(config=None)`** — The zero-config entry point. Inspects the root logger (and optionally all active loggers), wrapping their existing formatters with `RedactingFormatter`.

- **`hushlog.Config`** — Optional configuration for disabling built-in patterns, adding custom regex patterns, or changing the mask style.

## Key Design Constraints

- **Performance is critical.** Logging is typically blocking in Python. All regex must be pre-compiled. Use lightweight heuristic pre-checks before expensive patterns. Benchmark any new pattern additions.
- **Zero-config by default.** `hushlog.patch()` with no arguments must work. Advanced config is opt-in.
- **Non-invasive.** The library wraps existing formatters — it never replaces loggers or handlers. Existing `logger.info()` calls remain unchanged.

## Default Redaction Patterns (MVP)

Email, credit card numbers (with Luhn validation), SSN, phone numbers, IPv4/IPv6 addresses, common API keys (AWS, Stripe, GitHub), JWT tokens.

Output format: `[EMAIL REDACTED]`, `[CREDIT_CARD REDACTED]`, etc.

## Development Workflow

Use `/workflow <task description>` to run the full multi-phase development workflow. This orchestrates planning, implementation, testing, review, documentation, and shipping through specialized subagents with automatic reset-on-failure gates.

See `.claude/commands/workflow.md` for the full workflow definition.

## Git & Release Conventions

- Branch naming: `feat/<description>`, `fix/<description>`, `chore/<description>`
- All git actions under the repository owner's identity — no Claude attribution
- Releases are automated via GitHub Actions on tag push (`v*`)
- PRs target `main` and require GitHub Actions + Copilot review to pass

## Roadmap

See `ROADMAP.md` for the full roadmap. The project is in early development (v0.1.0 MVP). Future milestones: partial masking (v0.2.0), structlog/loguru integrations (v0.3.0), production benchmarks (v1.0.0).
