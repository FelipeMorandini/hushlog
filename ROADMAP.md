# HushLog Roadmap

> Keep your logs loud, but your users' secrets quiet.

## v0.1.0 — MVP (Foundation)

### 0.1.0-alpha.1: Project Scaffolding
- [x] Python package structure (`src/hushlog/`)
- [x] `pyproject.toml` with build system, dependencies, and dev extras
- [x] Development tooling: ruff, mypy, pytest, pre-commit
- [x] GitHub Actions: CI pipeline (lint, type-check, test on Python 3.10–3.13)
- [x] GitHub Actions: Automated release pipeline (on tag push → build → publish to PyPI)
- [x] `CONTRIBUTING.md`, `SECURITY.md`, `LICENSE`
- [x] Basic `README.md` with installation and quickstart

### 0.1.0-alpha.2: Core Engine
- [x] `PatternRegistry` — singleton pattern store with compiled regexes and heuristic pre-checks
- [x] `RedactingFormatter(logging.Formatter)` — wraps base formatter, redacts final output string
- [x] `hushlog.patch()` — zero-config entry point, wraps root logger formatters
- [x] `hushlog.unpatch()` — clean teardown for testing and runtime toggling

### 0.1.0-alpha.3: Basic PII Patterns
- [ ] Email addresses (RFC 5322 subset with `@` heuristic pre-check)
- [ ] Credit card numbers (Visa, MasterCard, Amex, Discover with Luhn validation)
- [ ] Social Security Numbers (XXX-XX-XXXX format)
- [ ] US phone numbers (multiple formats: parenthesized area code, dashes, dots, spaces)

### 0.1.0-rc.1: MVP Polish
- [ ] End-to-end integration tests through Python logging pipeline
- [ ] Performance baseline benchmarks (ops/sec for redaction)
- [ ] Complete README with zero-config and advanced usage examples
- [ ] First PyPI release candidate

### 0.1.0: Release
- [ ] Final testing pass
- [ ] Tag and release v0.1.0

---

## v0.2.0 — Security Expansion

### 0.2.0-alpha.1: API Key & Token Detection
- [ ] AWS access keys (`AKIA...`)
- [ ] AWS secret keys
- [ ] Stripe keys (`sk_live_...`, `pk_live_...`)
- [ ] GitHub tokens (`ghp_...`, `gho_...`, `ghs_...`)
- [ ] GCP API keys
- [ ] Generic high-entropy secret detection (base64 strings with key-like prefixes)
- [ ] JWT tokens (three base64 segments separated by dots)

### 0.2.0-alpha.2: IPv4 & IPv6 Redaction
- [ ] IPv4 addresses (with validation, excluding version-number false positives)
- [ ] IPv6 addresses (full, compressed, and mixed formats)

### 0.2.0-alpha.3: Partial Masking
- [ ] `Config` dataclass with `mask_character` option
- [ ] Partial masking for emails: `j***@g***.com`
- [ ] Partial masking for credit cards: `****-****-****-1234`
- [ ] Partial masking for phone numbers: `(***) ***-1234`
- [ ] Partial masking for API keys: `AKIA****...XXXX`

### 0.2.0-alpha.4: Custom Patterns API
- [ ] `Config.custom_patterns` — dict of name → regex string
- [ ] `Config.disable_patterns` — list of pattern names to skip
- [ ] Pattern validation on config load (catch invalid regex early)

### 0.2.0: Release
- [ ] Full test coverage for all new patterns and masking modes
- [ ] Updated docs and examples
- [ ] Tag and release v0.2.0

---

## v0.3.0 — Ecosystem Integrations

### 0.3.0-alpha.1: JSON Log Redaction
- [ ] Deep dictionary/list traversal for redacting values in structured log records
- [ ] Compatibility with `python-json-logger`
- [ ] Redact both string values and nested structures

### 0.3.0-alpha.2: structlog Support
- [ ] `hushlog.structlog_processor()` — a structlog processor that redacts event dicts
- [ ] Integration test with structlog pipeline

### 0.3.0-alpha.3: loguru Support
- [ ] `hushlog.loguru_patcher()` — a loguru patcher/sink wrapper
- [ ] Integration test with loguru

### 0.3.0: Release
- [ ] Cross-framework integration tests
- [ ] Updated docs with framework-specific guides
- [ ] Tag and release v0.3.0

---

## v1.0.0 — Production Ready

### 1.0.0-rc.1: Performance & Reliability
- [ ] Comprehensive benchmarks: latency per log line, throughput under load
- [ ] Benchmark CI gate (fail if redaction adds >X% overhead)
- [ ] 100% test coverage
- [ ] Fuzz testing for regex patterns (ReDoS detection)
- [ ] Thread-safety verification under concurrent logging
- [ ] ReDoS validation for custom patterns (reject or warn on catastrophic backtracking)
- [ ] Unicode normalization (NFC) before redaction to prevent homograph bypasses

### 1.0.0-rc.2: Hardening
- [ ] Track patched handlers via `weakref.WeakKeyDictionary` instead of `id()` to handle handler removal
- [ ] Protect `record.exc_text` from leaking unredacted exception text (format a shallow copy or restore after)
- [ ] Validate mask strings at registration time (reject invalid backreferences)
- [ ] Make `Config.custom_patterns` truly immutable (`MappingProxyType` or defensive copy)
- [ ] Document heuristic security model (trusted code only, not user-supplied)

### 1.0.0-rc.3: Documentation & Community
- [ ] MkDocs or ReadTheDocs site
- [ ] API reference (auto-generated from docstrings)
- [ ] Contribution guide with pattern submission template
- [ ] Security policy and vulnerability reporting process

### 1.0.0: Release
- [ ] Final audit pass
- [ ] Stable PyPI release
- [ ] Go-to-market: r/Python, r/netsec, Hacker News
