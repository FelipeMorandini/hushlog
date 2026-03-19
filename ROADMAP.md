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
- [x] Email addresses (RFC 5322 subset with `@` heuristic pre-check)
- [x] Credit card numbers (Visa, MasterCard, Amex, Discover with Luhn validation)
- [x] Social Security Numbers (XXX-XX-XXXX format)
- [x] US phone numbers (multiple formats: parenthesized area code, dashes, dots, spaces)

### 0.1.0-rc.1: MVP Polish
- [x] End-to-end integration tests through Python logging pipeline
- [x] Performance baseline benchmarks (ops/sec for redaction)
- [x] Complete README with zero-config and advanced usage examples
- [x] First PyPI release candidate

### 0.1.0: Release
- [x] Final testing pass
- [x] Tag and release v0.1.0

---

## v0.2.0 — Security Expansion

### 0.2.0-alpha.1: API Key & Token Detection
- [x] AWS access keys (`AKIA...`, `ASIA...`)
- [x] AWS secret keys (context-dependent, requires label prefix)
- [x] Stripe keys (`sk_live_...`, `pk_live_...`, `rk_live_...`)
- [x] GitHub tokens (`ghp_...`, `gho_...`, `ghs_...`, `github_pat_...`)
- [x] GCP API keys (`AIza...`)
- [x] Generic high-entropy secret detection (label-based: password, secret, api_key, etc.)
- [x] JWT tokens (3-5 base64url segments separated by dots)

### 0.2.0-alpha.2: IPv4 & IPv6 Redaction
- [x] IPv4 addresses (with validation, excluding version-number false positives)
- [x] IPv6 addresses (full, compressed, and mixed formats)

### 0.2.0-alpha.3: Partial Masking
- [x] `Config` dataclass with `mask_character` option
- [x] Partial masking for emails: `j***@g***.com`
- [x] Partial masking for credit cards: `****-****-****-1234`
- [x] Partial masking for phone numbers: `(***) ***-1234`
- [x] Partial masking for API keys: `AKIA****...XXXX`

### 0.2.0-alpha.4: Custom Patterns API
- [x] `Config.custom_patterns` — dict of name → regex string
- [x] `Config.disable_patterns` — list of pattern names to skip
- [x] Pattern validation on config load (catch invalid regex early)

### 0.2.0: Release
- [x] Full test coverage for all new patterns and masking modes
- [x] Updated docs and examples
- [x] Tag and release v0.2.0

---

## v0.3.0 — Ecosystem Integrations

### 0.3.0-alpha.1: JSON Log Redaction
- [x] Deep dictionary/list traversal for redacting values in structured log records
- [x] Compatibility with `python-json-logger`
- [x] Redact both string values and nested structures

### 0.3.0-alpha.2: structlog Support
- [x] `hushlog.structlog_processor()` — a structlog processor that redacts event dicts
- [x] Integration test with structlog pipeline

### 0.3.0-alpha.3: loguru Support
- [x] `hushlog.loguru_sink()` — a loguru sink wrapper for PII redaction
- [x] Integration test with loguru

### 0.3.0: Release
- [x] Cross-framework integration tests
- [x] Updated docs with framework-specific guides
- [x] Tag and release v0.3.0

---

## v1.0.0 — Production Ready

### 1.0.0-rc.1: Performance & Reliability
- [x] Comprehensive benchmarks: latency per log line, throughput under load
- [x] Benchmark CI gate (fail if redaction adds >X% overhead)
- [x] 100% test coverage
- [x] Fuzz testing for regex patterns (ReDoS detection)
- [x] Thread-safety verification under concurrent logging
- [ ] ReDoS validation for custom patterns (reject or warn on catastrophic backtracking)
- [x] Unicode normalization (NFC) before redaction to prevent homograph bypasses

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

---

## Future — Internationalization (i18n)

> HushLog v0.1–v1.0 is US-centric for region-specific patterns (SSN, phone). International
> support is planned as optional region packs to avoid bloating the core pattern set.

### Region Packs (optional extras)

**Brazil (`hushlog[br]`):**
- [ ] CPF (`XXX.XXX.XXX-XX` with check digit validation)
- [ ] CNPJ (`XX.XXX.XXX/XXXX-XX`)
- [ ] Brazilian phone numbers (+55 formats, 10-11 digits)
- [ ] RG (regional ID, variable format)

**European Union (`hushlog[eu]`):**
- [ ] IBAN (2-letter country + 2 check digits + up to 30 alphanumeric)
- [ ] UK National Insurance Number (NI: `XX 00 00 00 X`)
- [ ] Netherlands BSN (9 digits with 11-check)
- [ ] German Personalausweisnummer
- [ ] EU VAT numbers (country-prefixed)

**India (`hushlog[in]`):**
- [ ] Aadhaar (12 digits with Verhoeff checksum)
- [ ] PAN (`XXXXX0000X` format)
- [ ] Indian phone numbers (+91 formats)

**Canada (`hushlog[ca]`):**
- [ ] SIN (`XXX-XXX-XXX` with Luhn validation)
- [ ] Canadian phone numbers (+1, same NANP as US — already covered)

**International:**
- [ ] E.164 phone numbers (global format: `+` country code + subscriber)
- [ ] Passport numbers (per-country regex with configurable country set)
- [ ] SWIFT/BIC codes (8 or 11 alphanumeric)

### Architecture
- Region packs register additional `PatternEntry` objects via a plugin mechanism
- Each pack is an optional dependency: `pip install hushlog[br]`
- Core library remains zero-dependency and US-focused
- Users can always add custom patterns via `Config.custom_patterns` for unsupported regions
