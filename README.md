# HushLog

Zero-config PII redaction for Python logging.

[![PyPI version](https://img.shields.io/pypi/v/hushlog)](https://pypi.org/project/hushlog/)
[![Python versions](https://img.shields.io/pypi/pyversions/hushlog)](https://pypi.org/project/hushlog/)
[![CI](https://github.com/FelipeMorandini/hushlog/actions/workflows/ci.yml/badge.svg)](https://github.com/FelipeMorandini/hushlog/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

## Features

- **Zero-config** -- one call to `hushlog.patch()` and you're done
- **Non-invasive** -- wraps existing formatters, no logger rewrites needed
- **Performant** -- pre-compiled regex with heuristic early-exit checks
- **Type-safe** -- fully typed with PEP 561 `py.typed` marker
- **Python 3.10+** -- supports Python 3.10 through 3.13

## Installation

```bash
pip install hushlog
```

Or with [uv](https://docs.astral.sh/uv/):

```bash
uv add hushlog
```

## Quick Start

```python
import logging
import hushlog

# Configure logging FIRST, then patch
logging.basicConfig(level=logging.INFO)
hushlog.patch()

logger = logging.getLogger(__name__)

logger.info("User email: john@example.com")
# Output: User email: [EMAIL REDACTED]

logger.info("Card: 4111-1111-1111-1111")
# Output: Card: [CREDIT_CARD REDACTED]

logger.info("SSN: 123-45-6789")
# Output: SSN: [SSN REDACTED]
```

## How It Works

HushLog wraps your existing logging formatters with a `RedactingFormatter` that scans the final formatted string for PII patterns. It never replaces loggers or handlers -- your existing `logger.info()` calls remain unchanged. All regex patterns are pre-compiled at import time with lightweight heuristic pre-checks to minimize overhead on the hot logging path.

## What Gets Redacted

| Pattern | Example | Output | Notes |
| --- | --- | --- | --- |
| Email | `john@example.com` | `[EMAIL REDACTED]` | RFC 5322 subset, `@` heuristic pre-check |
| Credit Card | `4111-1111-1111-1111` | `[CREDIT_CARD REDACTED]` | Luhn validated, supports spaces/dashes |
| SSN | `123-45-6789` | `[SSN REDACTED]` | Dashed format only, invalid ranges excluded |
| Phone | `(555) 123-4567` | `[PHONE REDACTED]` | US NANP, multiple formats |
| JWT | `eyJhbGci...` | `[JWT REDACTED]` | 3-5 segment base64url tokens |
| AWS Access Key | `AKIAIOSFODNN7EXAMPLE` | `[AWS_ACCESS_KEY REDACTED]` | AKIA/ASIA prefixed |
| AWS Secret Key | `aws_secret_access_key=...` | `[AWS_SECRET_KEY REDACTED]` | Context-dependent (requires label) |
| Stripe Key | `sk_live_abc123...` | `[STRIPE_KEY REDACTED]` | sk/pk/rk live/test keys |
| GitHub Token | `ghp_xxxx...` | `[GITHUB_TOKEN REDACTED]` | Classic + fine-grained (`github_pat_`) |
| GCP API Key | `AIzaSyA...` | `[GCP_KEY REDACTED]` | AIza-prefixed keys |
| Generic Secret | `password=MyS3cret` | `[SECRET REDACTED]` | Label-based (password, secret, api_key, etc.) |
| IPv4 | `192.168.1.1` | `[IPV4 REDACTED]` | Octet-validated, rejects version strings |
| IPv6 | `2001:db8::8a2e:370:7334` | `[IPV6 REDACTED]` | Full, compressed, and mixed forms |
| CPF | `529.982.247-25` | `[CPF REDACTED]` | Brazilian individual taxpayer ID, check digit validated |
| CNPJ | `11.222.333/0001-81` | `[CNPJ REDACTED]` | Brazilian company taxpayer ID, check digit validated |
| BR Phone | `(11) 91234-5678` | `[BR_PHONE REDACTED]` | Brazilian mobile/landline, optional +55 prefix |
| IBAN | `GB29 NWBK 6016 1331 9268 19` | `[IBAN REDACTED]` | International bank account number, mod-97 validated |
| EU VAT | `DE123456789` | `[EU_VAT REDACTED]` | EU VAT numbers with country prefix |
| Aadhaar | `2345 6789 0124` | `[AADHAAR REDACTED]` | Indian 12-digit ID, Verhoeff checksum validated |
| PAN | `BNZPM2501F` | `[PAN REDACTED]` | Indian Permanent Account Number, entity type validated |
| IN Phone | `+91 98765 43210` | `[IN_PHONE REDACTED]` | Indian mobile numbers, optional +91/0 prefix |
| SIN | `130-692-544` | `[SIN REDACTED]` | Canadian Social Insurance Number, Luhn validated |
| E.164 Phone | `+44 7911 123456` | `[E164_PHONE REDACTED]` | International phone numbers, 8-15 digits |
| SWIFT/BIC | `DEUTDEFF` | `[SWIFT REDACTED]` | Bank identifier codes, 8 or 11 characters |

## Configuration

Disable specific built-in patterns or add custom ones:

```python
from hushlog import Config

hushlog.patch(Config(
    disable_patterns=frozenset({"phone"}),
    custom_patterns={"internal_id": r"ID-[A-Z]{3}-[0-9]{6}"},
))
```

### Partial Masking

Show partial values instead of full redaction:

```python
hushlog.patch(Config(mask_style="partial"))
# john@example.com → j***@e***.com
# 4111111111111111 → ****-****-****-1111
# 078-05-1120      → ***-**-1120
# (555) 234-5678   → (***) ***-5678
```

Use a custom mask character:

```python
hushlog.patch(Config(mask_style="partial", mask_character="#"))
# john@example.com → j###@e###.com
```

> **Note:** Partial masking reveals partial information (first/last characters). In small organizations, this may be identifying. Use `mask_style="full"` (default) for maximum privacy.

## JSON / Structured Logging

HushLog supports JSON log output with automatic PII redaction in all string values, including nested structures.

### RedactingJsonFormatter

Use `RedactingJsonFormatter` as a drop-in JSON formatter for any handler:

```python
import logging
from hushlog import RedactingJsonFormatter

formatter = RedactingJsonFormatter.from_config()

handler = logging.StreamHandler()
handler.setFormatter(formatter)
logging.getLogger().addHandler(handler)

logger = logging.getLogger(__name__)
logger.info("Contact user@example.com", extra={"ssn": "078-05-1120"})
# Output: {"message": "Contact [EMAIL REDACTED]", "ssn": "[SSN REDACTED]", ...}
```

Works with or without [`python-json-logger`](https://pypi.org/project/python-json-logger/) installed. Install the optional dependency for enhanced JSON serialization:

```bash
pip install hushlog[json]
```

### redact_dict()

For manual redaction of dict/list/string structures:

```python
import hushlog

data = {"user": {"email": "alice@corp.io", "name": "Alice", "age": 30}}
clean = hushlog.redact_dict(data)
# {"user": {"email": "[EMAIL REDACTED]", "name": "Alice", "age": 30}}
```

> **Note:** `redact_dict()` creates a new `PatternRegistry` on every call. For repeated use, create a registry once via `PatternRegistry.from_config()` and call `registry.redact_dict()` directly.

### structlog

Use `structlog_processor()` as a processor in your structlog pipeline:

```python
import structlog
from hushlog import structlog_processor

structlog.configure(
    processors=[
        structlog.stdlib.add_log_level,
        structlog_processor(),
        structlog.dev.ConsoleRenderer(),
    ],
)

logger = structlog.get_logger()
logger.info("login", email="alice@corp.com")
# Output: email=[EMAIL REDACTED]
```

Install the optional dependency: `pip install hushlog[structlog]`

### loguru

Wrap any loguru sink with PII redaction:

```python
from loguru import logger
from hushlog import loguru_sink

logger.remove()  # Remove default sink
logger.add(loguru_sink(print), format="{message}")

logger.info("User alice@corp.com logged in")
# Output: User [EMAIL REDACTED] logged in
```

Install the optional dependency: `pip install hushlog[loguru]`

## Teardown

Call `unpatch()` to remove HushLog's formatter wrappers and restore the original formatters. This is useful for testing or runtime toggling:

```python
hushlog.unpatch()
```

Calling `unpatch()` without a prior `patch()` is safe (no-op). Calling `patch()` multiple times is also safe (idempotent).

## Limitations

- Only handlers present on the **root logger** at `patch()` time are wrapped. Handlers added later will not be redacted.
- Named loggers with `propagate=False` and their own handlers bypass root-level redaction.
- For structlog/loguru, use the dedicated integrations (`structlog_processor`, `loguru_sink`) instead of `patch()`.
- Phone detection covers US NANP, Brazilian, Indian, and E.164 international formats.

## Security Model

HushLog uses **regex-based pattern matching** for PII detection. This is a best-effort approach with known trade-offs:

- **Heuristic pre-checks** (e.g., checking for `@` before running email regex) are **performance optimizations**, not security boundaries. They reduce regex invocations but do not guarantee detection.
- **Regex patterns** are pre-compiled and tested against common formats, but they cannot detect PII in obfuscated, encrypted, or encoded forms.
- **Partial masking** (`mask_style="partial"`) reveals partial information by design. In small organizations, first/last characters may be identifying. Use `mask_style="full"` for maximum privacy.
- **Custom patterns** are compiled at Config construction and validated, but HushLog does not check for ReDoS vulnerability in user-supplied regex. Use tested patterns from trusted sources.
- **Unicode normalization** (NFC) is applied before redaction to handle decomposed character forms, but does not protect against confusable characters (homoglyphs like Cyrillic "a" vs Latin "a").

For high-security environments, combine HushLog with additional controls (log access restrictions, encryption at rest, audit logging).

## Planned

Production hardening, docs site, and more. See the [roadmap](ROADMAP.md) for details.

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT -- see [LICENSE](LICENSE) for details.
