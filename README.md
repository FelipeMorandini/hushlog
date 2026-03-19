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
from hushlog import Config, RedactingJsonFormatter
from hushlog._registry import PatternRegistry  # internal API

registry = PatternRegistry.from_config(Config())
formatter = RedactingJsonFormatter(registry)

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

## Teardown

Call `unpatch()` to remove HushLog's formatter wrappers and restore the original formatters. This is useful for testing or runtime toggling:

```python
hushlog.unpatch()
```

Calling `unpatch()` without a prior `patch()` is safe (no-op). Calling `patch()` multiple times is also safe (idempotent).

## Limitations

- Only handlers present on the **root logger** at `patch()` time are wrapped. Handlers added later will not be redacted.
- Named loggers with `propagate=False` and their own handlers bypass root-level redaction.
- structlog/loguru integrations planned for v0.3.0.
- Phone detection is US NANP only.

## Planned

Structlog/loguru integrations, pattern validation, and more. See the [roadmap](ROADMAP.md) for details.

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT -- see [LICENSE](LICENSE) for details.
