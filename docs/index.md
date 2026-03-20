# HushLog

**Zero-config PII redaction for Python logging.**

HushLog automatically detects and redacts personally identifiable information (PII) and secrets from your Python log output. One call to `patch()` — emails, credit cards, SSNs, phone numbers, API keys, and more are redacted.

## Features

- **Zero-config** — one call to `hushlog.patch()` and you're done
- **21 built-in patterns** — email, credit card (Luhn validated), SSN, phone, JWT, AWS keys, Stripe, GitHub tokens, GCP keys, IPv4/IPv6, CPF, CNPJ, BR phone, IBAN, EU VAT, Aadhaar, PAN, Indian phone, generic secrets
- **Non-invasive** — wraps existing formatters, no logger rewrites needed
- **Partial masking** — `j***@e***.com` instead of `[EMAIL REDACTED]`
- **Ecosystem integrations** — JSON logs, structlog, loguru
- **Performant** — pre-compiled regex with heuristic early-exit checks
- **Type-safe** — fully typed with PEP 561 `py.typed` marker
- **Python 3.10+** — tested on 3.10 through 3.13

## Installation

```bash
pip install hushlog
```

With optional integrations:

```bash
pip install hushlog[json]       # python-json-logger support
pip install hushlog[structlog]  # structlog processor
pip install hushlog[loguru]     # loguru sink wrapper
```

## Quick Example

```python
import logging
import hushlog

logging.basicConfig(level=logging.INFO)
hushlog.patch()

logger = logging.getLogger(__name__)
logger.info("User email: john@example.com")
# Output: User email: [EMAIL REDACTED]
```

See the [Quick Start](quickstart.md) for more examples.
