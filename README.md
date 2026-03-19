# HushLog

Zero-config PII redaction for Python logging.

[![PyPI version](https://img.shields.io/pypi/v/hushlog)](https://pypi.org/project/hushlog/)
[![Python versions](https://img.shields.io/pypi/pyversions/hushlog)](https://pypi.org/project/hushlog/)
[![CI](https://github.com/FelipeMorandini/hushlog/actions/workflows/ci.yml/badge.svg)](https://github.com/FelipeMorandini/hushlog/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

## Features

- **Zero-config** — one call to `hushlog.patch()` and you're done
- **Non-invasive** — wraps existing formatters, no logger rewrites needed
- **Performant** — pre-compiled regex with heuristic early-exit checks
- **Type-safe** — fully typed with PEP 561 `py.typed` marker
- **Python 3.10+** — supports Python 3.10 through 3.13

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

hushlog.patch()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

logger.info("User email: john@example.com")
# Output: User email: [EMAIL REDACTED]

logger.info("Card: 4111-1111-1111-1111")
# Output: Card: [CREDIT_CARD REDACTED]
```

## What Gets Redacted

| Pattern      | Example Input             | Redacted Output          |
| ------------ | ------------------------- | ------------------------ |
| Email        | `john@example.com`        | `[EMAIL REDACTED]`       |
| Credit Card  | `4111-1111-1111-1111`     | `[CREDIT_CARD REDACTED]` |
| SSN          | `123-45-6789`             | `[SSN REDACTED]`         |
| Phone        | `(555) 123-4567`          | `[PHONE REDACTED]`       |

Credit card detection includes Luhn checksum validation to minimize false positives.

## Planned Patterns (v0.2.0+)

IPv4/IPv6 addresses, AWS keys, Stripe keys, GitHub tokens, JWT tokens, and more. See the [roadmap](ROADMAP.md) for details.

## Configuration

Disable specific patterns or add custom ones:

```python
from hushlog import Config

hushlog.patch(Config(
    disable_patterns=frozenset({"phone"}),
    custom_patterns={"internal_id": r"ID-[A-Z]{3}-[0-9]{6}"},
))
```

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT -- see [LICENSE](LICENSE) for details.
