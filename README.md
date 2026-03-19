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

## Configuration

Disable specific built-in patterns or add custom ones:

```python
from hushlog import Config

hushlog.patch(Config(
    disable_patterns=frozenset({"phone"}),
    custom_patterns={"internal_id": r"ID-[A-Z]{3}-[0-9]{6}"},
))
```

> **Note:** The `mask_style` option for partial masking (e.g., `j***@example.com`) is planned for v0.2.0.

## Teardown

Call `unpatch()` to remove HushLog's formatter wrappers and restore the original formatters. This is useful for testing or runtime toggling:

```python
hushlog.unpatch()
```

Calling `unpatch()` without a prior `patch()` is safe (no-op). Calling `patch()` multiple times is also safe (idempotent).

## Limitations

- Only handlers present on the **root logger** at `patch()` time are wrapped. Handlers added later will not be redacted.
- Named loggers with `propagate=False` and their own handlers bypass root-level redaction.
- No structured log support yet (structlog/loguru integrations planned for v0.3.0).
- Phone detection is US NANP only.

## Planned

IPv4/IPv6 addresses, AWS keys, Stripe keys, GitHub tokens, JWT tokens, partial masking, and more. See the [roadmap](ROADMAP.md) for details.

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT -- see [LICENSE](LICENSE) for details.
