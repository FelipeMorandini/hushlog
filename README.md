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

logger.info("Processing complete")
```

> **Note:** This is v0.1.0-alpha.1 — the project scaffolding release. PII redaction patterns are being implemented and will land in upcoming alpha releases. See the [roadmap](ROADMAP.md) for details.

## Planned Redaction Patterns

The following patterns will be supported by v0.1.0:

| Pattern      | Example Input                              | Redacted Output           |
| ------------ | ------------------------------------------ | ------------------------- |
| Email        | `john@example.com`                         | `[EMAIL REDACTED]`        |
| Credit Card  | `4111-1111-1111-1111`                      | `[CREDIT_CARD REDACTED]`  |
| SSN          | `123-45-6789`                              | `[SSN REDACTED]`          |
| Phone        | `+1 (555) 123-4567`                        | `[PHONE REDACTED]`        |
| IPv4         | `192.168.1.1`                              | `[IPV4 REDACTED]`         |
| IPv6         | `2001:0db8:85a3::8a2e:0370:7334`          | `[IPV6 REDACTED]`         |
| AWS Key      | `AKIAIOSFODNN7EXAMPLE`                     | `[AWS_KEY REDACTED]`      |
| Stripe Key   | `sk_live_abc123...`                        | `[STRIPE_KEY REDACTED]`   |
| GitHub Token | `ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` | `[GITHUB_TOKEN REDACTED]` |
| JWT          | `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...` | `[JWT REDACTED]`          |

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT -- see [LICENSE](LICENSE) for details.
