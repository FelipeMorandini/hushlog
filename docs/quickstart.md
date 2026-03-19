# Quick Start

## Basic Usage (Zero-Config)

```python
import logging
import hushlog

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

!!! note
    Call `logging.basicConfig()` (or set up handlers) **before** `hushlog.patch()`.
    `patch()` wraps handlers that exist at call time.

## Partial Masking

```python
from hushlog import Config

hushlog.patch(Config(mask_style="partial"))

logger.info("User email: john@example.com")
# Output: User email: j***@e***.com

logger.info("Card: 4111111111111111")
# Output: Card: ****-****-****-1111
```

## Custom Mask Character

```python
hushlog.patch(Config(mask_style="partial", mask_character="#"))
# Output: j###@e###.com
```

## Disable Specific Patterns

```python
hushlog.patch(Config(disable_patterns=frozenset({"phone", "ipv4"})))
```

## Add Custom Patterns

```python
hushlog.patch(Config(
    custom_patterns={"internal_id": r"ID-[A-Z]{3}-[0-9]{6}"},
))
# Matches: ID-ABC-123456 → [INTERNAL_ID REDACTED]
```

## Teardown

```python
hushlog.unpatch()  # Restores original formatters
```

Both `patch()` and `unpatch()` are idempotent — safe to call multiple times.

## JSON Logging

```python
from hushlog import RedactingJsonFormatter
from hushlog._registry import PatternRegistry
from hushlog._config import Config

registry = PatternRegistry.from_config(Config())
formatter = RedactingJsonFormatter(registry)
handler.setFormatter(formatter)
```

## structlog

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
```

## loguru

```python
from loguru import logger
from hushlog import loguru_sink

logger.remove()
logger.add(loguru_sink(print), format="{message}")
```

## Dict Redaction (Standalone)

```python
import hushlog

data = {"user": {"email": "alice@corp.io", "age": 30}}
clean = hushlog.redact_dict(data)
# {"user": {"email": "[EMAIL REDACTED]", "age": 30}}
```
