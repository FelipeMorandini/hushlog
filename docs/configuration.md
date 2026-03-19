# Configuration

HushLog is zero-config by default — `hushlog.patch()` with no arguments works out of the box. For advanced use, pass a `Config` object.

## Config Options

```python
from hushlog import Config

config = Config(
    custom_patterns={"token": r"tok_[A-Za-z0-9]{32}"},
    disable_patterns=frozenset({"phone", "ipv4"}),
    mask_style="partial",      # "full" (default) or "partial"
    mask_character="*",        # single character, default "*"
)

hushlog.patch(config)
```

### `custom_patterns`

A dictionary mapping pattern names to regex strings. Each custom pattern:

- Is compiled and validated at `Config()` construction time
- Gets an auto-generated mask: `[NAME_UPPER REDACTED]`
- Can override a built-in pattern by using the same name

```python
Config(custom_patterns={
    "internal_id": r"ID-[A-Z]{3}-[0-9]{6}",
    "session": r"sess_[a-f0-9]{32}",
})
```

### `disable_patterns`

A frozenset of built-in pattern names to skip. Available names:

| Name | Pattern |
|------|---------|
| `email` | Email addresses |
| `credit_card` | Credit card numbers (Luhn validated) |
| `ssn` | Social Security Numbers |
| `phone` | US phone numbers |
| `jwt` | JSON Web Tokens |
| `aws_access_key` | AWS access key IDs |
| `aws_secret_key` | AWS secret keys (context-dependent) |
| `stripe_key` | Stripe API keys |
| `github_token` | GitHub tokens |
| `gcp_key` | GCP API keys |
| `ipv4` | IPv4 addresses |
| `ipv6` | IPv6 addresses |
| `cpf` | Brazilian CPF numbers (check digit validated) |
| `cnpj` | Brazilian CNPJ numbers (check digit validated) |
| `br_phone` | Brazilian phone numbers |
| `generic_secret` | Generic secrets (label-based) |

### `mask_style`

- `"full"` (default): replaces matches with `[TYPE REDACTED]`
- `"partial"`: preserves partial information (first/last characters)

### `mask_character`

Single character used for partial masking. Default: `"*"`.

## Validation

`Config` validates all fields at construction time:

- `mask_style` must be `"full"` or `"partial"` — raises `ValueError` otherwise
- `mask_character` must be exactly 1 character — raises `ValueError` otherwise
- `custom_patterns` regex strings are compiled — raises `ValueError` on invalid regex
- `custom_patterns` is made immutable after construction (cannot be modified)
