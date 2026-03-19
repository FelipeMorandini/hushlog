# Security Model

HushLog uses **regex-based pattern matching** for PII detection. This is a best-effort approach with known trade-offs documented below.

## How It Works

1. `hushlog.patch()` wraps existing logging formatters with `RedactingFormatter`
2. Each log message passes through 13 pre-compiled regex patterns
3. Heuristic pre-checks (e.g., `"@" in text`) skip patterns unlikely to match
4. Matched text is replaced with mask strings (full or partial)

## Trade-Offs

### Heuristic Pre-Checks

Heuristics like checking for `@` before running the email regex are **performance optimizations**, not security boundaries. They reduce regex invocations but do not guarantee detection. A log message that somehow contains an email without `@` (encoded, split across lines) would bypass the heuristic — but would also bypass the regex itself.

### Regex Limitations

- Patterns cannot detect PII in **obfuscated, encrypted, or encoded** forms (base64-encoded emails, ROT13, etc.)
- **Structured data** within string values is handled, but PII in binary blobs or compressed data is not
- **Context-dependent patterns** (AWS secret keys, generic secrets) require label keywords — unlabeled secrets are not detected

### Partial Masking

`mask_style="partial"` reveals partial information by design:

- Email: `j***@e***.com` — first character of local part + domain
- Credit card: `****-****-****-1234` — last 4 digits
- Phone: `(***) ***-5678` — last 4 digits

In small organizations, first/last characters may be identifying. Use `mask_style="full"` for maximum privacy.

### Custom Patterns

- Custom regex is compiled and validated at `Config()` construction
- HushLog does **not** check for ReDoS vulnerability in user-supplied regex
- Use tested patterns from trusted sources
- The `hypothesis` fuzz test suite covers built-in patterns but not custom ones

### Unicode

- **NFC normalization** is applied before redaction to handle decomposed character forms (e.g., `ü` as `u` + combining diaeresis)
- NFC does **not** protect against confusable characters (homoglyphs like Cyrillic "а" vs Latin "a")
- NFKC normalization for homoglyph detection is planned for a future release

## Recommendations

For high-security environments, combine HushLog with:

- **Log access restrictions** — limit who can read log files
- **Encryption at rest** — encrypt log storage
- **Audit logging** — track who accessed which logs
- **Data classification** — identify which logs may contain PII before they're written
- **Network controls** — ensure logs don't leave trusted boundaries
