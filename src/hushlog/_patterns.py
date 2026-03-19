"""Built-in PII redaction patterns for HushLog."""

from __future__ import annotations

import ipaddress as _ipaddress
import re

from hushlog._types import PatternEntry

_ASCII_DIGITS = frozenset("0123456789")


def _luhn_check(text: str) -> bool:
    """Validate a credit card number using the Luhn algorithm."""
    digits = [int(c) for c in text if c in _ASCII_DIGITS]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _ipv4_validate(text: str) -> bool:
    """Validate an IPv4 address: each octet must be 0-255 with no leading zeros."""
    parts = text.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part or not all(c in _ASCII_DIGITS for c in part):
            return False
        if len(part) > 1 and part[0] == "0":
            return False  # Reject leading zeros (e.g., 01, 001)
        val = int(part)
        if val > 255:
            return False
    return True


def _cpf_validate(text: str) -> bool:
    """Validate a Brazilian CPF number using check digit algorithm."""
    digits = [int(c) for c in text if c in _ASCII_DIGITS]
    if len(digits) != 11:
        return False
    # Reject all-same-digit CPFs (e.g., 111.111.111-11)
    if len(set(digits)) == 1:
        return False
    # First check digit
    total = sum(d * w for d, w in zip(digits[:9], range(10, 1, -1), strict=False))
    remainder = total % 11
    check1 = 0 if remainder < 2 else 11 - remainder
    if digits[9] != check1:
        return False
    # Second check digit
    total = sum(d * w for d, w in zip(digits[:10], range(11, 1, -1), strict=False))
    remainder = total % 11
    check2 = 0 if remainder < 2 else 11 - remainder
    return digits[10] == check2


def _cnpj_validate(text: str) -> bool:
    """Validate a Brazilian CNPJ number using check digit algorithm."""
    digits = [int(c) for c in text if c in _ASCII_DIGITS]
    if len(digits) != 14:
        return False
    if len(set(digits)) == 1:
        return False
    # First check digit
    weights1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    total = sum(d * w for d, w in zip(digits[:12], weights1, strict=False))
    remainder = total % 11
    check1 = 0 if remainder < 2 else 11 - remainder
    if digits[12] != check1:
        return False
    # Second check digit
    weights2 = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    total = sum(d * w for d, w in zip(digits[:13], weights2, strict=False))
    remainder = total % 11
    check2 = 0 if remainder < 2 else 11 - remainder
    return digits[13] == check2


def _iban_validate(text: str) -> bool:
    """Validate an IBAN using the mod-97 algorithm (ISO 7064)."""
    # Remove spaces
    cleaned = "".join(c for c in text if c != " ")
    if len(cleaned) < 15 or len(cleaned) > 34:
        return False
    # First 2 chars must be uppercase letters
    if not cleaned[:2].isalpha() or not cleaned[:2].isupper():
        return False
    # Next 2 chars must be digits
    if not cleaned[2:4].isdigit():
        return False
    # Move first 4 chars to end, convert letters to numbers (A=10, B=11, ...)
    rearranged = cleaned[4:] + cleaned[:4]
    numeric = ""
    for c in rearranged:
        if c.isdigit():
            numeric += c
        elif c.isalpha():
            numeric += str(ord(c.upper()) - 55)  # A=10, B=11, ..., Z=35
        else:
            return False
    return int(numeric) % 97 == 1


def _ipv6_validate(text: str) -> bool:
    """Validate an IPv6 address using the standard library."""
    try:
        _ipaddress.IPv6Address(text)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Partial masker functions
# ---------------------------------------------------------------------------


def _partial_mask_email(m: re.Match[str], mc: str) -> str:
    text = m.group()
    local, domain = text.rsplit("@", 1)
    if "." in domain:
        domain_name, tld = domain.rsplit(".", 1)
        return f"{local[0]}{mc * 3}@{domain_name[0]}{mc * 3}.{tld}"
    return f"{local[0]}{mc * 3}@{mc * 3}"


def _partial_mask_credit_card(m: re.Match[str], mc: str) -> str:
    digits = [c for c in m.group() if c in _ASCII_DIGITS]
    last4 = "".join(digits[-4:])
    return f"{mc * 4}-{mc * 4}-{mc * 4}-{last4}"


def _partial_mask_ssn(m: re.Match[str], mc: str) -> str:
    text = m.group()
    last4 = text[-4:]
    return f"{mc * 3}-{mc * 2}-{last4}"


def _partial_mask_phone(m: re.Match[str], mc: str) -> str:
    digits = [c for c in m.group() if c in _ASCII_DIGITS]
    last4 = "".join(digits[-4:])
    return f"({mc * 3}) {mc * 3}-{last4}"


def _partial_mask_jwt(m: re.Match[str], mc: str) -> str:
    return f"eyJ{mc * 3}...{mc * 3}"


def _partial_mask_aws_access_key(m: re.Match[str], mc: str) -> str:
    text = m.group()
    return f"{text[:4]}{mc * (len(text) - 8)}{text[-4:]}"


def _partial_mask_aws_secret_key(m: re.Match[str], mc: str) -> str:
    # Match includes label=value. Keep label, mask value.
    text = m.group()
    for sep in ("=", ":"):
        if sep in text:
            idx = text.index(sep)
            label = text[: idx + 1]
            return f"{label} {mc * 40}"
    return f"{mc * len(text)}"


def _partial_mask_stripe_key(m: re.Match[str], mc: str) -> str:
    text = m.group()
    if len(text) > 8:
        return f"{text[:4]}{mc * (len(text) - 8)}{text[-4:]}"
    return mc * len(text)


def _partial_mask_github_token(m: re.Match[str], mc: str) -> str:
    text = m.group()
    if len(text) > 8:
        return f"{text[:4]}{mc * (len(text) - 8)}{text[-4:]}"
    return mc * len(text)


def _partial_mask_gcp_key(m: re.Match[str], mc: str) -> str:
    text = m.group()
    if len(text) > 8:
        return f"{text[:4]}{mc * (len(text) - 8)}{text[-4:]}"
    return mc * len(text)


def _partial_mask_ipv4(m: re.Match[str], mc: str) -> str:
    parts = m.group().split(".")
    return f"{parts[0]}.{mc * 3}.{mc * 3}.{mc * 3}"


def _partial_mask_ipv6(m: re.Match[str], mc: str) -> str:
    text = m.group()
    first_group = text.split(":")[0] if ":" in text else text
    return f"{first_group}:{mc * 4}:{mc * 4}:{mc * 4}"


def _partial_mask_cpf(m: re.Match[str], mc: str) -> str:
    text = m.group()
    last2 = text[-2:]
    return f"{mc * 3}.{mc * 3}.{mc * 3}-{last2}"


def _partial_mask_cnpj(m: re.Match[str], mc: str) -> str:
    text = m.group()
    # Show branch (4 digits after /) and check digits (last 2)
    digits = [c for c in text if c in _ASCII_DIGITS]
    branch = "".join(digits[8:12])
    check = "".join(digits[12:14])
    return f"{mc * 2}.{mc * 3}.{mc * 3}/{branch}-{check}"


def _partial_mask_br_phone(m: re.Match[str], mc: str) -> str:
    digits = [c for c in m.group() if c in _ASCII_DIGITS]
    last4 = "".join(digits[-4:])
    return f"({mc * 2}) {mc * 5}-{last4}"


def _partial_mask_iban(m: re.Match[str], mc: str) -> str:
    cleaned = "".join(c for c in m.group() if c != " ")
    country = cleaned[:2]
    last4 = cleaned[-4:]
    middle_len = len(cleaned) - 6
    return f"{country}{mc * 2} {mc * middle_len} {last4}"


def _partial_mask_eu_vat(m: re.Match[str], mc: str) -> str:
    text = m.group()
    prefix = text[:2]
    last3 = text[-3:]
    middle_len = len(text) - 5
    return f"{prefix}{mc * middle_len}{last3}"


def _partial_mask_generic_secret(m: re.Match[str], mc: str) -> str:
    text = m.group()
    for sep in ("=", ":"):
        if sep in text:
            idx = text.index(sep)
            label = text[: idx + 1]
            return f"{label} {mc * 8}"
    return mc * len(text)


# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------


# --- Credit Card ---
# Matches 13-19 digit sequences with optional separators (space, dash)
# Prefix-aware: Visa (4), MasterCard (5[1-5], 2[2-7]), Amex (3[47]), Discover (6011, 65, 644-649)
# Uses [0-9] instead of \d to prevent Unicode digit bypass.
# Luhn validator handles final length and checksum verification.
_CREDIT_CARD_RE = re.compile(
    r"\b"
    r"(?:"
    r"4[0-9]{3}|"  # Visa
    r"5[1-5][0-9]{2}|"  # MasterCard (classic)
    r"2[2-7][0-9]{2}|"  # MasterCard (2-series)
    r"3[47][0-9]{2}|"  # Amex
    r"6(?:011|5[0-9]{2}|4[4-9][0-9])"  # Discover
    r")"
    r"(?:[\s-]?[0-9]{1,6}){2,5}"  # Remaining digit groups with optional separators
    r"\b"
)

_CREDIT_CARD = PatternEntry(
    name="credit_card",
    regex=_CREDIT_CARD_RE,
    heuristic=None,
    mask="[CREDIT_CARD REDACTED]",
    validator=_luhn_check,
    partial_masker=_partial_mask_credit_card,
)


# --- SSN ---
# Matches XXX-XX-XXXX format only (dashed). Excludes invalid ranges.
# Uses [0-9] instead of \d to prevent Unicode digit bypass.
_SSN_RE = re.compile(r"\b(?!000|666|9[0-9]{2})[0-9]{3}-(?!00)[0-9]{2}-(?!0000)[0-9]{4}\b")

_SSN = PatternEntry(
    name="ssn",
    regex=_SSN_RE,
    heuristic=lambda text: "-" in text,
    mask="[SSN REDACTED]",
    partial_masker=_partial_mask_ssn,
)


# --- Email ---
# RFC 5322 practical subset. Requires TLD with dot to avoid user@localhost false positives.
_EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")

_EMAIL = PatternEntry(
    name="email",
    regex=_EMAIL_RE,
    heuristic=lambda text: "@" in text,
    mask="[EMAIL REDACTED]",
    partial_masker=_partial_mask_email,
)


# --- US Phone ---
# Matches 10-digit US phone numbers with optional +1/1 country code.
# Formats: (555) 123-4567, 555-123-4567, 555.123.4567, 555 123 4567, +1-555-123-4567
# Area code and exchange must not start with 0 or 1 (NANP rules).
# Uses [0-9] instead of \d to prevent Unicode digit bypass.
_PHONE_RE = re.compile(
    r"(?<![0-9])"  # Not preceded by a digit
    r"(?:\+?1[\s.-]?)?"  # Optional country code +1 or 1
    r"(?:\([2-9][0-9]{2}\)|(?<!\()[2-9][0-9]{2})[\s.-]?"  # Area code: both parens or neither
    r"[2-9][0-9]{2}[\s.-]?"  # Exchange (2-9 start)
    r"[0-9]{4}"  # Subscriber
    r"(?![0-9])"  # Not followed by a digit
)

_PHONE = PatternEntry(
    name="phone",
    regex=_PHONE_RE,
    heuristic=None,
    mask="[PHONE REDACTED]",
    partial_masker=_partial_mask_phone,
)


# --- JWT ---
# Matches JSON Web Tokens (3 or 5 dot-separated base64url segments).
# Both header and payload start with eyJ (base64 of '{"').
_JWT_RE = re.compile(
    r"eyJ[A-Za-z0-9_-]+\."
    r"eyJ[A-Za-z0-9_-]+\."
    r"[A-Za-z0-9_-]+"
    r"(?:\.[A-Za-z0-9_-]+){0,2}"  # JWE has 5 segments
)

_JWT = PatternEntry(
    name="jwt",
    regex=_JWT_RE,
    heuristic=lambda text: "eyJ" in text,
    mask="[JWT REDACTED]",
    partial_masker=_partial_mask_jwt,
)


# --- AWS Access Key ---
# Matches AKIA (long-lived) and ASIA (temporary/STS) access key IDs.
_AWS_ACCESS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")

_AWS_ACCESS_KEY = PatternEntry(
    name="aws_access_key",
    regex=_AWS_ACCESS_KEY_RE,
    heuristic=lambda text: "AKIA" in text or "ASIA" in text,
    mask="[AWS_ACCESS_KEY REDACTED]",
    partial_masker=_partial_mask_aws_access_key,
)


# --- AWS Secret Key ---
# Context-dependent: requires a label prefix to avoid false positives on random base64.
_AWS_SECRET_KEY_RE = re.compile(
    r"(?i)"
    r"(?<![a-zA-Z_])(?:aws_secret_access_key|aws_secret_key|secret_access_key)"
    r"\s*[=:\s]\s*"
    r"[A-Za-z0-9/+=]{40}"
    r"(?![A-Za-z0-9/+=])"
)

_AWS_SECRET_KEY = PatternEntry(
    name="aws_secret_key",
    regex=_AWS_SECRET_KEY_RE,
    heuristic=lambda text: "secret" in text.lower(),
    mask="[AWS_SECRET_KEY REDACTED]",
    partial_masker=_partial_mask_aws_secret_key,
)


# --- Stripe Key ---
# Matches sk_live_, pk_live_, rk_live_, sk_test_, pk_test_, rk_test_ prefixed keys.
_STRIPE_KEY_RE = re.compile(r"\b[spr]k_(?:live|test)_[A-Za-z0-9]{24,}\b")

_STRIPE_KEY = PatternEntry(
    name="stripe_key",
    regex=_STRIPE_KEY_RE,
    heuristic=lambda text: "_live_" in text or "_test_" in text,
    mask="[STRIPE_KEY REDACTED]",
    partial_masker=_partial_mask_stripe_key,
)


# --- GitHub Token ---
# Matches classic tokens (ghp_, gho_, ghs_, ghu_, ghr_) and fine-grained (github_pat_).
_GITHUB_TOKEN_RE = re.compile(
    r"\bgh[pousr]_[A-Za-z0-9]{36}\b"
    r"|"
    r"\bgithub_pat_[A-Za-z0-9_]{80,}\b"
)

_GITHUB_TOKEN = PatternEntry(
    name="github_token",
    regex=_GITHUB_TOKEN_RE,
    heuristic=lambda text: (
        "ghp_" in text
        or "gho_" in text
        or "ghs_" in text
        or "ghu_" in text
        or "ghr_" in text
        or "github_pat_" in text
    ),
    mask="[GITHUB_TOKEN REDACTED]",
    partial_masker=_partial_mask_github_token,
)


# --- GCP API Key ---
# Matches Google Cloud API keys starting with AIza.
_GCP_KEY_RE = re.compile(r"\bAIza[A-Za-z0-9_-]{35}\b")

_GCP_KEY = PatternEntry(
    name="gcp_key",
    regex=_GCP_KEY_RE,
    heuristic=lambda text: "AIza" in text,
    mask="[GCP_KEY REDACTED]",
    partial_masker=_partial_mask_gcp_key,
)


# --- IPv4 ---
# Matches IPv4 addresses (0-255 per octet). Validator rejects invalid octets
# and leading zeros. Lookbehind rejects version-like contexts (v1.2.3.4, pkg@1.2.3.4).
_IPV4_RE = re.compile(
    r"(?<![0-9a-zA-Z.@])"  # Not preceded by alphanumeric, dot, or @
    r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"
    r"(?![0-9.])"  # Not followed by digit or dot
)

_IPV4 = PatternEntry(
    name="ipv4",
    regex=_IPV4_RE,
    heuristic=None,
    mask="[IPV4 REDACTED]",
    validator=_ipv4_validate,
    partial_masker=_partial_mask_ipv4,
)


# --- IPv6 ---
# Matches IPv6 addresses (full, compressed, and mixed IPv4-mapped forms).
# The regex is a loose pre-filter; the validator uses ipaddress.IPv6Address for correctness.
_IPV6_RE = re.compile(
    r"(?<![0-9a-zA-Z:.])"
    r"(?:"
    # Full form: 8 groups of 1-4 hex digits
    r"[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){7}"
    r"|"
    # Compressed forms with ::
    r"(?:[0-9a-fA-F]{1,4}:){1,7}:"
    r"|"
    r"(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"
    r"|"
    r"(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}"
    r"|"
    r"(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}"
    r"|"
    r"(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}"
    r"|"
    r"(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}"
    r"|"
    r"[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}"
    r"|"
    # :: with suffix
    r":(?::[0-9a-fA-F]{1,4}){1,7}"
    r"|"
    # IPv4-mapped: ::ffff:192.168.1.1
    r"::(?:ffff:)?[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"
    r"|"
    # Just ::
    r"::"
    r")"
    r"(?![0-9a-zA-Z:.])"
)

_IPV6 = PatternEntry(
    name="ipv6",
    regex=_IPV6_RE,
    heuristic=lambda text: ":" in text,
    mask="[IPV6 REDACTED]",
    validator=_ipv6_validate,
    partial_masker=_partial_mask_ipv6,
)


# --- CPF (Brazilian Individual Taxpayer ID) ---
# Matches XXX.XXX.XXX-XX format only (formatted with dots and dash).
# Uses check digit validation (mod-11 algorithm).
_CPF_RE = re.compile(
    r"(?<![0-9])"
    r"[0-9]{3}\.[0-9]{3}\.[0-9]{3}-[0-9]{2}"
    r"(?![0-9])"
)

_CPF = PatternEntry(
    name="cpf",
    regex=_CPF_RE,
    heuristic=lambda text: "." in text and "-" in text,
    mask="[CPF REDACTED]",
    validator=_cpf_validate,
    partial_masker=_partial_mask_cpf,
)


# --- CNPJ (Brazilian Company Taxpayer ID) ---
# Matches XX.XXX.XXX/XXXX-XX format only (formatted with dots, slash, dash).
# Uses check digit validation (mod-11 algorithm).
_CNPJ_RE = re.compile(
    r"(?<![0-9])"
    r"[0-9]{2}\.[0-9]{3}\.[0-9]{3}/[0-9]{4}-[0-9]{2}"
    r"(?![0-9])"
)

_CNPJ = PatternEntry(
    name="cnpj",
    regex=_CNPJ_RE,
    heuristic=lambda text: "/" in text,
    mask="[CNPJ REDACTED]",
    validator=_cnpj_validate,
    partial_masker=_partial_mask_cnpj,
)


# --- Brazilian Phone ---
# Matches formatted Brazilian phone numbers with area code in parentheses.
# Mobile: (XX) 9XXXX-XXXX, Landline: (XX) XXXX-XXXX
# Optional +55 country code prefix.
_BR_PHONE_RE = re.compile(
    r"(?<![0-9])"
    r"(?:\+55[\s.-]?)?"  # Optional country code
    r"\([1-9][0-9]\)[\s.-]?"  # Area code (11-99)
    r"(?:9[0-9]{4}|[2-9][0-9]{3})"  # Mobile (9XXXX) or landline (2-9XXX)
    r"[\s.-]?"
    r"[0-9]{4}"  # Last 4 digits
    r"(?![0-9])"
)

_BR_PHONE = PatternEntry(
    name="br_phone",
    regex=_BR_PHONE_RE,
    heuristic=lambda text: "(" in text,
    mask="[BR_PHONE REDACTED]",
    partial_masker=_partial_mask_br_phone,
)


# --- IBAN (International Bank Account Number) ---
# Matches 2 uppercase letters (country code) + 2 digits (check) + up to 30 alphanumeric chars.
# Handles both spaced (GB29 NWBK 6016 1331 9268 19) and unspaced formats.
# Validated via mod-97 algorithm (ISO 7064 / ISO 13616).
_IBAN_RE = re.compile(
    r"\b[A-Z]{2}[0-9]{2}[\s]?[A-Z0-9]{4}(?:[\s]?[A-Z0-9]{4}){2,7}(?:[\s]?[A-Z0-9]{1,4})?\b"
)

_IBAN = PatternEntry(
    name="iban",
    regex=_IBAN_RE,
    heuristic=None,
    mask="[IBAN REDACTED]",
    validator=_iban_validate,
    partial_masker=_partial_mask_iban,
)


# --- EU VAT Number ---
# Matches 2-letter country prefix + 8-12 alphanumeric characters.
# Covers EU member states + GB and XI (Northern Ireland).
_EU_VAT_RE = re.compile(
    r"\b(?:AT|BE|BG|CY|CZ|DE|DK|EE|EL|ES|FI|FR|HR|HU|IE|IT|LT|LU|LV|MT|NL|PL|PT|RO|SE|SI|SK|XI|GB)"
    r"[A-Z0-9]{8,12}\b"
)

_EU_VAT = PatternEntry(
    name="eu_vat",
    regex=_EU_VAT_RE,
    heuristic=None,
    mask="[EU_VAT REDACTED]",
    partial_masker=_partial_mask_eu_vat,
)


# --- Generic Secret ---
# Context-dependent: matches values after common secret-related labels.
# Replaces the entire match (label + value) to avoid leaking context.
_GENERIC_SECRET_RE = re.compile(
    r"(?i)"
    r"(?:password|passwd|pwd|secret|api_key|apikey|api[-_]secret|"
    r"auth_token|access_token|client_secret|private_key)"
    r"\s*[=:]\s*"
    r"[\"']?"
    r"[^\s\"']{8,128}"
    r"[\"']?"
)

_GENERIC_SECRET_HEURISTIC_KEYS = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "api_key",
    "apikey",
    "token",
    "private_key",
)


def _generic_secret_heuristic(text: str) -> bool:
    lowered = text.lower()
    return any(k in lowered for k in _GENERIC_SECRET_HEURISTIC_KEYS)


_GENERIC_SECRET = PatternEntry(
    name="generic_secret",
    regex=_GENERIC_SECRET_RE,
    heuristic=_generic_secret_heuristic,
    mask="[SECRET REDACTED]",
    partial_masker=_partial_mask_generic_secret,
)


def get_builtin_patterns() -> tuple[PatternEntry, ...]:
    """Return all built-in PII patterns in recommended application order.

    Order rationale:
    - Specific patterns with fixed prefixes (credit_card, ssn, API keys) first
    - IPv6 before IPv4 to catch ::ffff:x.x.x.x mapped addresses first
    - CPF/CNPJ/BR phone after IPv4 — formatted with check digits, specific enough
    - IBAN/EU VAT after BR patterns — validated with mod-97 / prefix matching
    - Context-dependent patterns (generic_secret) before general patterns (email)
      because email redaction inserts spaces that break generic_secret's ``\\S{8,128}``
    - Broadest patterns (email, phone) last to avoid consuming text needed by
      more specific patterns
    """
    return (
        _CREDIT_CARD,
        _SSN,
        _JWT,
        _AWS_ACCESS_KEY,
        _AWS_SECRET_KEY,
        _STRIPE_KEY,
        _GITHUB_TOKEN,
        _GCP_KEY,
        _IPV6,
        _IPV4,
        _CPF,
        _CNPJ,
        _BR_PHONE,
        _IBAN,
        _EU_VAT,
        _GENERIC_SECRET,
        _EMAIL,
        _PHONE,
    )
