"""Built-in PII redaction patterns for HushLog."""

from __future__ import annotations

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


# --- Credit Card ---
# Matches 13-19 digit sequences with optional separators (space, dash)
# Prefix-aware: Visa (4), MasterCard (5[1-5], 2[2-7]), Amex (3[47]), Discover (6011, 65, 644-649)
# Uses [0-9] instead of \d to prevent Unicode digit bypass.
_CREDIT_CARD_RE = re.compile(
    r"\b"
    r"(?:"
    r"4[0-9]{3}|"  # Visa
    r"5[1-5][0-9]{2}|"  # MasterCard (classic)
    r"2[2-7][0-9]{2}|"  # MasterCard (2-series)
    r"3[47][0-9]{2}|"  # Amex
    r"6(?:011|5[0-9]{2}|4[4-9][0-9])"  # Discover
    r")"
    r"[\s-]?[0-9]{3,4}"
    r"[\s-]?[0-9]{3,4}"
    r"[\s-]?[0-9]{3,5}"
    r"\b"
)

_CREDIT_CARD = PatternEntry(
    name="credit_card",
    regex=_CREDIT_CARD_RE,
    heuristic=None,
    mask="[CREDIT_CARD REDACTED]",
    validator=_luhn_check,
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
)


# --- Email ---
# RFC 5322 practical subset. Requires TLD with dot to avoid user@localhost false positives.
_EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")

_EMAIL = PatternEntry(
    name="email",
    regex=_EMAIL_RE,
    heuristic=lambda text: "@" in text,
    mask="[EMAIL REDACTED]",
)


# --- US Phone ---
# Matches 10-digit US phone numbers with optional +1/1 country code.
# Formats: (555) 123-4567, 555-123-4567, 555.123.4567, 555 123 4567, +1-555-123-4567
# Area code and exchange must not start with 0 or 1 (NANP rules).
# Uses [0-9] instead of \d to prevent Unicode digit bypass.
_PHONE_RE = re.compile(
    r"(?<![0-9])"  # Not preceded by a digit
    r"(?:\+?1[\s.-]?)?"  # Optional country code +1 or 1
    r"\(?[2-9][0-9]{2}\)?[\s.-]?"  # Area code (2-9 start) with optional parens
    r"[2-9][0-9]{2}[\s.-]?"  # Exchange (2-9 start)
    r"[0-9]{4}"  # Subscriber
    r"(?![0-9])"  # Not followed by a digit
)

_PHONE = PatternEntry(
    name="phone",
    regex=_PHONE_RE,
    heuristic=None,
    mask="[PHONE REDACTED]",
)


def get_builtin_patterns() -> tuple[PatternEntry, ...]:
    """Return all built-in PII patterns in recommended application order.

    Order: credit_card, ssn, email, phone (most specific first, greediest last).
    """
    return (_CREDIT_CARD, _SSN, _EMAIL, _PHONE)
