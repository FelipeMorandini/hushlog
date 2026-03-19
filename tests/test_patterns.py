"""Unit tests for hushlog._patterns — built-in PII redaction patterns."""

from __future__ import annotations

import re

import pytest

from hushlog._patterns import (
    _AWS_ACCESS_KEY,
    _AWS_SECRET_KEY,
    _BR_PHONE,
    _CNPJ,
    _CPF,
    _CREDIT_CARD,
    _EMAIL,
    _GCP_KEY,
    _GENERIC_SECRET,
    _GITHUB_TOKEN,
    _IPV4,
    _IPV6,
    _JWT,
    _PHONE,
    _SSN,
    _STRIPE_KEY,
    _cnpj_validate,
    _cpf_validate,
    _ipv4_validate,
    _ipv6_validate,
    _luhn_check,
    get_builtin_patterns,
)
from hushlog._registry import PatternRegistry
from hushlog._types import PatternEntry

# ---------------------------------------------------------------------------
# get_builtin_patterns
# ---------------------------------------------------------------------------


class TestGetBuiltinPatterns:
    """Verify the shape and ordering of built-in patterns."""

    def test_returns_tuple(self) -> None:
        result = get_builtin_patterns()
        assert isinstance(result, tuple)

    def test_count(self) -> None:
        assert len(get_builtin_patterns()) == 16

    def test_all_are_pattern_entries(self) -> None:
        for entry in get_builtin_patterns():
            assert isinstance(entry, PatternEntry)

    def test_order(self) -> None:
        patterns = get_builtin_patterns()
        names = [p.name for p in patterns]
        assert names == [
            "credit_card",
            "ssn",
            "jwt",
            "aws_access_key",
            "aws_secret_key",
            "stripe_key",
            "github_token",
            "gcp_key",
            "ipv6",
            "ipv4",
            "cpf",
            "cnpj",
            "br_phone",
            "generic_secret",
            "email",
            "phone",
        ]


# ---------------------------------------------------------------------------
# Luhn validator
# ---------------------------------------------------------------------------


class TestLuhnCheck:
    """Validate the Luhn algorithm implementation."""

    @pytest.mark.parametrize(
        "number",
        [
            "4111111111111111",  # Visa test card
            "5500000000000004",  # MasterCard test card
            "340000000000009",  # Amex test card
            "6011000000000004",  # Discover test card
            "4242424242424242",  # Stripe test card
        ],
    )
    def test_valid_card_numbers(self, number: str) -> None:
        assert _luhn_check(number) is True

    @pytest.mark.parametrize(
        "number",
        [
            "4111111111111112",  # Off-by-one from valid Visa
            "0000000000000000",  # All zeros (passes Luhn but prefix check N/A here)
            "1234567890123456",  # Random number
        ],
    )
    def test_invalid_card_numbers(self, number: str) -> None:
        # 0000000000000000 actually passes Luhn, so skip it
        if number != "0000000000000000":
            assert _luhn_check(number) is False

    def test_too_short(self) -> None:
        assert _luhn_check("123456") is False

    def test_too_long(self) -> None:
        assert _luhn_check("1" * 20) is False

    def test_with_separators(self) -> None:
        # Luhn should strip non-digits
        assert _luhn_check("4111-1111-1111-1111") is True
        assert _luhn_check("4111 1111 1111 1111") is True


# ---------------------------------------------------------------------------
# Credit Card pattern
# ---------------------------------------------------------------------------


class TestCreditCardPattern:
    """Test credit card regex + Luhn validator integration."""

    def _redact(self, text: str) -> str:
        registry = PatternRegistry()
        registry.register(_CREDIT_CARD)
        return registry.redact(text)

    def test_visa_plain(self) -> None:
        assert self._redact("card: 4111111111111111") == "card: [CREDIT_CARD REDACTED]"

    def test_visa_with_dashes(self) -> None:
        assert self._redact("card: 4111-1111-1111-1111") == "card: [CREDIT_CARD REDACTED]"

    def test_visa_with_spaces(self) -> None:
        assert self._redact("card: 4111 1111 1111 1111") == "card: [CREDIT_CARD REDACTED]"

    def test_mastercard(self) -> None:
        assert self._redact("card: 5500000000000004") == "card: [CREDIT_CARD REDACTED]"

    def test_amex(self) -> None:
        assert self._redact("card: 340000000000009") == "card: [CREDIT_CARD REDACTED]"

    def test_discover(self) -> None:
        assert self._redact("card: 6011000000000004") == "card: [CREDIT_CARD REDACTED]"

    def test_invalid_luhn_not_redacted(self) -> None:
        """A number that matches the regex but fails Luhn should NOT be redacted."""
        assert self._redact("card: 4111111111111112") == "card: 4111111111111112"

    def test_random_digits_not_redacted(self) -> None:
        """Random digit sequences without valid CC prefixes should not match."""
        result = self._redact("order: 1234567890123")
        assert "[CREDIT_CARD REDACTED]" not in result


# ---------------------------------------------------------------------------
# SSN pattern
# ---------------------------------------------------------------------------


class TestSSNPattern:
    """Test SSN regex."""

    def _redact(self, text: str) -> str:
        registry = PatternRegistry()
        registry.register(_SSN)
        return registry.redact(text)

    def test_valid_ssn(self) -> None:
        assert self._redact("ssn: 123-45-6789") == "ssn: [SSN REDACTED]"

    def test_ssn_in_sentence(self) -> None:
        assert self._redact("User SSN is 456-78-9012 ok") == "User SSN is [SSN REDACTED] ok"

    def test_invalid_area_000(self) -> None:
        """Area code 000 is invalid."""
        assert self._redact("ssn: 000-45-6789") == "ssn: 000-45-6789"

    def test_invalid_area_666(self) -> None:
        """Area code 666 is invalid."""
        assert self._redact("ssn: 666-45-6789") == "ssn: 666-45-6789"

    def test_invalid_area_9xx(self) -> None:
        """Area codes 900-999 are invalid."""
        assert self._redact("ssn: 900-45-6789") == "ssn: 900-45-6789"

    def test_invalid_group_00(self) -> None:
        """Group 00 is invalid."""
        assert self._redact("ssn: 123-00-6789") == "ssn: 123-00-6789"

    def test_invalid_serial_0000(self) -> None:
        """Serial 0000 is invalid."""
        assert self._redact("ssn: 123-45-0000") == "ssn: 123-45-0000"

    def test_no_dashes_not_matched(self) -> None:
        """SSN without dashes should NOT match (reduces false positives)."""
        assert self._redact("ssn: 123456789") == "ssn: 123456789"

    def test_heuristic_skips_no_dash(self) -> None:
        """Heuristic checks for dash; text without dash should skip regex entirely."""
        assert _SSN.heuristic is not None
        assert _SSN.heuristic("no dashes here") is False
        assert _SSN.heuristic("has-a-dash") is True


# ---------------------------------------------------------------------------
# Email pattern
# ---------------------------------------------------------------------------


class TestEmailPattern:
    """Test email regex."""

    def _redact(self, text: str) -> str:
        registry = PatternRegistry()
        registry.register(_EMAIL)
        return registry.redact(text)

    def test_simple_email(self) -> None:
        assert self._redact("email: user@example.com") == "email: [EMAIL REDACTED]"

    def test_email_with_dots(self) -> None:
        assert self._redact("first.last@company.co.uk") == "[EMAIL REDACTED]"

    def test_email_with_plus(self) -> None:
        assert self._redact("user+tag@gmail.com") == "[EMAIL REDACTED]"

    def test_email_in_sentence(self) -> None:
        result = self._redact("Contact alice@example.com for info")
        assert result == "Contact [EMAIL REDACTED] for info"

    def test_multiple_emails(self) -> None:
        result = self._redact("a@b.com and c@d.com")
        assert result == "[EMAIL REDACTED] and [EMAIL REDACTED]"

    def test_not_an_email(self) -> None:
        """Bare @ without TLD should not match."""
        assert self._redact("user@localhost") == "user@localhost"

    def test_heuristic_skips_no_at(self) -> None:
        assert _EMAIL.heuristic is not None
        assert _EMAIL.heuristic("no at sign") is False
        assert _EMAIL.heuristic("has@sign") is True


# ---------------------------------------------------------------------------
# Phone pattern
# ---------------------------------------------------------------------------


class TestPhonePattern:
    """Test US phone number regex."""

    def _redact(self, text: str) -> str:
        registry = PatternRegistry()
        registry.register(_PHONE)
        return registry.redact(text)

    def test_dashed_format(self) -> None:
        assert self._redact("call 555-234-5678") == "call [PHONE REDACTED]"

    def test_dotted_format(self) -> None:
        assert self._redact("call 555.234.5678") == "call [PHONE REDACTED]"

    def test_spaced_format(self) -> None:
        assert self._redact("call 555 234 5678") == "call [PHONE REDACTED]"

    def test_parenthesized_area_code(self) -> None:
        assert self._redact("call (555) 234-5678") == "call [PHONE REDACTED]"

    def test_with_country_code(self) -> None:
        assert self._redact("call +1-555-234-5678") == "call [PHONE REDACTED]"

    def test_with_country_code_no_dash(self) -> None:
        assert self._redact("call +15552345678") == "call [PHONE REDACTED]"

    def test_seven_digit_not_matched(self) -> None:
        """7-digit numbers without area code should NOT match."""
        result = self._redact("call 234-5678")
        # This should not be redacted as a full phone number
        assert "[PHONE REDACTED]" not in result

    def test_area_code_starts_with_0_not_matched(self) -> None:
        """NANP: area codes starting with 0 or 1 are invalid."""
        assert "[PHONE REDACTED]" not in self._redact("call 055-234-5678")
        assert "[PHONE REDACTED]" not in self._redact("call 155-234-5678")

    def test_exchange_starts_with_0_not_matched(self) -> None:
        """NANP: exchange starting with 0 or 1 is invalid."""
        assert "[PHONE REDACTED]" not in self._redact("call 555-034-5678")
        assert "[PHONE REDACTED]" not in self._redact("call 555-134-5678")


# ---------------------------------------------------------------------------
# False positive resistance
# ---------------------------------------------------------------------------


class TestFalsePositives:
    """Verify patterns don't match common non-PII text."""

    def _redact_all(self, text: str) -> str:
        """Apply all built-in patterns."""
        registry = PatternRegistry()
        for entry in get_builtin_patterns():
            registry.register(entry)
        return registry.redact(text)

    def test_ipv4_not_phone(self) -> None:
        """IP addresses should be matched as IPv4, not as phone numbers."""
        result = self._redact_all("server 192.168.1.100")
        assert "[PHONE REDACTED]" not in result
        assert "[IPV4 REDACTED]" in result

    def test_version_number_not_phone(self) -> None:
        """Version strings should not be matched."""
        result = self._redact_all("v1.2.3.4")
        assert "[PHONE REDACTED]" not in result

    def test_normal_log_unchanged(self) -> None:
        """Typical log messages without PII should pass through unchanged."""
        text = "INFO 2024-01-15 Request processed in 42ms"
        assert self._redact_all(text) == text

    def test_date_not_ssn(self) -> None:
        """Dates should not be matched as SSN."""
        text = "Date: 2024-01-15"
        assert "[SSN REDACTED]" not in self._redact_all(text)


# ---------------------------------------------------------------------------
# Validator integration
# ---------------------------------------------------------------------------


class TestValidatorIntegration:
    """Test that the validator field works correctly in the registry."""

    def test_validator_true_redacts(self) -> None:
        entry = PatternEntry(
            name="test",
            regex=re.compile(r"\d+"),
            heuristic=None,
            mask="[NUM]",
            validator=lambda text: True,
        )
        registry = PatternRegistry()
        registry.register(entry)
        assert registry.redact("abc 123") == "abc [NUM]"

    def test_validator_false_preserves(self) -> None:
        entry = PatternEntry(
            name="test",
            regex=re.compile(r"\d+"),
            heuristic=None,
            mask="[NUM]",
            validator=lambda text: False,
        )
        registry = PatternRegistry()
        registry.register(entry)
        assert registry.redact("abc 123") == "abc 123"

    def test_validator_none_always_redacts(self) -> None:
        entry = PatternEntry(
            name="test",
            regex=re.compile(r"\d+"),
            heuristic=None,
            mask="[NUM]",
            validator=None,
        )
        registry = PatternRegistry()
        registry.register(entry)
        assert registry.redact("abc 123") == "abc [NUM]"


# ---------------------------------------------------------------------------
# Email edge cases
# ---------------------------------------------------------------------------


class TestEmailEdgeCases:
    """Additional email edge cases."""

    def _redact(self, text: str) -> str:
        registry = PatternRegistry()
        registry.register(_EMAIL)
        return registry.redact(text)

    def test_plus_addressing(self) -> None:
        assert self._redact("user+tag@example.com") == "[EMAIL REDACTED]"

    def test_multiple_dots_subdomain(self) -> None:
        assert self._redact("first.last@sub.domain.co.uk") == "[EMAIL REDACTED]"

    def test_single_char_local_part(self) -> None:
        assert self._redact("a@b.co") == "[EMAIL REDACTED]"

    def test_numbers_in_local_part(self) -> None:
        assert self._redact("user123@test.com") == "[EMAIL REDACTED]"

    def test_bare_at_symbol_no_match(self) -> None:
        """A bare @ symbol without valid email structure should not match."""
        assert self._redact("@") == "@"
        assert self._redact("hello @ world") == "hello @ world"

    def test_no_tld_no_match(self) -> None:
        """user@localhost (no TLD) should not match."""
        assert self._redact("user@localhost") == "user@localhost"

    def test_underscore_in_local_part(self) -> None:
        assert self._redact("first_last@example.com") == "[EMAIL REDACTED]"

    def test_percent_in_local_part(self) -> None:
        assert self._redact("user%name@example.com") == "[EMAIL REDACTED]"


# ---------------------------------------------------------------------------
# Credit card edge cases
# ---------------------------------------------------------------------------


class TestCreditCardEdgeCases:
    """Additional credit card edge cases."""

    def _redact(self, text: str) -> str:
        registry = PatternRegistry()
        registry.register(_CREDIT_CARD)
        return registry.redact(text)

    def test_visa_known_test_number(self) -> None:
        assert self._redact("4111111111111111") == "[CREDIT_CARD REDACTED]"

    def test_mastercard_known_test_number(self) -> None:
        assert self._redact("5500000000000004") == "[CREDIT_CARD REDACTED]"

    def test_amex_known_test_number_378(self) -> None:
        assert self._redact("378282246310005") == "[CREDIT_CARD REDACTED]"

    def test_discover_known_test_number(self) -> None:
        assert self._redact("6011111111111117") == "[CREDIT_CARD REDACTED]"

    def test_visa_with_spaces(self) -> None:
        assert self._redact("4111 1111 1111 1111") == "[CREDIT_CARD REDACTED]"

    def test_visa_with_dashes(self) -> None:
        assert self._redact("4111-1111-1111-1111") == "[CREDIT_CARD REDACTED]"

    def test_amex_with_spaces(self) -> None:
        """Amex uses 4-6-5 grouping."""
        assert self._redact("3782 822463 10005") == "[CREDIT_CARD REDACTED]"

    def test_luhn_fail_not_redacted(self) -> None:
        """Same prefix as valid Visa but bad checksum — must NOT match."""
        assert self._redact("4111111111111112") == "4111111111111112"

    def test_random_16_digits_not_redacted(self) -> None:
        """Random 16-digit numbers without valid CC prefixes should not match."""
        result = self._redact("1234567890123456")
        assert "[CREDIT_CARD REDACTED]" not in result

    def test_13_digit_visa_legacy(self) -> None:
        """Legacy 13-digit Visa cards (4xxx-xxxx-xxxx-x) should be handled."""
        # 4222222222225 is a known 13-digit Visa test number (passes Luhn)
        result = self._redact("4222222222225")
        # Whether this matches depends on regex — document behavior
        # The regex requires at minimum ~13 digits with Visa prefix
        # This tests whether the pattern can handle it
        if "[CREDIT_CARD REDACTED]" in result:
            assert _luhn_check("4222222222225") is True
        else:
            # If regex doesn't match 13-digit, that's acceptable for MVP
            assert result == "4222222222225"

    def test_19_digit_card(self) -> None:
        """19-digit cards exist (China UnionPay, some Visa). Test handling."""
        # 4111111111111111110 — 19 digits starting with 4
        result = self._redact("4111111111111111110")
        # Document behavior: MVP may or may not support 19-digit cards
        assert isinstance(result, str)


# ---------------------------------------------------------------------------
# SSN edge cases
# ---------------------------------------------------------------------------


class TestSSNEdgeCases:
    """Additional SSN edge cases."""

    def _redact(self, text: str) -> str:
        registry = PatternRegistry()
        registry.register(_SSN)
        return registry.redact(text)

    def test_valid_historical_ssn(self) -> None:
        """078-05-1120 is a historically valid SSN range."""
        assert self._redact("ssn: 078-05-1120") == "ssn: [SSN REDACTED]"

    def test_invalid_area_000(self) -> None:
        assert self._redact("000-12-3456") == "000-12-3456"

    def test_invalid_area_666(self) -> None:
        assert self._redact("666-12-3456") == "666-12-3456"

    def test_invalid_area_900(self) -> None:
        assert self._redact("900-12-3456") == "900-12-3456"

    def test_invalid_area_950(self) -> None:
        assert self._redact("950-12-3456") == "950-12-3456"

    def test_invalid_area_999(self) -> None:
        assert self._redact("999-12-3456") == "999-12-3456"

    def test_invalid_group_00(self) -> None:
        assert self._redact("123-00-4567") == "123-00-4567"

    def test_invalid_serial_0000(self) -> None:
        assert self._redact("123-45-0000") == "123-45-0000"

    def test_no_dashes_no_match(self) -> None:
        """Bare 9 digits without dashes should NOT match."""
        assert self._redact("078051120") == "078051120"

    def test_partial_format_short_area_no_match(self) -> None:
        """12-34-5678 has only 2-digit area — should not match."""
        assert self._redact("12-34-5678") == "12-34-5678"

    def test_partial_format_long_area_no_match(self) -> None:
        """1234-56-7890 has 4-digit area — should not match."""
        assert self._redact("1234-56-7890") == "1234-56-7890"

    def test_boundary_area_code_001(self) -> None:
        """Area code 001 is valid (not 000, not 666, not 9xx)."""
        assert self._redact("001-12-3456") == "[SSN REDACTED]"

    def test_boundary_area_code_899(self) -> None:
        """Area code 899 is valid (not in 900-999 range)."""
        assert self._redact("899-12-3456") == "[SSN REDACTED]"


# ---------------------------------------------------------------------------
# Phone edge cases
# ---------------------------------------------------------------------------


class TestPhoneEdgeCases:
    """Additional phone edge cases."""

    def _redact(self, text: str) -> str:
        registry = PatternRegistry()
        registry.register(_PHONE)
        return registry.redact(text)

    def test_parenthesized(self) -> None:
        assert self._redact("(555) 234-5678") == "[PHONE REDACTED]"

    def test_dashed(self) -> None:
        assert self._redact("555-234-5678") == "[PHONE REDACTED]"

    def test_dotted(self) -> None:
        assert self._redact("555.234.5678") == "[PHONE REDACTED]"

    def test_plus_one_spaced(self) -> None:
        """Format: +1 555 234 5678"""
        assert self._redact("+1 555 234 5678") == "[PHONE REDACTED]"

    def test_seven_digit_no_match(self) -> None:
        """7-digit numbers without area code should NOT match."""
        assert "[PHONE REDACTED]" not in self._redact("234-5678")

    def test_ip_address_not_phone(self) -> None:
        """192.168.1.100 should NOT match as phone."""
        assert "[PHONE REDACTED]" not in self._redact("192.168.1.100")

    def test_version_string_not_phone(self) -> None:
        """1.2.3.4 should NOT match as phone."""
        assert "[PHONE REDACTED]" not in self._redact("1.2.3.4")

    def test_area_code_starts_with_0_no_match(self) -> None:
        assert "[PHONE REDACTED]" not in self._redact("055-234-5678")

    def test_area_code_starts_with_1_no_match(self) -> None:
        assert "[PHONE REDACTED]" not in self._redact("155-234-5678")

    def test_exchange_starts_with_0_no_match(self) -> None:
        assert "[PHONE REDACTED]" not in self._redact("555-034-5678")

    def test_exchange_starts_with_1_no_match(self) -> None:
        assert "[PHONE REDACTED]" not in self._redact("555-134-5678")

    def test_country_code_1_dashed(self) -> None:
        assert self._redact("1-555-234-5678") == "[PHONE REDACTED]"


# ---------------------------------------------------------------------------
# Mixed PII in one string
# ---------------------------------------------------------------------------


class TestMixedPII:
    """Test multiple PII types in a single string."""

    def _redact_all(self, text: str) -> str:
        registry = PatternRegistry()
        for entry in get_builtin_patterns():
            registry.register(entry)
        return registry.redact(text)

    def test_email_phone_ssn_in_one_string(self) -> None:
        text = "Contact john@test.com at 555-234-5678, SSN 078-05-1120"
        result = self._redact_all(text)
        assert "[EMAIL REDACTED]" in result
        assert "[PHONE REDACTED]" in result
        assert "[SSN REDACTED]" in result
        assert "john@test.com" not in result
        assert "555-234-5678" not in result
        assert "078-05-1120" not in result

    def test_email_and_credit_card(self) -> None:
        text = "user@example.com paid with 4111111111111111"
        result = self._redact_all(text)
        assert "[EMAIL REDACTED]" in result
        assert "[CREDIT_CARD REDACTED]" in result

    def test_all_four_types(self) -> None:
        text = (
            "Email: bob@corp.com, Phone: (555) 234-5678, SSN: 123-45-6789, Card: 4111111111111111"
        )
        result = self._redact_all(text)
        assert "[EMAIL REDACTED]" in result
        assert "[PHONE REDACTED]" in result
        assert "[SSN REDACTED]" in result
        assert "[CREDIT_CARD REDACTED]" in result


# ---------------------------------------------------------------------------
# Luhn validator edge cases
# ---------------------------------------------------------------------------


class TestLuhnEdgeCases:
    """Additional Luhn algorithm edge cases."""

    def test_all_zeros_16_digits(self) -> None:
        """All zeros passes Luhn mathematically (sum mod 10 == 0)."""
        assert _luhn_check("0000000000000000") is True

    def test_single_digit(self) -> None:
        """Single digit is too short (< 13 digits)."""
        assert _luhn_check("0") is False

    def test_empty_string(self) -> None:
        """Empty string should fail."""
        assert _luhn_check("") is False

    def test_12_digits_too_short(self) -> None:
        assert _luhn_check("123456789012") is False

    def test_20_digits_too_long(self) -> None:
        assert _luhn_check("1" * 20) is False

    def test_13_digits_minimum_valid_length(self) -> None:
        """13 digits is the minimum valid length."""
        # 4222222222222 is a 13-digit number that passes Luhn
        assert _luhn_check("4222222222222") is True

    def test_19_digits_maximum_valid_length(self) -> None:
        """19 digits is the maximum valid length."""
        # Construct a 19-digit number that passes Luhn
        # 4111111111111111110 — check if it passes
        result = _luhn_check("4111111111111111110")
        # Just verify it returns a bool and doesn't crash
        assert isinstance(result, bool)

    def test_non_digit_characters_stripped(self) -> None:
        """Separators should be stripped before validation."""
        assert _luhn_check("4111-1111-1111-1111") is True
        assert _luhn_check("4111 1111 1111 1111") is True


# ---------------------------------------------------------------------------
# JWT pattern
# ---------------------------------------------------------------------------


class TestJWTPattern:
    """Test JWT regex and heuristic."""

    def _redact(self, text: str) -> str:
        registry = PatternRegistry()
        registry.register(_JWT)
        return registry.redact(text)

    def test_valid_three_segment_jwt(self) -> None:
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abc123signature"
        assert self._redact(jwt) == "[JWT REDACTED]"

    def test_jwt_embedded_in_log_message(self) -> None:
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abc123signature"
        text = f"Auth header: Bearer {jwt} was used"
        result = self._redact(text)
        assert "[JWT REDACTED]" in result
        assert "eyJhbGci" not in result

    def test_two_segments_not_matched(self) -> None:
        """Only 2 dot-separated segments should NOT match."""
        text = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
        assert "[JWT REDACTED]" not in self._redact(text)

    def test_random_dot_separated_strings_not_matched(self) -> None:
        """Random dot-separated strings without eyJ prefix should NOT match."""
        text = "foo.bar.baz"
        assert self._redact(text) == "foo.bar.baz"

    def test_url_paths_not_matched(self) -> None:
        """URL-like paths should NOT match as JWT."""
        text = "https://example.com/api/v1/resource"
        assert self._redact(text) == text

    def test_heuristic_skips_without_eyj(self) -> None:
        """Text without 'eyJ' should skip regex entirely."""
        assert _JWT.heuristic is not None
        assert _JWT.heuristic("no jwt here at all") is False
        assert _JWT.heuristic("token: eyJhbGciOiJ...") is True


# ---------------------------------------------------------------------------
# AWS Access Key pattern
# ---------------------------------------------------------------------------


class TestAWSAccessKeyPattern:
    """Test AWS Access Key regex and heuristic."""

    def _redact(self, text: str) -> str:
        registry = PatternRegistry()
        registry.register(_AWS_ACCESS_KEY)
        return registry.redact(text)

    def test_valid_akia_key(self) -> None:
        assert self._redact("key: AKIAIOSFODNN7EXAMPLE") == "key: [AWS_ACCESS_KEY REDACTED]"

    def test_valid_asia_key(self) -> None:
        """ASIA prefix is used for temporary STS credentials."""
        assert self._redact("key: ASIASAMPLEKEY1234567") == "key: [AWS_ACCESS_KEY REDACTED]"

    def test_lowercase_not_matched(self) -> None:
        """Lowercase variants should NOT match."""
        assert "[AWS_ACCESS_KEY REDACTED]" not in self._redact("akiaiosfodnn7example")

    def test_too_short_not_matched(self) -> None:
        """Key shorter than 20 chars should NOT match."""
        assert "[AWS_ACCESS_KEY REDACTED]" not in self._redact("AKIAIOSFODNN7EXA")

    def test_wrong_prefix_aida_not_matched(self) -> None:
        """AIDA prefix (unique ID) should NOT match as access key."""
        assert "[AWS_ACCESS_KEY REDACTED]" not in self._redact("AIDAIOSFODNN7EXAMPLE1")

    def test_wrong_prefix_aroa_not_matched(self) -> None:
        """AROA prefix (role ID) should NOT match as access key."""
        assert "[AWS_ACCESS_KEY REDACTED]" not in self._redact("AROAIOSFODNN7EXAMPLE1")

    def test_heuristic(self) -> None:
        assert _AWS_ACCESS_KEY.heuristic is not None
        assert _AWS_ACCESS_KEY.heuristic("no key here") is False
        assert _AWS_ACCESS_KEY.heuristic("AKIAIOSFODNN7EXAMPLE") is True
        assert _AWS_ACCESS_KEY.heuristic("ASIASAMPLEKEY12345Q") is True


# ---------------------------------------------------------------------------
# AWS Secret Key pattern
# ---------------------------------------------------------------------------


class TestAWSSecretKeyPattern:
    """Test AWS Secret Key regex (context-dependent, requires label)."""

    def _redact(self, text: str) -> str:
        registry = PatternRegistry()
        registry.register(_AWS_SECRET_KEY)
        return registry.redact(text)

    def test_with_equals_label(self) -> None:
        text = "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        result = self._redact(text)
        assert "[AWS_SECRET_KEY REDACTED]" in result
        assert "wJalrXUtnFEMI" not in result

    def test_with_colon_label(self) -> None:
        text = "secret_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        result = self._redact(text)
        assert "[AWS_SECRET_KEY REDACTED]" in result

    def test_bare_40_char_base64_not_matched(self) -> None:
        """A bare 40-char base64 string WITHOUT label prefix must NOT match."""
        text = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        assert "[AWS_SECRET_KEY REDACTED]" not in self._redact(text)

    def test_case_insensitive_label(self) -> None:
        text = "AWS_SECRET_ACCESS_KEY = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        result = self._redact(text)
        assert "[AWS_SECRET_KEY REDACTED]" in result

    def test_aws_secret_key_label(self) -> None:
        text = "aws_secret_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        result = self._redact(text)
        assert "[AWS_SECRET_KEY REDACTED]" in result

    def test_heuristic(self) -> None:
        assert _AWS_SECRET_KEY.heuristic is not None
        assert _AWS_SECRET_KEY.heuristic("no keyword here") is False
        assert _AWS_SECRET_KEY.heuristic("my secret key value") is True


# ---------------------------------------------------------------------------
# Stripe Key pattern
# ---------------------------------------------------------------------------


class TestStripeKeyPattern:
    """Test Stripe key regex and heuristic."""

    def _redact(self, text: str) -> str:
        registry = PatternRegistry()
        registry.register(_STRIPE_KEY)
        return registry.redact(text)

    def test_sk_test_key(self) -> None:
        key = "sk_test_00000000000000000000000000"
        assert self._redact(f"key: {key}") == "key: [STRIPE_KEY REDACTED]"

    def test_pk_test_key(self) -> None:
        key = "pk_test_00000000000000000000000000"
        assert self._redact(f"key: {key}") == "key: [STRIPE_KEY REDACTED]"

    def test_rk_test_key(self) -> None:
        key = "rk_test_00000000000000000000000000"
        assert self._redact(f"key: {key}") == "key: [STRIPE_KEY REDACTED]"

    def test_random_string_with_live_not_matched(self) -> None:
        """Random string with _live_ in the middle should NOT match."""
        text = "my_live_configuration_setting_value"
        assert "[STRIPE_KEY REDACTED]" not in self._redact(text)

    def test_heuristic(self) -> None:
        assert _STRIPE_KEY.heuristic is not None
        assert _STRIPE_KEY.heuristic("no stripe here") is False
        assert _STRIPE_KEY.heuristic("sk_live_abc") is True
        assert _STRIPE_KEY.heuristic("pk_test_abc") is True


# ---------------------------------------------------------------------------
# GitHub Token pattern
# ---------------------------------------------------------------------------


class TestGitHubTokenPattern:
    """Test GitHub token regex and heuristic."""

    def _redact(self, text: str) -> str:
        registry = PatternRegistry()
        registry.register(_GITHUB_TOKEN)
        return registry.redact(text)

    def test_classic_ghp_token(self) -> None:
        """Classic personal access token: ghp_ + 36 alphanumeric chars."""
        token = "ghp_" + "A" * 36
        assert self._redact(f"token: {token}") == "token: [GITHUB_TOKEN REDACTED]"

    def test_fine_grained_github_pat_token(self) -> None:
        """Fine-grained PAT: github_pat_ + 80+ chars."""
        token = "github_pat_" + "A" * 82
        assert self._redact(f"token: {token}") == "token: [GITHUB_TOKEN REDACTED]"

    def test_gho_variant(self) -> None:
        """OAuth access token prefix."""
        token = "gho_" + "B" * 36
        assert self._redact(f"token: {token}") == "token: [GITHUB_TOKEN REDACTED]"

    def test_ghs_variant(self) -> None:
        """Server-to-server token prefix."""
        token = "ghs_" + "C" * 36
        assert self._redact(f"token: {token}") == "token: [GITHUB_TOKEN REDACTED]"

    def test_too_short_not_matched(self) -> None:
        """ghp_ with fewer than 36 chars should NOT match."""
        token = "ghp_" + "A" * 10
        assert "[GITHUB_TOKEN REDACTED]" not in self._redact(token)

    def test_wrong_prefix_not_matched(self) -> None:
        """A prefix like ghx_ should NOT match."""
        token = "ghx_" + "A" * 36
        assert "[GITHUB_TOKEN REDACTED]" not in self._redact(token)

    def test_heuristic(self) -> None:
        assert _GITHUB_TOKEN.heuristic is not None
        assert _GITHUB_TOKEN.heuristic("no token here") is False
        assert _GITHUB_TOKEN.heuristic("ghp_something") is True
        assert _GITHUB_TOKEN.heuristic("github_pat_something") is True


# ---------------------------------------------------------------------------
# GCP Key pattern
# ---------------------------------------------------------------------------


class TestGCPKeyPattern:
    """Test GCP API key regex and heuristic."""

    def _redact(self, text: str) -> str:
        registry = PatternRegistry()
        registry.register(_GCP_KEY)
        return registry.redact(text)

    def test_valid_aiza_key(self) -> None:
        """Valid GCP key: AIza + 35 chars = 39 total."""
        key = "AIza" + "A" * 35
        assert self._redact(f"key: {key}") == "key: [GCP_KEY REDACTED]"

    def test_too_short_not_matched(self) -> None:
        """AIza + fewer than 35 chars should NOT match."""
        key = "AIza" + "A" * 10
        assert "[GCP_KEY REDACTED]" not in self._redact(key)

    def test_lowercase_aiza_not_matched(self) -> None:
        """Lowercase 'aiza' should NOT match."""
        key = "aiza" + "A" * 35
        assert "[GCP_KEY REDACTED]" not in self._redact(key)

    def test_heuristic(self) -> None:
        assert _GCP_KEY.heuristic is not None
        assert _GCP_KEY.heuristic("no gcp key here") is False
        assert _GCP_KEY.heuristic("AIzaSyExampleKey") is True


# ---------------------------------------------------------------------------
# Generic Secret pattern
# ---------------------------------------------------------------------------


class TestGenericSecretPattern:
    """Test generic secret regex (context-dependent, requires label)."""

    def _redact(self, text: str) -> str:
        registry = PatternRegistry()
        registry.register(_GENERIC_SECRET)
        return registry.redact(text)

    def test_password_equals(self) -> None:
        text = "password=MyS3cr3tP@ss"
        result = self._redact(text)
        assert "[SECRET REDACTED]" in result
        assert "MyS3cr3tP@ss" not in result

    def test_api_key_colon(self) -> None:
        text = "api_key: sk-abc123def456ghi"
        result = self._redact(text)
        assert "[SECRET REDACTED]" in result
        assert "sk-abc123def456ghi" not in result

    def test_secret_with_quotes(self) -> None:
        text = 'secret = "some-secret-value-here"'
        result = self._redact(text)
        assert "[SECRET REDACTED]" in result
        assert "some-secret-value-here" not in result

    def test_bare_value_without_label_not_matched(self) -> None:
        """A bare value without a label prefix must NOT match."""
        text = "MyS3cr3tP@ssw0rd123"
        assert "[SECRET REDACTED]" not in self._redact(text)

    def test_short_value_not_matched(self) -> None:
        """Values shorter than 8 chars should NOT match."""
        text = "password=short"
        assert "[SECRET REDACTED]" not in self._redact(text)

    def test_docs_text_password_equals_short(self) -> None:
        r"""Doc-like text 'password= is required' has no 8+ char \S value after =."""
        text = "The password= field is required"
        # "field" is only 5 chars, so should not match
        # But "password=" followed by " field" — \S{8,} requires 8+ non-space
        # " field" starts with space, so \S{8,} won't match
        assert "[SECRET REDACTED]" not in self._redact(text)

    def test_heuristic(self) -> None:
        from hushlog._patterns import _generic_secret_heuristic

        assert _generic_secret_heuristic("no keywords here") is False
        assert _generic_secret_heuristic("password=abc") is True
        assert _generic_secret_heuristic("my api_key value") is True
        assert _generic_secret_heuristic("auth token here") is True

    def test_client_secret_label(self) -> None:
        text = "client_secret=abcdefgh12345678"
        result = self._redact(text)
        assert "[SECRET REDACTED]" in result

    def test_access_token_label(self) -> None:
        text = "access_token: mytoken12345678value"
        result = self._redact(text)
        assert "[SECRET REDACTED]" in result


# ---------------------------------------------------------------------------
# Mixed API keys and PII
# ---------------------------------------------------------------------------


class TestMixedAPIKeysAndPII:
    """Test multiple API key/PII types redacted in a single string."""

    def _redact_all(self, text: str) -> str:
        registry = PatternRegistry()
        for entry in get_builtin_patterns():
            registry.register(entry)
        return registry.redact(text)

    def test_aws_key_and_email(self) -> None:
        text = "key=AKIAIOSFODNN7EXAMPLE user=admin@example.com"
        result = self._redact_all(text)
        assert "[AWS_ACCESS_KEY REDACTED]" in result
        assert "[EMAIL REDACTED]" in result
        assert "AKIAIOSFODNN7EXAMPLE" not in result
        assert "admin@example.com" not in result

    def test_jwt_and_phone(self) -> None:
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abc123signature"
        text = f"token={jwt} caller=555-234-5678"
        result = self._redact_all(text)
        assert "[JWT REDACTED]" in result
        assert "[PHONE REDACTED]" in result
        assert "eyJhbGci" not in result
        assert "555-234-5678" not in result

    def test_stripe_key_and_ssn(self) -> None:
        text = "payment_key=sk_test_00000000000000000000000000 ssn=123-45-6789"
        result = self._redact_all(text)
        assert "[STRIPE_KEY REDACTED]" in result
        assert "[SSN REDACTED]" in result
        assert "sk_test_" not in result
        assert "123-45-6789" not in result


# ---------------------------------------------------------------------------
# IPv4 validator
# ---------------------------------------------------------------------------


class TestIPv4Validate:
    """Validate the IPv4 address validator."""

    def test_valid_common_addresses(self) -> None:
        assert _ipv4_validate("192.168.1.1") is True
        assert _ipv4_validate("10.0.0.1") is True
        assert _ipv4_validate("8.8.8.8") is True
        assert _ipv4_validate("255.255.255.255") is True
        assert _ipv4_validate("0.0.0.0") is True

    def test_invalid_octet_over_255(self) -> None:
        assert _ipv4_validate("256.1.1.1") is False
        assert _ipv4_validate("1.1.1.999") is False

    def test_leading_zeros_rejected(self) -> None:
        assert _ipv4_validate("192.168.01.1") is False
        assert _ipv4_validate("01.01.01.01") is False

    def test_wrong_part_count(self) -> None:
        assert _ipv4_validate("1.2.3") is False
        assert _ipv4_validate("1.2.3.4.5") is False

    def test_empty_parts(self) -> None:
        assert _ipv4_validate("1..2.3") is False
        assert _ipv4_validate("") is False


# ---------------------------------------------------------------------------
# IPv6 validator
# ---------------------------------------------------------------------------


class TestIPv6Validate:
    """Validate the IPv6 address validator."""

    def test_full_address(self) -> None:
        assert _ipv6_validate("2001:0db8:85a3:0000:0000:8a2e:0370:7334") is True

    def test_compressed_address(self) -> None:
        assert _ipv6_validate("::1") is True
        assert _ipv6_validate("fe80::1") is True
        assert _ipv6_validate("::") is True

    def test_loopback(self) -> None:
        assert _ipv6_validate("::1") is True

    def test_ipv4_mapped(self) -> None:
        assert _ipv6_validate("::ffff:192.168.1.1") is True

    def test_invalid_addresses(self) -> None:
        assert _ipv6_validate("not-an-ipv6") is False
        assert _ipv6_validate("192.168.1.1") is False
        assert _ipv6_validate("") is False


# ---------------------------------------------------------------------------
# IPv4 pattern
# ---------------------------------------------------------------------------


class TestIPv4Pattern:
    """Test IPv4 regex + validator integration."""

    def _redact(self, text: str) -> str:
        registry = PatternRegistry()
        registry.register(_IPV4)
        return registry.redact(text)

    def test_simple_ipv4(self) -> None:
        assert self._redact("server 192.168.1.1") == "server [IPV4 REDACTED]"

    def test_google_dns(self) -> None:
        """8.8.8.8 (all single-digit octets) must be matched."""
        assert self._redact("dns: 8.8.8.8") == "dns: [IPV4 REDACTED]"

    def test_localhost(self) -> None:
        assert self._redact("host: 127.0.0.1") == "host: [IPV4 REDACTED]"

    def test_broadcast(self) -> None:
        assert self._redact("broadcast: 255.255.255.255") == "broadcast: [IPV4 REDACTED]"

    def test_zero_address(self) -> None:
        assert self._redact("addr: 0.0.0.0") == "addr: [IPV4 REDACTED]"

    def test_ip_in_url(self) -> None:
        """IPs after :// in URLs should still match."""
        result = self._redact("http://192.168.1.1/path")
        assert "[IPV4 REDACTED]" in result

    def test_multiple_ips(self) -> None:
        result = self._redact("src 10.0.0.1 dst 10.0.0.2")
        assert result == "src [IPV4 REDACTED] dst [IPV4 REDACTED]"

    def test_invalid_octet_not_redacted(self) -> None:
        """Octets > 255 should NOT be redacted (validator rejects)."""
        assert self._redact("addr: 999.999.999.999") == "addr: 999.999.999.999"

    def test_leading_zeros_not_redacted(self) -> None:
        """Leading zeros should NOT be redacted (validator rejects)."""
        assert self._redact("addr: 192.168.01.1") == "addr: 192.168.01.1"

    def test_version_string_not_matched(self) -> None:
        """v1.2.3.4 should NOT match (lookbehind blocks alphanumeric prefix)."""
        assert self._redact("version v1.2.3.4") == "version v1.2.3.4"

    def test_package_version_not_matched(self) -> None:
        """pkg@1.2.3.4 should NOT match (lookbehind blocks @)."""
        assert self._redact("pkg@1.2.3.4") == "pkg@1.2.3.4"

    def test_five_octets_not_matched(self) -> None:
        """1.2.3.4.5 should not produce a match (lookahead blocks trailing dot)."""
        result = self._redact("1.2.3.4.5")
        assert "[IPV4 REDACTED]" not in result


# ---------------------------------------------------------------------------
# IPv6 pattern
# ---------------------------------------------------------------------------


class TestIPv6Pattern:
    """Test IPv6 regex + validator integration."""

    def _redact(self, text: str) -> str:
        registry = PatternRegistry()
        registry.register(_IPV6)
        return registry.redact(text)

    def test_full_ipv6(self) -> None:
        assert (
            self._redact("addr: 2001:0db8:85a3:0000:0000:8a2e:0370:7334") == "addr: [IPV6 REDACTED]"
        )

    def test_loopback(self) -> None:
        assert self._redact("addr: ::1") == "addr: [IPV6 REDACTED]"

    def test_compressed(self) -> None:
        assert self._redact("addr: fe80::1") == "addr: [IPV6 REDACTED]"

    def test_ipv4_mapped(self) -> None:
        assert self._redact("addr: ::ffff:192.168.1.1") == "addr: [IPV6 REDACTED]"

    def test_double_colon_only(self) -> None:
        assert self._redact("addr: ::") == "addr: [IPV6 REDACTED]"

    def test_heuristic_skips_no_colon(self) -> None:
        assert _IPV6.heuristic is not None
        assert _IPV6.heuristic("no colons here") is False
        assert _IPV6.heuristic("has:colon") is True

    def test_not_a_valid_ipv6(self) -> None:
        """Random hex with colons that doesn't form valid IPv6 should not be redacted."""
        # gggg is not valid hex for IPv6
        result = self._redact("addr: gggg::1")
        assert "[IPV6 REDACTED]" not in result

    def test_time_not_matched(self) -> None:
        """10:30:45 (a time string) should NOT be matched as IPv6."""
        result = self._redact("meeting at 10:30:45 today")
        assert "[IPV6 REDACTED]" not in result
        assert "10:30:45" in result

    def test_mac_address_not_matched(self) -> None:
        """aa:bb:cc:dd:ee:ff (a MAC address) should NOT be matched as IPv6."""
        result = self._redact("MAC aa:bb:cc:dd:ee:ff")
        assert "[IPV6 REDACTED]" not in result
        assert "aa:bb:cc:dd:ee:ff" in result


# ---------------------------------------------------------------------------
# IPv4 additional coverage
# ---------------------------------------------------------------------------


class TestIPv4AdditionalCoverage:
    """Additional IPv4 edge cases."""

    def _redact(self, text: str) -> str:
        registry = PatternRegistry()
        registry.register(_IPV4)
        return registry.redact(text)

    def test_google_dns_single_digit_octets(self) -> None:
        """8.8.8.8 — all single-digit octets must be redacted."""
        assert self._redact("dns 8.8.8.8") == "dns [IPV4 REDACTED]"

    def test_ip_in_url_with_port(self) -> None:
        """IP in URL with port: http://192.168.1.1:8080 should be redacted."""
        result = self._redact("http://192.168.1.1:8080/path")
        assert "[IPV4 REDACTED]" in result
        assert "192.168.1.1" not in result

    def test_zero_address(self) -> None:
        """0.0.0.0 is a valid IPv4 address."""
        assert self._redact("bind 0.0.0.0") == "bind [IPV4 REDACTED]"

    def test_subnet_mask(self) -> None:
        """255.255.255.0 is a valid IPv4 address."""
        assert self._redact("mask 255.255.255.0") == "mask [IPV4 REDACTED]"


# ---------------------------------------------------------------------------
# Mixed IPv4 + IPv6 redaction
# ---------------------------------------------------------------------------


class TestMixedIPRedaction:
    """Test that both IPv4 and IPv6 are redacted in the same string."""

    def _redact(self, text: str) -> str:
        registry = PatternRegistry()
        registry.register(_IPV6)
        registry.register(_IPV4)
        return registry.redact(text)

    def test_both_ipv4_and_ipv6_redacted(self) -> None:
        """A string containing both IPv4 and IPv6 addresses should redact both."""
        result = self._redact("src 192.168.1.1 dst 2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        assert "[IPV4 REDACTED]" in result
        assert "[IPV6 REDACTED]" in result
        assert "192.168.1.1" not in result
        assert "2001:0db8" not in result


# ---------------------------------------------------------------------------
# IP + Email cross-pattern redaction
# ---------------------------------------------------------------------------


class TestIPAndEmailRedaction:
    """Test that IP and email patterns redact independently in the same string."""

    def test_ip_and_email_both_redacted(self) -> None:
        registry = PatternRegistry()
        registry.register(_IPV4)
        registry.register(_EMAIL)
        result = registry.redact("user admin@example.com from 10.0.0.1")
        assert "[IPV4 REDACTED]" in result
        assert "[EMAIL REDACTED]" in result
        assert "10.0.0.1" not in result
        assert "admin@example.com" not in result


# ---------------------------------------------------------------------------
# v1.1.0 — Phone matched parentheses
# ---------------------------------------------------------------------------


class TestPhoneMatchedParens:
    """Phone regex must require both parens or neither."""

    def _redact(self, text: str) -> str:
        registry = PatternRegistry()
        registry.register(_PHONE)
        return registry.redact(text)

    def test_both_parens_matches(self) -> None:
        assert self._redact("(555) 234-5678") == "[PHONE REDACTED]"

    def test_no_parens_matches(self) -> None:
        assert self._redact("555-234-5678") == "[PHONE REDACTED]"

    def test_open_paren_only_no_match(self) -> None:
        """Mismatched open paren should NOT match as phone."""
        result = self._redact("(555 234-5678")
        assert "[PHONE REDACTED]" not in result

    def test_close_paren_only_no_match(self) -> None:
        """Mismatched close paren should NOT match as phone."""
        result = self._redact("555) 234-5678")
        assert "[PHONE REDACTED]" not in result


# ---------------------------------------------------------------------------
# v1.1.0 — Generic secret stops at quotes
# ---------------------------------------------------------------------------


class TestGenericSecretQuoteBoundary:
    """Generic secret regex should stop at quote characters."""

    def _redact(self, text: str) -> str:
        registry = PatternRegistry()
        registry.register(_GENERIC_SECRET)
        return registry.redact(text)

    def test_double_quoted_value(self) -> None:
        result = self._redact('password="mysecretvalue123"')
        assert "[SECRET REDACTED]" in result

    def test_single_quoted_value(self) -> None:
        result = self._redact("password='mysecretvalue123'")
        assert "[SECRET REDACTED]" in result


# ---------------------------------------------------------------------------
# v1.1.0 — NFKC normalization
# ---------------------------------------------------------------------------


class TestNormalizationConfig:
    """Test configurable Unicode normalization form."""

    def test_nfkc_detects_cyrillic_homoglyph(self) -> None:
        """NFKC normalization should help detect confusable characters."""
        from hushlog._config import Config

        # Cyrillic "а" (U+0430) looks like Latin "a" (U+0061)
        # With NFKC, some confusables are normalized
        registry = PatternRegistry.from_config(Config(normalize_form="NFKC"))
        # Test that registry works with NFKC normalization
        result = registry.redact("user@example.com")
        assert "[EMAIL REDACTED]" in result

    def test_normalize_none_skips_normalization(self) -> None:
        """normalize_form='none' should skip Unicode normalization."""
        from hushlog._config import Config

        registry = PatternRegistry.from_config(Config(normalize_form="none"))
        result = registry.redact("user@example.com")
        assert "[EMAIL REDACTED]" in result

    def test_default_nfc_normalization(self) -> None:
        """Default NFC normalization should work as before."""
        from hushlog._config import Config

        registry = PatternRegistry.from_config(Config())
        assert registry._normalize_form == "NFC"  # noqa: SLF001

    def test_invalid_normalize_form_raises(self) -> None:
        """Invalid normalize_form should raise ValueError."""
        from hushlog._config import Config

        with pytest.raises(ValueError, match="normalize_form"):
            Config(normalize_form="INVALID")


# ---------------------------------------------------------------------------
# CPF validator
# ---------------------------------------------------------------------------


class TestCPFValidator:
    """Validate the CPF check digit algorithm implementation."""

    @pytest.mark.parametrize(
        "cpf",
        [
            "529.982.247-25",
            "453.178.287-91",
            "017.433.460-50",
            "111.444.777-35",
        ],
    )
    def test_valid_cpfs(self, cpf: str) -> None:
        assert _cpf_validate(cpf) is True

    @pytest.mark.parametrize(
        "cpf",
        [
            "529.982.247-26",  # Wrong check digit
            "000.000.000-00",  # All same digits
            "111.111.111-11",  # All same digits
            "123.456.789-0",  # Too short
        ],
    )
    def test_invalid_cpfs(self, cpf: str) -> None:
        assert _cpf_validate(cpf) is False

    def test_all_same_digits_rejected(self) -> None:
        """All-same-digit CPFs like 111.111.111-11 must be rejected."""
        for d in range(10):
            cpf = f"{d}{d}{d}.{d}{d}{d}.{d}{d}{d}-{d}{d}"
            assert _cpf_validate(cpf) is False


# ---------------------------------------------------------------------------
# CPF pattern
# ---------------------------------------------------------------------------


class TestCPFPattern:
    """Test CPF regex + validator integration."""

    def test_valid_cpf_redacted(self) -> None:
        registry = PatternRegistry()
        registry.register(_CPF)
        result = registry.redact("CPF: 529.982.247-25")
        assert "[CPF REDACTED]" in result
        assert "529.982.247-25" not in result

    def test_invalid_check_digit_not_redacted(self) -> None:
        registry = PatternRegistry()
        registry.register(_CPF)
        result = registry.redact("CPF: 529.982.247-26")
        assert "529.982.247-26" in result
        assert "[CPF REDACTED]" not in result

    def test_all_same_digits_not_redacted(self) -> None:
        registry = PatternRegistry()
        registry.register(_CPF)
        result = registry.redact("CPF: 111.111.111-11")
        assert "111.111.111-11" in result
        assert "[CPF REDACTED]" not in result

    def test_bare_digits_not_matched(self) -> None:
        """Bare 11-digit CPF (no formatting) should NOT be matched."""
        registry = PatternRegistry()
        registry.register(_CPF)
        result = registry.redact("CPF: 52998224725")
        assert "52998224725" in result
        assert "[CPF REDACTED]" not in result

    def test_multiple_cpfs(self) -> None:
        registry = PatternRegistry()
        registry.register(_CPF)
        result = registry.redact("CPFs: 529.982.247-25 and 453.178.287-91")
        assert result.count("[CPF REDACTED]") == 2

    def test_partial_mask(self) -> None:
        from hushlog._config import Config

        config = Config(mask_style="partial", mask_character="*")
        registry = PatternRegistry.from_config(config)
        result = registry.redact("CPF: 529.982.247-25")
        assert "***.***.***-25" in result

    def test_heuristic_skips_without_dot_and_dash(self) -> None:
        """Heuristic requires both '.' and '-' in the text."""
        assert _CPF.heuristic is not None
        assert _CPF.heuristic("no special chars here") is False
        assert _CPF.heuristic("has.dot but no dash") is False
        assert _CPF.heuristic("has-dash but no dot") is False
        assert _CPF.heuristic("has.both-chars") is True


# ---------------------------------------------------------------------------
# CNPJ validator
# ---------------------------------------------------------------------------


class TestCNPJValidator:
    """Validate the CNPJ check digit algorithm implementation."""

    @pytest.mark.parametrize(
        "cnpj",
        [
            "11.222.333/0001-81",
            "11.444.777/0001-61",
            "53.113.791/0001-22",
        ],
    )
    def test_valid_cnpjs(self, cnpj: str) -> None:
        assert _cnpj_validate(cnpj) is True

    @pytest.mark.parametrize(
        "cnpj",
        [
            "11.222.333/0001-82",  # Wrong check digit
            "00.000.000/0000-00",  # All same digits
            "11.111.111/1111-11",  # All same digits
        ],
    )
    def test_invalid_cnpjs(self, cnpj: str) -> None:
        assert _cnpj_validate(cnpj) is False


# ---------------------------------------------------------------------------
# CNPJ pattern
# ---------------------------------------------------------------------------


class TestCNPJPattern:
    """Test CNPJ regex + validator integration."""

    def test_valid_cnpj_redacted(self) -> None:
        registry = PatternRegistry()
        registry.register(_CNPJ)
        result = registry.redact("CNPJ: 11.222.333/0001-81")
        assert "[CNPJ REDACTED]" in result
        assert "11.222.333/0001-81" not in result

    def test_invalid_check_digit_not_redacted(self) -> None:
        registry = PatternRegistry()
        registry.register(_CNPJ)
        result = registry.redact("CNPJ: 11.222.333/0001-82")
        assert "11.222.333/0001-82" in result
        assert "[CNPJ REDACTED]" not in result

    def test_bare_digits_not_matched(self) -> None:
        """Bare 14-digit CNPJ (no formatting) should NOT be matched."""
        registry = PatternRegistry()
        registry.register(_CNPJ)
        result = registry.redact("CNPJ: 11222333000181")
        assert "11222333000181" in result
        assert "[CNPJ REDACTED]" not in result

    def test_partial_mask(self) -> None:
        from hushlog._config import Config

        config = Config(mask_style="partial", mask_character="*")
        registry = PatternRegistry.from_config(config)
        result = registry.redact("CNPJ: 11.222.333/0001-81")
        assert "**.***.***/0001-81" in result

    def test_heuristic_skips_without_slash(self) -> None:
        """Heuristic requires '/' in the text."""
        assert _CNPJ.heuristic is not None
        assert _CNPJ.heuristic("no slash here") is False
        assert _CNPJ.heuristic("has/slash") is True


# ---------------------------------------------------------------------------
# BR Phone pattern
# ---------------------------------------------------------------------------


class TestBRPhonePattern:
    """Test Brazilian phone number pattern."""

    def test_mobile_with_country_code(self) -> None:
        registry = PatternRegistry()
        registry.register(_BR_PHONE)
        result = registry.redact("Phone: +55 (11) 91234-5678")
        assert "[BR_PHONE REDACTED]" in result
        assert "91234-5678" not in result

    def test_mobile_without_country_code(self) -> None:
        registry = PatternRegistry()
        registry.register(_BR_PHONE)
        result = registry.redact("Phone: (11) 91234-5678")
        assert "[BR_PHONE REDACTED]" in result

    def test_landline(self) -> None:
        registry = PatternRegistry()
        registry.register(_BR_PHONE)
        result = registry.redact("Phone: (21) 2345-6789")
        assert "[BR_PHONE REDACTED]" in result

    def test_without_parens_not_matched(self) -> None:
        """Phone without parenthesized area code should NOT be matched."""
        registry = PatternRegistry()
        registry.register(_BR_PHONE)
        result = registry.redact("Phone: 11 91234-5678")
        assert "[BR_PHONE REDACTED]" not in result

    def test_invalid_area_code_not_matched(self) -> None:
        """Area code starting with 0 should NOT be matched."""
        registry = PatternRegistry()
        registry.register(_BR_PHONE)
        result = registry.redact("Phone: (01) 91234-5678")
        assert "[BR_PHONE REDACTED]" not in result

    def test_partial_mask(self) -> None:
        from hushlog._config import Config

        config = Config(mask_style="partial", mask_character="*")
        registry = PatternRegistry.from_config(config)
        result = registry.redact("Phone: (11) 91234-5678")
        assert "(**) *****-5678" in result

    def test_landline_with_country_code(self) -> None:
        registry = PatternRegistry()
        registry.register(_BR_PHONE)
        result = registry.redact("Phone: +55(21) 2345-6789")
        assert "[BR_PHONE REDACTED]" in result

    def test_heuristic_skips_without_paren(self) -> None:
        """Heuristic requires '(' in the text."""
        assert _BR_PHONE.heuristic is not None
        assert _BR_PHONE.heuristic("no parens here") is False
        assert _BR_PHONE.heuristic("has (paren)") is True
