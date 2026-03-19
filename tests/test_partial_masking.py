"""Tests for partial masking feature (v0.2.0-alpha.3)."""

from __future__ import annotations

import pytest

from hushlog._config import Config
from hushlog._registry import PatternRegistry

# ---------------------------------------------------------------------------
# Config validation
# ---------------------------------------------------------------------------


class TestConfigValidation:
    """Validate Config constraints for mask_style and mask_character."""

    def test_invalid_mask_style_raises(self) -> None:
        with pytest.raises(ValueError, match="mask_style must be 'full' or 'partial'"):
            Config(mask_style="redact")

    def test_invalid_mask_character_raises_empty(self) -> None:
        with pytest.raises(ValueError, match="mask_character must be a single character"):
            Config(mask_character="")

    def test_invalid_mask_character_raises_multi(self) -> None:
        with pytest.raises(ValueError, match="mask_character must be a single character"):
            Config(mask_character="**")

    def test_valid_full_config(self) -> None:
        cfg = Config(mask_style="full", mask_character="*")
        assert cfg.mask_style == "full"
        assert cfg.mask_character == "*"

    def test_valid_partial_config(self) -> None:
        cfg = Config(mask_style="partial", mask_character="#")
        assert cfg.mask_style == "partial"
        assert cfg.mask_character == "#"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _partial_registry(mask_char: str = "*") -> PatternRegistry:
    return PatternRegistry.from_config(Config(mask_style="partial", mask_character=mask_char))


def _full_registry() -> PatternRegistry:
    return PatternRegistry.from_config(Config(mask_style="full"))


# ---------------------------------------------------------------------------
# Partial mask: Email
# ---------------------------------------------------------------------------


class TestPartialMaskEmail:
    def test_standard_email(self) -> None:
        reg = _partial_registry()
        result = reg.redact("contact john@example.com please")
        assert result == "contact j***@e***.com please"

    def test_single_char_local(self) -> None:
        reg = _partial_registry()
        result = reg.redact("email: a@example.com")
        assert "a***@e***.com" in result

    def test_subdomain_email(self) -> None:
        reg = _partial_registry()
        result = reg.redact("mail to user@mail.example.com")
        # rsplit('.', 1) on 'mail.example' gives domain_name='mail.example', tld='com'
        assert "u***@m***.com" in result


# ---------------------------------------------------------------------------
# Partial mask: Credit Card
# ---------------------------------------------------------------------------


class TestPartialMaskCreditCard:
    def test_visa_number(self) -> None:
        reg = _partial_registry()
        result = reg.redact("Card: 4111111111111111")
        assert result == "Card: ****-****-****-1111"

    def test_dashed_format(self) -> None:
        reg = _partial_registry()
        result = reg.redact("Card: 4111-1111-1111-1111")
        assert result == "Card: ****-****-****-1111"

    def test_spaced_format(self) -> None:
        reg = _partial_registry()
        result = reg.redact("Card: 4111 1111 1111 1111")
        assert result == "Card: ****-****-****-1111"


# ---------------------------------------------------------------------------
# Partial mask: SSN
# ---------------------------------------------------------------------------


class TestPartialMaskSSN:
    def test_standard_ssn(self) -> None:
        reg = _partial_registry()
        result = reg.redact("SSN 078-05-1120")
        assert result == "SSN ***-**-1120"


# ---------------------------------------------------------------------------
# Partial mask: Phone
# ---------------------------------------------------------------------------


class TestPartialMaskPhone:
    def test_parenthesized_phone(self) -> None:
        reg = _partial_registry()
        result = reg.redact("call (212) 555-5678")
        assert "(***) ***-5678" in result

    def test_dashed_phone(self) -> None:
        reg = _partial_registry()
        result = reg.redact("call 212-555-5678")
        assert "(***) ***-5678" in result


# ---------------------------------------------------------------------------
# Partial mask: JWT
# ---------------------------------------------------------------------------


class TestPartialMaskJWT:
    def test_jwt_token(self) -> None:
        reg = _partial_registry()
        token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123signature"
        result = reg.redact(f"token: {token}")
        assert result == "token: eyJ***...***"


# ---------------------------------------------------------------------------
# Partial mask: AWS Access Key
# ---------------------------------------------------------------------------


class TestPartialMaskAWSAccessKey:
    def test_akia_key(self) -> None:
        reg = _partial_registry()
        # AKIA + 16 chars = 20 total. first4 + mask*(20-8) + last4 = AKIA + 12* + last4
        key = "AKIAIOSFODNN7EXAMPLE"
        result = reg.redact(f"key: {key}")
        assert result == f"key: AKIA{('*' * 12)}MPLE"


# ---------------------------------------------------------------------------
# Partial mask: Stripe Key
# ---------------------------------------------------------------------------


class TestPartialMaskStripeKey:
    def test_stripe_live_key(self) -> None:
        reg = _partial_registry()
        key = "sk_test_00000000000000000000000000"
        result = reg.redact(f"key: {key}")
        assert result.startswith("key: sk_t")
        assert result.endswith("0000")
        assert "***" in result


# ---------------------------------------------------------------------------
# Partial mask: GitHub Token
# ---------------------------------------------------------------------------


class TestPartialMaskGitHubToken:
    def test_ghp_token(self) -> None:
        reg = _partial_registry()
        token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        result = reg.redact(f"token: {token}")
        assert result.startswith("token: ghp_")
        assert result.endswith("ghij")
        assert "***" in result


# ---------------------------------------------------------------------------
# Partial mask: GCP Key
# ---------------------------------------------------------------------------


class TestPartialMaskGCPKey:
    def test_gcp_api_key(self) -> None:
        reg = _partial_registry()
        key = "AIzaSyA1234567890abcdefghijklmnopqrstuv"
        result = reg.redact(f"key: {key}")
        assert result.startswith("key: AIza")
        assert result.endswith("stuv")
        assert "***" in result


# ---------------------------------------------------------------------------
# Partial mask: IPv4
# ---------------------------------------------------------------------------


class TestPartialMaskIPv4:
    def test_ipv4_address(self) -> None:
        reg = _partial_registry()
        result = reg.redact("from 192.168.1.100")
        assert result == "from 192.***.***.***.***" or result == "from 192.***.***.***"
        # The partial masker produces: first_octet.***.***.***
        assert "192.***.***.***" in result


# ---------------------------------------------------------------------------
# Partial mask: IPv6
# ---------------------------------------------------------------------------


class TestPartialMaskIPv6:
    def test_full_ipv6(self) -> None:
        reg = _partial_registry()
        result = reg.redact("addr 2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        assert "2001:****:****:****" in result


# ---------------------------------------------------------------------------
# Partial mask: Generic Secret
# ---------------------------------------------------------------------------


class TestPartialMaskGenericSecret:
    def test_password_label_preserved(self) -> None:
        reg = _partial_registry()
        result = reg.redact("password=SuperSecretPassword123!")
        assert result.startswith("password=")
        assert "********" in result

    def test_api_key_label_preserved(self) -> None:
        reg = _partial_registry()
        result = reg.redact("api_key: my_very_secret_api_key_value")
        assert result.startswith("api_key:")
        assert "********" in result


# ---------------------------------------------------------------------------
# Full mode unchanged (backward compatibility)
# ---------------------------------------------------------------------------


class TestFullModeUnchanged:
    def test_email_full_mode(self) -> None:
        reg = _full_registry()
        result = reg.redact("contact john@example.com please")
        assert result == "contact [EMAIL REDACTED] please"

    def test_ssn_full_mode(self) -> None:
        reg = _full_registry()
        result = reg.redact("SSN 078-05-1120")
        assert result == "SSN [SSN REDACTED]"

    def test_credit_card_full_mode(self) -> None:
        reg = _full_registry()
        result = reg.redact("Card: 4111111111111111")
        assert result == "Card: [CREDIT_CARD REDACTED]"


# ---------------------------------------------------------------------------
# Custom mask character
# ---------------------------------------------------------------------------


class TestCustomMaskCharacter:
    def test_hash_mask_email(self) -> None:
        reg = _partial_registry(mask_char="#")
        result = reg.redact("contact john@example.com please")
        assert result == "contact j###@e###.com please"

    def test_hash_mask_ssn(self) -> None:
        reg = _partial_registry(mask_char="#")
        result = reg.redact("SSN 078-05-1120")
        assert result == "SSN ###-##-1120"


# ---------------------------------------------------------------------------
# Mixed partial redaction (multiple PII types in one string)
# ---------------------------------------------------------------------------


class TestMixedPartialRedaction:
    def test_email_and_ssn(self) -> None:
        reg = _partial_registry()
        result = reg.redact("User alice@corp.io SSN 078-05-1120")
        assert "a***@c***.io" in result
        assert "***-**-1120" in result
        assert "alice@corp.io" not in result
        assert "078-05-1120" not in result

    def test_email_and_phone(self) -> None:
        reg = _partial_registry()
        result = reg.redact("Email alice@corp.io Phone (212) 555-1234")
        assert "a***@c***.io" in result
        assert "(***) ***-1234" in result


# ---------------------------------------------------------------------------
# Custom patterns fall back to full mask in partial mode
# ---------------------------------------------------------------------------


class TestCustomPatternsFallback:
    def test_custom_pattern_uses_full_mask_in_partial_mode(self) -> None:
        config = Config(
            mask_style="partial",
            custom_patterns={"my_token": r"tok_[A-Za-z0-9]+"},
        )
        reg = PatternRegistry.from_config(config)
        result = reg.redact("value is tok_abc123XYZ here")
        # Custom patterns have no partial_masker, so they fall back to full mask
        assert "[MY_TOKEN REDACTED]" in result
        assert "tok_abc123XYZ" not in result


# ---------------------------------------------------------------------------
# Registry propagation of mask_style and mask_char
# ---------------------------------------------------------------------------


class TestRegistryConfigPropagation:
    def test_mask_style_propagated(self) -> None:
        reg = _partial_registry()
        assert reg._mask_style == "partial"

    def test_mask_char_propagated(self) -> None:
        reg = _partial_registry(mask_char="#")
        assert reg._mask_char == "#"

    def test_default_mask_style_is_full(self) -> None:
        reg = _full_registry()
        assert reg._mask_style == "full"

    def test_default_mask_char_is_star(self) -> None:
        reg = _full_registry()
        assert reg._mask_char == "*"
