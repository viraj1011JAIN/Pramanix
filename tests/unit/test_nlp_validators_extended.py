# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Tests for the 7 new NLP validators added in GA-2.

Covers: StringLengthValidator, NumericRangeValidator, DateValidator,
        URLValidator, EmailValidator, JSONSchemaValidator, ProfanityDetector.
"""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal

import pytest

from pramanix.nlp import (
    DateValidator,
    EmailValidator,
    JSONSchemaValidator,
    NumericRangeValidator,
    ProfanityDetector,
    StringLengthValidator,
    URLValidator,
)

# ── StringLengthValidator ─────────────────────────────────────────────────────


class TestStringLengthValidator:
    def test_valid_within_bounds(self) -> None:
        v = StringLengthValidator(min_length=1, max_length=10)
        ok, reason = v.validate("hello")
        assert ok
        assert reason == ""

    def test_too_short(self) -> None:
        v = StringLengthValidator(min_length=5, max_length=100)
        ok, reason = v.validate("hi")
        assert not ok
        assert "too short" in reason
        assert "2" in reason
        assert "5" in reason

    def test_too_long(self) -> None:
        v = StringLengthValidator(min_length=0, max_length=5)
        ok, reason = v.validate("toolong!")
        assert not ok
        assert "too long" in reason

    def test_exactly_at_min(self) -> None:
        v = StringLengthValidator(min_length=3, max_length=10)
        ok, _ = v.validate("abc")
        assert ok

    def test_exactly_at_max(self) -> None:
        v = StringLengthValidator(min_length=0, max_length=3)
        ok, _ = v.validate("abc")
        assert ok

    def test_empty_string_zero_min(self) -> None:
        v = StringLengthValidator(min_length=0, max_length=100)
        ok, _ = v.validate("")
        assert ok

    def test_is_valid_convenience(self) -> None:
        v = StringLengthValidator(max_length=5)
        assert v.is_valid("hi")
        assert not v.is_valid("toolongstring")

    def test_invalid_config_min_negative(self) -> None:
        with pytest.raises(ValueError, match="min_length"):
            StringLengthValidator(min_length=-1, max_length=10)

    def test_invalid_config_max_less_than_min(self) -> None:
        with pytest.raises(ValueError, match="max_length"):
            StringLengthValidator(min_length=10, max_length=5)

    def test_unicode_code_points_counted(self) -> None:
        # "café" is 4 code points even though UTF-8 is 5 bytes
        v = StringLengthValidator(min_length=4, max_length=4)
        ok, _ = v.validate("café")
        assert ok


# ── NumericRangeValidator ─────────────────────────────────────────────────────


class TestNumericRangeValidator:
    def test_within_inclusive_bounds(self) -> None:
        v = NumericRangeValidator(min_value=0, max_value=1000, inclusive=True)
        ok, _ = v.validate(500)
        assert ok

    def test_at_inclusive_lower_bound(self) -> None:
        v = NumericRangeValidator(min_value=0, max_value=100)
        ok, _ = v.validate(0)
        assert ok

    def test_at_inclusive_upper_bound(self) -> None:
        v = NumericRangeValidator(min_value=0, max_value=100)
        ok, _ = v.validate(100)
        assert ok

    def test_below_min(self) -> None:
        v = NumericRangeValidator(min_value=10)
        ok, reason = v.validate(5)
        assert not ok
        assert "10" in reason

    def test_above_max(self) -> None:
        v = NumericRangeValidator(max_value=100)
        ok, reason = v.validate(101)
        assert not ok
        assert "100" in reason

    def test_exclusive_bounds_at_boundary(self) -> None:
        v = NumericRangeValidator(min_value=0, max_value=100, inclusive=False)
        ok, _ = v.validate(Decimal("0.001"))
        assert ok
        ok2, _ = v.validate(0)
        assert not ok2

    def test_decimal_string_input(self) -> None:
        v = NumericRangeValidator(min_value=0, max_value=1000)
        ok, _ = v.validate("500.50")
        assert ok

    def test_unparseable_input(self) -> None:
        v = NumericRangeValidator(min_value=0, max_value=100)
        ok, reason = v.validate("notanumber")
        assert not ok
        assert "cannot parse" in reason

    def test_no_bounds(self) -> None:
        v = NumericRangeValidator()
        ok, _ = v.validate(-999999)
        assert ok

    def test_decimal_precision_preserved(self) -> None:
        v = NumericRangeValidator(min_value=Decimal("0.001"), max_value=Decimal("0.999"))
        ok, _ = v.validate(Decimal("0.500"))
        assert ok
        ok2, _ = v.validate(Decimal("1.0"))
        assert not ok2


# ── DateValidator ─────────────────────────────────────────────────────────────


class TestDateValidator:
    def test_valid_future_date(self) -> None:
        v = DateValidator()
        ok, _ = v.validate("2099-01-01T00:00:00+00:00")
        assert ok

    def test_invalid_format(self) -> None:
        v = DateValidator()
        ok, reason = v.validate("not-a-date")
        assert not ok
        assert "ISO 8601" in reason

    def test_allow_past_false_rejects_past(self) -> None:
        v = DateValidator(allow_past=False)
        ok, reason = v.validate("2000-01-01T00:00:00+00:00")
        assert not ok
        assert "past" in reason

    def test_allow_future_false_rejects_future(self) -> None:
        v = DateValidator(allow_future=False)
        ok, reason = v.validate("2099-12-31T00:00:00+00:00")
        assert not ok
        assert "future" in reason

    def test_not_before_respected(self) -> None:
        lower = datetime(2025, 1, 1, tzinfo=timezone.utc)
        v = DateValidator(not_before=lower)
        ok, _ = v.validate("2026-06-01T00:00:00+00:00")
        assert ok
        ok2, reason = v.validate("2024-01-01T00:00:00+00:00")
        assert not ok2
        assert "before" in reason

    def test_not_after_respected(self) -> None:
        upper = datetime(2027, 12, 31, tzinfo=timezone.utc)
        v = DateValidator(not_after=upper)
        ok, _ = v.validate("2026-06-01T00:00:00+00:00")
        assert ok
        ok2, reason = v.validate("2030-01-01T00:00:00+00:00")
        assert not ok2
        assert "after" in reason

    def test_naive_datetime_treated_as_utc(self) -> None:
        # Naive datetime is treated as UTC; 2000-01-01 is in the past.
        # allow_future=False only rejects future dates — past dates pass.
        v = DateValidator(allow_future=False)
        ok, _ = v.validate("2000-01-01T00:00:00")
        assert ok

    def test_is_valid_convenience(self) -> None:
        v = DateValidator()
        assert v.is_valid("2099-06-15T12:00:00+00:00")
        assert not v.is_valid("rubbish")


# ── URLValidator ──────────────────────────────────────────────────────────────


class TestURLValidator:
    def test_valid_https(self) -> None:
        v = URLValidator()
        ok, _ = v.validate("https://api.example.com/v1/endpoint")
        assert ok

    def test_http_blocked_by_default(self) -> None:
        v = URLValidator()
        ok, reason = v.validate("http://api.example.com/v1/endpoint")
        assert not ok
        assert "http" in reason.lower()

    def test_http_allowed_when_configured(self) -> None:
        v = URLValidator(allowed_schemes=frozenset({"http", "https"}))
        ok, _ = v.validate("http://internal.corp/health")
        assert ok

    def test_blocked_domain(self) -> None:
        v = URLValidator(blocked_domains=frozenset({"evil.com"}))
        ok, reason = v.validate("https://evil.com/payload")
        assert not ok
        assert "blocklist" in reason

    def test_blocked_subdomain(self) -> None:
        v = URLValidator(blocked_domains=frozenset({"evil.com"}))
        ok, reason = v.validate("https://sub.evil.com/path")
        assert not ok
        assert "blocklist" in reason

    def test_allowed_domains_enforce_allowlist(self) -> None:
        v = URLValidator(allowed_domains=frozenset({"trusted.com"}))
        ok, _ = v.validate("https://api.trusted.com/data")
        assert ok
        ok2, reason = v.validate("https://other.com/data")
        assert not ok2
        assert "allowlist" in reason

    def test_require_path(self) -> None:
        v = URLValidator(require_path=True)
        ok, reason = v.validate("https://example.com/")
        assert not ok
        assert "path" in reason
        ok2, _ = v.validate("https://example.com/api/v1")
        assert ok2

    def test_missing_scheme(self) -> None:
        v = URLValidator()
        ok, reason = v.validate("//example.com/path")
        assert not ok
        assert "scheme" in reason

    def test_is_valid(self) -> None:
        v = URLValidator()
        assert v.is_valid("https://safe.example.com/api")
        assert not v.is_valid("ftp://unsafe.com")


# ── EmailValidator ────────────────────────────────────────────────────────────


class TestEmailValidator:
    @pytest.fixture(autouse=True)
    def skip_without_re2(self) -> None:
        pytest.importorskip("re2", reason="google-re2 required for EmailValidator")

    def test_valid_email(self) -> None:
        v = EmailValidator()
        ok, _ = v.validate("alice@example.com")
        assert ok

    def test_valid_email_with_plus(self) -> None:
        v = EmailValidator()
        ok, _ = v.validate("alice+tag@sub.example.co.uk")
        assert ok

    def test_missing_at(self) -> None:
        v = EmailValidator()
        ok, reason = v.validate("noemail")
        assert not ok
        assert "@" in reason

    def test_empty_string(self) -> None:
        v = EmailValidator()
        ok, _ = v.validate("")
        assert not ok

    def test_invalid_domain(self) -> None:
        v = EmailValidator()
        ok, _ = v.validate("user@")
        assert not ok

    def test_local_part_too_long(self) -> None:
        v = EmailValidator()
        long_local = "a" * 65
        ok, reason = v.validate(f"{long_local}@example.com")
        assert not ok
        assert "64" in reason

    def test_is_valid_convenience(self) -> None:
        v = EmailValidator()
        assert v.is_valid("support@pramanix.dev")
        assert not v.is_valid("bad@")


# ── JSONSchemaValidator ───────────────────────────────────────────────────────


class TestJSONSchemaValidator:
    def test_valid_dict(self) -> None:
        v = JSONSchemaValidator(
            schema={"type": "object", "required": ["amount"], "properties": {"amount": {"type": "number"}}}
        )
        ok, _ = v.validate({"amount": 100})
        assert ok

    def test_missing_required_field(self) -> None:
        v = JSONSchemaValidator(schema={"type": "object", "required": ["amount", "currency"]})
        ok, reason = v.validate({"amount": 100})
        assert not ok
        assert "currency" in reason or "required" in reason.lower()

    def test_json_string_input(self) -> None:
        v = JSONSchemaValidator(schema={"type": "object", "required": ["x"]})
        ok, _ = v.validate('{"x": 1}')
        assert ok

    def test_invalid_json_string(self) -> None:
        v = JSONSchemaValidator(schema={})
        ok, reason = v.validate("{not valid json}")
        assert not ok
        assert "JSON" in reason

    def test_wrong_top_level_type(self) -> None:
        v = JSONSchemaValidator(schema={"type": "object"})
        ok, reason = v.validate([1, 2, 3])
        assert not ok

    def test_is_valid(self) -> None:
        v = JSONSchemaValidator(schema={"type": "object", "required": ["x"]})
        assert v.is_valid({"x": 1})
        assert not v.is_valid({})

    def test_empty_schema_accepts_anything(self) -> None:
        v = JSONSchemaValidator(schema={})
        ok, _ = v.validate({"any": "data"})
        assert ok


# ── ProfanityDetector ─────────────────────────────────────────────────────────


class TestProfanityDetector:
    def test_detects_profanity(self) -> None:
        d = ProfanityDetector()
        assert d.is_profane("What the fuck is this")

    def test_clean_text(self) -> None:
        d = ProfanityDetector()
        assert not d.is_profane("The quick brown fox jumped over the lazy dog")

    def test_no_false_positive_substring(self) -> None:
        # "classic" contains "ass" but should NOT be flagged
        d = ProfanityDetector()
        assert not d.is_profane("classic architecture")

    def test_detect_returns_list(self) -> None:
        d = ProfanityDetector()
        found = d.detect("shit and fuck")
        assert "shit" in found
        assert "fuck" in found

    def test_censor_replaces_words(self) -> None:
        d = ProfanityDetector()
        result = d.censor("What the shit!", replacement="***")
        assert "***" in result
        assert "shit" not in result

    def test_extra_words(self) -> None:
        d = ProfanityDetector(extra_words=["badword"])
        assert d.is_profane("this is a badword")
        assert not d.is_profane("this is fine")

    def test_case_insensitive_by_default(self) -> None:
        d = ProfanityDetector()
        assert d.is_profane("WHAT THE FUCK")
        assert d.is_profane("Shit happens")

    def test_case_sensitive_mode(self) -> None:
        d = ProfanityDetector(case_sensitive=True)
        # lowercase "fuck" should still match
        assert d.is_profane("fuck this")
        # UPPERCASE alone won't match lowercase patterns
        assert not d.is_profane("FUCK this")

    def test_censor_does_not_affect_clean_words(self) -> None:
        d = ProfanityDetector()
        result = d.censor("Classic architecture is great")
        assert "Classic" in result
        assert "architecture" in result
