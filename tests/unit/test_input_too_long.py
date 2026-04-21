# SPDX-License-Identifier: AGPL-3.0-only
# Phase D-3: Tests for InputTooLongError and sanitise_user_input length enforcement
"""Unit tests verifying that oversized inputs are rejected with InputTooLongError."""
from __future__ import annotations

import pytest

from pramanix import InputTooLongError
from pramanix.exceptions import InputTooLongError as ExceptionsInputTooLongError
from pramanix.guard_config import GuardConfig
from pramanix.translator._sanitise import sanitise_user_input


class TestInputTooLongErrorAttributes:
    def test_attributes_set_correctly(self) -> None:
        """Constructor sets actual, limit, truncated_preview."""
        err = InputTooLongError(actual=600, limit=512, truncated_preview="hello world")
        assert err.actual == 600
        assert err.limit == 512
        assert err.truncated_preview == "hello world"

    def test_message_includes_actual_and_limit(self) -> None:
        """Exception message contains both actual count and limit."""
        err = InputTooLongError(actual=999, limit=100, truncated_preview="foo")
        msg = str(err)
        assert "999" in msg
        assert "100" in msg

    def test_is_pramanix_error(self) -> None:
        """InputTooLongError is a PramanixError subclass."""
        from pramanix.exceptions import PramanixError
        err = InputTooLongError(actual=1, limit=1, truncated_preview="")
        assert isinstance(err, PramanixError)

    def test_same_class_exported_from_exceptions_and_public_api(self) -> None:
        """pramanix.InputTooLongError is identical to pramanix.exceptions.InputTooLongError."""
        assert InputTooLongError is ExceptionsInputTooLongError


class TestSanitiseUserInputLengthEnforcement:
    def test_exact_limit_passes(self) -> None:
        """Input of exactly max_length chars does NOT raise."""
        text = "a" * 512
        cleaned, warnings = sanitise_user_input(text, max_length=512)
        assert len(cleaned) == 512
        assert not any("truncated" in w for w in warnings)

    def test_one_over_limit_raises(self) -> None:
        """Input of max_length + 1 raises InputTooLongError."""
        text = "b" * 513
        with pytest.raises(InputTooLongError) as exc_info:
            sanitise_user_input(text, max_length=512)
        assert exc_info.value.actual == 513
        assert exc_info.value.limit == 512

    def test_preview_capped_at_100_chars(self) -> None:
        """truncated_preview is at most 100 characters."""
        text = "z" * 1000
        with pytest.raises(InputTooLongError) as exc_info:
            sanitise_user_input(text, max_length=512)
        assert len(exc_info.value.truncated_preview) == 100

    def test_preview_contains_beginning_of_input(self) -> None:
        """truncated_preview starts with the first chars of the input."""
        text = "ABCDEF" + "x" * 600
        with pytest.raises(InputTooLongError) as exc_info:
            sanitise_user_input(text, max_length=50)
        assert exc_info.value.truncated_preview.startswith("ABCDEF")

    def test_custom_max_length_respected(self) -> None:
        """max_length=10 rejects input of length 11."""
        with pytest.raises(InputTooLongError) as exc_info:
            sanitise_user_input("a" * 11, max_length=10)
        assert exc_info.value.actual == 11
        assert exc_info.value.limit == 10

    def test_short_input_not_affected(self) -> None:
        """Short inputs pass through normally."""
        cleaned, warnings = sanitise_user_input("hello", max_length=512)
        assert cleaned == "hello"

    def test_length_checked_after_nfkc_normalisation(self) -> None:
        """Length is measured after NFKC normalisation (full-width → ASCII)."""
        # Full-width letters NFKC-normalise to ASCII, so length is unchanged
        # (they are still 1 codepoint each). Verify the check applies post-norm.
        text = "\uff41" * 513  # U+FF41 = full-width 'a', NFKC → 'a' (same length)
        with pytest.raises(InputTooLongError):
            sanitise_user_input(text, max_length=512)

    def test_no_truncated_warning_in_returned_warnings(self) -> None:
        """The old 'input_truncated_to_N_chars' warning no longer appears."""
        # Input at exactly the limit should not produce a truncation warning
        cleaned, warnings = sanitise_user_input("x" * 100, max_length=100)
        assert not any("truncated" in w for w in warnings)


class TestGuardConfigMaxInputChars:
    def test_default_is_512(self) -> None:
        """GuardConfig.max_input_chars defaults to 512."""
        cfg = GuardConfig()
        assert cfg.max_input_chars == 512

    def test_custom_value_accepted(self) -> None:
        """GuardConfig accepts a custom max_input_chars."""
        cfg = GuardConfig(max_input_chars=1024)
        assert cfg.max_input_chars == 1024

    def test_zero_raises_configuration_error(self) -> None:
        """max_input_chars=0 raises ConfigurationError (must be positive)."""
        from pramanix.exceptions import ConfigurationError
        with pytest.raises(ConfigurationError):
            GuardConfig(max_input_chars=0)

    def test_negative_raises_configuration_error(self) -> None:
        """max_input_chars < 0 raises ConfigurationError."""
        from pramanix.exceptions import ConfigurationError
        with pytest.raises(ConfigurationError):
            GuardConfig(max_input_chars=-1)

    def test_env_var_sets_max_input_chars(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """PRAMANIX_MAX_INPUT_CHARS env var is picked up by GuardConfig()."""
        monkeypatch.setenv("PRAMANIX_MAX_INPUT_CHARS", "256")
        cfg = GuardConfig()
        assert cfg.max_input_chars == 256

    def test_invalid_env_var_falls_back_to_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Non-integer PRAMANIX_MAX_INPUT_CHARS falls back to 512."""
        monkeypatch.setenv("PRAMANIX_MAX_INPUT_CHARS", "not-a-number")
        cfg = GuardConfig()
        assert cfg.max_input_chars == 512
