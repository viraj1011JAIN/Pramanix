# SPDX-License-Identifier: AGPL-3.0-only
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
# Phase D-1: Tests for ConsensusStrictness semantic comparison
"""Unit tests for semantic consensus comparison in RedundantTranslator."""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import BaseModel

from pramanix.exceptions import ExtractionMismatchError
from pramanix.translator.redundant import (
    ConsensusStrictness,
    _enforce_consensus,
    _semantic_equal,
    _semantic_field_equal,
)

# ── Shared schema fixtures ────────────────────────────────────────────────────


class TransferIntent(BaseModel):
    amount: float
    currency: str
    recipient_id: str
    approved: bool


# ── _semantic_field_equal unit tests ─────────────────────────────────────────


class TestSemanticFieldEqual:
    def test_numeric_500_vs_500_dot_0_agrees(self) -> None:
        """'500' and '500.0' must agree under SEMANTIC mode (Decimal normalisation)."""
        assert _semantic_field_equal("500", "500.0") is True

    def test_numeric_500_vs_600_disagrees(self) -> None:
        """'500' and '600' must disagree — they represent different amounts."""
        assert _semantic_field_equal("500", "600") is False

    def test_numeric_scientific_notation_agrees(self) -> None:
        """'5.0E+2' and '500' must agree."""
        assert _semantic_field_equal("5.0E+2", "500") is True

    def test_int_vs_float_agrees(self) -> None:
        """int 500 vs float 500.0 must agree."""
        assert _semantic_field_equal(500, 500.0) is True

    def test_string_case_insensitive_agrees(self) -> None:
        """'USD' and 'usd' must agree under SEMANTIC mode (casefold)."""
        assert (
            _semantic_field_equal("USD", "usd", schema=TransferIntent, field_name="currency")
            is True
        )

    def test_string_different_values_disagrees(self) -> None:
        """'USD' and 'EUR' must disagree."""
        assert (
            _semantic_field_equal("USD", "EUR", schema=TransferIntent, field_name="currency")
            is False
        )

    def test_string_whitespace_trimmed(self) -> None:
        """'  USD  ' and 'usd' must agree after strip + casefold."""
        assert (
            _semantic_field_equal("  USD  ", "usd", schema=TransferIntent, field_name="currency")
            is True
        )

    def test_bool_true_vs_true_agrees(self) -> None:
        """bool True vs True must agree."""
        assert _semantic_field_equal(True, True) is True

    def test_bool_true_vs_false_disagrees(self) -> None:
        """bool True vs False must disagree."""
        assert _semantic_field_equal(True, False) is False

    def test_both_none_agrees(self) -> None:
        """None vs None must agree."""
        assert _semantic_field_equal(None, None) is True

    def test_none_vs_value_disagrees(self) -> None:
        """None vs a non-None value must disagree."""
        assert _semantic_field_equal(None, "hello") is False


# ── _semantic_equal dict comparison tests ────────────────────────────────────


class TestSemanticEqual:
    def test_identical_dicts_agree(self) -> None:
        a = {"amount": 500, "currency": "USD"}
        b = {"amount": 500, "currency": "USD"}
        all_equal, disagreeing = _semantic_equal(a, b, TransferIntent)
        assert all_equal is True
        assert disagreeing == []

    def test_numeric_string_variants_agree(self) -> None:
        a = {"amount": "500", "currency": "USD"}
        b = {"amount": "500.0", "currency": "USD"}
        all_equal, _disagreeing = _semantic_equal(a, b, TransferIntent)
        assert all_equal is True

    def test_disagreeing_fields_listed(self) -> None:
        a = {"amount": "500", "currency": "USD"}
        b = {"amount": "600", "currency": "EUR"}
        all_equal, disagreeing = _semantic_equal(a, b, TransferIntent)
        assert all_equal is False
        assert "amount" in disagreeing
        assert "currency" in disagreeing


# ── _enforce_consensus SEMANTIC vs STRICT tests ───────────────────────────────


class TestEnforceConsensus:
    def test_numeric_500_vs_500_dot_0_agrees_in_semantic_mode(self) -> None:
        """SEMANTIC mode: '500' vs '500.0' should NOT raise ExtractionMismatchError."""
        dump_a = {"amount": "500", "currency": "USD", "recipient_id": "acct-1", "approved": True}
        dump_b = {"amount": "500.0", "currency": "USD", "recipient_id": "acct-1", "approved": True}
        # Must NOT raise
        _enforce_consensus(
            dump_a,
            dump_b,
            model_a_name="gpt-4o",
            model_b_name="claude-3",
            agreement_mode="strict_keys",
            critical_fields=None,
            strictness=ConsensusStrictness.SEMANTIC,
            schema=TransferIntent,
        )

    def test_numeric_500_vs_500_dot_0_disagrees_in_strict_mode(self) -> None:
        """STRICT mode: '500' vs '500.0' MUST raise ExtractionMismatchError."""
        dump_a = {"amount": "500", "currency": "USD", "recipient_id": "acct-1", "approved": True}
        dump_b = {"amount": "500.0", "currency": "USD", "recipient_id": "acct-1", "approved": True}
        with pytest.raises(ExtractionMismatchError) as exc_info:
            _enforce_consensus(
                dump_a,
                dump_b,
                model_a_name="gpt-4o",
                model_b_name="claude-3",
                agreement_mode="strict_keys",
                critical_fields=None,
                strictness=ConsensusStrictness.STRICT,
                schema=TransferIntent,
            )
        assert "amount" in str(exc_info.value)

    def test_genuinely_different_values_raise_in_semantic_mode(self) -> None:
        """SEMANTIC mode: amount 500 vs 600 must still raise ExtractionMismatchError."""
        dump_a = {"amount": 500, "currency": "USD", "recipient_id": "acct-1", "approved": True}
        dump_b = {"amount": 600, "currency": "USD", "recipient_id": "acct-1", "approved": True}
        with pytest.raises(ExtractionMismatchError):
            _enforce_consensus(
                dump_a,
                dump_b,
                model_a_name="gpt-4o",
                model_b_name="claude-3",
                agreement_mode="strict_keys",
                critical_fields=None,
                strictness=ConsensusStrictness.SEMANTIC,
                schema=TransferIntent,
            )

    def test_disagreeing_fields_listed_in_error(self) -> None:
        """ExtractionMismatchError.disagreeing_fields lists the offending keys."""
        dump_a = {"amount": 500, "currency": "USD", "recipient_id": "acct-1", "approved": True}
        dump_b = {"amount": 999, "currency": "EUR", "recipient_id": "acct-1", "approved": True}
        with pytest.raises(ExtractionMismatchError) as exc_info:
            _enforce_consensus(
                dump_a,
                dump_b,
                model_a_name="gpt-4o",
                model_b_name="claude-3",
                agreement_mode="strict_keys",
                critical_fields=None,
                strictness=ConsensusStrictness.SEMANTIC,
                schema=TransferIntent,
            )
        err = exc_info.value
        assert "amount" in err.disagreeing_fields
        assert "currency" in err.disagreeing_fields
        assert "recipient_id" not in err.disagreeing_fields

    def test_strict_mode_still_available(self) -> None:
        """ConsensusStrictness.STRICT must remain accessible and functional."""
        assert ConsensusStrictness.STRICT.value == "strict"
        dump_a = {"amount": 42, "currency": "USD", "recipient_id": "x", "approved": True}
        dump_b = {"amount": 42, "currency": "USD", "recipient_id": "x", "approved": True}
        # Identical dicts — STRICT mode must pass without raising
        _enforce_consensus(
            dump_a,
            dump_b,
            model_a_name="m1",
            model_b_name="m2",
            agreement_mode="strict_keys",
            critical_fields=None,
            strictness=ConsensusStrictness.STRICT,
        )


# ── _semantic_field_equal boundary-string tests (§5 fix #35) ─────────────────


class TestSemanticFieldEqualBoundaryStrings:
    """IEEE 754 special values, non-ASCII numerals, and edge-case string inputs.

    Every case must return a consistent bool — never raise — regardless of
    whether the Decimal conversion branch, the JSON-equivalence branch, or
    the casefold fallback is taken.
    """

    # ── NaN semantics (IEEE 754: NaN ≠ NaN) ──────────────────────────────────

    def test_nan_vs_nan_is_false(self) -> None:
        """Decimal('NaN') == Decimal('NaN') is False per IEEE 754."""
        assert _semantic_field_equal("NaN", "NaN") is False

    def test_nan_vs_numeric_is_false(self) -> None:
        assert _semantic_field_equal("NaN", "1.0") is False

    def test_numeric_vs_nan_is_false(self) -> None:
        assert _semantic_field_equal("1.0", "NaN") is False

    # ── Infinity strings ──────────────────────────────────────────────────────

    def test_pos_inf_vs_pos_inf_is_true(self) -> None:
        """+inf parses to Decimal('Infinity'); same vs same → True."""
        assert _semantic_field_equal("+inf", "+inf") is True

    def test_neg_inf_vs_neg_inf_is_true(self) -> None:
        assert _semantic_field_equal("-inf", "-inf") is True

    def test_pos_inf_vs_neg_inf_is_false(self) -> None:
        assert _semantic_field_equal("+inf", "-inf") is False

    # ── Very-large exponent (overflow to Decimal, not float) ─────────────────

    def test_1e999_vs_1e999_is_true(self) -> None:
        """1e999 stays exact in Decimal (no float overflow); same vs same → True."""
        assert _semantic_field_equal("1e999", "1e999") is True

    def test_1e999_vs_1e998_is_false(self) -> None:
        assert _semantic_field_equal("1e999", "1e998") is False

    # ── Non-ASCII numeral scripts (Arabic-Indic) ──────────────────────────────

    def test_arabic_indic_same_vs_same_is_true(self) -> None:
        """Arabic-Indic '١٢٣' fails Decimal conversion; casefold fallback → True."""
        assert _semantic_field_equal("١٢٣", "١٢٣") is True

    def test_arabic_indic_vs_ascii_is_true(self) -> None:
        """Decimal converts Arabic-Indic digits to ASCII; '١٢٣' == '123' → True."""
        assert _semantic_field_equal("١٢٣", "123") is True

    # ── Vulgar-fraction character ─────────────────────────────────────────────

    def test_half_fraction_same_vs_same_is_true(self) -> None:
        """'½' fails Decimal conversion; casefold fallback → True."""
        assert _semantic_field_equal("½", "½") is True

    def test_half_fraction_vs_decimal_is_false(self) -> None:
        """'½' and '0.5' are in different branches → False (casefold != Decimal)."""
        assert _semantic_field_equal("½", "0.5") is False

    # ── Python underscore numeric syntax ──────────────────────────────────────

    def test_underscore_same_vs_same_is_true(self) -> None:
        """'1_000_000' fails Decimal; casefold fallback → True."""
        assert _semantic_field_equal("1_000_000", "1_000_000") is True

    def test_underscore_vs_plain_is_true(self) -> None:
        """Decimal strips underscores; '1_000_000' == '1000000' → True."""
        assert _semantic_field_equal("1_000_000", "1000000") is True

    # ── None cast to string ───────────────────────────────────────────────────

    def test_str_none_vs_str_none_is_true(self) -> None:
        """str(None) == 'None'; casefold fallback → True. Does not raise."""
        assert _semantic_field_equal(str(None), str(None)) is True

    def test_actual_none_vs_str_none_is_false(self) -> None:
        """Actual None vs the string 'None' must disagree (None-guard fires first)."""
        assert _semantic_field_equal(None, "None") is False

    def test_str_none_vs_actual_none_is_false(self) -> None:
        assert _semantic_field_equal("None", None) is False

    # ── No exception contract ─────────────────────────────────────────────────

    def test_boundary_inputs_never_raise(self) -> None:
        """All boundary-string inputs must return bool without raising."""
        pairs = [
            ("NaN", "NaN"),
            ("NaN", "1.0"),
            ("+inf", "+inf"),
            ("-inf", "-inf"),
            ("+inf", "-inf"),
            ("1e999", "1e999"),
            ("1e999", "1e998"),
            ("١٢٣", "١٢٣"),
            ("١٢٣", "123"),
            ("½", "½"),
            ("½", "0.5"),
            ("1_000_000", "1_000_000"),
            ("1_000_000", "1000000"),
            (str(None), str(None)),
        ]
        for a, b in pairs:
            result = _semantic_field_equal(a, b)
            assert isinstance(result, bool), f"Expected bool for ({a!r}, {b!r}), got {type(result)}"

    # ── Symmetry contract ─────────────────────────────────────────────────────

    def test_boundary_inputs_are_symmetric(self) -> None:
        """_semantic_field_equal(a, b) == _semantic_field_equal(b, a) for all pairs."""
        pairs = [
            ("NaN", "NaN"),
            ("NaN", "1.0"),
            ("+inf", "+inf"),
            ("-inf", "-inf"),
            ("+inf", "-inf"),
            ("1e999", "1e999"),
            ("1e999", "1e998"),
            ("١٢٣", "١٢٣"),
            ("١٢٣", "123"),
            ("½", "½"),
            ("½", "0.5"),
            ("1_000_000", "1_000_000"),
            ("1_000_000", "1000000"),
            (str(None), str(None)),
        ]
        for a, b in pairs:
            assert _semantic_field_equal(a, b) == _semantic_field_equal(
                b, a
            ), f"Asymmetry: ({a!r}, {b!r})"


# ── Hypothesis property tests ─────────────────────────────────────────────────


class TestSemanticFieldEqualProperties:
    """Hypothesis-driven properties that must hold for all string inputs."""

    @given(st.text(), st.text())
    @settings(max_examples=500)
    def test_never_raises_for_arbitrary_strings(self, a: str, b: str) -> None:
        """_semantic_field_equal must never raise for any pair of string inputs."""
        result = _semantic_field_equal(a, b)
        assert isinstance(result, bool)

    @given(st.text())
    @settings(max_examples=300)
    def test_reflexive_for_same_string(self, s: str) -> None:
        """_semantic_field_equal(s, s) must be True for any non-NaN string.

        NaN is the only standard exception: Decimal('NaN') != Decimal('NaN').
        For all other strings, the function must agree with itself.
        """
        from decimal import Decimal, InvalidOperation

        try:
            d = Decimal(s.strip())
            is_nan = d.is_nan()
        except InvalidOperation:
            is_nan = False

        result = _semantic_field_equal(s, s)
        assert isinstance(result, bool)
        if not is_nan:
            assert result is True, f"Expected True for ({s!r}, {s!r}), got False"

    @given(st.text(), st.text())
    @settings(max_examples=500)
    def test_symmetric_for_arbitrary_strings(self, a: str, b: str) -> None:
        """_semantic_field_equal(a, b) == _semantic_field_equal(b, a) always."""
        assert _semantic_field_equal(a, b) == _semantic_field_equal(b, a)
