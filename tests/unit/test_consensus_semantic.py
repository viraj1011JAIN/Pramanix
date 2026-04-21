# SPDX-License-Identifier: AGPL-3.0-only
# Phase D-1: Tests for ConsensusStrictness semantic comparison
"""Unit tests for semantic consensus comparison in RedundantTranslator."""
from __future__ import annotations

import pytest
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
        assert _semantic_field_equal("USD", "usd", schema=TransferIntent, field_name="currency") is True

    def test_string_different_values_disagrees(self) -> None:
        """'USD' and 'EUR' must disagree."""
        assert _semantic_field_equal("USD", "EUR", schema=TransferIntent, field_name="currency") is False

    def test_string_whitespace_trimmed(self) -> None:
        """'  USD  ' and 'usd' must agree after strip + casefold."""
        assert _semantic_field_equal("  USD  ", "usd") is True

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
        all_equal, disagreeing = _semantic_equal(a, b, TransferIntent)
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
