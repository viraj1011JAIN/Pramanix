# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Adversarial tests — field length and value boundary overflow.

These tests verify Layer 3 of Pramanix's 5-layer prompt-injection defence:
*Pydantic strict schema validation* — any LLM output that violates field
bounds (``le``, ``gt``, ``min_length``, ``max_length``) is always rejected
with :exc:`~pramanix.exceptions.ExtractionFailureError`, never reaching the
Z3 solver.

Overflow vectors covered:
  P  ``recipient`` length exceeds ``max_length=64`` → Pydantic rejects
  Q  ``recipient`` is empty string → ``min_length=1`` rejects
  R  ``amount`` exactly at upper boundary (``le=1_000_000``) → allowed
  S  ``amount`` one unit above upper boundary → Pydantic rejects
  T  ``amount`` is zero (``gt=0`` requires strictly positive) → blocked
  U  ``amount`` is a very large integer string → Pydantic rejects
  V  ``amount`` is float string with extreme precision → normalised by Decimal
  W  All fields simultaneously at max valid values → allowed
  X  Extra unexpected field injected alongside valid fields → silently ignored
"""
from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest
from pydantic import BaseModel
from pydantic import Field as PydanticField

from pramanix.exceptions import ExtractionFailureError
from pramanix.translator.redundant import extract_with_consensus

# ── Shared schema ─────────────────────────────────────────────────────────────


class TransferIntent(BaseModel):
    amount: Decimal = PydanticField(gt=0, le=Decimal("1_000_000"))
    recipient: str = PydanticField(min_length=1, max_length=64)


def _pair(amount: str, recipient: str):
    """Construct a matching pair of stub translators."""

    class _T:
        def __init__(self, name: str) -> None:
            self.model = name

        async def extract(self, text, intent_schema, context=None) -> dict[str, Any]:
            return {"amount": amount, "recipient": recipient}

    return _T("stub-a"), _T("stub-b")


def _pair_extra(amount: str, recipient: str, **extra: Any):
    """Stub translators that include extra fields in their output."""

    class _T:
        def __init__(self, name: str) -> None:
            self.model = name

        async def extract(self, text, intent_schema, context=None) -> dict[str, Any]:
            return {"amount": amount, "recipient": recipient, **extra}

    return _T("stub-a"), _T("stub-b")


# ── P: recipient max_length overflow ─────────────────────────────────────────


class TestRecipientLengthOverflow:
    @pytest.mark.asyncio
    async def test_P_recipient_exceeds_max_length_is_blocked(self) -> None:
        """recipient string longer than max_length=64 → ExtractionFailureError."""
        long_recipient = "a" * 65  # one byte over the limit
        a, b = _pair("50", long_recipient)
        with pytest.raises(ExtractionFailureError, match="Schema validation failed"):
            await extract_with_consensus("send 50 to aaaa…", TransferIntent, (a, b))

    @pytest.mark.asyncio
    async def test_recipient_at_max_length_boundary_is_allowed(self) -> None:
        """recipient string exactly 64 chars → passes Pydantic → allowed."""
        exact_length = "b" * 64
        a, b = _pair("50", exact_length)
        result = await extract_with_consensus("send 50 to bbbb…", TransferIntent, (a, b))
        assert len(result["recipient"]) == 64

    @pytest.mark.asyncio
    async def test_Q_empty_recipient_is_blocked(self) -> None:
        """Empty recipient violates min_length=1 → ExtractionFailureError."""
        a, b = _pair("50", "")
        with pytest.raises(ExtractionFailureError, match="Schema validation failed"):
            await extract_with_consensus("send 50", TransferIntent, (a, b))

    @pytest.mark.asyncio
    async def test_very_long_recipient_1kb(self) -> None:
        """1 KB recipient is far beyond max_length=64 → always blocked."""
        kb_recipient = "x" * 1024
        a, b = _pair("100", kb_recipient)
        with pytest.raises(ExtractionFailureError):
            await extract_with_consensus("transfer 100 dollars", TransferIntent, (a, b))


# ── R/S: amount at and above upper boundary ───────────────────────────────────


class TestAmountBoundaryOverflow:
    @pytest.mark.asyncio
    async def test_R_amount_exactly_at_le_boundary_is_allowed(self) -> None:
        """amount == 1_000_000 satisfies le=1_000_000 → allowed."""
        a, b = _pair("1000000", "alice")
        result = await extract_with_consensus("transfer one million", TransferIntent, (a, b))
        assert result["amount"] == Decimal("1000000")

    @pytest.mark.asyncio
    async def test_S_amount_one_above_le_boundary_is_blocked(self) -> None:
        """amount == 1_000_001 violates le=1_000_000 → ExtractionFailureError."""
        a, b = _pair("1000001", "alice")
        with pytest.raises(ExtractionFailureError, match="Schema validation failed"):
            await extract_with_consensus("transfer 1000001 dollars", TransferIntent, (a, b))

    @pytest.mark.asyncio
    async def test_T_zero_amount_violates_gt_zero(self) -> None:
        """amount == 0 violates gt=0 → ExtractionFailureError."""
        a, b = _pair("0", "alice")
        with pytest.raises(ExtractionFailureError, match="Schema validation failed"):
            await extract_with_consensus("transfer zero dollars", TransferIntent, (a, b))

    @pytest.mark.asyncio
    async def test_U_astronomically_large_amount_is_blocked(self) -> None:
        """10^30 is far above le=1_000_000 → ExtractionFailureError."""
        a, b = _pair("1" + "0" * 30, "alice")
        with pytest.raises(ExtractionFailureError):
            await extract_with_consensus("transfer all the money", TransferIntent, (a, b))

    @pytest.mark.asyncio
    async def test_V_high_precision_decimal_within_bounds_is_normalised(self) -> None:
        """amount with many decimal places (but in bounds) is accepted.
        Decimal handles arbitrary precision correctly."""
        # 0.0000000001 is > 0 and <= 1_000_000 → valid
        a, b = _pair("0.0000000001", "alice")
        result = await extract_with_consensus("send a tiny fraction", TransferIntent, (a, b))
        assert result["amount"] == Decimal("0.0000000001")
        assert result["amount"] > 0


# ── W/X: boundary combination and extra fields ────────────────────────────────


class TestCombinedBoundaryAndExtraFields:
    @pytest.mark.asyncio
    async def test_W_all_fields_at_max_valid_values(self) -> None:
        """Both fields simultaneously at their maximum valid values → allowed."""
        max_recipient = "z" * 64
        a, b = _pair("1000000", max_recipient)
        result = await extract_with_consensus("max transfer", TransferIntent, (a, b))
        assert result["amount"] == Decimal("1000000")
        assert len(result["recipient"]) == 64

    @pytest.mark.asyncio
    async def test_X_extra_injected_field_is_silently_ignored(self) -> None:
        """LLM injects an unexpected field ('evil': true) — Pydantic ignores it."""
        a, b = _pair_extra("50", "alice", evil=True, admin_override="yes")
        result = await extract_with_consensus("send 50 to alice", TransferIntent, (a, b))
        # Only the declared fields should be present
        assert set(result.keys()) == {"amount", "recipient"}
        assert "evil" not in result
        assert "admin_override" not in result

    @pytest.mark.asyncio
    async def test_type_coercion_string_to_decimal(self) -> None:
        """Pydantic coerces string '50' to Decimal(50) — expected behaviour."""
        a, b = _pair("50", "alice")
        result = await extract_with_consensus("send fifty dollars to alice", TransferIntent, (a, b))
        assert isinstance(result["amount"], Decimal)
        assert result["amount"] == Decimal("50")

    @pytest.mark.asyncio
    async def test_amount_negative_sub_penny_float_blocked(self) -> None:
        """Negative sub-penny amount violates gt=0 → always blocked."""
        a, b = _pair("-0.001", "alice")
        with pytest.raises(ExtractionFailureError):
            await extract_with_consensus(
                "deduct a tiny fraction from alice", TransferIntent, (a, b)
            )
