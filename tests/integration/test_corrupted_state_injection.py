# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Non-numeric / corrupted state injection tests — P2.3.

Guards the fail-closed invariant: any state value that cannot be coerced to
its declared Z3 sort must produce a BLOCK Decision, never an ALLOW.

What this validates beyond unit tests (test_solver.py covers FieldTypeError
at the solver level — these test the full Guard.verify() pipeline):
- ``guard.verify()`` wraps FieldTypeError in Decision.error(), not an exception
- Corrupted string values produce BLOCK, not crash
- None values produce BLOCK, not crash
- float inf/nan produce BLOCK, not crash
- Corrupted intent fields produce BLOCK (ValidationError path)
- Each BLOCK carries a non-empty reason string (no silent no-op)
- ``decision.allowed`` is False for every injected corrupted value
"""

from __future__ import annotations

import math
from decimal import Decimal

import pytest
from pydantic import BaseModel

from pramanix import Decision, E, Field, Guard, GuardConfig, Policy, SolverStatus

# ═══════════════════════════════════════════════════════════════════════════════
# Minimal policy — two Real fields so we can corrupt either
# ═══════════════════════════════════════════════════════════════════════════════


class _Intent(BaseModel):
    amount: Decimal


class _State(BaseModel):
    state_version: str
    balance: Decimal
    daily_limit: Decimal


class _CorruptionPolicy(Policy):
    class Meta:
        version = "1.0"
        intent_model = _Intent
        state_model = _State

    amount = Field("amount", Decimal, "Real")
    balance = Field("balance", Decimal, "Real")
    daily_limit = Field("daily_limit", Decimal, "Real")

    @classmethod
    def invariants(cls) -> list[object]:  # type: ignore[override,unused-ignore]
        return [
            (E(cls.balance) - E(cls.amount) >= 0)
            .named("non_negative_balance")
            .explain("balance={balance} amount={amount}"),
            (E(cls.amount) <= E(cls.daily_limit))
            .named("within_daily_limit")
            .explain("amount={amount} daily_limit={daily_limit}"),
        ]


@pytest.fixture(scope="module")
def guard() -> Guard:
    return Guard(_CorruptionPolicy, config=GuardConfig(solver_timeout_ms=5_000))


def _ok_state(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "balance": Decimal("1000"),
        "daily_limit": Decimal("5000"),
        "state_version": "1.0",
    }
    base.update(overrides)
    return base


def _ok_intent(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {"amount": Decimal("100")}
    base.update(overrides)
    return base


# ═══════════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════════


def _assert_blocked(decision: Decision) -> None:
    assert decision.allowed is False, f"Expected BLOCK, got ALLOW: {decision}"
    assert decision.reason, "BLOCK decision must carry a non-empty reason"


# ═══════════════════════════════════════════════════════════════════════════════
# Corrupted state-field values
# ═══════════════════════════════════════════════════════════════════════════════


class TestCorruptedStateBalance:
    """balance field receives non-Decimal values — must BLOCK, not crash."""

    def test_string_corrupted_balance(self, guard: Guard) -> None:
        """Literal string 'CORRUPTED' where Decimal expected → BLOCK."""
        d = guard.verify(_ok_intent(), _ok_state(balance="CORRUPTED"))
        _assert_blocked(d)

    def test_none_balance(self, guard: Guard) -> None:
        """None where Decimal expected → BLOCK."""
        d = guard.verify(_ok_intent(), _ok_state(balance=None))
        _assert_blocked(d)

    def test_list_balance(self, guard: Guard) -> None:
        """list where Decimal expected → BLOCK."""
        d = guard.verify(_ok_intent(), _ok_state(balance=[100, 200]))
        _assert_blocked(d)

    def test_dict_balance(self, guard: Guard) -> None:
        """dict where Decimal expected → BLOCK."""
        d = guard.verify(_ok_intent(), _ok_state(balance={"value": 100}))
        _assert_blocked(d)

    def test_inf_balance(self, guard: Guard) -> None:
        """float infinity where Decimal expected → BLOCK (not silently coerced)."""
        d = guard.verify(_ok_intent(), _ok_state(balance=math.inf))
        _assert_blocked(d)

    def test_nan_balance(self, guard: Guard) -> None:
        """float NaN where Decimal expected → BLOCK."""
        d = guard.verify(_ok_intent(), _ok_state(balance=math.nan))
        _assert_blocked(d)

    def test_bool_balance(self, guard: Guard) -> None:
        """bool where Real-sorted Decimal expected → BLOCK (Law: bool not numeric)."""
        d = guard.verify(_ok_intent(), _ok_state(balance=True))
        _assert_blocked(d)


class TestCorruptedStateDailyLimit:
    """daily_limit field receives non-Decimal values — must BLOCK, not crash."""

    def test_string_corrupted_daily_limit(self, guard: Guard) -> None:
        d = guard.verify(_ok_intent(), _ok_state(daily_limit="UNLIMITED"))
        _assert_blocked(d)

    def test_none_daily_limit(self, guard: Guard) -> None:
        d = guard.verify(_ok_intent(), _ok_state(daily_limit=None))
        _assert_blocked(d)

    def test_negative_inf_daily_limit(self, guard: Guard) -> None:
        d = guard.verify(_ok_intent(), _ok_state(daily_limit=-math.inf))
        _assert_blocked(d)


# ═══════════════════════════════════════════════════════════════════════════════
# Corrupted intent-field values
# ═══════════════════════════════════════════════════════════════════════════════


class TestCorruptedIntentAmount:
    """amount field (from intent) receives non-Decimal values — must BLOCK."""

    def test_string_amount(self, guard: Guard) -> None:
        d = guard.verify(_ok_intent(amount="INJECT"), _ok_state())
        _assert_blocked(d)

    def test_none_amount(self, guard: Guard) -> None:
        d = guard.verify(_ok_intent(amount=None), _ok_state())
        _assert_blocked(d)

    def test_inf_amount(self, guard: Guard) -> None:
        d = guard.verify(_ok_intent(amount=math.inf), _ok_state())
        _assert_blocked(d)


# ═══════════════════════════════════════════════════════════════════════════════
# Missing required fields
# ═══════════════════════════════════════════════════════════════════════════════


class TestMissingRequiredFields:
    """Missing required fields must BLOCK the verification, never silently skip."""

    def test_missing_balance_key(self, guard: Guard) -> None:
        """State dict without the 'balance' key → BLOCK."""
        state = {"daily_limit": Decimal("5000"), "state_version": "1.0"}
        d = guard.verify(_ok_intent(), state)
        _assert_blocked(d)

    def test_missing_amount_key(self, guard: Guard) -> None:
        """Intent dict without the 'amount' key → BLOCK."""
        d = guard.verify({}, _ok_state())
        _assert_blocked(d)

    def test_empty_state(self, guard: Guard) -> None:
        """Completely empty state dict → BLOCK."""
        d = guard.verify(_ok_intent(), {})
        _assert_blocked(d)

    def test_empty_intent_and_state(self, guard: Guard) -> None:
        """Both empty → BLOCK, not crash."""
        d = guard.verify({}, {})
        _assert_blocked(d)


# ═══════════════════════════════════════════════════════════════════════════════
# Status values for key corruption scenarios
# ═══════════════════════════════════════════════════════════════════════════════


class TestCorruptedDecisionStatus:
    """BLOCK decisions from corruption must carry a valid SolverStatus."""

    def test_status_not_safe_on_string_balance(self, guard: Guard) -> None:
        d = guard.verify(_ok_intent(), _ok_state(balance="CORRUPTED"))
        assert d.status is not SolverStatus.SAFE

    def test_status_not_safe_on_none_balance(self, guard: Guard) -> None:
        d = guard.verify(_ok_intent(), _ok_state(balance=None))
        assert d.status is not SolverStatus.SAFE
