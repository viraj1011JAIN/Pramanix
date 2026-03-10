# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Integration tests for the banking transfer flow — scenarios A through E.

These tests exercise the full guard.verify() pipeline end-to-end using real Z3
solving (no mocks). Each scenario corresponds to a named case from the banking
reference implementation.

Scenarios:
  A — Normal transfer (SAFE)
  B — Overdraft attempt (UNSAFE, non_negative_balance violated)
  C — Overdraft + frozen account (UNSAFE, two violations)
  D — Exact boundary: balance == amount (SAFE, border case)
  E — One cent over boundary: amount = balance + 0.01 (UNSAFE, exact decimal)

Additional integration scenarios:
  F — Stale state version (STALE_STATE)
  G — Validation failure: intent field has wrong type (VALIDATION_FAILURE)
  H — Daily limit exceeded (UNSAFE, within_daily_limit violated)
  I — All three invariants violated simultaneously (UNSAFE, three violations)
"""
from __future__ import annotations

from decimal import Decimal

import pytest
from pydantic import BaseModel

from pramanix import Decision, E, Field, Guard, GuardConfig, Policy, SolverStatus

# ═══════════════════════════════════════════════════════════════════════════════
# Pydantic models — intent and state schemas
# ═══════════════════════════════════════════════════════════════════════════════


class TransferIntent(BaseModel):
    """What the AI agent wants to do."""

    amount: Decimal


class AccountState(BaseModel):
    """Observable account state — must include state_version."""

    state_version: str
    balance: Decimal
    daily_limit: Decimal
    is_frozen: bool


# ═══════════════════════════════════════════════════════════════════════════════
# Policy definition
# ═══════════════════════════════════════════════════════════════════════════════


class BankingPolicy(Policy):
    """Three-invariant banking safety policy."""

    class Meta:
        version = "1.0"
        intent_model = TransferIntent
        state_model = AccountState

    amount = Field("amount", Decimal, "Real")
    balance = Field("balance", Decimal, "Real")
    daily_limit = Field("daily_limit", Decimal, "Real")
    is_frozen = Field("is_frozen", bool, "Bool")

    @classmethod
    def invariants(cls) -> list[object]:  # type: ignore[override,unused-ignore]
        return [
            (E(cls.balance) - E(cls.amount) >= 0)
            .named("non_negative_balance")
            .explain("Overdraft prevented: balance={balance} < amount={amount}"),
            (E(cls.amount) <= E(cls.daily_limit))
            .named("within_daily_limit")
            .explain("Daily limit exceeded: amount={amount} > daily_limit={daily_limit}"),
            (E(cls.is_frozen) == False)  # noqa: E712
            .named("account_not_frozen")
            .explain("Account is frozen — all transfers blocked"),
        ]


# ═══════════════════════════════════════════════════════════════════════════════
# Shared guard instance (constructed once, reused across all tests)
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.fixture(scope="module")
def guard() -> Guard:
    return Guard(BankingPolicy, config=GuardConfig(solver_timeout_ms=5_000))


# ═══════════════════════════════════════════════════════════════════════════════
# Helper
# ═══════════════════════════════════════════════════════════════════════════════


def _state(
    *,
    balance: str = "1000.00",
    daily_limit: str = "5000.00",
    is_frozen: bool = False,
    state_version: str = "1.0",
) -> dict[str, object]:
    return {
        "balance": Decimal(balance),
        "daily_limit": Decimal(daily_limit),
        "is_frozen": is_frozen,
        "state_version": state_version,
    }


def _intent(amount: str) -> dict[str, object]:
    return {"amount": Decimal(amount)}


# ═══════════════════════════════════════════════════════════════════════════════
# Scenario A — Normal transfer (SAFE)
# ═══════════════════════════════════════════════════════════════════════════════


class TestScenarioA:
    """A: 500 transfer from 1000 balance — all invariants pass."""

    @pytest.fixture()
    def decision(self, guard: Guard) -> Decision:
        return guard.verify(_intent("500.00"), _state())

    def test_allowed(self, decision: Decision) -> None:
        assert decision.allowed is True

    def test_status_safe(self, decision: Decision) -> None:
        assert decision.status is SolverStatus.SAFE

    def test_no_violations(self, decision: Decision) -> None:
        assert decision.violated_invariants == ()

    def test_explanation_empty(self, decision: Decision) -> None:
        assert decision.explanation == ""

    def test_decision_id_set(self, decision: Decision) -> None:
        import uuid

        uuid.UUID(decision.decision_id, version=4)  # must not raise

    def test_solver_time_populated(self, decision: Decision) -> None:
        assert decision.solver_time_ms >= 0.0

    def test_to_dict_json_serialisable(self, decision: Decision) -> None:
        import json

        json.dumps(decision.to_dict())  # must not raise


# ═══════════════════════════════════════════════════════════════════════════════
# Scenario B — Overdraft attempt (UNSAFE)
# ═══════════════════════════════════════════════════════════════════════════════


class TestScenarioB:
    """B: 1500 transfer from 1000 balance — non_negative_balance violated."""

    @pytest.fixture()
    def decision(self, guard: Guard) -> Decision:
        return guard.verify(_intent("1500.00"), _state(balance="1000.00"))

    def test_blocked(self, decision: Decision) -> None:
        assert decision.allowed is False

    def test_status_unsafe(self, decision: Decision) -> None:
        assert decision.status is SolverStatus.UNSAFE

    def test_non_negative_balance_violated(self, decision: Decision) -> None:
        assert "non_negative_balance" in decision.violated_invariants

    def test_within_daily_limit_not_violated(self, decision: Decision) -> None:
        assert "within_daily_limit" not in decision.violated_invariants

    def test_account_not_frozen_not_violated(self, decision: Decision) -> None:
        assert "account_not_frozen" not in decision.violated_invariants

    def test_explanation_mentions_balance_or_amount(self, decision: Decision) -> None:
        assert "1000" in decision.explanation or "1500" in decision.explanation

    def test_explanation_non_empty(self, decision: Decision) -> None:
        assert decision.explanation != ""


# ═══════════════════════════════════════════════════════════════════════════════
# Scenario C — Overdraft + frozen account (UNSAFE, two violations)
# ═══════════════════════════════════════════════════════════════════════════════


class TestScenarioC:
    """C: 2000 transfer from 1000 balance AND account frozen — two violations.

    This is the critical test for the per-invariant attribution design:
    a shared-solver unsat_core() would return only one label.
    The per-invariant design guarantees both are reported.
    """

    @pytest.fixture()
    def decision(self, guard: Guard) -> Decision:
        return guard.verify(
            _intent("2000.00"),
            _state(balance="1000.00", is_frozen=True),
        )

    def test_blocked(self, decision: Decision) -> None:
        assert decision.allowed is False

    def test_status_unsafe(self, decision: Decision) -> None:
        assert decision.status is SolverStatus.UNSAFE

    def test_overdraft_violation_reported(self, decision: Decision) -> None:
        assert "non_negative_balance" in decision.violated_invariants

    def test_frozen_violation_reported(self, decision: Decision) -> None:
        assert "account_not_frozen" in decision.violated_invariants

    def test_exactly_two_violations(self, decision: Decision) -> None:
        assert len(decision.violated_invariants) == 2

    def test_daily_limit_not_violated(self, decision: Decision) -> None:
        assert "within_daily_limit" not in decision.violated_invariants


# ═══════════════════════════════════════════════════════════════════════════════
# Scenario D — Exact boundary: balance == amount (SAFE)
# ═══════════════════════════════════════════════════════════════════════════════


class TestScenarioD:
    """D: amount == balance — invariant is `balance - amount >= 0`, so exactly 0 is SAT."""

    @pytest.fixture()
    def decision(self, guard: Guard) -> Decision:
        return guard.verify(_intent("1000.00"), _state(balance="1000.00"))

    def test_allowed(self, decision: Decision) -> None:
        assert decision.allowed is True

    def test_status_safe(self, decision: Decision) -> None:
        assert decision.status is SolverStatus.SAFE

    def test_no_violations(self, decision: Decision) -> None:
        assert decision.violated_invariants == ()


# ═══════════════════════════════════════════════════════════════════════════════
# Scenario E — One cent over boundary (UNSAFE, exact decimal arithmetic)
# ═══════════════════════════════════════════════════════════════════════════════


class TestScenarioE:
    """E: amount = balance + 0.01 — must be UNSAT with exact Decimal arithmetic.

    This test validates that Z3 receives exact rationals (via as_integer_ratio()),
    not IEEE 754 float approximations that could yield incorrect results.
    """

    @pytest.fixture()
    def decision(self, guard: Guard) -> Decision:
        return guard.verify(_intent("1000.01"), _state(balance="1000.00"))

    def test_blocked(self, decision: Decision) -> None:
        assert decision.allowed is False

    def test_status_unsafe(self, decision: Decision) -> None:
        assert decision.status is SolverStatus.UNSAFE

    def test_non_negative_balance_violated(self, decision: Decision) -> None:
        assert "non_negative_balance" in decision.violated_invariants

    def test_only_one_violation(self, decision: Decision) -> None:
        assert len(decision.violated_invariants) == 1

    @pytest.mark.parametrize(
        ("balance", "amount"),
        [
            ("100.00", "100.01"),
            ("0.10", "0.11"),
            ("999.99", "1000.00"),
            ("0.01", "0.02"),
        ],
    )
    def test_sub_cent_precision_unsat(
        self, guard: Guard, balance: str, amount: str
    ) -> None:
        """All these must be UNSAT — exact rational arithmetic required."""
        d = guard.verify(_intent(amount), _state(balance=balance))
        assert d.allowed is False
        assert "non_negative_balance" in d.violated_invariants


# ═══════════════════════════════════════════════════════════════════════════════
# Scenario F — Stale state version (STALE_STATE)
# ═══════════════════════════════════════════════════════════════════════════════


class TestScenarioF:
    def test_stale_version_blocked(self, guard: Guard) -> None:
        d = guard.verify(_intent("100.00"), _state(state_version="0.9"))
        assert d.allowed is False
        assert d.status is SolverStatus.STALE_STATE

    def test_explanation_contains_expected_and_actual(self, guard: Guard) -> None:
        d = guard.verify(_intent("100.00"), _state(state_version="0.9"))
        assert "1.0" in d.explanation
        assert "0.9" in d.explanation

    def test_future_version_also_stale(self, guard: Guard) -> None:
        d = guard.verify(_intent("100.00"), _state(state_version="2.0"))
        assert d.status is SolverStatus.STALE_STATE


# ═══════════════════════════════════════════════════════════════════════════════
# Scenario G — Validation failure: wrong intent type (VALIDATION_FAILURE)
# ═══════════════════════════════════════════════════════════════════════════════


class TestScenarioG:
    def test_string_amount_validation_failure(self, guard: Guard) -> None:
        d = guard.verify({"amount": "not-a-number"}, _state())
        assert d.allowed is False
        assert d.status is SolverStatus.VALIDATION_FAILURE

    def test_none_amount_validation_failure(self, guard: Guard) -> None:
        d = guard.verify({"amount": None}, _state())
        assert d.allowed is False
        assert d.status is SolverStatus.VALIDATION_FAILURE

    def test_missing_intent_field_validation_failure(self, guard: Guard) -> None:
        d = guard.verify({}, _state())
        assert d.allowed is False

    def test_invalid_state_type_validation_failure(self, guard: Guard) -> None:
        state = {**_state(), "balance": "not-a-decimal"}
        d = guard.verify(_intent("100.00"), state)
        assert d.allowed is False
        assert d.status is SolverStatus.VALIDATION_FAILURE


# ═══════════════════════════════════════════════════════════════════════════════
# Scenario H — Daily limit exceeded (UNSAFE)
# ═══════════════════════════════════════════════════════════════════════════════


class TestScenarioH:
    def test_daily_limit_exceeded_blocked(self, guard: Guard) -> None:
        # balance=10000 ensures non_negative_balance is satisfied; only within_daily_limit fails
        d = guard.verify(_intent("6000.00"), _state(balance="10000.00", daily_limit="5000.00"))
        assert d.allowed is False
        assert d.status is SolverStatus.UNSAFE
        assert "within_daily_limit" in d.violated_invariants

    def test_exactly_at_limit_allowed(self, guard: Guard) -> None:
        # balance equals daily_limit: both non_negative_balance (0 remaining) and within_daily_limit are SAT
        d = guard.verify(_intent("5000.00"), _state(balance="5000.00", daily_limit="5000.00"))
        assert d.allowed is True

    def test_one_cent_over_limit_blocked(self, guard: Guard) -> None:
        # balance=10000 to isolate only within_daily_limit violation
        d = guard.verify(_intent("5000.01"), _state(balance="10000.00", daily_limit="5000.00"))
        assert d.allowed is False
        assert "within_daily_limit" in d.violated_invariants


# ═══════════════════════════════════════════════════════════════════════════════
# Scenario I — All three invariants violated simultaneously
# ═══════════════════════════════════════════════════════════════════════════════


class TestScenarioI:
    def test_all_three_violations_reported(self, guard: Guard) -> None:
        d = guard.verify(
            _intent("9000.00"),
            _state(balance="50.00", daily_limit="5000.00", is_frozen=True),
        )
        assert d.allowed is False
        assert d.status is SolverStatus.UNSAFE
        violations = set(d.violated_invariants)
        assert violations == {"non_negative_balance", "within_daily_limit", "account_not_frozen"}

    def test_exactly_three_violations(self, guard: Guard) -> None:
        d = guard.verify(
            _intent("9000.00"),
            _state(balance="50.00", daily_limit="5000.00", is_frozen=True),
        )
        assert len(d.violated_invariants) == 3


# ═══════════════════════════════════════════════════════════════════════════════
# Decision immutability across pipeline
# ═══════════════════════════════════════════════════════════════════════════════


class TestDecisionIntegrity:
    def test_two_calls_produce_different_decision_ids(self, guard: Guard) -> None:
        d1 = guard.verify(_intent("100.00"), _state())
        d2 = guard.verify(_intent("100.00"), _state())
        assert d1.decision_id != d2.decision_id

    def test_safe_decision_serialises_to_json(self, guard: Guard) -> None:
        import json

        d = guard.verify(_intent("100.00"), _state())
        json.dumps(d.to_dict())  # must not raise

    def test_unsafe_decision_serialises_to_json(self, guard: Guard) -> None:
        import json

        d = guard.verify(_intent("9999.00"), _state(balance="50.00"))
        json.dumps(d.to_dict())  # must not raise
