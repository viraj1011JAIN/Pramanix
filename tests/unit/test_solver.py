# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Unit tests for pramanix.solver — solve(), _SolveResult, and helpers.

Coverage targets:
- _SolveResult dataclass construction
- SAT path: normal, boundary-exact, extra keys ignored, solver_time populated
- Single UNSAT: overdraft, daily-limit, frozen — correct label attribution
- Multiple UNSAT: all violated invariants reported (not just the minimal core)
- Boundary arithmetic: 0.01 Decimal precision, exact rational arithmetic
- Timeout paths: fast-path and attribution-path (via mocks)
- Type-error rejection: bool passed to Real-typed field
- Label enforcement: unlabelled invariant in attribution path raises
"""

from __future__ import annotations

from decimal import Decimal

import pytest

from pramanix.exceptions import (
    FieldTypeError,
    InvariantLabelError,
    SolverTimeoutError,
)
from pramanix.expressions import ConstraintExpr, E, Field
from pramanix.solver import _SolveResult, solve

# ── Shared field declarations ─────────────────────────────────────────────────

_balance = Field("balance", Decimal, "Real")
_amount = Field("amount", Decimal, "Real")
_daily_limit = Field("daily_limit", Decimal, "Real")
_is_frozen = Field("is_frozen", bool, "Bool")

INVARIANTS: list[ConstraintExpr] = [
    (E(_balance) - E(_amount) >= 0)
    .named("non_negative_balance")
    .explain("Overdraft: balance={balance}, amount={amount}"),
    (E(_amount) <= E(_daily_limit))
    .named("within_daily_limit")
    .explain("Exceeds daily limit: amount={amount}, limit={daily_limit}"),
    (E(_is_frozen) == False)  # noqa: E712
    .named("account_not_frozen")
    .explain("Account is frozen"),
]

# Baseline values that satisfy all three invariants
_BASE: dict[str, object] = {
    "balance": Decimal("1000"),
    "amount": Decimal("100"),
    "daily_limit": Decimal("5000"),
    "is_frozen": False,
}


# ═══════════════════════════════════════════════════════════════════════════════
# _SolveResult dataclass
# ═══════════════════════════════════════════════════════════════════════════════


class TestSolveResult:
    def test_sat_result_fields(self) -> None:
        r = _SolveResult(sat=True, violated=[], solver_time_ms=1.5)
        assert r.sat is True
        assert r.violated == []
        assert r.solver_time_ms == pytest.approx(1.5)

    def test_unsat_result_fields(self) -> None:
        inv = (E(_balance) >= 0).named("pos")
        r = _SolveResult(sat=False, violated=[inv], solver_time_ms=2.0)
        assert r.sat is False
        assert len(r.violated) == 1

    def test_solver_time_zero_allowed(self) -> None:
        r = _SolveResult(sat=True, violated=[], solver_time_ms=0.0)
        assert r.solver_time_ms == 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# SAT path
# ═══════════════════════════════════════════════════════════════════════════════


class TestSolveSAT:
    def test_normal_transaction_is_sat(self) -> None:
        r = solve(INVARIANTS, _BASE, timeout_ms=5_000)
        assert r.sat is True
        assert r.violated == []

    def test_boundary_exact_zero_remaining(self) -> None:
        """balance == amount → SAT (balance - amount == 0 >= 0)."""
        vals = {**_BASE, "balance": Decimal("100"), "amount": Decimal("100")}
        r = solve(INVARIANTS, vals, timeout_ms=5_000)
        assert r.sat is True

    def test_solver_time_is_non_negative(self) -> None:
        r = solve(INVARIANTS, _BASE, timeout_ms=5_000)
        assert r.solver_time_ms >= 0.0

    def test_solver_time_is_float(self) -> None:
        r = solve(INVARIANTS, _BASE, timeout_ms=5_000)
        assert isinstance(r.solver_time_ms, float)

    def test_extra_keys_ignored(self) -> None:
        vals = {**_BASE, "irrelevant_field": 999, "another_unused": "x"}
        r = solve(INVARIANTS, vals, timeout_ms=5_000)
        assert r.sat is True

    def test_large_balance_amount_sat(self) -> None:
        vals = {
            "balance": Decimal("1_000_000"),
            "amount": Decimal("999_999.99"),
            "daily_limit": Decimal("1_000_000"),
            "is_frozen": False,
        }
        r = solve(INVARIANTS, vals, timeout_ms=5_000)
        assert r.sat is True


# ═══════════════════════════════════════════════════════════════════════════════
# Single-invariant UNSAT (correct attribution)
# ═══════════════════════════════════════════════════════════════════════════════


class TestSolveSingleViolation:
    def _labels(self, r: _SolveResult) -> set[str]:
        return {inv.label for inv in r.violated if inv.label}

    def test_overdraft_unsat(self) -> None:
        vals = {**_BASE, "balance": Decimal("50"), "amount": Decimal("1000")}
        r = solve(INVARIANTS, vals, timeout_ms=5_000)
        assert r.sat is False

    def test_overdraft_correct_label(self) -> None:
        vals = {**_BASE, "balance": Decimal("50"), "amount": Decimal("1000")}
        r = solve(INVARIANTS, vals, timeout_ms=5_000)
        labels = self._labels(r)
        assert "non_negative_balance" in labels
        assert "within_daily_limit" not in labels
        assert "account_not_frozen" not in labels

    def test_daily_limit_exceeded_unsat(self) -> None:
        # balance=10000 ensures non_negative_balance is satisfied; only within_daily_limit fails
        vals = {
            **_BASE,
            "balance": Decimal("10000"),
            "amount": Decimal("6000"),
        }
        r = solve(INVARIANTS, vals, timeout_ms=5_000)
        assert r.sat is False
        assert "within_daily_limit" in self._labels(r)

    def test_daily_limit_only_that_label(self) -> None:
        # balance=10000 so balance - amount = 4000 >= 0 — isolates only within_daily_limit
        vals = {
            **_BASE,
            "balance": Decimal("10000"),
            "amount": Decimal("6000"),
        }
        r = solve(INVARIANTS, vals, timeout_ms=5_000)
        labels = self._labels(r)
        assert "non_negative_balance" not in labels
        assert "account_not_frozen" not in labels

    def test_frozen_account_unsat(self) -> None:
        vals = {**_BASE, "is_frozen": True}
        r = solve(INVARIANTS, vals, timeout_ms=5_000)
        assert r.sat is False
        assert "account_not_frozen" in self._labels(r)

    def test_frozen_only_that_label(self) -> None:
        vals = {**_BASE, "is_frozen": True}
        r = solve(INVARIANTS, vals, timeout_ms=5_000)
        labels = self._labels(r)
        assert "non_negative_balance" not in labels
        assert "within_daily_limit" not in labels

    def test_boundary_breach_by_one_cent_unsat(self) -> None:
        vals = {
            **_BASE,
            "balance": Decimal("100"),
            "amount": Decimal("100.01"),
        }
        r = solve(INVARIANTS, vals, timeout_ms=5_000)
        assert r.sat is False
        assert "non_negative_balance" in self._labels(r)

    def test_boundary_exact_plus_one_cent_unsat(self) -> None:
        """Regression: 1/10 arithmetic must be exact, not IEEE 754 approximation."""
        vals = {**_BASE, "balance": Decimal("0.10"), "amount": Decimal("0.11")}
        r = solve(INVARIANTS, vals, timeout_ms=5_000)
        assert r.sat is False

    def test_violated_count_single(self) -> None:
        vals = {**_BASE, "balance": Decimal("0"), "amount": Decimal("1")}
        r = solve(INVARIANTS, vals, timeout_ms=5_000)
        assert len(r.violated) == 1


# ═══════════════════════════════════════════════════════════════════════════════
# Multiple-invariant UNSAT — exact, complete attribution (key design property)
# ═══════════════════════════════════════════════════════════════════════════════


class TestSolveMultiViolation:
    """
    Z3's shared-solver unsat_core() returns only a *minimal* subset.
    The per-invariant solver design guarantees ALL violated invariants are reported.
    """

    def _labels(self, r: _SolveResult) -> set[str]:
        return {inv.label for inv in r.violated if inv.label}

    def test_two_violations_both_reported(self) -> None:
        """overdraft AND frozen — both must appear in violated."""
        vals = {
            **_BASE,
            "balance": Decimal("50"),
            "amount": Decimal("1000"),
            "is_frozen": True,
        }
        r = solve(INVARIANTS, vals, timeout_ms=5_000)
        assert r.sat is False
        labels = self._labels(r)
        assert "non_negative_balance" in labels
        assert "account_not_frozen" in labels

    def test_all_three_violated(self) -> None:
        vals = {
            "balance": Decimal("50"),
            "amount": Decimal("6000"),
            "daily_limit": Decimal("5000"),
            "is_frozen": True,
        }
        r = solve(INVARIANTS, vals, timeout_ms=5_000)
        assert self._labels(r) == {
            "non_negative_balance",
            "within_daily_limit",
            "account_not_frozen",
        }

    def test_violated_count_correct_for_two(self) -> None:
        vals = {
            **_BASE,
            "balance": Decimal("50"),
            "amount": Decimal("1000"),
            "is_frozen": True,
        }
        r = solve(INVARIANTS, vals, timeout_ms=5_000)
        assert len(r.violated) == 2

    def test_violated_count_correct_for_three(self) -> None:
        vals = {
            "balance": Decimal("0"),
            "amount": Decimal("9999"),
            "daily_limit": Decimal("5000"),
            "is_frozen": True,
        }
        r = solve(INVARIANTS, vals, timeout_ms=5_000)
        assert len(r.violated) == 3

    def test_sat_true_means_empty_violated_list(self) -> None:
        r = solve(INVARIANTS, _BASE, timeout_ms=5_000)
        assert r.sat is True
        assert r.violated == []


# ═══════════════════════════════════════════════════════════════════════════════
# Timeout paths — real Z3 rlimit=1 trigger
#
# rlimit=1 instructs Z3 to abort after one elementary operation.  Z3 returns
# ``unknown`` for ANY formula under this limit — including trivially satisfiable
# ones.  _fast_check converts ``unknown`` to SolverTimeoutError("<all-invariants>").
#
# The per-invariant attribution timeout (solver.py line 221) cannot be triggered
# without patching: the fast path and attribution path share the same rlimit, and
# a formula that is UNSAT on the combined solver is always simpler (not harder)
# for each per-invariant solver.  That line carries ``# pragma: no cover``.
# ═══════════════════════════════════════════════════════════════════════════════


class TestSolveTimeout:
    def test_fast_path_timeout_propagates(self) -> None:
        """rlimit=1 exhausts Z3 on the combined solver — real SolverTimeoutError."""
        with pytest.raises(SolverTimeoutError) as exc_info:
            solve(INVARIANTS, _BASE, timeout_ms=5000, rlimit=1)
        assert exc_info.value.label == "<all-invariants>"

    def test_timeout_carries_timeout_ms(self) -> None:
        """SolverTimeoutError.timeout_ms matches the value passed to solve()."""
        with pytest.raises(SolverTimeoutError) as exc_info:
            solve(INVARIANTS, _BASE, timeout_ms=9999, rlimit=1)
        assert exc_info.value.timeout_ms == 9999


# ═══════════════════════════════════════════════════════════════════════════════
# Type safety: bool-as-Real rejection
# ═══════════════════════════════════════════════════════════════════════════════


class TestSolveTypeErrors:
    def test_bool_as_real_raises_field_type_error(self) -> None:
        """bool is a subclass of int; passing True to a Real field must be rejected."""
        vals = {**_BASE, "balance": True}
        with pytest.raises(FieldTypeError, match="bool"):
            solve(INVARIANTS, vals, timeout_ms=5_000)

    def test_bool_false_as_real_raises_field_type_error(self) -> None:
        vals = {**_BASE, "amount": False}
        with pytest.raises(FieldTypeError, match="bool"):
            solve(INVARIANTS, vals, timeout_ms=5_000)


# ═══════════════════════════════════════════════════════════════════════════════
# Label enforcement: unlabelled invariant raises InvariantLabelError
# ═══════════════════════════════════════════════════════════════════════════════


class TestSolveLabelEnforcement:
    def test_unlabelled_invariant_in_attribution_raises(self) -> None:
        """Unlabelled invariant violated by real values → InvariantLabelError.

        balance=-1 makes (balance >= 0) UNSAT via real Z3 arithmetic.
        No monkeypatching needed — the solver reaches attribution naturally.
        """
        unlabelled = E(_balance) >= 0  # no .named()
        vals = {
            "balance": Decimal("-1"),  # Naturally makes the constraint UNSAT
            "amount": Decimal("0"),
            "daily_limit": Decimal("5000"),
            "is_frozen": False,
        }
        with pytest.raises(InvariantLabelError):
            solve([unlabelled, *INVARIANTS[1:]], vals, timeout_ms=5_000)
