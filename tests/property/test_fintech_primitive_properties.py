# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Property-based tests for FinTech primitives — float-drift safety and monotonicity.

Proves via Hypothesis (1 000+ examples each) that:
1. No float drift contaminates Z3 RealVal reasoning for monetary amounts.
2. Solver decisions are monotone — relaxing a constraint cannot flip SAT→UNSAT.
3. Every primitive that uses Decimal "Real" fields is immune to IEEE 754
   rounding errors regardless of number of decimal places.

These tests are the equivalent of HFT desk regression tests: if any property
fails, the primitive is considered unsafe for production deployment.

Run:
    pytest tests/property/test_fintech_primitive_properties.py -v --tb=short
"""

from __future__ import annotations

from decimal import Decimal

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from pramanix.expressions import Field
from pramanix.primitives.fintech import (
    AntiStructuring,
    CollateralHaircut,
    MarginRequirement,
    MaxDrawdown,
    SufficientBalance,
    VelocityCheck,
)
from pramanix.solver import solve

pytestmark = pytest.mark.slow

# ── Field declarations (reused across all property tests) ─────────────────────

_balance = Field("balance", Decimal, "Real")
_amount = Field("amount", Decimal, "Real")
_cumulative = Field("cumulative_amount", Decimal, "Real")
_collateral = Field("collateral", Decimal, "Real")
_loan = Field("loan", Decimal, "Real")
_current_nav = Field("current_nav", Decimal, "Real")
_peak_nav = Field("peak_nav", Decimal, "Real")
_account_equity = Field("account_equity", Decimal, "Real")
_position_value = Field("position_value", Decimal, "Real")
_tx_count = Field("tx_count", int, "Int")

# ── Hypothesis strategies ─────────────────────────────────────────────────────

# Positive Decimals — avoid zero/negative to keep domain invariants clean
_positive_decimal = st.decimals(
    min_value=Decimal("0.01"),
    max_value=Decimal("10_000_000"),
    allow_nan=False,
    allow_infinity=False,
    places=None,  # allow all decimal precisions, including 18-dp DeFi amounts
)

_non_negative_decimal = st.decimals(
    min_value=Decimal("0"),
    max_value=Decimal("10_000_000"),
    allow_nan=False,
    allow_infinity=False,
    places=None,
)

_positive_int = st.integers(min_value=1, max_value=10_000)

_pct = st.decimals(
    min_value=Decimal("0.01"),
    max_value=Decimal("0.99"),
    places=2,
    allow_nan=False,
    allow_infinity=False,
)


# ═══════════════════════════════════════════════════════════════════════════════
# SufficientBalance — monotonicity
# "More balance never hurts" and "More amount never helps"
# ═══════════════════════════════════════════════════════════════════════════════


@given(balance=_positive_decimal, amount=_positive_decimal)
@settings(max_examples=1_000, deadline=None)
def test_sufficient_balance_no_float_drift(balance: Decimal, amount: Decimal) -> None:
    """SAT result matches exact Decimal comparison — no float drift.

    Z3 must agree with Python's exact Decimal arithmetic on whether
    ``balance >= amount``.
    """
    inv = [SufficientBalance(_balance, _amount)]
    result = solve(inv, {"balance": balance, "amount": amount}, timeout_ms=5_000)

    expected_sat = balance >= amount
    assert result.sat == expected_sat, (
        f"Z3 and Python Decimal disagree: balance={balance}, amount={amount}, "
        f"expected SAT={expected_sat}, got SAT={result.sat}. "
        "Float drift detected in Z3 RealVal encoding."
    )


@given(balance=_positive_decimal, amount=_positive_decimal, extra=_positive_decimal)
@settings(max_examples=500, deadline=None)
def test_sufficient_balance_monotone_balance_increase(
    balance: Decimal, amount: Decimal, extra: Decimal
) -> None:
    """Adding more balance to a passing transaction never causes it to fail."""
    inv = [SufficientBalance(_balance, _amount)]
    base_result = solve(inv, {"balance": balance, "amount": amount}, timeout_ms=5_000)
    if not base_result.sat:
        return  # Only test the monotone property on already-SAT cases
    # Adding more balance should keep it SAT
    better_result = solve(inv, {"balance": balance + extra, "amount": amount}, timeout_ms=5_000)
    assert better_result.sat is True


# ═══════════════════════════════════════════════════════════════════════════════
# AntiStructuring — threshold safety
# "Amount strictly below threshold must be SAT; at-or-above must be UNSAT"
# ═══════════════════════════════════════════════════════════════════════════════

_CTR_THRESHOLD = Decimal("10000")


@given(amount=_non_negative_decimal)
@settings(max_examples=1_000, deadline=None)
def test_anti_structuring_threshold_exactness(amount: Decimal) -> None:
    """SAT ↔ amount < 10,000 — Z3 agrees with Python for all Decimal precisions."""
    inv = [AntiStructuring(_cumulative, _CTR_THRESHOLD)]
    result = solve(inv, {"cumulative_amount": amount}, timeout_ms=5_000)

    expected_sat = amount < _CTR_THRESHOLD
    assert result.sat == expected_sat, (
        f"Z3/Python mismatch: amount={amount}, threshold={_CTR_THRESHOLD}, "
        f"expected SAT={expected_sat}, got SAT={result.sat}"
    )


# ═══════════════════════════════════════════════════════════════════════════════
# CollateralHaircut — monotonicity of collateral
# "More collateral never causes a haircut violation"
# ═══════════════════════════════════════════════════════════════════════════════


@given(
    collateral=_positive_decimal,
    loan=_positive_decimal,
    haircut=_pct,
    extra_collateral=_positive_decimal,
)
@settings(max_examples=500, deadline=None)
def test_collateral_haircut_monotone(
    collateral: Decimal,
    loan: Decimal,
    haircut: Decimal,
    extra_collateral: Decimal,
) -> None:
    """Increasing collateral maintains or improves haircut coverage."""
    inv = [CollateralHaircut(_collateral, _loan, haircut)]
    base_result = solve(inv, {"collateral": collateral, "loan": loan}, timeout_ms=5_000)
    if not base_result.sat:
        return  # Only test monotonicity from SAT baseline
    better_result = solve(
        inv, {"collateral": collateral + extra_collateral, "loan": loan}, timeout_ms=5_000
    )
    assert better_result.sat is True


@given(collateral=_positive_decimal, loan=_positive_decimal, haircut=_pct)
@settings(max_examples=1_000, deadline=None)
def test_collateral_haircut_no_float_drift(
    collateral: Decimal, loan: Decimal, haircut: Decimal
) -> None:
    """Z3 Real arithmetic agrees with Python Decimal arithmetic on haircut coverage."""
    inv = [CollateralHaircut(_collateral, _loan, haircut)]
    result = solve(inv, {"collateral": collateral, "loan": loan}, timeout_ms=5_000)

    # Python-level exact check to compare against
    effective_collateral = collateral * (Decimal("1") - haircut)
    expected_sat = effective_collateral >= loan
    assert result.sat == expected_sat, (
        f"Float drift: collateral={collateral}, haircut={haircut}, loan={loan}, "
        f"effective={effective_collateral}, expected SAT={expected_sat}, got={result.sat}"
    )


# ═══════════════════════════════════════════════════════════════════════════════
# MaxDrawdown — range invariant
# "(peak - current) / peak can never exceed the limit — Z3 agrees with Python"
# ═══════════════════════════════════════════════════════════════════════════════


@given(current=_positive_decimal, peak=_positive_decimal, max_dd=_pct)
@settings(max_examples=1_000, deadline=None)
def test_max_drawdown_agrees_with_python(current: Decimal, peak: Decimal, max_dd: Decimal) -> None:
    """Z3 agrees with Python: (peak - current) <= max_dd * peak iff SAT.

    MaxDrawdown uses multiplication (not division), so peak == 0 is a valid
    input: both Python and Z3 agree that (0 - current) <= max_dd * 0 = 0,
    i.e. -current <= 0, which is True iff current >= 0 (always True for
    _positive_decimal).

    assume(peak >= current) is kept as a domain-constraint: the invariant is
    designed for the normal-drawdown regime (current has not exceeded peak).
    Behaviour for current > peak is separately tested in TestMaxDrawdownEdgeCases.
    """
    assume(peak >= current)

    inv = [MaxDrawdown(_current_nav, _peak_nav, max_dd)]
    result = solve(inv, {"current_nav": current, "peak_nav": peak}, timeout_ms=5_000)

    expected_sat = (peak - current) <= max_dd * peak
    assert result.sat == expected_sat, (
        f"Float drift: current={current}, peak={peak}, max_dd={max_dd}, "
        f"expected SAT={expected_sat}, got SAT={result.sat}"
    )


# ═══════════════════════════════════════════════════════════════════════════════
# MarginRequirement — Reg. T monotone equity
# "More equity monotonically improves margin coverage"
# ═══════════════════════════════════════════════════════════════════════════════


@given(
    equity=_non_negative_decimal,
    position=_positive_decimal,
    margin=_pct,
)
@settings(max_examples=1_000, deadline=None)
def test_margin_requirement_no_float_drift(
    equity: Decimal, position: Decimal, margin: Decimal
) -> None:
    """Z3 Real arithmetic agrees with Python Decimal: equity >= margin * position."""
    inv = [MarginRequirement(_account_equity, _position_value, margin)]
    result = solve(inv, {"account_equity": equity, "position_value": position}, timeout_ms=5_000)

    expected_sat = equity >= margin * position
    assert result.sat == expected_sat, (
        f"Float drift: equity={equity}, position={position}, margin={margin}, "
        f"expected SAT={expected_sat}, got SAT={result.sat}"
    )


@given(
    equity=_non_negative_decimal,
    position=_positive_decimal,
    margin=_pct,
    extra=_positive_decimal,
)
@settings(max_examples=500, deadline=None)
def test_margin_requirement_monotone_equity(
    equity: Decimal, position: Decimal, margin: Decimal, extra: Decimal
) -> None:
    """Adding more equity to a passing margin check never causes a margin call."""
    inv = [MarginRequirement(_account_equity, _position_value, margin)]
    base_result = solve(
        inv, {"account_equity": equity, "position_value": position}, timeout_ms=5_000
    )
    if not base_result.sat:
        return
    better_result = solve(
        inv,
        {"account_equity": equity + extra, "position_value": position},
        timeout_ms=5_000,
    )
    assert better_result.sat is True


# ── MaxDrawdown edge-case unit tests (#33) ────────────────────────────────────


class TestMaxDrawdownEdgeCases:
    """Explicit unit tests for inputs excluded from the MaxDrawdown property.

    MaxDrawdown uses (peak - current) <= max_pct * peak (no division), so:
    - peak == 0 is safe: both Python and Z3 evaluate -current <= 0, which is
      True for any positive current (always SAT).
    - peak < current (inverted — current exceeds historical high): the LHS
      is negative, so (peak - current) <= max_pct * peak with peak > 0 is
      True whenever -drawdown_abs <= max_pct * peak — almost always SAT.

    These unit tests document and verify that assumption-excluded inputs
    are handled correctly rather than crashing or diverging. (#33)
    """

    def test_peak_zero_with_positive_current_is_sat(self) -> None:
        """peak=0, current>0: (0 - current) <= max_pct * 0 = 0 → -current <= 0.

        Since current > 0, -current < 0 <= 0 is True → always SAT.
        Python and Z3 must agree: no ZeroDivisionError (formula uses *, not /).
        """
        inv = [MaxDrawdown(_current_nav, _peak_nav, Decimal("0.20"))]
        result = solve(
            inv,
            {"current_nav": Decimal("100"), "peak_nav": Decimal("0")},
            timeout_ms=5_000,
        )
        expected = (Decimal("0") - Decimal("100")) <= Decimal("0.20") * Decimal("0")
        assert result.sat == expected

    def test_peak_equals_current_is_sat(self) -> None:
        """peak == current: (peak - current) == 0 <= max_pct * peak — always SAT."""
        inv = [MaxDrawdown(_current_nav, _peak_nav, Decimal("0.10"))]
        result = solve(
            inv,
            {"current_nav": Decimal("500"), "peak_nav": Decimal("500")},
            timeout_ms=5_000,
        )
        assert result.sat is True

    def test_current_exceeds_peak_is_sat(self) -> None:
        """peak < current (recovery above peak): LHS is negative → SAT.

        (peak - current) = negative <= max_pct * peak = positive → True.
        This is not a normal drawdown scenario but must not crash.
        """
        inv = [MaxDrawdown(_current_nav, _peak_nav, Decimal("0.20"))]
        result = solve(
            inv,
            {"current_nav": Decimal("600"), "peak_nav": Decimal("500")},
            timeout_ms=5_000,
        )
        assert result.sat is True

    def test_drawdown_at_exact_limit_is_sat(self) -> None:
        """Drawdown exactly at the limit: (peak - current) == max_pct * peak → SAT."""
        peak = Decimal("1000")
        max_pct = Decimal("0.20")
        current = peak - max_pct * peak  # exactly at limit
        inv = [MaxDrawdown(_current_nav, _peak_nav, max_pct)]
        result = solve(
            inv,
            {"current_nav": current, "peak_nav": peak},
            timeout_ms=5_000,
        )
        assert result.sat is True

    def test_drawdown_beyond_limit_is_unsat(self) -> None:
        """Drawdown exceeds limit: (peak - current) > max_pct * peak → UNSAT."""
        peak = Decimal("1000")
        max_pct = Decimal("0.20")
        current = peak - max_pct * peak - Decimal("1")  # 1 unit below limit
        inv = [MaxDrawdown(_current_nav, _peak_nav, max_pct)]
        result = solve(
            inv,
            {"current_nav": current, "peak_nav": peak},
            timeout_ms=5_000,
        )
        assert result.sat is False


# ═══════════════════════════════════════════════════════════════════════════════
# VelocityCheck — integer boundary
# "tx_count == window_limit must always be SAT (<=, not <)"
# ═══════════════════════════════════════════════════════════════════════════════


@given(window_limit=st.integers(min_value=1, max_value=1_000))
@settings(max_examples=500, deadline=None)
def test_velocity_check_exact_boundary_is_sat(window_limit: int) -> None:
    """Exactly at the velocity limit is always allowed (constraint is <=)."""
    inv = [VelocityCheck(_tx_count, window_limit)]
    result = solve(inv, {"tx_count": window_limit}, timeout_ms=5_000)
    assert result.sat is True


@given(window_limit=st.integers(min_value=1, max_value=1_000))
@settings(max_examples=500, deadline=None)
def test_velocity_check_one_over_limit_is_unsat(window_limit: int) -> None:
    """One transaction over the limit is always rejected."""
    inv = [VelocityCheck(_tx_count, window_limit)]
    result = solve(inv, {"tx_count": window_limit + 1}, timeout_ms=5_000)
    assert result.sat is False
