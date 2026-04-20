# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Property-based tests for the DSL expression layer and transpiler.

Proves via Hypothesis (hundreds to thousands of examples each) that:

1. Arithmetic operator commutativity — E(a) + E(b) ≡ E(b) + E(a) for Z3.
2. Comparison monotonicity — relaxing a bound never turns UNSAT into SAT for
   strict inequalities.
3. Boolean conjunction coherence — A & B is only SAT when both A and B are
   individually SAT.
4. Boolean disjunction coherence — A | B is SAT when at least one of A or B is.
5. Negation correctness — ~A is SAT iff A is UNSAT.
6. Exact rational encoding — z3_val encodes Decimal via as_integer_ratio();
   Z3 must agree with Python Decimal for all precisions.
7. is_in() expansion — E(f).is_in([v]) is SAT iff value == v.
8. Transpiler sort isolation — Bool fields never accept Int/Real values; no
   cross-sort contamination between per-call z3.Contexts.
9. Named-invariant idempotency — calling .named() twice returns a fresh
   ConstraintExpr with only the second label (no label stacking).
10. Fail-safe under zero-invariant solve — solving an empty invariant list
    always returns SAT (vacuous truth).

Run:
    pytest tests/property/test_dsl_and_transpiler_properties.py -v --tb=short
"""
from __future__ import annotations

from decimal import Decimal

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from pramanix.expressions import E, Field
from pramanix.solver import solve

# ── Shared field declarations ─────────────────────────────────────────────────

_x = Field("x", Decimal, "Real")
_y = Field("y", Decimal, "Real")
_n = Field("n", int, "Int")
_m = Field("m", int, "Int")
_flag = Field("flag", bool, "Bool")

# ── Hypothesis strategies ─────────────────────────────────────────────────────

_decimal = st.decimals(
    min_value=Decimal("-1_000_000"),
    max_value=Decimal("1_000_000"),
    allow_nan=False,
    allow_infinity=False,
    places=None,
)

_positive_decimal = st.decimals(
    min_value=Decimal("0.01"),
    max_value=Decimal("1_000_000"),
    allow_nan=False,
    allow_infinity=False,
    places=None,
)

_int_val = st.integers(min_value=-100_000, max_value=100_000)
_pos_int = st.integers(min_value=1, max_value=100_000)


# ═══════════════════════════════════════════════════════════════════════════════
# 1. Arithmetic commutativity — E(a) + E(b) == E(b) + E(a) in Z3
# ═══════════════════════════════════════════════════════════════════════════════


@given(xv=_decimal, yv=_decimal, threshold=_decimal)
@settings(max_examples=500, deadline=None)
def test_addition_is_commutative(xv: Decimal, yv: Decimal, threshold: Decimal) -> None:
    """E(x) + E(y) >= t  iff  E(y) + E(x) >= t — Z3 Real addition is commutative."""
    inv_ab = [(E(_x) + E(_y) >= threshold).named("commute_ab")]
    inv_ba = [(E(_y) + E(_x) >= threshold).named("commute_ba")]
    vals = {"x": xv, "y": yv}
    result_ab = solve(inv_ab, vals, timeout_ms=5_000)
    result_ba = solve(inv_ba, vals, timeout_ms=5_000)
    assert result_ab.sat == result_ba.sat, (
        f"Commutativity violation: x={xv}, y={yv}, t={threshold}, "
        f"ab.sat={result_ab.sat}, ba.sat={result_ba.sat}"
    )


@given(xv=_decimal, yv=_decimal, threshold=_decimal)
@settings(max_examples=500, deadline=None)
def test_multiplication_is_commutative(xv: Decimal, yv: Decimal, threshold: Decimal) -> None:
    """E(x) * E(y) >= t  iff  E(y) * E(x) >= t — Z3 Real multiplication is commutative."""
    inv_ab = [(E(_x) * E(_y) >= threshold).named("mul_ab")]
    inv_ba = [(E(_y) * E(_x) >= threshold).named("mul_ba")]
    vals = {"x": xv, "y": yv}
    result_ab = solve(inv_ab, vals, timeout_ms=5_000)
    result_ba = solve(inv_ba, vals, timeout_ms=5_000)
    assert result_ab.sat == result_ba.sat, (
        f"Multiplication commutativity violation: x={xv}, y={yv}, t={threshold}"
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 2. Comparison monotonicity — relaxing a bound never turns UNSAT into SAT
#    for >=: if x >= tight_bound is UNSAT, x >= looser_bound is also UNSAT
#    (where looser_bound > tight_bound)
# ═══════════════════════════════════════════════════════════════════════════════


@given(xv=_decimal, tight=_decimal, delta=_positive_decimal)
@settings(max_examples=500, deadline=None)
def test_ge_monotone_bound_tightening(
    xv: Decimal, tight: Decimal, delta: Decimal
) -> None:
    """If x >= tight is SAT, then x >= (tight - delta) is also SAT.

    Making the bound easier (lower) can only maintain or improve satisfiability.
    """
    inv_tight = [(E(_x) >= tight).named("tight")]
    result_tight = solve(inv_tight, {"x": xv}, timeout_ms=5_000)
    if not result_tight.sat:
        return  # Only test from SAT baseline

    inv_looser = [(E(_x) >= tight - delta).named("looser")]
    result_looser = solve(inv_looser, {"x": xv}, timeout_ms=5_000)
    assert result_looser.sat is True, (
        f"Monotone violation: x={xv}, tight={tight}, delta={delta}: "
        f"x>=tight is SAT but x>=(tight-delta) is UNSAT"
    )


@given(xv=_int_val, tight=_int_val, delta=_pos_int)
@settings(max_examples=500, deadline=None)
def test_int_ge_monotone(xv: int, tight: int, delta: int) -> None:
    """Integer version: n >= tight SAT → n >= (tight - delta) SAT."""
    inv_tight = [(E(_n) >= tight).named("tight")]
    result_tight = solve(inv_tight, {"n": xv}, timeout_ms=5_000)
    if not result_tight.sat:
        return

    inv_looser = [(E(_n) >= tight - delta).named("looser")]
    result_looser = solve(inv_looser, {"n": xv}, timeout_ms=5_000)
    assert result_looser.sat is True


# ═══════════════════════════════════════════════════════════════════════════════
# 3. Boolean conjunction coherence — A & B is SAT only when both A and B are SAT
# ═══════════════════════════════════════════════════════════════════════════════


@given(xv=_decimal, yv=_decimal, tx=_decimal, ty=_decimal)
@settings(max_examples=500, deadline=None)
def test_conjunction_requires_both(
    xv: Decimal, yv: Decimal, tx: Decimal, ty: Decimal
) -> None:
    """(x >= tx) & (y >= ty) is SAT iff both individual constraints are SAT."""
    a = (E(_x) >= tx).named("a")
    b = (E(_y) >= ty).named("b")
    ab = ((E(_x) >= tx) & (E(_y) >= ty)).named("ab")

    vals = {"x": xv, "y": yv}
    sat_a = solve([a], vals, timeout_ms=5_000).sat
    sat_b = solve([b], vals, timeout_ms=5_000).sat
    sat_ab = solve([ab], vals, timeout_ms=5_000).sat

    expected = sat_a and sat_b
    assert sat_ab == expected, (
        f"Conjunction incoherent: x={xv}, y={yv}, tx={tx}, ty={ty}, "
        f"sat_a={sat_a}, sat_b={sat_b}, sat_ab={sat_ab}, expected={expected}"
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 4. Boolean disjunction coherence — A | B is SAT when at least one of A or B is
# ═══════════════════════════════════════════════════════════════════════════════


@given(xv=_decimal, yv=_decimal, tx=_decimal, ty=_decimal)
@settings(max_examples=500, deadline=None)
def test_disjunction_requires_at_least_one(
    xv: Decimal, yv: Decimal, tx: Decimal, ty: Decimal
) -> None:
    """(x >= tx) | (y >= ty) is SAT iff at least one individual constraint is SAT."""
    a = (E(_x) >= tx).named("a")
    b = (E(_y) >= ty).named("b")
    a_or_b = ((E(_x) >= tx) | (E(_y) >= ty)).named("a_or_b")

    vals = {"x": xv, "y": yv}
    sat_a = solve([a], vals, timeout_ms=5_000).sat
    sat_b = solve([b], vals, timeout_ms=5_000).sat
    sat_or = solve([a_or_b], vals, timeout_ms=5_000).sat

    expected = sat_a or sat_b
    assert sat_or == expected, (
        f"Disjunction incoherent: x={xv}, y={yv}, tx={tx}, ty={ty}, "
        f"sat_a={sat_a}, sat_b={sat_b}, sat_or={sat_or}, expected={expected}"
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 5. Negation correctness — ~A is SAT iff A is UNSAT
# ═══════════════════════════════════════════════════════════════════════════════


@given(xv=_decimal, threshold=_decimal)
@settings(max_examples=500, deadline=None)
def test_negation_is_complement(xv: Decimal, threshold: Decimal) -> None:
    """~(x >= t) is SAT iff (x >= t) is UNSAT — negation is exact complement."""
    inv = (E(_x) >= threshold).named("pos")
    inv_neg = (~(E(_x) >= threshold)).named("neg")

    vals = {"x": xv}
    sat_pos = solve([inv], vals, timeout_ms=5_000).sat
    sat_neg = solve([inv_neg], vals, timeout_ms=5_000).sat

    assert sat_pos != sat_neg or (sat_pos and sat_neg) is False, (
        f"Negation not complement: x={xv}, t={threshold}, "
        f"sat={sat_pos}, sat_neg={sat_neg}"
    )
    # Strict assertion: exactly one of pos/neg must be SAT (they partition truth)
    assert sat_pos ^ sat_neg, (
        f"Negation does not partition truth: x={xv}, t={threshold}, "
        f"sat_pos={sat_pos}, sat_neg={sat_neg}"
    )


@given(nv=_int_val, threshold=_int_val)
@settings(max_examples=500, deadline=None)
def test_int_negation_is_complement(nv: int, threshold: int) -> None:
    """Integer version: ~(n >= t) is SAT iff (n >= t) is UNSAT."""
    inv = (E(_n) >= threshold).named("pos")
    inv_neg = (~(E(_n) >= threshold)).named("neg")

    vals = {"n": nv}
    sat_pos = solve([inv], vals, timeout_ms=5_000).sat
    sat_neg = solve([inv_neg], vals, timeout_ms=5_000).sat

    assert sat_pos ^ sat_neg, (
        f"Int negation not complement: n={nv}, t={threshold}"
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 6. Exact rational encoding — z3_val uses as_integer_ratio; no float drift
# ═══════════════════════════════════════════════════════════════════════════════


@given(xv=_decimal, yv=_decimal)
@settings(max_examples=1_000, deadline=None)
def test_real_comparison_agrees_with_python_decimal(xv: Decimal, yv: Decimal) -> None:
    """Z3 Real >= agrees with Python Decimal >= for all arbitrary-precision inputs."""
    inv = [(E(_x) >= E(_y)).named("cmp")]
    result = solve(inv, {"x": xv, "y": yv}, timeout_ms=5_000)
    expected = xv >= yv
    assert result.sat == expected, (
        f"Z3/Python Decimal disagreement: x={xv!r}, y={yv!r}, "
        f"expected SAT={expected}, got SAT={result.sat}. "
        "Possible float drift in z3_val encoding."
    )


@given(xv=_decimal, yv=_decimal)
@settings(max_examples=1_000, deadline=None)
def test_real_equality_agrees_with_python_decimal(xv: Decimal, yv: Decimal) -> None:
    """Z3 Real == agrees with Python Decimal == (exact equality, no rounding)."""
    inv = [(E(_x) == E(_y)).named("eq")]
    result = solve(inv, {"x": xv, "y": yv}, timeout_ms=5_000)
    expected = xv == yv
    assert result.sat == expected, (
        f"Z3/Python Decimal equality disagreement: x={xv!r}, y={yv!r}, "
        f"expected={expected}, got={result.sat}"
    )


@given(xv=_int_val, yv=_int_val)
@settings(max_examples=500, deadline=None)
def test_int_comparison_agrees_with_python(xv: int, yv: int) -> None:
    """Z3 Int > agrees with Python int > for all integer inputs."""
    inv = [(E(_n) > E(_m)).named("gt")]
    result = solve(inv, {"n": xv, "m": yv}, timeout_ms=5_000)
    expected = xv > yv
    assert result.sat == expected, (
        f"Z3 Int > Python int disagreement: n={xv}, m={yv}, "
        f"expected={expected}, got={result.sat}"
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 7. is_in() expansion — E(f).is_in([v]) is SAT iff value == v
# ═══════════════════════════════════════════════════════════════════════════════


@given(
    value=st.integers(min_value=0, max_value=100),
    allowed=st.frozensets(st.integers(min_value=0, max_value=100), min_size=1, max_size=10),
)
@settings(max_examples=500, deadline=None)
def test_is_in_exactly_matches_python_membership(value: int, allowed: frozenset[int]) -> None:
    """E(n).is_in(list) is SAT iff value is in the allowed set."""
    allowed_list = list(allowed)
    inv = [E(_n).is_in(allowed_list).named("membership")]
    result = solve(inv, {"n": value}, timeout_ms=5_000)
    expected = value in allowed
    assert result.sat == expected, (
        f"is_in mismatch: n={value}, allowed={allowed_list}, "
        f"expected={expected}, got={result.sat}"
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 8. Transpiler sort isolation — Bool fields never contaminate Real/Int contexts
# ═══════════════════════════════════════════════════════════════════════════════


@given(flag_val=st.booleans())
@settings(max_examples=100, deadline=None)
def test_bool_field_isolation(flag_val: bool) -> None:
    """Bool field == True/False is correctly encoded; no sort confusion with Real."""
    inv_true = [(E(_flag) == True).named("is_true")]  # noqa: E712
    inv_false = [(E(_flag) == False).named("is_false")]  # noqa: E712

    result_true = solve(inv_true, {"flag": flag_val}, timeout_ms=5_000)
    result_false = solve(inv_false, {"flag": flag_val}, timeout_ms=5_000)

    assert result_true.sat == flag_val, (
        f"flag=={flag_val}: expected SAT for `flag == True` = {flag_val}, got {result_true.sat}"
    )
    assert result_false.sat == (not flag_val), (
        f"flag=={flag_val}: expected SAT for `flag == False` = {not flag_val}, got {result_false.sat}"
    )


@given(xv=_decimal, flag_val=st.booleans())
@settings(max_examples=200, deadline=None)
def test_mixed_real_bool_invariants_no_contamination(xv: Decimal, flag_val: bool) -> None:
    """Real and Bool fields coexist in one solve without cross-sort contamination."""
    threshold = Decimal("0")
    inv = [
        (E(_x) >= threshold).named("real_constraint"),
        (E(_flag) == True).named("bool_constraint"),  # noqa: E712
    ]
    result = solve(inv, {"x": xv, "flag": flag_val}, timeout_ms=5_000)
    expected = (xv >= threshold) and flag_val
    assert result.sat == expected, (
        f"Mixed sort contamination: x={xv}, flag={flag_val}, "
        f"expected={expected}, got={result.sat}"
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 9. Named-invariant idempotency — .named() applied twice keeps only the last label
# ═══════════════════════════════════════════════════════════════════════════════


def test_named_twice_uses_final_label() -> None:
    """Calling .named() twice on the same expression uses only the second label."""
    inv = (E(_x) >= Decimal("0")).named("first").named("second")
    assert inv.label == "second", (
        f"Expected label 'second' after double .named(), got '{inv.label}'"
    )


def test_named_label_preserved_through_boolean_composition() -> None:
    """Labels survive boolean & composition; each sub-expr retains its own label."""
    a = (E(_x) >= Decimal("0")).named("a")
    b = (E(_y) >= Decimal("0")).named("b")
    composed = (a & b).named("composed")
    assert composed.label == "composed"
    # The sub-expressions are not mutated by composition
    assert a.label == "a"
    assert b.label == "b"


# ═══════════════════════════════════════════════════════════════════════════════
# 10. Vacuous truth — empty invariant list always SAT (no Z3 constraints added)
# ═══════════════════════════════════════════════════════════════════════════════


@given(xv=_decimal)
@settings(max_examples=100, deadline=None)
def test_empty_invariant_list_is_always_sat(xv: Decimal) -> None:
    """solve([], ...) with no invariants is always SAT — vacuous truth."""
    result = solve([], {"x": xv}, timeout_ms=5_000)
    assert result.sat is True, (
        f"Empty invariant list returned UNSAT — vacuous truth violated: x={xv}"
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 11. Subtraction anti-monotonicity — E(x) - E(y) >= 0 is SAT iff x >= y
# ═══════════════════════════════════════════════════════════════════════════════


@given(xv=_decimal, yv=_decimal)
@settings(max_examples=1_000, deadline=None)
def test_subtraction_non_negative_iff_ge(xv: Decimal, yv: Decimal) -> None:
    """E(x) - E(y) >= 0  iff  x >= y — core financial invariant."""
    inv = [(E(_x) - E(_y) >= Decimal("0")).named("non_negative_diff")]
    result = solve(inv, {"x": xv, "y": yv}, timeout_ms=5_000)
    expected = xv >= yv
    assert result.sat == expected, (
        f"Subtraction non-negativity mismatch: x={xv!r}, y={yv!r}, "
        f"expected={expected}, got={result.sat}"
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 12. Strict vs non-strict inequality duality — x > t is SAT iff x >= t+ε for Int
# ═══════════════════════════════════════════════════════════════════════════════


@given(nv=_int_val, threshold=_int_val)
@settings(max_examples=500, deadline=None)
def test_strict_gt_is_ge_plus_one_for_integers(nv: int, threshold: int) -> None:
    """For integers, n > t iff n >= t + 1 — strict and non-strict are duals."""
    inv_strict = [(E(_n) > threshold).named("strict")]
    inv_nonstrict = [(E(_n) >= threshold + 1).named("nonstrict")]

    result_strict = solve(inv_strict, {"n": nv}, timeout_ms=5_000)
    result_nonstrict = solve(inv_nonstrict, {"n": nv}, timeout_ms=5_000)

    assert result_strict.sat == result_nonstrict.sat, (
        f"Strict/non-strict duality violated: n={nv}, t={threshold}, "
        f"strict.sat={result_strict.sat}, nonstrict.sat={result_nonstrict.sat}"
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 13. Multi-invariant UNSAT attribution completeness
#     When N invariants all fail, all N labels appear in violated_invariants
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize("n_failing", [1, 2, 3, 5])
def test_all_failing_invariants_are_attributed(n_failing: int) -> None:
    """Every violated invariant gets its own label in violated_invariants.

    This tests the per-invariant solver attribution mechanism: if N invariants
    all fail, all N labels must appear in the result (not just a minimal core).
    """
    # All constraints require x >= 1 but we pass x = 0 so all fail
    inv = [
        (E(_x) >= Decimal("1")).named(f"inv_{i}")
        for i in range(n_failing)
    ]
    result = solve(inv, {"x": Decimal("0")}, timeout_ms=5_000)
    assert result.sat is False
    violated = {c.label for c in result.violated if c.label is not None}
    expected = {f"inv_{i}" for i in range(n_failing)}
    assert violated == expected, (
        f"Attribution incomplete: expected {expected}, got {violated}"
    )
