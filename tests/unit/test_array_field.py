# SPDX-License-Identifier: AGPL-3.0-only
# Phase A-3: Tests for ArrayField, ForAll, Exists quantifiers
"""Gate tests: BasketTradePolicy ForAll must ALLOW all-positive and BLOCK any-negative."""
from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest

from pramanix.exceptions import PolicyCompilationError, ValidationError
from pramanix.expressions import (
    ArrayField,
    ConstraintExpr,
    E,
    Exists,
    Field,
    ForAll,
    _ExistsOp,
    _ForAllOp,
)

# ── Shared fixtures ───────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def amounts_field() -> ArrayField:
    return ArrayField("amounts", Decimal, "Real", max_length=10)


@pytest.fixture(scope="module")
def flags_field() -> ArrayField:
    return ArrayField("flags", bool, "Bool", max_length=5)


# ── ArrayField construction ───────────────────────────────────────────────────


class TestArrayField:
    def test_basic_attributes(self, amounts_field: ArrayField) -> None:
        assert amounts_field.name == "amounts"
        assert amounts_field.element_type is Decimal
        assert amounts_field.z3_sort == "Real"
        assert amounts_field.max_length == 10

    def test_element_field_naming(self, amounts_field: ArrayField) -> None:
        f0 = amounts_field.element_field(0)
        f3 = amounts_field.element_field(3)
        assert f0.name == "amounts_0"
        assert f3.name == "amounts_3"

    def test_element_field_type(self, amounts_field: ArrayField) -> None:
        f = amounts_field.element_field(0)
        assert isinstance(f, Field)
        assert f.z3_type == "Real"
        assert f.python_type is Decimal

    def test_max_length_zero_raises(self) -> None:
        with pytest.raises(PolicyCompilationError, match="max_length must be >= 1"):
            ArrayField("x", int, "Int", max_length=0)

    def test_max_length_negative_raises(self) -> None:
        with pytest.raises(PolicyCompilationError, match="max_length must be >= 1"):
            ArrayField("x", int, "Int", max_length=-5)

    def test_frozen(self, amounts_field: ArrayField) -> None:
        with pytest.raises(Exception):
            amounts_field.max_length = 99  # type: ignore[misc]


# ── ForAll / Exists construction ──────────────────────────────────────────────


class TestQuantifierConstruction:
    def test_forall_produces_constraint_expr(self, amounts_field: ArrayField) -> None:
        expr = ForAll(amounts_field, lambda a: E(a) >= Decimal("0"))
        assert isinstance(expr, ConstraintExpr)
        assert isinstance(expr.node, _ForAllOp)

    def test_exists_produces_constraint_expr(self, amounts_field: ArrayField) -> None:
        expr = Exists(amounts_field, lambda a: E(a) > Decimal("0"))
        assert isinstance(expr, ConstraintExpr)
        assert isinstance(expr.node, _ExistsOp)

    def test_forall_named(self, amounts_field: ArrayField) -> None:
        expr = ForAll(amounts_field, lambda a: E(a) >= Decimal("0")).named("all_non_negative")
        assert expr.label == "all_non_negative"

    def test_forall_non_array_field_raises(self) -> None:
        plain = Field("x", Decimal, "Real")
        with pytest.raises(PolicyCompilationError, match="ArrayField"):
            ForAll(plain, lambda a: E(a) >= Decimal("0"))  # type: ignore[arg-type]

    def test_forall_non_callable_raises(self, amounts_field: ArrayField) -> None:
        with pytest.raises(PolicyCompilationError, match="callable"):
            ForAll(amounts_field, "not a function")  # type: ignore[arg-type]

    def test_exists_non_array_field_raises(self) -> None:
        plain = Field("x", Decimal, "Real")
        with pytest.raises(PolicyCompilationError, match="ArrayField"):
            Exists(plain, lambda a: E(a) >= Decimal("0"))  # type: ignore[arg-type]

    def test_exists_non_callable_raises(self, amounts_field: ArrayField) -> None:
        with pytest.raises(PolicyCompilationError, match="callable"):
            Exists(amounts_field, 42)  # type: ignore[arg-type]


# ── Gate: BasketTradePolicy — full Guard integration ─────────────────────────


def _make_basket_guard(max_length: int = 10) -> Any:
    """Create a Guard with ForAll(amounts >= 0) policy."""
    from pramanix.guard import Guard, GuardConfig
    from pramanix.policy import Policy

    amounts = ArrayField("amounts", Decimal, "Real", max_length=max_length)

    class BasketPolicy(Policy):
        @classmethod
        def invariants(cls) -> list[ConstraintExpr]:
            return [
                ForAll(amounts, lambda a: E(a) >= Decimal("0")).named("all_non_negative"),
            ]

    return Guard(BasketPolicy, GuardConfig(solver_timeout_ms=5000))


class TestForAllGuardIntegration:
    """Gate condition: ALLOW all-positive, BLOCK any-negative."""

    def test_all_positive_is_allowed(self) -> None:
        guard = _make_basket_guard()
        d = guard.verify(intent={"amounts": [Decimal("10"), Decimal("20"), Decimal("5")]}, state={})
        assert d.allowed is True

    def test_all_positive_single_element(self) -> None:
        guard = _make_basket_guard()
        d = guard.verify(intent={"amounts": [Decimal("1")]}, state={})
        assert d.allowed is True

    def test_zero_is_allowed(self) -> None:
        guard = _make_basket_guard()
        d = guard.verify(intent={"amounts": [Decimal("0"), Decimal("5")]}, state={})
        assert d.allowed is True

    def test_any_negative_is_blocked(self) -> None:
        guard = _make_basket_guard()
        d = guard.verify(intent={"amounts": [Decimal("10"), Decimal("-1"), Decimal("5")]}, state={})
        assert d.allowed is False

    def test_first_negative_is_blocked(self) -> None:
        guard = _make_basket_guard()
        d = guard.verify(intent={"amounts": [Decimal("-5"), Decimal("10")]}, state={})
        assert d.allowed is False

    def test_last_negative_is_blocked(self) -> None:
        guard = _make_basket_guard()
        d = guard.verify(intent={"amounts": [Decimal("10"), Decimal("20"), Decimal("-3")]}, state={})
        assert d.allowed is False

    def test_empty_array_vacuously_allowed(self) -> None:
        guard = _make_basket_guard()
        d = guard.verify(intent={"amounts": []}, state={})
        assert d.allowed is True

    def test_full_array_at_max_length(self) -> None:
        guard = _make_basket_guard(max_length=5)
        d = guard.verify(intent={"amounts": [Decimal("1")] * 5}, state={})
        assert d.allowed is True

    def test_overflow_is_blocked(self) -> None:
        guard = _make_basket_guard(max_length=5)
        d = guard.verify(intent={"amounts": [Decimal("1")] * 6}, state={})
        assert d.allowed is False

    def test_wrong_type_is_blocked(self) -> None:
        guard = _make_basket_guard()
        d = guard.verify(intent={"amounts": "not-a-list"}, state={})
        assert d.allowed is False

    def test_violated_invariant_name_reported(self) -> None:
        guard = _make_basket_guard()
        d = guard.verify(intent={"amounts": [Decimal("-1")]}, state={})
        assert d.allowed is False
        assert "all_non_negative" in d.violated_invariants


# ── Gate: Exists integration ──────────────────────────────────────────────────


def _make_exists_guard() -> Any:
    """Guard requiring at least one positive amount."""
    from pramanix.guard import Guard, GuardConfig
    from pramanix.policy import Policy

    amounts = ArrayField("amounts", Decimal, "Real", max_length=10)

    class AnyPositivePolicy(Policy):
        @classmethod
        def invariants(cls) -> list[ConstraintExpr]:
            return [
                Exists(amounts, lambda a: E(a) > Decimal("0")).named("has_positive"),
            ]

    return Guard(AnyPositivePolicy, GuardConfig(solver_timeout_ms=5000))


class TestExistsGuardIntegration:
    def test_one_positive_allowed(self) -> None:
        guard = _make_exists_guard()
        d = guard.verify(intent={"amounts": [Decimal("0"), Decimal("5"), Decimal("-1")]}, state={})
        assert d.allowed is True

    def test_all_negative_blocked(self) -> None:
        guard = _make_exists_guard()
        d = guard.verify(intent={"amounts": [Decimal("-1"), Decimal("-2")]}, state={})
        assert d.allowed is False

    def test_empty_array_blocked(self) -> None:
        guard = _make_exists_guard()
        d = guard.verify(intent={"amounts": []}, state={})
        assert d.allowed is False

    def test_single_positive_allowed(self) -> None:
        guard = _make_exists_guard()
        d = guard.verify(intent={"amounts": [Decimal("1")]}, state={})
        assert d.allowed is True


# ── Hypothesis: random arrays produce no exceptions ───────────────────────────


class TestHypothesisArrayRobustness:
    """Arrays of any length up to max_length must never raise — only ALLOW or BLOCK."""

    def _check_no_exception(self, values: list[Decimal], max_length: int) -> None:
        guard = _make_basket_guard(max_length=max_length)
        d = guard.verify(intent={"amounts": values}, state={})
        assert d.allowed in (True, False)

    def test_random_arrays_length_1_to_max(self) -> None:
        import random
        rng = random.Random(42)
        for _ in range(50):
            n = rng.randint(1, 8)
            vals = [Decimal(str(rng.uniform(-10, 10))) for _ in range(n)]
            self._check_no_exception(vals, max_length=8)

    def test_all_zeros(self) -> None:
        self._check_no_exception([Decimal("0")] * 10, max_length=10)

    def test_single_element_positive(self) -> None:
        self._check_no_exception([Decimal("1")], max_length=10)

    def test_single_element_negative(self) -> None:
        self._check_no_exception([Decimal("-1")], max_length=10)

    def test_max_length_exactly_reached(self) -> None:
        guard = _make_basket_guard(max_length=3)
        d = guard.verify(intent={"amounts": [Decimal("1"), Decimal("2"), Decimal("3")]}, state={})
        assert d.allowed is True

    def test_max_length_exceeded_by_one(self) -> None:
        guard = _make_basket_guard(max_length=3)
        d = guard.verify(intent={"amounts": [Decimal("1")] * 4}, state={})
        assert d.allowed is False


# ── Solver pre-processing unit tests ──────────────────────────────────────────


class TestSolverPreprocessing:
    def test_expand_values(self) -> None:
        from pramanix.solver import _preprocess_invariants

        af = ArrayField("items", int, "Int", max_length=5)
        inv = ForAll(af, lambda a: E(a) >= 0).named("all_non_neg")
        _, expanded = _preprocess_invariants([inv], {"items": [10, 20, 30]})
        assert expanded.get("items_0") == 10
        assert expanded.get("items_1") == 20
        assert expanded.get("items_2") == 30
        assert "items" not in expanded

    def test_overflow_raises_validation_error(self) -> None:
        from pramanix.solver import _preprocess_invariants

        af = ArrayField("items", int, "Int", max_length=3)
        inv = ForAll(af, lambda a: E(a) >= 0).named("ok")
        with pytest.raises(ValidationError, match="exceeds"):
            _preprocess_invariants([inv], {"items": [1, 2, 3, 4]})

    def test_wrong_type_raises_validation_error(self) -> None:
        from pramanix.solver import _preprocess_invariants

        af = ArrayField("items", int, "Int", max_length=3)
        inv = ForAll(af, lambda a: E(a) >= 0).named("ok")
        with pytest.raises(ValidationError, match="list or tuple"):
            _preprocess_invariants([inv], {"items": "oops"})

    def test_no_array_fields_passthrough(self) -> None:
        from pramanix.solver import _preprocess_invariants

        plain = Field("x", int, "Int")
        inv = (E(plain) >= 0).named("non_neg")
        values = {"x": 5}
        realized, expanded = _preprocess_invariants([inv], values)
        assert expanded is values  # unchanged

    def test_missing_array_key_treated_as_empty(self) -> None:
        from pramanix.solver import _preprocess_invariants

        af = ArrayField("items", int, "Int", max_length=5)
        inv = ForAll(af, lambda a: E(a) >= 0).named("ok")
        _, expanded = _preprocess_invariants([inv], {})
        assert "items" not in expanded
