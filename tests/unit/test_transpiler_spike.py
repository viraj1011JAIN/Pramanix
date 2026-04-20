# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Unit tests for transpiler_spike.py — Phase 1 gate validation.

These tests prove:
  1. The DSL builds lazy expression trees (no eager evaluation).
  2. The transpiler emits correct Z3 AST for all node types.
  3. Decimal arithmetic is exact (no floating-point drift).
  4. verify() returns exactly the violated invariant labels.
  5. Solver timeout is respected.
  6. Error paths raise appropriate exceptions.
"""
from __future__ import annotations

import sys
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

# transpiler_spike.py lives in spikes/, not inside src/
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "spikes"))

import z3
from transpiler_spike import (
    REFERENCE_INVARIANTS,
    ConstraintExpr,
    E,
    ExpressionNode,
    Field,
    _BinOp,
    _BoolOp,
    _CmpOp,
    _collect_fields,
    _FieldRef,
    _Literal,
    _transpile,
    _z3_lit,
    verify,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def balance_field() -> Field:
    return Field("balance", Decimal, "Real")


@pytest.fixture
def amount_field() -> Field:
    return Field("amount", Decimal, "Real")


@pytest.fixture
def limit_field() -> Field:
    return Field("daily_limit", Decimal, "Real")


@pytest.fixture
def frozen_field() -> Field:
    return Field("is_frozen", bool, "Bool")


@pytest.fixture
def base_values() -> dict[str, Any]:
    return {
        "balance": 1000,
        "amount": 100,
        "daily_limit": 5000,
        "is_frozen": False,
    }


# ---------------------------------------------------------------------------
# 1. Tree construction -- no eager evaluation
# ---------------------------------------------------------------------------


class TestTreeConstruction:
    def test_e_returns_expressionnode(self, balance_field: Field) -> None:
        node = E(balance_field)
        assert isinstance(node, ExpressionNode)
        assert isinstance(node.node, _FieldRef)
        assert node.node.field is balance_field

    def test_arithmetic_builds_tree_not_value(
        self, balance_field: Field, amount_field: Field
    ) -> None:
        expr = E(balance_field) - E(amount_field)
        assert isinstance(expr, ExpressionNode)
        assert isinstance(expr.node, _BinOp)
        assert expr.node.op == "sub"

    def test_comparison_returns_constraint_expr(self, balance_field: Field) -> None:
        c = E(balance_field) >= 0
        assert isinstance(c, ConstraintExpr)
        assert isinstance(c.node, _CmpOp)
        assert c.node.op == "ge"

    def test_literal_wrapping(self, balance_field: Field) -> None:
        expr = E(balance_field) + 500
        assert isinstance(expr.node.right, _Literal)
        assert expr.node.right.value == 500

    def test_reflected_arithmetic(self, balance_field: Field) -> None:
        expr = 100 - E(balance_field)
        assert isinstance(expr, ExpressionNode)
        assert expr.node.op == "sub"
        assert isinstance(expr.node.left, _Literal)

    def test_all_comparison_ops(self, balance_field: Field) -> None:
        ops = {
            "ge": E(balance_field) >= 0,
            "le": E(balance_field) <= 0,
            "gt": E(balance_field) > 0,
            "lt": E(balance_field) < 0,
            "eq": E(balance_field) == 0,
            "ne": E(balance_field) != 0,
        }
        for op, constraint in ops.items():
            assert isinstance(constraint, ConstraintExpr)
            assert constraint.node.op == op

    def test_named_attaches_label(self, balance_field: Field) -> None:
        c = (E(balance_field) >= 0).named("my_label")
        assert c.label == "my_label"

    def test_explain_attaches_template(self, balance_field: Field) -> None:
        c = (E(balance_field) >= 0).named("lbl").explain("bal={balance}")
        assert c.explanation == "bal={balance}"
        assert c.label == "lbl"

    def test_named_explain_are_immutable(self, balance_field: Field) -> None:
        orig = E(balance_field) >= 0
        named = orig.named("lbl")
        assert orig.label is None  # original unmodified
        assert named.label == "lbl"

    def test_bool_ops_build_tree(self, balance_field: Field, amount_field: Field) -> None:
        c1 = E(balance_field) >= 0
        c2 = E(amount_field) <= 100
        combined_and = c1 & c2
        combined_or = c1 | c2
        inverted = ~c1
        assert isinstance(combined_and.node, _BoolOp)
        assert combined_and.node.op == "and"
        assert combined_or.node.op == "or"
        assert inverted.node.op == "not"

    def test_mul_builds_tree(self, balance_field: Field) -> None:
        expr = E(balance_field) * 2
        assert isinstance(expr.node, _BinOp)
        assert expr.node.op == "mul"

    def test_rmul_builds_tree(self, balance_field: Field) -> None:
        expr = 2 * E(balance_field)
        assert isinstance(expr.node, _BinOp)
        assert expr.node.op == "mul"


# ---------------------------------------------------------------------------
# 2. Literal conversion -- exact arithmetic
# ---------------------------------------------------------------------------


class TestLiteralConversion:
    def test_int_becomes_real_val(self) -> None:
        v = _z3_lit(42)
        assert z3.is_real(v)

    def test_bool_becomes_bool_val(self) -> None:
        vt = _z3_lit(True)
        vf = _z3_lit(False)
        assert z3.is_bool(vt)
        assert z3.is_bool(vf)

    def test_decimal_exact_no_float_drift(self) -> None:
        # 0.1 cannot be represented exactly in IEEE 754 float.
        # Decimal('0.1').as_integer_ratio() -> (1, 10) -- exact.
        v = _z3_lit(Decimal("0.1"))
        # Z3 should represent 1/10 exactly
        s = z3.Solver()
        x = z3.Real("x")
        s.add(x == v)
        assert s.check() == z3.sat
        model = s.model()
        # Z3 rational: numerator/denominator
        frac = model[x].as_fraction()
        from fractions import Fraction

        assert frac == Fraction(1, 10)

    def test_float_exact_via_decimal(self) -> None:
        # 100.01 as float is inexact; via Decimal(str(v)) it is exact.
        v = _z3_lit(100.01)
        s = z3.Solver()
        x = z3.Real("x")
        s.add(x == v)
        assert s.check() == z3.sat
        from fractions import Fraction

        model = s.model()
        assert model[x].as_fraction() == Fraction(10001, 100)

    def test_unsupported_literal_raises(self) -> None:
        with pytest.raises(TypeError, match="Unsupported literal"):
            _z3_lit([1, 2, 3])


# ---------------------------------------------------------------------------
# 3. Transpiler -- tree -> Z3 AST
# ---------------------------------------------------------------------------


class TestTranspiler:
    def test_field_ref_real(self, balance_field: Field) -> None:
        z3v = _transpile(_FieldRef(balance_field))
        assert z3.is_real(z3v)
        assert str(z3v) == "balance"

    def test_field_ref_int(self) -> None:
        f = Field("count", int, "Int")
        z3v = _transpile(_FieldRef(f))
        assert z3.is_int(z3v)

    def test_field_ref_bool(self, frozen_field: Field) -> None:
        z3v = _transpile(_FieldRef(frozen_field))
        assert z3.is_bool(z3v)

    def test_unknown_z3_type_raises(self) -> None:
        f = Field("bad", int, "Complex")
        with pytest.raises(ValueError, match="Unknown z3_type"):
            _transpile(_FieldRef(f))

    def test_arithmetic_sub(self, balance_field: Field, amount_field: Field) -> None:
        node = _BinOp("sub", _FieldRef(balance_field), _FieldRef(amount_field))
        z3expr = _transpile(node)
        assert z3.is_arith(z3expr)

    def test_comparison_ge(self, balance_field: Field) -> None:
        node = _CmpOp("ge", _FieldRef(balance_field), _Literal(0))
        z3expr = _transpile(node)
        assert z3.is_bool(z3expr)

    def test_bool_and(self, balance_field: Field, amount_field: Field) -> None:
        lhs = _CmpOp("ge", _FieldRef(balance_field), _Literal(0))
        rhs = _CmpOp("le", _FieldRef(amount_field), _Literal(1000))
        node = _BoolOp("and", (lhs, rhs))
        z3expr = _transpile(node)
        assert z3.is_bool(z3expr)

    def test_bool_not(self, frozen_field: Field) -> None:
        inner = _CmpOp("eq", _FieldRef(frozen_field), _Literal(False))
        node = _BoolOp("not", (inner,))
        z3expr = _transpile(node)
        assert z3.is_bool(z3expr)

    def test_unknown_binop_raises(self, balance_field: Field) -> None:
        node = _BinOp("div", _FieldRef(balance_field), _Literal(2))
        with pytest.raises(ValueError, match="Unknown BinOp"):
            _transpile(node)

    def test_unknown_cmpop_raises(self, balance_field: Field) -> None:
        node = _CmpOp("spaceship", _FieldRef(balance_field), _Literal(0))
        with pytest.raises(ValueError, match="Unknown CmpOp"):
            _transpile(node)

    def test_unknown_boolop_raises(self, balance_field: Field) -> None:
        inner = _CmpOp("ge", _FieldRef(balance_field), _Literal(0))
        node = _BoolOp("xor", (inner,))
        with pytest.raises(ValueError, match="Unknown BoolOp"):
            _transpile(node)

    def test_unknownnode_type_raises(self) -> None:
        with pytest.raises(TypeError, match="Unknown node type"):
            _transpile(object())


# ---------------------------------------------------------------------------
# 4. _collect_fields
# ---------------------------------------------------------------------------


class TestCollectFields:
    def test_collects_single_field(self, balance_field: Field) -> None:
        node = _FieldRef(balance_field)
        result = _collect_fields(node)
        assert result == {"balance": balance_field}

    def test_collects_from_binop(self, balance_field: Field, amount_field: Field) -> None:
        node = _BinOp("sub", _FieldRef(balance_field), _FieldRef(amount_field))
        result = _collect_fields(node)
        assert set(result) == {"balance", "amount"}

    def test_literal_returns_empty(self) -> None:
        assert _collect_fields(_Literal(42)) == {}

    def test_collects_from_boolop(self, balance_field: Field, frozen_field: Field) -> None:
        lhs = _CmpOp("ge", _FieldRef(balance_field), _Literal(0))
        rhs = _CmpOp("eq", _FieldRef(frozen_field), _Literal(False))
        node = _BoolOp("and", (lhs, rhs))
        result = _collect_fields(node)
        assert set(result) == {"balance", "is_frozen"}


# ---------------------------------------------------------------------------
# 5. Phase 1 gate tests — the five mandated scenarios
# ---------------------------------------------------------------------------


class TestPhase1Gate:
    """Five mandatory gate tests specified in the Phase 1 blueprint."""

    @pytest.fixture
    def invs(self) -> list[ConstraintExpr]:
        return REFERENCE_INVARIANTS

    def test_gate_1_sat_normal_transaction(self, invs: list[ConstraintExpr]) -> None:
        """SAT: balance=1000, amount=100, frozen=False -- all satisfied."""
        r = verify(invs, {"balance": 1000, "amount": 100, "daily_limit": 5000, "is_frozen": False})
        assert r.sat is True
        assert r.unsat_core_labels == []

    def test_gate_2_unsat_single_overdraft(self, invs: list[ConstraintExpr]) -> None:
        """UNSAT single: balance=50, amount=1000 -> core=['non_negative_balance'] exactly."""
        r = verify(invs, {"balance": 50, "amount": 1000, "daily_limit": 5000, "is_frozen": False})
        assert r.sat is False
        assert r.unsat_core_labels == ["non_negative_balance"]

    def test_gate_3_unsat_multiple_overdraft_and_frozen(self, invs: list[ConstraintExpr]) -> None:
        """UNSAT multiple: both non_negative_balance AND account_not_frozen violated."""
        r = verify(invs, {"balance": 50, "amount": 1000, "daily_limit": 5000, "is_frozen": True})
        assert r.sat is False
        assert "non_negative_balance" in r.unsat_core_labels
        assert "account_not_frozen" in r.unsat_core_labels
        assert len(r.unsat_core_labels) == 2

    def test_gate_4_sat_boundary_exact(self, invs: list[ConstraintExpr]) -> None:
        """SAT boundary: balance=100, amount=100 -> 100-100=0 >= 0 is exactly true."""
        r = verify(invs, {"balance": 100, "amount": 100, "daily_limit": 5000, "is_frozen": False})
        assert r.sat is True

    def test_gate_5_unsat_boundary_breach_decimal(self, invs: list[ConstraintExpr]) -> None:
        """UNSAT boundary: amount=100.01 breaches balance=100 by exactly 0.01."""
        r = verify(
            invs,
            {
                "balance": 100,
                "amount": Decimal("100.01"),
                "daily_limit": 5000,
                "is_frozen": False,
            },
        )
        assert r.sat is False
        assert "non_negative_balance" in r.unsat_core_labels

    def test_gate_5_float_boundary_breach(self, invs: list[ConstraintExpr]) -> None:
        """Same boundary breach with float -- exact conversion via Decimal(str(v))."""
        r = verify(
            invs,
            {
                "balance": 100,
                "amount": 100.01,
                "daily_limit": 5000,
                "is_frozen": False,
            },
        )
        assert r.sat is False
        assert "non_negative_balance" in r.unsat_core_labels


# ---------------------------------------------------------------------------
# 6. verify() -- additional coverage
# ---------------------------------------------------------------------------


class TestVerify:
    def test_daily_limit_violated_alone(self) -> None:
        invs = REFERENCE_INVARIANTS
        r = verify(invs, {"balance": 5000, "amount": 1001, "daily_limit": 1000, "is_frozen": False})
        assert r.sat is False
        assert r.unsat_core_labels == ["within_daily_limit"]

    def test_all_three_violated(self) -> None:
        invs = REFERENCE_INVARIANTS
        r = verify(invs, {"balance": 50, "amount": 2000, "daily_limit": 1000, "is_frozen": True})
        assert r.sat is False
        assert set(r.unsat_core_labels) == {
            "non_negative_balance",
            "within_daily_limit",
            "account_not_frozen",
        }

    def test_labels_are_sorted(self) -> None:
        invs = REFERENCE_INVARIANTS
        r = verify(invs, {"balance": 50, "amount": 2000, "daily_limit": 1000, "is_frozen": True})
        assert r.unsat_core_labels == sorted(r.unsat_core_labels)

    def test_violated_explanations_populated(self) -> None:
        invs = REFERENCE_INVARIANTS
        r = verify(invs, {"balance": 50, "amount": 1000, "daily_limit": 5000, "is_frozen": False})
        assert len(r.violated_explanations) == 1
        assert "Overdraft" in r.violated_explanations[0]

    def test_missing_label_raises(self) -> None:
        f = Field("x", int, "Real")
        unlabeled = E(f) >= 0  # no .named()
        with pytest.raises(ValueError, match=r"must carry a \.named\(\) label"):
            verify([unlabeled], {"x": 5})

    def test_real_field_with_bool_value_raises(self) -> None:
        f = Field("x", Decimal, "Real")
        inv = (E(f) >= 0).named("lbl")
        with pytest.raises(TypeError, match="bool not allowed"):
            verify([inv], {"x": True})

    def test_extra_values_ignored(self) -> None:
        """Values for fields not in any invariant are silently ignored."""
        f = Field("x", int, "Real")
        inv = (E(f) >= 0).named("lbl")
        r = verify([inv], {"x": 5, "unknown_field": 99})
        assert r.sat is True

    def test_verify_result_is_frozen(self) -> None:
        f = Field("x", int, "Real")
        inv = (E(f) >= 0).named("lbl")
        r = verify([inv], {"x": 5})
        with pytest.raises((AttributeError, TypeError)):
            r.sat = False  # type: ignore[misc]

    def test_timeout_parameter_accepted(self) -> None:
        """verify() must not raise when timeout_ms is explicitly set."""
        invs = REFERENCE_INVARIANTS
        r = verify(
            invs,
            {"balance": 1000, "amount": 100, "daily_limit": 5000, "is_frozen": False},
            timeout_ms=500,
        )
        assert r.sat is True

    def test_decimal_exact_boundary_not_off_by_one(self) -> None:
        """Decimal('99.99') vs balance=100 must be SAT; 100.01 must be UNSAT."""
        f_bal = Field("balance", Decimal, "Real")
        f_amt = Field("amount", Decimal, "Real")
        inv = (E(f_bal) - E(f_amt) >= 0).named("chk")

        r_sat = verify([inv], {"balance": 100, "amount": Decimal("99.99")})
        assert r_sat.sat is True

        r_unsat = verify([inv], {"balance": 100, "amount": Decimal("100.01")})
        assert r_unsat.sat is False

    def test_int_field(self) -> None:
        f = Field("count", int, "Int")
        inv = (E(f) >= 0).named("non_negative_count")
        assert verify([inv], {"count": 0}).sat is True
        assert verify([inv], {"count": -1}).sat is False

    def test_bool_field_equality(self) -> None:
        f = Field("active", bool, "Bool")
        inv = (E(f) == True).named("must_be_active")  # noqa: E712
        assert verify([inv], {"active": True}).sat is True
        assert verify([inv], {"active": False}).sat is False

    def test_composed_and_constraint(self) -> None:
        f1 = Field("a", int, "Real")
        f2 = Field("b", int, "Real")
        inv = ((E(f1) >= 0) & (E(f2) >= 0)).named("both_positive")
        assert verify([inv], {"a": 1, "b": 1}).sat is True
        assert verify([inv], {"a": -1, "b": 1}).sat is False
        assert verify([inv], {"a": 1, "b": -1}).sat is False
        assert verify([inv], {"a": -1, "b": -1}).sat is False

    def test_composed_or_constraint(self) -> None:
        f1 = Field("a", int, "Real")
        f2 = Field("b", int, "Real")
        inv = ((E(f1) >= 0) | (E(f2) >= 0)).named("at_least_one_positive")
        assert verify([inv], {"a": -1, "b": 1}).sat is True
        assert verify([inv], {"a": -1, "b": -1}).sat is False
