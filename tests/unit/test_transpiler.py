# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Unit tests for pramanix.transpiler."""
from __future__ import annotations

from decimal import Decimal

import pytest
import z3

from pramanix.exceptions import FieldTypeError, TranspileError
from pramanix.expressions import (
    ConstraintExpr,
    E,
    ExpressionNode,
    Field,
    _BinOp,
    _BoolOp,
    _CmpOp,
    _FieldRef,
    _Literal,
)
from pramanix.transpiler import collect_fields, transpile, z3_val, z3_var

# ── Shared fields ──────────────────────────────────────────────────────────────

_balance = Field("balance", Decimal, "Real")
_amount = Field("amount", Decimal, "Real")
_count = Field("count", int, "Int")
_flag = Field("active", bool, "Bool")


def _sat(formula: z3.ExprRef) -> bool:
    """Helper: is the formula satisfiable in isolation?"""
    s = z3.Solver()
    s.add(formula)
    return bool(s.check() == z3.sat)


def _is_unsat(formula: z3.ExprRef) -> bool:
    s = z3.Solver()
    s.add(formula)
    return bool(s.check() == z3.unsat)


# ── z3_var ─────────────────────────────────────────────────────────────────────


class TestZ3Var:
    def test_real_field(self) -> None:
        v = z3_var(_balance)
        assert z3.is_real(v)
        assert str(v) == "balance"

    def test_int_field(self) -> None:
        v = z3_var(_count)
        assert z3.is_int(v)
        assert str(v) == "count"

    def test_bool_field(self) -> None:
        v = z3_var(_flag)
        assert z3.is_bool(v)
        assert str(v) == "active"

    def test_unknown_z3_type_raises(self) -> None:
        bad = Field("x", int, "Float")  # type: ignore[arg-type]
        with pytest.raises(FieldTypeError, match="Unknown z3_type"):
            z3_var(bad)


# ── z3_val ─────────────────────────────────────────────────────────────────────


class TestZ3Val:
    def test_bool_field_true(self) -> None:
        v = z3_val(_flag, True)
        assert z3.is_true(v)

    def test_bool_field_false(self) -> None:
        v = z3_val(_flag, False)
        assert z3.is_false(v)

    def test_int_field(self) -> None:
        v = z3_val(_count, 42)
        assert z3.is_int_value(v)
        assert v.as_long() == 42

    def test_real_from_decimal(self) -> None:
        v = z3_val(_balance, Decimal("100.25"))
        assert z3.is_rational_value(v)

    def test_real_from_float(self) -> None:
        v = z3_val(_balance, 0.1)
        assert z3.is_rational_value(v)
        # 0.1 must NOT be 3602879701896397/36028797018963968 (IEEE 754 drift)
        frac = v.as_fraction()
        assert frac.denominator == 10  # exact: 1/10

    def test_real_from_int(self) -> None:
        v = z3_val(_balance, 500)
        assert z3.is_rational_value(v)

    def test_real_rejects_bool(self) -> None:
        with pytest.raises(FieldTypeError, match="bool"):
            z3_val(_balance, True)

    def test_unknown_z3_type_raises(self) -> None:
        bad = Field("x", int, "Float")  # type: ignore[arg-type]
        with pytest.raises(FieldTypeError):
            z3_val(bad, 1)


# ── transpile — leaf nodes ─────────────────────────────────────────────────────


class TestTranspileLeaves:
    def test_field_ref_real(self) -> None:
        expr = transpile(_FieldRef(_balance))
        assert z3.is_real(expr)

    def test_field_ref_bool(self) -> None:
        expr = transpile(_FieldRef(_flag))
        assert z3.is_bool(expr)

    def test_literal_bool(self) -> None:
        expr = transpile(_Literal(True))
        assert z3.is_bool(expr)

    def test_literal_decimal(self) -> None:
        expr = transpile(_Literal(Decimal("3.14")))
        assert z3.is_rational_value(expr)

    def test_literal_float_exact(self) -> None:
        expr = transpile(_Literal(0.5))
        frac = expr.as_fraction()
        assert frac.numerator == 1 and frac.denominator == 2

    def test_literal_int(self) -> None:
        expr = transpile(_Literal(42))
        assert z3.is_rational_value(expr)

    def test_literal_unknown_type_raises(self) -> None:
        with pytest.raises(FieldTypeError):
            transpile(_Literal("not-a-number"))

    def test_unknown_node_type_raises(self) -> None:
        with pytest.raises(TranspileError, match="Unknown DSL AST node type"):
            transpile(object())


# ── transpile — arithmetic (BinOp) ────────────────────────────────────────────


class TestTranspileBinOp:
    def _make_bool(self, op: str) -> z3.ExprRef:
        """Wrap arithmetic BinOp in >= 0 to produce a Boolean for the solver."""
        return transpile(_CmpOp("ge", _BinOp(op, _FieldRef(_balance), _Literal(100)), _Literal(0)))

    def test_add_transpiles_without_error(self) -> None:
        assert _sat(self._make_bool("add"))

    def test_sub_transpiles_without_error(self) -> None:
        assert _sat(self._make_bool("sub"))

    def test_mul_transpiles_without_error(self) -> None:
        assert _sat(self._make_bool("mul"))

    def test_div_transpiles_without_error(self) -> None:
        assert _sat(self._make_bool("div"))

    def test_unknown_binop_raises(self) -> None:
        with pytest.raises(TranspileError, match="Unknown BinOp operator"):
            transpile(_BinOp("mod", _FieldRef(_balance), _Literal(10)))

    def test_add_produces_correct_z3(self) -> None:
        # balance + 100 >= 50 is SAT when balance == 0
        add_expr = transpile(_BinOp("add", _FieldRef(_balance), _Literal(100)))
        s = z3.Solver()
        s.add(z3.Real("balance") == z3.RealVal(0))
        s.add(add_expr >= z3.RealVal(50))
        assert s.check() == z3.sat

    def test_div_new_operator(self) -> None:
        # balance / amount >= 0 is SAT (positive values)
        expr = transpile(
            _CmpOp("ge", _BinOp("div", _FieldRef(_balance), _FieldRef(_amount)), _Literal(0))
        )
        assert _sat(expr)


# ── transpile — comparisons (CmpOp) ───────────────────────────────────────────


class TestTranspileCmpOp:
    def _cmp(self, op: str, rhs: int = 0) -> z3.ExprRef:
        return transpile(_CmpOp(op, _FieldRef(_balance), _Literal(rhs)))

    def test_ge_produces_bool(self) -> None:
        assert z3.is_bool(self._cmp("ge"))

    def test_le_produces_bool(self) -> None:
        assert z3.is_bool(self._cmp("le"))

    def test_gt_produces_bool(self) -> None:
        assert z3.is_bool(self._cmp("gt"))

    def test_lt_produces_bool(self) -> None:
        assert z3.is_bool(self._cmp("lt"))

    def test_eq_produces_bool(self) -> None:
        assert z3.is_bool(self._cmp("eq"))

    def test_ne_produces_bool(self) -> None:
        assert z3.is_bool(self._cmp("ne"))

    def test_unknown_cmpop_raises(self) -> None:
        with pytest.raises(TranspileError, match="Unknown CmpOp operator"):
            transpile(_CmpOp("spaceship", _FieldRef(_balance), _Literal(0)))

    def test_ge_correct_semantics(self) -> None:
        # balance >= 100 should be UNSAT when balance == 50
        formula = transpile(_CmpOp("ge", _FieldRef(_balance), _Literal(100)))
        s = z3.Solver()
        s.add(z3.Real("balance") == z3.RealVal(50))
        s.add(formula)
        assert s.check() == z3.unsat

    def test_eq_bool_field(self) -> None:
        # active == False — valid for Bool-sorted field
        formula = transpile(_CmpOp("eq", _FieldRef(_flag), _Literal(False)))
        s = z3.Solver()
        s.add(z3.Bool("active") == z3.BoolVal(True))
        s.add(formula)
        assert s.check() == z3.unsat  # active=True but formula says active=False


# ── transpile — boolean combinators (BoolOp) ──────────────────────────────────


class TestTranspileBoolOp:
    def test_and_produces_bool(self) -> None:
        a = _CmpOp("ge", _FieldRef(_balance), _Literal(0))
        b = _CmpOp("le", _FieldRef(_amount), _Literal(1000))
        expr = transpile(_BoolOp("and", (a, b)))
        assert z3.is_bool(expr)

    def test_or_produces_bool(self) -> None:
        a = _CmpOp("ge", _FieldRef(_balance), _Literal(0))
        b = _CmpOp("eq", _FieldRef(_flag), _Literal(False))
        expr = transpile(_BoolOp("or", (a, b)))
        assert z3.is_bool(expr)

    def test_not_produces_bool(self) -> None:
        a = _CmpOp("eq", _FieldRef(_flag), _Literal(True))
        expr = transpile(_BoolOp("not", (a,)))
        assert z3.is_bool(expr)

    def test_unknown_boolop_raises(self) -> None:
        a = _CmpOp("ge", _FieldRef(_balance), _Literal(0))
        with pytest.raises(TranspileError, match="Unknown BoolOp operator"):
            transpile(_BoolOp("xor", (a,)))

    def test_and_correct_semantics(self) -> None:
        # balance >= 100 AND amount <= 50: SAT when balance=200, amount=10
        and_expr = transpile(
            _BoolOp(
                "and",
                (
                    _CmpOp("ge", _FieldRef(_balance), _Literal(100)),
                    _CmpOp("le", _FieldRef(_amount), _Literal(50)),
                ),
            )
        )
        s = z3.Solver()
        s.add(z3.Real("balance") == z3.RealVal(200))
        s.add(z3.Real("amount") == z3.RealVal(10))
        s.add(and_expr)
        assert s.check() == z3.sat


# ── collect_fields ─────────────────────────────────────────────────────────────


class TestCollectFields:
    def test_single_field_ref(self) -> None:
        result = collect_fields(_FieldRef(_balance))
        assert result == {"balance": _balance}

    def test_literal_returns_empty(self) -> None:
        assert collect_fields(_Literal(42)) == {}

    def test_binop_both_sides(self) -> None:
        node = _BinOp("sub", _FieldRef(_balance), _FieldRef(_amount))
        result = collect_fields(node)
        assert "balance" in result
        assert "amount" in result

    def test_cmpop_both_sides(self) -> None:
        node = _CmpOp("ge", _FieldRef(_balance), _Literal(0))
        result = collect_fields(node)
        assert "balance" in result
        assert len(result) == 1

    def test_boolop_all_operands(self) -> None:
        a = _CmpOp("ge", _FieldRef(_balance), _Literal(0))
        b = _CmpOp("le", _FieldRef(_amount), _Literal(1000))
        c = _CmpOp("eq", _FieldRef(_flag), _Literal(False))
        node = _BoolOp("and", (a, b, c))
        result = collect_fields(node)
        assert set(result) == {"balance", "amount", "active"}

    def test_unknown_node_returns_empty(self) -> None:
        assert collect_fields(object()) == {}

    def test_full_constraint_expr_node(self) -> None:
        expr: ConstraintExpr = (E(_balance) - E(_amount) >= 0).named("check")
        result = collect_fields(expr.node)
        assert set(result) == {"balance", "amount"}

    def test_expression_node_wrapped(self) -> None:
        node: ExpressionNode = E(_balance) + E(_amount)
        result = collect_fields(node.node)
        assert "balance" in result
        assert "amount" in result
