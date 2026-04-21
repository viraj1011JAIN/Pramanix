# SPDX-License-Identifier: AGPL-3.0-only
# Phase A-1: Tests for POW/MOD DSL operators (_PowOp, _ModOp)
"""Verifies that ** and % work end-to-end from DSL through Z3 transpilation."""
from __future__ import annotations

import pytest

from pramanix import E, Field, Policy
from pramanix.exceptions import PolicyCompilationError
from pramanix.expressions import ExpressionNode, _ModOp, _PowOp

# ── AST node construction ─────────────────────────────────────────────────────


class TestPowOpASTConstruction:
    def _field_expr(self) -> ExpressionNode:
        f = Field("x", int, "Int")
        return E(f)

    def test_pow_creates_pow_op_node(self) -> None:
        """E(x) ** 2 produces an ExpressionNode wrapping a _PowOp."""
        expr = self._field_expr() ** 2
        assert isinstance(expr.node, _PowOp)
        assert expr.node.exp == 2

    def test_pow_degree_1_allowed(self) -> None:
        """Degree 1 is the identity — still valid."""
        expr = self._field_expr() ** 1
        assert isinstance(expr.node, _PowOp)

    def test_pow_degree_4_allowed(self) -> None:
        """Degree 4 is the maximum allowed."""
        expr = self._field_expr() ** 4
        assert expr.node.exp == 4

    def test_pow_degree_5_raises(self) -> None:
        """Degree 5 exceeds maximum; raises PolicyCompilationError."""
        with pytest.raises(PolicyCompilationError, match=r"\[1, 4\]"):
            self._field_expr() ** 5

    def test_pow_degree_0_raises(self) -> None:
        """Degree 0 is not in [1, 4]; raises PolicyCompilationError."""
        with pytest.raises(PolicyCompilationError, match=r"\[1, 4\]"):
            self._field_expr() ** 0

    def test_pow_float_exponent_raises(self) -> None:
        """Float exponent raises PolicyCompilationError."""
        with pytest.raises(PolicyCompilationError, match="plain integer"):
            self._field_expr() ** 2.0  # type: ignore[operator]

    def test_rpow_raises(self) -> None:
        """Reflected pow (literal ** E(x)) raises PolicyCompilationError."""
        with pytest.raises(PolicyCompilationError, match="reflected"):
            _ = 2 ** self._field_expr()  # type: ignore[operator]

    def test_bool_exponent_raises(self) -> None:
        """Bool exponent (which is a subclass of int) raises PolicyCompilationError."""
        with pytest.raises(PolicyCompilationError, match="plain integer"):
            self._field_expr() ** True  # type: ignore[operator]


class TestModOpASTConstruction:
    def _field_expr(self) -> ExpressionNode:
        f = Field("n", int, "Int")
        return E(f)

    def test_mod_creates_mod_op_node(self) -> None:
        """E(n) % 3 produces an ExpressionNode wrapping a _ModOp."""
        expr = self._field_expr() % 3
        assert isinstance(expr.node, _ModOp)

    def test_rmod_creates_mod_op_node(self) -> None:
        """Reflected: 10 % E(n) also produces a _ModOp."""
        expr = 10 % self._field_expr()
        assert isinstance(expr.node, _ModOp)

    def test_mod_expr_expr(self) -> None:
        """E(n) % E(m) produces a _ModOp."""
        m = E(Field("m", int, "Int"))
        n = self._field_expr()
        expr = n % m
        assert isinstance(expr.node, _ModOp)


# ── Z3 transpilation ──────────────────────────────────────────────────────────


class TestPowOpTranspilation:
    def test_pow2_transpiles_without_error(self) -> None:
        """(E(x) ** 2) compiles to a Z3 expression."""
        import z3

        from pramanix.transpiler import transpile

        f = Field("x", int, "Int")
        expr = E(f) ** 2
        result = transpile(expr.node)
        assert isinstance(result, z3.ExprRef)

    def test_pow3_transpiles_without_error(self) -> None:
        """(E(x) ** 3) compiles to a Z3 expression."""
        import z3

        from pramanix.transpiler import transpile

        f = Field("x", int, "Int")
        expr = E(f) ** 3
        result = transpile(expr.node)
        assert isinstance(result, z3.ExprRef)


class TestModOpTranspilation:
    def test_mod_int_transpiles(self) -> None:
        """(E(n) % 3) on an Int-sorted field transpiles without error."""
        import z3

        from pramanix.transpiler import transpile

        f = Field("n", int, "Int")
        expr = E(f) % 3
        result = transpile(expr.node)
        assert isinstance(result, z3.ExprRef)


# ── End-to-end Policy verification ───────────────────────────────────────────


class TestPowE2E:
    """Full Guard round-trip for POW constraints."""

    def test_x_squared_geq_zero_is_always_satisfiable(self) -> None:
        """x**2 >= 0 is always SAT (tautology for real/int arithmetic)."""
        from pramanix import Guard, GuardConfig

        class QuadPolicy(Policy):
            x = Field("x", int, "Int")

            @classmethod
            def invariants(cls):
                return [(E(cls.x) ** 2 >= 0).named("sq_non_neg")]

        g = Guard(QuadPolicy, config=GuardConfig(execution_mode="sync"))
        d = g.verify(intent={"x": 5}, state={})
        assert d.allowed

    def test_x_squared_lt_zero_is_never_allowed(self) -> None:
        """x**2 < 0 is UNSAT — should block."""
        from pramanix import Guard, GuardConfig

        class NegSqPolicy(Policy):
            x = Field("x", int, "Int")

            @classmethod
            def invariants(cls):
                return [(E(cls.x) ** 2 < 0).named("neg_sq")]

        g = Guard(NegSqPolicy, config=GuardConfig(execution_mode="sync"))
        d = g.verify(intent={"x": 3}, state={})
        assert not d.allowed

    def test_quadratic_compound(self) -> None:
        """x**2 - x >= 0 holds for x=5 (25 - 5 = 20 ≥ 0)."""
        from pramanix import Guard, GuardConfig

        class QuadComp(Policy):
            x = Field("x", int, "Int")

            @classmethod
            def invariants(cls):
                return [((E(cls.x) ** 2 - E(cls.x)) >= 0).named("quad_comp")]

        g = Guard(QuadComp, config=GuardConfig(execution_mode="sync"))
        d = g.verify(intent={"x": 5}, state={})
        assert d.allowed


class TestModE2E:
    """Full Guard round-trip for MOD constraints."""

    def test_even_number_passes(self) -> None:
        """n % 2 == 0 should ALLOW n=4."""
        from pramanix import Guard, GuardConfig

        class EvenPolicy(Policy):
            n = Field("n", int, "Int")

            @classmethod
            def invariants(cls):
                return [(E(cls.n) % 2 == 0).named("even")]

        g = Guard(EvenPolicy, config=GuardConfig(execution_mode="sync"))
        d = g.verify(intent={"n": 4}, state={})
        assert d.allowed

    def test_odd_number_blocked(self) -> None:
        """n % 2 == 0 should BLOCK n=3 (3 is odd)."""
        from pramanix import Guard, GuardConfig

        class EvenPolicy(Policy):
            n = Field("n", int, "Int")

            @classmethod
            def invariants(cls):
                return [(E(cls.n) % 2 == 0).named("even")]

        g = Guard(EvenPolicy, config=GuardConfig(execution_mode="sync"))
        d = g.verify(intent={"n": 3}, state={})
        assert not d.allowed
