# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Unit tests for pramanix.expressions — DSL tree building."""
from __future__ import annotations

from decimal import Decimal

import pytest

from pramanix.exceptions import PolicyCompilationError
from pramanix.expressions import (
    ConstraintExpr,
    E,
    ExpressionNode,
    Field,
    _BinOp,
    _BoolOp,
    _FieldRef,
    _InOp,
    _Literal,
)

# ── Shared fixtures ────────────────────────────────────────────────────────────

_balance = Field("balance", Decimal, "Real")
_amount = Field("amount", Decimal, "Real")
_flag = Field("active", bool, "Bool")
_count = Field("count", int, "Int")


# ── Field ──────────────────────────────────────────────────────────────────────


class TestField:
    def test_stores_name(self) -> None:
        assert _balance.name == "balance"

    def test_stores_python_type(self) -> None:
        assert _balance.python_type is Decimal

    def test_stores_z3_type(self) -> None:
        assert _balance.z3_type == "Real"

    def test_frozen_cannot_reassign(self) -> None:
        with pytest.raises((AttributeError, TypeError)):
            _balance.name = "other"  # type: ignore[misc]

    def test_equality_by_value(self) -> None:
        f1 = Field("x", int, "Int")
        f2 = Field("x", int, "Int")
        assert f1 == f2

    def test_hash_stable(self) -> None:
        f = Field("x", int, "Int")
        s: set[Field] = {f}
        assert f in s


# ── E() and ExpressionNode leaf ───────────────────────────────────────────────


class TestEFactory:
    def test_returns_expression_node(self) -> None:
        assert isinstance(E(_balance), ExpressionNode)

    def test_node_is_field_ref(self) -> None:
        node = E(_balance).node
        assert isinstance(node, _FieldRef)
        assert node.field is _balance


# ── Arithmetic operators ───────────────────────────────────────────────────────


class TestArithmetic:
    def test_add_field_field(self) -> None:
        expr = E(_balance) + E(_amount)
        assert isinstance(expr, ExpressionNode)
        assert isinstance(expr.node, _BinOp)
        assert expr.node.op == "add"

    def test_radd_int_field(self) -> None:
        expr = 100 + E(_balance)
        assert isinstance(expr.node, _BinOp)
        assert expr.node.op == "add"
        assert isinstance(expr.node.left, _Literal)
        assert expr.node.left.value == 100

    def test_sub_field_literal(self) -> None:
        expr = E(_balance) - 50
        assert expr.node.op == "sub"
        assert isinstance(expr.node.right, _Literal)
        assert expr.node.right.value == 50

    def test_rsub(self) -> None:
        expr = 1000 - E(_amount)
        assert expr.node.op == "sub"
        assert isinstance(expr.node.left, _Literal)

    def test_mul_field_literal(self) -> None:
        expr = E(_balance) * 2
        assert expr.node.op == "mul"

    def test_rmul(self) -> None:
        expr = 2 * E(_balance)
        assert expr.node.op == "mul"
        assert isinstance(expr.node.left, _Literal)

    def test_truediv_field_literal(self) -> None:
        expr = E(_balance) / 100
        assert expr.node.op == "div"

    def test_rtruediv(self) -> None:
        expr = 1 / E(_balance)
        assert expr.node.op == "div"
        assert isinstance(expr.node.left, _Literal)

    def test_chained_arithmetic(self) -> None:
        expr = (E(_balance) - E(_amount)) * 2
        assert expr.node.op == "mul"
        assert isinstance(expr.node.left, _BinOp)
        assert expr.node.left.op == "sub"


# ── Comparison operators (produce ConstraintExpr) ─────────────────────────────


class TestComparisons:
    def test_ge_returns_constraint_expr(self) -> None:
        c = E(_balance) >= 0
        assert isinstance(c, ConstraintExpr)
        assert c.node.op == "ge"

    def test_le(self) -> None:
        c = E(_amount) <= E(_balance)
        assert c.node.op == "le"

    def test_gt(self) -> None:
        c = E(_balance) > 0
        assert c.node.op == "gt"

    def test_lt(self) -> None:
        c = E(_amount) < 1000
        assert c.node.op == "lt"

    def test_eq_bool_field(self) -> None:
        c = E(_flag) == False  # noqa: E712
        assert c.node.op == "eq"
        assert isinstance(c.node.right, _Literal)
        assert c.node.right.value is False

    def test_ne(self) -> None:
        c = E(_count) != 0
        assert c.node.op == "ne"


# ── ConstraintExpr — named / explain ──────────────────────────────────────────


class TestConstraintExpr:
    def test_no_label_by_default(self) -> None:
        c = E(_balance) >= 0
        assert c.label is None

    def test_named_sets_label(self) -> None:
        c = (E(_balance) >= 0).named("non_negative")
        assert c.label == "non_negative"

    def test_named_returns_new_instance(self) -> None:
        original = E(_balance) >= 0
        labelled = original.named("lbl")
        assert original is not labelled
        assert original.label is None

    def test_explain_sets_template(self) -> None:
        c = (E(_balance) >= 0).named("lbl").explain("balance={balance}")
        assert c.explanation == "balance={balance}"

    def test_explain_returns_new_instance(self) -> None:
        c = (E(_balance) >= 0).named("lbl")
        explained = c.explain("template")
        assert c is not explained
        assert c.explanation is None

    def test_chain_named_explain(self) -> None:
        c = (E(_balance) >= 0).named("check").explain("msg")
        assert c.label == "check"
        assert c.explanation == "msg"

    def test_named_preserves_explanation(self) -> None:
        c = (E(_balance) >= 0).explain("msg").named("lbl")
        assert c.explanation == "msg"
        assert c.label == "lbl"


# ── Boolean combinators ────────────────────────────────────────────────────────


class TestBooleanCombinators:
    def test_and_produces_bool_op(self) -> None:
        c = (E(_balance) >= 0) & (E(_amount) <= 1000)
        assert isinstance(c, ConstraintExpr)
        assert isinstance(c.node, _BoolOp)
        assert c.node.op == "and"
        assert len(c.node.operands) == 2

    def test_or_produces_bool_op(self) -> None:
        c = (E(_balance) >= 0) | (E(_flag) == True)  # noqa: E712
        assert c.node.op == "or"

    def test_invert_produces_bool_op(self) -> None:
        c = ~(E(_flag) == True)  # noqa: E712
        assert isinstance(c, ConstraintExpr)
        assert c.node.op == "not"
        assert len(c.node.operands) == 1

    def test_combined_label_dropped_on_and(self) -> None:
        # Composite expressions start unlabelled; label at the top level.
        c = (E(_balance) >= 0).named("a") & (E(_amount) <= 1000).named("b")
        assert c.label is None


# ── ExpressionNode identity / hash ────────────────────────────────────────────


class TestExpressionNodeHash:
    def test_two_distinct_nodes_can_be_in_set(self) -> None:
        n1 = E(_balance)
        n2 = E(_amount)
        s = {n1, n2}
        assert len(s) == 2

    def test_same_node_identity(self) -> None:
        n = E(_balance)
        assert hash(n) == hash(n)


# ── __bool__ trap — ExpressionNode ────────────────────────────────────────────


class TestExpressionNodeBoolTrap:
    """ExpressionNode.__bool__ must raise TypeError unconditionally.

    Python's implicit coercion rules mean that without this trap,
    ``if E(x):`` evaluates the node as truthy (non-None object → True),
    silently discarding the lazy constraint tree.
    """

    def test_bool_raises_type_error(self) -> None:
        with pytest.raises(TypeError):
            bool(E(_balance))

    def test_if_statement_raises(self) -> None:
        node = E(_balance)
        with pytest.raises(TypeError):
            if node:  # type: ignore[truthy-bool,unused-ignore]
                pass

    def test_not_raises(self) -> None:
        with pytest.raises(TypeError):
            not E(_balance)  # type: ignore[truthy-bool,unused-ignore]

    def test_and_keyword_raises_on_first_operand(self) -> None:
        # Python short-circuits: evaluates left operand's __bool__ first
        with pytest.raises(TypeError):
            _ = E(_balance) and E(_amount)  # type: ignore[truthy-bool,unused-ignore]

    def test_or_keyword_raises_on_first_operand(self) -> None:
        with pytest.raises(TypeError):
            _ = E(_balance) or E(_amount)  # type: ignore[truthy-bool,unused-ignore]

    def test_error_message_mentions_comparison_operators(self) -> None:
        with pytest.raises(TypeError, match="comparison operators"):
            bool(E(_balance))

    def test_error_message_mentions_bitwise_and(self) -> None:
        with pytest.raises(TypeError, match=r"&"):
            bool(E(_balance))

    def test_arithmetic_result_also_raises(self) -> None:
        """Arithmetic ExpressionNode (not just leaf) must also be protected."""
        expr = E(_balance) - E(_amount)
        with pytest.raises(TypeError):
            bool(expr)


# ── __bool__ trap — ConstraintExpr ────────────────────────────────────────────


class TestConstraintExprBoolTrap:
    """ConstraintExpr.__bool__ must raise TypeError unconditionally.

    The critical failure mode without this trap:
      ``(E(a) > 0) and (E(b) > 0)``
    Python evaluates ``__bool__`` on the first operand. Without the guard
    it returns ``True`` (non-None object) and then returns the *second*
    ConstraintExpr as the expression's value — silently dropping the first
    constraint. This trap prevents that exact bug.
    """

    def test_bool_raises_type_error(self) -> None:
        with pytest.raises(TypeError):
            bool(E(_balance) >= 0)

    def test_if_statement_raises(self) -> None:
        c = E(_balance) >= 0
        with pytest.raises(TypeError):
            if c:  # type: ignore[truthy-bool,unused-ignore]
                pass

    def test_not_keyword_raises(self) -> None:
        with pytest.raises(TypeError):
            not (E(_balance) >= 0)  # type: ignore[truthy-bool,unused-ignore]

    def test_and_keyword_silently_drops_constraint_is_prevented(self) -> None:
        """The critical silent-drop bug is prevented."""
        c1 = E(_balance) >= 0
        c2 = E(_amount) <= 1000
        with pytest.raises(TypeError):
            _ = c1 and c2  # type: ignore[truthy-bool,unused-ignore]

    def test_or_keyword_raises_on_first_operand(self) -> None:
        c1 = E(_balance) >= 0
        c2 = E(_amount) <= 1000
        with pytest.raises(TypeError):
            _ = c1 or c2  # type: ignore[truthy-bool,unused-ignore]

    def test_error_message_mentions_bitwise_and(self) -> None:
        with pytest.raises(TypeError, match=r"&"):
            bool(E(_balance) >= 0)

    def test_error_message_warns_against_and_keyword(self) -> None:
        with pytest.raises(TypeError, match="'and'"):
            bool(E(_balance) >= 0)

    def test_labelled_constraint_also_raises(self) -> None:
        c = (E(_balance) >= 0).named("non_negative")
        with pytest.raises(TypeError):
            bool(c)

    def test_combined_constraint_also_raises(self) -> None:
        """&-combined ConstraintExpr must also be protected."""
        c = (E(_balance) >= 0) & (E(_amount) <= 1000)
        with pytest.raises(TypeError):
            bool(c)


# ── __pow__ ban ───────────────────────────────────────────────────────────────


class TestExpressionNodePowBan:
    """ExpressionNode.__pow__ and __rpow__ must raise PolicyCompilationError.

    Z3's real/integer arithmetic does not support symbolic exponentiation.
    Catching this at policy-definition time (not at solver runtime) gives
    the developer an immediate, actionable error message.
    """

    def test_pow_raises_policy_compilation_error(self) -> None:
        with pytest.raises(PolicyCompilationError):
            _ = E(_balance) ** 2  # type: ignore[operator,unused-ignore]

    def test_rpow_raises_policy_compilation_error(self) -> None:
        with pytest.raises(PolicyCompilationError):
            _ = 2 ** E(_balance)  # type: ignore[operator,unused-ignore]

    def test_pow_error_message_mentions_exponentiation(self) -> None:
        with pytest.raises(PolicyCompilationError, match="exponentiation"):
            _ = E(_balance) ** 3  # type: ignore[operator,unused-ignore]

    def test_pow_error_message_mentions_z3(self) -> None:
        with pytest.raises(PolicyCompilationError, match="Z3"):
            _ = E(_balance) ** 2  # type: ignore[operator,unused-ignore]

    def test_pow_error_is_policy_compilation_error_subclass(self) -> None:
        from pramanix.exceptions import PolicyError

        with pytest.raises(PolicyError):
            _ = E(_balance) ** 2  # type: ignore[operator,unused-ignore]

    def test_rpow_error_message_mentions_exponentiation(self) -> None:
        with pytest.raises(PolicyCompilationError, match="exponentiation"):
            _ = 2 ** E(_count)  # type: ignore[operator,unused-ignore]

    def test_pow_does_not_return_expression_node(self) -> None:
        """Confirm no accidental fallthrough to a numeric result."""
        try:
            result = E(_balance) ** 2  # type: ignore[operator,unused-ignore]
        except PolicyCompilationError:
            pass  # expected
        else:
            pytest.fail(f"Expected PolicyCompilationError, got {result!r}")

    @pytest.mark.parametrize("exponent", [0, 1, 2, 10, -1, 0.5])
    def test_pow_banned_for_all_exponent_values(self, exponent: object) -> None:
        with pytest.raises(PolicyCompilationError):
            _ = E(_balance) ** exponent  # type: ignore[operator,unused-ignore]


# ── is_in() helper ────────────────────────────────────────────────────────────


class TestIsIn:
    """ExpressionNode.is_in() happy-path, AST structure, and error cases."""

    def test_returns_constraint_expr(self) -> None:
        c = E(_count).is_in([1, 2, 3])
        assert isinstance(c, ConstraintExpr)

    def test_node_is_in_op(self) -> None:
        c = E(_count).is_in([1, 2, 3])
        assert isinstance(c.node, _InOp)

    def test_in_op_left_is_field_ref(self) -> None:
        from pramanix.expressions import _FieldRef

        c = E(_count).is_in([10, 20])
        assert isinstance(c.node.left, _FieldRef)
        assert c.node.left.field is _count

    def test_in_op_values_are_literals(self) -> None:
        from pramanix.expressions import _Literal

        c = E(_count).is_in([7, 8, 9])
        assert all(isinstance(v, _Literal) for v in c.node.values)

    def test_in_op_values_count_matches_input(self) -> None:
        c = E(_count).is_in([1, 2, 3, 4, 5])
        assert len(c.node.values) == 5

    def test_in_op_values_preserve_order(self) -> None:

        vals = [3, 1, 4, 1, 5]
        c = E(_count).is_in(vals)
        assert [v.value for v in c.node.values] == vals  # type: ignore[attr-defined,unused-ignore]

    def test_single_value_allowed(self) -> None:
        c = E(_count).is_in([42])
        assert isinstance(c, ConstraintExpr)
        assert len(c.node.values) == 1

    def test_no_label_by_default(self) -> None:
        c = E(_count).is_in([1, 2])
        assert c.label is None

    def test_named_can_be_chained(self) -> None:
        c = E(_count).is_in([1, 2]).named("allowed_codes")
        assert c.label == "allowed_codes"

    def test_explain_can_be_chained(self) -> None:
        c = E(_count).is_in([1, 2]).named("check").explain("code must be 1 or 2")
        assert c.explanation == "code must be 1 or 2"

    def test_empty_list_raises_policy_compilation_error(self) -> None:
        with pytest.raises(PolicyCompilationError):
            E(_count).is_in([])

    def test_empty_list_error_message_is_descriptive(self) -> None:
        with pytest.raises(PolicyCompilationError, match="empty"):
            E(_count).is_in([])

    def test_tuple_input_accepted(self) -> None:
        c = E(_count).is_in((1, 2, 3))
        assert len(c.node.values) == 3

    def test_generator_input_accepted(self) -> None:
        c = E(_count).is_in(x for x in range(3))
        assert len(c.node.values) == 3

    def test_decimal_values_accepted(self) -> None:
        from decimal import Decimal

        c = E(_balance).is_in([Decimal("100.00"), Decimal("200.00")])
        assert len(c.node.values) == 2

    def test_mixed_type_values_stored(self) -> None:
        """is_in does not validate types — the transpiler is responsible."""
        c = E(_count).is_in([1, "two", 3.0])
        assert len(c.node.values) == 3

    def test_result_can_be_combined_with_and(self) -> None:
        c = E(_count).is_in([1, 2]) & (E(_balance) >= 0)
        assert isinstance(c, ConstraintExpr)

    def test_result_can_be_combined_with_or(self) -> None:
        c = E(_count).is_in([1, 2]) | (E(_balance) >= 0)
        assert isinstance(c, ConstraintExpr)

    def test_result_bool_trap_still_active(self) -> None:
        """is_in result is a ConstraintExpr — __bool__ must still raise."""
        c = E(_count).is_in([1, 2, 3])
        with pytest.raises(TypeError):
            bool(c)
