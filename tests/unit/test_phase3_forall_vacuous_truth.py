# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Phase 3 STOP 4 tests: ForAll vacuous-truth exploit is closed.

Verifies:
1. ForAll(empty_array) returns BLOCK by default (fail-closed).
2. ForAll(empty_array, allow_empty=True) returns ALLOW (explicit opt-in).
3. Non-empty array behaviour is unchanged by the fix.
4. Exists(empty_array) continues to return BLOCK (already correct, regression).
5. Full Guard.verify() with a ForAll policy and empty array returns BLOCK.
6. Full Guard.verify() with ForAll(allow_empty=True) and empty array returns ALLOW.
7. ForAll with allow_empty=False is the keyword-only argument correctly enforced.
8. _realize_node is the single point of fix — no Z3 leak for empty-array exploit.

Design rules
------------
* No mocks, no stubs, no unittest.mock imports.
* All solver tests go through the real Z3 stack via real Guard/Policy.
"""

from __future__ import annotations

from decimal import Decimal

import pytest

from pramanix.expressions import (
    ArrayField,
    ConstraintExpr,
    E,
    Field,
    ForAll,
    Exists,
    _ForAllOp,
)
from pramanix.policy import Policy
from pramanix.solver import _realize_node, _Literal, _BoolOp


# ══════════════════════════════════════════════════════════════════════════════
# 1 & 2. _ForAllOp.allow_empty field and _realize_node behaviour
# ══════════════════════════════════════════════════════════════════════════════


class TestForAllOpAllowEmptyField:
    """_ForAllOp carries allow_empty and _realize_node respects it."""

    def _make_array_field(self, name: str = "items") -> ArrayField:
        return ArrayField(name, Decimal, z3_sort="Real", max_length=10)

    def test_default_allow_empty_is_false(self) -> None:
        af = self._make_array_field()
        op = _ForAllOp(array_field=af, predicate=lambda f: E(f) >= 0)
        assert op.allow_empty is False

    def test_explicit_allow_empty_true_stored(self) -> None:
        af = self._make_array_field()
        op = _ForAllOp(array_field=af, predicate=lambda f: E(f) >= 0, allow_empty=True)
        assert op.allow_empty is True

    def test_empty_array_allow_empty_false_returns_literal_false(self) -> None:
        af = self._make_array_field()
        op = _ForAllOp(array_field=af, predicate=lambda f: E(f) >= 0, allow_empty=False)
        result = _realize_node(op, {af.name: []})
        assert isinstance(result, _Literal)
        assert result.value is False

    def test_empty_array_allow_empty_true_returns_literal_true(self) -> None:
        af = self._make_array_field()
        op = _ForAllOp(array_field=af, predicate=lambda f: E(f) >= 0, allow_empty=True)
        result = _realize_node(op, {af.name: []})
        assert isinstance(result, _Literal)
        assert result.value is True

    def test_empty_array_key_missing_allow_empty_false_returns_literal_false(self) -> None:
        """Missing key in values dict is treated as empty array → BLOCK."""
        af = self._make_array_field()
        op = _ForAllOp(array_field=af, predicate=lambda f: E(f) >= 0, allow_empty=False)
        result = _realize_node(op, {})  # key absent
        assert isinstance(result, _Literal)
        assert result.value is False

    def test_nonempty_array_returns_and_of_constraints(self) -> None:
        af = ArrayField("xs", Decimal, z3_sort="Real", max_length=5)
        op = _ForAllOp(array_field=af, predicate=lambda f: E(f) >= 0)
        result = _realize_node(op, {af.name: [Decimal("1"), Decimal("2")]})
        # Two elements → _BoolOp("and", ...)
        assert isinstance(result, _BoolOp)
        assert result.op == "and"
        assert len(result.operands) == 2

    def test_single_element_array_returns_single_constraint(self) -> None:
        af = ArrayField("xs", Decimal, z3_sort="Real", max_length=5)
        op = _ForAllOp(array_field=af, predicate=lambda f: E(f) >= 0)
        result = _realize_node(op, {af.name: [Decimal("5")]})
        # One element → not wrapped in _BoolOp
        assert not isinstance(result, _BoolOp)


# ══════════════════════════════════════════════════════════════════════════════
# 3. ForAll() public API propagates allow_empty
# ══════════════════════════════════════════════════════════════════════════════


class TestForAllAPIAllowEmpty:
    """ForAll() correctly passes allow_empty to _ForAllOp."""

    def test_default_allow_empty_false(self) -> None:
        af = ArrayField("xs", Decimal, z3_sort="Real", max_length=5)
        expr = ForAll(af, lambda f: E(f) >= 0)
        assert expr.node.allow_empty is False

    def test_explicit_allow_empty_true(self) -> None:
        af = ArrayField("xs", Decimal, z3_sort="Real", max_length=5)
        expr = ForAll(af, lambda f: E(f) >= 0, allow_empty=True)
        assert expr.node.allow_empty is True

    def test_allow_empty_is_keyword_only(self) -> None:
        """allow_empty must be passed as a keyword argument."""
        af = ArrayField("xs", Decimal, z3_sort="Real", max_length=5)
        with pytest.raises(TypeError):
            ForAll(af, lambda f: E(f) >= 0, True)  # positional → TypeError


# ══════════════════════════════════════════════════════════════════════════════
# 4. Exists(empty_array) regression — still returns BLOCK (already correct)
# ══════════════════════════════════════════════════════════════════════════════


class TestExistsEmptyArrayRegression:
    """Exists over empty array was already fail-closed — verify it remains so."""

    def test_exists_empty_returns_false(self) -> None:
        from pramanix.expressions import _ExistsOp

        af = ArrayField("ys", Decimal, z3_sort="Real", max_length=5)
        op = _ExistsOp(array_field=af, predicate=lambda f: E(f) >= 0)
        result = _realize_node(op, {af.name: []})
        assert isinstance(result, _Literal)
        assert result.value is False

    def test_exists_nonempty_returns_or_of_constraints(self) -> None:
        from pramanix.expressions import _ExistsOp

        af = ArrayField("ys", Decimal, z3_sort="Real", max_length=5)
        op = _ExistsOp(array_field=af, predicate=lambda f: E(f) >= 0)
        result = _realize_node(op, {af.name: [Decimal("1"), Decimal("2")]})
        assert isinstance(result, _BoolOp)
        assert result.op == "or"


# ══════════════════════════════════════════════════════════════════════════════
# 5. Full Guard.verify() — empty array is blocked by default
# ══════════════════════════════════════════════════════════════════════════════


class TestGuardForAllEmptyArrayBlocked:
    """Guard.verify() with a ForAll policy and empty array returns BLOCK."""

    def _make_guard(self, allow_empty: bool = False):
        from pramanix.guard import Guard
        from pramanix.guard_config import GuardConfig

        class _AmountsPolicy(Policy):
            amounts = ArrayField("amounts", Decimal, z3_sort="Real", max_length=20)

            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [
                    ForAll(
                        cls.amounts,
                        lambda amt: E(amt) >= Decimal("0"),
                        allow_empty=allow_empty,
                    ).named("all_non_negative")
                ]

        return Guard(_AmountsPolicy, GuardConfig())

    def test_empty_array_returns_block_by_default(self) -> None:
        from pramanix.decision import SolverStatus

        guard = self._make_guard(allow_empty=False)
        decision = guard.verify(intent={"amounts": []}, state={})
        assert not decision.allowed
        assert decision.status == SolverStatus.UNSAFE

    def test_nonempty_valid_array_returns_allow(self) -> None:
        from pramanix.decision import SolverStatus

        guard = self._make_guard(allow_empty=False)
        decision = guard.verify(
            intent={"amounts": [Decimal("10"), Decimal("20")]}, state={}
        )
        assert decision.allowed
        assert decision.status == SolverStatus.SAFE

    def test_nonempty_invalid_array_returns_block(self) -> None:
        from pramanix.decision import SolverStatus

        guard = self._make_guard(allow_empty=False)
        decision = guard.verify(
            intent={"amounts": [Decimal("10"), Decimal("-5")]}, state={}
        )
        assert not decision.allowed
        assert decision.status == SolverStatus.UNSAFE

    def test_exploit_empty_array_no_longer_bypasses_policy(self) -> None:
        """Regression: before STOP 4 fix, empty array returned ALLOW (vacuous truth).

        An attacker who submits {"amounts": []} must receive BLOCK, not ALLOW.
        """
        guard = self._make_guard(allow_empty=False)
        decision = guard.verify(intent={"amounts": []}, state={})
        assert not decision.allowed, (
            "Security regression: empty array satisfied ForAll vacuously "
            "(STOP 4 fix missing or reverted)"
        )


# ══════════════════════════════════════════════════════════════════════════════
# 6. Full Guard.verify() — empty array allowed with allow_empty=True
# ══════════════════════════════════════════════════════════════════════════════


class TestGuardForAllAllowEmptyOptIn:
    """Guard.verify() with ForAll(allow_empty=True) and empty array returns ALLOW."""

    def _make_guard_allow_empty(self):
        from pramanix.guard import Guard
        from pramanix.guard_config import GuardConfig

        class _PaymentsPolicy(Policy):
            payments = ArrayField("payments", Decimal, z3_sort="Real", max_length=20)

            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [
                    ForAll(
                        cls.payments,
                        lambda p: E(p) >= Decimal("0"),
                        allow_empty=True,
                    ).named("all_payments_non_negative_or_none")
                ]

        return Guard(_PaymentsPolicy, GuardConfig())

    def test_empty_array_returns_allow_when_opted_in(self) -> None:
        from pramanix.decision import SolverStatus

        guard = self._make_guard_allow_empty()
        decision = guard.verify(intent={"payments": []}, state={})
        assert decision.allowed
        assert decision.status == SolverStatus.SAFE

    def test_nonempty_valid_array_still_returns_allow(self) -> None:
        from pramanix.decision import SolverStatus

        guard = self._make_guard_allow_empty()
        decision = guard.verify(
            intent={"payments": [Decimal("100"), Decimal("200")]}, state={}
        )
        assert decision.allowed
        assert decision.status == SolverStatus.SAFE

    def test_nonempty_invalid_array_still_blocked(self) -> None:
        from pramanix.decision import SolverStatus

        guard = self._make_guard_allow_empty()
        decision = guard.verify(
            intent={"payments": [Decimal("100"), Decimal("-1")]}, state={}
        )
        assert not decision.allowed
        assert decision.status == SolverStatus.UNSAFE


# ══════════════════════════════════════════════════════════════════════════════
# 7. Mixed policies: one ForAll default-closed, one allow_empty
# ══════════════════════════════════════════════════════════════════════════════


class TestGuardMixedForAllPolicies:
    """Policies with both default and allow_empty=True ForAll invariants."""

    def _make_mixed_guard(self):
        from pramanix.guard import Guard
        from pramanix.guard_config import GuardConfig

        class _MixedPolicy(Policy):
            required = ArrayField("required", Decimal, z3_sort="Real", max_length=10)
            optional = ArrayField("optional", Decimal, z3_sort="Real", max_length=10)

            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [
                    ForAll(
                        cls.required,
                        lambda x: E(x) >= Decimal("0"),
                        allow_empty=False,
                    ).named("required_all_non_negative"),
                    ForAll(
                        cls.optional,
                        lambda x: E(x) >= Decimal("0"),
                        allow_empty=True,
                    ).named("optional_all_non_negative"),
                ]

        return Guard(_MixedPolicy, GuardConfig())

    def test_required_empty_blocks_even_with_optional_valid(self) -> None:
        guard = self._make_mixed_guard()
        decision = guard.verify(
            intent={"required": [], "optional": [Decimal("5")]}, state={}
        )
        assert not decision.allowed

    def test_optional_empty_allowed_when_required_valid(self) -> None:
        from pramanix.decision import SolverStatus

        guard = self._make_mixed_guard()
        decision = guard.verify(
            intent={"required": [Decimal("1")], "optional": []}, state={}
        )
        assert decision.allowed
        assert decision.status == SolverStatus.SAFE

    def test_both_empty_blocks_due_to_required(self) -> None:
        guard = self._make_mixed_guard()
        decision = guard.verify(
            intent={"required": [], "optional": []}, state={}
        )
        assert not decision.allowed
