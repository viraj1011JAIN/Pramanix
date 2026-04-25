# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Gate tests for Phase B-3: Cross-Policy Constraint Sharing via @invariant_mixin.

Gate condition (from engineering plan):
    pytest -k 'invariant_mixin'
    # AccountSafetyMixin must compose into two different Policy classes
    # without duplication.
    # Removing a required field must raise PolicyCompilationError at
    # Guard.__init__ time, not at verify() time.

Coverage targets
----------------
* @invariant_mixin decorator preserves function identity and sets flag
* Mixin composes into a Policy (invariants() returns own + mixin constraints)
* Same mixin composes into two independent policies without cross-contamination
* Two different mixins both applied to one policy
* Mixin returning single ConstraintExpr (not a list) is handled
* Mixin returning list[ConstraintExpr] is handled
* Policy with ONLY mixin invariants (no own invariants) works
* Policy.validate() passes on a correctly composed policy
* Missing field raises PolicyCompilationError at Guard.__init__ time
* Error message names the mixin, the missing field, and the policy
* Non-callable mixin raises PolicyCompilationError at Guard.__init__ time
* Guard ALLOW when own AND mixin invariants satisfied
* Guard BLOCK when own invariant violated
* Guard BLOCK when mixin invariant violated
* Guard BLOCK when both violated
* Duplicate label (own vs mixin) raises InvariantLabelError via validate()
* Duplicate label (mixin vs mixin) raises InvariantLabelError via validate()
* invariant_mixin is importable from pramanix top-level package
"""
from __future__ import annotations

from decimal import Decimal

import pytest

from pramanix import E, Field, Guard, GuardConfig, Policy, invariant_mixin
from pramanix.exceptions import InvariantLabelError, PolicyCompilationError
from pramanix.expressions import ConstraintExpr

# ═══════════════════════════════════════════════════════════════════════════════
# Shared fixtures
# ═══════════════════════════════════════════════════════════════════════════════

_balance_field = Field("balance", Decimal, "Real")
_amount_field = Field("amount", Decimal, "Real")
_is_frozen_field = Field("is_frozen", bool, "Bool")

_ALLOW_FUNDS = {"balance": Decimal("1000"), "amount": Decimal("100")}
_BLOCK_FUNDS = {"balance": Decimal("50"), "amount": Decimal("500")}
_ALLOW_FROZEN = {"balance": Decimal("1000"), "amount": Decimal("100"), "is_frozen": False}
_BLOCK_FROZEN = {"balance": Decimal("1000"), "amount": Decimal("100"), "is_frozen": True}


# ═══════════════════════════════════════════════════════════════════════════════
# @invariant_mixin decorator basics
# ═══════════════════════════════════════════════════════════════════════════════


class TestInvariantMixinDecorator:
    def test_decorator_returns_same_function(self) -> None:
        def my_mixin(fields: dict) -> list[ConstraintExpr]:
            return []

        result = invariant_mixin(my_mixin)
        assert result is my_mixin

    def test_decorator_sets_is_invariant_mixin_flag(self) -> None:
        @invariant_mixin
        def my_mixin(fields: dict) -> list[ConstraintExpr]:
            return []

        assert getattr(my_mixin, "_is_invariant_mixin", False) is True

    def test_decorated_function_still_callable(self) -> None:
        @invariant_mixin
        def my_mixin(fields: dict[str, Field]) -> list[ConstraintExpr]:
            return [(E(fields["balance"]) >= 0).named("pos")]

        result = my_mixin({"balance": _balance_field})
        assert len(result) == 1
        assert result[0].label == "pos"

    def test_importable_from_top_level_package(self) -> None:
        from pramanix import invariant_mixin as _im

        assert callable(_im)


# ═══════════════════════════════════════════════════════════════════════════════
# Mixin composition into Policy
# ═══════════════════════════════════════════════════════════════════════════════


class TestPolicyMixinComposition:
    def test_mixin_constraints_appended_to_own_invariants(self) -> None:
        @invariant_mixin
        def SafetyMixin(fields: dict[str, Field]) -> list[ConstraintExpr]:
            return [(E(fields["balance"]) >= 0).named("non_neg_balance")]

        class _P(Policy, mixins=[SafetyMixin]):
            balance = Field("balance", Decimal, "Real")
            amount = Field("amount", Decimal, "Real")

            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [(E(cls.amount) <= Decimal("10000")).named("max_tx")]

        labels = {i.label for i in _P.invariants()}
        assert "max_tx" in labels
        assert "non_neg_balance" in labels

    def test_mixin_constraints_are_at_end_of_list(self) -> None:
        @invariant_mixin
        def MixinA(fields: dict[str, Field]) -> list[ConstraintExpr]:
            return [(E(fields["balance"]) >= 0).named("mixin_constraint")]

        class _P(Policy, mixins=[MixinA]):
            balance = Field("balance", Decimal, "Real")
            amount = Field("amount", Decimal, "Real")

            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [(E(cls.amount) >= 0).named("own_constraint")]

        invs = _P.invariants()
        assert invs[0].label == "own_constraint"
        assert invs[1].label == "mixin_constraint"

    def test_same_mixin_into_two_policies_no_cross_contamination(self) -> None:
        @invariant_mixin
        def AccountSafetyMixin(fields: dict[str, Field]) -> list[ConstraintExpr]:
            return [(E(fields["balance"]) >= 0).named("non_neg_balance")]

        class _PolicyA(Policy, mixins=[AccountSafetyMixin]):
            balance = Field("balance", Decimal, "Real")
            amount = Field("amount", Decimal, "Real")

            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [(E(cls.amount) <= Decimal("1000")).named("max_tx_a")]

        class _PolicyB(Policy, mixins=[AccountSafetyMixin]):
            balance = Field("balance", Decimal, "Real")
            amount = Field("amount", Decimal, "Real")

            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [(E(cls.amount) <= Decimal("5000")).named("max_tx_b")]

        labels_a = {i.label for i in _PolicyA.invariants()}
        labels_b = {i.label for i in _PolicyB.invariants()}

        assert "non_neg_balance" in labels_a
        assert "max_tx_a" in labels_a
        assert "non_neg_balance" in labels_b
        assert "max_tx_b" in labels_b
        # No cross-contamination
        assert "max_tx_b" not in labels_a
        assert "max_tx_a" not in labels_b

    def test_two_mixins_both_applied(self) -> None:
        @invariant_mixin
        def MixinA(fields: dict[str, Field]) -> list[ConstraintExpr]:
            return [(E(fields["balance"]) >= 0).named("non_neg_balance")]

        @invariant_mixin
        def MixinB(fields: dict[str, Field]) -> ConstraintExpr:
            return (E(fields["is_frozen"]) == False).named("not_frozen")  # noqa: E712

        class _P(Policy, mixins=[MixinA, MixinB]):
            balance = Field("balance", Decimal, "Real")
            amount = Field("amount", Decimal, "Real")
            is_frozen = Field("is_frozen", bool, "Bool")

            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [(E(cls.amount) <= Decimal("10000")).named("max_tx")]

        labels = {i.label for i in _P.invariants()}
        assert "max_tx" in labels
        assert "non_neg_balance" in labels
        assert "not_frozen" in labels
        assert len(_P.invariants()) == 3

    def test_mixin_returning_single_constraint_not_list(self) -> None:
        @invariant_mixin
        def SingleConstraintMixin(fields: dict[str, Field]) -> ConstraintExpr:
            return (E(fields["balance"]) >= 0).named("non_neg")

        class _P(Policy, mixins=[SingleConstraintMixin]):
            balance = Field("balance", Decimal, "Real")
            amount = Field("amount", Decimal, "Real")

            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [(E(cls.amount) >= 0).named("pos_amount")]

        invs = _P.invariants()
        assert len(invs) == 2
        labels = {i.label for i in invs}
        assert "non_neg" in labels
        assert "pos_amount" in labels

    def test_policy_with_only_mixin_invariants_no_own(self) -> None:
        @invariant_mixin
        def AllConstraintsMixin(fields: dict[str, Field]) -> list[ConstraintExpr]:
            return [
                (E(fields["balance"]) >= 0).named("non_neg_balance"),
                (E(fields["amount"]) >= 0).named("pos_amount"),
            ]

        class _P(Policy, mixins=[AllConstraintsMixin]):
            balance = Field("balance", Decimal, "Real")
            amount = Field("amount", Decimal, "Real")

            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                # Explicitly empty — all constraints come from the mixin.
                return []

        invs = _P.invariants()
        assert len(invs) == 2
        labels = {i.label for i in invs}
        assert "non_neg_balance" in labels
        assert "pos_amount" in labels

    def test_validate_passes_on_correctly_composed_policy(self) -> None:
        @invariant_mixin
        def SafetyMixin(fields: dict[str, Field]) -> list[ConstraintExpr]:
            return [(E(fields["balance"]) >= 0).named("non_neg_balance")]

        class _P(Policy, mixins=[SafetyMixin]):
            balance = Field("balance", Decimal, "Real")
            amount = Field("amount", Decimal, "Real")

            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [(E(cls.amount) <= Decimal("10000")).named("max_tx")]

        _P.validate()  # must not raise


# ═══════════════════════════════════════════════════════════════════════════════
# Missing field — error at Guard.__init__ time, not at verify() time
# ═══════════════════════════════════════════════════════════════════════════════


class TestMixinMissingFieldValidation:
    def test_missing_field_raises_at_guard_init_not_class_definition(self) -> None:
        @invariant_mixin
        def SafetyMixin(fields: dict[str, Field]) -> list[ConstraintExpr]:
            return [(E(fields["balance"]) >= 0).named("non_neg")]

        # Class definition must succeed even though "balance" is missing.
        class _Broken(Policy, mixins=[SafetyMixin]):
            amount = Field("amount", Decimal, "Real")
            # "balance" field is intentionally absent

            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [(E(cls.amount) <= Decimal("10000")).named("max_tx")]

        # Error must surface at Guard.__init__ time.
        with pytest.raises(PolicyCompilationError):
            Guard(_Broken, GuardConfig(solver_timeout_ms=5000))

    def test_missing_field_error_message_names_the_mixin(self) -> None:
        @invariant_mixin
        def SpecialNamedMixin(fields: dict[str, Field]) -> list[ConstraintExpr]:
            return [(E(fields["balance"]) >= 0).named("non_neg")]

        class _Broken(Policy, mixins=[SpecialNamedMixin]):
            amount = Field("amount", Decimal, "Real")

            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [(E(cls.amount) >= 0).named("pos")]

        with pytest.raises(PolicyCompilationError, match="SpecialNamedMixin"):
            Guard(_Broken, GuardConfig(solver_timeout_ms=5000))

    def test_missing_field_error_message_names_the_missing_field(self) -> None:
        @invariant_mixin
        def SafetyMixin(fields: dict[str, Field]) -> list[ConstraintExpr]:
            return [(E(fields["balance"]) >= 0).named("non_neg")]

        class _Broken(Policy, mixins=[SafetyMixin]):
            amount = Field("amount", Decimal, "Real")

            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [(E(cls.amount) >= 0).named("pos")]

        with pytest.raises(PolicyCompilationError, match="balance"):
            Guard(_Broken, GuardConfig(solver_timeout_ms=5000))

    def test_missing_field_error_message_names_the_policy(self) -> None:
        @invariant_mixin
        def SafetyMixin(fields: dict[str, Field]) -> list[ConstraintExpr]:
            return [(E(fields["balance"]) >= 0).named("non_neg")]

        class _MySpecificPolicy(Policy, mixins=[SafetyMixin]):
            amount = Field("amount", Decimal, "Real")

            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [(E(cls.amount) >= 0).named("pos")]

        with pytest.raises(PolicyCompilationError, match="_MySpecificPolicy"):
            Guard(_MySpecificPolicy, GuardConfig(solver_timeout_ms=5000))

    def test_non_callable_mixin_raises_policy_compilation_error(self) -> None:
        class _Broken(Policy, mixins=["not_a_function"]):  # type: ignore[list-item]
            amount = Field("amount", Decimal, "Real")

            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [(E(cls.amount) >= 0).named("pos")]

        with pytest.raises(PolicyCompilationError):
            Guard(_Broken, GuardConfig(solver_timeout_ms=5000))

    def test_verify_never_reached_if_guard_init_raises(self) -> None:
        """Fail-safe: no verify() call if construction raises."""

        @invariant_mixin
        def SafetyMixin(fields: dict[str, Field]) -> list[ConstraintExpr]:
            return [(E(fields["balance"]) >= 0).named("non_neg")]

        class _Broken(Policy, mixins=[SafetyMixin]):
            amount = Field("amount", Decimal, "Real")

            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [(E(cls.amount) >= 0).named("pos")]

        with pytest.raises(PolicyCompilationError):
            guard = Guard(_Broken, GuardConfig(solver_timeout_ms=5000))
            # This line must never execute.
            guard.verify(intent={"amount": Decimal("100")}, state={})


# ═══════════════════════════════════════════════════════════════════════════════
# Guard round-trip: ALLOW / BLOCK through mixin constraints
# ═══════════════════════════════════════════════════════════════════════════════


class TestMixinGuardRoundTrip:
    def _make_guard_with_funds_mixin(self) -> Guard:
        @invariant_mixin
        def FundsMixin(fields: dict[str, Field]) -> list[ConstraintExpr]:
            return [(E(fields["balance"]) - E(fields["amount"]) >= 0).named("funds_check")]

        class _P(Policy, mixins=[FundsMixin]):
            balance = Field("balance", Decimal, "Real")
            amount = Field("amount", Decimal, "Real")

            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [(E(cls.amount) <= Decimal("10000")).named("max_tx")]

        return Guard(_P, GuardConfig(solver_timeout_ms=5000))

    def test_allow_when_own_and_mixin_invariants_both_satisfied(self) -> None:
        guard = self._make_guard_with_funds_mixin()
        d = guard.verify(
            intent={"amount": Decimal("100")},
            state={"balance": Decimal("500")},
        )
        assert d.allowed is True

    def test_block_when_own_invariant_violated(self) -> None:
        guard = self._make_guard_with_funds_mixin()
        d = guard.verify(
            intent={"amount": Decimal("20000")},  # exceeds max_tx
            state={"balance": Decimal("50000")},
        )
        assert d.allowed is False
        assert "max_tx" in d.violated_invariants

    def test_block_when_mixin_invariant_violated(self) -> None:
        guard = self._make_guard_with_funds_mixin()
        d = guard.verify(
            intent={"amount": Decimal("500")},
            state={"balance": Decimal("100")},  # balance < amount
        )
        assert d.allowed is False
        assert "funds_check" in d.violated_invariants

    def test_block_when_both_violated(self) -> None:
        guard = self._make_guard_with_funds_mixin()
        d = guard.verify(
            intent={"amount": Decimal("20000")},  # exceeds max_tx
            state={"balance": Decimal("100")},    # and balance < amount
        )
        assert d.allowed is False
        violated = set(d.violated_invariants)
        assert "max_tx" in violated or "funds_check" in violated

    def test_same_mixin_enforced_by_both_policies(self) -> None:
        """The DRY goal: one mixin enforced across two independent policies."""

        @invariant_mixin
        def FundsMixin(fields: dict[str, Field]) -> list[ConstraintExpr]:
            return [(E(fields["balance"]) - E(fields["amount"]) >= 0).named("funds_check")]

        class _TradingPolicy(Policy, mixins=[FundsMixin]):
            balance = Field("balance", Decimal, "Real")
            amount = Field("amount", Decimal, "Real")

            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [(E(cls.amount) <= Decimal("10000")).named("trading_max")]

        class _SavingsPolicy(Policy, mixins=[FundsMixin]):
            balance = Field("balance", Decimal, "Real")
            amount = Field("amount", Decimal, "Real")

            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [(E(cls.amount) <= Decimal("1000")).named("savings_max")]

        guard_trading = Guard(_TradingPolicy, GuardConfig(solver_timeout_ms=5000))
        guard_savings = Guard(_SavingsPolicy, GuardConfig(solver_timeout_ms=5000))

        # Both guards enforce the mixin constraint.
        insufficient = {"amount": Decimal("500"), "balance": Decimal("100")}
        assert guard_trading.verify(intent=insufficient, state={}).allowed is False
        assert guard_savings.verify(intent=insufficient, state={}).allowed is False

        # Both guards ALLOW when funds are sufficient.
        sufficient = {"amount": Decimal("100"), "balance": Decimal("500")}
        assert guard_trading.verify(intent=sufficient, state={}).allowed is True
        assert guard_savings.verify(intent=sufficient, state={}).allowed is True


# ═══════════════════════════════════════════════════════════════════════════════
# Label uniqueness — mixin labels interact with own labels in validate()
# ═══════════════════════════════════════════════════════════════════════════════


class TestMixinLabelUniqueness:
    def test_duplicate_label_between_own_and_mixin_raises(self) -> None:
        @invariant_mixin
        def MixinWithDupLabel(fields: dict[str, Field]) -> list[ConstraintExpr]:
            return [(E(fields["balance"]) >= 0).named("same_label")]

        class _P(Policy, mixins=[MixinWithDupLabel]):
            balance = Field("balance", Decimal, "Real")
            amount = Field("amount", Decimal, "Real")

            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [(E(cls.amount) >= 0).named("same_label")]  # duplicate!

        with pytest.raises(InvariantLabelError, match="same_label"):
            _P.validate()

    def test_duplicate_label_between_two_mixins_raises(self) -> None:
        @invariant_mixin
        def MixinOne(fields: dict[str, Field]) -> list[ConstraintExpr]:
            return [(E(fields["balance"]) >= 0).named("dup_label")]

        @invariant_mixin
        def MixinTwo(fields: dict[str, Field]) -> list[ConstraintExpr]:
            return [(E(fields["balance"]) >= 0).named("dup_label")]  # duplicate!

        class _P(Policy, mixins=[MixinOne, MixinTwo]):
            balance = Field("balance", Decimal, "Real")
            amount = Field("amount", Decimal, "Real")

            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [(E(cls.amount) >= 0).named("pos_amount")]

        with pytest.raises(InvariantLabelError, match="dup_label"):
            _P.validate()

    def test_unique_labels_across_own_and_mixin_pass_validate(self) -> None:
        @invariant_mixin
        def SafeMixin(fields: dict[str, Field]) -> list[ConstraintExpr]:
            return [(E(fields["balance"]) >= 0).named("mixin_label")]

        class _P(Policy, mixins=[SafeMixin]):
            balance = Field("balance", Decimal, "Real")
            amount = Field("amount", Decimal, "Real")

            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [(E(cls.amount) >= 0).named("own_label")]

        _P.validate()  # must not raise
