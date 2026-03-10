# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Unit tests for pramanix.policy — Policy base class."""
from __future__ import annotations

from decimal import Decimal

import pytest

from pramanix.exceptions import InvariantLabelError, PolicyError
from pramanix.expressions import ConstraintExpr, E, Field
from pramanix.policy import Policy

# ── Helpers ────────────────────────────────────────────────────────────────────


class _ValidPolicy(Policy):
    balance = Field("balance", Decimal, "Real")
    amount = Field("amount", Decimal, "Real")

    @classmethod
    def invariants(cls) -> list[ConstraintExpr]:
        return [
            (E(cls.balance) - E(cls.amount) >= 0)
            .named("non_negative_balance")
            .explain("Overdraft: balance={balance}, amount={amount}"),
            (E(cls.amount) <= Decimal("10000"))
            .named("max_single_tx")
            .explain("Amount exceeds max transaction limit"),
        ]


class _UnlabelledPolicy(Policy):
    x = Field("x", Decimal, "Real")

    @classmethod
    def invariants(cls) -> list[ConstraintExpr]:
        return [
            E(cls.x) >= 0,  # no .named() — deliberately unlabelled
        ]


class _DuplicateLabelPolicy(Policy):
    x = Field("x", Decimal, "Real")

    @classmethod
    def invariants(cls) -> list[ConstraintExpr]:
        return [
            (E(cls.x) >= 0).named("same_label"),
            (E(cls.x) <= 100).named("same_label"),
        ]


class _EmptyInvariantsPolicy(Policy):
    x = Field("x", Decimal, "Real")

    @classmethod
    def invariants(cls) -> list[ConstraintExpr]:
        return []


# ── Policy.fields() ────────────────────────────────────────────────────────────


class TestPolicyFields:
    def test_returns_declared_fields(self) -> None:
        fields = _ValidPolicy.fields()
        assert "balance" in fields
        assert "amount" in fields

    def test_returns_field_instances(self) -> None:
        fields = _ValidPolicy.fields()
        assert isinstance(fields["balance"], Field)

    def test_non_field_attributes_excluded(self) -> None:
        class _Mixed(Policy):
            f = Field("f", int, "Int")
            not_a_field = "hello"
            also_not = 42

            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [(E(cls.f) >= 0).named("pos")]

        fields = _Mixed.fields()
        assert "f" in fields
        assert "not_a_field" not in fields
        assert "also_not" not in fields

    def test_no_fields_returns_empty_dict(self) -> None:
        class _NoFields(Policy):
            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [Field("x", int, "Int") >= 0]  # type: ignore[list-item,operator]

        assert _NoFields.fields() == {}

    def test_inherited_fields_excluded(self) -> None:
        class _Parent(Policy):
            parent_field = Field("pf", int, "Int")

            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [(E(cls.parent_field) >= 0).named("pos")]

        class _Child(_Parent):
            child_field = Field("cf", int, "Int")

            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [(E(cls.child_field) >= 0).named("pos2")]

        child_fields = _Child.fields()
        assert "child_field" in child_fields
        assert "parent_field" not in child_fields


# ── Policy.invariants() ────────────────────────────────────────────────────────


class TestPolicyInvariants:
    def test_raises_not_implemented_on_base(self) -> None:
        with pytest.raises(NotImplementedError):
            Policy.invariants()

    def test_returns_list_of_constraint_expr(self) -> None:
        invs = _ValidPolicy.invariants()
        assert isinstance(invs, list)
        assert all(isinstance(i, ConstraintExpr) for i in invs)

    def test_returns_correct_count(self) -> None:
        assert len(_ValidPolicy.invariants()) == 2


# ── Policy.validate() — happy path ────────────────────────────────────────────


class TestPolicyValidateHappy:
    def test_valid_policy_does_not_raise(self) -> None:
        _ValidPolicy.validate()  # should complete without exception

    def test_single_invariant_ok(self) -> None:
        class _Single(Policy):
            x = Field("x", int, "Int")

            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [(E(cls.x) >= 0).named("non_negative")]

        _Single.validate()


# ── Policy.validate() — error paths ───────────────────────────────────────────


class TestPolicyValidateErrors:
    def test_empty_invariants_raises_policy_error(self) -> None:
        with pytest.raises(PolicyError):
            _EmptyInvariantsPolicy.validate()

    def test_empty_invariants_error_message_names_class(self) -> None:
        with pytest.raises(PolicyError, match="_EmptyInvariantsPolicy"):
            _EmptyInvariantsPolicy.validate()

    def test_unlabelled_invariant_raises_invariant_label_error(self) -> None:
        with pytest.raises(InvariantLabelError):
            _UnlabelledPolicy.validate()

    def test_unlabelled_error_message_includes_index(self) -> None:
        with pytest.raises(InvariantLabelError, match=r"\[0\]"):
            _UnlabelledPolicy.validate()

    def test_duplicate_label_raises_invariant_label_error(self) -> None:
        with pytest.raises(InvariantLabelError):
            _DuplicateLabelPolicy.validate()

    def test_duplicate_label_error_message_includes_label(self) -> None:
        with pytest.raises(InvariantLabelError, match="same_label"):
            _DuplicateLabelPolicy.validate()

    def test_invariant_label_error_is_policy_error(self) -> None:
        with pytest.raises(PolicyError):
            _UnlabelledPolicy.validate()

    def test_base_policy_invariants_raises_not_implemented(self) -> None:
        with pytest.raises(NotImplementedError):
            Policy.validate()


# ── Full round-trip: define, validate, inspect ────────────────────────────────


class TestPolicyRoundTrip:
    def test_fields_match_invariant_field_refs(self) -> None:
        fields = _ValidPolicy.fields()
        assert fields["balance"].name == "balance"
        assert fields["amount"].name == "amount"

    def test_invariant_labels_are_unique(self) -> None:
        labels = [inv.label for inv in _ValidPolicy.invariants()]
        assert len(labels) == len(set(labels))

    def test_all_invariants_have_explanations(self) -> None:
        for inv in _ValidPolicy.invariants():
            assert inv.explanation is not None
