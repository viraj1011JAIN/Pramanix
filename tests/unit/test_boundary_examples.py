# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for PolicyAuditor.boundary_examples (Z3-driven SAT/UNSAT witnesses)."""
from __future__ import annotations

from decimal import Decimal

from pramanix.expressions import E, Field
from pramanix.helpers.policy_auditor import PolicyAuditor
from pramanix.policy import Policy

# ── Minimal test policies ─────────────────────────────────────────────────────


class SimpleBudgetPolicy(Policy):
    """Policy with one numeric invariant: amount <= 1000."""
    amount = Field("amount", Decimal, "Real")

    @classmethod
    def invariants(cls):
        return [
            (E(cls.amount) <= 1000).named("within_budget"),
        ]


class BoolPolicy(Policy):
    """Policy with a boolean invariant: approved must be True."""
    approved = Field("approved", bool, "Bool")

    @classmethod
    def invariants(cls):
        return [
            (E(cls.approved) == True).named("must_be_approved"),  # noqa: E712
        ]


class MultiInvariantPolicy(Policy):
    """Policy with two independent invariants."""
    balance = Field("balance", Decimal, "Real")
    amount = Field("amount", Decimal, "Real")

    @classmethod
    def invariants(cls):
        return [
            (E(cls.balance) >= 0).named("non_negative_balance"),
            (E(cls.amount) <= E(cls.balance)).named("within_balance"),
        ]


class AlwaysUnsatisfiablePolicy(Policy):
    """Invariant that can never be satisfied: x > x."""
    x = Field("x", int, "Int")

    @classmethod
    def invariants(cls):
        return [
            (E(cls.x) > E(cls.x)).named("impossible"),
        ]


# ── Return type contract ──────────────────────────────────────────────────────


def test_boundary_examples_returns_dict() -> None:
    result = PolicyAuditor.boundary_examples(SimpleBudgetPolicy)
    assert isinstance(result, dict)


def test_boundary_examples_keys_match_invariant_labels() -> None:
    result = PolicyAuditor.boundary_examples(SimpleBudgetPolicy)
    assert "within_budget" in result


def test_boundary_examples_values_have_sat_and_unsat_keys() -> None:
    result = PolicyAuditor.boundary_examples(SimpleBudgetPolicy)
    entry = result["within_budget"]
    assert set(entry.keys()) == {"sat", "unsat"}


def test_boundary_examples_multi_invariant_all_labels_present() -> None:
    result = PolicyAuditor.boundary_examples(MultiInvariantPolicy)
    assert "non_negative_balance" in result
    assert "within_balance" in result


# ── SAT witness correctness ───────────────────────────────────────────────────


def test_boundary_examples_sat_example_satisfies_invariant() -> None:
    """The SAT example values must actually satisfy 'amount <= 1000'."""
    result = PolicyAuditor.boundary_examples(SimpleBudgetPolicy)
    sat = result["within_budget"]["sat"]
    assert sat is not None
    assert "amount" in sat
    assert sat["amount"] <= Decimal("1000")


def test_boundary_examples_sat_witness_type_is_decimal_for_real() -> None:
    result = PolicyAuditor.boundary_examples(SimpleBudgetPolicy)
    sat = result["within_budget"]["sat"]
    assert sat is not None
    assert isinstance(sat["amount"], Decimal)


def test_boundary_examples_sat_witness_type_is_bool_for_bool_field() -> None:
    result = PolicyAuditor.boundary_examples(BoolPolicy)
    sat = result["must_be_approved"]["sat"]
    assert sat is not None
    assert "approved" in sat
    assert isinstance(sat["approved"], bool)
    assert sat["approved"] is True


# ── UNSAT witness correctness ─────────────────────────────────────────────────


def test_boundary_examples_unsat_example_violates_invariant() -> None:
    """The UNSAT example must violate 'amount <= 1000', i.e. amount > 1000."""
    result = PolicyAuditor.boundary_examples(SimpleBudgetPolicy)
    unsat = result["within_budget"]["unsat"]
    assert unsat is not None
    assert "amount" in unsat
    assert unsat["amount"] > Decimal("1000")


def test_boundary_examples_unsat_witness_for_bool_is_false() -> None:
    result = PolicyAuditor.boundary_examples(BoolPolicy)
    unsat = result["must_be_approved"]["unsat"]
    assert unsat is not None
    assert "approved" in unsat
    assert unsat["approved"] is False


# ── Unsatisfiable invariant ───────────────────────────────────────────────────


def test_boundary_examples_unsat_invariant_returns_none_for_sat() -> None:
    """An invariant that can never be true should yield sat=None."""
    result = PolicyAuditor.boundary_examples(AlwaysUnsatisfiablePolicy)
    assert result["impossible"]["sat"] is None


# ── Empty policy ──────────────────────────────────────────────────────────────


class EmptyPolicy(Policy):
    x = Field("x", Decimal, "Real")

    @classmethod
    def invariants(cls):
        return []


def test_boundary_examples_empty_policy_returns_empty_dict() -> None:
    result = PolicyAuditor.boundary_examples(EmptyPolicy)
    assert result == {}


# ── Error resilience ──────────────────────────────────────────────────────────


class BadInvariantsPolicy(Policy):
    x = Field("x", Decimal, "Real")

    @classmethod
    def invariants(cls):
        raise RuntimeError("broken policy")


def test_boundary_examples_handles_invariants_exception_gracefully() -> None:
    result = PolicyAuditor.boundary_examples(BadInvariantsPolicy)
    assert result == {}
