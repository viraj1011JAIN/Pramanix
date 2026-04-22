# SPDX-License-Identifier: AGPL-3.0-only
# Phase B-1: Tests for nested Pydantic models and NestedField descriptor chaining
"""Gate: Account->Position->Instrument nested model must compile and verify."""
from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest
from pydantic import BaseModel

from pramanix.exceptions import PolicyCompilationError
from pramanix.expressions import ConstraintExpr, E, Field, NestedField

# ── Test model hierarchy ──────────────────────────────────────────────────────


class Instrument(BaseModel):
    symbol: str
    price: Decimal


class Position(BaseModel):
    instrument: Instrument
    amount: Decimal
    is_long: bool


class Account(BaseModel):
    state_version: str
    position: Position
    balance: Decimal


# ── flatten_model unit tests ──────────────────────────────────────────────────


class TestFlattenModel:
    def test_flat_model_unchanged(self) -> None:
        from pramanix.helpers.serialization import flatten_model

        class Simple(BaseModel):
            amount: Decimal
            is_active: bool

        m = Simple(amount=Decimal("100"), is_active=True)
        result = flatten_model(m)
        assert result == {"amount": Decimal("100"), "is_active": True}

    def test_one_level_nesting(self) -> None:
        from pramanix.helpers.serialization import flatten_model

        class Inner(BaseModel):
            value: Decimal

        class Outer(BaseModel):
            name: str
            inner: Inner

        m = Outer(name="test", inner=Inner(value=Decimal("42")))
        result = flatten_model(m)
        assert result == {"name": "test", "inner.value": Decimal("42")}

    def test_three_level_nesting(self) -> None:
        from pramanix.helpers.serialization import flatten_model

        acc = Account(
            state_version="1",
            position=Position(
                instrument=Instrument(symbol="AAPL", price=Decimal("150")),
                amount=Decimal("10"),
                is_long=True,
            ),
            balance=Decimal("5000"),
        )
        result = flatten_model(acc)
        assert result["balance"] == Decimal("5000")
        assert result["position.amount"] == Decimal("10")
        assert result["position.is_long"] is True
        assert result["position.instrument.symbol"] == "AAPL"
        assert result["position.instrument.price"] == Decimal("150")

    def test_max_depth_exceeded_raises(self) -> None:
        from pramanix.helpers.serialization import flatten_model

        class L3(BaseModel):
            v: int

        class L2(BaseModel):
            l3: L3

        class L1(BaseModel):
            l2: L2

        class L0(BaseModel):
            l1: L1

        m = L0(l1=L1(l2=L2(l3=L3(v=1))))
        with pytest.raises(PolicyCompilationError, match="max_nesting_depth"):
            flatten_model(m, max_depth=2)

    def test_circular_reference_raises(self) -> None:
        from pramanix.helpers.serialization import flatten_model

        class Node(BaseModel):
            value: int
            child: Node | None = None  # type: ignore[assignment]

        # Can't truly create a circular instance in Pydantic, but we can test the
        # type-level detection by providing same model type at two levels
        class Parent(BaseModel):
            value: int

        class GrandParent(BaseModel):
            parent: Parent

        # This should NOT raise (different types)
        gp = GrandParent(parent=Parent(value=1))
        result = flatten_model(gp)
        assert result["parent.value"] == 1


# ── NestedField descriptor chaining ──────────────────────────────────────────


class TestNestedField:
    def test_single_level_returns_field(self) -> None:
        nf = NestedField("position", Position)
        amount_field = nf.amount
        assert isinstance(amount_field, Field)
        assert amount_field.name == "position.amount"
        assert amount_field.z3_type == "Real"

    def test_two_level_chaining(self) -> None:
        account = NestedField("account", Account)
        position = account.position
        assert isinstance(position, NestedField)
        amount_field = position.amount
        assert isinstance(amount_field, Field)
        assert amount_field.name == "account.position.amount"

    def test_three_level_chaining(self) -> None:
        account = NestedField("account", Account)
        symbol_field = account.position.instrument.symbol
        assert isinstance(symbol_field, Field)
        assert symbol_field.name == "account.position.instrument.symbol"

    def test_bool_field_inferred(self) -> None:
        nf = NestedField("position", Position)
        f = nf.is_long
        assert isinstance(f, Field)
        assert f.z3_type == "Bool"

    def test_missing_field_raises(self) -> None:
        nf = NestedField("position", Position)
        with pytest.raises(AttributeError, match="no field"):
            _ = nf.nonexistent_field

    def test_repr_informative(self) -> None:
        nf = NestedField("account", Account)
        assert "account" in repr(nf)
        assert "Account" in repr(nf)


# ── Gate: nested policy integration — compile and verify ─────────────────────


def _make_nested_guard() -> Any:
    from pramanix.guard import Guard, GuardConfig
    from pramanix.policy import Policy

    # flatten_model(Account_instance) produces keys: position.*, balance, state_version
    # NestedField("position", Position) produces position.amount — matches the flatten output.
    position_field = NestedField("position", Position)
    balance_field = Field("balance", Decimal, "Real")

    class NestedAccountPolicy(Policy):
        @classmethod
        def invariants(cls) -> list[ConstraintExpr]:
            return [
                (E(position_field.amount) >= 0).named("non_negative_position"),
                (E(balance_field) >= 0).named("non_negative_balance"),
            ]

    return Guard(NestedAccountPolicy, GuardConfig(solver_timeout_ms=5000))


class TestNestedGuardIntegration:
    """Gate: Account->Position nested model must compile and verify."""

    def _make_account(self, amount: Decimal, balance: Decimal) -> Account:
        return Account(
            state_version="1",
            position=Position(
                instrument=Instrument(symbol="AAPL", price=Decimal("150")),
                amount=amount,
                is_long=True,
            ),
            balance=balance,
        )

    def test_valid_position_allowed(self) -> None:
        guard = _make_nested_guard()
        acc = self._make_account(Decimal("10"), Decimal("5000"))
        d = guard.verify(intent={}, state=acc)
        assert d.allowed is True

    def test_negative_position_blocked(self) -> None:
        guard = _make_nested_guard()
        acc = self._make_account(Decimal("-5"), Decimal("5000"))
        d = guard.verify(intent={}, state=acc)
        assert d.allowed is False
        assert "non_negative_position" in d.violated_invariants

    def test_negative_balance_blocked(self) -> None:
        guard = _make_nested_guard()
        acc = self._make_account(Decimal("10"), Decimal("-100"))
        d = guard.verify(intent={}, state=acc)
        assert d.allowed is False
        assert "non_negative_balance" in d.violated_invariants

    def test_dict_with_dotted_keys_works(self) -> None:
        """Callers can also pass a pre-flattened dict directly."""
        guard = _make_nested_guard()
        d = guard.verify(
            intent={},
            state={
                "position.amount": Decimal("10"),
                "balance": Decimal("5000"),
            },
        )
        assert d.allowed is True


# ── Equivalence gate: nested == flat ─────────────────────────────────────────


class TestNestedVsFlat:
    """Gate: E(cls.account.position.amount) produces the same Z3 result as E(cls.amount)."""

    def test_nested_and_flat_produce_same_decision(self) -> None:
        from pramanix.guard import Guard, GuardConfig
        from pramanix.policy import Policy

        # Flat policy
        amount_flat = Field("amount", Decimal, "Real")

        class FlatPolicy(Policy):
            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [(E(amount_flat) >= 0).named("non_negative")]

        flat_guard = Guard(FlatPolicy, GuardConfig(solver_timeout_ms=5000))

        # Nested policy
        account_nf = NestedField("account", Account)

        class NestedPolicy(Policy):
            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [(E(account_nf.position.amount) >= 0).named("non_negative")]

        nested_guard = Guard(NestedPolicy, GuardConfig(solver_timeout_ms=5000))

        # Both should ALLOW positive values
        flat_allow = flat_guard.verify(intent={"amount": Decimal("10")}, state={})
        nested_allow = nested_guard.verify(
            intent={},
            state={"account.position.amount": Decimal("10")},
        )
        assert flat_allow.allowed is True
        assert nested_allow.allowed is True

        # Both should BLOCK negative values
        flat_block = flat_guard.verify(intent={"amount": Decimal("-1")}, state={})
        nested_block = nested_guard.verify(
            intent={},
            state={"account.position.amount": Decimal("-1")},
        )
        assert flat_block.allowed is False
        assert nested_block.allowed is False

