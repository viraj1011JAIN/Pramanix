# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Unit tests for Phase B-1 (Nested Pydantic Models)."""

from decimal import Decimal
from typing import Any

import pytest
from pydantic import BaseModel

from pramanix.decision import Decision
from pramanix.exceptions import ConfigurationError
from pramanix.expressions import E, Field, NestedField
from pramanix.guard import Guard, GuardConfig
from pramanix.helpers.serialization import flatten_model
from pramanix.policy import Policy


# ── Test Models ───────────────────────────────────────────────────────────────


class Instrument(BaseModel):
    ticker: str
    is_active: bool


class Position(BaseModel):
    instrument: Instrument
    amount: Decimal


class Account(BaseModel):
    position: Position
    balance: Decimal
    account_id: str


class StateWrapper(BaseModel):
    account: Account


# ── Flattening Tests ──────────────────────────────────────────────────────────


def test_flatten_model() -> None:
    """Test that nested models flatten correctly into dotted-path keys."""
    inst = Instrument(ticker="AAPL", is_active=True)
    pos = Position(instrument=inst, amount=Decimal("150.0"))
    acc = Account(position=pos, balance=Decimal("1000.0"), account_id="acc-123")
    state = StateWrapper(account=acc)

    flat = flatten_model(state)
    assert flat == {
        "account.position.instrument.ticker": "AAPL",
        "account.position.instrument.is_active": True,
        "account.position.amount": Decimal("150.0"),
        "account.balance": Decimal("1000.0"),
        "account.account_id": "acc-123",
    }


def test_flatten_model_circular_reference() -> None:
    """Test that circular references are rejected."""
    class Node(BaseModel):
        val: int
        child: Any

    n1 = Node(val=1, child=None)
    n2 = Node(val=2, child=n1)
    n1.child = n2  # Circular reference

    from pramanix.exceptions import PolicyCompilationError
    with pytest.raises(PolicyCompilationError, match="Circular model reference detected"):
        flatten_model(n1)


# ── Policy Integration Tests ──────────────────────────────────────────────────


class NestedTradePolicy(Policy):
    class Meta:
        state_model = StateWrapper

    account = NestedField("account", Account)

    @classmethod
    def invariants(cls) -> list[Any]:
        return [
            # Check deep nested scalar
            (E(cls.account.position.amount) <= E(cls.account.balance)).named("funds_check"),
            # Check nested boolean
            (E(cls.account.position.instrument.is_active) == True).named("instrument_active"),  # noqa: E712
            # Check nested string
            E(cls.account.position.instrument.ticker).is_in({"AAPL", "MSFT"}).named("approved_ticker"),
        ]


def test_nested_field_descriptor_resolution() -> None:
    """Test that descriptor chaining properly resolves to Leaf Fields."""
    # account is a NestedField
    assert isinstance(NestedTradePolicy.account, NestedField)
    
    # position is a NestedField
    assert isinstance(NestedTradePolicy.account.position, NestedField)
    
    # amount is a concrete Field with the dotted path and inferred Z3 type
    amount_field = NestedTradePolicy.account.position.amount
    assert isinstance(amount_field, Field)
    assert amount_field.name == "account.position.amount"
    assert amount_field.z3_type == "Real"
    
    # ticker is a string field
    ticker_field = NestedTradePolicy.account.position.instrument.ticker
    assert isinstance(ticker_field, Field)
    assert ticker_field.name == "account.position.instrument.ticker"
    assert ticker_field.z3_type == "String"


def test_nested_policy_execution_allow() -> None:
    """Test that a policy with nested models evaluates correctly for ALLOW."""
    guard = Guard(NestedTradePolicy)
    
    inst = Instrument(ticker="AAPL", is_active=True)
    pos = Position(instrument=inst, amount=Decimal("150.0"))
    acc = Account(position=pos, balance=Decimal("1000.0"), account_id="acc-123")
    state = StateWrapper(account=acc)

    decision = guard.verify(intent={}, state=state)
    assert decision.allowed is True


def test_nested_policy_execution_block_funds() -> None:
    """Test that a policy blocks correctly based on nested scalar limits."""
    guard = Guard(NestedTradePolicy)
    
    inst = Instrument(ticker="AAPL", is_active=True)
    pos = Position(instrument=inst, amount=Decimal("1500.0"))  # Exceeds balance
    acc = Account(position=pos, balance=Decimal("1000.0"), account_id="acc-123")
    state = StateWrapper(account=acc)

    decision = guard.verify(intent={}, state=state)
    assert decision.allowed is False
    assert "funds_check" in decision.violated_invariants


def test_nested_policy_execution_block_boolean() -> None:
    """Test that a policy blocks correctly based on nested boolean flags."""
    guard = Guard(NestedTradePolicy)
    
    inst = Instrument(ticker="AAPL", is_active=False)  # Not active
    pos = Position(instrument=inst, amount=Decimal("150.0"))
    acc = Account(position=pos, balance=Decimal("1000.0"), account_id="acc-123")
    state = StateWrapper(account=acc)

    decision = guard.verify(intent={}, state=state)
    assert decision.allowed is False
    assert "instrument_active" in decision.violated_invariants


def test_nested_policy_execution_block_string() -> None:
    """Test that a policy blocks correctly based on nested string constraints."""
    guard = Guard(NestedTradePolicy)
    
    inst = Instrument(ticker="TSLA", is_active=True)  # TSLA not in approved list
    pos = Position(instrument=inst, amount=Decimal("150.0"))
    acc = Account(position=pos, balance=Decimal("1000.0"), account_id="acc-123")
    state = StateWrapper(account=acc)

    decision = guard.verify(intent={}, state=state)
    assert decision.allowed is False
    assert "approved_ticker" in decision.violated_invariants


def test_flatten_model_missing_nested_attribute() -> None:
    """Test that accessing a non-existent attribute raises an AttributeError."""
    with pytest.raises(AttributeError, match="has no field 'missing'"):
        _ = NestedTradePolicy.account.missing

