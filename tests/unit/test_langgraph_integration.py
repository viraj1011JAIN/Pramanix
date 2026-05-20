# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Tests for LangGraph integration protocol wrappers."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Any

import pytest
from pydantic import BaseModel

from pramanix import E, Field, Policy
from pramanix.decision import Decision
from pramanix.integrations.langgraph import (
    GuardNodeAdapterProtocol,
    PramanixGuardNode,
    PramanixNodeBlockedError,
    pramanix_node,
)


class _IntentModel(BaseModel):
    amount: Decimal


class _StateModel(BaseModel):
    state_version: str
    limit: Decimal


class _MoneyPolicy(Policy):
    class Meta:
        version = "1.0"
        intent_model = _IntentModel
        state_model = _StateModel

    amount = Field("amount", Decimal, "Real")
    limit = Field("limit", Decimal, "Real")

    @classmethod
    def invariants(cls) -> list[Any]:
        return [
            (E(cls.amount) <= E(cls.limit)).named("within_limit").explain("amount must be <= limit")
        ]


class _GraphState(BaseModel):
    amount: int
    limit: int
    state_version: str = "1.0"


def test_pramanix_node_halt_blocks() -> None:
    @pramanix_node(policy=_MoneyPolicy, on_fail="halt")
    def process(state: _GraphState) -> dict[str, Any]:
        return {"status": "ok"}

    with pytest.raises(PramanixNodeBlockedError):
        process(_GraphState(amount=20, limit=10))


def test_pramanix_node_warn_injects_sidecar() -> None:
    @pramanix_node(policy=_MoneyPolicy, on_fail="warn")
    def process(state: _GraphState) -> dict[str, Any]:
        return {"status": "ok"}

    result = process(_GraphState(amount=20, limit=10))

    assert result["status"] == "ok"
    sidecar = result["_pramanix_policy_verdict"]
    assert sidecar["production_verdict"] == "UNSAT"
    assert "within_limit" in sidecar["formal_proof"]
    assert sidecar["plain_explanation"] == "amount must be <= limit"


def test_pramanix_node_shadow_does_not_block() -> None:
    @pramanix_node(policy=_MoneyPolicy, on_fail="halt", shadow=True)
    def process(state: _GraphState) -> dict[str, Any]:
        return {"status": "ok"}

    result = process(_GraphState(amount=20, limit=10))
    assert result["status"] == "ok"
    assert result["_pramanix_policy_verdict"]["shadow_mode"] is True


def test_pramanix_node_pydantic_state_introspection_and_coercion() -> None:
    @pramanix_node(policy=_MoneyPolicy, on_fail="halt")
    def process(state: _GraphState) -> dict[str, Any]:
        return {"status": "authorized"}

    # amount/limit are ints in state model, but policy intent/state models
    # require Decimal. Integration should coerce safely.
    result = process(_GraphState(amount=5, limit=10))
    assert result["status"] == "authorized"
    assert result["_pramanix_policy_verdict"]["production_verdict"] == "SAT"


@dataclass
class _TimeoutPolicy:
    __name__ = "TimeoutPolicy"


class _TimeoutGuard:
    _policy = _TimeoutPolicy

    async def verify_async(
        self,
        *,
        intent: dict[str, Any],
        state: dict[str, Any],
    ) -> Decision:
        return Decision.timeout(label="z3", timeout_ms=120)


def test_timeout_bypass_with_warn_and_sidecar() -> None:
    @pramanix_node(
        guard=_TimeoutGuard(),
        on_fail="halt",
        bypass_on_timeout=True,
    )
    def process(state: dict[str, Any]) -> dict[str, Any]:
        return {"status": "continued"}

    result = process({"amount": 1})
    assert result["status"] == "continued"
    assert result["_pramanix_policy_verdict"]["production_verdict"] == "TIMEOUT"


# ── GuardNodeAdapterProtocol structural conformance ───────────────────────────


class TestGuardNodeAdapterProtocol:
    """PramanixGuardNode must satisfy GuardNodeAdapterProtocol at runtime."""

    def test_pramanix_guard_node_is_instance_of_protocol(self) -> None:
        node = PramanixGuardNode(policy=_MoneyPolicy)
        assert isinstance(node, GuardNodeAdapterProtocol)

    def test_protocol_is_runtime_checkable(self) -> None:
        # isinstance() must not raise — the @runtime_checkable decorator is required
        result = isinstance(object(), GuardNodeAdapterProtocol)
        assert result is False  # plain object does not have .decorate

    def test_custom_adapter_satisfying_protocol_passes_isinstance(self) -> None:
        class _CustomAdapter:
            def decorate(self, fn: Any) -> Any:
                return fn

        adapter = _CustomAdapter()
        assert isinstance(adapter, GuardNodeAdapterProtocol)

    def test_object_missing_decorate_fails_isinstance(self) -> None:
        class _BadAdapter:
            def gate(self, fn: Any) -> Any:  # wrong method name
                return fn

        assert not isinstance(_BadAdapter(), GuardNodeAdapterProtocol)

    def test_protocol_exported_in_all(self) -> None:
        import pramanix.integrations.langgraph as _lg

        assert "GuardNodeAdapterProtocol" in _lg.__all__
