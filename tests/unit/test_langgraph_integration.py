# SPDX-License-Identifier: Apache-2.0
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
    @pramanix_node(policy=_MoneyPolicy, on_fail="halt", timeout_ms=5000)
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


# ── _state_to_dict edge cases ─────────────────────────────────────────────────


class TestStateToDictEdgeCases:
    """Exercise the fallback branches in _state_to_dict."""

    def test_dict_method_path(self) -> None:
        from pramanix.integrations.langgraph import _state_to_dict

        class _LegacyState:
            def dict(self) -> dict:
                return {"amount": 42}

        result = _state_to_dict(_LegacyState())
        assert result == {"amount": 42}

    def test_dunder_dict_path(self) -> None:
        from pramanix.integrations.langgraph import _state_to_dict

        class _SimpleState:
            def __init__(self) -> None:
                self.amount = 7
                self.limit = 5

        result = _state_to_dict(_SimpleState())
        assert result["amount"] == 7
        assert result["limit"] == 5

    def test_invalid_type_raises_type_error(self) -> None:
        from pramanix.integrations.langgraph import _state_to_dict

        with pytest.raises(TypeError, match="State must be a dict or Pydantic model"):
            _state_to_dict(("tuple", "has", "no_dict"))


# ── _coerce_payload_with_model edge cases ────────────────────────────────────


class TestCoercePayloadWithModel:
    def test_model_none_returns_copy(self) -> None:
        from pramanix.integrations.langgraph import _coerce_payload_with_model

        payload = {"x": 1}
        result = _coerce_payload_with_model(payload, None)
        assert result == {"x": 1}
        assert result is not payload

    def test_model_without_model_fields_dict_returns_copy(self) -> None:
        from pramanix.integrations.langgraph import _coerce_payload_with_model

        class _NotPydantic:
            model_fields = "not_a_dict"

        result = _coerce_payload_with_model({"x": 1}, _NotPydantic())
        assert result == {"x": 1}

    def test_key_missing_from_payload_is_skipped(self) -> None:
        from decimal import Decimal as D

        from pydantic import BaseModel

        from pramanix.integrations.langgraph import _coerce_payload_with_model

        class _M(BaseModel):
            amount: D
            extra: D

        result = _coerce_payload_with_model({"amount": 5}, _M)
        assert result["amount"] == D("5")
        assert "extra" not in result


# ── _suggest_remediation ──────────────────────────────────────────────────────


class TestSuggestRemediation:
    def test_numeric_path_when_intent_exceeds_state(self) -> None:
        from pramanix.decision import Decision
        from pramanix.integrations.langgraph import _suggest_remediation

        decision = Decision.unsafe(violated_invariants=("under_limit",), explanation="over limit")
        result = _suggest_remediation(
            decision,
            intent_payload={"amount": 20},
            state_payload={"limit": 10},
        )
        # _suggest_remediation no longer embeds raw field values to prevent
        # binary-search policy probing (#136); returns the invariant label instead.
        assert "under_limit" in result
        assert "Review invariant" in result

    def test_numeric_path_skipped_when_intent_not_greater(self) -> None:
        from pramanix.decision import Decision
        from pramanix.integrations.langgraph import _suggest_remediation

        decision = Decision.unsafe(violated_invariants=("cap_rule",), explanation="over cap")
        result = _suggest_remediation(
            decision,
            intent_payload={"amount": 5},
            state_payload={"cap": 10},
        )
        # intent < state, so numeric path doesn't return early; falls through
        assert "Review invariant" in result

    def test_no_violated_invariants_returns_no_remediation(self) -> None:
        from pramanix.decision import Decision
        from pramanix.integrations.langgraph import _suggest_remediation

        decision = Decision.error(reason="timeout")
        result = _suggest_remediation(decision, intent_payload={}, state_payload={})
        assert result == "No remediation available."


# ── _emit_audit paths ─────────────────────────────────────────────────────────


class TestEmitAudit:
    def _make_node_with_audit(self, sink: Any) -> PramanixGuardNode:
        return PramanixGuardNode(policy=_MoneyPolicy, on_fail="warn", audit_sink=sink)

    def test_callable_audit_sink_is_called(self) -> None:
        received: list[dict] = []

        @pramanix_node(policy=_MoneyPolicy, on_fail="warn", audit_sink=received.append)
        def process(state: _GraphState) -> dict[str, Any]:
            return {"status": "ok"}

        process(_GraphState(amount=20, limit=10))
        assert len(received) == 1
        assert "production_verdict" in received[0]

    def test_emit_method_audit_sink_is_called(self) -> None:
        class _Sink:
            def __init__(self) -> None:
                self.emitted: list[dict] = []

            def emit(self, verdict: dict) -> None:
                self.emitted.append(verdict)

        sink = _Sink()

        @pramanix_node(policy=_MoneyPolicy, on_fail="warn", audit_sink=sink)
        def process(state: _GraphState) -> dict[str, Any]:
            return {"status": "ok"}

        process(_GraphState(amount=5, limit=10))
        assert len(sink.emitted) == 1

    def test_audit_sink_exception_is_swallowed(self) -> None:
        def _bad_sink(verdict: dict) -> None:
            raise RuntimeError("audit failure")

        @pramanix_node(policy=_MoneyPolicy, on_fail="warn", audit_sink=_bad_sink)
        def process(state: _GraphState) -> dict[str, Any]:
            return {"status": "ok"}

        # Must not propagate audit failure to caller
        result = process(_GraphState(amount=5, limit=10))
        assert result["status"] == "ok"


# ── _inject_sidecar when result is not a dict ─────────────────────────────────


def test_inject_sidecar_non_dict_result_is_returned_unchanged() -> None:
    @pramanix_node(policy=_MoneyPolicy, on_fail="warn")
    def process(state: _GraphState) -> str:
        return "plain string result"

    result = process(_GraphState(amount=5, limit=10))
    # Non-dict results are returned as-is (no sidecar injected)
    assert result == "plain string result"


# ── Async node decoration ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_async_node_function_is_wrapped_and_runs() -> None:
    @pramanix_node(policy=_MoneyPolicy, on_fail="warn")
    async def process_async(state: _GraphState) -> dict[str, Any]:
        return {"status": "async_ok"}

    result = await process_async(_GraphState(amount=5, limit=10))
    assert result["status"] == "async_ok"
    assert result["_pramanix_policy_verdict"]["production_verdict"] == "SAT"


@pytest.mark.asyncio
async def test_async_node_blocked_raises_blocked_error() -> None:
    @pramanix_node(policy=_MoneyPolicy, on_fail="halt")
    async def process_async(state: _GraphState) -> dict[str, Any]:
        return {"status": "should_not_reach"}

    with pytest.raises(PramanixNodeBlockedError) as exc_info:
        await process_async(_GraphState(amount=20, limit=10))

    assert "within_limit" in str(exc_info.value.verdict)


# ── ERROR verdict in _build_verdict ──────────────────────────────────────────


class _ErrorGuard:
    _policy = type("_ErrorPolicy", (), {"__name__": "_ErrorPolicy"})

    async def verify_async(self, *, intent: Any, state: Any) -> Any:
        from pramanix.decision import Decision

        return Decision.error(reason="internal error for test")


def test_error_decision_produces_error_verdict() -> None:
    @pramanix_node(guard=_ErrorGuard(), on_fail="warn")
    def process(state: dict[str, Any]) -> dict[str, Any]:
        return {"status": "ok"}

    result = process({"value": 1})
    assert result["_pramanix_policy_verdict"]["production_verdict"] == "ERROR"


# ── Sync node called from inside running event loop ───────────────────────────


@pytest.mark.asyncio
async def test_sync_node_called_from_async_context_uses_thread_executor() -> None:
    """Sync LangGraph node called from async host dispatches to thread pool."""

    @pramanix_node(policy=_MoneyPolicy, on_fail="warn")
    def process(state: _GraphState) -> dict[str, Any]:
        return {"status": "from_thread"}

    # Inside async context asyncio.get_running_loop() succeeds → ThreadPoolExecutor path
    result = process(_GraphState(amount=5, limit=10))
    assert result["status"] == "from_thread"
    assert result["_pramanix_policy_verdict"]["production_verdict"] == "SAT"


# ── PramanixNodeBlockedError .verdict attribute ───────────────────────────────


def test_pramanix_node_blocked_error_exposes_verdict() -> None:
    @pramanix_node(policy=_MoneyPolicy, on_fail="halt")
    def process(state: _GraphState) -> dict[str, Any]:
        return {}

    with pytest.raises(PramanixNodeBlockedError) as exc_info:
        process(_GraphState(amount=20, limit=10))

    err = exc_info.value
    assert isinstance(err.verdict, dict)
    assert err.verdict["production_verdict"] == "UNSAT"
    assert err.verdict["node"] == "process"


# ── intent_extractor / state_extractor paths ─────────────────────────────────


def test_custom_intent_and_state_extractors_are_used() -> None:
    node = PramanixGuardNode(
        policy=_MoneyPolicy,
        on_fail="warn",
        intent_extractor=lambda s: {"amount": s.get("amount", 0)},
        state_extractor=lambda s: {"limit": s.get("limit", 100)},
    )

    @node.decorate
    def process(state: dict[str, Any]) -> dict[str, Any]:
        return {"processed": True}

    result = process({"amount": 5, "limit": 10})
    assert result["processed"] is True
