# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Unit tests for AgentOrchestrationAdapter Protocol.

Verifies that:
- The Protocol is @runtime_checkable (isinstance() works correctly).
- Concrete implementations satisfy the Protocol.
- Partial implementations are correctly rejected.
- The Protocol is importable from both the module and the integrations package.

References §6.7 item 4 of flaws.md.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any

from pramanix.decision import Decision
from pramanix.expressions import E, Field
from pramanix.integrations.agent_orchestration import (
    AgentOrchestrationAdapter,
    AutoGenGuardAdapter,
    LangGraphGuardAdapter,
)
from pramanix.policy import Policy


# ── Shared guard factory ──────────────────────────────────────────────────────


def _amount_field() -> Field:
    return Field("amount", Decimal, "Real")


def _make_real_guard(max_amount: Decimal = Decimal("1000")):
    """Return a real Guard with a simple amount-ceiling policy.

    Meta.version=None disables the state_version check so tests can pass
    plain intent dicts without a version sidecar in the state payload.
    """
    from pramanix.guard import Guard, GuardConfig

    f = _amount_field()

    class _P(Policy):
        class Meta:
            version = None  # skip state_version binding check in tests

        amount = f

        @classmethod
        def fields(cls):
            return {"amount": f}

        @classmethod
        def invariants(cls):
            return [(E(f) <= max_amount).named("max_amount")]

    return Guard(_P, GuardConfig(execution_mode="sync"))

# ── Helpers ────────────────────────────────────────────────────────────────────


def _allowed_decision() -> Decision:
    return Decision.safe()


def _blocked_decision() -> Decision:
    return Decision.unsafe(
        violated_invariants=("test_invariant",),
        explanation="blocked for test",
    )


# ── Concrete implementations used in tests ────────────────────────────────────


class _NullAdapter:
    """Minimal adapter that logs nothing and never blocks."""

    def on_node_enter(self, node_id: str, state: dict[str, Any]) -> None:
        pass

    def on_node_exit(self, node_id: str, state: dict[str, Any], decision: Decision) -> None:
        pass

    def should_block(self, state: dict[str, Any]) -> bool:
        return False


class _RecordingAdapter:
    """Adapter that records all lifecycle calls for assertion."""

    def __init__(self) -> None:
        self.entered: list[tuple[str, dict[str, Any]]] = []
        self.exited: list[tuple[str, dict[str, Any], Decision]] = []
        self.blocked_checks: list[dict[str, Any]] = []

    def on_node_enter(self, node_id: str, state: dict[str, Any]) -> None:
        self.entered.append((node_id, state))

    def on_node_exit(self, node_id: str, state: dict[str, Any], decision: Decision) -> None:
        self.exited.append((node_id, state, decision))

    def should_block(self, state: dict[str, Any]) -> bool:
        self.blocked_checks.append(state)
        return bool(state.get("_block", False))


class _BlockingAdapter:
    """Adapter that always blocks."""

    def on_node_enter(self, node_id: str, state: dict[str, Any]) -> None:
        pass

    def on_node_exit(self, node_id: str, state: dict[str, Any], decision: Decision) -> None:
        pass

    def should_block(self, state: dict[str, Any]) -> bool:
        return True


class _MissingOnNodeEnter:
    """Partial implementation missing on_node_enter — must NOT satisfy the Protocol."""

    def on_node_exit(self, node_id: str, state: dict[str, Any], decision: Decision) -> None:
        pass

    def should_block(self, state: dict[str, Any]) -> bool:
        return False


class _MissingShouldBlock:
    """Partial implementation missing should_block — must NOT satisfy the Protocol."""

    def on_node_enter(self, node_id: str, state: dict[str, Any]) -> None:
        pass

    def on_node_exit(self, node_id: str, state: dict[str, Any], decision: Decision) -> None:
        pass


# ── Tests ─────────────────────────────────────────────────────────────────────


class TestAgentOrchestrationAdapterProtocol:
    """Protocol structural checks."""

    def test_runtime_checkable(self) -> None:
        """AgentOrchestrationAdapter must be @runtime_checkable."""
        # Accessing __protocol_attrs__ or attempting isinstance() is the key check.
        adapter = _NullAdapter()
        assert isinstance(adapter, AgentOrchestrationAdapter)

    def test_recording_adapter_satisfies_protocol(self) -> None:
        assert isinstance(_RecordingAdapter(), AgentOrchestrationAdapter)

    def test_blocking_adapter_satisfies_protocol(self) -> None:
        assert isinstance(_BlockingAdapter(), AgentOrchestrationAdapter)

    def test_missing_on_node_enter_fails_isinstance(self) -> None:
        assert not isinstance(_MissingOnNodeEnter(), AgentOrchestrationAdapter)

    def test_missing_should_block_fails_isinstance(self) -> None:
        assert not isinstance(_MissingShouldBlock(), AgentOrchestrationAdapter)

    def test_plain_object_fails_isinstance(self) -> None:
        assert not isinstance(object(), AgentOrchestrationAdapter)

    def test_importable_from_integrations_package(self) -> None:
        """AgentOrchestrationAdapter is exported from pramanix.integrations."""
        from pramanix.integrations import AgentOrchestrationAdapter as _via_pkg

        assert _via_pkg is AgentOrchestrationAdapter


class TestNullAdapter:
    """_NullAdapter baseline behaviour — no errors, no side-effects."""

    def test_on_node_enter_does_not_raise(self) -> None:
        adapter = _NullAdapter()
        adapter.on_node_enter("test_node", {"key": "value"})

    def test_on_node_exit_does_not_raise(self) -> None:
        adapter = _NullAdapter()
        adapter.on_node_exit("test_node", {}, _allowed_decision())

    def test_should_block_returns_false(self) -> None:
        assert _NullAdapter().should_block({}) is False


class TestRecordingAdapter:
    """Lifecycle hooks are called with the correct arguments."""

    def test_on_node_enter_records_call(self) -> None:
        adapter = _RecordingAdapter()
        state = {"amount": 100}
        adapter.on_node_enter("transfer_node", state)
        assert len(adapter.entered) == 1
        assert adapter.entered[0] == ("transfer_node", state)

    def test_on_node_exit_records_decision(self) -> None:
        adapter = _RecordingAdapter()
        decision = _blocked_decision()
        adapter.on_node_exit("transfer_node", {}, decision)
        assert len(adapter.exited) == 1
        assert adapter.exited[0][2] is decision

    def test_should_block_records_state_check(self) -> None:
        adapter = _RecordingAdapter()
        state = {"amount": 100}
        result = adapter.should_block(state)
        assert not result
        assert len(adapter.blocked_checks) == 1
        assert adapter.blocked_checks[0] is state

    def test_should_block_returns_true_when_flag_set(self) -> None:
        adapter = _RecordingAdapter()
        result = adapter.should_block({"_block": True})
        assert result is True

    def test_sequential_lifecycle_correct_order(self) -> None:
        adapter = _RecordingAdapter()
        state = {"amount": 500}
        decision = _allowed_decision()

        adapter.on_node_enter("pay_node", state)
        assert not adapter.should_block(state)
        adapter.on_node_exit("pay_node", state, decision)

        assert adapter.entered[0][0] == "pay_node"
        assert adapter.exited[0][0] == "pay_node"
        assert adapter.exited[0][2].allowed is True


class TestBlockingAdapter:
    """BlockingAdapter always returns True from should_block."""

    def test_should_block_always_true(self) -> None:
        adapter = _BlockingAdapter()
        assert adapter.should_block({}) is True
        assert adapter.should_block({"amount": 100}) is True
        assert adapter.should_block({"_block": False}) is True


class TestRouterPattern:
    """Simulate a framework router using should_block to choose the next node."""

    def test_router_routes_to_blocked_node_when_adapter_blocks(self) -> None:
        adapter = _BlockingAdapter()

        def route(state: dict[str, Any]) -> str:
            if adapter.should_block(state):
                return "blocked_node"
            return "proceed_node"

        assert route({}) == "blocked_node"
        assert route({"amount": 999}) == "blocked_node"

    def test_router_proceeds_when_adapter_allows(self) -> None:
        adapter = _NullAdapter()

        def route(state: dict[str, Any]) -> str:
            if adapter.should_block(state):
                return "blocked_node"
            return "proceed_node"

        assert route({}) == "proceed_node"
        assert route({"amount": 100}) == "proceed_node"


# ── LangGraphGuardAdapter with real Guard ─────────────────────────────────────


class TestLangGraphGuardAdapter:
    """LangGraphGuardAdapter wired to a real Guard instance."""

    def test_satisfies_protocol(self) -> None:
        guard = _make_real_guard()
        adapter = LangGraphGuardAdapter(guard=guard, intent_key="intent")
        assert isinstance(adapter, AgentOrchestrationAdapter)

    def test_should_block_false_when_allowed(self) -> None:
        guard = _make_real_guard(max_amount=Decimal("1000"))
        adapter = LangGraphGuardAdapter(guard=guard, intent_key="intent")
        state = {"intent": {"amount": Decimal("500")}}
        assert adapter.should_block(state) is False

    def test_should_block_true_when_violated(self) -> None:
        guard = _make_real_guard(max_amount=Decimal("1000"))
        adapter = LangGraphGuardAdapter(guard=guard, intent_key="intent")
        state = {"intent": {"amount": Decimal("2000")}}
        assert adapter.should_block(state) is True

    def test_should_block_fail_closed_on_bad_intent(self) -> None:
        guard = _make_real_guard()
        adapter = LangGraphGuardAdapter(guard=guard)
        # Passing an unhashable or type-broken intent should not raise — fail closed.
        # The guard receives the full state dict; missing `amount` field → solver
        # returns UNKNOWN/error → adapter returns True (block).
        result = adapter.should_block({"irrelevant_key": "no_amount_field"})
        assert isinstance(result, bool)

    def test_on_node_enter_records_timestamp(self) -> None:
        guard = _make_real_guard()
        adapter = LangGraphGuardAdapter(guard=guard)
        adapter.on_node_enter("transfer_node", {"amount": Decimal("100")})
        assert "transfer_node" in adapter._enter_times

    def test_on_node_exit_writes_sidecar(self) -> None:
        guard = _make_real_guard()
        adapter = LangGraphGuardAdapter(guard=guard, sidecar_key="_verdict")
        state: dict[str, Any] = {}
        adapter.on_node_enter("pay_node", state)
        adapter.on_node_exit("pay_node", state, Decision.safe())
        assert "_verdict" in state
        verdict = state["_verdict"]
        assert verdict["node"] == "pay_node"
        assert verdict["allowed"] is True
        assert "latency_ms" in verdict
        assert isinstance(verdict["latency_ms"], float)

    def test_on_node_exit_sidecar_contains_violated_invariants(self) -> None:
        guard = _make_real_guard()
        adapter = LangGraphGuardAdapter(guard=guard)
        state: dict[str, Any] = {}
        blocked = Decision.unsafe(
            violated_invariants=("max_amount",), explanation="exceeded"
        )
        adapter.on_node_enter("pay_node", state)
        adapter.on_node_exit("pay_node", state, blocked)
        verdict = state["_pramanix_verdict"]
        assert verdict["allowed"] is False
        assert "max_amount" in verdict["violated_invariants"]

    def test_full_allow_roundtrip(self) -> None:
        guard = _make_real_guard(max_amount=Decimal("1000"))
        adapter = LangGraphGuardAdapter(guard=guard, intent_key="intent")
        state: dict[str, Any] = {"intent": {"amount": Decimal("100")}}

        adapter.on_node_enter("pay_node", state)
        blocked = adapter.should_block(state)
        decision = guard.verify(intent={"amount": Decimal("100")}, state={})
        adapter.on_node_exit("pay_node", state, decision)

        assert blocked is False
        assert state["_pramanix_verdict"]["allowed"] is True

    def test_full_block_roundtrip(self) -> None:
        guard = _make_real_guard(max_amount=Decimal("500"))
        adapter = LangGraphGuardAdapter(guard=guard, intent_key="intent")
        state: dict[str, Any] = {"intent": {"amount": Decimal("2000")}}

        adapter.on_node_enter("pay_node", state)
        blocked = adapter.should_block(state)
        decision = guard.verify(intent={"amount": Decimal("2000")}, state={})
        adapter.on_node_exit("pay_node", state, decision)

        assert blocked is True
        assert state["_pramanix_verdict"]["allowed"] is False


# ── AutoGenGuardAdapter with real Guard ───────────────────────────────────────


class TestAutoGenGuardAdapter:
    """AutoGenGuardAdapter wired to a real Guard instance."""

    def test_satisfies_protocol(self) -> None:
        guard = _make_real_guard()
        adapter = AutoGenGuardAdapter(guard=guard)
        assert isinstance(adapter, AgentOrchestrationAdapter)

    def test_should_block_false_when_allowed(self) -> None:
        guard = _make_real_guard(max_amount=Decimal("1000"))
        adapter = AutoGenGuardAdapter(guard=guard, intent_key="tool_args")
        state = {"tool_args": {"amount": Decimal("300")}}
        assert adapter.should_block(state) is False

    def test_should_block_true_when_violated(self) -> None:
        guard = _make_real_guard(max_amount=Decimal("1000"))
        adapter = AutoGenGuardAdapter(guard=guard, intent_key="tool_args")
        state = {"tool_args": {"amount": Decimal("9999")}}
        assert adapter.should_block(state) is True

    def test_on_node_exit_writes_rejection_when_blocked(self) -> None:
        guard = _make_real_guard()
        adapter = AutoGenGuardAdapter(guard=guard, rejection_key="_rejection")
        state: dict[str, Any] = {}
        blocked = Decision.unsafe(
            violated_invariants=("max_amount",), explanation="exceeded limit"
        )
        adapter.on_node_exit("tool_node", state, blocked)
        assert "_rejection" in state
        assert state["_rejection"]["explanation"] == "exceeded limit"
        assert "max_amount" in state["_rejection"]["violated_invariants"]

    def test_on_node_exit_does_not_write_rejection_when_allowed(self) -> None:
        guard = _make_real_guard()
        adapter = AutoGenGuardAdapter(guard=guard, rejection_key="_rejection")
        state: dict[str, Any] = {}
        adapter.on_node_exit("tool_node", state, Decision.safe())
        assert "_rejection" not in state

    def test_on_node_enter_does_not_raise(self) -> None:
        guard = _make_real_guard()
        adapter = AutoGenGuardAdapter(guard=guard)
        adapter.on_node_enter("any_node", {"tool_args": {}})

    def test_full_allow_roundtrip(self) -> None:
        guard = _make_real_guard(max_amount=Decimal("1000"))
        adapter = AutoGenGuardAdapter(guard=guard, intent_key="tool_args")
        state: dict[str, Any] = {"tool_args": {"amount": Decimal("200")}}

        adapter.on_node_enter("tool_node", state)
        blocked = adapter.should_block(state)
        decision = guard.verify(intent={"amount": Decimal("200")}, state={})
        adapter.on_node_exit("tool_node", state, decision)

        assert blocked is False
        assert "_pramanix_rejection" not in state

    def test_full_block_roundtrip(self) -> None:
        guard = _make_real_guard(max_amount=Decimal("100"))
        adapter = AutoGenGuardAdapter(guard=guard, intent_key="tool_args")
        state: dict[str, Any] = {"tool_args": {"amount": Decimal("999")}}

        adapter.on_node_enter("tool_node", state)
        blocked = adapter.should_block(state)
        decision = guard.verify(intent={"amount": Decimal("999")}, state={})
        adapter.on_node_exit("tool_node", state, decision)

        assert blocked is True
        assert "_pramanix_rejection" in state
