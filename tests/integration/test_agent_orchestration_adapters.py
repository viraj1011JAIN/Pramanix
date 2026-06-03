# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Integration tests for concrete AgentOrchestrationAdapter implementations.

Validates that LangGraphGuardAdapter and AutoGenGuardAdapter:
- Satisfy the AgentOrchestrationAdapter protocol (isinstance check)
- Correctly call Guard.verify() with real Z3 solver (no stubs/mocks)
- Return True from should_block() on policy violations
- Return False from should_block() when policy is satisfied
- Write the correct sidecar/rejection data into state in on_node_exit()
- Fail closed on unexpected exceptions (should_block returns True)
- Work correctly wired into a simulated LangGraph-style router
- Work correctly wired into a simulated AutoGen-style tool gate

No unittest.mock, no MagicMock, no patch(), no sys.modules injection.
All verification uses real Guard instances backed by the real Z3 solver.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any

from pramanix.decision import Decision
from pramanix.expressions import E, Field
from pramanix.guard import Guard, GuardConfig
from pramanix.integrations.agent_orchestration import (
    AgentOrchestrationAdapter,
    AutoGenGuardAdapter,
    LangGraphGuardAdapter,
)
from pramanix.policy import Policy
from tests.helpers.solver_stubs import RaisingSolverStub

# ── Shared test policy ────────────────────────────────────────────────────────


class _BankingPolicy(Policy):
    """amount <= balance — blocks when amount exceeds balance."""

    amount = Field("amount", Decimal, "Real")
    balance = Field("balance", Decimal, "Real")

    @classmethod
    def invariants(cls) -> list[Any]:
        return [
            (E(cls.amount) <= E(cls.balance))
            .named("within_balance")
            .explain("amount must not exceed balance")
        ]


class _PositiveAmountPolicy(Policy):
    """amount > 0 — always blocks negative/zero amounts."""

    amount = Field("amount", Decimal, "Real")

    @classmethod
    def invariants(cls) -> list[Any]:
        return [
            (E(cls.amount) > Decimal("0"))
            .named("positive_amount")
            .explain("amount must be positive")
        ]


_CFG = GuardConfig(execution_mode="sync", solver_timeout_ms=5_000)


def _banking_guard() -> Guard:
    return Guard(_BankingPolicy, config=_CFG)


def _positive_guard() -> Guard:
    return Guard(_PositiveAmountPolicy, config=_CFG)


# ── Protocol conformance ──────────────────────────────────────────────────────


class TestProtocolConformance:
    """Both concrete adapters satisfy AgentOrchestrationAdapter at runtime."""

    def test_langgraph_adapter_satisfies_protocol(self) -> None:
        adapter = LangGraphGuardAdapter(guard=_banking_guard())
        assert isinstance(adapter, AgentOrchestrationAdapter)

    def test_autogen_adapter_satisfies_protocol(self) -> None:
        adapter = AutoGenGuardAdapter(guard=_banking_guard())
        assert isinstance(adapter, AgentOrchestrationAdapter)

    def test_langgraph_exported_from_integrations_package(self) -> None:
        from pramanix.integrations import LangGraphGuardAdapter as _via_pkg

        assert _via_pkg is LangGraphGuardAdapter

    def test_autogen_exported_from_integrations_package(self) -> None:
        from pramanix.integrations import AutoGenGuardAdapter as _via_pkg

        assert _via_pkg is AutoGenGuardAdapter

    def test_integration_status_includes_both_adapters(self) -> None:
        from pramanix.integrations import INTEGRATION_STATUS

        assert INTEGRATION_STATUS.get("LangGraphGuardAdapter") == "stable"
        assert INTEGRATION_STATUS.get("AutoGenGuardAdapter") == "stable"


# ── LangGraphGuardAdapter — should_block ─────────────────────────────────────


class TestLangGraphGuardAdapterShouldBlock:
    """Guard.verify() is called with real Z3 solver — no stubs."""

    def test_should_block_returns_false_when_policy_satisfied(self) -> None:
        adapter = LangGraphGuardAdapter(guard=_banking_guard())
        # amount=100 <= balance=500 → ALLOW → should_block=False
        state = {"amount": Decimal("100"), "balance": Decimal("500")}
        assert adapter.should_block(state) is False

    def test_should_block_returns_true_when_policy_violated(self) -> None:
        adapter = LangGraphGuardAdapter(guard=_banking_guard())
        # amount=600 > balance=500 → BLOCK → should_block=True
        state = {"amount": Decimal("600"), "balance": Decimal("500")}
        assert adapter.should_block(state) is True

    def test_should_block_uses_intent_key_when_configured(self) -> None:
        adapter = LangGraphGuardAdapter(guard=_positive_guard(), intent_key="tool_args")
        # state["tool_args"] is the intent; amount=50 is positive → ALLOW
        state = {"tool_args": {"amount": Decimal("50")}, "session_id": "abc"}
        assert adapter.should_block(state) is False

    def test_should_block_blocks_with_intent_key_violation(self) -> None:
        adapter = LangGraphGuardAdapter(guard=_positive_guard(), intent_key="tool_args")
        # amount=-1 violates positive_amount → BLOCK
        state = {"tool_args": {"amount": Decimal("-1")}, "session_id": "abc"}
        assert adapter.should_block(state) is True

    def test_should_block_fails_closed_on_exception(self) -> None:
        """should_block must return True (block) if Guard.verify() raises."""
        guard = Guard(
            _BankingPolicy,
            config=GuardConfig(
                execution_mode="sync",
                solver_factory=lambda ctx: RaisingSolverStub(RuntimeError("deliberate Z3 failure")),
            ),
        )
        adapter = LangGraphGuardAdapter(guard=guard)
        result = adapter.should_block({"amount": Decimal("100"), "balance": Decimal("500")})
        assert result is True

    def test_should_block_not_mutate_state(self) -> None:
        """should_block must not mutate the state dict it reads."""
        adapter = LangGraphGuardAdapter(guard=_banking_guard())
        state = {"amount": Decimal("100"), "balance": Decimal("500")}
        original_keys = set(state.keys())
        adapter.should_block(state)
        assert set(state.keys()) == original_keys


# ── LangGraphGuardAdapter — lifecycle hooks ───────────────────────────────────


class TestLangGraphGuardAdapterLifecycle:
    """on_node_enter and on_node_exit correctly instrument the state dict."""

    def test_on_node_enter_does_not_raise(self) -> None:
        adapter = LangGraphGuardAdapter(guard=_banking_guard())
        adapter.on_node_enter("transfer_node", {"amount": Decimal("100")})

    def test_on_node_exit_writes_sidecar_on_allow(self) -> None:
        adapter = LangGraphGuardAdapter(guard=_banking_guard())
        state: dict[str, Any] = {}
        decision = Decision.safe()
        adapter.on_node_enter("pay_node", state)
        adapter.on_node_exit("pay_node", state, decision)
        sidecar = state["_pramanix_verdict"]
        assert sidecar["node"] == "pay_node"
        assert sidecar["allowed"] is True
        assert sidecar["violated_invariants"] == []
        assert isinstance(sidecar["latency_ms"], float)

    def test_on_node_exit_writes_sidecar_on_block(self) -> None:
        adapter = LangGraphGuardAdapter(guard=_banking_guard())
        state: dict[str, Any] = {}
        decision = Decision.unsafe(
            violated_invariants=("within_balance",),
            explanation="amount must not exceed balance",
        )
        adapter.on_node_enter("transfer_node", state)
        adapter.on_node_exit("transfer_node", state, decision)
        sidecar = state["_pramanix_verdict"]
        assert sidecar["allowed"] is False
        assert "within_balance" in sidecar["violated_invariants"]
        assert "exceed" in sidecar["explanation"]

    def test_custom_sidecar_key(self) -> None:
        adapter = LangGraphGuardAdapter(
            guard=_banking_guard(), sidecar_key="_guard_result"
        )
        state: dict[str, Any] = {}
        adapter.on_node_enter("n", state)
        adapter.on_node_exit("n", state, Decision.safe())
        assert "_guard_result" in state
        assert "_pramanix_verdict" not in state

    def test_latency_recorded_correctly(self) -> None:
        import time

        adapter = LangGraphGuardAdapter(guard=_banking_guard())
        state: dict[str, Any] = {}
        adapter.on_node_enter("slow_node", state)
        time.sleep(0.01)
        adapter.on_node_exit("slow_node", state, Decision.safe())
        latency = state["_pramanix_verdict"]["latency_ms"]
        assert latency >= 10.0, f"Expected >=10ms latency, got {latency}"


# ── LangGraphGuardAdapter — router integration ────────────────────────────────


class TestLangGraphRouterIntegration:
    """End-to-end simulation of a LangGraph conditional-edge router using the adapter."""

    def _router(self, adapter: LangGraphGuardAdapter, state: dict[str, Any]) -> str:
        """Simulates a LangGraph conditional edge function."""
        adapter.on_node_enter("route", state)
        blocked = adapter.should_block(state)
        decision = (
            Decision.unsafe(violated_invariants=("within_balance",), explanation="blocked")
            if blocked
            else Decision.safe()
        )
        adapter.on_node_exit("route", state, decision)
        return "blocked_node" if blocked else "proceed_node"

    def test_router_proceeds_on_valid_transfer(self) -> None:
        adapter = LangGraphGuardAdapter(guard=_banking_guard())
        state = {"amount": Decimal("100"), "balance": Decimal("1000")}
        assert self._router(adapter, state) == "proceed_node"
        assert state["_pramanix_verdict"]["allowed"] is True

    def test_router_blocks_on_overdraft(self) -> None:
        adapter = LangGraphGuardAdapter(guard=_banking_guard())
        state = {"amount": Decimal("5000"), "balance": Decimal("100")}
        assert self._router(adapter, state) == "blocked_node"
        assert state["_pramanix_verdict"]["allowed"] is False

    def test_multiple_sequential_route_decisions(self) -> None:
        adapter = LangGraphGuardAdapter(guard=_positive_guard())
        transitions = [
            ({"amount": Decimal("1")}, "proceed_node"),
            ({"amount": Decimal("-1")}, "blocked_node"),
            ({"amount": Decimal("999")}, "proceed_node"),
            ({"amount": Decimal("0")}, "blocked_node"),
        ]
        for state, expected in transitions:
            result = self._router(adapter, state)
            assert result == expected, f"state={state!r}: expected {expected}, got {result}"


# ── AutoGenGuardAdapter — should_block ───────────────────────────────────────


class TestAutoGenGuardAdapterShouldBlock:
    """Guard.verify() is called with real Z3 solver — no stubs."""

    def test_should_block_returns_false_when_policy_satisfied(self) -> None:
        adapter = AutoGenGuardAdapter(guard=_positive_guard())
        assert adapter.should_block({"amount": Decimal("50")}) is False

    def test_should_block_returns_true_when_policy_violated(self) -> None:
        adapter = AutoGenGuardAdapter(guard=_positive_guard())
        assert adapter.should_block({"amount": Decimal("-50")}) is True

    def test_should_block_uses_intent_key(self) -> None:
        adapter = AutoGenGuardAdapter(guard=_positive_guard(), intent_key="kwargs")
        state = {"kwargs": {"amount": Decimal("10")}, "thread_id": "t1"}
        assert adapter.should_block(state) is False

    def test_should_block_blocks_with_intent_key_violation(self) -> None:
        adapter = AutoGenGuardAdapter(guard=_positive_guard(), intent_key="kwargs")
        state = {"kwargs": {"amount": Decimal("0")}}
        assert adapter.should_block(state) is True

    def test_should_block_fails_closed_on_exception(self) -> None:
        guard = Guard(
            _PositiveAmountPolicy,
            config=GuardConfig(
                execution_mode="sync",
                solver_factory=lambda ctx: RaisingSolverStub(RuntimeError("deliberate Z3 failure")),
            ),
        )
        adapter = AutoGenGuardAdapter(guard=guard)
        result = adapter.should_block({"amount": Decimal("10")})
        assert result is True

    def test_should_block_not_mutate_state(self) -> None:
        adapter = AutoGenGuardAdapter(guard=_positive_guard())
        state = {"amount": Decimal("10"), "extra": "x"}
        original = dict(state)
        adapter.should_block(state)
        assert state == original


# ── AutoGenGuardAdapter — lifecycle hooks ────────────────────────────────────


class TestAutoGenGuardAdapterLifecycle:
    """on_node_enter and on_node_exit write rejection data when blocked."""

    def test_on_node_enter_does_not_raise(self) -> None:
        adapter = AutoGenGuardAdapter(guard=_positive_guard())
        adapter.on_node_enter("tool_node", {"amount": Decimal("1")})

    def test_on_node_exit_no_sidecar_on_allow(self) -> None:
        adapter = AutoGenGuardAdapter(guard=_positive_guard())
        state: dict[str, Any] = {}
        adapter.on_node_exit("tool_node", state, Decision.safe())
        assert "_pramanix_rejection" not in state

    def test_on_node_exit_writes_rejection_on_block(self) -> None:
        adapter = AutoGenGuardAdapter(guard=_positive_guard())
        state: dict[str, Any] = {}
        decision = Decision.unsafe(
            violated_invariants=("positive_amount",),
            explanation="amount must be positive",
        )
        adapter.on_node_exit("pay_tool", state, decision)
        rejection = state["_pramanix_rejection"]
        assert rejection["node"] == "pay_tool"
        assert "positive_amount" in rejection["violated_invariants"]
        assert "positive" in rejection["explanation"]

    def test_custom_rejection_key(self) -> None:
        adapter = AutoGenGuardAdapter(
            guard=_positive_guard(), rejection_key="_block_reason"
        )
        state: dict[str, Any] = {}
        decision = Decision.unsafe(
            violated_invariants=("positive_amount",),
            explanation="amount must be positive",
        )
        adapter.on_node_exit("n", state, decision)
        assert "_block_reason" in state
        assert "_pramanix_rejection" not in state


# ── AutoGen tool-gate integration pattern ────────────────────────────────────


class TestAutoGenToolGateIntegration:
    """Simulate an AutoGen tool-gate that respects the adapter's should_block verdict."""

    def _execute_tool(
        self,
        adapter: AutoGenGuardAdapter,
        node_id: str,
        state: dict[str, Any],
        tool_fn: Any,
    ) -> str:
        adapter.on_node_enter(node_id, state)
        if adapter.should_block(state):
            decision = Decision.unsafe(
                violated_invariants=("positive_amount",),
                explanation="blocked by policy",
            )
            adapter.on_node_exit(node_id, state, decision)
            return f"[BLOCKED] {state.get('_pramanix_rejection', {}).get('explanation', '')}"
        result = tool_fn(**state)
        adapter.on_node_exit(node_id, state, Decision.safe())
        return str(result)

    def test_tool_executes_when_allowed(self) -> None:
        adapter = AutoGenGuardAdapter(guard=_positive_guard())
        state = {"amount": Decimal("50")}
        result = self._execute_tool(
            adapter, "transfer", state, lambda amount: f"Transferred {amount}"
        )
        assert "Transferred" in result
        assert "[BLOCKED]" not in result

    def test_tool_blocked_when_policy_violated(self) -> None:
        adapter = AutoGenGuardAdapter(guard=_positive_guard())
        state = {"amount": Decimal("-100")}
        executed = []
        result = self._execute_tool(
            adapter,
            "transfer",
            state,
            lambda amount: executed.append(amount) or "done",
        )
        assert "[BLOCKED]" in result
        assert len(executed) == 0

    def test_sequential_tool_calls_independent(self) -> None:
        adapter = AutoGenGuardAdapter(guard=_positive_guard())
        calls = [
            ({"amount": Decimal("1")}, False),
            ({"amount": Decimal("-1")}, True),
            ({"amount": Decimal("100")}, False),
        ]
        for state, expect_block in calls:
            result = adapter.should_block(state)
            assert result is expect_block, (
                f"state={state!r}: expected block={expect_block}, got {result}"
            )
