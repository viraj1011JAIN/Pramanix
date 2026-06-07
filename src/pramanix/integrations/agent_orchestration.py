# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""AgentOrchestrationAdapter — framework-agnostic Protocol for agent graph integration.

This module defines :class:`AgentOrchestrationAdapter`, a ``@runtime_checkable``
Protocol that unifies how Pramanix guards are wired into any agent orchestration
framework (LangGraph, AutoGen, CrewAI, etc.) as a first-class gate.

Architecture overview
---------------------
Agent orchestration frameworks model computation as directed graphs of *nodes*.
Each node receives a *state* dict, mutates it, and optionally decides the next
step.  Pramanix can be inserted as a guard gate at any node boundary:

.. code-block:: text

    ┌─────────────────────────────────────────────────────────┐
    │ Agent Graph                                             │
    │                                                         │
    │  [LLM Node] ──state──► [Guard Gate] ──state──► [Tool]  │
    │                              │                          │
    │                              └── BLOCKED ──► [Fallback] │
    └─────────────────────────────────────────────────────────┘

The :class:`AgentOrchestrationAdapter` Protocol specifies the three lifecycle
hooks that any framework adapter must implement:

- :meth:`on_node_enter` — called when the state machine enters a guarded node.
- :meth:`on_node_exit` — called after the node executes; receives the Decision.
- :meth:`should_block` — synchronous predicate used by routers to short-circuit.

LangGraph integration pattern
------------------------------
Wire Pramanix as a LangGraph conditional edge::

    from pramanix.integrations.agent_orchestration import AgentOrchestrationAdapter
    from pramanix.integrations.langgraph import PramanixGuardNode

    class MyAdapter(AgentOrchestrationAdapter):
        def __init__(self, guard: Guard):
            self._guard = guard

        def on_node_enter(self, node_id: str, state: dict) -> None:
            pass  # audit / telemetry

        def on_node_exit(self, node_id: str, state: dict, decision: Decision) -> None:
            if not decision.allowed:
                state["error"] = decision.explanation  # surface reason to LLM

        def should_block(self, state: dict) -> bool:
            d = self._guard.verify(intent=state.get("intent", {}), state=state)
            return not d.allowed

Usage in any framework::

    # Use isinstance() at runtime — @runtime_checkable guarantees this works:
    assert isinstance(my_adapter, AgentOrchestrationAdapter)

Notes
-----
- All methods are synchronous.  Async adapters should expose a thin sync wrapper
  or use ``asyncio.run()`` where the framework permits.  Async adapter support
  is tracked in https://github.com/pramanix-dev/pramanix/issues/xxx.
- :meth:`should_block` is deliberately non-caching.  State is read-only during
  the predicate; the adapter must not mutate it.

References
----------
- §6.7 item 4 of flaws.md: "Formalise the LangGraph integration pattern as a
  concrete AgentOrchestrationAdapter Protocol, exportable from the integrations
  sub-package, with @runtime_checkable so isinstance() checks work at runtime."
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from pramanix.decision import Decision
    from pramanix.guard import Guard

__all__ = [
    "AgentOrchestrationAdapter",
    "LangGraphGuardAdapter",
    "AutoGenGuardAdapter",
]

_log = logging.getLogger(__name__)


@runtime_checkable
class AgentOrchestrationAdapter(Protocol):
    """Framework-agnostic adapter protocol for wiring Pramanix into agent graphs.

    Any class that implements all three methods is automatically a valid
    ``AgentOrchestrationAdapter`` — no explicit inheritance required.

    Implementors must provide all three methods.  Default no-ops are NOT
    supplied by the Protocol; all methods must be explicitly defined so that
    adapter implementations are always complete and deliberate.

    Parameters carried through the lifecycle
    -----------------------------------------
    node_id:
        Opaque string identifying the graph node (e.g. ``"transfer_node"``).
        Frameworks typically use the function name or a user-supplied label.
    state:
        The current agent state dict.  **Do not mutate this in**
        :meth:`on_node_enter` — wait for :meth:`on_node_exit` if you need to
        annotate the state with a decision result.
    decision:
        The :class:`~pramanix.decision.Decision` returned by ``Guard.verify()``.
        Only present in :meth:`on_node_exit`.
    """

    def on_node_enter(self, node_id: str, state: dict[str, Any]) -> None:
        """Called when the orchestrator is about to enter a guarded node.

        Use this hook for:
        - Pre-entry audit logging.
        - Recording timestamps for latency tracking.
        - Injecting telemetry span identifiers into the state.

        Args:
            node_id: Identifier for the graph node being entered.
            state:   Current agent state (do not mutate).
        """
        ...

    def on_node_exit(
        self,
        node_id: str,
        state: dict[str, Any],
        decision: Decision,
    ) -> None:
        """Called after a guarded node executes with the resulting Decision.

        Use this hook for:
        - Post-exit audit logging.
        - Writing the denial reason into the state for downstream LLM nodes.
        - Emitting Prometheus/OTLP metrics.

        Args:
            node_id:  Identifier for the graph node that just executed.
            state:    Current agent state (may be mutated here if required).
            decision: The :class:`~pramanix.decision.Decision` from the guard.
        """
        ...

    def should_block(self, state: dict[str, Any]) -> bool:
        """Synchronous predicate consumed by router nodes in the agent graph.

        Called by conditional-edge routers to decide the next node::

            def route(state):
                if adapter.should_block(state):
                    return "blocked_node"
                return "proceed_node"

        **Invariant**: must NOT mutate *state*.

        Args:
            state: Current agent state (read-only).

        Returns:
            ``True`` if the guard would block the intent in *state*,
            ``False`` if the guard would allow it.
        """
        ...


# ── Concrete adapter implementations ─────────────────────────────────────────


class LangGraphGuardAdapter:
    """Concrete ``AgentOrchestrationAdapter`` for LangGraph state machines.

    Wraps a :class:`~pramanix.guard.Guard` and implements the three lifecycle
    hooks so Pramanix can be inserted as a conditional edge in any LangGraph
    StateGraph without subclassing or mocking.

    ``should_block()`` calls ``Guard.verify()`` synchronously — safe to call
    from any LangGraph router function.  The ``on_node_exit()`` hook writes the
    full policy verdict sidecar (including latency and violated invariants) into
    the state dict under ``sidecar_key`` so downstream nodes and the LLM have
    full context about why an action was blocked.

    Args:
        guard:       A pre-constructed :class:`~pramanix.guard.Guard`.
        intent_key:  State key whose value is passed as ``intent`` to
                     ``Guard.verify()``.  When ``None`` the entire state dict
                     is used as intent.
        state_key:   State key whose value is passed as ``state`` to
                     ``Guard.verify()``.  When ``None`` ``{}`` is used.
        sidecar_key: Key written into the state dict by ``on_node_exit()``
                     with the full policy verdict.

    Example::

        from pramanix.integrations.agent_orchestration import LangGraphGuardAdapter

        adapter = LangGraphGuardAdapter(guard=guard, intent_key="intent")

        def router(state):
            return "blocked" if adapter.should_block(state) else "proceed"
    """

    def __init__(
        self,
        *,
        guard: Guard,
        intent_key: str | None = None,
        state_key: str | None = None,
        sidecar_key: str = "_pramanix_verdict",
    ) -> None:
        self._guard = guard
        self._intent_key = intent_key
        self._state_key = state_key
        self._sidecar_key = sidecar_key
        # Use a deque per node_id (FIFO) so concurrent parallel branches of the
        # same node each push their own entry time and pop the oldest entry on exit.
        # This prevents concurrent same-node calls from overwriting each other's
        # timestamps (the previous dict approach would set/get by key, so Thread A
        # could overwrite Thread B's entry and both would see wrong latencies).
        # A deque also bounds memory: entries that never get an on_node_exit call
        # (leaked entries) are bounded by the depth of the parallel fan-out.
        import collections as _coll
        import threading as _thr
        self._enter_times: dict[str, _coll.deque[float]] = _coll.defaultdict(_coll.deque)
        self._enter_times_lock = _thr.Lock()

    def on_node_enter(self, node_id: str, state: dict[str, Any]) -> None:
        """Record the node entry timestamp for latency tracking."""
        with self._enter_times_lock:
            self._enter_times[node_id].append(time.perf_counter())
        _log.debug("pramanix.langgraph.enter node=%s", node_id)

    def on_node_exit(
        self,
        node_id: str,
        state: dict[str, Any],
        decision: Decision,
    ) -> None:
        """Write the policy verdict sidecar into *state* under ``sidecar_key``."""
        with self._enter_times_lock:
            times_q = self._enter_times.get(node_id)
            enter_t = times_q.popleft() if times_q else time.perf_counter()
        latency_ms = (time.perf_counter() - enter_t) * 1000.0

        state[self._sidecar_key] = {
            "node": node_id,
            "allowed": decision.allowed,
            "status": decision.status.value,
            "violated_invariants": list(decision.violated_invariants),
            "explanation": decision.explanation,
            "latency_ms": round(latency_ms, 3),
        }
        _log.debug(
            "pramanix.langgraph.exit node=%s allowed=%s",
            node_id,
            decision.allowed,
        )

    def should_block(self, state: dict[str, Any]) -> bool:
        """Return ``True`` if the guard would block the intent in *state*.

        Extracts ``intent`` and ``state`` payloads from the state dict using
        the configured ``intent_key`` / ``state_key``, then calls
        ``Guard.verify()`` synchronously.  Never raises — any error is treated
        as a block (fail-closed).
        """
        try:
            intent: dict[str, Any] = (
                dict(state.get(self._intent_key, state))
                if self._intent_key is not None
                else dict(state)
            )
            payload: dict[str, Any] = (
                dict(state.get(self._state_key, {}))
                if self._state_key is not None
                else {}
            )
            decision = self._guard.verify(intent=intent, state=payload)
            return not decision.allowed
        except Exception:
            _log.exception("pramanix.langgraph.should_block error — failing closed")
            return True


class AutoGenGuardAdapter:
    """Concrete ``AgentOrchestrationAdapter`` for AutoGen conversation graphs.

    Implements the three lifecycle hooks so Pramanix can be wired into any
    AutoGen-style multi-agent conversation as a guard gate.  The adapter is
    completely framework-agnostic — it does not import ``pyautogen`` and works
    with any class whose tool functions accept keyword arguments.

    ``should_block()`` calls ``Guard.verify()`` synchronously.  The
    ``on_node_exit()`` hook records the rejection reason under ``rejection_key``
    in the state dict so the orchestrating agent has full context.

    Args:
        guard:         A pre-constructed :class:`~pramanix.guard.Guard`.
        intent_key:    State key whose value is the intent dict.  When ``None``
                       the full state dict is treated as intent.
        rejection_key: Key written into state by ``on_node_exit()`` when the
                       action is blocked.  Contains the explanation string.

    Example::

        from pramanix.integrations.agent_orchestration import AutoGenGuardAdapter

        adapter = AutoGenGuardAdapter(guard=guard, intent_key="tool_args")

        def should_execute(state):
            return not adapter.should_block(state)
    """

    def __init__(
        self,
        *,
        guard: Guard,
        intent_key: str | None = None,
        rejection_key: str = "_pramanix_rejection",
    ) -> None:
        self._guard = guard
        self._intent_key = intent_key
        self._rejection_key = rejection_key

    def on_node_enter(self, node_id: str, state: dict[str, Any]) -> None:
        """No-op for AutoGen — tool calls do not have a separate entry phase."""
        _log.debug("pramanix.autogen.enter node=%s", node_id)

    def on_node_exit(
        self,
        node_id: str,
        state: dict[str, Any],
        decision: Decision,
    ) -> None:
        """Write the rejection reason into *state* when the action was blocked."""
        if not decision.allowed:
            state[self._rejection_key] = {
                "node": node_id,
                "explanation": decision.explanation,
                "violated_invariants": list(decision.violated_invariants),
            }
        _log.debug(
            "pramanix.autogen.exit node=%s allowed=%s",
            node_id,
            decision.allowed,
        )

    def should_block(self, state: dict[str, Any]) -> bool:
        """Return ``True`` if the guard would block the intent in *state*.

        Extracts the intent from ``state[intent_key]`` when configured, or
        uses the full state dict as intent.  Never raises — any error is a block.
        """
        try:
            intent: dict[str, Any] = (
                dict(state.get(self._intent_key, state))
                if self._intent_key is not None
                else dict(state)
            )
            decision = self._guard.verify(intent=intent, state={})
            return not decision.allowed
        except Exception:
            _log.exception("pramanix.autogen.should_block error — failing closed")
            return True
