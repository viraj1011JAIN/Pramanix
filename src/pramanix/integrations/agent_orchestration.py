# SPDX-License-Identifier: AGPL-3.0-only
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

from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from pramanix.decision import Decision

__all__ = ["AgentOrchestrationAdapter"]


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
