# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""CrewAI integration for Pramanix — Phase F-1.

Wraps any CrewAI ``BaseTool`` (or plain callable) so that every execution is
gated by a ``Guard.verify()`` call.  If the guard blocks the action, the tool
returns a structured safe-failure message instead of crashing the agent.

Install: pip install 'pramanix[crewai]'
Requires: crewai >= 0.1

Usage::

    from pramanix.integrations.crewai import PramanixCrewAITool

    safe_tool = PramanixCrewAITool(
        name="transfer_funds",
        description="Move money between accounts",
        guard=Guard(TransferPolicy, config=GuardConfig(execution_mode="sync")),
        intent_builder=lambda tool_input: {"amount": tool_input["amount"], ...},
        state_provider=lambda: {"balance": fetch_balance(), ...},
    )

    agent = Agent(tools=[safe_tool], ...)
"""
from __future__ import annotations

import logging
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from pramanix.integrations._feedback import format_block_feedback

if TYPE_CHECKING:
    from pramanix.guard import Guard

__all__ = ["PramanixCrewAITool"]

_log = logging.getLogger(__name__)
_SAFE_FAILURE_PREFIX = "[PRAMANIX_BLOCKED]"


try:
    from crewai.tools import BaseTool as _CrewAIBase

    _CREWAI_AVAILABLE = True
except ImportError:
    _CREWAI_AVAILABLE = False
    _CrewAIBase = object


class PramanixCrewAITool(_CrewAIBase if _CREWAI_AVAILABLE else object):  # type: ignore[misc]
    """CrewAI ``BaseTool`` subclass with Z3 formal verification gate.

    If CrewAI is **not** installed the class still functions as a plain
    callable wrapper usable in tests and non-CrewAI contexts.

    Args:
        name:            Tool name shown to the agent.
        description:     Tool description shown to the agent.
        guard:           A fully constructed :class:`~pramanix.guard.Guard`.
        intent_builder:  Callable ``(tool_input: dict) → intent dict`` that
                         maps raw tool arguments to the Guard's intent schema.
        state_provider:  Callable ``() → state dict`` that fetches current
                         system state at call time.
        underlying_fn:   The actual tool implementation invoked when the Guard
                         allows the action.  Receives the raw ``tool_input``
                         dict and must return a string result.
        block_message:   Optional custom message returned when the guard
                         blocks the action.  If ``None``, a detailed
                         violation message is generated automatically.

    Raises:
        ImportError: If ``crewai`` is not installed and the subclass
                     requirement is strict (soft-fail by default).
    """

    # Pydantic v2 / CrewAI compatibility — declare fields at class level so
    # CrewAI's Pydantic model introspection finds them.
    name: str = ""
    description: str = ""

    def __init__(
        self,
        *,
        name: str,
        description: str,
        guard: Guard,
        intent_builder: Callable[[dict[str, Any]], dict[str, Any]],
        state_provider: Callable[[], dict[str, Any]],
        underlying_fn: Callable[[dict[str, Any]], str] | None = None,
        block_message: str | None = None,
    ) -> None:
        if _CREWAI_AVAILABLE:
            # Let CrewAI's Pydantic model handle field assignment.
            super().__init__(name=name, description=description)
        else:
            self.name = name
            self.description = description

        # Store guard state using object.__setattr__ to bypass Pydantic
        # field validation (these are behavioural, not domain fields).
        object.__setattr__(self, "_guard", guard)
        object.__setattr__(self, "_intent_builder", intent_builder)
        object.__setattr__(self, "_state_provider", state_provider)
        object.__setattr__(self, "_underlying_fn", underlying_fn)
        object.__setattr__(self, "_block_message", block_message)

    # ── CrewAI BaseTool protocol ──────────────────────────────────────────────

    def _run(self, **tool_input: Any) -> str:
        """Synchronous execution — called by CrewAI's agent loop."""
        return self._execute(tool_input)

    async def _arun(self, **tool_input: Any) -> str:
        """Async execution — called by CrewAI's async agent loop."""
        return self._execute(tool_input)

    # ── Plain-callable interface (non-CrewAI usage) ───────────────────────────

    def __call__(self, tool_input: dict[str, Any] | None = None, **kwargs: Any) -> str:
        """Direct call interface for non-CrewAI contexts."""
        merged = dict(tool_input or {})
        merged.update(kwargs)
        return self._execute(merged)

    # ── Core execution logic ──────────────────────────────────────────────────

    def _execute(self, tool_input: dict[str, Any]) -> str:
        """Run the guard check and, if allowed, the underlying tool."""
        guard: Guard = object.__getattribute__(self, "_guard")
        intent_builder: Callable[..., Any] = object.__getattribute__(self, "_intent_builder")
        state_provider: Callable[..., Any] = object.__getattribute__(self, "_state_provider")
        underlying_fn: Callable[..., str] | None = object.__getattribute__(self, "_underlying_fn")
        block_message: str | None = object.__getattribute__(self, "_block_message")

        try:
            intent = intent_builder(tool_input)
            state = state_provider()
            decision = guard.verify(intent=intent, state=state)
        except Exception as exc:
            _log.error("pramanix.crewai.guard_error: %s", exc, exc_info=True)
            return (
                f"{_SAFE_FAILURE_PREFIX} Guard error during verification. "
                "Action blocked as a precaution."
            )

        if not decision.allowed:
            if block_message:
                return f"{_SAFE_FAILURE_PREFIX} {block_message}"
            return (
                f"{_SAFE_FAILURE_PREFIX} "
                + format_block_feedback(decision, {})
            )

        if underlying_fn is not None:
            return str(underlying_fn(tool_input))

        return f"Action '{self.name}' allowed by Pramanix guard. No underlying function configured."
