# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
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


_CREWAI_AVAILABLE: bool = False

if TYPE_CHECKING:
    from crewai.tools import BaseTool as _CrewAIBase
else:
    try:
        from crewai.tools import BaseTool as _CrewAIBase

        _CREWAI_AVAILABLE = True
    except ImportError:
        _CrewAIBase = object


class _PramanixState:
    """Plain-Python container for guard state — invisible to Pydantic/CrewAI.

    Storing all non-field attributes here means only a single
    ``object.__setattr__`` bypass is needed (for the container itself),
    rather than one per attribute.  This minimises the surface area that
    could be affected by upstream Pydantic or CrewAI model changes.
    """

    __slots__ = ("guard", "intent_builder", "state_provider", "underlying_fn", "block_message")

    def __init__(
        self,
        guard: Any,
        intent_builder: Any,
        state_provider: Any,
        underlying_fn: Any,
        block_message: Any,
    ) -> None:
        self.guard = guard
        self.intent_builder = intent_builder
        self.state_provider = state_provider
        self.underlying_fn = underlying_fn
        self.block_message = block_message


class PramanixCrewAITool(_CrewAIBase):
    """CrewAI ``BaseTool`` subclass with Z3 formal verification gate.

    When crewai is installed, ``_CrewAIBase`` is ``crewai.tools.BaseTool``
    and this class is a proper subclass registered in CrewAI's tool registry.
    When crewai is absent, ``_CrewAIBase`` falls back to ``object``, so the
    class still functions as a plain callable wrapper for non-CrewAI contexts.

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
        if not _CREWAI_AVAILABLE:
            raise ImportError(
                "PramanixCrewAITool requires 'crewai': "
                "pip install 'pramanix[crewai]'"
            )
        # Let CrewAI's Pydantic model handle field assignment.
        super().__init__(name=name, description=description)

        # Store all guard state in a single plain-Python container.  One
        # object.__setattr__ bypass is narrower than five separate ones and
        # survives Pydantic / CrewAI upstream changes more robustly.
        object.__setattr__(
            self,
            "_pramanix",
            _PramanixState(guard, intent_builder, state_provider, underlying_fn, block_message),
        )

    # ── CrewAI BaseTool protocol ──────────────────────────────────────────────

    def _run(self, **tool_input: Any) -> str:
        """Synchronous execution — called by CrewAI's agent loop."""
        return self._execute(tool_input)

    async def _arun(self, **tool_input: Any) -> str:
        """Async execution — called by CrewAI's async agent loop.

        Uses :meth:`~pramanix.guard.Guard.verify_async` to avoid blocking the
        event loop during Z3 solving (previously called sync ``verify()`` which
        would stall the entire async CrewAI agent loop for solver duration).
        """
        st: _PramanixState = object.__getattribute__(self, "_pramanix")
        try:
            intent = st.intent_builder(tool_input)
            state = st.state_provider()
            decision = await st.guard.verify_async(intent=intent, state=state)
        except Exception as exc:
            _log.error("pramanix.crewai.guard_error: %s", exc, exc_info=True)
            return (
                f"{_SAFE_FAILURE_PREFIX} Guard error during async verification. "
                "Action blocked as a precaution."
            )
        if not decision.allowed:
            if st.block_message:
                return f"{_SAFE_FAILURE_PREFIX} {st.block_message}"
            return f"{_SAFE_FAILURE_PREFIX} " + format_block_feedback(decision, {})
        if st.underlying_fn is not None:
            import asyncio as _asyncio
            if _asyncio.iscoroutinefunction(st.underlying_fn):
                return str(await st.underlying_fn(tool_input))
            return str(st.underlying_fn(tool_input))
        from pramanix.exceptions import ConfigurationError
        raise ConfigurationError(
            f"PramanixCrewAITool '{self.name}': decision is ALLOW but no "
            "underlying_fn was supplied at construction time."
        )

    # ── Plain-callable interface (non-CrewAI usage) ───────────────────────────

    def __call__(self, tool_input: dict[str, Any] | None = None, **kwargs: Any) -> str:
        """Direct call interface for non-CrewAI contexts."""
        merged = dict(tool_input or {})
        merged.update(kwargs)
        return self._execute(merged)

    # ── Core execution logic ──────────────────────────────────────────────────

    def _execute(self, tool_input: dict[str, Any]) -> str:
        """Run the guard check and, if allowed, the underlying tool."""
        st: _PramanixState = object.__getattribute__(self, "_pramanix")

        try:
            intent = st.intent_builder(tool_input)
            state = st.state_provider()
            decision = st.guard.verify(intent=intent, state=state)
        except Exception as exc:
            _log.error("pramanix.crewai.guard_error: %s", exc, exc_info=True)
            return (
                f"{_SAFE_FAILURE_PREFIX} Guard error during verification. "
                "Action blocked as a precaution."
            )

        if not decision.allowed:
            if st.block_message:
                return f"{_SAFE_FAILURE_PREFIX} {st.block_message}"
            return f"{_SAFE_FAILURE_PREFIX} " + format_block_feedback(decision, {})

        if st.underlying_fn is not None:
            return str(st.underlying_fn(tool_input))

        from pramanix.exceptions import ConfigurationError

        raise ConfigurationError(
            f"PramanixCrewAITool '{self.name}': decision is ALLOW but no "
            "underlying_fn was supplied at construction time. "
            "Pass underlying_fn=<callable> when creating the tool."
        )
