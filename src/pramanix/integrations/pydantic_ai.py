# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""PydanticAI integration for Pramanix — Phase F-1.

Integrates Pramanix :class:`~pramanix.guard.Guard` with PydanticAI tool
validation hooks.  The ``PramanixPydanticAIValidator`` can be used as a
``RunContext`` validator or as a standalone tool wrapper to ensure agent tools
only execute when the Guard allows it.

Install: pip install 'pramanix[pydantic-ai]'
Requires: pydantic-ai >= 0.0.9

Usage::

    from pramanix.integrations.pydantic_ai import PramanixPydanticAIValidator

    validator = PramanixPydanticAIValidator(guard=guard)

    @agent.tool
    async def transfer(ctx: RunContext[Deps], amount: float, to: str) -> str:
        await validator.check_async(
            intent={"amount": amount, "recipient": to},
            state={"balance": ctx.deps.balance},
        )
        return await do_transfer(amount, to)
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from pramanix.decision import Decision
from pramanix.exceptions import ConfigurationError, GuardViolationError

if TYPE_CHECKING:
    from pramanix.guard import Guard

__all__ = ["PramanixPydanticAIValidator"]


class PramanixPydanticAIValidator:
    """PydanticAI-compatible validator wrapping a Pramanix Guard.

    Can be used in three ways:

    1. **Direct call** — ``validator.check(intent, state)`` / ``await validator.check_async(…)``
       raises :exc:`~pramanix.exceptions.GuardViolationError` if the Guard
       blocks the request.

    2. **Decorator** — ``@validator.guard_tool`` wraps an async pydantic-ai
       tool function, injecting guard verification before the tool body runs.

    3. **Context hook** — Register via ``agent.system_prompt`` or
       ``RunContext`` validators if pydantic-ai exposes hook points.

    Args:
        guard:       A fully constructed :class:`~pramanix.guard.Guard`.
        state_fn:    Optional callable ``() → dict`` providing current state.
                     If ``None``, callers must pass ``state=`` explicitly.

    Raises:
        ConfigurationError: If ``pydantic-ai`` is not installed.
    """

    def __init__(
        self,
        guard: Guard,
        state_fn: Any | None = None,
    ) -> None:
        self._guard = guard
        self._state_fn = state_fn

        try:
            import pydantic_ai  # noqa: F401
        except ImportError as exc:
            raise ConfigurationError(
                "pydantic-ai is required for PramanixPydanticAIValidator. "
                "Install it with: pip install 'pramanix[pydantic-ai]'"
            ) from exc

    def check(
        self,
        intent: dict[str, Any],
        state: dict[str, Any] | None = None,
    ) -> Decision:
        """Synchronous guard check.

        Args:
            intent: Intent dict to verify.
            state:  Current state dict.  Falls back to ``state_fn()`` if omitted.

        Raises:
            GuardViolationError: If the Guard blocks the intent.
        """
        resolved: dict[str, Any] = (
            state if state is not None else (self._state_fn() if self._state_fn is not None else {})
        )
        decision = self._guard.verify(intent=intent, state=resolved)
        if not decision.allowed:
            raise GuardViolationError(decision)
        return decision

    async def check_async(
        self,
        intent: dict[str, Any],
        state: dict[str, Any] | None = None,
    ) -> Decision:
        """Asynchronous guard check.

        Args:
            intent: Intent dict to verify.
            state:  Current state dict.  Falls back to ``state_fn()`` if omitted.

        Raises:
            GuardViolationError: If the Guard blocks the intent.
        """
        resolved: dict[str, Any] = (
            state if state is not None else (self._state_fn() if self._state_fn is not None else {})
        )
        decision = await self._guard.verify_async(intent=intent, state=resolved)
        if not decision.allowed:
            raise GuardViolationError(decision)
        return decision

    def guard_tool(self, fn: Any) -> Any:
        """Decorator for pydantic-ai tool functions.

        Wraps an async tool so the Guard check runs before the tool body.
        The decorated tool must have ``intent`` and optionally ``state``
        keyword arguments that are forwarded to :meth:`check_async`.

        Args:
            fn: Async pydantic-ai tool function.

        Returns:
            Wrapped coroutine function with guard pre-check.

        Example::

            @agent.tool
            @validator.guard_tool
            async def withdraw(ctx, intent: dict, state: dict | None = None) -> str:
                ...
        """
        import functools

        @functools.wraps(fn)
        async def _wrapper(*args: Any, **kwargs: Any) -> Any:
            intent: dict[str, Any] = kwargs.get("intent", {})
            state: dict[str, Any] | None = kwargs.get("state")
            await self.check_async(intent=intent, state=state)
            return await fn(*args, **kwargs)

        return _wrapper
