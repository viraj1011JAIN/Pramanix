# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""AutoGen integration for Pramanix — PramanixToolCallback.

Compatible with AutoGen >= 0.2 (ConversableAgent.register_for_execution pattern)
and AutoGen >= 0.4 (FunctionTool pattern).

Install: pip install 'pramanix[autogen]'

Usage (AutoGen v0.2)::

    callback = PramanixToolCallback(
        guard=guard,
        intent_schema=TransferIntent,
        state_provider=lambda: get_state(),
    )

    @assistant.register_for_execution()
    @assistant.register_for_llm(description="Transfer funds")
    @callback
    async def transfer(amount: float, recipient: str) -> str:
        return f"Transferred {amount} to {recipient}"

Usage (class method)::

    guarded_fn = PramanixToolCallback.wrap(
        transfer,
        guard=guard,
        intent_schema=TransferIntent,
        state_provider=state_provider,
    )
"""
from __future__ import annotations

import asyncio
import functools
from collections.abc import Callable
from typing import Any

from pramanix.guard import Guard
from pramanix.integrations._feedback import format_autogen_rejection

__all__ = ["PramanixToolCallback"]


class PramanixToolCallback:
    """Callable decorator class that gates AutoGen tool functions through Pramanix.

    A callable class (not a framework subclass) that works with all AutoGen
    versions >= 0.2.  Use it as a decorator to wrap any async or sync tool
    function with a Pramanix policy guard.

    The wrapped function **never raises** for policy violations — all blocks
    are returned as structured rejection strings so the orchestrating LLM can
    understand and adapt gracefully.

    Args:
        guard:          A pre-constructed :class:`~pramanix.guard.Guard`.
        intent_schema:  Pydantic model class for input validation.
        state_provider: Zero-argument callable returning ``dict`` (or coroutine).
        name:           Optional name override (defaults to wrapped function name).
        description:    Optional description for the tool.

    Example::

        callback = PramanixToolCallback(
            guard=guard,
            intent_schema=TransferIntent,
            state_provider=lambda: get_state(),
        )

        @callback
        async def transfer(amount: float, recipient: str) -> str:
            return f"Transferred {amount} to {recipient}"
    """

    def __init__(
        self,
        *,
        guard: Guard,
        intent_schema: Any,
        state_provider: Callable[[], Any],
        name: str = "",
        description: str = "",
    ) -> None:
        self._guard = guard
        self._intent_schema = intent_schema
        self._state_provider = state_provider
        self._name = name
        self._description = description

    # ── Decorator __call__ ────────────────────────────────────────────────────

    def __call__(self, fn: Callable[..., Any]) -> Callable[..., Any]:
        """Wrap *fn* with the Pramanix guard gate.

        Returns an ``async def _guarded(**kwargs) -> str`` that:

        1. Validates kwargs via ``intent_schema.model_validate``.
        2. Loads state via ``state_provider``.
        3. Calls ``guard.verify_async``.
        4. If ALLOW: calls ``fn(**kwargs)`` (awaits if coroutine) and returns
           ``str(result)``.
        5. If BLOCK: returns ``format_autogen_rejection(decision, intent)``
           (never raises).

        All exceptions from validation, state loading, or verification are
        caught and returned as rejection strings — the wrapped function never
        raises.

        Args:
            fn: The tool function to wrap (sync or async).

        Returns:
            An async wrapper with ``functools.wraps(fn)`` applied.
        """
        guard = self._guard
        intent_schema = self._intent_schema
        state_provider_ref = self._state_provider

        @functools.wraps(fn)
        async def _guarded(**kwargs: Any) -> str:
            # ── Step 1: Validate kwargs against intent schema ─────────────────
            try:
                intent: dict[str, Any] = intent_schema.model_validate(
                    kwargs, strict=True
                ).model_dump()
            except Exception as exc:
                # Return a safe rejection string — never raise.
                from pramanix.decision import Decision

                bad_decision = Decision.validation_failure(
                    reason=f"Intent validation failed: {exc}"
                )
                return format_autogen_rejection(bad_decision, dict(kwargs))

            # ── Step 2: Load state ────────────────────────────────────────────
            try:
                state: dict[str, Any] = await _get_state_inner(state_provider_ref)
            except Exception as exc:
                from pramanix.decision import Decision

                err_decision = Decision.error(reason=f"State provider error: {exc}")
                return format_autogen_rejection(err_decision, intent)

            # ── Step 3: Guard verify ──────────────────────────────────────────
            try:
                decision = await guard.verify_async(intent=intent, state=state)
            except Exception as exc:
                from pramanix.decision import Decision

                err_decision = Decision.error(reason=f"Guard verification error: {exc}")
                return format_autogen_rejection(err_decision, intent)

            # ── Step 4: ALLOW — call fn ───────────────────────────────────────
            if decision.allowed:
                try:
                    result = fn(**kwargs)
                    if asyncio.iscoroutine(result):
                        result = await result
                    return str(result)
                except Exception:
                    # Propagate genuine execution errors — only policy blocks
                    # are silently returned.  Caller can handle fn exceptions.
                    raise

            # ── Step 5: BLOCK — return rejection string, never raise ──────────
            return format_autogen_rejection(decision, intent)

        # Preserve original function identity for AutoGen's introspection.
        _guarded.__name__ = fn.__name__
        _guarded.__doc__ = fn.__doc__

        return _guarded

    # ── State retrieval ───────────────────────────────────────────────────────

    async def _get_state(self) -> dict[str, Any]:
        """Retrieve current state, awaiting if the provider is a coroutine."""
        return await _get_state_inner(self._state_provider)

    # ── Class method factory ──────────────────────────────────────────────────

    @classmethod
    def wrap(
        cls,
        fn: Callable[..., Any],
        *,
        guard: Guard,
        intent_schema: Any,
        state_provider: Callable[[], Any],
        name: str = "",
        description: str = "",
    ) -> Callable[..., Any]:
        """Convenience factory: create a callback and apply it to *fn* in one call.

        Equivalent to::

            callback = PramanixToolCallback(guard=g, ...)
            guarded_fn = callback(fn)

        Args:
            fn:             The tool function to wrap (sync or async).
            guard:          A pre-constructed :class:`~pramanix.guard.Guard`.
            intent_schema:  Pydantic model class for input validation.
            state_provider: Zero-argument callable returning ``dict``.
            name:           Optional name override.
            description:    Optional description.

        Returns:
            The wrapped async function.
        """
        callback = cls(
            guard=guard,
            intent_schema=intent_schema,
            state_provider=state_provider,
            name=name,
            description=description,
        )
        return callback(fn)


# ── Module-level helper (avoids closures capturing self) ─────────────────────


async def _get_state_inner(state_provider: Callable[[], Any]) -> dict[str, Any]:
    """Retrieve state from *state_provider*, awaiting if it returns a coroutine."""
    result = state_provider()
    if asyncio.iscoroutine(result):
        result = await result
    return result  # type: ignore[no-any-return]
