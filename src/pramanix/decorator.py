# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""``@guard`` decorator — one-line async policy enforcement.

Usage::

    from pramanix import guard, Guard, GuardConfig, Policy, Field, E

    class BankingPolicy(Policy): ...

    @guard(policy=BankingPolicy, config=GuardConfig(execution_mode="async-thread"))
    async def transfer(intent: dict, state: dict) -> dict:
        # Only reached when Guard.verify_async() returns Decision(allowed=True)
        return {"status": "ok"}

    # on_block="return" - return the Decision instead of raising
    @guard(policy=BankingPolicy, on_block="return")
    async def transfer_soft(intent: dict, state: dict) -> dict | Decision:
        return {"status": "ok"}

The decorated function must be an ``async def`` coroutine.  Passing a sync
function raises :exc:`TypeError` at decoration time (not at call time), so
mistakes are caught immediately.
"""
from __future__ import annotations

import asyncio
import functools
from typing import TYPE_CHECKING, Any, Literal

from pramanix.exceptions import GuardViolationError

if TYPE_CHECKING:
    from collections.abc import Callable

    from pramanix.decision import Decision
    from pramanix.guard import Guard, GuardConfig
    from pramanix.policy import Policy

__all__ = ["guard"]


def guard(
    *,
    policy: type[Policy],
    config: GuardConfig | None = None,
    on_block: Literal["raise", "return"] = "raise",
) -> Callable[[Any], Any]:
    """Policy-enforcement decorator factory.

    Creates a :class:`~pramanix.guard.Guard` instance **once** at decoration
    time and reuses it across all calls to the wrapped function.

    Args:
        policy:   A :class:`~pramanix.policy.Policy` subclass (the class,
                  not an instance).
        config:   Optional :class:`~pramanix.guard.GuardConfig`.  Defaults to
                  ``GuardConfig()`` (sync mode, 5 000 ms timeout).
        on_block: What to do when the Guard blocks the action:

                  * ``"raise"``  — raise :exc:`GuardViolationError` (default).
                  * ``"return"`` — return the blocked :class:`Decision` to the
                    caller without executing the wrapped function.

    Returns:
        A decorator that wraps an ``async def`` function.

    Raises:
        TypeError: At decoration time if the wrapped function is not a
            coroutine function (``async def``).

    Example::

        @guard(policy=BankingPolicy)
        async def handle_transfer(intent, state): ...
    """
    # Import here to avoid circular imports at module load time.
    from pramanix.guard import Guard, GuardConfig

    _config = config or GuardConfig()
    _guard_instance: Guard = Guard(policy=policy, config=_config)

    def decorator(fn: Any) -> Any:
        if not asyncio.iscoroutinefunction(fn):
            raise TypeError(
                f"@guard can only decorate async functions (coroutines). "
                f"'{fn.__name__}' is a synchronous function. "
                "Use guard_instance.verify() directly for sync contexts."
            )

        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Extract intent and state from positional / keyword args.
            # Convention: first two positional args are (intent, state).
            if len(args) < 2:
                intent = kwargs.get("intent", {})
                state = kwargs.get("state", {})
            else:
                intent, state = args[0], args[1]

            decision: Decision = await _guard_instance.verify_async(
                intent=intent, state=state
            )

            if not decision.allowed:
                if on_block == "raise":
                    raise GuardViolationError(decision)
                else:  # on_block == "return"
                    return decision

            return await fn(*args, **kwargs)

        # Attach the guard instance for introspection in tests.
        wrapper.__guard__ = _guard_instance  # type: ignore[attr-defined]
        return wrapper

    return decorator
