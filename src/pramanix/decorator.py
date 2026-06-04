# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""``@guard`` decorator — one-line policy enforcement for async and sync functions.

Usage::

    from pramanix import guard, Guard, GuardConfig, Policy, Field, E

    class BankingPolicy(Policy): ...

    # Async function — uses Guard.verify_async() under the hood.
    @guard(policy=BankingPolicy, config=GuardConfig(execution_mode="async-thread"))
    async def transfer(intent: dict, state: dict) -> dict:
        # Only reached when Guard.verify_async() returns Decision(allowed=True)
        return {"status": "ok"}

    # Sync function — uses Guard.verify() (blocking) under the hood.
    # Works in Django views, Flask endpoints, Celery tasks, and any
    # synchronous Python context.
    @guard(policy=BankingPolicy)
    def transfer_sync(intent: dict, state: dict) -> dict:
        return {"status": "ok"}

    # on_block="return" — return the Decision instead of raising.
    # Works identically for both async and sync variants.
    @guard(policy=BankingPolicy, on_block="return")
    async def transfer_soft(intent: dict, state: dict) -> dict | Decision:
        return {"status": "ok"}
"""

from __future__ import annotations

import asyncio
import functools
import inspect
from typing import TYPE_CHECKING, Any, Literal, cast

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
    """Policy-enforcement decorator factory for async and sync functions.

    Creates a :class:`~pramanix.guard.Guard` instance **once** at decoration
    time and reuses it across all calls to the wrapped function.

    * **Async functions** are wrapped with
      :meth:`~pramanix.guard.Guard.verify_async`.
    * **Sync functions** are wrapped with :meth:`~pramanix.guard.Guard.verify`
      (the blocking synchronous interface), enabling use in Django views, Flask
      endpoints, Celery tasks, and any synchronous Python context.

    The decorator signature is identical for both variants — no ``async def``
    requirement.

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
        A decorator that wraps an ``async def`` or ``def`` function.

    Example::

        @guard(policy=BankingPolicy)
        async def handle_transfer_async(intent, state): ...

        @guard(policy=BankingPolicy)
        def handle_transfer_sync(intent, state): ...
    """
    # Import here to avoid circular imports at module load time.
    from pramanix.guard import Guard, GuardConfig

    _config = config or GuardConfig()
    _guard_instance: Guard = Guard(policy=policy, config=_config)

    def decorator(fn: Any) -> Any:
        """Wrap fn with guard enforcement, choosing sync or async path automatically."""
        # Detect instance methods: if fn's first parameter is "self" or "cls",
        # args[0] is the instance/class, not intent — offset by 1 (#293).
        _fn_params = list(inspect.signature(fn).parameters)
        _is_method = bool(_fn_params and _fn_params[0] in ("self", "cls"))
        _intent_offset = 1 if _is_method else 0

        if asyncio.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                """Run guard.verify_async() before delegating to the original coroutine."""
                # Extract intent and state from positional / keyword args.
                # Convention: first two positional args after any self/cls are (intent, state).
                _needed = _intent_offset + 2
                if len(args) < _needed:
                    intent = kwargs.get("intent", {})
                    state = kwargs.get("state", {})
                else:
                    intent, state = args[_intent_offset], args[_intent_offset + 1]

                decision: Decision = await _guard_instance.verify_async(intent=intent, state=state)

                if not decision.allowed:
                    if on_block == "raise":
                        raise GuardViolationError(decision)
                    else:  # on_block == "return"
                        return decision

                return await fn(*args, **kwargs)

            cast(Any, async_wrapper).__guard__ = _guard_instance
            return async_wrapper

        else:

            @functools.wraps(fn)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                """Run guard.verify() before delegating to the original function."""
                # Same intent/state extraction convention as the async path.
                _needed_sync = _intent_offset + 2
                if len(args) < _needed_sync:
                    intent = kwargs.get("intent", {})
                    state = kwargs.get("state", {})
                else:
                    intent, state = args[_intent_offset], args[_intent_offset + 1]

                decision: Decision = _guard_instance.verify(intent=intent, state=state)

                if not decision.allowed:
                    if on_block == "raise":
                        raise GuardViolationError(decision)
                    else:  # on_block == "return"
                        return decision

                return fn(*args, **kwargs)

            cast(Any, sync_wrapper).__guard__ = _guard_instance
            return sync_wrapper

    return decorator
