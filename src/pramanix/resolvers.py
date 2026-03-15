# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Lazy field resolver registry with per-request context isolation.

Problem solved
--------------
In a multi-tenant service multiple concurrent requests share resources.

In threaded servers (Gunicorn sync workers) multiple threads run in parallel;
in async servers (FastAPI / Uvicorn), multiple requests run as separate asyncio
Tasks on the **same** OS thread.  When User A's Task pauses for an ``await``
and User B's Task resumes on the same thread, :class:`threading.local` would
let them share a cache — a P0 data-bleed (User B sees User A's bank balance).

Solution
--------
:class:`ResolverRegistry` stores its cache in a :class:`contextvars.ContextVar`.
Python's execution context is Task-scoped under asyncio and thread-scoped under
threading, so each request owns an independent cache namespace regardless of the
concurrency model in use.  :class:`~pramanix.guard.Guard` calls
:meth:`ResolverRegistry.clear_cache` in its ``finally`` block after every
:meth:`~pramanix.guard.Guard.verify` call, so no resolved value survives across
requests.

Usage::

    from pramanix.resolvers import resolver_registry

    # Register once at startup:
    resolver_registry.register("account_balance", fetch_balance_from_db)

    # Guard.verify() calls resolver_registry.resolve("account_balance", account_id)
    # when the field is needed, caches the result for the duration of the
    # verify() call, then clears it in the finally block.
"""
from __future__ import annotations

import contextvars
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

__all__ = ["ResolverRegistry", "resolver_registry"]


class ResolverRegistry:
    """Async-safe lazy field resolver with per-request context isolation.

    Register named resolver callables once at application startup, then call
    :meth:`resolve` during a policy verification.  The result is memoised in a
    :class:`contextvars.ContextVar` so it is scoped to the current execution
    context — an OS thread *or* an asyncio :class:`asyncio.Task`.  This guards
    against data-bleed in async backends (FastAPI / Uvicorn) where concurrent
    requests share an OS thread.

    :meth:`~pramanix.guard.Guard.verify` **always** calls :meth:`clear_cache`
    in its ``finally`` block, so no resolved value leaks across requests.
    """

    def __init__(self) -> None:
        self._resolvers: dict[str, Callable[..., Any]] = {}
        # default=None so every fresh context (asyncio Task or OS thread) starts
        # without a cache; _get_cache() lazily creates an isolated dict on
        # first access within this context, never sharing a parent's dict.
        self._cache_var: contextvars.ContextVar[dict[str, Any] | None] = contextvars.ContextVar(
            "pramanix_resolver_cache", default=None
        )

    # ── Registration ─────────────────────────────────────────────────────────

    def register(self, name: str, resolver: Callable[..., Any]) -> None:
        """Register a named resolver callable.

        Args:
            name:     Logical field name used as the cache key.
            resolver: Any callable that accepts positional/keyword arguments
                      and returns the field value.  Called at most once per
                      ``verify()`` invocation (results are memoised).

        Raises:
            TypeError: If *resolver* is not callable.
        """
        if not callable(resolver):
            raise TypeError(f"resolver for '{name}' must be callable, got {type(resolver)!r}")
        self._resolvers[name] = resolver

    # ── Resolution ───────────────────────────────────────────────────────────

    def resolve(self, name: str, *args: Any, **kwargs: Any) -> Any:
        """Resolve and cache *name*, calling the registered resolver if needed.

        The result is stored in the current execution context's private cache
        (asyncio Task or OS thread) and reused for the lifetime of the current
        ``verify()`` call.

        Args:
            name:     The field name registered via :meth:`register`.
            *args:    Forwarded to the resolver callable on first call.
            **kwargs: Forwarded to the resolver callable on first call.

        Returns:
            The resolver's return value (possibly cached from an earlier call
            on this same thread within this request).

        Raises:
            KeyError: If no resolver has been registered for *name*.
        """
        cache = self._get_cache()
        if name in cache:
            return cache[name]
        if name not in self._resolvers:
            raise KeyError(
                f"No resolver registered for field '{name}'. "
                "Call resolver_registry.register(name, fn) at startup."
            )
        result = self._resolvers[name](*args, **kwargs)
        cache[name] = result
        return result

    # ── Cache management ─────────────────────────────────────────────────────

    def clear_cache(self) -> None:
        """Wipe this context's resolver cache.

        Called by :meth:`~pramanix.guard.Guard.verify` in its ``finally``
        block after every verification.  Ensures that data resolved for one
        request is never visible to the next request on this asyncio Task or
        OS thread.
        """
        self._cache_var.set({})

    def _get_cache(self) -> dict[str, Any]:
        """Return (and lazily create) this context's cache dict."""
        cache = self._cache_var.get()
        if cache is None:
            cache = {}
            self._cache_var.set(cache)
        return cache


# ── Module-level singleton ────────────────────────────────────────────────────
# Import and use this in application code:
#   from pramanix.resolvers import resolver_registry
#   resolver_registry.register("balance", fetch_balance)

resolver_registry: ResolverRegistry = ResolverRegistry()
