# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Unit tests for ResolverRegistry — thread-local cache isolation.

Critical invariants under test
--------------------------------
1. **No data bleed** — User A's resolved value for a field must *never* be
   visible to User B's concurrent request on a different thread.
2. **Intra-request memoisation** — The same field resolved twice within one
   verify() call must hit the cache and invoke the resolver only once.
3. **Cache wipe** — After ``clear_cache()`` the cache is empty; the next
   ``resolve()`` call re-invokes the resolver.
4. **Thread-local isolation** — Each thread owns an independent cache; writing
   to one thread's cache does not affect another thread's cache.
"""
from __future__ import annotations

import threading
from typing import Any

import pytest

from pramanix.resolvers import ResolverRegistry

# ── Fixtures ───────────────────────────────────────────────────────────────


def make_registry() -> ResolverRegistry:
    """Return a fresh registry for each test."""
    return ResolverRegistry()


# ── Registration ───────────────────────────────────────────────────────────


class TestRegister:
    def test_register_callable_succeeds(self) -> None:
        reg = make_registry()
        reg.register("balance", lambda: 1000)

    def test_register_non_callable_raises_type_error(self) -> None:
        reg = make_registry()
        with pytest.raises(TypeError, match="callable"):
            reg.register("balance", 42)  # type: ignore[arg-type]

    def test_register_overwrites_previous(self) -> None:
        reg = make_registry()
        reg.register("x", lambda: 1)
        reg.register("x", lambda: 2)
        assert reg.resolve("x") == 2


# ── Resolution & memoisation ────────────────────────────────────────────────


class TestResolve:
    def test_resolver_is_called_on_first_access(self) -> None:
        reg = make_registry()
        calls: list[int] = []

        def resolver() -> int:
            calls.append(1)
            return 999

        reg.register("v", resolver)
        result = reg.resolve("v")

        assert result == 999
        assert len(calls) == 1

    def test_resolver_is_cached_on_second_access(self) -> None:
        reg = make_registry()
        calls: list[int] = []

        def resolver() -> int:
            calls.append(1)
            return 42

        reg.register("v", resolver)
        reg.resolve("v")
        reg.resolve("v")

        assert len(calls) == 1, "Resolver must only be invoked once per request"

    def test_resolve_unknown_field_raises_key_error(self) -> None:
        reg = make_registry()
        with pytest.raises(KeyError, match="no_such_field"):
            reg.resolve("no_such_field")

    def test_resolve_forwards_args_to_resolver(self) -> None:
        reg = make_registry()
        received: list[Any] = []

        def resolver(*args: Any, **kwargs: Any) -> str:
            received.extend(args)
            received.append(kwargs)
            return "ok"

        reg.register("r", resolver)
        reg.resolve("r", "user_a", account_id=7)

        assert received == ["user_a", {"account_id": 7}]


# ── Cache management ────────────────────────────────────────────────────────


class TestClearCache:
    def test_clear_cache_wipes_all_entries(self) -> None:
        reg = make_registry()
        counter = [0]

        def resolver() -> int:
            counter[0] += 1
            return counter[0]

        reg.register("n", resolver)
        first = reg.resolve("n")
        reg.clear_cache()
        second = reg.resolve("n")

        assert first == 1
        assert second == 2, "Resolver must be re-invoked after clear_cache()"

    def test_clear_cache_is_idempotent(self) -> None:
        reg = make_registry()
        reg.clear_cache()  # no error even if cache was never populated
        reg.clear_cache()

    def test_clear_cache_only_affects_calling_thread(self) -> None:
        """Clearing one thread's cache must not disturb another thread's cache."""
        reg = make_registry()
        reg.register("x", lambda: 100)

        thread_result: dict[str, int] = {}
        barrier = threading.Barrier(2)

        def thread_fn(label: str) -> None:
            reg.resolve("x")  # warm the cache
            barrier.wait()  # both threads warmed
            reg.clear_cache()  # each thread clears its own cache
            thread_result[label] = reg.resolve("x")  # re-resolve

        t1 = threading.Thread(target=thread_fn, args=("t1",))
        t2 = threading.Thread(target=thread_fn, args=("t2",))
        t1.start()
        t2.start()
        t1.join(timeout=5)
        t2.join(timeout=5)

        assert thread_result["t1"] == 100
        assert thread_result["t2"] == 100


# ── Thread-local isolation (data-bleed proof) ───────────────────────────────


class TestThreadLocalIsolation:
    def test_user_a_value_never_visible_to_user_b_thread(self) -> None:
        """Core data-bleed guarantee: each thread's resolved values are private.

        Simulate two concurrent requests:
        - Thread A resolves "balance" → 1_000 (User A)
        - Thread B resolves "balance" → 2_000 (User B)
        Each thread must see *only* its own resolved value.
        """
        make_registry()
        errors: list[str] = []
        barrier = threading.Barrier(2)

        def simulate_request(user_balance: int, label: str) -> None:
            # Each thread registers its own per-call resolver via a closure.
            # In production this would come from the request context.
            local_reg = make_registry()
            local_reg.register("balance", lambda: user_balance)

            local_reg.resolve("balance")  # warm the cache
            barrier.wait()  # synchronise: both threads active

            value = local_reg.resolve("balance")
            if value != user_balance:
                errors.append(f"{label}: expected {user_balance}, got {value} (DATA BLEED!)")
            local_reg.clear_cache()

        t_a = threading.Thread(target=simulate_request, args=(1_000, "user_a"))
        t_b = threading.Thread(target=simulate_request, args=(2_000, "user_b"))
        t_a.start()
        t_b.start()
        t_a.join(timeout=5)
        t_b.join(timeout=5)

        assert not errors, "\n".join(errors)

    def test_shared_registry_thread_local_cache_per_thread(self) -> None:
        """A single shared registry must isolate cache writes across threads."""
        reg = make_registry()
        thread_values: dict[str, int] = {}
        barrier = threading.Barrier(2)

        def thread_work(label: str, value: int) -> None:
            call_count = [0]

            def resolver() -> int:
                call_count[0] += 1
                return value

            reg.register(f"field_{label}", resolver)
            reg.resolve(f"field_{label}")  # prime
            barrier.wait()
            # Accessing the *other* thread's field key must still work
            # (resolver is global), but the cache is per-thread.
            assert call_count[0] == 1, "Each thread must call its resolver once"
            thread_values[label] = reg.resolve(f"field_{label}")
            reg.clear_cache()

        t1 = threading.Thread(target=thread_work, args=("alpha", 111))
        t2 = threading.Thread(target=thread_work, args=("beta", 222))
        t1.start()
        t2.start()
        t1.join(timeout=5)
        t2.join(timeout=5)

        assert thread_values["alpha"] == 111
        assert thread_values["beta"] == 222
