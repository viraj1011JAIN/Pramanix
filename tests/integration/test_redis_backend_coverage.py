# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Integration tests for RedisDistributedBackend — real Redis 7 container.

Replaces all fakeredis-backed tests that were previously in
tests/unit/test_coverage_final_push.py.  Every test here runs against a
genuine Redis 7-alpine container started by the session fixture in conftest.py.

Covered code paths
------------------
- ``_get_client()`` lazy-init and caching (one ``from_url`` call)
- ``get_state()`` returns defaults on malformed hash data
- ``set_state()`` pipeline write + TTL + conservative severity merge
- ``set_state()`` non-fatal error logging when Redis is unreachable
- ``clear()`` thread-path (``asyncio.run()`` fallback)
- ``_async_clear(None)`` deletes all keys under the prefix
"""

from __future__ import annotations

import threading
from typing import Any

import pytest

from tests.integration.conftest import requires_docker

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def redis_backend(redis_url: str) -> Any:
    """Return a RedisDistributedBackend with ``_client=None`` (lazy-init path)."""
    pytest.importorskip("redis")
    from pramanix.circuit_breaker import RedisDistributedBackend

    backend = RedisDistributedBackend.__new__(RedisDistributedBackend)
    backend._redis_url = redis_url
    backend._sync_interval = 1.0
    backend._prefix = "pramanix:cb:test:"
    backend._ttl = 300
    backend._client = None
    return backend


# ── _get_client() ─────────────────────────────────────────────────────────────


@requires_docker
class TestRedisGetClientLazyInit:
    """_get_client() creates the client once and caches it."""

    @pytest.mark.asyncio
    async def test_lazy_client_creation(self, redis_backend: Any) -> None:
        """Two consecutive _get_client() calls must return the identical object.

        With a real Redis connection the client is created on the first call
        and the cached reference is returned on the second — ``from_url`` is
        only ever called once per backend instance.
        """
        client1 = await redis_backend._get_client()
        client2 = await redis_backend._get_client()

        assert (
            client1 is client2
        ), "_get_client() must return the same cached client object on the second call"
        # Verify the connection is actually live.
        assert await client1.ping()


# ── get_state() malformed data ────────────────────────────────────────────────


@requires_docker
class TestRedisGetStateMalformedData:
    """get_state() returns defaults when stored data has malformed int/float."""

    @pytest.mark.asyncio
    async def test_malformed_failure_count_returns_default(self, redis_backend: Any) -> None:
        from pramanix.circuit_breaker import CircuitState

        client = await redis_backend._get_client()
        # Seed a hash with a non-integer failure_count directly into real Redis.
        await client.hset(
            "pramanix:cb:test:ns_bad",
            mapping={"circuit_state": "open", "failure_count": "NOT_AN_INT"},
        )

        state = await redis_backend.get_state("ns_bad")

        # ValueError in int("NOT_AN_INT") → returns _DistributedState() defaults
        assert state.circuit_state == CircuitState.CLOSED.value
        assert state.failure_count == 0

        await client.delete("pramanix:cb:test:ns_bad")


# ── set_state() ───────────────────────────────────────────────────────────────


@requires_docker
class TestRedisSetStatePipeline:
    """set_state() persists state and enforces the conservative severity merge."""

    @pytest.mark.asyncio
    async def test_set_state_executes_pipeline(self, redis_backend: Any) -> None:
        from pramanix.circuit_breaker import CircuitState, _DistributedState

        await redis_backend.set_state(
            "pipe_ns",
            _DistributedState(circuit_state=CircuitState.OPEN.value, failure_count=2),
        )

        state = await redis_backend.get_state("pipe_ns")
        assert state.circuit_state == CircuitState.OPEN.value
        assert state.failure_count == 2

        client = await redis_backend._get_client()
        await client.delete("pramanix:cb:test:pipe_ns")

    @pytest.mark.asyncio
    async def test_set_state_lower_severity_keeps_existing(self, redis_backend: Any) -> None:
        """Conservative merge: existing OPEN state must not be downgraded to CLOSED."""
        from pramanix.circuit_breaker import CircuitState, _DistributedState

        client = await redis_backend._get_client()
        # Pre-seed OPEN (severity=2) directly in real Redis.
        await client.hset(
            "pramanix:cb:test:severity_ns",
            mapping={
                "circuit_state": CircuitState.OPEN.value,
                "failure_count": "3",
                "last_failure_time": "1000.0",
                "open_episode_count": "1",
            },
        )

        # Attempt to downgrade to CLOSED (severity=0).
        await redis_backend.set_state(
            "severity_ns",
            _DistributedState(circuit_state=CircuitState.CLOSED.value, failure_count=0),
        )

        state = await redis_backend.get_state("severity_ns")
        assert (
            state.circuit_state == CircuitState.OPEN.value
        ), "Conservative merge must keep the more-severe OPEN state"

        await client.delete("pramanix:cb:test:severity_ns")

    @pytest.mark.asyncio
    async def test_set_state_logs_and_does_not_raise_on_unreachable_redis(
        self,
    ) -> None:
        """set_state() must not propagate exceptions when Redis is unreachable.

        Points the backend at a TCP port where nothing is listening so that the
        real Redis client raises a connection error — verifying the non-fatal
        error-handling path without any fakes.
        """
        pytest.importorskip("redis")
        from pramanix.circuit_breaker import (
            CircuitState,
            RedisDistributedBackend,
            _DistributedState,
        )

        bad_backend = RedisDistributedBackend.__new__(RedisDistributedBackend)
        bad_backend._redis_url = "redis://localhost:1"  # nothing listening on port 1
        bad_backend._sync_interval = 1.0
        bad_backend._prefix = "pramanix:cb:"
        bad_backend._ttl = 300
        bad_backend._client = None

        # Must NOT raise — connection failure is non-fatal; local state governs.
        await bad_backend.set_state(
            "fail_ns",
            _DistributedState(circuit_state=CircuitState.OPEN.value, failure_count=1),
        )


# ── clear() ───────────────────────────────────────────────────────────────────


@requires_docker
class TestRedisClear:
    """clear() falls back to asyncio.run() in a non-async thread."""

    def test_clear_no_loop_uses_asyncio_run(self, redis_url: str) -> None:
        """Running clear() from a plain thread (no running event loop) exercises
        the asyncio.run() fallback branch.

        pytest-asyncio mode="auto" gives the test thread a running loop, so a
        real threading.Thread is spawned — threads start with no event loop,
        forcing clear() to use asyncio.run().
        """
        pytest.importorskip("redis")
        from pramanix.circuit_breaker import RedisDistributedBackend

        results: list[str] = []

        def _run_in_thread() -> None:
            import redis.asyncio as aioredis

            backend = RedisDistributedBackend.__new__(RedisDistributedBackend)
            backend._redis_url = redis_url
            backend._sync_interval = 1.0
            backend._prefix = "pramanix:cb:test:"
            backend._ttl = 300
            backend._client = aioredis.from_url(redis_url, decode_responses=True)
            backend.clear("thread_test_ns")
            results.append("ok")

        t = threading.Thread(target=_run_in_thread)
        t.start()
        t.join(timeout=10.0)
        assert results == ["ok"], "clear() in a no-loop thread must complete without error"

    @pytest.mark.asyncio
    async def test_async_clear_all_namespaces(self, redis_backend: Any) -> None:
        """_async_clear(None) deletes all keys matching the backend prefix."""
        client = await redis_backend._get_client()
        await client.hset("pramanix:cb:test:ns_clear_1", mapping={"circuit_state": "open"})
        await client.hset("pramanix:cb:test:ns_clear_2", mapping={"circuit_state": "open"})

        await redis_backend._async_clear(None)

        assert await client.exists("pramanix:cb:test:ns_clear_1") == 0
        assert await client.exists("pramanix:cb:test:ns_clear_2") == 0
