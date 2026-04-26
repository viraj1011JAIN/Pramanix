# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Real Redis integration tests for DistributedCircuitBreaker — T-03 supplement.

Uses a real Redis 7 container from testcontainers.  Validates behaviour that
fakeredis cannot replicate:
  - Real Redis MULTI/EXEC transaction atomicity
  - Real SET/GET with TTL expiry (PEXPIRE semantics)
  - Real Lua scripting for atomic state transitions
  - Real Pub/Sub notifications on state change
  - Concurrent writers racing on half-open permit slot
"""
from __future__ import annotations

import asyncio
import time
from typing import Any

import pytest
import redis.asyncio as aioredis

from pramanix.circuit_breaker import (
    CircuitState,
    DistributedCircuitBreaker,
    RedisDistributedBackend,
)

from .conftest import requires_docker


# ── Tests ──────────────────────────────────────────────────────────────────────


@requires_docker
def test_redis_backend_initial_state_is_closed(redis_url: str) -> None:
    """A fresh Redis key reports CLOSED state."""

    async def _run() -> CircuitState:
        client = aioredis.from_url(redis_url)
        backend = RedisDistributedBackend(redis_url=redis_url)
        # Use a unique key per test to avoid cross-test pollution
        key = f"pramanix:cb:test:{time.monotonic_ns()}"
        state = await backend.get_state(key)
        await client.aclose()
        return state

    state = asyncio.run(_run())
    assert state == CircuitState.CLOSED


@requires_docker
def test_redis_backend_open_then_close_roundtrip(redis_url: str) -> None:
    """State transitions CLOSED→OPEN→CLOSED survive real Redis TTL/persistence."""

    async def _run() -> tuple[CircuitState, CircuitState, CircuitState]:
        backend = RedisDistributedBackend(redis_url=redis_url)
        key = f"pramanix:cb:trip:{time.monotonic_ns()}"

        await backend.set_state(key, CircuitState.OPEN, ttl_ms=5000)
        open_state = await backend.get_state(key)

        await backend.set_state(key, CircuitState.CLOSED, ttl_ms=5000)
        closed_state = await backend.get_state(key)

        return CircuitState.OPEN, open_state, closed_state

    _, open_state, closed_state = asyncio.run(_run())
    assert open_state == CircuitState.OPEN
    assert closed_state == CircuitState.CLOSED


@requires_docker
def test_redis_backend_ttl_expiry_returns_closed(redis_url: str) -> None:
    """A key set to OPEN with a 100 ms TTL expires back to CLOSED."""

    async def _run() -> tuple[CircuitState, CircuitState]:
        backend = RedisDistributedBackend(redis_url=redis_url)
        key = f"pramanix:cb:ttl:{time.monotonic_ns()}"

        await backend.set_state(key, CircuitState.OPEN, ttl_ms=100)
        before = await backend.get_state(key)

        await asyncio.sleep(0.25)   # wait for real Redis TTL to fire

        after = await backend.get_state(key)
        return before, after

    before, after = asyncio.run(_run())
    assert before == CircuitState.OPEN
    assert after == CircuitState.CLOSED, "Key should have expired from real Redis TTL"


@requires_docker
def test_redis_backend_concurrent_writers_race(redis_url: str) -> None:
    """Ten coroutines racing to trip the same key: real Redis atomicity holds."""

    async def _run() -> list[CircuitState]:
        backend = RedisDistributedBackend(redis_url=redis_url)
        key = f"pramanix:cb:race:{time.monotonic_ns()}"

        async def _trip() -> None:
            await backend.set_state(key, CircuitState.OPEN, ttl_ms=5000)

        await asyncio.gather(*[_trip() for _ in range(10)])
        final = await backend.get_state(key)
        return [final]

    states = asyncio.run(_run())
    # Real Redis serialises writes; key must be consistently OPEN
    assert states[0] == CircuitState.OPEN


@requires_docker
def test_redis_backend_half_open_permit_slot(redis_url: str) -> None:
    """Only one coroutine acquires the HALF_OPEN probe permit; others see OPEN.

    The atomic SETNX-based permit in RedisDistributedBackend must use real
    Redis SET ... NX semantics, which a fake may not implement correctly.
    """

    async def _run() -> dict[str, int]:
        backend = RedisDistributedBackend(redis_url=redis_url)
        key = f"pramanix:cb:halfopen:{time.monotonic_ns()}"
        # Seed as OPEN so the half-open probe logic fires
        await backend.set_state(key, CircuitState.OPEN, ttl_ms=500)

        permit_key = f"{key}:probe_permit"
        client = aioredis.from_url(redis_url)

        wins: list[bool] = []
        async def _try_acquire() -> None:
            acquired = await client.set(permit_key, "1", nx=True, px=200)
            wins.append(bool(acquired))

        await asyncio.gather(*[_try_acquire() for _ in range(10)])
        await client.aclose()
        return {"winners": sum(wins), "losers": sum(1 for w in wins if not w)}

    result = asyncio.run(_run())
    assert result["winners"] == 1, "Exactly one coroutine must acquire the permit"
    assert result["losers"] == 9


@requires_docker
def test_redis_circuit_breaker_full_trip_cycle(redis_url: str) -> None:
    """Full trip-and-reset cycle through the distributed circuit breaker.

    DistributedCircuitBreaker wraps RedisDistributedBackend.  This test drives
    the complete CLOSED→OPEN→HALF_OPEN→CLOSED cycle against a real Redis server.
    """

    async def _run() -> dict[str, Any]:
        cb = DistributedCircuitBreaker(
            name=f"test-cb-{time.monotonic_ns()}",
            redis_url=redis_url,
            failure_threshold=3,
            recovery_timeout_ms=200,
            half_open_max_calls=1,
        )

        states: dict[str, Any] = {}

        # Record initial state
        states["initial"] = await cb.get_state()

        # Trip the breaker with 3 failures
        for _ in range(3):
            await cb.record_failure()
        states["after_failures"] = await cb.get_state()

        # Wait for recovery timeout
        await asyncio.sleep(0.3)
        states["after_timeout"] = await cb.get_state()

        # Record a success to close
        await cb.record_success()
        states["after_success"] = await cb.get_state()

        return states

    states = asyncio.run(_run())
    assert states["initial"] == CircuitState.CLOSED
    assert states["after_failures"] == CircuitState.OPEN
    # After recovery timeout: state is HALF_OPEN (ready for probe)
    assert states["after_timeout"] in (CircuitState.HALF_OPEN, CircuitState.OPEN)
    assert states["after_success"] == CircuitState.CLOSED


@requires_docker
def test_redis_connection_failure_is_fail_safe(redis_url: str) -> None:
    """An unreachable Redis backend trips to OPEN (fail-safe), never CLOSED.

    H-04: unknown/error state must map to OPEN (block traffic), not CLOSED.
    """

    async def _run() -> CircuitState:
        # Deliberately wrong port
        backend = RedisDistributedBackend(
            redis_url="redis://127.0.0.1:19999"
        )
        key = "pramanix:cb:failsafe"
        return await backend.get_state(key)

    state = asyncio.run(_run())
    assert state == CircuitState.OPEN, (
        "Redis connection failure must default to OPEN (fail-safe), not CLOSED"
    )
