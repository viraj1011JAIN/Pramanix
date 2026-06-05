# SPDX-License-Identifier: Apache-2.0
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Tests for RedisDistributedBackend (C-5)."""

from __future__ import annotations

import pytest

from pramanix.circuit_breaker import (
    CircuitState,
    InMemoryDistributedBackend,
    RedisDistributedBackend,
    _DistributedState,
)

# ── InMemoryDistributedBackend (shared with RedisDistributedBackend interface) ─


@pytest.mark.asyncio
async def test_in_memory_get_default_state() -> None:
    InMemoryDistributedBackend.clear()
    state = await InMemoryDistributedBackend.get_state("ns_test")
    assert state.circuit_state == CircuitState.CLOSED.value
    assert state.failure_count == 0


@pytest.mark.asyncio
async def test_in_memory_set_and_get() -> None:
    InMemoryDistributedBackend.clear()
    await InMemoryDistributedBackend.set_state(
        "ns1",
        _DistributedState(circuit_state=CircuitState.OPEN.value, failure_count=3),
    )
    state = await InMemoryDistributedBackend.get_state("ns1")
    assert state.circuit_state == CircuitState.OPEN.value
    assert state.failure_count == 3


@pytest.mark.asyncio
async def test_conservative_merge_severity() -> None:
    """More severe state wins in conservative merge."""
    InMemoryDistributedBackend.clear()
    # Set OPEN first
    await InMemoryDistributedBackend.set_state(
        "ns2",
        _DistributedState(circuit_state=CircuitState.OPEN.value, failure_count=2),
    )
    # Try to set CLOSED — severity 0 < 2 (OPEN) → OPEN should win
    await InMemoryDistributedBackend.set_state(
        "ns2",
        _DistributedState(circuit_state=CircuitState.CLOSED.value, failure_count=0),
    )
    state = await InMemoryDistributedBackend.get_state("ns2")
    assert state.circuit_state == CircuitState.OPEN.value


@pytest.mark.asyncio
async def test_failure_count_summed_in_merge() -> None:
    InMemoryDistributedBackend.clear()
    await InMemoryDistributedBackend.set_state(
        "ns3",
        _DistributedState(circuit_state=CircuitState.CLOSED.value, failure_count=2),
    )
    await InMemoryDistributedBackend.set_state(
        "ns3",
        _DistributedState(circuit_state=CircuitState.CLOSED.value, failure_count=3),
    )
    state = await InMemoryDistributedBackend.get_state("ns3")
    assert state.failure_count == 5


@pytest.mark.asyncio
async def test_clear_single_namespace() -> None:
    InMemoryDistributedBackend.clear()
    await InMemoryDistributedBackend.set_state(
        "clear_ns",
        _DistributedState(circuit_state=CircuitState.OPEN.value, failure_count=1),
    )
    InMemoryDistributedBackend.clear("clear_ns")
    state = await InMemoryDistributedBackend.get_state("clear_ns")
    assert state.circuit_state == CircuitState.CLOSED.value


# ── RedisDistributedBackend with real Redis testcontainer ─────────────────────


@pytest.mark.asyncio
async def test_redis_backend_get_default(redis_url: str) -> None:
    """Redis backend returns default CLOSED state when key is absent."""
    import redis.asyncio as aioredis

    client = aioredis.from_url(redis_url, decode_responses=True)
    backend = RedisDistributedBackend(redis_client=client, key_prefix="pramanix:cb:get_default:")

    state = await backend.get_state("test_ns")
    assert state.circuit_state == CircuitState.CLOSED.value


@pytest.mark.asyncio
async def test_redis_backend_set_and_get(redis_url: str) -> None:
    import redis.asyncio as aioredis

    client = aioredis.from_url(redis_url, decode_responses=True)
    backend = RedisDistributedBackend(redis_client=client, key_prefix="pramanix:cb:set_and_get:")

    await backend.set_state(
        "my_ns",
        _DistributedState(
            circuit_state=CircuitState.OPEN.value,
            failure_count=5,
            last_failure_time=1000.0,
            open_episode_count=2,
        ),
    )
    state = await backend.get_state("my_ns")
    assert state.circuit_state == CircuitState.OPEN.value
    assert state.failure_count == 5


@pytest.mark.asyncio
async def test_redis_backend_conservative_merge(redis_url: str) -> None:
    import redis.asyncio as aioredis

    client = aioredis.from_url(redis_url, decode_responses=True)
    backend = RedisDistributedBackend(
        redis_client=client, key_prefix="pramanix:cb:conservative_merge:"
    )

    await backend.set_state(
        "merge_ns",
        _DistributedState(circuit_state=CircuitState.OPEN.value, failure_count=3),
    )
    # CLOSED should not downgrade OPEN
    await backend.set_state(
        "merge_ns",
        _DistributedState(circuit_state=CircuitState.CLOSED.value, failure_count=1),
    )
    state = await backend.get_state("merge_ns")
    assert state.circuit_state == CircuitState.OPEN.value


@pytest.mark.asyncio
async def test_redis_backend_unavailable_fails_safe() -> None:
    """Redis failures return OPEN (fail-safe) so unknown state blocks requests."""

    backend = RedisDistributedBackend._for_testing(redis_client)
    # Simulate Redis failure by giving a client that always raises
    class _FailClient:
        async def hgetall(self, *a: object, **kw: object) -> dict:
            raise ConnectionError("Redis unavailable")

        async def pipeline(self, *a: object, **kw: object) -> object:
            raise ConnectionError("Redis unavailable")

    backend._client = _FailClient()
    state = await backend.get_state("fail_ns")
    # On Redis failure the circuit breaker must fail SAFE (OPEN), not fail-open
    # (CLOSED). An unknown distributed state should block requests, not silently
    # allow them — this is the financially-safe behaviour.
    assert state.circuit_state == CircuitState.OPEN.value
