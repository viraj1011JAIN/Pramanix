# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for RedisDistributedBackend (C-5)."""
from __future__ import annotations

import pytest

from pramanix.circuit_breaker import (
    CircuitState,
    InMemoryDistributedBackend,
    RedisDistributedBackend,
    _DistributedState,
)
from pramanix.exceptions import ConfigurationError

# ── RedisDistributedBackend import guard ──────────────────────────────────────


def test_redis_backend_raises_config_error_without_redis(monkeypatch: pytest.MonkeyPatch) -> None:
    """ConfigurationError raised when redis is not installed."""
    import sys
    monkeypatch.setitem(sys.modules, "redis", None)
    monkeypatch.setitem(sys.modules, "redis.asyncio", None)
    with pytest.raises(ConfigurationError, match="pip install 'pramanix\\[redis\\]'"):
        RedisDistributedBackend("redis://localhost:6379")


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


# ── RedisDistributedBackend with fakeredis ────────────────────────────────────


try:
    import fakeredis.aioredis  # type: ignore[import-untyped]  # noqa: F401
    HAS_FAKEREDIS = True
except ImportError:
    HAS_FAKEREDIS = False

needs_fakeredis = pytest.mark.skipif(not HAS_FAKEREDIS, reason="fakeredis not installed")


@needs_fakeredis
@pytest.mark.asyncio
async def test_redis_backend_get_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """Redis backend returns default CLOSED state when key is absent."""
    import fakeredis.aioredis as fake_aioredis

    backend = RedisDistributedBackend.__new__(RedisDistributedBackend)
    backend._redis_url = "redis://localhost"
    backend._sync_interval = 1.0
    backend._prefix = "pramanix:cb:"
    backend._ttl = 300
    backend._client = fake_aioredis.FakeRedis(decode_responses=True)

    state = await backend.get_state("test_ns")
    assert state.circuit_state == CircuitState.CLOSED.value


@needs_fakeredis
@pytest.mark.asyncio
async def test_redis_backend_set_and_get(monkeypatch: pytest.MonkeyPatch) -> None:
    import fakeredis.aioredis as fake_aioredis

    backend = RedisDistributedBackend.__new__(RedisDistributedBackend)
    backend._redis_url = "redis://localhost"
    backend._sync_interval = 1.0
    backend._prefix = "pramanix:cb:"
    backend._ttl = 300
    backend._client = fake_aioredis.FakeRedis(decode_responses=True)

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


@needs_fakeredis
@pytest.mark.asyncio
async def test_redis_backend_conservative_merge(monkeypatch: pytest.MonkeyPatch) -> None:
    import fakeredis.aioredis as fake_aioredis

    backend = RedisDistributedBackend.__new__(RedisDistributedBackend)
    backend._redis_url = "redis://localhost"
    backend._sync_interval = 1.0
    backend._prefix = "pramanix:cb:"
    backend._ttl = 300
    backend._client = fake_aioredis.FakeRedis(decode_responses=True)

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


@needs_fakeredis
@pytest.mark.asyncio
async def test_redis_backend_unavailable_fails_safe() -> None:
    """Redis failures return OPEN (fail-safe) so unknown state blocks requests."""

    backend = RedisDistributedBackend.__new__(RedisDistributedBackend)
    backend._redis_url = "redis://localhost"
    backend._sync_interval = 1.0
    backend._prefix = "pramanix:cb:"
    backend._ttl = 300
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
