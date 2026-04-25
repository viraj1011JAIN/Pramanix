# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Circuit breaker HALF_OPEN state transitions and missing branch coverage.

Targets:
  circuit_breaker.py lines 189->194, 224-233, 329->exit, 331-332, 343-344,
  465-466, 516, 614-618, 623-625, 654-655, 698-700, 708-716, 719-729

Design:  _record_solve() is called directly to drive deterministic state
transitions without sleeping — the same pattern as test_circuit_breaker.py.
"""
from __future__ import annotations

import asyncio
import sys
from decimal import Decimal

import pytest

from pramanix.circuit_breaker import (
    AdaptiveCircuitBreaker,
    CircuitBreakerConfig,
    CircuitState,
)
from pramanix.expressions import E, Field
from pramanix.guard import Guard, GuardConfig
from pramanix.policy import Policy

# ── Minimal real policy ───────────────────────────────────────────────────────


class _SimplePolicy(Policy):
    amount = Field("amount", Decimal, "Real")

    @classmethod
    def invariants(cls):
        return [(E(cls.amount) >= 0).named("non_negative")]


_GUARD = Guard(_SimplePolicy, GuardConfig(execution_mode="sync"))
_ALLOW_INTENT = {"amount": Decimal("10")}
_STATE = {}


# ── HALF_OPEN → OPEN transition (lines 231-233) ───────────────────────────────


@pytest.mark.asyncio
async def test_half_open_probe_fails_transitions_to_open() -> None:
    """HALF_OPEN + high-latency probe → OPEN (not ISOLATED).

    isolation_threshold=2, so first open_episodes=1 → OPEN, not ISOLATED.
    """
    config = CircuitBreakerConfig(
        namespace="test_ho_to_open",
        pressure_threshold_ms=50,
        consecutive_pressure_count=1,
        recovery_seconds=0,
        isolation_threshold=2,
    )
    cb = AdaptiveCircuitBreaker(_GUARD, config)

    # Set OPEN directly with open_episodes=0 so the HALF_OPEN probe failure
    # increments to 1, which is < isolation_threshold=2 → OPEN not ISOLATED.
    cb._state = CircuitState.OPEN
    cb._open_episodes = 0

    # Drive the HALF_OPEN probe manually to hit lines 224-225, 231-233
    cb._state = CircuitState.HALF_OPEN
    async with cb._lock:
        cb._record_solve(1000.0)  # high latency probe: HALF_OPEN → OPEN

    assert cb._state == CircuitState.OPEN


# ── HALF_OPEN → ISOLATED transition (lines 224-230) ──────────────────────────


@pytest.mark.asyncio
async def test_half_open_probe_fails_repeatedly_transitions_to_isolated() -> None:
    """HALF_OPEN + high-latency probe when open_episodes >= isolation_threshold → ISOLATED."""
    config = CircuitBreakerConfig(
        namespace="test_ho_to_isolated",
        pressure_threshold_ms=50,
        consecutive_pressure_count=1,
        recovery_seconds=0,
        isolation_threshold=2,
    )
    cb = AdaptiveCircuitBreaker(_GUARD, config)

    # Drive open_episodes to isolation_threshold - 1 first
    async with cb._lock:
        cb._record_solve(1000.0)  # CLOSED → OPEN, open_episodes=1
    assert cb._state == CircuitState.OPEN

    # Force into HALF_OPEN then fail probe → open_episodes=2 = isolation_threshold
    cb._state = CircuitState.HALF_OPEN
    async with cb._lock:
        cb._record_solve(1000.0)  # HALF_OPEN probe fails: open_episodes=2 ≥ 2 → ISOLATED

    assert cb._state == CircuitState.ISOLATED


@pytest.mark.asyncio
async def test_half_open_successful_probe_recovers_to_closed() -> None:
    """HALF_OPEN + low-latency probe → CLOSED."""
    config = CircuitBreakerConfig(
        namespace="test_ho_recover",
        pressure_threshold_ms=500,
        consecutive_pressure_count=1,
        recovery_seconds=0,
    )
    cb = AdaptiveCircuitBreaker(_GUARD, config)

    cb._state = CircuitState.HALF_OPEN
    async with cb._lock:
        cb._record_solve(1.0)  # fast probe → CLOSED

    assert cb._state == CircuitState.CLOSED


# ── Race condition: double-OPEN prevention (branch 189->194) ─────────────────


@pytest.mark.asyncio
async def test_verify_open_state_already_changed_to_half_open() -> None:
    """Branch 189->194: inner lock check sees state no longer OPEN (changed by another task)."""
    config = CircuitBreakerConfig(
        namespace="test_race",
        pressure_threshold_ms=50,
        consecutive_pressure_count=1,
        recovery_seconds=0,
    )
    cb = AdaptiveCircuitBreaker(_GUARD, config)

    # Set OPEN with recovery_seconds elapsed
    async with cb._lock:
        cb._record_solve(1000.0)
    cb._last_transition = asyncio.get_event_loop().time() - 999.0

    # Simulate another coroutine already transitioned to HALF_OPEN
    cb._state = CircuitState.HALF_OPEN

    # verify_async() will re-check inside the lock and see state != OPEN → skip transition
    # Then proceeds with the HALF_OPEN probe (189->194)
    decision = await cb.verify_async(intent=_ALLOW_INTENT, state=_STATE)
    assert decision is not None


# ── Prometheus re-registration (lines 329->exit, 331-332) ────────────────────


def test_second_circuit_breaker_reuses_existing_prometheus_metrics() -> None:
    """Lines 329->exit: second CB with same namespace hits ValueError and recovers from registry."""
    config1 = CircuitBreakerConfig(namespace="test_prom_reuse", pressure_threshold_ms=100)

    # Create two circuit breakers with the same namespace so the second hits
    # the ValueError re-registration path and recovers gracefully.
    cb1 = AdaptiveCircuitBreaker(_GUARD, config1)
    cb3 = AdaptiveCircuitBreaker(_GUARD, config1)  # same namespace as cb1 → ValueError path

    assert cb1._state == CircuitState.CLOSED
    assert cb3._state == CircuitState.CLOSED


def test_prometheus_update_exception_does_not_propagate() -> None:
    """Lines 343-344: _update_prometheus() catches all exceptions silently."""
    config = CircuitBreakerConfig(namespace="test_prom_exc", pressure_threshold_ms=100)
    cb = AdaptiveCircuitBreaker(_GUARD, config)

    # Corrupt the gauge to trigger an exception inside _update_prometheus
    cb._state_gauge = None
    cb._metrics_available = True

    # Must not raise
    cb._update_prometheus()
    cb._metrics_available = False  # restore clean state


# ── Distributed CB: unknown circuit state (line 465-466) ─────────────────────


@pytest.mark.asyncio
async def test_distributed_cb_unknown_state_defaults_to_closed() -> None:
    """_sync_state() falls back to CLOSED when backend returns unknown state string (line 466)."""
    from pramanix.circuit_breaker import DistributedCircuitBreaker, _DistributedState

    class _UnknownStateBackend:
        async def get_state(self, namespace: str) -> _DistributedState:
            return _DistributedState(circuit_state="COMPLETELY_UNKNOWN")

        async def set_state(self, namespace: str, state: _DistributedState) -> None:
            pass

    config = CircuitBreakerConfig(namespace="test_unknown_state")
    dcb = DistributedCircuitBreaker(_GUARD, config, backend=_UnknownStateBackend())

    synced = await dcb._sync_state()
    assert synced == CircuitState.CLOSED


# ── Distributed CB: fast solve resets failure count (line 516) ───────────────


@pytest.mark.asyncio
async def test_distributed_cb_fast_solve_resets_local_failure_count() -> None:
    """Line 516: fast solve (solve_ms <= threshold) resets _local_failure_count."""
    from pramanix.circuit_breaker import DistributedCircuitBreaker, _DistributedState

    class _FakeBackend:
        async def get_state(self, namespace: str) -> _DistributedState:
            return _DistributedState(circuit_state=CircuitState.CLOSED.value)

        async def set_state(self, namespace: str, state: _DistributedState) -> None:
            pass

    config = CircuitBreakerConfig(
        namespace="test_fast_solve",
        pressure_threshold_ms=99999,  # very high → solve always "fast"
    )
    dcb = DistributedCircuitBreaker(_GUARD, config, backend=_FakeBackend())
    dcb._local_failure_count = 3  # pre-load some failures

    await dcb.verify_async(intent=_ALLOW_INTENT, state=_STATE)

    assert dcb._local_failure_count == 0


# ── Distributed CB: OPEN state blocks requests ───────────────────────────────


@pytest.mark.asyncio
async def test_distributed_cb_open_state_returns_error_decision() -> None:
    """DistributedCircuitBreaker returns error when backend reports OPEN state."""
    from pramanix.circuit_breaker import DistributedCircuitBreaker, _DistributedState

    class _OpenBackend:
        async def get_state(self, namespace: str) -> _DistributedState:
            return _DistributedState(circuit_state=CircuitState.OPEN.value)

        async def set_state(self, namespace: str, state: _DistributedState) -> None:
            pass

    config = CircuitBreakerConfig(namespace="test_dist_open")
    dcb = DistributedCircuitBreaker(_GUARD, config, backend=_OpenBackend())
    decision = await dcb.verify_async(intent=_ALLOW_INTENT, state=_STATE)
    assert decision.allowed is False


# ── Redis backend: ConfigurationError (lines 614-618) ────────────────────────


def test_redis_distributed_backend_config_error_without_redis() -> None:
    """Lines 614-618: ConfigurationError when redis.asyncio is not available."""
    from pramanix.exceptions import ConfigurationError

    prev = sys.modules.get("redis.asyncio")
    sys.modules["redis.asyncio"] = None  # type: ignore[assignment]
    try:
        if "pramanix.circuit_breaker" in sys.modules:
            # Force module reload to pick up missing redis check at instantiation
            pass
        from pramanix.circuit_breaker import RedisDistributedBackend
        with pytest.raises(ConfigurationError, match="redis\\[asyncio\\]"):
            RedisDistributedBackend(redis_url="redis://localhost/0")
    finally:
        if prev is None:
            sys.modules.pop("redis.asyncio", None)
        else:
            sys.modules["redis.asyncio"] = prev


# ── Redis backend: _get_client() cached path (lines 623-625) ─────────────────


@pytest.mark.asyncio
async def test_redis_backend_get_client_returns_cached_instance() -> None:
    """Lines 623-625: second call to _get_client() returns the already-created client."""
    import fakeredis.aioredis as aioredis

    from pramanix.circuit_breaker import RedisDistributedBackend

    backend = RedisDistributedBackend(redis_url="redis://localhost/0")
    fake_client = aioredis.FakeRedis(decode_responses=True)
    backend._client = fake_client  # pre-inject so _get_client returns cached

    client1 = await backend._get_client()
    client2 = await backend._get_client()
    assert client1 is client2 is fake_client


# ── Redis backend: set_state() conservative merge ────────────────────────────


@pytest.mark.asyncio
async def test_redis_backend_set_state_lower_severity_not_overwritten() -> None:
    """Lines 698-700: conservative merge keeps existing state when it has higher severity."""
    import fakeredis.aioredis as aioredis

    from pramanix.circuit_breaker import RedisDistributedBackend, _DistributedState

    backend = RedisDistributedBackend(redis_url="redis://localhost/0")
    fake_client = aioredis.FakeRedis(decode_responses=True)
    backend._client = fake_client

    # First write: OPEN state (higher severity)
    await backend.set_state(
        "ns1",
        _DistributedState(circuit_state=CircuitState.OPEN.value, failure_count=1),
    )

    # Second write: CLOSED state (lower severity) — existing OPEN should survive
    await backend.set_state(
        "ns1",
        _DistributedState(circuit_state=CircuitState.CLOSED.value, failure_count=0),
    )

    result = await backend.get_state("ns1")
    assert result.circuit_state == CircuitState.OPEN.value


@pytest.mark.asyncio
async def test_redis_backend_set_state_higher_severity_wins() -> None:
    """Conservative merge: OPEN overwrites CLOSED (higher severity wins)."""
    import fakeredis.aioredis as aioredis

    from pramanix.circuit_breaker import RedisDistributedBackend, _DistributedState

    backend = RedisDistributedBackend(redis_url="redis://localhost/0")
    backend._client = aioredis.FakeRedis(decode_responses=True)

    await backend.set_state(
        "ns2",
        _DistributedState(circuit_state=CircuitState.CLOSED.value, failure_count=0),
    )
    await backend.set_state(
        "ns2",
        _DistributedState(circuit_state=CircuitState.OPEN.value, failure_count=3),
    )

    result = await backend.get_state("ns2")
    assert result.circuit_state == CircuitState.OPEN.value
    assert result.failure_count == 3


@pytest.mark.asyncio
async def test_redis_backend_set_state_accumulates_failure_count() -> None:
    """set_state() failure_count is summed (lines 708-716)."""
    import fakeredis.aioredis as aioredis

    from pramanix.circuit_breaker import RedisDistributedBackend, _DistributedState

    backend = RedisDistributedBackend(redis_url="redis://localhost/0")
    backend._client = aioredis.FakeRedis(decode_responses=True)

    await backend.set_state(
        "ns3",
        _DistributedState(circuit_state=CircuitState.CLOSED.value, failure_count=2),
    )
    await backend.set_state(
        "ns3",
        _DistributedState(circuit_state=CircuitState.CLOSED.value, failure_count=3),
    )

    result = await backend.get_state("ns3")
    assert result.failure_count == 5


@pytest.mark.asyncio
async def test_redis_backend_get_state_returns_closed_on_empty() -> None:
    """get_state() returns default CLOSED state when no data in Redis."""
    import fakeredis.aioredis as aioredis

    from pramanix.circuit_breaker import RedisDistributedBackend

    backend = RedisDistributedBackend(redis_url="redis://localhost/0")
    backend._client = aioredis.FakeRedis(decode_responses=True)

    result = await backend.get_state("nonexistent_namespace")
    assert result.circuit_state == CircuitState.CLOSED.value
    assert result.failure_count == 0


@pytest.mark.asyncio
async def test_redis_backend_clear_specific_namespace() -> None:
    """clear() removes only the specified namespace (lines 719-729)."""
    import fakeredis.aioredis as aioredis

    from pramanix.circuit_breaker import RedisDistributedBackend, _DistributedState

    backend = RedisDistributedBackend(redis_url="redis://localhost/0")
    fake_client = aioredis.FakeRedis(decode_responses=True)
    backend._client = fake_client

    await backend.set_state(
        "ns_to_clear",
        _DistributedState(circuit_state=CircuitState.OPEN.value, failure_count=1),
    )
    await backend.set_state(
        "ns_to_keep",
        _DistributedState(circuit_state=CircuitState.CLOSED.value, failure_count=0),
    )

    await backend._async_clear("ns_to_clear")

    cleared = await backend.get_state("ns_to_clear")
    kept = await backend.get_state("ns_to_keep")
    assert cleared.circuit_state == CircuitState.CLOSED.value
    assert kept.circuit_state == CircuitState.CLOSED.value


@pytest.mark.asyncio
async def test_redis_backend_clear_all_namespaces() -> None:
    """clear(None) removes all namespace keys under the prefix."""
    import fakeredis.aioredis as aioredis

    from pramanix.circuit_breaker import RedisDistributedBackend, _DistributedState

    backend = RedisDistributedBackend(
        redis_url="redis://localhost/0",
        key_prefix="pramanix:cb:clearall:",
    )
    backend._client = aioredis.FakeRedis(decode_responses=True)

    await backend.set_state(
        "ns_a",
        _DistributedState(circuit_state=CircuitState.OPEN.value),
    )
    await backend.set_state(
        "ns_b",
        _DistributedState(circuit_state=CircuitState.OPEN.value),
    )

    await backend._async_clear(None)

    r_a = await backend.get_state("ns_a")
    r_b = await backend.get_state("ns_b")
    assert r_a.circuit_state == CircuitState.CLOSED.value
    assert r_b.circuit_state == CircuitState.CLOSED.value
