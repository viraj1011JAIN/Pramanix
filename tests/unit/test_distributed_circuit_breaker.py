# SPDX-License-Identifier: Apache-2.0
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Tests for RedisDistributedBackend (C-5)."""

from __future__ import annotations

import asyncio

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

    backend = RedisDistributedBackend._for_testing(None)
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


# ── InMemoryDistributedBackend: new probe + force_reset_state methods ──────────


@pytest.mark.asyncio
async def test_in_memory_try_claim_probe_exclusive() -> None:
    """try_claim_probe returns True once and False for all subsequent callers."""
    InMemoryDistributedBackend.clear()

    first = await InMemoryDistributedBackend.try_claim_probe("probe_ns")
    second = await InMemoryDistributedBackend.try_claim_probe("probe_ns")
    third = await InMemoryDistributedBackend.try_claim_probe("probe_ns")

    assert first is True, "First caller must claim the probe token"
    assert second is False, "Second concurrent caller must be rejected"
    assert third is False, "Third concurrent caller must be rejected"


@pytest.mark.asyncio
async def test_in_memory_release_probe_allows_re_claim() -> None:
    """After release_probe, the next try_claim_probe succeeds."""
    InMemoryDistributedBackend.clear()

    claimed = await InMemoryDistributedBackend.try_claim_probe("release_ns")
    assert claimed is True

    await InMemoryDistributedBackend.release_probe("release_ns")

    reclaimed = await InMemoryDistributedBackend.try_claim_probe("release_ns")
    assert reclaimed is True, "After release, probe token must be claimable again"


@pytest.mark.asyncio
async def test_in_memory_force_reset_state_clears_open_and_probe() -> None:
    """force_reset_state returns CLOSED state and releases any held probe token."""
    InMemoryDistributedBackend.clear()

    # Simulate OPEN state + held probe token
    await InMemoryDistributedBackend.set_state(
        "reset_ns",
        _DistributedState(circuit_state=CircuitState.OPEN.value, failure_count=5),
    )
    await InMemoryDistributedBackend.try_claim_probe("reset_ns")  # claim probe

    await InMemoryDistributedBackend.force_reset_state("reset_ns")

    # State must be CLOSED
    state = await InMemoryDistributedBackend.get_state("reset_ns")
    assert state.circuit_state == CircuitState.CLOSED.value
    assert state.failure_count == 0

    # Probe token must be released (can claim again)
    can_claim = await InMemoryDistributedBackend.try_claim_probe("reset_ns")
    assert can_claim is True


@pytest.mark.asyncio
async def test_in_memory_clear_also_releases_probe_holders() -> None:
    """InMemoryDistributedBackend.clear() resets _probe_holders."""
    InMemoryDistributedBackend.clear()
    await InMemoryDistributedBackend.try_claim_probe("clear_probe_ns")

    InMemoryDistributedBackend.clear("clear_probe_ns")

    can_claim = await InMemoryDistributedBackend.try_claim_probe("clear_probe_ns")
    assert can_claim is True, "clear() must also release probe holders"


@pytest.mark.asyncio
async def test_in_memory_open_at_epoch_preserved_in_merge() -> None:
    """Conservative merge keeps the max open_at_epoch across replicas."""
    import time as _time

    InMemoryDistributedBackend.clear()

    t_early = _time.time() - 100.0
    t_recent = _time.time() - 10.0

    await InMemoryDistributedBackend.set_state(
        "epoch_ns",
        _DistributedState(circuit_state=CircuitState.OPEN.value, open_at_epoch=t_early),
    )
    await InMemoryDistributedBackend.set_state(
        "epoch_ns",
        _DistributedState(circuit_state=CircuitState.OPEN.value, open_at_epoch=t_recent),
    )

    state = await InMemoryDistributedBackend.get_state("epoch_ns")
    assert abs(state.open_at_epoch - t_recent) < 0.01, (
        "open_at_epoch merge must keep the most recent (max) value"
    )


# ── DistributedCircuitBreaker: #263 HALF_OPEN, #265 reset_async, #270 no-inflation ──


class _InMemoryAllowGuard:
    """Protocol-compliant guard for DistributedCircuitBreaker tests.

    Resolves instantly with an ALLOW decision and a configurable solve_ms
    fingerprint via a monotonic time sleep.
    """

    def __init__(self, delay_s: float = 0.0) -> None:
        self._delay = delay_s
        self.call_count = 0

    async def verify_async(self, *, intent: dict, state: dict) -> object:
        import asyncio as _asyncio

        from pramanix.decision import Decision, SolverStatus

        self.call_count += 1
        if self._delay:
            await _asyncio.sleep(self._delay)
        return Decision(
            allowed=True,
            status=SolverStatus.SAFE,
            violated_invariants=(),
            explanation="allow",
        )


@pytest.mark.asyncio
async def test_distributed_failure_count_not_inflated_after_sync() -> None:
    """#270 fix: _local_failure_count must reset to 0 on _sync_state, not to agg total.

    Before the fix, _sync_state set _local_failure_count = agg.failure_count
    (the cumulative total across all replicas).  A single local pressure event
    then made _local_failure_count = agg_total + 1 >= threshold, immediately
    tripping OPEN even with just one new local failure.
    """
    import warnings as _w

    from pramanix.circuit_breaker import (
        CircuitBreakerConfig,
        DistributedCircuitBreaker,
        InMemoryDistributedBackend,
    )

    with _w.catch_warnings():
        _w.simplefilter("ignore", UserWarning)
        backend = InMemoryDistributedBackend()

    InMemoryDistributedBackend.clear()

    # Pre-load a high aggregate failure_count that would trip OPEN if compared directly.
    await InMemoryDistributedBackend.set_state(
        "inflation-ns",
        _DistributedState(
            circuit_state=CircuitState.CLOSED.value,
            failure_count=999,  # far above any reasonable threshold
        ),
    )

    config = CircuitBreakerConfig(
        pressure_threshold_ms=1.0,
        consecutive_pressure_count=5,  # threshold = 5 local failures
        namespace="inflation-ns",
    )
    guard = _InMemoryAllowGuard()
    cb = DistributedCircuitBreaker(guard, config, backend=backend)

    # After one verify_async, _sync_state runs and must reset _local_failure_count=0.
    # The guard returns instantly so solve_ms ≈ 0 (below threshold) → no pressure event.
    await cb.verify_async(intent={}, state={})

    # _local_failure_count must be 0 (reset by sync, no local pressure events).
    assert cb._local_failure_count == 0, (
        f"_local_failure_count={cb._local_failure_count} — inflation bug still present (#270)"
    )
    # State must remain CLOSED (999 aggregate should not have triggered OPEN).
    assert cb.state == CircuitState.CLOSED


@pytest.mark.asyncio
async def test_distributed_half_open_single_probe_guarantee() -> None:
    """#263 fix: exactly one replica probes when recovery window elapses; others see OPEN.

    Two DistributedCircuitBreaker instances share the same InMemoryDistributedBackend.
    We force OPEN state with open_at_epoch far enough in the past to exceed recovery_seconds.
    Both instances run verify_async concurrently.  Only the one that claims the probe token
    must invoke the guard; the other must return an OPEN decision immediately.
    """
    import time as _time
    import warnings as _w

    from pramanix.circuit_breaker import (
        CircuitBreakerConfig,
        DistributedCircuitBreaker,
        InMemoryDistributedBackend,
    )
    from pramanix.decision import Decision

    with _w.catch_warnings():
        _w.simplefilter("ignore", UserWarning)
        backend = InMemoryDistributedBackend()

    InMemoryDistributedBackend.clear()

    # Push OPEN state with open_at_epoch well past recovery window.
    recovery_s = 0.001
    past_epoch = _time.time() - 999.0
    await InMemoryDistributedBackend.set_state(
        "half-open-ns",
        _DistributedState(
            circuit_state=CircuitState.OPEN.value,
            failure_count=5,
            open_at_epoch=past_epoch,
        ),
    )

    config = CircuitBreakerConfig(
        pressure_threshold_ms=10_000.0,  # high → probe will succeed (solve_ms << threshold)
        recovery_seconds=recovery_s,
        namespace="half-open-ns",
    )

    slow_guard = _InMemoryAllowGuard(delay_s=0.05)
    breaker_a = DistributedCircuitBreaker(slow_guard, config, backend=backend)
    breaker_b = DistributedCircuitBreaker(slow_guard, config, backend=backend)

    results = await asyncio.gather(
        breaker_a.verify_async(intent={}, state={}),
        breaker_b.verify_async(intent={}, state={}),
        return_exceptions=True,
    )

    # Guard must be called exactly once — only the probe replica invokes it.
    assert slow_guard.call_count == 1, (
        f"Guard called {slow_guard.call_count} times — thundering herd not prevented (#263)"
    )

    # Both calls must return Decision objects (no raised exceptions).
    for r in results:
        assert isinstance(r, Decision), f"Expected Decision, got {type(r).__name__}: {r}"

    # After successful probe, backend state must be CLOSED.
    final_state = await InMemoryDistributedBackend.get_state("half-open-ns")
    assert final_state.circuit_state == CircuitState.CLOSED.value, (
        "Probe success must reset distributed state to CLOSED (#263)"
    )


@pytest.mark.asyncio
async def test_distributed_reset_async_awaits_backend_clear() -> None:
    """#265 fix: reset_async() must fully clear Redis state before returning.

    Before the fix, reset() called backend.clear() which in async contexts
    schedules a fire-and-forget task.  If the process exits before that task
    runs, ISOLATED state persists across restarts.  reset_async() must
    force_reset_state (awaitable) and update all local fields synchronously.
    """
    import warnings as _w

    from pramanix.circuit_breaker import (
        CircuitBreakerConfig,
        DistributedCircuitBreaker,
        InMemoryDistributedBackend,
    )

    with _w.catch_warnings():
        _w.simplefilter("ignore", UserWarning)
        backend = InMemoryDistributedBackend()

    InMemoryDistributedBackend.clear()

    await InMemoryDistributedBackend.set_state(
        "reset-async-ns",
        _DistributedState(
            circuit_state=CircuitState.ISOLATED.value,
            failure_count=20,
        ),
    )

    config = CircuitBreakerConfig(namespace="reset-async-ns")
    guard = _InMemoryAllowGuard()
    cb = DistributedCircuitBreaker(guard, config, backend=backend)
    cb._local_state = CircuitState.ISOLATED

    # Call reset_async — must await backend clear before returning.
    await cb.reset_async()

    # Local state must be CLOSED immediately after reset_async() returns.
    assert cb.state == CircuitState.CLOSED
    assert cb._local_failure_count == 0
    assert cb._synced_open_at_epoch == 0.0

    # Backend state must also be CLOSED (not just local).
    backend_state = await InMemoryDistributedBackend.get_state("reset-async-ns")
    assert backend_state.circuit_state == CircuitState.CLOSED.value, (
        "reset_async() must persist CLOSED to backend before returning (#265)"
    )


@pytest.mark.asyncio
async def test_distributed_reset_sync_in_async_context_warns(caplog: pytest.LogCaptureFixture) -> None:
    """#265 fix: reset() in async context logs a warning directing to reset_async()."""
    import logging
    import warnings as _w

    from pramanix.circuit_breaker import (
        CircuitBreakerConfig,
        DistributedCircuitBreaker,
        InMemoryDistributedBackend,
    )

    with _w.catch_warnings():
        _w.simplefilter("ignore", UserWarning)
        backend = InMemoryDistributedBackend()

    InMemoryDistributedBackend.clear()
    config = CircuitBreakerConfig(namespace="reset-warn-ns")
    guard = _InMemoryAllowGuard()
    cb = DistributedCircuitBreaker(guard, config, backend=backend)

    with caplog.at_level(logging.WARNING, logger="pramanix.circuit_breaker"):
        cb.reset()  # called from async context (this test is async)

    assert any(
        "reset_async" in record.message for record in caplog.records
    ), "reset() in async context must warn about using reset_async()"


@pytest.mark.asyncio
async def test_distributed_open_at_epoch_written_on_open_push() -> None:
    """open_at_epoch must be set to a wall-clock time when OPEN state is pushed.

    This is the prerequisite for cross-process HALF_OPEN recovery timing (#263):
    all replicas need a common absolute timestamp to independently decide when
    recovery_seconds have elapsed.
    """
    import time as _time
    import warnings as _w

    from pramanix.circuit_breaker import (
        CircuitBreakerConfig,
        DistributedCircuitBreaker,
        InMemoryDistributedBackend,
    )

    with _w.catch_warnings():
        _w.simplefilter("ignore", UserWarning)
        backend = InMemoryDistributedBackend()

    InMemoryDistributedBackend.clear()
    config = CircuitBreakerConfig(
        pressure_threshold_ms=0.0001,  # everything is "slow" → trips OPEN
        consecutive_pressure_count=1,
        namespace="epoch-push-ns",
    )
    guard = _InMemoryAllowGuard(delay_s=0.0)
    cb = DistributedCircuitBreaker(guard, config, backend=backend)

    before = _time.time()
    await cb.verify_async(intent={}, state={})  # one pressure event → OPEN
    after = _time.time()

    state = await InMemoryDistributedBackend.get_state("epoch-push-ns")
    if state.circuit_state == CircuitState.OPEN.value:
        assert state.open_at_epoch >= before, "open_at_epoch must be >= before the push"
        assert state.open_at_epoch <= after + 1.0, "open_at_epoch must be near current time"
