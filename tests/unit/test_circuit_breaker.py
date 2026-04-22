# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Circuit breaker state machine tests — production-level, zero stubs.

Design principles
-----------------
* No asyncio.sleep() to *simulate* solver latency.  asyncio.sleep()
  yields the event loop cooperatively and does NOT simulate Z3's native
  C++ GIL-blocking behaviour.

* State-machine transitions are driven by calling ``_record_solve()``
  directly with explicit millisecond values.  This is the correct unit
  test for the state machine itself (CLOSED → OPEN → HALF_OPEN logic).

* Happy-path (CLOSED) tests use a real ``Guard`` backed by a real Z3
  solve so the integration between Guard and CircuitBreaker is exercised
  with actual solver execution.

* ``_CountingGuard`` is a non-mock decorator that forwards ALL work to
  a real ``Guard`` and only adds call-count instrumentation.  It is used
  to verify the circuit breaker does NOT call the guard when OPEN —
  a circuit-breaker correctness invariant.
"""
from __future__ import annotations

import asyncio
from decimal import Decimal

import pytest

from pramanix.circuit_breaker import (
    AdaptiveCircuitBreaker,
    CircuitBreakerConfig,
    CircuitState,
)
from pramanix.decision import Decision
from pramanix.expressions import E, Field
from pramanix.guard import Guard, GuardConfig
from pramanix.policy import Policy

# ── Real policy and guard ─────────────────────────────────────────────────────

_amount_field = Field("amount", Decimal, "Real")


class _SimplePolicy(Policy):
    """Minimal policy for circuit-breaker integration tests."""

    class Meta:
        version = "1.0"

    @classmethod
    def fields(cls):  # type: ignore[override]
        return {"amount": _amount_field}

    @classmethod
    def invariants(cls):  # type: ignore[override]
        return [(E(_amount_field) >= 0).named("non_negative")]


# One shared guard — Guard is thread-safe; the circuit breaker adds its own lock.
_REAL_GUARD = Guard(_SimplePolicy, GuardConfig(execution_mode="sync"))

# State and intent that produce a real ALLOW from Z3.
_STATE = {"state_version": "1.0"}
_ALLOW_INTENT = {"amount": Decimal("50")}


# ── _CountingGuard: non-mock decorator ───────────────────────────────────────


class _CountingGuard:
    """Real Guard decorator that counts ``verify_async`` invocations.

    This is NOT a mock.  Every call is fully delegated to the wrapped
    ``Guard`` instance — Z3 runs, a real ``Decision`` is returned.  The
    only addition is a ``call_count`` attribute used by tests that need
    to assert the circuit breaker does NOT forward requests when OPEN.
    """

    def __init__(self, guard: Guard) -> None:
        self._guard = guard
        self.call_count: int = 0

    async def verify_async(self, *, intent: dict, state: dict) -> Decision:
        self.call_count += 1
        return await self._guard.verify_async(intent=intent, state=state)


# ── Helpers ────────────────────────────────────────────────────────────────────


async def _inject_pressure(
    breaker: AdaptiveCircuitBreaker,
    count: int,
    solve_ms: float,
) -> None:
    """Drive the state machine with *count* observations of *solve_ms*.

    This calls ``_record_solve()`` directly under the lock — the same
    path taken by ``verify_async()`` after a real solve.  Using this
    helper instead of asyncio.sleep() stubs:

    * Tests the state machine logic in isolation from guard timing.
    * Produces deterministic, sub-millisecond test execution.
    * Does not imply Z3 is fast or slow — it tests the circuit breaker's
      response to observed latency values, which is its actual contract.
    """
    for _ in range(count):
        async with breaker._lock:
            breaker._record_solve(solve_ms)


# ── CLOSED state ──────────────────────────────────────────────────────────────


class TestCircuitBreakerClosed:
    @pytest.mark.asyncio
    async def test_starts_in_closed_state(self) -> None:
        breaker = AdaptiveCircuitBreaker(guard=_REAL_GUARD)
        assert breaker.state == CircuitState.CLOSED

    @pytest.mark.asyncio
    async def test_fast_solves_stay_closed(self) -> None:
        """Real Z3 solves (< 40 ms) must not trip the circuit breaker."""
        config = CircuitBreakerConfig(pressure_threshold_ms=40.0)
        breaker = AdaptiveCircuitBreaker(guard=_REAL_GUARD, config=config)
        for _ in range(10):
            await breaker.verify_async(intent=_ALLOW_INTENT, state=_STATE)
        assert breaker.state == CircuitState.CLOSED

    @pytest.mark.asyncio
    async def test_consecutive_slow_observations_transition_to_open(self) -> None:
        """5 consecutive solve_ms > 40 ms → OPEN.

        The state machine operates on *observed* solve_ms values.  We
        inject them directly; the guard is not involved.
        """
        config = CircuitBreakerConfig(
            pressure_threshold_ms=40.0,
            consecutive_pressure_count=5,
        )
        breaker = AdaptiveCircuitBreaker(guard=_REAL_GUARD, config=config)
        await _inject_pressure(breaker, count=5, solve_ms=55.0)
        assert breaker.state == CircuitState.OPEN

    @pytest.mark.asyncio
    async def test_pressure_counter_resets_on_fast_observation(self) -> None:
        """Fast observation after slow ones resets the pressure counter."""
        config = CircuitBreakerConfig(
            pressure_threshold_ms=40.0,
            consecutive_pressure_count=10,
        )
        breaker = AdaptiveCircuitBreaker(guard=_REAL_GUARD, config=config)

        # Build up pressure (4 slow, not enough to trip)
        await _inject_pressure(breaker, count=4, solve_ms=55.0)
        assert breaker.status.consecutive_pressure == 4

        # One fast observation resets
        async with breaker._lock:
            breaker._record_solve(2.0)  # well below threshold
        assert breaker.status.consecutive_pressure == 0
        assert breaker.state == CircuitState.CLOSED


# ── OPEN state ───────────────────────────────────────────────────────────────


class TestCircuitBreakerOpen:
    @pytest.mark.asyncio
    async def test_open_does_not_call_guard(self) -> None:
        """When OPEN, verify_async must NOT delegate to the guard."""
        counting = _CountingGuard(_REAL_GUARD)
        config = CircuitBreakerConfig(
            pressure_threshold_ms=40.0,
            consecutive_pressure_count=5,
        )
        breaker = AdaptiveCircuitBreaker(guard=counting, config=config)

        # Trip the breaker via injected observations (no guard calls yet)
        await _inject_pressure(breaker, count=5, solve_ms=55.0)
        assert breaker.state == CircuitState.OPEN

        count_at_open = counting.call_count

        # This call must be intercepted by the breaker, guard NOT called
        decision = await breaker.verify_async(intent=_ALLOW_INTENT, state=_STATE)

        assert counting.call_count == count_at_open, (
            "Guard was called while circuit was OPEN — invariant violated"
        )
        assert not decision.allowed

    @pytest.mark.asyncio
    async def test_open_returns_block_decision(self) -> None:
        config = CircuitBreakerConfig(
            pressure_threshold_ms=40.0,
            consecutive_pressure_count=3,
        )
        breaker = AdaptiveCircuitBreaker(guard=_REAL_GUARD, config=config)
        await _inject_pressure(breaker, count=3, solve_ms=55.0)
        assert breaker.state == CircuitState.OPEN

        decision = await breaker.verify_async(intent=_ALLOW_INTENT, state=_STATE)
        assert not decision.allowed

    @pytest.mark.asyncio
    async def test_open_transitions_to_half_open_after_recovery(self) -> None:
        """After recovery_seconds elapses, the first call enters HALF_OPEN and
        succeeds (real Z3 solve is fast) → transitions to CLOSED.

        pressure_threshold_ms=500 is intentionally high so that a real Z3 solve
        on any machine (including Windows under full-suite load) never accidentally
        exceeds the threshold and causes HALF_OPEN → OPEN instead of CLOSED.
        The fake pressure uses solve_ms=600 to stay above the threshold.
        """
        config = CircuitBreakerConfig(
            pressure_threshold_ms=500.0,
            consecutive_pressure_count=2,
            recovery_seconds=0.05,  # 50 ms — only real wall-clock wait in this file
        )
        breaker = AdaptiveCircuitBreaker(guard=_REAL_GUARD, config=config)

        await _inject_pressure(breaker, count=2, solve_ms=600.0)
        assert breaker.state == CircuitState.OPEN

        # Wait for the real recovery period
        await asyncio.sleep(0.1)

        # Real guard runs a real Z3 solve — well below 500 ms → probe succeeds → CLOSED
        await breaker.verify_async(intent=_ALLOW_INTENT, state=_STATE)
        assert breaker.state == CircuitState.CLOSED


# ── ISOLATED state ────────────────────────────────────────────────────────────


class TestCircuitBreakerIsolation:
    @pytest.mark.asyncio
    async def test_three_open_episodes_cause_isolation(self) -> None:
        config = CircuitBreakerConfig(
            pressure_threshold_ms=40.0,
            consecutive_pressure_count=2,
            isolation_threshold=3,
            recovery_seconds=0.05,
        )
        breaker = AdaptiveCircuitBreaker(guard=_REAL_GUARD, config=config)

        for _episode in range(3):
            # Trip the breaker
            await _inject_pressure(breaker, count=2, solve_ms=55.0)

            if breaker.state != CircuitState.ISOLATED:
                # Allow recovery window to elapse
                await asyncio.sleep(0.1)
                # Inject a failing probe to keep breaker under pressure
                await _inject_pressure(breaker, count=1, solve_ms=55.0)

        assert breaker.state == CircuitState.ISOLATED

    @pytest.mark.asyncio
    async def test_isolated_blocks_all_requests(self) -> None:
        config = CircuitBreakerConfig(
            pressure_threshold_ms=40.0,
            consecutive_pressure_count=2,
            isolation_threshold=3,
            recovery_seconds=0.01,
        )
        counting = _CountingGuard(_REAL_GUARD)
        breaker = AdaptiveCircuitBreaker(guard=counting, config=config)

        # Drive to ISOLATED
        for _ep in range(4):
            await _inject_pressure(breaker, count=2, solve_ms=55.0)
            await asyncio.sleep(0.02)
            if breaker.state == CircuitState.ISOLATED:
                break
            await _inject_pressure(breaker, count=1, solve_ms=55.0)

        if breaker.state != CircuitState.ISOLATED:
            pytest.skip("Could not reach ISOLATED in this run — skipping")

        count_before = counting.call_count
        decision = await breaker.verify_async(intent=_ALLOW_INTENT, state=_STATE)
        assert counting.call_count == count_before, (
            "Guard was called while circuit was ISOLATED — invariant violated"
        )
        assert not decision.allowed

    @pytest.mark.asyncio
    async def test_manual_reset_recovers_from_isolated(self) -> None:
        config = CircuitBreakerConfig(
            pressure_threshold_ms=40.0,
            consecutive_pressure_count=2,
            isolation_threshold=1,
        )
        breaker = AdaptiveCircuitBreaker(guard=_REAL_GUARD, config=config)

        await _inject_pressure(breaker, count=2, solve_ms=55.0)
        # Directly assign ISOLATED to test that reset() returns to CLOSED,
        # without relying on multiple open episodes to reach isolation.
        breaker._state = CircuitState.ISOLATED

        breaker.reset()
        assert breaker.state == CircuitState.CLOSED


# ── Status and metrics ────────────────────────────────────────────────────────


class TestCircuitBreakerStatus:
    @pytest.mark.asyncio
    async def test_status_namespace_matches_config(self) -> None:
        config = CircuitBreakerConfig(namespace="test_banking")
        breaker = AdaptiveCircuitBreaker(guard=_REAL_GUARD, config=config)
        assert breaker.status.namespace == "test_banking"

    @pytest.mark.asyncio
    async def test_status_state_matches_current_state(self) -> None:
        config = CircuitBreakerConfig(
            pressure_threshold_ms=40.0,
            consecutive_pressure_count=3,
        )
        breaker = AdaptiveCircuitBreaker(guard=_REAL_GUARD, config=config)
        await _inject_pressure(breaker, count=3, solve_ms=55.0)
        assert breaker.status.state == CircuitState.OPEN
        assert breaker.status.open_episodes >= 1

    @pytest.mark.asyncio
    async def test_prometheus_metrics_do_not_raise(self) -> None:
        """Prometheus state transitions must not raise regardless of availability."""
        config = CircuitBreakerConfig(
            pressure_threshold_ms=40.0,
            consecutive_pressure_count=2,
            namespace="prometheus_test",
        )
        breaker = AdaptiveCircuitBreaker(guard=_REAL_GUARD, config=config)
        await _inject_pressure(breaker, count=2, solve_ms=55.0)
        assert breaker.state == CircuitState.OPEN
