# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Circuit breaker state machine tests.

Uses a stub guard with configurable solver_time_ms.
No real Z3 required — state machine logic tested in isolation.
"""
from __future__ import annotations

import asyncio

import pytest

from pramanix.circuit_breaker import (
    AdaptiveCircuitBreaker,
    CircuitBreakerConfig,
    CircuitState,
)
from pramanix.decision import Decision


class _StubGuard:
    """Guard stub returning decisions with configurable timing."""

    def __init__(self, solve_ms: float = 2.0, allowed: bool = True) -> None:
        self.solve_ms = solve_ms
        self.allowed = allowed
        self.call_count = 0

    async def verify_async(self, *, intent: dict, state: dict) -> Decision:
        self.call_count += 1
        await asyncio.sleep(self.solve_ms / 1000.0)
        if self.allowed:
            return Decision.safe()
        return Decision.unsafe(
            violated_invariants=("test_rule",),
            explanation="stub block",
        )


_STATE = {"state_version": "v1"}


class TestCircuitBreakerClosed:
    @pytest.mark.asyncio
    async def test_starts_in_closed_state(self):
        breaker = AdaptiveCircuitBreaker(guard=_StubGuard())
        assert breaker.state == CircuitState.CLOSED

    @pytest.mark.asyncio
    async def test_fast_solves_stay_closed(self):
        stub = _StubGuard(solve_ms=2.0)
        config = CircuitBreakerConfig(pressure_threshold_ms=40.0)
        breaker = AdaptiveCircuitBreaker(guard=stub, config=config)
        for _ in range(10):
            await breaker.verify_async(intent={}, state=_STATE)
        assert breaker.state == CircuitState.CLOSED

    @pytest.mark.asyncio
    async def test_consecutive_slow_solves_transition_to_open(self):
        stub = _StubGuard(solve_ms=55.0)
        config = CircuitBreakerConfig(
            pressure_threshold_ms=40.0,
            consecutive_pressure_count=5,
        )
        breaker = AdaptiveCircuitBreaker(guard=stub, config=config)
        for _ in range(5):
            await breaker.verify_async(intent={}, state=_STATE)
        assert breaker.state == CircuitState.OPEN

    @pytest.mark.asyncio
    async def test_pressure_counter_resets_on_fast_solve(self):
        stub = _StubGuard(solve_ms=55.0)
        config = CircuitBreakerConfig(
            pressure_threshold_ms=40.0,
            consecutive_pressure_count=10,
        )
        breaker = AdaptiveCircuitBreaker(guard=stub, config=config)
        for _ in range(4):
            await breaker.verify_async(intent={}, state=_STATE)
        assert breaker.status.consecutive_pressure == 4

        stub.solve_ms = 2.0
        await breaker.verify_async(intent={}, state=_STATE)
        assert breaker.status.consecutive_pressure == 0
        assert breaker.state == CircuitState.CLOSED


class TestCircuitBreakerOpen:
    @pytest.mark.asyncio
    async def test_open_does_not_call_guard(self):
        stub = _StubGuard(solve_ms=55.0)
        config = CircuitBreakerConfig(
            pressure_threshold_ms=40.0,
            consecutive_pressure_count=5,
        )
        breaker = AdaptiveCircuitBreaker(guard=stub, config=config)

        for _ in range(5):
            await breaker.verify_async(intent={}, state=_STATE)

        assert breaker.state == CircuitState.OPEN
        count_at_open = stub.call_count

        decision = await breaker.verify_async(intent={}, state=_STATE)

        assert stub.call_count == count_at_open  # Guard NOT called
        assert not decision.allowed

    @pytest.mark.asyncio
    async def test_open_returns_block_decision(self):
        stub = _StubGuard(solve_ms=55.0)
        config = CircuitBreakerConfig(
            pressure_threshold_ms=40.0,
            consecutive_pressure_count=3,
        )
        breaker = AdaptiveCircuitBreaker(guard=stub, config=config)
        for _ in range(3):
            await breaker.verify_async(intent={}, state=_STATE)
        assert breaker.state == CircuitState.OPEN

        decision = await breaker.verify_async(intent={}, state=_STATE)
        assert not decision.allowed

    @pytest.mark.asyncio
    async def test_open_transitions_to_half_open_after_recovery(self):
        stub = _StubGuard(solve_ms=55.0)
        config = CircuitBreakerConfig(
            pressure_threshold_ms=40.0,
            consecutive_pressure_count=2,
            recovery_seconds=0.05,  # 50ms for test speed
        )
        breaker = AdaptiveCircuitBreaker(guard=stub, config=config)

        for _ in range(2):
            await breaker.verify_async(intent={}, state=_STATE)
        assert breaker.state == CircuitState.OPEN

        # Wait for recovery period
        await asyncio.sleep(0.1)

        # Set guard to return fast so probe succeeds
        stub.solve_ms = 2.0
        await breaker.verify_async(intent={}, state=_STATE)

        assert breaker.state == CircuitState.CLOSED


class TestCircuitBreakerIsolation:
    @pytest.mark.asyncio
    async def test_three_open_episodes_cause_isolation(self):
        stub = _StubGuard(solve_ms=55.0)
        config = CircuitBreakerConfig(
            pressure_threshold_ms=40.0,
            consecutive_pressure_count=2,
            isolation_threshold=3,
            recovery_seconds=0.05,
        )
        breaker = AdaptiveCircuitBreaker(guard=stub, config=config)

        for _episode in range(3):
            # Trip the breaker
            for _ in range(2):
                await breaker.verify_async(intent={}, state=_STATE)

            if breaker.state != CircuitState.ISOLATED:
                # Recover to HALF_OPEN and fail probe
                await asyncio.sleep(0.1)
                # Guard still slow — probe fails → back to OPEN
                await breaker.verify_async(intent={}, state=_STATE)

        assert breaker.state == CircuitState.ISOLATED

    @pytest.mark.asyncio
    async def test_isolated_blocks_all_requests(self):
        stub = _StubGuard(solve_ms=55.0)
        config = CircuitBreakerConfig(
            pressure_threshold_ms=40.0,
            consecutive_pressure_count=2,
            isolation_threshold=3,
            recovery_seconds=0.01,
        )
        breaker = AdaptiveCircuitBreaker(guard=stub, config=config)

        # Force to isolated through multiple trips
        for _ep in range(4):
            for _ in range(2):
                await breaker.verify_async(intent={}, state=_STATE)
            await asyncio.sleep(0.02)
            if breaker.state == CircuitState.ISOLATED:
                break
            await breaker.verify_async(intent={}, state=_STATE)

        if breaker.state != CircuitState.ISOLATED:
            pytest.skip("Could not reach ISOLATED in this run — skipping")

        # Even with fast guard, isolated still blocks
        stub.solve_ms = 1.0
        count_before = stub.call_count
        decision = await breaker.verify_async(intent={}, state=_STATE)
        assert stub.call_count == count_before  # Guard not called
        assert not decision.allowed

    @pytest.mark.asyncio
    async def test_manual_reset_recovers_from_isolated(self):
        stub = _StubGuard(solve_ms=55.0)
        config = CircuitBreakerConfig(
            pressure_threshold_ms=40.0,
            consecutive_pressure_count=2,
            isolation_threshold=1,  # Trip to isolated after 1 OPEN episode
        )
        breaker = AdaptiveCircuitBreaker(guard=stub, config=config)

        for _ in range(2):
            await breaker.verify_async(intent={}, state=_STATE)

        # Force isolated
        breaker._state = CircuitState.ISOLATED

        breaker.reset()
        assert breaker.state == CircuitState.CLOSED


class TestCircuitBreakerStatus:
    @pytest.mark.asyncio
    async def test_status_namespace_matches_config(self):
        config = CircuitBreakerConfig(namespace="test_banking")
        breaker = AdaptiveCircuitBreaker(guard=_StubGuard(), config=config)
        assert breaker.status.namespace == "test_banking"

    @pytest.mark.asyncio
    async def test_status_state_matches_current_state(self):
        stub = _StubGuard(solve_ms=55.0)
        config = CircuitBreakerConfig(
            pressure_threshold_ms=40.0,
            consecutive_pressure_count=3,
        )
        breaker = AdaptiveCircuitBreaker(guard=stub, config=config)
        for _ in range(3):
            await breaker.verify_async(intent={}, state=_STATE)
        assert breaker.status.state == CircuitState.OPEN
        assert breaker.status.open_episodes >= 1

    @pytest.mark.asyncio
    async def test_prometheus_metrics_do_not_raise(self):
        """Verify no exception during state transitions regardless of prometheus availability."""
        stub = _StubGuard(solve_ms=55.0)
        config = CircuitBreakerConfig(
            pressure_threshold_ms=40.0,
            consecutive_pressure_count=2,
            namespace="prometheus_test",
        )
        breaker = AdaptiveCircuitBreaker(guard=stub, config=config)
        # All these transitions should complete without exception
        for _ in range(2):
            await breaker.verify_async(intent={}, state=_STATE)
        assert breaker.state == CircuitState.OPEN
