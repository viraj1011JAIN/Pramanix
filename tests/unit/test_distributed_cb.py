# SPDX-License-Identifier: AGPL-3.0-only
# Phase C-5: Tests for DistributedCircuitBreaker
"""Verifies distributed circuit breaker state sharing across replicas."""
from __future__ import annotations

import asyncio

import pytest

from pramanix import Guard, GuardConfig
from pramanix.circuit_breaker import (
    CircuitBreakerConfig,
    CircuitState,
    DistributedCircuitBreaker,
    InMemoryDistributedBackend,
    _DistributedState,
)
from pramanix.exceptions import ConfigurationError
from pramanix.expressions import E, Field
from pramanix.policy import Policy


class _SimplePolicy(Policy):
    amount = Field("amount", int, "Int")

    @classmethod
    def invariants(cls):
        return [(E(cls.amount) >= 0).named("non_negative")]


def _make_guard() -> Guard:
    return Guard(_SimplePolicy, config=GuardConfig(execution_mode="async-thread"))


def _make_distributed_breaker(namespace: str = "test") -> DistributedCircuitBreaker:
    return DistributedCircuitBreaker(
        _make_guard(),
        CircuitBreakerConfig(namespace=namespace, pressure_threshold_ms=5.0, consecutive_pressure_count=3),
    )


@pytest.fixture(autouse=True)
def _clear_backend() -> None:
    """Reset InMemoryDistributedBackend before each test."""
    InMemoryDistributedBackend.clear()


class TestDistributedCBBasic:
    """Basic distributed circuit breaker operation."""

    def test_verify_sync_allow(self) -> None:
        cb = _make_distributed_breaker()
        d = cb.verify_sync(intent={"amount": 10}, state={})
        assert d.allowed

    def test_verify_sync_block(self) -> None:
        cb = _make_distributed_breaker()
        d = cb.verify_sync(intent={"amount": -1}, state={})
        assert not d.allowed

    def test_initial_state_is_closed(self) -> None:
        cb = _make_distributed_breaker()
        assert cb.state == CircuitState.CLOSED

    def test_verify_sync_from_event_loop_raises(self) -> None:
        cb = _make_distributed_breaker("loop_test")

        async def _inner() -> None:
            with pytest.raises(ConfigurationError, match="verify_async"):
                cb.verify_sync(intent={"amount": 5}, state={})

        asyncio.run(_inner())


class TestDistributedCBStateSharing:
    """State propagates across replicas sharing the same namespace."""

    def test_three_replicas_share_state(self) -> None:
        """Trip breaker on replica 1; replicas 2 and 3 see OPEN after sync."""
        ns = "shared_ns"
        # Use conservative threshold: trip after 3 pressure events
        cfg = CircuitBreakerConfig(
            namespace=ns,
            pressure_threshold_ms=0.0001,  # virtually always exceeded
            consecutive_pressure_count=3,
        )
        guard = _make_guard()
        r1 = DistributedCircuitBreaker(guard, cfg)
        r2 = DistributedCircuitBreaker(guard, cfg)
        r3 = DistributedCircuitBreaker(guard, cfg)

        # Trip replica 1: make 3 pressure-threshold-exceeding calls
        for _ in range(3):
            asyncio.run(r1.verify_async(intent={"amount": 5}, state={}))

        # Replica 1 should now be OPEN
        asyncio.run(r1._sync_state())
        assert r1.state == CircuitState.OPEN

        # Replicas 2 and 3 should also see OPEN after syncing
        asyncio.run(r2._sync_state())
        asyncio.run(r3._sync_state())
        assert r2.state == CircuitState.OPEN
        assert r3.state == CircuitState.OPEN

    def test_open_state_blocks_other_replicas(self) -> None:
        """When aggregate state is OPEN, all replicas return blocked Decision."""
        ns = "block_ns"
        cfg = CircuitBreakerConfig(namespace=ns, pressure_threshold_ms=0.0001, consecutive_pressure_count=3)
        guard = _make_guard()
        r1 = DistributedCircuitBreaker(guard, cfg)
        r2 = DistributedCircuitBreaker(guard, cfg)

        # Trip r1
        for _ in range(3):
            asyncio.run(r1.verify_async(intent={"amount": 5}, state={}))

        # r2 should now block (aggregate is OPEN)
        d = r2.verify_sync(intent={"amount": 5}, state={})
        assert not d.allowed

    def test_different_namespaces_independent(self) -> None:
        """Circuit breakers in different namespaces don't affect each other."""
        cfg_a = CircuitBreakerConfig(namespace="ns_a", pressure_threshold_ms=0.0001, consecutive_pressure_count=3)
        cfg_b = CircuitBreakerConfig(namespace="ns_b")
        guard = _make_guard()
        r_a = DistributedCircuitBreaker(guard, cfg_a)
        r_b = DistributedCircuitBreaker(guard, cfg_b)

        # Trip namespace A
        for _ in range(3):
            asyncio.run(r_a.verify_async(intent={"amount": 5}, state={}))
        asyncio.run(r_a._sync_state())
        assert r_a.state == CircuitState.OPEN

        # Namespace B should be unaffected
        asyncio.run(r_b._sync_state())
        assert r_b.state == CircuitState.CLOSED


class TestInMemoryBackend:
    """InMemoryDistributedBackend correctness."""

    def test_get_empty_namespace_returns_default(self) -> None:
        result = asyncio.run(InMemoryDistributedBackend.get_state("does_not_exist"))
        assert result.circuit_state == CircuitState.CLOSED.value
        assert result.failure_count == 0

    def test_set_and_get_roundtrip(self) -> None:
        s = _DistributedState(circuit_state=CircuitState.OPEN.value, failure_count=5)
        asyncio.run(InMemoryDistributedBackend.set_state("rt_ns", s))
        got = asyncio.run(InMemoryDistributedBackend.get_state("rt_ns"))
        assert got.circuit_state == CircuitState.OPEN.value

    def test_conservative_merge_escalates_to_open(self) -> None:
        """If one set is CLOSED and another OPEN, result is OPEN."""
        ns = "merge_ns"
        asyncio.run(InMemoryDistributedBackend.set_state(
            ns, _DistributedState(circuit_state=CircuitState.CLOSED.value, failure_count=0)
        ))
        asyncio.run(InMemoryDistributedBackend.set_state(
            ns, _DistributedState(circuit_state=CircuitState.OPEN.value, failure_count=2)
        ))
        got = asyncio.run(InMemoryDistributedBackend.get_state(ns))
        assert got.circuit_state == CircuitState.OPEN.value

    def test_clear_specific_namespace(self) -> None:
        asyncio.run(InMemoryDistributedBackend.set_state(
            "clr_ns", _DistributedState(circuit_state=CircuitState.OPEN.value, failure_count=1)
        ))
        InMemoryDistributedBackend.clear("clr_ns")
        got = asyncio.run(InMemoryDistributedBackend.get_state("clr_ns"))
        assert got.circuit_state == CircuitState.CLOSED.value

    def test_reset_clears_distributed_state(self) -> None:
        ns = "reset_ns"
        cfg = CircuitBreakerConfig(namespace=ns, pressure_threshold_ms=0.0001, consecutive_pressure_count=3)
        cb = DistributedCircuitBreaker(_make_guard(), cfg)
        for _ in range(3):
            asyncio.run(cb.verify_async(intent={"amount": 5}, state={}))
        asyncio.run(cb._sync_state())
        assert cb.state == CircuitState.OPEN

        cb.reset()
        asyncio.run(cb._sync_state())
        assert cb.state == CircuitState.CLOSED
