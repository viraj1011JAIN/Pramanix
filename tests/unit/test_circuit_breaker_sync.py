# SPDX-License-Identifier: AGPL-3.0-only
# Phase C-4: Tests for AdaptiveCircuitBreaker.verify_sync()
"""Verifies synchronous circuit breaker interface works from non-async contexts."""
from __future__ import annotations

import asyncio

import pytest

from pramanix import Guard, GuardConfig
from pramanix.circuit_breaker import AdaptiveCircuitBreaker, CircuitBreakerConfig
from pramanix.exceptions import ConfigurationError
from pramanix.expressions import E, Field
from pramanix.policy import Policy


class _SimplePolicy(Policy):
    amount = Field("amount", int, "Int")

    @classmethod
    def invariants(cls):
        return [(E(cls.amount) >= 0).named("non_negative")]


def _make_breaker() -> AdaptiveCircuitBreaker:
    guard = Guard(_SimplePolicy, config=GuardConfig(execution_mode="async-thread"))
    return AdaptiveCircuitBreaker(guard, CircuitBreakerConfig())


class TestCircuitBreakerSync:
    """verify_sync works from synchronous contexts."""

    def test_verify_sync_allow_returns_decision(self) -> None:
        breaker = _make_breaker()
        d = breaker.verify_sync(intent={"amount": 10}, state={})
        assert d.allowed

    def test_verify_sync_block_returns_decision(self) -> None:
        breaker = _make_breaker()
        d = breaker.verify_sync(intent={"amount": -1}, state={})
        assert not d.allowed

    def test_verify_sync_returns_decision_type(self) -> None:
        from pramanix.decision import Decision

        breaker = _make_breaker()
        d = breaker.verify_sync(intent={"amount": 5}, state={})
        assert isinstance(d, Decision)

    def test_verify_sync_from_inside_event_loop_raises(self) -> None:
        breaker = _make_breaker()

        async def _inner() -> None:
            with pytest.raises(ConfigurationError, match="verify_async"):
                breaker.verify_sync(intent={"amount": 5}, state={})

        asyncio.run(_inner())

    def test_verify_sync_error_message_mentions_verify_async(self) -> None:
        breaker = _make_breaker()

        async def _inner() -> None:
            with pytest.raises(ConfigurationError, match="verify_async"):
                breaker.verify_sync(intent={"amount": 5}, state={})

        asyncio.run(_inner())

    def test_verify_sync_multiple_calls_succeed(self) -> None:
        breaker = _make_breaker()
        for i in range(5):
            d = breaker.verify_sync(intent={"amount": i}, state={})
            assert d.allowed

    def test_verify_sync_state_persists_across_calls(self) -> None:
        breaker = _make_breaker()
        d1 = breaker.verify_sync(intent={"amount": 10}, state={})
        d2 = breaker.verify_sync(intent={"amount": 20}, state={})
        assert d1.allowed
        assert d2.allowed
        assert breaker.state.value == "closed"
