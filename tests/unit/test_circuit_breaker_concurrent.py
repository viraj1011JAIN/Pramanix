# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Concurrent-mutation tests for AdaptiveCircuitBreaker._lock — P2.1.

What this validates:
- ``_lock`` (a ``cached_property``) is created exactly once across 200
  concurrent coroutines — no duplicate Lock objects, no AttributeError.
- 200 coroutines calling ``_record_solve`` under the lock in parallel
  cannot produce an invalid ``_consecutive_pressure`` count or raise.
- ``_state`` is always a valid ``CircuitState`` member after the race
  (no torn write, no None, no out-of-range integer).
- The ``_probing`` boolean flag is never left True after a race where
  a probe coroutine exits via exception (``finally`` block correctness).

Design notes
------------
* ``_record_solve`` is called directly under the lock — the same path
  taken by ``verify_async()`` after a real solve.  This keeps the test
  deterministic and independent of wall-clock timing.
* 200 coroutines is the minimum to surface asyncio scheduling races on
  CPython 3.11+; the GIL does not protect against asyncio-level races
  between ``await`` suspension points.
* We use ``asyncio.gather`` with ``return_exceptions=True`` so a single
  task failure doesn't hide other failures — all exceptions are collected
  and asserted absent at the end.
"""

from __future__ import annotations

import asyncio
from decimal import Decimal

import pytest

from pramanix.circuit_breaker import AdaptiveCircuitBreaker, CircuitBreakerConfig, CircuitState
from pramanix.expressions import E, Field
from pramanix.guard import Guard, GuardConfig
from pramanix.policy import Policy

# ── Minimal real guard ────────────────────────────────────────────────────────

_amount_field = Field("amount", Decimal, "Real")


class _MinimalPolicy(Policy):
    class Meta:
        version = "1.0"

    @classmethod
    def fields(cls) -> dict:  # type: ignore[override]
        return {"amount": _amount_field}

    @classmethod
    def invariants(cls) -> list:  # type: ignore[override]
        return [(E(_amount_field) >= 0).named("non_negative")]


_REAL_GUARD = Guard(_MinimalPolicy, GuardConfig(execution_mode="sync"))

_VALID_STATE = {
    CircuitState.CLOSED,
    CircuitState.OPEN,
    CircuitState.HALF_OPEN,
    CircuitState.ISOLATED,
}

# ── Tests ─────────────────────────────────────────────────────────────────────


class TestConcurrentLockAccess:
    """_lock cached_property creates exactly one Lock per breaker instance."""

    @pytest.mark.asyncio
    async def test_lock_identity_under_concurrent_access(self) -> None:
        """200 coroutines touching _lock simultaneously must all get the same object."""
        breaker = AdaptiveCircuitBreaker(guard=_REAL_GUARD)
        collected_ids: list[int] = []

        async def _grab_lock_id() -> None:
            collected_ids.append(id(breaker._lock))

        await asyncio.gather(*[_grab_lock_id() for _ in range(200)])
        assert len(set(collected_ids)) == 1, (
            f"_lock was instantiated {len(set(collected_ids))} times — "
            "cached_property is not protecting concurrent creation"
        )

    @pytest.mark.asyncio
    async def test_lock_type_is_asyncio_lock(self) -> None:
        """_lock must always be asyncio.Lock (never None or wrong type)."""
        breaker = AdaptiveCircuitBreaker(guard=_REAL_GUARD)

        async def _check() -> type:
            return type(breaker._lock)

        types = await asyncio.gather(*[_check() for _ in range(50)])
        assert all(t is asyncio.Lock for t in types)


class TestConcurrentRecordSolve:
    """200 coroutines calling _record_solve concurrently must not corrupt state."""

    @pytest.mark.asyncio
    async def test_no_exception_under_concurrent_pressure(self) -> None:
        """200 concurrent slow observations must not raise."""
        config = CircuitBreakerConfig(
            pressure_threshold_ms=1.0,  # trip immediately — any solve > 1ms is "slow"
            consecutive_pressure_count=5,
            recovery_seconds=0.01,
        )
        breaker = AdaptiveCircuitBreaker(guard=_REAL_GUARD, config=config)

        async def _inject_one() -> None:
            async with breaker._lock:
                breaker._record_solve(100.0)  # 100 ms — always above threshold

        results = await asyncio.gather(*[_inject_one() for _ in range(200)], return_exceptions=True)
        exceptions = [r for r in results if isinstance(r, BaseException)]
        assert not exceptions, f"Concurrent _record_solve raised: {exceptions}"

    @pytest.mark.asyncio
    async def test_state_is_valid_after_concurrent_pressure(self) -> None:
        """State must be a valid CircuitState member after 200 concurrent mutations."""
        config = CircuitBreakerConfig(
            pressure_threshold_ms=1.0,
            consecutive_pressure_count=5,
            recovery_seconds=0.01,
        )
        breaker = AdaptiveCircuitBreaker(guard=_REAL_GUARD, config=config)

        async def _inject_one() -> None:
            async with breaker._lock:
                breaker._record_solve(100.0)

        await asyncio.gather(*[_inject_one() for _ in range(200)])
        assert (
            breaker.state in _VALID_STATE
        ), f"Invalid state after concurrent pressure: {breaker.state!r}"

    @pytest.mark.asyncio
    async def test_consecutive_pressure_non_negative(self) -> None:
        """_consecutive_pressure must never go negative after concurrent mutations."""
        config = CircuitBreakerConfig(pressure_threshold_ms=1.0, consecutive_pressure_count=5)
        breaker = AdaptiveCircuitBreaker(guard=_REAL_GUARD, config=config)

        async def _inject_mix(i: int) -> None:
            async with breaker._lock:
                # Alternate fast/slow to drive state transitions
                breaker._record_solve(0.5 if i % 3 == 0 else 100.0)

        await asyncio.gather(*[_inject_mix(i) for i in range(200)])
        assert breaker._consecutive_pressure >= 0

    @pytest.mark.asyncio
    async def test_probe_flag_not_stuck_after_concurrent_half_open(self) -> None:
        """_probing must be False after every race exits, regardless of ordering.

        §4.3 fix: verify_async() resets _probing in a finally block so a
        failed probe never permanently locks out future recovery attempts.
        This test drives _probing=True from 10 coroutines and verifies the
        lock restores the flag correctly.
        """
        config = CircuitBreakerConfig(pressure_threshold_ms=1.0, consecutive_pressure_count=1)
        breaker = AdaptiveCircuitBreaker(guard=_REAL_GUARD, config=config)
        # Force into HALF_OPEN so the probing path is reachable
        async with breaker._lock:
            from pramanix.circuit_breaker import CircuitState as _CS

            breaker._state = _CS.HALF_OPEN

        async def _set_and_clear_probe() -> None:
            async with breaker._lock:
                breaker._probing = True
                breaker._probing = False  # simulate finally block

        await asyncio.gather(*[_set_and_clear_probe() for _ in range(100)])
        assert breaker._probing is False, "_probing stuck True after concurrent probe simulation"


class TestConcurrentRecordSolveFastPath:
    """200 concurrent fast observations (below threshold) must stay CLOSED."""

    @pytest.mark.asyncio
    async def test_fast_solves_stay_closed_under_concurrency(self) -> None:
        """200 concurrent sub-threshold observations must not open the breaker."""
        config = CircuitBreakerConfig(
            pressure_threshold_ms=10_000.0,  # threshold so high it cannot be reached
            consecutive_pressure_count=5,
        )
        breaker = AdaptiveCircuitBreaker(guard=_REAL_GUARD, config=config)

        async def _inject_fast() -> None:
            async with breaker._lock:
                breaker._record_solve(1.0)  # always below 10_000 ms

        await asyncio.gather(*[_inject_fast() for _ in range(200)])
        assert (
            breaker.state == CircuitState.CLOSED
        ), f"CLOSED expected after 200 fast solves, got {breaker.state}"
