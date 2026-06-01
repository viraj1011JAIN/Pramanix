# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Phase 3 Item 9: Concurrency/runtime-path gap closure.

Three targeted concurrency scenarios that were not previously covered:

1. ArchiveKeySet — 50 threads simultaneously add / rotate / get:
   no data corruption, no deadlock, no torn reads.

2. WorkerPool pool-not-ready path — 20 threads simultaneously call
   submit_solve() on an unstarted pool: every caller gets a non-allowed
   Decision, and the pramanix_worker_pool_not_ready_total counter
   increments once per call.

3. AdaptiveCircuitBreaker — two real async coroutines race at the HALF_OPEN
   recovery window: exactly one probe fires (gets the guard decision),
   the other is immediately rejected with an OPEN decision.

Design notes
------------
* No MagicMock, no monkeypatching production code paths — failures and
  race conditions are reproduced by construction (unstarted pool, forced
  OPEN state, real concurrent threads/coroutines).
* Prometheus counter assertions capture the before-value and assert the
  delta, so tests are independent of run-order and suite-wide accumulation.
"""

from __future__ import annotations

import asyncio
import secrets
import threading
import time
from decimal import Decimal
from typing import Any

import pytest

from pramanix.audit.archiver import ArchiveKeySet
from pramanix.circuit_breaker import AdaptiveCircuitBreaker, CircuitBreakerConfig, CircuitState
from pramanix.expressions import E, Field
from pramanix.guard import Guard, GuardConfig
from pramanix.policy import Policy
from pramanix.worker import WorkerPool

# ── Minimal real policy / guard ───────────────────────────────────────────────

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

# ── ArchiveKeySet: concurrent thread-safety ───────────────────────────────────


class TestArchiveKeySetConcurrentSafety:
    """ArchiveKeySet internal Lock must protect all mutations under concurrent load."""

    def test_concurrent_add_all_keys_readable(self) -> None:
        """50 threads simultaneously adding distinct keys: all readable with correct bytes."""
        key_set = ArchiveKeySet()
        n = 50
        keys_added: dict[str, bytes] = {f"key-{i:03d}": secrets.token_bytes(32) for i in range(n)}

        errors: list[Exception] = []
        error_lock = threading.Lock()

        def _add(key_id: str, key: bytes) -> None:
            try:
                key_set.add(key_id, key)
            except Exception as exc:
                with error_lock:
                    errors.append(exc)

        threads = [threading.Thread(target=_add, args=(kid, k)) for kid, k in keys_added.items()]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Exceptions during concurrent add: {errors}"
        for kid, expected in keys_added.items():
            assert key_set.get(kid) == expected, f"Key {kid!r} corrupted after concurrent add"

    def test_concurrent_rotate_no_deadlock_valid_active_key(self) -> None:
        """10 threads simultaneously rotating: no deadlock, active key valid after all done."""
        key_set = ArchiveKeySet()
        initial_key = secrets.token_bytes(32)
        key_set.add("initial", initial_key)
        key_set.set_active("initial")

        errors: list[Exception] = []
        error_lock = threading.Lock()

        def _rotate(i: int) -> None:
            try:
                new_id = f"rotated-{i:02d}"
                new_key = secrets.token_bytes(32)
                key_set.add(new_id, new_key)
                key_set.rotate(new_id, new_key)
            except Exception as exc:
                with error_lock:
                    errors.append(exc)

        threads = [threading.Thread(target=_rotate, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Exceptions during concurrent rotate: {errors}"
        active_id = key_set.active_key_id  # must not raise
        _ = key_set.get(active_id)  # active key must be retrievable

    def test_concurrent_readers_see_consistent_state(self) -> None:
        """Readers and writers interleaved: pre-seeded key always readable, no torn read."""
        key_set = ArchiveKeySet()
        seed_id = "seed"
        seed_key = secrets.token_bytes(32)
        key_set.add(seed_id, seed_key)

        errors: list[Exception] = []
        error_lock = threading.Lock()

        def _writer(i: int) -> None:
            try:
                key_set.add(f"writer-{i:02d}", secrets.token_bytes(32))
            except Exception as exc:
                with error_lock:
                    errors.append(exc)

        def _reader() -> None:
            try:
                got = key_set.get(seed_id)
                if got != seed_key:
                    with error_lock:
                        errors.append(
                            AssertionError("Torn read: seed key changed under concurrent write")
                        )
            except Exception as exc:
                with error_lock:
                    errors.append(exc)

        threads = [threading.Thread(target=_writer, args=(i,)) for i in range(20)] + [
            threading.Thread(target=_reader) for _ in range(20)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Errors during concurrent read/write: {errors}"


# ── WorkerPool: pool-not-ready concurrent path ───────────────────────────────


class TestWorkerPoolNotReadyConcurrent:
    """submit_solve() on an unstarted pool must be safe under concurrent load."""

    def test_all_threads_get_error_decision(self) -> None:
        """20 concurrent threads hitting an unstarted pool all receive error decisions."""
        pool = WorkerPool(
            mode="async-thread",
            max_workers=2,
            max_decisions_per_worker=100,
            warmup=False,
        )
        # Pool is not started — _alive == False

        results: list[Any] = []
        lock = threading.Lock()

        def _call() -> None:
            decision = pool.submit_solve(_MinimalPolicy, {"amount": Decimal("1.00")}, 5000)
            with lock:
                results.append(decision)

        threads = [threading.Thread(target=_call) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(results) == 20, f"Expected 20 results, got {len(results)}"
        for d in results:
            assert not d.allowed, f"Unstarted pool returned allowed=True: {d!r}"
            assert d.explanation

    def test_not_ready_counter_increments_per_rejection(self) -> None:
        """pramanix_worker_pool_not_ready_total increments once per pool-not-ready rejection."""
        pytest.importorskip("prometheus_client")
        from prometheus_client import REGISTRY

        def _read() -> float:
            for metric in REGISTRY.collect():
                # prometheus_client strips the _total suffix from metric.name
                if metric.name in (
                    "pramanix_worker_pool_not_ready",
                    "pramanix_worker_pool_not_ready_total",
                ):
                    for sample in metric.samples:
                        if sample.name.endswith("_total") and sample.labels == {}:
                            return sample.value
            return 0.0

        pool = WorkerPool(
            mode="async-thread",
            max_workers=2,
            max_decisions_per_worker=100,
            warmup=False,
        )
        before = _read()
        n = 10

        threads = [
            threading.Thread(
                target=pool.submit_solve,
                args=(_MinimalPolicy, {"amount": Decimal("1.00")}, 5000),
            )
            for _ in range(n)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        after = _read()
        assert after >= before + n, (
            f"pramanix_worker_pool_not_ready_total: expected +{n} increments "
            f"(before={before}, after={after}, delta={after - before})"
        )


# ── Circuit breaker: concurrent verify_async at HALF_OPEN recovery ────────────


class TestCircuitBreakerConcurrentHalfOpen:
    """Two real async coroutines racing at HALF_OPEN recovery: one probe, one rejection."""

    @pytest.mark.asyncio
    async def test_exactly_one_probe_fires_other_gets_open(self) -> None:
        """Of two concurrent verify_async() calls at recovery time, exactly one probes."""
        config = CircuitBreakerConfig(
            pressure_threshold_ms=10_000.0,  # threshold so high the probe will never fail
            consecutive_pressure_count=100,
            recovery_seconds=0.0,
        )
        breaker = AdaptiveCircuitBreaker(guard=_REAL_GUARD, config=config)

        async with breaker._lock:
            breaker._state = CircuitState.OPEN
            breaker._last_transition = time.monotonic() - 5.0  # well past recovery window

        _intent = {"amount": Decimal("1.00")}

        decisions = await asyncio.gather(
            breaker.verify_async(intent=_intent, state={"state_version": "1.0"}),
            breaker.verify_async(intent=_intent, state={"state_version": "1.0"}),
            return_exceptions=True,
        )

        exceptions = [r for r in decisions if isinstance(r, BaseException)]
        assert not exceptions, f"Unexpected exceptions from concurrent verify: {exceptions}"

        allowed = [d for d in decisions if d.allowed]
        blocked = [d for d in decisions if not d.allowed]

        assert len(allowed) == 1, (
            f"Expected exactly 1 probe (allowed=True), got {len(allowed)}. "
            f"Decisions: {[(d.allowed, d.explanation) for d in decisions]}"
        )
        assert len(blocked) == 1, (
            f"Expected exactly 1 rejection (allowed=False), got {len(blocked)}. "
            f"Decisions: {[(d.allowed, d.explanation) for d in decisions]}"
        )
        # The probe succeeded (amount=1.00 >= 0) so the breaker must have recovered.
        assert (
            breaker.state == CircuitState.CLOSED
        ), f"Expected CLOSED after successful probe, got {breaker.state!r}"

    @pytest.mark.asyncio
    async def test_probing_flag_reset_after_successful_probe(self) -> None:
        """_probing must be False after a probe that succeeds."""
        config = CircuitBreakerConfig(
            pressure_threshold_ms=10_000.0,
            recovery_seconds=0.0,
        )
        breaker = AdaptiveCircuitBreaker(guard=_REAL_GUARD, config=config)

        async with breaker._lock:
            breaker._state = CircuitState.OPEN
            breaker._last_transition = time.monotonic() - 5.0

        await breaker.verify_async(intent={"amount": Decimal("1.00")}, state={"state_version": "1.0"})

        assert not breaker._probing, "_probing must be False after successful probe"
        assert breaker.state == CircuitState.CLOSED

    @pytest.mark.asyncio
    async def test_probing_flag_reset_after_failed_probe(self) -> None:
        """_probing must be False after a probe that fails (slow solve → OPEN again)."""
        config = CircuitBreakerConfig(
            # pressure_threshold_ms=0.0 means any solve latency (> 0 ms) is "slow"
            pressure_threshold_ms=0.0,
            consecutive_pressure_count=1,
            recovery_seconds=0.0,
        )
        breaker = AdaptiveCircuitBreaker(guard=_REAL_GUARD, config=config)

        async with breaker._lock:
            breaker._state = CircuitState.OPEN
            breaker._last_transition = time.monotonic() - 5.0

        await breaker.verify_async(intent={"amount": Decimal("1.00")}, state={"state_version": "1.0"})

        # Probe failed (latency > 0 > 0.0 ms threshold) → breaker returned to OPEN.
        # But _probing must still have been reset by the finally block.
        assert not breaker._probing, "_probing must be False even after a failed probe"

    @pytest.mark.asyncio
    async def test_second_concurrent_call_reason_mentions_circuit(self) -> None:
        """The rejected concurrent call's reason must mention circuit state."""
        config = CircuitBreakerConfig(
            pressure_threshold_ms=10_000.0,
            recovery_seconds=0.0,
        )
        breaker = AdaptiveCircuitBreaker(guard=_REAL_GUARD, config=config)

        async with breaker._lock:
            breaker._state = CircuitState.OPEN
            breaker._last_transition = time.monotonic() - 5.0

        decisions = await asyncio.gather(
            breaker.verify_async(intent={"amount": Decimal("1.00")}, state={"state_version": "1.0"}),
            breaker.verify_async(intent={"amount": Decimal("1.00")}, state={"state_version": "1.0"}),
            return_exceptions=True,
        )
        blocked = [d for d in decisions if not d.allowed and not isinstance(d, BaseException)]
        assert blocked, "Expected at least one blocked decision"
        reason_lower = (blocked[0].explanation or "").lower()
        assert (
            "circuit" in reason_lower or "open" in reason_lower or "recovery" in reason_lower
        ), f"Rejected decision must describe circuit state, got: {blocked[0].explanation!r}"
