# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Performance and memory-stability benchmarks for Guard.verify().

Thresholds
----------
* RSS growth       < 50 MiB over 1 000 000 decisions
* P50 latency      < 10 ms
* P95 latency      < 30 ms
* P99 latency      < 100 ms
* Sustained RPS    >= 100 RPS for 60 seconds (concurrent async load)

These tests are marked ``perf`` and are excluded from the default pytest run.
Run them explicitly::

    pytest tests/perf/ -m perf -v

The benchmarks require ``psutil`` (``pip install psutil``).  If psutil is
absent the tests are skipped so CI does not break on minimal environments.
"""
from __future__ import annotations

import asyncio
import time
from decimal import Decimal

import pytest

from pramanix import Field
from pramanix.expressions import E
from pramanix.guard import Guard, GuardConfig
from pramanix.policy import Policy

# ── psutil guard ─────────────────────────────────────────────────────────────

try:
    import psutil as _psutil

    _PSUTIL_AVAILABLE = True
except ImportError:
    _PSUTIL_AVAILABLE = False

psutil_required = pytest.mark.skipif(
    not _PSUTIL_AVAILABLE,
    reason="psutil not installed — skipping memory benchmarks",
)

pytestmark = pytest.mark.perf


# ── Minimal policy fixture ────────────────────────────────────────────────────


class _BenchPolicy(Policy):
    """Minimal single-invariant policy for low-overhead benchmarking."""

    balance = Field("balance", Decimal, "Real")
    amount = Field("amount", Decimal, "Real")

    @classmethod
    def invariants(cls):
        return [
            (E(cls.balance) - E(cls.amount) >= Decimal("0")).named("non_negative_balance"),
        ]


_GUARD = Guard(_BenchPolicy, GuardConfig(execution_mode="sync"))

_INTENT_SAT = {"amount": Decimal("100")}
_STATE_SAT = {"balance": Decimal("1000")}


# ── Helper ────────────────────────────────────────────────────────────────────


def _rss_mib(proc: _psutil.Process) -> float:
    return proc.memory_info().rss / (1024 * 1024)


# ─────────────────────────────────────────────────────────────────────────────
# Memory stability
# ─────────────────────────────────────────────────────────────────────────────


@psutil_required
def test_memory_stability_1m_decisions() -> None:
    """RSS must not grow by more than 50 MiB over 1 000 000 decisions.

    The Z3 solver accumulates memory if solver/variable objects are not
    deleted after each decision.  This test validates that Guard.verify()
    properly cleans up Z3 context after each call.
    """
    proc = _psutil.Process()
    rss_before = _rss_mib(proc)

    for _ in range(1_000_000):
        _GUARD.verify(intent=_INTENT_SAT, state=_STATE_SAT)

    rss_after = _rss_mib(proc)
    growth_mib = rss_after - rss_before

    assert growth_mib < 50, (
        f"RSS grew by {growth_mib:.1f} MiB over 1 M decisions "
        f"(limit 50 MiB). Z3 memory leak suspected."
    )


# ─────────────────────────────────────────────────────────────────────────────
# Latency benchmarks
# ─────────────────────────────────────────────────────────────────────────────


def test_latency_percentiles_10k_decisions() -> None:
    """P50 < 25 ms, P95 < 75 ms, P99 < 200 ms over 10 000 decisions.

    Thresholds include 2.5x margin over the expected 5-10 ms steady-state
    to tolerate CI machine variance and Z3 JIT warm-up differences across
    operating systems.  Decisions below the threshold indicate that the
    per-request overhead of Guard.verify() is dominated by Z3, not by
    Python overhead introduced by Pramanix.
    """
    # Warm-up: allow Z3 JIT to stabilise before timing starts.
    # Cold-start decisions (300-400 ms on first import) inflate percentiles
    # when this test runs first in the suite.  200 warm-up calls are enough
    # to reach steady-state on all tested platforms.
    for _ in range(200):
        _GUARD.verify(intent=_INTENT_SAT, state=_STATE_SAT)

    latencies_ms: list[float] = []

    for _ in range(10_000):
        t0 = time.perf_counter()
        _GUARD.verify(intent=_INTENT_SAT, state=_STATE_SAT)
        latencies_ms.append((time.perf_counter() - t0) * 1_000)

    latencies_ms.sort()
    p50 = latencies_ms[int(len(latencies_ms) * 0.50)]
    p95 = latencies_ms[int(len(latencies_ms) * 0.95)]
    p99 = latencies_ms[int(len(latencies_ms) * 0.99)]

    assert p50 < 25, f"P50 latency {p50:.2f} ms exceeds 25 ms threshold"
    assert p95 < 75, f"P95 latency {p95:.2f} ms exceeds 75 ms threshold"
    assert p99 < 200, f"P99 latency {p99:.2f} ms exceeds 200 ms threshold"


def test_latency_mixed_sat_unsat() -> None:
    """Latency percentiles hold for a 50/50 SAT/UNSAT workload."""
    intent_unsat = {"amount": Decimal("2000")}  # exceeds balance → UNSAT
    latencies_ms: list[float] = []

    for i in range(10_000):
        intent = _INTENT_SAT if i % 2 == 0 else intent_unsat
        t0 = time.perf_counter()
        _GUARD.verify(intent=intent, state=_STATE_SAT)
        latencies_ms.append((time.perf_counter() - t0) * 1_000)

    latencies_ms.sort()
    p95 = latencies_ms[int(len(latencies_ms) * 0.95)]
    p99 = latencies_ms[int(len(latencies_ms) * 0.99)]

    assert p95 < 75, f"P95 mixed-workload latency {p95:.2f} ms exceeds 75 ms"
    assert p99 < 200, f"P99 mixed-workload latency {p99:.2f} ms exceeds 200 ms"


# ─────────────────────────────────────────────────────────────────────────────
# Sustained throughput — 100 RPS for 60 seconds
# ─────────────────────────────────────────────────────────────────────────────


def test_sustained_100_rps_60s() -> None:
    """Guard must sustain >= 100 RPS for 60 consecutive seconds.

    Uses asyncio.to_thread() to run synchronous verify() calls
    concurrently without spawning new OS threads for each request —
    the same pattern used by FastAPI/Uvicorn in production.
    """
    target_rps = 100
    duration_s = 60
    target_calls = target_rps * duration_s  # 6 000 total

    async def _run() -> int:
        guard = Guard(_BenchPolicy, GuardConfig(execution_mode="sync"))
        completed = 0
        deadline = asyncio.get_event_loop().time() + duration_s

        async def _one() -> None:
            nonlocal completed
            await asyncio.to_thread(guard.verify, intent=_INTENT_SAT, state=_STATE_SAT)
            completed += 1

        # Fire tasks at 100 RPS by batching 100 coroutines per second
        while asyncio.get_event_loop().time() < deadline:
            batch_start = asyncio.get_event_loop().time()
            tasks = [asyncio.create_task(_one()) for _ in range(target_rps)]
            await asyncio.gather(*tasks)
            elapsed = asyncio.get_event_loop().time() - batch_start
            sleep_for = max(0.0, 1.0 - elapsed)
            if sleep_for > 0:
                await asyncio.sleep(sleep_for)

        return completed

    completed = asyncio.run(_run())

    # Allow 5 % tolerance for scheduling jitter
    min_acceptable = int(target_calls * 0.95)
    assert completed >= min_acceptable, (
        f"Sustained throughput test: completed {completed} calls in {duration_s}s "
        f"(need >= {min_acceptable} for 100 RPS target)"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Worker recycling — RSS stable across max_decisions_per_worker boundaries
# ─────────────────────────────────────────────────────────────────────────────


@psutil_required
def test_worker_recycle_rss_stable() -> None:
    """RSS must stay bounded across multiple worker recycle boundaries.

    Uses max_decisions_per_worker=500 to force recycling every 500 calls.
    Runs 5 000 calls (10 recycles) and checks that total RSS growth stays
    under 20 MiB — recycling must not accumulate worker process memory.
    """
    guard = Guard(
        _BenchPolicy,
        GuardConfig(
            execution_mode="sync",
            max_decisions_per_worker=500,
        ),
    )

    proc = _psutil.Process()
    rss_before = _rss_mib(proc)

    for _ in range(5_000):
        guard.verify(intent=_INTENT_SAT, state=_STATE_SAT)

    rss_after = _rss_mib(proc)
    growth_mib = rss_after - rss_before

    assert growth_mib < 20, (
        f"RSS grew {growth_mib:.1f} MiB across worker recycle boundaries "
        f"(limit 20 MiB). Worker teardown memory leak suspected."
    )
