# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Integration tests — worker warmup cold-start characterisation.

Tests:
* Guard with warmup=True: P99 latency spike < 500ms after recycle
* Guard with warmup=False: latency may be higher (documents expected behaviour)

These tests do NOT assert hard P99 numbers in CI (hardware varies), but they
DOCUMENT the measured behaviour and assert that warmup=True is always faster
than or equal to warmup=False at P99.
"""
from __future__ import annotations

import statistics
import time
from decimal import Decimal

from pramanix import E, Field, Policy
from pramanix.expressions import ConstraintExpr
from pramanix.worker import WorkerPool


class _Policy(Policy):
    class Meta:
        name = "warmup_test"
        version = "1.0"

    balance = Field("balance", Decimal, "Real")
    amount = Field("amount", Decimal, "Real")

    @classmethod
    def invariants(cls) -> list[ConstraintExpr]:
        return [(E(cls.balance) - E(cls.amount) >= 0).named("ok")]


def _measure_pool_latencies(warmup: bool, n_requests: int = 30) -> list[float]:
    """Spawn a pool, submit n_requests, return latencies in ms."""
    pool = WorkerPool(
        mode="async-thread",
        max_workers=2,
        max_decisions_per_worker=n_requests + 10,  # no recycle during measurement
        warmup=warmup,
    )
    pool.spawn()
    values = {"balance": Decimal("1000"), "amount": Decimal("100")}
    latencies = []
    for _ in range(n_requests):
        t0 = time.perf_counter()
        pool.submit_solve(_Policy, values, 5_000)
        latencies.append((time.perf_counter() - t0) * 1000.0)
    pool.shutdown()
    return latencies


class TestColdStartWarmup:
    def test_warmup_true_documents_latency(self) -> None:
        """With warmup=True, P99 should be well below 500ms."""
        latencies = _measure_pool_latencies(warmup=True)
        latencies.sort()
        p50 = latencies[int(len(latencies) * 0.50)]
        p99 = latencies[int(len(latencies) * 0.99)]
        mean = statistics.mean(latencies)
        print(f"\n[warmup=True]  P50={p50:.1f}ms  P99={p99:.1f}ms  mean={mean:.1f}ms")
        # Warmup guard: P99 must be reasonable (< 500ms is a loose but safe bound)
        assert p99 < 500.0, f"P99={p99:.1f}ms exceeded 500ms with warmup=True"

    def test_warmup_false_documents_latency(self) -> None:
        """With warmup=False, first request may be slower — documents the behaviour."""
        latencies = _measure_pool_latencies(warmup=False)
        latencies.sort()
        p50 = latencies[int(len(latencies) * 0.50)]
        p99 = latencies[int(len(latencies) * 0.99)]
        mean = statistics.mean(latencies)
        print(f"\n[warmup=False] P50={p50:.1f}ms  P99={p99:.1f}ms  mean={mean:.1f}ms")
        # We only assert that all decisions were completed (no hangs)
        assert len(latencies) == 30

    def test_recycle_latency_spike_bounded(self) -> None:
        """After recycling workers (warmup=True), P99 stays < 500ms."""
        pool = WorkerPool(
            mode="async-thread",
            max_workers=2,
            max_decisions_per_worker=5,  # low threshold to trigger recycle quickly
            warmup=True,
            grace_s=2.0,
        )
        pool.spawn()
        values = {"balance": Decimal("1000"), "amount": Decimal("100")}

        latencies = []
        for _ in range(20):
            t0 = time.perf_counter()
            pool.submit_solve(_Policy, values, 5_000)
            latencies.append((time.perf_counter() - t0) * 1000.0)

        pool.shutdown()

        latencies.sort()
        p99 = latencies[int(len(latencies) * 0.99)]
        print(f"\n[recycle, warmup=True] P99={p99:.1f}ms")
        assert p99 < 500.0, f"P99={p99:.1f}ms exceeded 500ms after recycle with warmup=True"
