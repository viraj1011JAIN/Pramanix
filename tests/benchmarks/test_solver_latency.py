# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Phase 6 Item 17: Z3 solver latency and Guard throughput benchmarks.

These tests enforce timing SLOs for the production hot path.  They run in
the standard pytest suite (no external benchmark library required) and fail if
latency exceeds the specified budgets.

Timing budgets (conservative — tuned for a single-core CI runner):
  - First verify() call:      ≤ 3 000 ms  (includes Z3 JIT compilation)
  - Steady-state verify():    ≤  500 ms   (JIT-warmed, simple policy)
  - 100-call throughput:      ≤ 30 000 ms (30 s total, 300 ms/call avg)

These are REGRESSION bounds, not optimality targets.  A significant increase
in latency (e.g. 5× slower than baseline) should block the build so
performance regressions are caught in CI rather than in production.
"""

from __future__ import annotations

import statistics
import time
from decimal import Decimal

import pytest

from pramanix.expressions import E, Field
from pramanix.guard import Guard, GuardConfig
from pramanix.policy import Policy

# ── Minimal policy for benchmarking ──────────────────────────────────────────

_amount = Field("amount", Decimal, "Real")
_limit = Field("limit", Decimal, "Real")
_balance = Field("balance", Decimal, "Real")


class _BenchPolicy(Policy):
    """Three-invariant policy — representative of a simple financial guard."""

    class Meta:
        version = "1.0"

    @classmethod
    def fields(cls) -> dict:  # type: ignore[override]
        return {"amount": _amount, "limit": _limit, "balance": _balance}

    @classmethod
    def invariants(cls) -> list:  # type: ignore[override]
        return [
            (E(_amount) >= 0).named("non_negative").explain("Amount must be >= 0"),
            (E(_amount) <= E(_limit)).named("within_limit").explain("Amount must not exceed limit"),
            (E(_balance) - E(_amount) >= 0)
            .named("sufficient_balance")
            .explain("Balance must cover the transfer"),
        ]


@pytest.fixture(scope="module")
def bench_guard() -> Guard:
    """Module-scoped Guard — created once per test module to amortize setup."""
    return Guard(_BenchPolicy, GuardConfig(execution_mode="sync", audit_sinks=[]))


_ALLOW_INTENT = {"amount": Decimal("100.00"), "limit": Decimal("1000.00")}
_ALLOW_STATE = {
    "balance": Decimal("5000.00"),
    "state_version": "1.0",
}
_BLOCK_INTENT = {"amount": Decimal("9999.00"), "limit": Decimal("500.00")}
_BLOCK_STATE = {
    "balance": Decimal("100.00"),
    "state_version": "1.0",
}


pytestmark = pytest.mark.benchmark

# ── First-call latency (cold Z3) ──────────────────────────────────────────────


class TestFirstCallLatency:
    """First verify() call may be slow due to Z3 JIT — must still be ≤ 3 000 ms."""

    BUDGET_MS = 3_000.0

    def test_first_allow_within_budget(self) -> None:
        fresh_guard = Guard(_BenchPolicy, GuardConfig(execution_mode="sync", audit_sinks=[]))
        t0 = time.perf_counter()
        decision = fresh_guard.verify(intent=_ALLOW_INTENT, state=_ALLOW_STATE)
        elapsed_ms = (time.perf_counter() - t0) * 1000

        assert decision.allowed, f"Expected ALLOW, got: {decision.explanation}"
        assert elapsed_ms <= self.BUDGET_MS, (
            f"First verify() call took {elapsed_ms:.1f} ms — budget is {self.BUDGET_MS:.0f} ms. "
            "Z3 JIT compilation may be unusually slow; check build environment."
        )

    def test_first_block_within_budget(self) -> None:
        fresh_guard = Guard(_BenchPolicy, GuardConfig(execution_mode="sync", audit_sinks=[]))
        t0 = time.perf_counter()
        decision = fresh_guard.verify(intent=_BLOCK_INTENT, state=_BLOCK_STATE)
        elapsed_ms = (time.perf_counter() - t0) * 1000

        assert not decision.allowed
        assert (
            elapsed_ms <= self.BUDGET_MS
        ), f"First verify() BLOCK call took {elapsed_ms:.1f} ms — budget is {self.BUDGET_MS:.0f} ms."


# ── Steady-state latency (warm Z3) ────────────────────────────────────────────


class TestSteadyStateLatency:
    """After warmup, each verify() call must complete ≤ 500 ms (p99)."""

    WARMUP_CALLS = 3
    MEASURE_CALLS = 10
    P99_BUDGET_MS = 500.0

    def test_allow_p99_within_budget(self, bench_guard: Guard) -> None:
        for _ in range(self.WARMUP_CALLS):
            bench_guard.verify(intent=_ALLOW_INTENT, state=_ALLOW_STATE)

        latencies: list[float] = []
        for _ in range(self.MEASURE_CALLS):
            t0 = time.perf_counter()
            bench_guard.verify(intent=_ALLOW_INTENT, state=_ALLOW_STATE)
            latencies.append((time.perf_counter() - t0) * 1000)

        p99 = sorted(latencies)[int(0.99 * len(latencies))]
        mean_ms = statistics.mean(latencies)
        assert p99 <= self.P99_BUDGET_MS, (
            f"verify() ALLOW p99={p99:.1f} ms exceeds budget {self.P99_BUDGET_MS:.0f} ms. "
            f"Mean={mean_ms:.1f} ms, all={[f'{x:.1f}' for x in latencies]}"
        )

    def test_block_p99_within_budget(self, bench_guard: Guard) -> None:
        for _ in range(self.WARMUP_CALLS):
            bench_guard.verify(intent=_BLOCK_INTENT, state=_BLOCK_STATE)

        latencies: list[float] = []
        for _ in range(self.MEASURE_CALLS):
            t0 = time.perf_counter()
            bench_guard.verify(intent=_BLOCK_INTENT, state=_BLOCK_STATE)
            latencies.append((time.perf_counter() - t0) * 1000)

        p99 = sorted(latencies)[int(0.99 * len(latencies))]
        assert (
            p99 <= self.P99_BUDGET_MS
        ), f"verify() BLOCK p99={p99:.1f} ms exceeds budget {self.P99_BUDGET_MS:.0f} ms."


# ── Throughput: 100 calls ─────────────────────────────────────────────────────


class TestThroughput:
    """100 sequential verify() calls must complete within 30 000 ms total."""

    N_CALLS = 100
    TOTAL_BUDGET_MS = 30_000.0

    def test_100_allow_calls_within_budget(self, bench_guard: Guard) -> None:
        bench_guard.verify(intent=_ALLOW_INTENT, state=_ALLOW_STATE)  # warmup

        t0 = time.perf_counter()
        for _ in range(self.N_CALLS):
            decision = bench_guard.verify(intent=_ALLOW_INTENT, state=_ALLOW_STATE)
            assert decision.allowed
        total_ms = (time.perf_counter() - t0) * 1000

        avg_ms = total_ms / self.N_CALLS
        assert total_ms <= self.TOTAL_BUDGET_MS, (
            f"{self.N_CALLS} verify() calls took {total_ms:.0f} ms total "
            f"(avg {avg_ms:.1f} ms/call) — budget is {self.TOTAL_BUDGET_MS:.0f} ms."
        )

    def test_mixed_allow_block_throughput(self, bench_guard: Guard) -> None:
        """Alternating ALLOW/BLOCK calls: throughput must hold."""
        bench_guard.verify(intent=_ALLOW_INTENT, state=_ALLOW_STATE)  # warmup

        t0 = time.perf_counter()
        for i in range(self.N_CALLS):
            if i % 2 == 0:
                bench_guard.verify(intent=_ALLOW_INTENT, state=_ALLOW_STATE)
            else:
                bench_guard.verify(intent=_BLOCK_INTENT, state=_BLOCK_STATE)
        total_ms = (time.perf_counter() - t0) * 1000

        assert (
            total_ms <= self.TOTAL_BUDGET_MS
        ), f"Mixed 100-call batch took {total_ms:.0f} ms — budget {self.TOTAL_BUDGET_MS:.0f} ms."


# ── Latency reporting (always passes — for CI artifact logging) ───────────────


class TestLatencyReport:
    """Measure and print latency distribution — never fails, useful for CI artifacts."""

    def test_latency_distribution_report(
        self, bench_guard: Guard, capsys: pytest.CaptureFixture
    ) -> None:
        """Print mean/p50/p95/p99 latencies for CI trend analysis."""
        n = 20
        for _ in range(3):
            bench_guard.verify(intent=_ALLOW_INTENT, state=_ALLOW_STATE)  # warmup

        latencies: list[float] = []
        for _ in range(n):
            t0 = time.perf_counter()
            bench_guard.verify(intent=_ALLOW_INTENT, state=_ALLOW_STATE)
            latencies.append((time.perf_counter() - t0) * 1000)

        latencies_sorted = sorted(latencies)
        p50 = latencies_sorted[int(0.50 * n)]
        p95 = latencies_sorted[int(0.95 * n)]
        p99 = latencies_sorted[int(0.99 * n)]
        mean_ms = statistics.mean(latencies)

        print(
            f"\n[BENCH] Guard.verify() latency ({n} calls, sync mode): "
            f"mean={mean_ms:.1f}ms  p50={p50:.1f}ms  p95={p95:.1f}ms  p99={p99:.1f}ms"
        )
