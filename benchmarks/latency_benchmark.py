#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Pramanix latency benchmark — API mode.

Produces machine-readable results in benchmarks/results/latency_results.json.

Targets (Phase 10):
    API Mode: P50 < 5ms, P95 < 10ms, P99 < 15ms

Usage:
    python benchmarks/latency_benchmark.py
    python benchmarks/latency_benchmark.py --n 1000
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from pramanix import E, Field, Guard, GuardConfig, Policy

_amount  = Field("amount",    Decimal, "Real")
_balance = Field("balance",   Decimal, "Real")
_frozen  = Field("is_frozen", bool,    "Bool")
_limit   = Field("daily_limit", Decimal, "Real")
_risk    = Field("risk_score",  float,  "Real")


class BenchmarkPolicy(Policy):
    class Meta:
        version = "1.0"

    @classmethod
    def fields(cls):
        return {
            "amount": _amount, "balance": _balance, "is_frozen": _frozen,
            "daily_limit": _limit, "risk_score": _risk,
        }

    @classmethod
    def invariants(cls):
        return [
            ((E(_balance) - E(_amount)) >= Decimal("0"))
                .named("sufficient_balance").explain("Insufficient balance"),
            (E(_frozen) == False)  # noqa: E712
                .named("account_not_frozen").explain("Account frozen"),
            (E(_amount) <= E(_limit))
                .named("within_daily_limit").explain("Exceeds daily limit"),
            (E(_risk) <= 0.8)
                .named("acceptable_risk").explain("Risk too high"),
            (E(_amount) > Decimal("0"))
                .named("positive_amount").explain("Must be positive"),
        ]


def run_benchmark(n: int = 1000) -> dict:
    guard = Guard(BenchmarkPolicy, GuardConfig(execution_mode="sync"))

    intent = {"amount": Decimal("100")}
    state = {
        "balance": Decimal("5000"), "is_frozen": False,
        "daily_limit": Decimal("10000"), "risk_score": 0.3,
        "state_version": "1.0",
    }

    # Warmup
    for _ in range(10):
        guard.verify(intent=intent, state=state)

    # Benchmark
    latencies_ms = []
    for _ in range(n):
        t0 = time.perf_counter()
        guard.verify(intent=intent, state=state)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        latencies_ms.append(elapsed_ms)

    latencies_ms.sort()
    p50  = latencies_ms[int(n * 0.50)]
    p95  = latencies_ms[int(n * 0.95)]
    p99  = latencies_ms[int(n * 0.99)]
    mean = statistics.mean(latencies_ms)

    results = {
        "mode": "api",
        "n": n,
        "p50_ms": round(p50, 3),
        "p95_ms": round(p95, 3),
        "p99_ms": round(p99, 3),
        "mean_ms": round(mean, 3),
        "targets": {
            "p50_target_ms": 5.0,
            "p95_target_ms": 10.0,
            "p99_target_ms": 15.0,
        },
        "passed": p50 < 5.0 and p95 < 10.0 and p99 < 15.0,
    }
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Pramanix latency benchmark")
    parser.add_argument("--n", type=int, default=1000)
    args = parser.parse_args()

    results = run_benchmark(n=args.n)

    print(f"\nAPI Mode Latency Benchmark ({results['n']} iterations)")
    print(f"  P50:  {results['p50_ms']:.2f}ms  (target: <5ms)")
    print(f"  P95:  {results['p95_ms']:.2f}ms  (target: <10ms)")
    print(f"  P99:  {results['p99_ms']:.2f}ms  (target: <15ms)")
    print(f"  Mean: {results['mean_ms']:.2f}ms")
    print(f"\nRESULT: {'PASS' if results['passed'] else 'FAIL'}")

    out_path = Path(__file__).parent / "results" / "latency_results.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"Results saved to {out_path}")


if __name__ == "__main__":
    main()
