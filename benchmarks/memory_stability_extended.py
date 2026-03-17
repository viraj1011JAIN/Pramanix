#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Memory stability benchmark — extended run.

Verifies that Guard.verify() does not accumulate Z3 memory over time.

Usage:
    python benchmarks/memory_stability_extended.py
    python benchmarks/memory_stability_extended.py --n 10000
"""
from __future__ import annotations

import gc
import json
import sys
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

try:
    import tracemalloc
    HAS_TRACEMALLOC = True
except ImportError:
    HAS_TRACEMALLOC = False

from pramanix import E, Field, Guard, GuardConfig, Policy

_amount  = Field("amount",  Decimal, "Real")
_balance = Field("balance", Decimal, "Real")


class MemPolicy(Policy):
    class Meta:
        version = "1.0"

    @classmethod
    def fields(cls):
        return {"amount": _amount, "balance": _balance}

    @classmethod
    def invariants(cls):
        return [
            ((E(_balance) - E(_amount)) >= Decimal("0"))
                .named("sufficient_balance").explain("Insufficient balance"),
        ]


def run_memory_benchmark(n: int = 5000) -> dict:
    guard = Guard(MemPolicy, GuardConfig(execution_mode="sync"))

    intent = {"amount": Decimal("100")}
    state  = {"balance": Decimal("5000"), "state_version": "1.0"}

    # Warmup + force GC
    for _ in range(10):
        guard.verify(intent=intent, state=state)
    gc.collect()

    if HAS_TRACEMALLOC:
        tracemalloc.start()

    baseline_size = 0
    final_size = 0

    checkpoint_interval = n // 10
    checkpoints = []

    for i in range(n):
        guard.verify(intent=intent, state=state)
        if i % checkpoint_interval == 0:
            gc.collect()
            if HAS_TRACEMALLOC:
                current, peak = tracemalloc.get_traced_memory()
                checkpoints.append(
                    {"iteration": i, "current_kb": current / 1024}
                )
                if i == 0:
                    baseline_size = current

    gc.collect()
    if HAS_TRACEMALLOC:
        final_mem, peak_mem = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        final_size = final_mem
        growth_kb = (final_size - baseline_size) / 1024
    else:
        growth_kb = None

    results = {
        "n": n,
        "memory_growth_kb": (
            round(growth_kb, 2) if growth_kb is not None else None
        ),
        "checkpoints": checkpoints,
        "stable": growth_kb is None or growth_kb < 1024,  # < 1MB = stable
    }
    return results


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--n", type=int, default=5000)
    args = parser.parse_args()

    print(f"Memory stability benchmark ({args.n} iterations)...")
    results = run_memory_benchmark(n=args.n)

    if results["memory_growth_kb"] is not None:
        print(f"Memory growth: {results['memory_growth_kb']:.1f} KB")
        print(
            f"Result: {'STABLE' if results['stable'] else 'LEAK DETECTED'}"
        )
    else:
        print("tracemalloc not available — skipped memory tracking")

    out_path = (
        Path(__file__).parent / "results" / "memory_results.json"
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"Results saved to {out_path}")


if __name__ == "__main__":
    main()
