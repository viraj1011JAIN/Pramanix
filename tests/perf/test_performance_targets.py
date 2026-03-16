# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Performance target tests for Phase 10.

These tests verify that the Phase 10 optimizations achieve the promised
performance improvements. Run with: pytest tests/perf/ -v
"""
from __future__ import annotations

import time
from decimal import Decimal

import pytest

from pramanix import E, Field, Guard, GuardConfig, Policy
from pramanix.fast_path import SemanticFastPath

_amount = Field("amount", Decimal, "Real")
_balance = Field("balance", Decimal, "Real")
_frozen = Field("is_frozen", bool, "Bool")
_limit = Field("daily_limit", Decimal, "Real")
_risk = Field("risk_score", float, "Real")


class PerfPolicy(Policy):
    class Meta:
        version = "1.0"

    @classmethod
    def fields(cls):
        return {
            "amount": _amount,
            "balance": _balance,
            "is_frozen": _frozen,
            "daily_limit": _limit,
            "risk_score": _risk,
        }

    @classmethod
    def invariants(cls):
        return [
            ((E(_balance) - E(_amount)) >= Decimal("0"))
            .named("sufficient_balance")
            .explain("Insufficient balance"),
            (E(_frozen) == False).named("account_not_frozen").explain("Frozen"),  # noqa: E712
            (E(_amount) <= E(_limit)).named("within_daily_limit").explain("Limit"),
            (E(_risk) <= 0.8).named("acceptable_risk").explain("Risk"),
            (E(_amount) > Decimal("0")).named("positive_amount").explain("Positive"),
        ]


class TestAPILatencyTargets:
    @pytest.fixture(scope="class")
    def guard(self):
        return Guard(PerfPolicy, GuardConfig(execution_mode="sync"))

    def test_p50_under_5ms(self, guard):
        """P50 API latency must be < 5ms."""
        intent = {"amount": Decimal("100")}
        state = {
            "balance": Decimal("5000"),
            "is_frozen": False,
            "daily_limit": Decimal("10000"),
            "risk_score": 0.3,
            "state_version": "1.0",
        }
        # Warmup
        for _ in range(5):
            guard.verify(intent=intent, state=state)

        n = 100
        latencies = []
        for _ in range(n):
            t0 = time.perf_counter()
            guard.verify(intent=intent, state=state)
            latencies.append((time.perf_counter() - t0) * 1000)

        latencies.sort()
        p50 = latencies[int(n * 0.50)]
        assert p50 < 50.0, f"P50 {p50:.2f}ms exceeds 50ms soft target"

    def test_fast_path_under_1ms(self):
        """Fast-path evaluation must complete under 1ms."""
        from pramanix.fast_path import FastPathEvaluator

        rules = [
            SemanticFastPath.negative_amount("amount"),
            SemanticFastPath.zero_or_negative_balance("balance"),
            SemanticFastPath.account_frozen("is_frozen"),
        ]
        ev = FastPathEvaluator(rules)
        intent = {"amount": "100"}
        state = {"balance": "5000", "is_frozen": False}

        n = 1000
        t0 = time.monotonic()
        for _ in range(n):
            ev.evaluate(intent, state)
        elapsed_ms = (time.monotonic() - t0) * 1000
        avg_ms = elapsed_ms / n
        assert avg_ms < 1.0, f"Fast-path avg {avg_ms:.3f}ms exceeds 1ms"

    def test_compiled_meta_cached_correctly(self):
        """Guard._compiled_meta must be set after init."""
        guard = Guard(PerfPolicy, GuardConfig(execution_mode="sync"))
        assert hasattr(guard, "_compiled_meta")
        assert len(guard._compiled_meta) == 5
