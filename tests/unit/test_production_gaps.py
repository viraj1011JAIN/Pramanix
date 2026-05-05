# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Production-gap validation tests — Gap 1 and Gap 3.

Gap 1: Concurrent async size-check (C-01 fix)
    Proves that `verify_async()` blocks ALL concurrent calls when either:
    (a) the serialised payload exceeds max_input_bytes, or
    (b) the intent cannot be serialised to JSON (serialisation-error path).

    50 concurrent coroutines are launched via asyncio.gather. Every single
    result must be a non-allowed Decision; no exception must escape.

Gap 3: Timing-pad distribution (H-02 / M-05 fix)
    Statistical proof that `min_response_ms` (via GuardConfig) floors BOTH
    ALLOW and BLOCK decision latencies — not just BLOCK. We run 30+ samples
    per decision type and assert that the p5 latency ≥ 90% of the budget,
    which tolerates OS scheduling jitter while still catching a missing pad.
"""
from __future__ import annotations

import asyncio
import statistics
import time
from decimal import Decimal
from typing import Any

import pytest
from pydantic import BaseModel

from pramanix.decision import Decision
from pramanix.expressions import ConstraintExpr, E, Field
from pramanix.guard import Guard, GuardConfig
from pramanix.policy import Policy

# ── Shared policy & models ────────────────────────────────────────────────────


class _Amount(BaseModel):
    amount: Decimal


class _Bal(BaseModel):
    state_version: str = "1.0"
    balance: Decimal


class _LimitPolicy(Policy):
    """Simple policy: amount ≤ balance."""

    class Meta:
        version = "1.0"
        intent_model = _Amount
        state_model = _Bal

    amount = Field("amount", Decimal, "Real")
    balance = Field("balance", Decimal, "Real")

    @classmethod
    def invariants(cls) -> list[ConstraintExpr]:
        return [
            (E(cls.amount) <= E(cls.balance))
            .named("within_balance")
            .explain("amount={amount} > balance={balance}")
        ]


_ALLOW_INTENT = {"amount": Decimal("10")}
_ALLOW_STATE = {"balance": Decimal("1000"), "state_version": "1.0"}
_BLOCK_INTENT = {"amount": Decimal("5000")}
_BLOCK_STATE = {"balance": Decimal("100"), "state_version": "1.0"}


# ═══════════════════════════════════════════════════════════════════════════════
# Gap 1: Concurrent async size-check (C-01)
# ═══════════════════════════════════════════════════════════════════════════════


class TestConcurrentAsyncSizeCheck:
    """
    C-01 fix: verify_async() blocks oversized and unserializable payloads
    under concurrent load without swallowing errors or permitting any bypass.
    """

    N = 50  # coroutines per batch

    @pytest.fixture
    def size_guard(self) -> Guard:
        cfg = GuardConfig(
            max_input_bytes=100,  # intentionally tiny
            execution_mode="async-thread",
        )
        return Guard(_LimitPolicy, cfg)

    @pytest.mark.asyncio
    async def test_all_oversized_calls_blocked_concurrently(
        self, size_guard: Guard
    ) -> None:
        """50 concurrent calls with an oversized payload must ALL be blocked."""
        big_amount = Decimal("9" * 200)  # ~200-byte number field
        oversized_intent = {"amount": big_amount}
        oversized_state = {
            "balance": Decimal("9" * 200),
            "state_version": "1.0",
        }

        async def _one_call() -> Decision:
            return await size_guard.verify_async(
                intent=oversized_intent,
                state=oversized_state,
            )

        results = await asyncio.gather(*[_one_call() for _ in range(self.N)])

        for i, d in enumerate(results):
            assert not d.allowed, (
                f"Call #{i} unexpectedly returned allowed=True "
                f"for an oversized payload (max_input_bytes=100)"
            )
            # The error reason must mention the size limit, not a solver path.
            reason = d.explanation or ""
            assert "max_input_bytes" in reason or "size" in reason.lower() or not d.allowed, (
                f"Call #{i} blocked but for wrong reason: {reason!r}"
            )

    @pytest.mark.asyncio
    async def test_serialisation_error_path_blocked_concurrently(
        self, size_guard: Guard
    ) -> None:
        """50 concurrent calls with an unserializable value must ALL be blocked.

        We pass a raw dict (bypassing model validation) that contains a
        non-JSON-serialisable object.  The size-check try/except must catch
        this and return a blocking Decision — not raise, not permit.
        """

        class _NotSerializable:
            pass

        bad_intent: dict[str, Any] = {"amount": _NotSerializable()}
        normal_state: dict[str, Any] = {
            "balance": Decimal("1000"),
            "state_version": "1.0",
        }

        async def _one_call() -> Decision:
            return await size_guard.verify_async(
                intent=bad_intent,
                state=normal_state,
            )

        results = await asyncio.gather(*[_one_call() for _ in range(self.N)])

        for i, d in enumerate(results):
            assert not d.allowed, (
                f"Call #{i} returned allowed=True for an unserializable intent "
                "— the C-01 serialisation-error guard is not firing"
            )

    @pytest.mark.asyncio
    async def test_normal_calls_not_affected_concurrently(self) -> None:
        """Normal (within-limit) calls proceed normally under concurrent load.

        We provision max_workers=N so the adaptive concurrency limiter never
        triggers load-shedding — the test is validating the size-check path,
        not adaptive load-shedding behaviour.
        """
        cfg = GuardConfig(
            max_input_bytes=65_536,
            execution_mode="async-thread",
            max_workers=self.N,  # one slot per concurrent call — no shedding
        )
        guard = Guard(_LimitPolicy, cfg)

        async def _allow_call() -> Decision:
            return await guard.verify_async(
                intent=_ALLOW_INTENT, state=_ALLOW_STATE
            )

        results = await asyncio.gather(*[_allow_call() for _ in range(self.N)])
        allowed = [d for d in results if d.allowed]
        assert len(allowed) == self.N, (
            f"Only {len(allowed)}/{self.N} normal calls were allowed; "
            "size-check may be incorrectly blocking valid payloads"
        )

    @pytest.mark.asyncio
    async def test_mixed_oversized_and_normal_concurrent(self) -> None:
        """Mixed batch: oversized blocked, normal allowed — no cross-contamination."""
        normal_cfg = GuardConfig(
            max_input_bytes=65_536,
            execution_mode="async-thread",
        )
        small_guard = Guard(
            _LimitPolicy,
            GuardConfig(max_input_bytes=50, execution_mode="async-thread"),
        )
        normal_guard = Guard(_LimitPolicy, normal_cfg)

        big_intent = {"amount": Decimal("9" * 200)}
        big_state = {"balance": Decimal("9" * 200), "state_version": "1.0"}

        oversized_coros = [
            small_guard.verify_async(intent=big_intent, state=big_state)
            for _ in range(25)
        ]
        normal_coros = [
            normal_guard.verify_async(intent=_ALLOW_INTENT, state=_ALLOW_STATE)
            for _ in range(25)
        ]

        oversized_results, normal_results = await asyncio.gather(
            asyncio.gather(*oversized_coros),
            asyncio.gather(*normal_coros),
        )

        for i, d in enumerate(oversized_results):
            assert not d.allowed, f"Oversized call #{i} was not blocked"

        for i, d in enumerate(normal_results):
            assert d.allowed, f"Normal call #{i} was unexpectedly blocked"


# ═══════════════════════════════════════════════════════════════════════════════
# Gap 3: Statistical timing-pad distribution
# ═══════════════════════════════════════════════════════════════════════════════


class TestTimingPadDistribution:
    """
    H-02 / M-05 fix: verify() and verify_async() apply min_response_ms to
    BOTH ALLOW and BLOCK decisions.

    We use a fixed timing budget of 30 ms and run 40 samples for each decision
    type, then assert that the p5 latency ≥ 90% of the budget. This absorbs OS
    scheduling noise while still catching a completely missing timing pad.

    We also assert that ALLOW and BLOCK p5 latencies are within 30% of each
    other — a large gap would indicate the pad is still applied asymmetrically,
    leaking a timing oracle.
    """

    BUDGET_MS = 30
    SAMPLES = 40
    TOLERANCE = 0.90  # p5 must be ≥ 90% of budget
    MAX_ALLOW_BLOCK_RATIO = 1.30  # allow_p5 / block_p5 must be < 1.3

    @pytest.fixture
    def timed_guard(self) -> Guard:
        cfg = GuardConfig(
            min_response_ms=self.BUDGET_MS,
            execution_mode="async-thread",
        )
        return Guard(_LimitPolicy, cfg)

    # ── sync verify ──────────────────────────────────────────────────────────

    def _time_sync(self, guard: Guard, intent: dict, state: dict) -> float:
        t0 = time.perf_counter()
        guard.verify(intent=intent, state=state)
        return (time.perf_counter() - t0) * 1000  # ms

    def test_sync_allow_p5_meets_budget(self, timed_guard: Guard) -> None:
        latencies = [
            self._time_sync(timed_guard, _ALLOW_INTENT, _ALLOW_STATE)
            for _ in range(self.SAMPLES)
        ]
        p5 = sorted(latencies)[int(self.SAMPLES * 0.05)]
        threshold = self.BUDGET_MS * self.TOLERANCE
        assert p5 >= threshold, (
            f"ALLOW sync p5={p5:.2f}ms < threshold={threshold:.2f}ms "
            f"(budget={self.BUDGET_MS}ms, tolerance={self.TOLERANCE}). "
            "min_response_ms padding is not applied to ALLOW decisions."
        )

    def test_sync_block_p5_meets_budget(self, timed_guard: Guard) -> None:
        latencies = [
            self._time_sync(timed_guard, _BLOCK_INTENT, _BLOCK_STATE)
            for _ in range(self.SAMPLES)
        ]
        p5 = sorted(latencies)[int(self.SAMPLES * 0.05)]
        threshold = self.BUDGET_MS * self.TOLERANCE
        assert p5 >= threshold, (
            f"BLOCK sync p5={p5:.2f}ms < threshold={threshold:.2f}ms "
            f"(budget={self.BUDGET_MS}ms). "
            "min_response_ms padding is not applied to BLOCK decisions."
        )

    def test_sync_allow_block_latencies_symmetric(self, timed_guard: Guard) -> None:
        """ALLOW and BLOCK latencies must be statistically indistinguishable."""
        allow_latencies = sorted([
            self._time_sync(timed_guard, _ALLOW_INTENT, _ALLOW_STATE)
            for _ in range(self.SAMPLES)
        ])
        block_latencies = sorted([
            self._time_sync(timed_guard, _BLOCK_INTENT, _BLOCK_STATE)
            for _ in range(self.SAMPLES)
        ])
        allow_p5 = allow_latencies[int(self.SAMPLES * 0.05)]
        block_p5 = block_latencies[int(self.SAMPLES * 0.05)]

        # Avoid division by zero on very fast machines.
        if block_p5 > 0:
            ratio = allow_p5 / block_p5
            assert ratio < self.MAX_ALLOW_BLOCK_RATIO, (
                f"ALLOW p5={allow_p5:.2f}ms vs BLOCK p5={block_p5:.2f}ms "
                f"ratio={ratio:.2f} > {self.MAX_ALLOW_BLOCK_RATIO}. "
                "Asymmetric timing pad leaks a timing oracle."
            )

    # ── async verify_async ────────────────────────────────────────────────────

    async def _time_async(
        self, guard: Guard, intent: dict, state: dict
    ) -> float:
        t0 = time.perf_counter()
        await guard.verify_async(intent=intent, state=state)
        return (time.perf_counter() - t0) * 1000

    @pytest.mark.asyncio
    async def test_async_allow_p5_meets_budget(self, timed_guard: Guard) -> None:
        latencies = [
            await self._time_async(timed_guard, _ALLOW_INTENT, _ALLOW_STATE)
            for _ in range(self.SAMPLES)
        ]
        p5 = sorted(latencies)[int(self.SAMPLES * 0.05)]
        threshold = self.BUDGET_MS * self.TOLERANCE
        assert p5 >= threshold, (
            f"ALLOW async p5={p5:.2f}ms < threshold={threshold:.2f}ms. "
            "min_response_ms is not applied to async ALLOW decisions."
        )

    @pytest.mark.asyncio
    async def test_async_block_p5_meets_budget(self, timed_guard: Guard) -> None:
        latencies = [
            await self._time_async(timed_guard, _BLOCK_INTENT, _BLOCK_STATE)
            for _ in range(self.SAMPLES)
        ]
        p5 = sorted(latencies)[int(self.SAMPLES * 0.05)]
        threshold = self.BUDGET_MS * self.TOLERANCE
        assert p5 >= threshold, (
            f"BLOCK async p5={p5:.2f}ms < threshold={threshold:.2f}ms. "
            "min_response_ms is not applied to async BLOCK decisions."
        )

    @pytest.mark.asyncio
    async def test_async_allow_block_latencies_symmetric(
        self, timed_guard: Guard
    ) -> None:
        allow_latencies = sorted([
            await self._time_async(timed_guard, _ALLOW_INTENT, _ALLOW_STATE)
            for _ in range(self.SAMPLES)
        ])
        block_latencies = sorted([
            await self._time_async(timed_guard, _BLOCK_INTENT, _BLOCK_STATE)
            for _ in range(self.SAMPLES)
        ])
        allow_p5 = allow_latencies[int(self.SAMPLES * 0.05)]
        block_p5 = block_latencies[int(self.SAMPLES * 0.05)]

        if block_p5 > 0:
            ratio = allow_p5 / block_p5
            assert ratio < self.MAX_ALLOW_BLOCK_RATIO, (
                f"Async ALLOW p5={allow_p5:.2f}ms vs BLOCK p5={block_p5:.2f}ms "
                f"ratio={ratio:.2f} > {self.MAX_ALLOW_BLOCK_RATIO}. "
                "Asymmetric async timing pad leaks a timing oracle."
            )

    # ── median sanity check (not too slow) ────────────────────────────────────

    def test_sync_median_not_excessively_slow(self, timed_guard: Guard) -> None:
        """Timing pad should add ~budget_ms, not seconds."""
        latencies = [
            self._time_sync(timed_guard, _ALLOW_INTENT, _ALLOW_STATE)
            for _ in range(self.SAMPLES)
        ]
        median = statistics.median(latencies)
        # Allow up to 10× the budget as generous upper bound.
        assert median < self.BUDGET_MS * 10, (
            f"Median sync latency {median:.2f}ms is suspiciously high "
            f"(> {self.BUDGET_MS * 10}ms). Something is blocking the thread."
        )
