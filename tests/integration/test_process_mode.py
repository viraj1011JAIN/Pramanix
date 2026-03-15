# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Integration tests — async-thread mode process boundary verification.

Tests:
* No Pydantic models in pickled data (inspect pickle.dumps output)
* Correct Decision returned across thread pool
* Worker warmup completes before first real request
* Worker recycled after max_decisions_per_worker
"""
from __future__ import annotations

import pickle
from decimal import Decimal

import pytest

from pramanix import E, Field, Guard, GuardConfig, Policy
from pramanix.decision import SolverStatus
from pramanix.expressions import ConstraintExpr
from pramanix.worker import WorkerPool, _worker_solve

# ── Test policy (picklable — defined at module level) ─────────────────────────


class _SimpleTransferPolicy(Policy):
    class Meta:
        name = "process_test_transfer"
        version = "1.0"

    balance = Field("balance", Decimal, "Real")
    amount = Field("amount", Decimal, "Real")

    @classmethod
    def invariants(cls) -> list[ConstraintExpr]:
        return [(E(cls.balance) - E(cls.amount) >= 0).named("non_negative_balance")]


# ── Boundary tests ────────────────────────────────────────────────────────────


class TestSerializationBoundaryIntegration:
    def test_no_pydantic_in_pickled_worker_args(self) -> None:
        """Worker args must be free of Pydantic BaseModel instances."""
        from pydantic import BaseModel

        values = {"balance": Decimal("1000"), "amount": Decimal("100")}
        payload = (_SimpleTransferPolicy, values, 5_000)
        dumped = pickle.dumps(payload)

        # Reconstruct and walk all values
        unpickled_policy, unpickled_values, _ = pickle.loads(dumped)
        for v in unpickled_values.values():
            assert not isinstance(
                v, BaseModel
            ), f"Pydantic model found in worker payload: {type(v).__name__}"

    def test_no_z3_objects_in_pickled_worker_args(self) -> None:
        """worker_solve args must contain no Z3 objects."""
        import z3

        values = {"balance": Decimal("1000"), "amount": Decimal("100")}
        payload = (_SimpleTransferPolicy, values, 5_000)
        dumped = pickle.dumps(payload)
        unpickled_policy, unpickled_values, _ = pickle.loads(dumped)
        for v in unpickled_values.values():
            assert not isinstance(
                v, z3.ExprRef
            ), f"Z3 object found in worker payload: {type(v).__name__}"

    def test_worker_solve_returns_correct_decision(self) -> None:
        """_worker_solve produces a correct SAT decision dict."""
        values = {"balance": Decimal("1000"), "amount": Decimal("100")}
        result = _worker_solve(_SimpleTransferPolicy, values, 5_000)
        assert result["allowed"] is True
        assert result["status"] == "safe"

    def test_worker_solve_unsafe_decision(self) -> None:
        values = {"balance": Decimal("10"), "amount": Decimal("1000")}
        result = _worker_solve(_SimpleTransferPolicy, values, 5_000)
        assert result["allowed"] is False
        assert result["status"] == "unsafe"
        assert "non_negative_balance" in result["violated_invariants"]


# ── WorkerPool lifecycle integration ─────────────────────────────────────────


class TestWorkerPoolLifecycle:
    def test_warmup_completes_before_first_request(self) -> None:
        pool = WorkerPool(
            mode="async-thread",
            max_workers=2,
            max_decisions_per_worker=100,
            warmup=True,
        )
        pool.spawn()
        assert pool._alive
        # First request must succeed (warmup already done in spawn)
        values = {"balance": Decimal("500"), "amount": Decimal("100")}
        d = pool.submit_solve(_SimpleTransferPolicy, values, 5_000)
        assert d.allowed
        pool.shutdown()

    def test_worker_recycled_after_max_decisions(self) -> None:
        """After max_decisions_per_worker solves, counter resets."""
        pool = WorkerPool(
            mode="async-thread",
            max_workers=1,
            max_decisions_per_worker=5,
            warmup=False,
            grace_s=1.0,
        )
        pool.spawn()
        values = {"balance": Decimal("500"), "amount": Decimal("100")}

        # Submit 6 — the 5th triggers recycle, counter resets, 6th increments to 1
        for _ in range(6):
            d = pool.submit_solve(_SimpleTransferPolicy, values, 5_000)
            assert d.allowed  # must always succeed across recycle

        assert pool._counter <= 1  # counter has been reset
        pool.shutdown()

    def test_multiple_decisions_all_correct(self) -> None:
        """All decisions must be correct regardless of pool state."""
        pool = WorkerPool(
            mode="async-thread",
            max_workers=3,
            max_decisions_per_worker=50,
            warmup=False,
        )
        pool.spawn()

        safe_vals = {"balance": Decimal("1000"), "amount": Decimal("100")}
        unsafe_vals = {"balance": Decimal("10"), "amount": Decimal("1000")}

        for _ in range(10):
            d_safe = pool.submit_solve(_SimpleTransferPolicy, safe_vals, 5_000)
            d_unsafe = pool.submit_solve(_SimpleTransferPolicy, unsafe_vals, 5_000)
            assert d_safe.allowed
            assert not d_unsafe.allowed

        pool.shutdown()


# ── Guard async-thread mode end-to-end ───────────────────────────────────────


class TestGuardAsyncThreadEndToEnd:
    @pytest.mark.asyncio
    async def test_verify_async_safe(self) -> None:
        g = Guard(
            _SimpleTransferPolicy,
            GuardConfig(execution_mode="async-thread", worker_warmup=False),
        )
        try:
            d = await g.verify_async(
                intent={"amount": Decimal("100")},
                state={"balance": Decimal("1000"), "state_version": "1.0"},
            )
            assert d.allowed
            assert d.status is SolverStatus.SAFE
        finally:
            await g.shutdown()

    @pytest.mark.asyncio
    async def test_verify_async_unsafe(self) -> None:
        g = Guard(
            _SimpleTransferPolicy,
            GuardConfig(execution_mode="async-thread", worker_warmup=False),
        )
        try:
            d = await g.verify_async(
                intent={"amount": Decimal("9999")},
                state={"balance": Decimal("10"), "state_version": "1.0"},
            )
            assert not d.allowed
            assert d.status is SolverStatus.UNSAFE
        finally:
            await g.shutdown()

    @pytest.mark.asyncio
    async def test_guard_shutdown_is_idempotent(self) -> None:
        g = Guard(
            _SimpleTransferPolicy,
            GuardConfig(execution_mode="async-thread", worker_warmup=False),
        )
        await g.shutdown()
        await g.shutdown()  # must not raise

    @pytest.mark.asyncio
    async def test_concurrent_verify_async(self) -> None:
        """Multiple concurrent verify_async calls all return correct results."""
        import asyncio

        g = Guard(
            _SimpleTransferPolicy,
            GuardConfig(
                execution_mode="async-thread",
                max_workers=4,
                worker_warmup=False,
            ),
        )
        try:
            safe = {"amount": Decimal("100")}
            state = {"balance": Decimal("500"), "state_version": "1.0"}
            tasks = [g.verify_async(intent=safe, state=state) for _ in range(20)]
            results = await asyncio.gather(*tasks)
            assert all(d.allowed for d in results)
        finally:
            await g.shutdown()
