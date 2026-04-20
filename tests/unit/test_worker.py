# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Unit tests for WorkerPool — thread and process modes.

Tests cover:
* spawn / warmup
* host-side counter increments
* recycle triggering
* idempotent shutdown
* worker failure isolation (never propagates to caller)
* process boundary: no Pydantic objects in pickle payload
"""
from __future__ import annotations

import pickle
from decimal import Decimal

from pramanix import E, Field, Guard, GuardConfig, Policy
from pramanix.decision import SolverStatus
from pramanix.expressions import ConstraintExpr
from pramanix.worker import WorkerPool, _worker_solve

# ── Shared test policy ────────────────────────────────────────────────────────


class _SimplePolicy(Policy):
    class Meta:
        name = "worker_test"
        version = "1.0"

    balance = Field("balance", Decimal, "Real")
    amount = Field("amount", Decimal, "Real")

    @classmethod
    def invariants(cls) -> list[ConstraintExpr]:
        return [(E(cls.balance) - E(cls.amount) >= 0).named("non_negative_balance")]


# ── Thread mode tests ──────────────────────────────────────────────────────────


class TestWorkerPoolThreadMode:
    def test_spawn_succeeds(self) -> None:
        pool = WorkerPool(
            mode="async-thread",
            max_workers=2,
            max_decisions_per_worker=100,
            warmup=True,
        )
        pool.spawn()
        assert pool._alive
        pool.shutdown()

    def test_spawn_idempotent(self) -> None:
        pool = WorkerPool(
            mode="async-thread",
            max_workers=2,
            max_decisions_per_worker=100,
            warmup=False,
        )
        pool.spawn()
        pool.spawn()  # second call must not raise
        pool.shutdown()

    def test_submit_solve_safe(self) -> None:
        pool = WorkerPool(
            mode="async-thread",
            max_workers=2,
            max_decisions_per_worker=100,
            warmup=False,
        )
        pool.spawn()
        values = {"balance": Decimal("1000"), "amount": Decimal("100")}
        decision = pool.submit_solve(_SimplePolicy, values, timeout_ms=5_000)
        assert decision.allowed
        assert decision.status is SolverStatus.SAFE
        pool.shutdown()

    def test_submit_solve_unsafe(self) -> None:
        pool = WorkerPool(
            mode="async-thread",
            max_workers=2,
            max_decisions_per_worker=100,
            warmup=False,
        )
        pool.spawn()
        values = {"balance": Decimal("50"), "amount": Decimal("1000")}
        decision = pool.submit_solve(_SimplePolicy, values, timeout_ms=5_000)
        assert not decision.allowed
        assert decision.status is SolverStatus.UNSAFE
        assert "non_negative_balance" in decision.violated_invariants
        pool.shutdown()

    def test_counter_increments(self) -> None:
        pool = WorkerPool(
            mode="async-thread",
            max_workers=2,
            max_decisions_per_worker=100,
            warmup=False,
        )
        pool.spawn()
        values = {"balance": Decimal("100"), "amount": Decimal("10")}
        for _ in range(5):
            pool.submit_solve(_SimplePolicy, values, timeout_ms=5_000)
        assert pool._counter == 5
        pool.shutdown()

    def test_recycle_triggers_and_resets_counter(self) -> None:
        """After max_decisions_per_worker calls, counter resets."""
        pool = WorkerPool(
            mode="async-thread",
            max_workers=1,
            max_decisions_per_worker=3,
            warmup=False,
            grace_s=2.0,
        )
        pool.spawn()
        values = {"balance": Decimal("100"), "amount": Decimal("10")}
        # Submit one more than the threshold to trigger recycle
        for _ in range(4):
            pool.submit_solve(_SimplePolicy, values, timeout_ms=5_000)
        # Counter resets after recycle — should be 1 (the 4th call, post-recycle)
        assert pool._counter <= 1
        pool.shutdown()

    def test_shutdown_idempotent(self) -> None:
        pool = WorkerPool(
            mode="async-thread",
            max_workers=2,
            max_decisions_per_worker=100,
            warmup=False,
        )
        pool.spawn()
        pool.shutdown()
        pool.shutdown()  # must not raise

    def test_submit_when_not_alive_returns_error_decision(self) -> None:
        pool = WorkerPool(
            mode="async-thread",
            max_workers=2,
            max_decisions_per_worker=100,
            warmup=False,
        )
        # Never spawned
        values = {"balance": Decimal("100"), "amount": Decimal("10")}
        decision = pool.submit_solve(_SimplePolicy, values, timeout_ms=5_000)
        assert not decision.allowed
        assert decision.status is SolverStatus.ERROR


# ── Process boundary tests ─────────────────────────────────────────────────────


class TestSerializationBoundary:
    def test_worker_solve_args_are_picklable(self) -> None:
        """Confirm that _worker_solve args contain no Pydantic instances."""
        values = {"balance": Decimal("500"), "amount": Decimal("100")}
        # policy_cls is a class reference — picklable via import path
        payload = (_worker_solve, _SimplePolicy, values, 5_000)
        # This must not raise
        dumped = pickle.dumps(payload)
        assert len(dumped) > 0

    def test_no_pydantic_in_pickled_payload(self) -> None:
        """Ensure no BaseModel instances appear in the serialised worker args."""
        from pydantic import BaseModel

        values = {"balance": Decimal("500"), "amount": Decimal("100")}
        dumped = pickle.dumps((_SimplePolicy, values, 5_000))
        # Reconstruct and verify no BaseModel instances
        unpickled = pickle.loads(dumped)
        _policy_cls, vals, _tm = unpickled
        assert not isinstance(vals["balance"], BaseModel)
        assert not isinstance(vals["amount"], BaseModel)

    def test_worker_solve_returns_plain_dict(self) -> None:
        """_worker_solve must return a plain dict (Decision.to_dict() format)."""
        values = {"balance": Decimal("1000"), "amount": Decimal("100")}
        result = _worker_solve(_SimplePolicy, values, 5_000)
        assert isinstance(result, dict)
        assert "allowed" in result
        assert "status" in result
        assert isinstance(result["allowed"], bool)

    def test_worker_solve_fail_safe(self) -> None:
        """_worker_solve never raises — returns error Decision dict instead."""

        class _BrokenPolicy(Policy):
            class Meta:
                name = "broken"
                version = "1.0"

            x = Field("x", Decimal, "Real")

            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                raise RuntimeError("Deliberate crash for testing")

        result = _worker_solve(_BrokenPolicy, {"x": Decimal("1")}, 5_000)
        assert isinstance(result, dict)
        assert result["allowed"] is False
        assert result["status"] == "error"


# ── Guard async-thread integration (sync entry for easy pytest) ───────────────


class TestGuardAsyncThreadViaPool:
    """Smoke tests for Guard configured with async-thread mode."""

    def test_guard_with_async_thread_mode_creates_pool(self) -> None:
        g = Guard(_SimplePolicy, GuardConfig(execution_mode="async-thread", worker_warmup=False))
        assert g._pool is not None
        assert g._pool._alive
        g._pool.shutdown()

    def test_guard_sync_verify_unaffected(self) -> None:
        """Guard.verify() (sync) still works regardless of execution_mode."""
        g = Guard(_SimplePolicy, GuardConfig(execution_mode="async-thread", worker_warmup=False))
        decision = g.verify(
            intent={"amount": Decimal("100")},
            state={"balance": Decimal("500"), "state_version": "1.0"},
        )
        assert decision.allowed
        g._pool.shutdown()  # type: ignore[union-attr]
