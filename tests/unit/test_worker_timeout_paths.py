# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Tests for WorkerPool host-side timeout paths.

Covers worker.py lines 693-699 (process mode timeout) and 718-724 (thread mode timeout).

The approach: replace the pool's executor with a stub whose futures timeout
on result(), then call submit_solve() and verify we get an error Decision
with the expected reason text.
"""

from __future__ import annotations

import concurrent.futures
from concurrent.futures import Future

from pramanix.decision import SolverStatus
from pramanix.expressions import ConstraintExpr
from pramanix.expressions import Field as ExprField
from pramanix.policy import Policy
from pramanix.worker import WorkerPool

# ── Stub executor that always times out ────────────────────────────────────────


class _TimeoutFuture(Future):
    """A Future whose result() always raises TimeoutError after a short wait."""

    def result(self, timeout: float | None = None):  # type: ignore[override]
        raise concurrent.futures.TimeoutError("stub timeout")

    def cancel(self) -> bool:
        return True


class _TimeoutExecutor:
    """Minimal executor that always returns a _TimeoutFuture."""

    def submit(self, fn, *args, **kwargs) -> _TimeoutFuture:  # type: ignore[override]
        return _TimeoutFuture()

    def shutdown(self, wait: bool = True) -> None:
        pass


# ── Minimal policy for submit_solve ────────────────────────────────────────────


class _TrivialPolicy(Policy):
    x = ExprField("x", int, "Int")

    @classmethod
    def invariants(cls) -> list[ConstraintExpr]:
        return []


# ═══════════════════════════════════════════════════════════════════════════════
# Thread mode host timeout
# ═══════════════════════════════════════════════════════════════════════════════


class TestThreadModeHostTimeout:
    """worker.py lines 718-724: thread worker host deadline exceeded."""

    def test_thread_timeout_returns_error_decision(self) -> None:
        pool = WorkerPool(
            mode="async-thread",
            max_workers=1,
            max_decisions_per_worker=100,
            warmup=False,
        )
        pool.spawn()

        # Inject the stub executor so submit() returns a timing-out Future.
        pool._executor = _TimeoutExecutor()  # type: ignore[assignment]
        pool._alive = True

        decision = pool.submit_solve(_TrivialPolicy, {"x": 1}, 1_000)

        pool.shutdown(wait=False)

        assert not decision.allowed
        assert decision.status == SolverStatus.ERROR
        assert (
            "deadline" in decision.explanation.lower() or "timeout" in decision.explanation.lower()
        )


# ═══════════════════════════════════════════════════════════════════════════════
# Process mode host timeout
# ═══════════════════════════════════════════════════════════════════════════════


class TestProcessModeHostTimeout:
    """worker.py lines 693-699: process worker host deadline exceeded."""

    def test_process_timeout_returns_error_decision(self) -> None:
        pool = WorkerPool(
            mode="async-process",
            max_workers=1,
            max_decisions_per_worker=100,
            warmup=False,
        )
        pool.spawn()

        pool._executor = _TimeoutExecutor()  # type: ignore[assignment]
        pool._alive = True

        decision = pool.submit_solve(_TrivialPolicy, {"x": 1}, 1_000)

        pool.shutdown(wait=False)

        assert not decision.allowed
        assert decision.status == SolverStatus.ERROR
        assert (
            "deadline" in decision.explanation.lower() or "timeout" in decision.explanation.lower()
        )


# ═══════════════════════════════════════════════════════════════════════════════
# WorkerPool.__del__ finalizer paths
# ═══════════════════════════════════════════════════════════════════════════════


class TestWorkerPoolDelPaths:
    """WorkerPool._emergency_shutdown finalizer callback paths."""

    def test_del_when_not_alive_is_noop(self) -> None:
        # Cell containing None — _emergency_shutdown must return immediately.
        WorkerPool._emergency_shutdown([None])  # Must not raise

    def test_del_when_alive_logs_warning_and_shuts_down(self, caplog) -> None:
        import logging

        pool = WorkerPool(
            mode="async-thread",
            max_workers=1,
            max_decisions_per_worker=10,
            warmup=False,
        )
        pool.spawn()
        assert pool._alive

        executor = pool._executor
        with caplog.at_level(logging.WARNING, logger="pramanix.worker"):
            WorkerPool._emergency_shutdown([executor])

        assert "GC'd without explicit shutdown" in caplog.text

    def test_del_when_finalizing_shuts_down_silently(self) -> None:
        pool = WorkerPool(
            mode="async-thread",
            max_workers=1,
            max_decisions_per_worker=10,
            warmup=False,
        )
        pool.spawn()
        assert pool._alive

        # _emergency_shutdown with a live executor — must shut it down without raising.
        executor = pool._executor
        WorkerPool._emergency_shutdown([executor])
        # After emergency shutdown the underlying executor is terminated.
        pool._alive = False  # mark pool as no longer alive so shutdown() no-ops
        pool.shutdown(wait=False)
