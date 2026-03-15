# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Unit tests for worker.py dark / uncovered paths.

Coverage targets
----------------
* _worker_solve — SolverTimeoutError, PramanixError paths
* _drain_executor — grace-period timeout, force-kill path
* _force_kill_processes — alive process killed, exception swallowed
* WorkerPool.spawn — executor creation failure
* WorkerPool.shutdown — executor shutdown exception swallowed
* WorkerPool.submit_solve — pool not alive, exception in executor
* WorkerPool._make_executor — async-process mode
* WorkerPool._run_warmup — slot failure swallowed
* WorkerPool._recycle — early return (already recycled), executor failure
* WorkerPool.executor property
"""
from __future__ import annotations

import threading
import time
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from decimal import Decimal
from unittest.mock import MagicMock, patch

import pytest

from pramanix import E, Field, Policy
from pramanix.decision import Decision
from pramanix.exceptions import SolverTimeoutError, WorkerError
from pramanix.worker import WorkerPool, _drain_executor, _force_kill_processes


# ═══════════════════════════════════════════════════════════════════════════════
# Minimal policy
# ═══════════════════════════════════════════════════════════════════════════════

_f = Field("amount", Decimal, "Real")


class _P(Policy):
    @classmethod
    def fields(cls):  # type: ignore[override]
        return {"amount": _f}

    @classmethod
    def invariants(cls):  # type: ignore[override]
        return [(E(_f) >= 0).named("ok").explain("amount {amount} >= 0")]


# ═══════════════════════════════════════════════════════════════════════════════
# _worker_solve error paths
# ═══════════════════════════════════════════════════════════════════════════════


class TestWorkerSolveErrorPaths:
    def test_solver_timeout_error_returns_timeout_dict(self) -> None:
        from pramanix.worker import _worker_solve

        err = SolverTimeoutError("ok", 100)
        with patch("pramanix.solver.solve", side_effect=err):
            result = _worker_solve(_P, {"amount": Decimal("50")}, 100)

        assert result["status"] == "timeout"
        assert not result["allowed"]

    def test_pramanix_error_returns_error_dict(self) -> None:
        from pramanix.exceptions import PramanixError
        from pramanix.worker import _worker_solve

        with patch(
            "pramanix.solver.solve",
            side_effect=PramanixError("boom"),
        ):
            result = _worker_solve(_P, {"amount": Decimal("50")}, 100)

        assert result["status"] == "error"
        assert not result["allowed"]

    def test_generic_exception_returns_error_dict(self) -> None:
        from pramanix.worker import _worker_solve

        with patch(
            "pramanix.solver.solve",
            side_effect=ValueError("oops"),
        ):
            result = _worker_solve(_P, {"amount": Decimal("50")}, 100)

        assert result["status"] == "error"
        assert "ValueError" in result["explanation"]


# ═══════════════════════════════════════════════════════════════════════════════
# _drain_executor — timeout path
# ═══════════════════════════════════════════════════════════════════════════════


class TestDrainExecutor:
    def test_drain_completes_when_executor_shuts_down_quickly(self) -> None:
        executor = ThreadPoolExecutor(max_workers=1)
        # No pending work — shutdown is instantaneous.
        _drain_executor(executor, grace_s=5.0)

    def test_drain_logs_warning_when_grace_period_exceeded(self) -> None:
        """Simulate a hung executor by never calling shutdown_event.set()."""
        mock_executor = MagicMock(spec=ThreadPoolExecutor)

        # Make shutdown() block indefinitely
        barrier = threading.Event()

        def _hang(*_a: object, **_kw: object) -> None:
            barrier.wait(timeout=30)

        mock_executor.shutdown = _hang

        with patch("pramanix.worker._log") as mock_log:
            _drain_executor(mock_executor, grace_s=0.05)

        # Warning must have been logged about the grace period
        assert mock_log.warning.called
        # Unblock the hanging thread
        barrier.set()

    def test_drain_calls_force_kill_for_process_executor(self) -> None:
        """When grace period expires and executor is a ProcessPoolExecutor,
        _force_kill_processes is invoked."""
        mock_pexec = MagicMock(spec=ProcessPoolExecutor)

        barrier = threading.Event()

        def _hang(*_a: object, **_kw: object) -> None:
            barrier.wait(timeout=30)

        mock_pexec.shutdown = _hang

        with patch("pramanix.worker._force_kill_processes") as mock_fkp:
            _drain_executor(mock_pexec, grace_s=0.05)

        mock_fkp.assert_called_once_with(mock_pexec)
        barrier.set()


# ═══════════════════════════════════════════════════════════════════════════════
# _force_kill_processes
# ═══════════════════════════════════════════════════════════════════════════════


class TestForceKillProcesses:
    def test_alive_process_is_killed(self) -> None:
        mock_proc = MagicMock()
        mock_proc.is_alive.return_value = True
        mock_proc.pid = 99999

        mock_executor = MagicMock(spec=ProcessPoolExecutor)
        mock_executor._processes = {99999: mock_proc}

        _force_kill_processes(mock_executor)

        mock_proc.kill.assert_called_once()

    def test_dead_process_is_not_killed(self) -> None:
        mock_proc = MagicMock()
        mock_proc.is_alive.return_value = False

        mock_executor = MagicMock(spec=ProcessPoolExecutor)
        mock_executor._processes = {1: mock_proc}

        _force_kill_processes(mock_executor)

        mock_proc.kill.assert_not_called()

    def test_kill_exception_is_logged_not_raised(self) -> None:
        mock_proc = MagicMock()
        mock_proc.is_alive.return_value = True
        mock_proc.pid = 42
        mock_proc.kill.side_effect = OSError("Permission denied")

        mock_executor = MagicMock(spec=ProcessPoolExecutor)
        mock_executor._processes = {42: mock_proc}

        with patch("pramanix.worker._log") as mock_log:
            _force_kill_processes(mock_executor)

        assert mock_log.error.called

    def test_no_processes_attribute_is_safe(self) -> None:
        """Executor without _processes → getattr returns {} → no kill."""
        mock_executor = MagicMock(spec=ProcessPoolExecutor)
        del mock_executor._processes

        _force_kill_processes(mock_executor)  # must not raise


# ═══════════════════════════════════════════════════════════════════════════════
# WorkerPool lifecycle error paths
# ═══════════════════════════════════════════════════════════════════════════════


class TestWorkerPoolLifecycle:
    def test_spawn_raises_worker_error_on_make_executor_failure(self) -> None:
        pool = WorkerPool(
            mode="async-thread",
            max_workers=1,
            max_decisions_per_worker=1000,
            warmup=False,
        )
        with patch.object(
            pool, "_make_executor", side_effect=OSError("disk full")
        ):
            with pytest.raises(WorkerError, match="disk full"):
                pool.spawn()

    def test_spawn_is_idempotent_when_alive(self) -> None:
        pool = WorkerPool(
            mode="async-thread",
            max_workers=1,
            max_decisions_per_worker=1000,
            warmup=False,
        )
        pool.spawn()
        # Second spawn should be a no-op — _make_executor called once only
        with patch.object(
            pool, "_make_executor"
        ) as mock_make:
            pool.spawn()
        mock_make.assert_not_called()
        pool.shutdown()

    def test_shutdown_swallows_executor_error(self) -> None:
        pool = WorkerPool(
            mode="async-thread",
            max_workers=1,
            max_decisions_per_worker=1000,
            warmup=False,
        )
        pool.spawn()
        pool._executor.shutdown = MagicMock(
            side_effect=RuntimeError("shutdown error")
        )
        with patch("pramanix.worker._log") as mock_log:
            pool.shutdown()
        assert mock_log.error.called

    def test_shutdown_noop_when_not_alive(self) -> None:
        pool = WorkerPool(
            mode="async-thread",
            max_workers=1,
            max_decisions_per_worker=1000,
            warmup=False,
        )
        # Not yet spawned — should be a no-op
        pool.shutdown()


# ═══════════════════════════════════════════════════════════════════════════════
# WorkerPool.submit_solve
# ═══════════════════════════════════════════════════════════════════════════════


class TestWorkerPoolSubmitSolve:
    def test_submit_when_not_alive_returns_error_decision(self) -> None:
        pool = WorkerPool(
            mode="async-thread",
            max_workers=1,
            max_decisions_per_worker=1000,
            warmup=False,
        )
        # Pool not spawned — _alive is False
        result = pool.submit_solve(_P, {"amount": Decimal("50")}, 5000)
        assert not result.allowed
        assert "not running" in result.explanation.lower()

    def test_submit_executor_exception_returns_error_decision(self) -> None:
        pool = WorkerPool(
            mode="async-thread",
            max_workers=1,
            max_decisions_per_worker=1000,
            warmup=False,
        )
        pool.spawn()
        pool._executor = MagicMock()
        pool._executor.submit.side_effect = RuntimeError("executor dead")

        with patch("pramanix.worker._log"):
            result = pool.submit_solve(
                _P, {"amount": Decimal("50")}, 5000
            )

        assert not result.allowed
        assert result.explanation is not None
        pool.shutdown()

    def test_submit_recycles_after_max_decisions(self) -> None:
        pool = WorkerPool(
            mode="async-thread",
            max_workers=1,
            max_decisions_per_worker=1,  # recycle after every call
            warmup=False,
        )
        pool.spawn()
        result = pool.submit_solve(
            _P, {"amount": Decimal("50")}, 5000
        )
        assert result.allowed
        # After recycling, pool should still be alive
        assert pool._alive
        pool.shutdown()


# ═══════════════════════════════════════════════════════════════════════════════
# WorkerPool._make_executor — async-process mode
# ═══════════════════════════════════════════════════════════════════════════════


class TestWorkerPoolMakeExecutor:
    def test_async_process_mode_returns_process_pool_executor(self) -> None:
        pool = WorkerPool(
            mode="async-process",
            max_workers=1,
            max_decisions_per_worker=1000,
            warmup=False,
        )
        executor = pool._make_executor()
        assert isinstance(executor, ProcessPoolExecutor)
        executor.shutdown(wait=False)

    def test_unknown_mode_raises_worker_error(self) -> None:
        pool = WorkerPool(
            mode="unknown-mode",
            max_workers=1,
            max_decisions_per_worker=1000,
            warmup=False,
        )
        with pytest.raises(WorkerError, match="Unknown worker mode"):
            pool._make_executor()


# ═══════════════════════════════════════════════════════════════════════════════
# WorkerPool._run_warmup — slot failure swallowed
# ═══════════════════════════════════════════════════════════════════════════════


class TestWorkerPoolRunWarmup:
    def test_warmup_slot_failure_is_logged_not_raised(self) -> None:
        pool = WorkerPool(
            mode="async-thread",
            max_workers=1,
            max_decisions_per_worker=1000,
            warmup=True,
        )
        pool._executor = ThreadPoolExecutor(max_workers=1)

        mock_future = MagicMock()
        mock_future.result.side_effect = RuntimeError("warmup failed")
        pool._executor.submit = MagicMock(return_value=mock_future)

        with patch("pramanix.worker._log") as mock_log:
            pool._run_warmup()

        assert mock_log.warning.called
        pool._executor.shutdown(wait=False)


# ═══════════════════════════════════════════════════════════════════════════════
# WorkerPool._recycle — early return and executor failure
# ═══════════════════════════════════════════════════════════════════════════════


class TestWorkerPoolRecycle:
    def test_recycle_early_return_when_counter_reset(self) -> None:
        """Another thread already recycled — counter reset → return early."""
        pool = WorkerPool(
            mode="async-thread",
            max_workers=1,
            max_decisions_per_worker=10,
            warmup=False,
        )
        pool.spawn()
        # Set counter high enough to trigger recycle check, then manually
        # reset it to simulate a race where another thread already recycled.
        pool._counter = 10  # matches max_decisions_per_worker

        with patch.object(pool, "_make_executor") as mock_make:
            # Simulate: counter already reset inside the lock (race condition)
            def _reset_counter() -> None:
                pool._counter = 0
                raise RuntimeError("should not create executor")

            mock_make.side_effect = RuntimeError("should not be called")
            # Manually reset counter before calling _recycle
            pool._counter = 0
            pool._recycle()  # counter < max → early return

        mock_make.assert_not_called()
        pool.shutdown()

    def test_recycle_swallows_executor_creation_failure(self) -> None:
        """New executor creation fails → old executor restored, no raise."""
        pool = WorkerPool(
            mode="async-thread",
            max_workers=1,
            max_decisions_per_worker=1,
            warmup=False,
        )
        pool.spawn()
        original_executor = pool._executor
        pool._counter = 1  # trigger recycle on next check

        with patch("pramanix.worker._log") as mock_log:
            with patch.object(
                pool,
                "_make_executor",
                side_effect=OSError("can't create"),
            ):
                pool._recycle()

        # Old executor should be restored
        assert pool._executor is original_executor
        assert mock_log.error.called
        pool.shutdown()


# ═══════════════════════════════════════════════════════════════════════════════
# WorkerPool.executor property
# ═══════════════════════════════════════════════════════════════════════════════


class TestWorkerPoolExecutorProperty:
    def test_executor_property_returns_underlying_executor(self) -> None:
        pool = WorkerPool(
            mode="async-thread",
            max_workers=1,
            max_decisions_per_worker=1000,
            warmup=False,
        )
        pool.spawn()
        assert pool.executor is pool._executor
        pool.shutdown()
