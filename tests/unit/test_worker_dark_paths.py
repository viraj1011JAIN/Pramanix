# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Unit tests for worker.py dark / uncovered paths — production-level, zero mocks.

Design principles
-----------------
* No MagicMock, patch, or AsyncMock anywhere in this file.

* Solver error paths (_worker_solve): monkeypatch.setattr on pramanix.solver.solve
  is acceptable here — these paths test the WORKER's error handling in response
  to impossible-to-trigger-deterministically solver failures (SolverTimeoutError
  requires Z3 to hit a 1 ms wall-clock budget; PramanixError is rarely raised
  directly by solve()).  The invariant under test is the worker dict shape, not
  the solver's own logic.

* Hanging executors: real ThreadPoolExecutor / ProcessPoolExecutor subclasses
  whose shutdown() blocks on a threading.Event.  Allows testing _drain_executor's
  grace-period timeout path without any fake objects.

* Process kill: _FakeProcess is a real class (not a mock) with real is_alive(),
  pid, and kill() methods; state is tracked in plain instance attributes.

* Log capture: _LogCapture is a real logging-like object that records calls.
  monkeypatch.setattr replaces pramanix.worker._log for the duration of the test.

* Executor failures: _BrokenSubmitExecutor and _FailingSubmitExecutor are real
  ThreadPoolExecutor subclasses that override submit() with deterministic
  failure behaviour.
"""
from __future__ import annotations

import threading
from concurrent.futures import Future, ProcessPoolExecutor, ThreadPoolExecutor
from decimal import Decimal

import pytest

import pramanix.solver as _solver_mod
from pramanix import E, Field, Policy
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
# Real helper classes — not mocks
# ═══════════════════════════════════════════════════════════════════════════════


class _HangingThreadExecutor(ThreadPoolExecutor):
    """Real ThreadPoolExecutor whose shutdown() blocks until .release() is called.

    Used to test _drain_executor's grace-period timeout path without any mock.
    """

    def __init__(self) -> None:
        super().__init__(max_workers=1)
        self._barrier = threading.Event()

    def shutdown(self, wait: bool = True, **kwargs: object) -> None:  # type: ignore[override]
        self._barrier.wait(timeout=30)

    def release(self) -> None:
        self._barrier.set()


class _HangingProcessExecutor(ProcessPoolExecutor):
    """Real ProcessPoolExecutor whose shutdown() blocks until .release() is called.

    isinstance(executor, ProcessPoolExecutor) → True, so _drain_executor will
    call _force_kill_processes on grace-period expiry — exactly what we test.
    """

    def __init__(self) -> None:
        super().__init__(max_workers=1)
        self._barrier = threading.Event()

    def shutdown(self, wait: bool = True, **kwargs: object) -> None:  # type: ignore[override]
        self._barrier.wait(timeout=30)

    def release(self) -> None:
        self._barrier.set()


class _FakeProcess:
    """Real process-like object for testing _force_kill_processes.

    Tracks kill() calls via a plain boolean — no mock instrumentation.
    """

    def __init__(
        self,
        *,
        alive: bool,
        pid: int,
        kill_raises: Exception | None = None,
    ) -> None:
        self._alive = alive
        self.pid = pid
        self._kill_raises = kill_raises
        self.kill_called: bool = False

    def is_alive(self) -> bool:
        return self._alive

    def kill(self) -> None:
        self.kill_called = True
        if self._kill_raises is not None:
            raise self._kill_raises


class _FakeProcessContainer:
    """Real object carrying a _processes dict.

    _force_kill_processes only reads executor._processes — it does NOT require
    a true ProcessPoolExecutor instance.  This minimal class is sufficient.
    """

    def __init__(self, processes: dict) -> None:
        self._processes = processes


class _EmptyProcessContainer:
    """Real object without a _processes attribute — tests the safe getattr path."""


class _BrokenSubmitExecutor(ThreadPoolExecutor):
    """Real ThreadPoolExecutor whose submit() always raises RuntimeError."""

    def submit(self, fn, *args, **kwargs):  # type: ignore[override]
        raise RuntimeError("executor dead")


class _FailingSubmitExecutor(ThreadPoolExecutor):
    """Real ThreadPoolExecutor whose submit() returns an already-failed Future.

    Used to drive the warmup slot-failure warning path without mocking submit().
    """

    def submit(self, fn, *args, **kwargs):  # type: ignore[override]
        f: Future = Future()
        f.set_exception(RuntimeError("warmup failed"))
        return f


class _LogCapture:
    """Real logging-like object that records .warning() and .error() calls.

    Replaces pramanix.worker._log via monkeypatch for tests that need to verify
    that a warning or error was emitted — without using MagicMock.
    """

    def __init__(self) -> None:
        self.warnings: list[str] = []
        self.errors: list[str] = []

    def warning(self, msg: str, *args: object, **kw: object) -> None:
        self.warnings.append(msg % args if args else msg)

    def error(self, msg: str, *args: object, **kw: object) -> None:
        self.errors.append(msg % args if args else msg)

    def info(self, msg: str, *args: object, **kw: object) -> None:
        pass

    def debug(self, msg: str, *args: object, **kw: object) -> None:
        pass

    @property
    def warning_called(self) -> bool:
        return bool(self.warnings)

    @property
    def error_called(self) -> bool:
        return bool(self.errors)


# ═══════════════════════════════════════════════════════════════════════════════
# _worker_solve error paths
# ═══════════════════════════════════════════════════════════════════════════════


class TestWorkerSolveErrorPaths:
    def test_solver_timeout_error_returns_timeout_dict(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from pramanix.worker import _worker_solve

        err = SolverTimeoutError("ok", 100)

        def _raise(*a: object, **kw: object) -> None:
            raise err

        monkeypatch.setattr(_solver_mod, "solve", _raise)
        result = _worker_solve(_P, {"amount": Decimal("50")}, 100)

        assert result["status"] == "timeout"
        assert not result["allowed"]

    def test_pramanix_error_returns_error_dict(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from pramanix.exceptions import PramanixError
        from pramanix.worker import _worker_solve

        def _raise(*a: object, **kw: object) -> None:
            raise PramanixError("boom")

        monkeypatch.setattr(_solver_mod, "solve", _raise)
        result = _worker_solve(_P, {"amount": Decimal("50")}, 100)

        assert result["status"] == "error"
        assert not result["allowed"]

    def test_generic_exception_returns_error_dict(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from pramanix.worker import _worker_solve

        def _raise(*a: object, **kw: object) -> None:
            raise ValueError("oops")

        monkeypatch.setattr(_solver_mod, "solve", _raise)
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

    def test_drain_logs_warning_when_grace_period_exceeded(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Hanging ThreadPoolExecutor triggers grace-period warning."""
        executor = _HangingThreadExecutor()
        log_cap = _LogCapture()
        monkeypatch.setattr("pramanix.worker._log", log_cap)

        try:
            _drain_executor(executor, grace_s=0.05)
        finally:
            executor.release()  # Unblock background shutdown thread

        assert log_cap.warning_called

    def test_drain_calls_force_kill_for_process_executor(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Hanging ProcessPoolExecutor → _force_kill_processes is called."""
        executor = _HangingProcessExecutor()
        kill_calls: list[object] = []

        def _capture_kill(ex: object) -> None:
            kill_calls.append(ex)

        monkeypatch.setattr("pramanix.worker._force_kill_processes", _capture_kill)

        try:
            _drain_executor(executor, grace_s=0.05)
        finally:
            executor.release()

        assert len(kill_calls) == 1
        assert kill_calls[0] is executor


# ═══════════════════════════════════════════════════════════════════════════════
# _force_kill_processes
# ═══════════════════════════════════════════════════════════════════════════════


class TestForceKillProcesses:
    def test_alive_process_is_killed(self) -> None:
        proc = _FakeProcess(alive=True, pid=99999)
        container = _FakeProcessContainer({99999: proc})

        _force_kill_processes(container)  # type: ignore[arg-type]

        assert proc.kill_called

    def test_dead_process_is_not_killed(self) -> None:
        proc = _FakeProcess(alive=False, pid=1)
        container = _FakeProcessContainer({1: proc})

        _force_kill_processes(container)  # type: ignore[arg-type]

        assert not proc.kill_called

    def test_kill_exception_is_logged_not_raised(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        proc = _FakeProcess(
            alive=True, pid=42, kill_raises=OSError("Permission denied")
        )
        container = _FakeProcessContainer({42: proc})
        log_cap = _LogCapture()
        monkeypatch.setattr("pramanix.worker._log", log_cap)

        _force_kill_processes(container)  # type: ignore[arg-type]

        assert log_cap.error_called

    def test_no_processes_attribute_is_safe(self) -> None:
        """Executor without _processes → getattr returns {} → no kill."""
        container = _EmptyProcessContainer()
        _force_kill_processes(container)  # type: ignore[arg-type]  # must not raise


# ═══════════════════════════════════════════════════════════════════════════════
# WorkerPool lifecycle error paths
# ═══════════════════════════════════════════════════════════════════════════════


class TestWorkerPoolLifecycle:
    def test_spawn_raises_worker_error_on_make_executor_failure(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pool = WorkerPool(
            mode="async-thread",
            max_workers=1,
            max_decisions_per_worker=1000,
            warmup=False,
        )

        def _raise() -> None:
            raise OSError("disk full")

        monkeypatch.setattr(pool, "_make_executor", _raise)
        with pytest.raises(WorkerError, match="disk full"):
            pool.spawn()

    def test_spawn_is_idempotent_when_alive(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pool = WorkerPool(
            mode="async-thread",
            max_workers=1,
            max_decisions_per_worker=1000,
            warmup=False,
        )
        pool.spawn()

        make_calls: list[int] = []

        def _counting_make() -> None:
            make_calls.append(1)
            raise AssertionError("_make_executor must not be called on second spawn")

        monkeypatch.setattr(pool, "_make_executor", _counting_make)
        pool.spawn()  # No-op — already alive

        assert len(make_calls) == 0
        pool.shutdown()

    def test_shutdown_swallows_executor_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pool = WorkerPool(
            mode="async-thread",
            max_workers=1,
            max_decisions_per_worker=1000,
            warmup=False,
        )
        pool.spawn()

        def _raise_shutdown(*a: object, **kw: object) -> None:
            raise RuntimeError("shutdown error")

        monkeypatch.setattr(pool._executor, "shutdown", _raise_shutdown)
        log_cap = _LogCapture()
        monkeypatch.setattr("pramanix.worker._log", log_cap)
        pool.shutdown()

        assert log_cap.error_called

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

    def test_submit_executor_exception_returns_error_decision(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pool = WorkerPool(
            mode="async-thread",
            max_workers=1,
            max_decisions_per_worker=1000,
            warmup=False,
        )
        pool.spawn()
        # Replace the live executor with one whose submit() always raises
        pool._executor = _BrokenSubmitExecutor(max_workers=1)

        log_cap = _LogCapture()
        monkeypatch.setattr("pramanix.worker._log", log_cap)
        result = pool.submit_solve(_P, {"amount": Decimal("50")}, 5000)

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
        result = pool.submit_solve(_P, {"amount": Decimal("50")}, 5000)
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
    def test_warmup_slot_failure_is_logged_not_raised(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pool = WorkerPool(
            mode="async-thread",
            max_workers=1,
            max_decisions_per_worker=1000,
            warmup=True,
        )
        # Install a real executor whose submit() returns an already-failed Future
        pool._executor = _FailingSubmitExecutor(max_workers=1)
        log_cap = _LogCapture()
        monkeypatch.setattr("pramanix.worker._log", log_cap)

        pool._run_warmup()

        assert log_cap.warning_called
        pool._executor.shutdown(wait=False)


# ═══════════════════════════════════════════════════════════════════════════════
# WorkerPool._recycle — early return and executor failure
# ═══════════════════════════════════════════════════════════════════════════════


class TestWorkerPoolRecycle:
    def test_recycle_early_return_when_counter_reset(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Counter already reset before lock acquired → _make_executor not called."""
        pool = WorkerPool(
            mode="async-thread",
            max_workers=1,
            max_decisions_per_worker=10,
            warmup=False,
        )
        pool.spawn()

        make_calls: list[int] = []

        def _fail_if_called() -> None:
            make_calls.append(1)
            raise AssertionError("_make_executor should not be called")

        monkeypatch.setattr(pool, "_make_executor", _fail_if_called)
        pool._counter = 0  # Already reset — simulates race where another thread recycled
        pool._recycle()

        assert len(make_calls) == 0
        pool.shutdown()

    def test_recycle_swallows_executor_creation_failure(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
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

        def _raise() -> None:
            raise OSError("can't create")

        monkeypatch.setattr(pool, "_make_executor", _raise)
        log_cap = _LogCapture()
        monkeypatch.setattr("pramanix.worker._log", log_cap)
        pool._recycle()

        # Old executor should be restored
        assert pool._executor is original_executor
        assert log_cap.error_called
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
