# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Unit tests for worker.py dark paths — production-level, zero structural stubs.

Design principles
-----------------
* No _FakeProcess, _FakeProcessContainer, or structural stubs.  Every process
  test spawns a REAL multiprocessing.Process; psutil confirms OS-level kill.

* Solver error paths use REAL Z3 trigger conditions — not solver patches:
    - Timeout:      rlimit=1 forces Z3 resource exhaustion → unknown → timeout
    - PramanixError: bool value for a Real field → FieldTypeError (subclass)
    - Generic:      Policy.invariants() raising ValueError → bare-except handler

* Hanging executors: real ThreadPoolExecutor / ProcessPoolExecutor subclasses
  whose shutdown() blocks on a threading.Event.

* Executor failures: _BrokenSubmitExecutor / _FailingSubmitExecutor /
  _RaisingShutdownExecutor are real ThreadPoolExecutor subclasses.

* Log capture: _LogCapture is a real object, not a MagicMock.  monkeypatch
  replaces pramanix.worker._log for observability — not to bypass physics.

* The only remaining monkeypatches are:
    - pramanix.worker._log → _LogCapture (test observability)
    - pool._make_executor → error-injection via pool.mode = "unknown-mode"
      (direct attribute mutation, no module-level patch)
    - pool._executor direct replacement with _BrokenSubmitExecutor /
      _RaisingShutdownExecutor (attribute assignment, no method stub)
"""

from __future__ import annotations

import multiprocessing
import pickle
import threading
import time
import types
from concurrent.futures import Future, ProcessPoolExecutor, ThreadPoolExecutor
from decimal import Decimal

import psutil
import pytest

from pramanix import E, Field, Policy
from pramanix.exceptions import WorkerError
from pramanix.worker import (
    WorkerPool,
    _drain_executor,
    _force_kill_processes,
    _worker_solve,
)

# ═══════════════════════════════════════════════════════════════════════════════
# Shared policy — satisfiable for positive amounts
# ═══════════════════════════════════════════════════════════════════════════════

_f = Field("amount", Decimal, "Real")


class _P(Policy):
    @classmethod
    def fields(cls):  # type: ignore[override]
        return {"amount": _f}

    @classmethod
    def invariants(cls):  # type: ignore[override]
        return [(E(_f) >= 0).named("ok").explain("amount {amount} >= 0")]


class _BrokenPolicy(Policy):
    """Policy whose invariants() raises — exercises the generic exception handler."""

    @classmethod
    def fields(cls):  # type: ignore[override]
        return {"amount": _f}

    @classmethod
    def invariants(cls):  # type: ignore[override]
        raise ValueError("invariants method exploded")


# ═══════════════════════════════════════════════════════════════════════════════
# Real helper classes — no structural stubs
# ═══════════════════════════════════════════════════════════════════════════════


class _HangingThreadExecutor(ThreadPoolExecutor):
    """Real ThreadPoolExecutor whose shutdown() blocks until .release() is called."""

    def __init__(self) -> None:
        super().__init__(max_workers=1)
        self._barrier = threading.Event()

    def shutdown(self, wait: bool = True, **kwargs: object) -> None:  # type: ignore[override]
        self._barrier.wait(timeout=30)

    def release(self) -> None:
        self._barrier.set()


class _RaisingShutdownExecutor(ThreadPoolExecutor):
    """Real ThreadPoolExecutor whose shutdown() always raises RuntimeError.

    Used to exercise the _do_shutdown except-and-swallow path (lines 485-486)
    and the WorkerPool.shutdown() error-swallow path — without patching any method.
    """

    def shutdown(self, wait: bool = True, **kwargs: object) -> None:  # type: ignore[override]
        raise RuntimeError("executor shutdown crashed")


class _BrokenSubmitExecutor(ThreadPoolExecutor):
    """Real ThreadPoolExecutor whose submit() always raises RuntimeError."""

    def submit(self, fn, *args, **kwargs):  # type: ignore[override]
        raise RuntimeError("executor dead")


class _FailingSubmitExecutor(ThreadPoolExecutor):
    """Real ThreadPoolExecutor whose submit() returns an already-failed Future."""

    def submit(self, fn, *args, **kwargs):  # type: ignore[override]
        f: Future = Future()
        f.set_exception(RuntimeError("warmup failed"))
        return f


class _LogCapture:
    """Real logging-like object that records warning/error/info/debug calls.

    Not a mock — has real method bodies that record formatted messages.
    monkeypatch replaces pramanix.worker._log for test observability only.
    """

    def __init__(self) -> None:
        self.warnings: list[str] = []
        self.errors: list[str] = []
        self.debugs: list[str] = []

    def warning(self, msg: str, *args: object, **kw: object) -> None:
        self.warnings.append(msg % args if args else msg)

    def error(self, msg: str, *args: object, **kw: object) -> None:
        self.errors.append(msg % args if args else msg)

    def info(self, msg: str, *args: object, **kw: object) -> None:
        pass

    def debug(self, msg: str, *args: object, **kw: object) -> None:
        self.debugs.append(msg % args if args else msg)

    @property
    def warning_called(self) -> bool:
        return bool(self.warnings)

    @property
    def error_called(self) -> bool:
        return bool(self.errors)

    @property
    def debug_called(self) -> bool:
        return bool(self.debugs)


# ═══════════════════════════════════════════════════════════════════════════════
# Real process helpers
# ═══════════════════════════════════════════════════════════════════════════════


def _sleeper() -> None:
    """Long-running target for real worker processes — sleeps until killed."""
    import time as _t

    _t.sleep(30)


def _noop() -> None:
    """No-op target that exits immediately — used for dead-process tests."""


def _wait_for_processes(
    executor: ProcessPoolExecutor, timeout: float = 8.0
) -> dict:
    """Block until executor._processes is non-empty; return a stable copy.

    ProcessPoolExecutor (spawn context) takes up to ~500 ms on Windows to
    start its first worker.  Polling is necessary to avoid a race.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        procs = getattr(executor, "_processes", {})
        if procs:
            return dict(procs)
        time.sleep(0.05)
    raise TimeoutError("Worker process did not start within timeout")


def _assert_pid_dead(pid: int) -> None:
    """Assert that *pid* is no longer an active OS process.

    Accepts NoSuchProcess (fully gone) and STATUS_ZOMBIE / STATUS_DEAD
    (reaped by OS but still in table).  Any other running status fails.
    """
    try:
        p = psutil.Process(pid)
        status = p.status()
        assert status in (
            psutil.STATUS_ZOMBIE,
            psutil.STATUS_DEAD,
        ), f"PID {pid} still active (status={status!r}) after force-kill"
    except psutil.NoSuchProcess:
        pass  # Fully gone — ideal


# ═══════════════════════════════════════════════════════════════════════════════
# _worker_solve error paths — real Z3 trigger conditions, no solver patches
# ═══════════════════════════════════════════════════════════════════════════════


class TestWorkerSolveErrorPaths:
    def test_solver_timeout_returns_timeout_dict(self) -> None:
        """rlimit=1 exhausts Z3's resource budget on any formula — returns unknown.

        Z3 returns ``unknown`` when rlimit is exhausted, regardless of formula
        complexity. ``_fast_check`` converts this to SolverTimeoutError.
        ``_worker_solve`` catches it and returns a timeout-status dict.

        No solver patching — the real Z3 engine is exercised.
        """
        result = _worker_solve(_P, {"amount": Decimal("50")}, 5000, rlimit=1)
        assert result["status"] == "timeout"
        assert not result["allowed"]

    def test_pramanix_error_returns_error_dict(self) -> None:
        """bool value for a Real field raises FieldTypeError (PramanixError subclass).

        ``_build_bindings`` enforces type safety: bool is a subclass of int in
        Python, and passing it for a Real field is an explicit guard against
        silent precision loss.  ``_worker_solve`` catches PramanixError and
        returns an error-status dict.

        No solver patching — the real type-validation code path is exercised.
        """
        result = _worker_solve(_P, {"amount": True}, 5000)
        assert result["status"] == "error"
        assert "bool" in result["explanation"]

    def test_generic_exception_returns_error_dict(self) -> None:
        """Policy.invariants() raising ValueError exercises the bare-except handler.

        ``_worker_solve`` has a fail-safe ``except Exception`` that prevents
        raw exceptions from escaping the worker boundary.  _BrokenPolicy
        triggers this path via a real ValueError from invariants().

        No solver patching — the real exception-propagation path is exercised.
        """
        result = _worker_solve(_BrokenPolicy, {"amount": Decimal("10")}, 5000)
        assert result["status"] == "error"
        assert "ValueError" in result["explanation"]


# ═══════════════════════════════════════════════════════════════════════════════
# _drain_executor
# ═══════════════════════════════════════════════════════════════════════════════


class TestDrainExecutor:
    def test_drain_completes_when_executor_shuts_down_quickly(self) -> None:
        """Clean executor shuts down within grace period — no timeout."""
        executor = ThreadPoolExecutor(max_workers=1)
        _drain_executor(executor, grace_s=5.0)

    def test_drain_swallows_shutdown_exception(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """executor.shutdown() raising is swallowed; exception is debug-logged.

        _RaisingShutdownExecutor.shutdown() raises RuntimeError immediately.
        _drain_executor must complete without propagating the exception and
        must emit a debug log message naming the exception.
        """
        executor = _RaisingShutdownExecutor(max_workers=1)
        log_cap = _LogCapture()
        monkeypatch.setattr("pramanix.worker._log", log_cap)
        _drain_executor(executor, grace_s=5.0)  # Must not raise
        assert log_cap.debug_called, (
            "executor.shutdown exception must be debug-logged"
        )

    def test_drain_logs_warning_when_grace_period_exceeded(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Hanging executor exceeds grace period — warning is emitted."""
        executor = _HangingThreadExecutor()
        log_cap = _LogCapture()
        monkeypatch.setattr("pramanix.worker._log", log_cap)
        try:
            _drain_executor(executor, grace_s=0.05)
        finally:
            executor.release()
        assert log_cap.warning_called

    def test_drain_kills_processes_when_grace_period_exceeded(self) -> None:
        """Hanging ProcessPoolExecutor: child processes are force-killed after grace.

        A real sleeping worker is spawned via ProcessPoolExecutor.  _drain_executor
        times out (grace_s=0.1 << worker's 30s sleep) and calls _force_kill_processes.
        psutil confirms the OS-level process no longer runs.
        """
        executor = ProcessPoolExecutor(max_workers=1)
        executor.submit(_sleeper)
        procs = _wait_for_processes(executor)

        alive_pids = [p.pid for p in procs.values() if p.is_alive()]
        assert alive_pids, "No worker process started"

        _drain_executor(executor, grace_s=0.1)
        time.sleep(0.5)  # Allow SIGKILL / TerminateProcess to propagate

        for pid in alive_pids:
            _assert_pid_dead(pid)

        executor.shutdown(wait=False)


# ═══════════════════════════════════════════════════════════════════════════════
# _force_kill_processes — real processes, psutil verification
# ═══════════════════════════════════════════════════════════════════════════════


class TestForceKillProcesses:
    def test_alive_process_is_killed(self) -> None:
        """_force_kill_processes sends kill signal to live worker processes.

        A real ProcessPoolExecutor starts a sleeping worker.  After
        _force_kill_processes runs, psutil confirms the OS process is gone.
        No boolean flags — the OS process table is the ground truth.
        """
        executor = ProcessPoolExecutor(max_workers=1)
        executor.submit(_sleeper)
        procs = _wait_for_processes(executor)

        alive_pids = [p.pid for p in procs.values() if p.is_alive()]
        assert alive_pids, "No worker process started"

        _force_kill_processes(executor)
        time.sleep(0.5)

        for pid in alive_pids:
            _assert_pid_dead(pid)

        executor.shutdown(wait=False)

    def test_dead_process_is_not_killed(self) -> None:
        """_force_kill_processes skips processes that have already exited.

        A real multiprocessing.Process running a no-op target exits immediately.
        After it exits, is_alive() == False.  _force_kill_processes must not
        attempt to kill it and must not raise.
        """
        proc = multiprocessing.Process(target=_noop)
        proc.start()
        # Poll until dead — more robust than a fixed join timeout under load on
        # Windows where spawning a new Python interpreter can take several seconds.
        deadline = time.monotonic() + 30.0
        while proc.is_alive() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert not proc.is_alive(), "No-op process did not exit within 30 s"

        container = types.SimpleNamespace(_processes={proc.pid: proc})
        _force_kill_processes(container)  # type: ignore[arg-type]  # Must not raise

    def test_kill_exception_is_logged_not_raised(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """kill() raising on an alive process is logged as an error, not propagated.

        A real multiprocessing.Process is started.  Its kill() method is overridden
        at the INSTANCE level to raise OSError — simulating OS EPERM (permission
        denied), which occurs when a process is owned by a different user.  The
        container holds the real PID and the real is_alive() state.

        This is the minimum intervention needed to test a genuine OS boundary
        condition.  No module-level patching — only the single-process instance's
        kill() is overridden.
        """
        proc = multiprocessing.Process(target=_sleeper)
        proc.start()
        assert proc.is_alive()

        def _raise_kill() -> None:
            raise OSError("Operation not permitted")

        proc.kill = _raise_kill  # type: ignore[method-assign]  # instance-level only

        container = types.SimpleNamespace(_processes={proc.pid: proc})
        log_cap = _LogCapture()
        monkeypatch.setattr("pramanix.worker._log", log_cap)

        _force_kill_processes(container)  # type: ignore[arg-type]
        assert log_cap.error_called

        # Restore and reap to avoid orphaned process
        del proc.kill  # removes instance override — falls back to class method
        proc.kill()
        proc.join(timeout=5)

    def test_no_processes_attribute_is_safe(self) -> None:
        """Executor without _processes attribute → empty dict → no action."""
        container = types.SimpleNamespace()  # No _processes attribute
        _force_kill_processes(container)  # type: ignore[arg-type]  # Must not raise


# ═══════════════════════════════════════════════════════════════════════════════
# WorkerPool lifecycle
# ═══════════════════════════════════════════════════════════════════════════════


class TestWorkerPoolLifecycle:
    def test_spawn_raises_worker_error_on_make_executor_failure(self) -> None:
        """Unknown mode causes _make_executor to raise WorkerError.

        spawn() wraps any _make_executor exception in WorkerError.
        This exercises the spawn() exception handler via the REAL _make_executor
        code path — no method patching.
        """
        pool = WorkerPool(
            mode="unknown-mode",
            max_workers=1,
            max_decisions_per_worker=1000,
            warmup=False,
        )
        with pytest.raises(WorkerError):
            pool.spawn()

    def test_spawn_is_idempotent_when_alive(self) -> None:
        """Second spawn() on an already-alive pool is a no-op (same executor object)."""
        pool = WorkerPool(
            mode="async-thread",
            max_workers=1,
            max_decisions_per_worker=1000,
            warmup=False,
        )
        pool.spawn()
        exec_before = pool._executor
        pool.spawn()  # Must be a no-op
        assert pool._executor is exec_before
        pool.shutdown()

    def test_shutdown_swallows_executor_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """WorkerPool.shutdown() swallows executor errors and logs them.

        pool._executor is replaced with a _RaisingShutdownExecutor (real subclass).
        No method patching — the assignment is direct attribute mutation.
        """
        pool = WorkerPool(
            mode="async-thread",
            max_workers=1,
            max_decisions_per_worker=1000,
            warmup=False,
        )
        pool.spawn()

        # Swap in a real executor whose shutdown() raises — direct assignment
        old = pool._executor
        old.shutdown(wait=False)
        pool._executor = _RaisingShutdownExecutor(max_workers=1)

        log_cap = _LogCapture()
        monkeypatch.setattr("pramanix.worker._log", log_cap)
        pool.shutdown()

        assert log_cap.error_called

    def test_shutdown_noop_when_not_alive(self) -> None:
        """shutdown() on an unspawned pool is a no-op — must not raise."""
        pool = WorkerPool(
            mode="async-thread",
            max_workers=1,
            max_decisions_per_worker=1000,
            warmup=False,
        )
        pool.shutdown()


# ═══════════════════════════════════════════════════════════════════════════════
# WorkerPool.submit_solve
# ═══════════════════════════════════════════════════════════════════════════════


class TestWorkerPoolSubmitSolve:
    def test_submit_when_not_alive_returns_error_decision(self) -> None:
        """submit_solve on an unspawned pool returns an error Decision."""
        pool = WorkerPool(
            mode="async-thread",
            max_workers=1,
            max_decisions_per_worker=1000,
            warmup=False,
        )
        result = pool.submit_solve(_P, {"amount": Decimal("50")}, 5000)
        assert not result.allowed
        assert "not running" in result.explanation.lower()

    def test_submit_executor_exception_returns_error_decision(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Executor submit() raising is caught — returns an error Decision.

        pool._executor is replaced with _BrokenSubmitExecutor (real subclass).
        Direct attribute assignment — no method patching.
        """
        pool = WorkerPool(
            mode="async-thread",
            max_workers=1,
            max_decisions_per_worker=1000,
            warmup=False,
        )
        pool.spawn()
        old = pool._executor
        old.shutdown(wait=False)
        pool._executor = _BrokenSubmitExecutor(max_workers=1)

        log_cap = _LogCapture()
        monkeypatch.setattr("pramanix.worker._log", log_cap)
        result = pool.submit_solve(_P, {"amount": Decimal("50")}, 5000)

        assert not result.allowed
        assert result.explanation is not None
        pool.shutdown()

    def test_submit_recycles_after_max_decisions(self) -> None:
        """Pool recycles executor after max_decisions_per_worker calls."""
        pool = WorkerPool(
            mode="async-thread",
            max_workers=1,
            max_decisions_per_worker=1,  # recycle after every call
            warmup=False,
        )
        pool.spawn()
        result = pool.submit_solve(_P, {"amount": Decimal("50")}, 5000)
        assert result.allowed
        assert pool._alive
        pool.shutdown()


# ═══════════════════════════════════════════════════════════════════════════════
# WorkerPool._make_executor — mode dispatch
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
# WorkerPool._run_warmup
# ═══════════════════════════════════════════════════════════════════════════════


class TestWorkerPoolRunWarmup:
    def test_warmup_slot_failure_is_logged_not_raised(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Warmup Future that fails logs a warning — does not raise.

        _FailingSubmitExecutor.submit() returns an already-failed Future.
        pool._executor is replaced directly (no method patch).
        """
        pool = WorkerPool(
            mode="async-thread",
            max_workers=1,
            max_decisions_per_worker=1000,
            warmup=True,
        )
        pool._executor = _FailingSubmitExecutor(max_workers=1)

        log_cap = _LogCapture()
        monkeypatch.setattr("pramanix.worker._log", log_cap)
        pool._run_warmup()

        assert log_cap.warning_called
        pool._executor.shutdown(wait=False)


# ═══════════════════════════════════════════════════════════════════════════════
# WorkerPool._recycle
# ═══════════════════════════════════════════════════════════════════════════════


class TestWorkerPoolRecycle:
    def test_recycle_early_return_when_counter_reset(self) -> None:
        """Counter already < max → _recycle returns early without swapping executor."""
        pool = WorkerPool(
            mode="async-thread",
            max_workers=1,
            max_decisions_per_worker=10,
            warmup=False,
        )
        pool.spawn()
        exec_before = pool._executor

        pool._counter = (
            0  # Already reset — simulates a race where another thread recycled
        )
        pool._recycle()  # Must be a no-op

        assert pool._executor is exec_before
        pool.shutdown()

    def test_recycle_swallows_executor_creation_failure(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """New executor creation fails → old executor is restored, error is logged.

        pool.mode is changed to "unknown-mode" AFTER spawn() so that _recycle()
        triggers _make_executor() → WorkerError without patching _make_executor.
        """
        pool = WorkerPool(
            mode="async-thread",
            max_workers=1,
            max_decisions_per_worker=1,
            warmup=False,
        )
        pool.spawn()
        original_executor = pool._executor
        pool._counter = 1  # Trigger recycle threshold

        # Direct mode mutation — _recycle's _make_executor call will raise WorkerError
        pool.mode = "unknown-mode"
        log_cap = _LogCapture()
        monkeypatch.setattr("pramanix.worker._log", log_cap)
        pool._recycle()

        # Old executor must be restored on failure
        assert pool._executor is original_executor
        assert log_cap.error_called

        # Restore mode so shutdown() works
        pool.mode = "async-thread"
        pool.shutdown()

    def test_recycle_concurrent_double_trigger_only_recycles_once(self) -> None:
        """Two threads both call _recycle() concurrently; only one does the swap.

        The guard `if self._counter < max_decisions_per_worker: return` inside
        the lock must ensure the second thread finds a reset counter and bails
        without swapping the executor a second time.
        """
        import threading

        pool = WorkerPool(
            mode="async-thread",
            max_workers=1,
            max_decisions_per_worker=5,
            warmup=False,
        )
        pool.spawn()
        pool._counter = 5  # Both threads will see threshold met

        recycle_calls: list[int] = []
        original_make_executor = pool._make_executor

        def _counting_make_executor() -> object:
            recycle_calls.append(1)
            return original_make_executor()

        pool._make_executor = _counting_make_executor  # type: ignore[method-assign]

        barrier = threading.Barrier(2)

        def _thread_recycle() -> None:
            barrier.wait()  # Both threads start simultaneously
            pool._recycle()

        t1 = threading.Thread(target=_thread_recycle)
        t2 = threading.Thread(target=_thread_recycle)
        t1.start()
        t2.start()
        t1.join(timeout=10)
        t2.join(timeout=10)

        # Exactly one recycle must have executed
        assert len(recycle_calls) == 1, (
            f"Expected 1 recycle, got {len(recycle_calls)} — "
            "double-recycle race condition detected"
        )
        assert pool._counter == 0  # Counter was reset by the winner
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


# ═══════════════════════════════════════════════════════════════════════════════
# HMAC Result Integrity Seal — _EphemeralKey, _worker_solve_sealed, _unseal_decision
# ═══════════════════════════════════════════════════════════════════════════════


class TestEphemeralKey:
    """_EphemeralKey must be log-safe and non-picklable."""

    def test_repr_is_redacted(self) -> None:
        from pramanix.worker import _EphemeralKey

        key = _EphemeralKey(b"\xab" * 32)
        assert repr(key) == "<EphemeralKey: redacted>"
        assert str(key) == "<EphemeralKey: redacted>"

    def test_bytes_returns_raw_key(self) -> None:
        from pramanix.worker import _EphemeralKey

        raw = b"\x01\x02\x03" * 10 + b"\x04\x05"
        key = _EphemeralKey(raw)
        assert key.bytes == raw

    def test_pickle_raises_type_error(self) -> None:
        """_EphemeralKey.__reduce__ must raise TypeError to prevent disk serialisation."""
        from pramanix.worker import _EphemeralKey

        key = _EphemeralKey(b"secret" * 5)
        with pytest.raises(TypeError, match="serialised to disk"):
            pickle.dumps(key)

    def test_module_level_seal_key_is_ephemeral_key(self) -> None:
        from pramanix.worker import _RESULT_SEAL_KEY, _EphemeralKey

        assert isinstance(_RESULT_SEAL_KEY, _EphemeralKey)
        assert len(_RESULT_SEAL_KEY.bytes) == 32


class TestWorkerSolveSealedAndUnseal:
    """_worker_solve_sealed / _unseal_decision IPC integrity contract."""

    def test_sealed_envelope_has_payload_and_tag_keys(self) -> None:
        import secrets

        from pramanix.worker import _worker_solve_sealed

        seal_key = secrets.token_bytes(32)
        envelope = _worker_solve_sealed(_P, {"amount": Decimal("50")}, 5000, seal_key)
        assert "_p" in envelope
        assert "_t" in envelope
        assert isinstance(envelope["_p"], str)
        assert isinstance(envelope["_t"], str)

    def test_unseal_returns_correct_dict_for_valid_envelope(self) -> None:
        from pramanix.worker import _RESULT_SEAL_KEY, _unseal_decision, _worker_solve_sealed

        envelope = _worker_solve_sealed(
            _P, {"amount": Decimal("50")}, 5000, _RESULT_SEAL_KEY.bytes
        )
        result = _unseal_decision(envelope)
        assert "allowed" in result

    def test_unseal_raises_on_tampered_tag(self) -> None:
        """Flipping one character in _t must raise ValueError."""
        from pramanix.worker import _RESULT_SEAL_KEY, _unseal_decision, _worker_solve_sealed

        envelope = _worker_solve_sealed(
            _P, {"amount": Decimal("50")}, 5000, _RESULT_SEAL_KEY.bytes
        )
        # Flip last character of HMAC tag
        bad_tag = envelope["_t"][:-1] + ("a" if envelope["_t"][-1] != "a" else "b")
        tampered = {**envelope, "_t": bad_tag}
        with pytest.raises(ValueError, match="HMAC mismatch"):
            _unseal_decision(tampered)

    def test_unseal_raises_on_tampered_payload(self) -> None:
        """Modifying _p while leaving _t intact must raise ValueError."""
        from pramanix.worker import _RESULT_SEAL_KEY, _unseal_decision, _worker_solve_sealed

        envelope = _worker_solve_sealed(
            _P, {"amount": Decimal("50")}, 5000, _RESULT_SEAL_KEY.bytes
        )
        # Append a byte to the payload (tag now mismatches)
        tampered = {**envelope, "_p": envelope["_p"] + "X"}
        with pytest.raises(ValueError, match="HMAC mismatch"):
            _unseal_decision(tampered)

    def test_unseal_raises_key_error_on_missing_payload_key(self) -> None:
        """Envelope missing _p raises KeyError."""
        from pramanix.worker import _unseal_decision

        with pytest.raises(KeyError):
            _unseal_decision({"_t": "abc123"})

    def test_unseal_raises_key_error_on_missing_tag_key(self) -> None:
        """Envelope missing _t raises KeyError."""
        from pramanix.worker import _unseal_decision

        with pytest.raises(KeyError):
            _unseal_decision({"_p": '{"allowed": false}'})

    def test_wrong_seal_key_raises_value_error(self) -> None:
        """Envelope signed with key A must fail verification with key B."""
        import secrets

        key_a = secrets.token_bytes(32)
        key_b = secrets.token_bytes(32)
        # Ensure the two keys differ (astronomically unlikely to collide but guard anyway)
        assert key_a != key_b

        import pramanix.worker as _worker_mod
        from pramanix.worker import _EphemeralKey, _unseal_decision, _worker_solve_sealed

        # Temporarily swap the module-level seal key so _unseal_decision uses key_b
        original_key = _worker_mod._RESULT_SEAL_KEY
        _worker_mod._RESULT_SEAL_KEY = _EphemeralKey(key_b)
        try:
            envelope = _worker_solve_sealed(
                _P, {"amount": Decimal("50")}, 5000, key_a  # signed with key_a
            )
            with pytest.raises(ValueError, match="HMAC mismatch"):
                _unseal_decision(envelope)  # verified with key_b
        finally:
            _worker_mod._RESULT_SEAL_KEY = original_key


class TestWorkerPoolHmacFailureIntegration:
    """WorkerPool.submit_solve in async-process mode handles HMAC failure safely."""

    def test_tampered_sealed_result_returns_error_decision(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When the sealed envelope is tampered, submit_solve must return an error Decision.

        A real Future is pre-loaded with a tampered envelope dict (wrong tag).
        pool._executor is replaced with a real ThreadPoolExecutor subclass whose
        submit() returns this Future — no method patching.

        The pool mode is forced to "async-process" so the HMAC verification path
        is taken.  Because the tag is wrong, _unseal_decision raises ValueError,
        which submit_solve catches and converts to Decision.error().
        """
        from concurrent.futures import Future

        class _TamperedSealedExecutor(ThreadPoolExecutor):
            """Real ThreadPoolExecutor whose submit returns a Future with bad HMAC."""

            def submit(self, fn, *args, **kwargs):  # type: ignore[override]
                f: Future = Future()
                f.set_result({"_p": '{"allowed":true}', "_t": "badhmacsignature"})
                return f

        pool = WorkerPool(
            mode="async-process",
            max_workers=1,
            max_decisions_per_worker=1000,
            warmup=False,
        )
        pool.spawn()
        old = pool._executor
        old.shutdown(wait=False)
        pool._executor = _TamperedSealedExecutor(max_workers=1)

        log_cap = _LogCapture()
        monkeypatch.setattr("pramanix.worker._log", log_cap)

        result = pool.submit_solve(_P, {"amount": Decimal("50")}, 5000)

        assert not result.allowed, "Tampered IPC result must never produce an ALLOW decision"
        assert log_cap.error_called, "HMAC seal violation must be logged at ERROR level"
        assert "integrity" in " ".join(log_cap.errors).lower() or "hmac" in " ".join(
            log_cap.errors
        ).lower()
        pool.shutdown()
