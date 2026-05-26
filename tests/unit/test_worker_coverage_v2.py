# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Targeted coverage tests for worker.py — round 2.

Covers:
  _worker_prom_register       — cache-hit path
  _worker_prometheus_register_all — ValueError branch (no sys.modules pop)
  AdaptiveConcurrencyLimiter  — all uncovered paths
  _ppid_watchdog              — stable-PPID loop, counter=None exception, exit
  _warmup_worker              — subprocess ppid watchdog start, unsat check,
                                counter=None except path
  _force_kill_processes       — outer except path
  WorkerPool._emergency_shutdown — except Exception path, is_finalizing=True path
  WorkerPool.shutdown         — finalizer.detach, finalizer=None (790->792)
  WorkerPool.submit_solve     — rate_limited, process mode success, WorkerError re-raise
  WorkerPool._recycle         — warmup=True paths, no _active_executor_cell (967->972)
  WorkerPool.executor         — raise when not spawned

Design principles
-----------------
* NO sys.modules pop/restore — it corrupts concurrent.futures.process state on
  Python 3.13 spawn-context pools, causing PicklingError in subsequent tests.
* NO ProcessPoolExecutor creation except in tests that explicitly need it.
  Process-mode paths are tested by manually initialising WorkerPool._executor
  with a synchronous ThreadPoolExecutor shim (avoids any OS-process spawning).
* All branch misses (325->322, 343->322, 457->461, 731->747, 790->792, 967->972)
  are covered by targeted monkeypatching or manual pool initialisation.
"""

from __future__ import annotations

import multiprocessing
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from decimal import Decimal
from typing import Any

import pytest

from pramanix import E, Field, Policy
from pramanix.decision import SolverStatus
from pramanix.exceptions import WorkerError
from pramanix.worker import (
    AdaptiveConcurrencyLimiter,
    WorkerPool,
    _warmup_worker,
)

# ── Shared policy ─────────────────────────────────────────────────────────────

_f = Field("amount", Decimal, "Real")


class _P(Policy):
    @classmethod
    def fields(cls):  # type: ignore[override]
        return {"amount": _f}

    @classmethod
    def invariants(cls):  # type: ignore[override]
        return [(E(_f) >= 0).named("ok").explain("amount >= 0")]


# ── Prometheus registration ───────────────────────────────────────────────────


class TestWorkerPrometheusRegistration:
    def test_worker_prom_register_cache_hit(self) -> None:
        """Cache-hit path in _worker_prom_register: second call returns cached metric.

        _worker_prom_register(name, description) is defined inside the `try` block
        only when prometheus_client is available.  Calling it with an already-
        registered name returns the cached Counter without creating a new one.
        """
        import pramanix.worker as _wk

        if not hasattr(_wk, "_worker_prom_register"):
            pytest.skip("prometheus_client not installed")
        if _wk._WORKER_WARMUP_FAILURE_COUNTER is None:
            pytest.skip("prometheus counter was not registered (ValueError during import)")

        existing = _wk._WORKER_WARMUP_FAILURE_COUNTER
        result = _wk._worker_prom_register(
            "pramanix_worker_warmup_failures_total",
            "Number of Z3 worker warmup failures",
        )
        assert result is existing, "cache hit must return the same Counter object"

    def test_prometheus_register_all_value_error_branch(
        self, monkeypatch: pytest.MonkeyPatch, caplog: Any
    ) -> None:
        """ValueError inside _worker_prometheus_register_all is caught and logged.

        Patches _worker_prom_register to raise ValueError so the except block
        in _worker_prometheus_register_all runs and logs a warning.

        No sys.modules pop — avoids corrupting concurrent.futures.process state
        on Python 3.13 spawn-context pools (which causes PicklingError in
        subsequent ProcessPoolExecutor tests).

        When ValueError is raised inside the try block before any assignment
        completes, the counters retain their previous values (they are not reset
        to None).  The only observable side-effect is the warning log.
        """
        import logging

        import pramanix.worker as _wk

        if not hasattr(_wk, "_worker_prometheus_register_all"):
            pytest.skip("prometheus_client not installed")

        def _raising_register(name: str, description: str) -> None:
            raise ValueError("Duplicate timeseries — simulated test error")

        monkeypatch.setattr(_wk, "_worker_prom_register", _raising_register)

        with caplog.at_level(logging.WARNING, logger="pramanix.worker"):
            _wk._worker_prometheus_register_all()  # must not raise

        assert any(
            "prometheus metric registration error" in r.message.lower() for r in caplog.records
        ), "ValueError must be caught and logged as a warning"


# ── AdaptiveConcurrencyLimiter ────────────────────────────────────────────────


class TestAdaptiveConcurrencyLimiter:
    def test_max_outstanding_param_provided(self) -> None:
        """When max_outstanding is given explicitly it is stored directly."""
        limiter = AdaptiveConcurrencyLimiter(max_workers=4, max_outstanding=3)
        assert limiter._max_outstanding == 3

    def test_active_workers_property(self) -> None:
        """active_workers property returns _active counter."""
        limiter = AdaptiveConcurrencyLimiter(max_workers=4)
        assert limiter.active_workers == 0
        limiter.acquire()
        assert limiter.active_workers == 1
        limiter.release(10.0)

    def test_shed_count_property(self) -> None:
        """shed_count property returns _shed_count."""
        limiter = AdaptiveConcurrencyLimiter(max_workers=1, max_outstanding=0)
        assert limiter.shed_count == 0
        limiter.acquire()  # immediately sheds (max_outstanding=0)
        assert limiter.shed_count == 1

    def test_hard_cap_sheds_at_max_outstanding(self) -> None:
        """acquire() returns False when _active >= _max_outstanding."""
        limiter = AdaptiveConcurrencyLimiter(max_workers=4, max_outstanding=0)
        result = limiter.acquire()
        assert result is False
        assert limiter.shed_count == 1

    def test_shed_conditions_sheds_when_high_p99_and_saturated(self) -> None:
        """acquire() sheds when both conditions are met simultaneously.

        Strategy:
        - max_workers=1, worker_pct=50 → saturation at 50% (just 1 active worker)
        - Fill the 60-s latency window with 15 entries of 9999 ms (>> threshold 200 ms)
        - Increment _active to 1 so saturation_pct = 100% >= 50%
        - acquire() checks shed conditions → p99 > threshold → shed
        """
        limiter = AdaptiveConcurrencyLimiter(
            max_workers=1,
            latency_threshold_ms=200.0,
            worker_pct=50.0,
            max_outstanding=100,
        )
        now = time.monotonic()
        for _ in range(15):
            limiter._latency_window.append((now, 9999.0))
        limiter._active = 1
        result = limiter.acquire()
        assert result is False
        assert limiter.shed_count == 1

    def test_release_evicts_old_latency_entries(self) -> None:
        """release() removes entries older than 60 seconds from the window."""
        limiter = AdaptiveConcurrencyLimiter(max_workers=4)
        old_ts = time.monotonic() - 120.0
        limiter._latency_window.append((old_ts, 50.0))
        limiter._active = 1

        limiter.release(latency_ms=5.0)
        assert len(limiter._latency_window) == 1
        _, latency = limiter._latency_window[0]
        assert latency == 5.0

    def test_compute_p99_with_ten_or_more_entries(self) -> None:
        """_compute_p99 returns a float when window has >= 10 entries."""
        limiter = AdaptiveConcurrencyLimiter(max_workers=4)
        now = time.monotonic()
        for i in range(15):
            limiter._latency_window.append((now, float(i * 10)))
        with limiter._lock:
            p99 = limiter._compute_p99()
        assert p99 is not None
        assert isinstance(p99, float)

    def test_check_shed_conditions_returns_true_when_both_met(self) -> None:
        """_check_shed_conditions returns True when both conditions are met."""
        limiter = AdaptiveConcurrencyLimiter(
            max_workers=1,
            latency_threshold_ms=10.0,
            worker_pct=50.0,
            max_outstanding=100,
        )
        now = time.monotonic()
        for _ in range(15):
            limiter._latency_window.append((now, 9999.0))
        limiter._active = 1
        with limiter._lock:
            result = limiter._check_shed_conditions()
        assert result is True

    def test_env_var_defaults_used_when_params_are_none(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Env vars PRAMANIX_SHED_LATENCY_THRESHOLD_MS and WORKER_PCT are read."""
        monkeypatch.setenv("PRAMANIX_SHED_LATENCY_THRESHOLD_MS", "500")
        monkeypatch.setenv("PRAMANIX_SHED_WORKER_PCT", "75")
        monkeypatch.setenv("PRAMANIX_MAX_OUTSTANDING", "32")
        limiter = AdaptiveConcurrencyLimiter(max_workers=4)
        assert limiter._latency_threshold == 500.0
        assert limiter._worker_pct == 75.0
        assert limiter._max_outstanding == 32


# ── _ppid_watchdog ────────────────────────────────────────────────────────────


class TestPpidWatchdog:
    def test_ppid_watchdog_stable_loop_exception_and_exit_paths(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """_ppid_watchdog: stable-PPID loop (325->322), counter=None except (343->322), exit.

        Call sequence for os.getppid():
          call 1  initial_ppid = stable_ppid          (setup)
          call 2  returns stable_ppid                 → False branch (325->322 covered)
          call 3  raises RuntimeError                 → except block; counter=None → 343->322
          call 4  returns stable_ppid + 1             → os._exit(0) → exit path

        Monkeypatching _WORKER_WATCHDOG_ERROR_COUNTER to None ensures the False
        branch of `if counter is not None:` (343->322) is taken on call 3.
        """
        import os
        import time as _time_mod

        import pramanix.worker as _wk_mod
        from pramanix.worker import _ppid_watchdog

        call_count = [0]
        stable_ppid = 99999

        def _fake_getppid() -> int:
            call_count[0] += 1
            if call_count[0] == 1:
                return stable_ppid  # initial_ppid assignment
            elif call_count[0] == 2:
                return stable_ppid  # PPID unchanged → False branch (325->322)
            elif call_count[0] == 3:
                raise RuntimeError("test: forced watchdog exception")
            else:
                return stable_ppid + 1  # PPID changed → os._exit(0)

        exit_called = threading.Event()

        def _fake_exit(code: int) -> None:
            exit_called.set()
            raise SystemExit(code)

        monkeypatch.setattr(os, "getppid", _fake_getppid)
        monkeypatch.setattr(os, "_exit", _fake_exit)
        monkeypatch.setattr(_time_mod, "sleep", lambda _s: None)
        # Set counter to None so the False branch of `if counter is not None:` runs.
        monkeypatch.setattr(_wk_mod, "_WORKER_WATCHDOG_ERROR_COUNTER", None)

        def _run_watchdog() -> None:
            try:
                _ppid_watchdog()
            except SystemExit:
                pass

        wdog_thread = threading.Thread(
            target=_run_watchdog, daemon=True, name="test-ppid-watchdog-full"
        )
        wdog_thread.start()

        assert exit_called.wait(timeout=5.0), "_ppid_watchdog did not call os._exit within 5 s"
        wdog_thread.join(timeout=2.0)


# ── _warmup_worker — subprocess ppid watchdog start ──────────────────────────


class TestWarmupWorkerSubprocessContext:
    def test_warmup_worker_starts_ppid_watchdog_in_subprocess_context(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """ppid watchdog thread is started when process name != 'MainProcess'.

        Fakes the subprocess context by replacing current_process() with a
        process object whose name != 'MainProcess'.  Passes a _solver_factory that
        raises immediately so _warmup_worker exits the try block quickly without
        running 8 Z3 patterns, yet still traverses the watchdog-start lines first.
        """

        class _FakeChildProcess:
            name = "SpawnProcess-1"

        monkeypatch.setattr(multiprocessing, "current_process", lambda: _FakeChildProcess())

        wdog_started: list[str] = []
        _real_thread_init = threading.Thread.__init__

        def _tracking_thread_init(self_t: Any, *args: Any, **kwargs: Any) -> None:
            if kwargs.get("name") == "ppid-watchdog":
                wdog_started.append("started")
            _real_thread_init(self_t, *args, **kwargs)

        monkeypatch.setattr(threading.Thread, "__init__", _tracking_thread_init)

        class _RaisingSolver:
            def __init__(self, **kwargs: Any) -> None:
                raise RuntimeError("solver unavailable — test-triggered warmup failure")

        _warmup_worker(_solver_factory=_RaisingSolver)  # must not raise

        assert wdog_started, "ppid-watchdog thread was not started in subprocess context"


# ── _warmup_worker exception paths ───────────────────────────────────────────


class TestWarmupWorkerExceptionPaths:
    def test_warmup_solver_factory_raising_triggers_except_block(self) -> None:
        """When the solver raises, warmup logs and increments counter (counter != None)."""

        class _RaisingSolver:
            def __init__(self, **kwargs: Any) -> None:
                raise RuntimeError("solver init failed — deliberate test raise")

        _warmup_worker(_solver_factory=_RaisingSolver)  # must not raise

    def test_warmup_counter_none_branch_when_counter_is_none(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """457->461: when _WORKER_WARMUP_FAILURE_COUNTER is None, skip inc() → del ctx.

        Monkeypatching the counter to None causes the False branch of
        `if _WORKER_WARMUP_FAILURE_COUNTER is not None:` to be taken, sending
        control directly to `finally: del ctx` (branch 457->461).
        """
        import pramanix.worker as _wk_mod

        monkeypatch.setattr(_wk_mod, "_WORKER_WARMUP_FAILURE_COUNTER", None)

        class _RaisingSolver:
            def __init__(self, **kwargs: Any) -> None:
                raise RuntimeError("solver unavailable — deliberate test raise")

        _warmup_worker(_solver_factory=_RaisingSolver)  # must not raise

    def test_warmup_always_sat_solver_triggers_unsat_check(self) -> None:
        """A solver that always returns sat triggers the unsat guard in warmup."""
        import z3

        class _AlwaysSatSolver:
            def __init__(self, ctx: Any = None, **kwargs: Any) -> None:
                pass

            def set(self, key: str, value: Any) -> None:
                pass

            def add(self, *args: Any) -> None:
                pass

            def check(self) -> Any:
                return z3.sat

        _warmup_worker(_solver_factory=_AlwaysSatSolver)  # must not raise


# ── _force_kill_processes outer except (outer try/except) ────────────────────


class TestForceKillProcessesOuterExcept:
    def test_outer_except_catches_getattr_error(self, caplog: Any) -> None:
        """Outer except block in _force_kill_processes catches ._processes access errors.

        _force_kill_processes wraps everything in a try/except.  An executor
        whose ._processes property raises triggers the outer except.
        caplog captures the error() call on the standard-library logger _log.
        """
        import logging

        from pramanix.worker import _force_kill_processes

        class _RaisingContainer:
            @property
            def _processes(self) -> dict:
                raise RuntimeError("_processes access deliberately failed")

        with caplog.at_level(logging.ERROR, logger="pramanix.worker"):
            _force_kill_processes(_RaisingContainer())  # type: ignore[arg-type]

        assert any(
            "force-kill" in r.message.lower() for r in caplog.records
        ), "outer except must emit an error log referencing force-kill"


# ── WorkerPool._emergency_shutdown ───────────────────────────────────────────


class TestEmergencyShutdownBranches:
    def test_emergency_shutdown_sys_is_finalizing_exception(
        self, monkeypatch: pytest.MonkeyPatch, caplog: Any
    ) -> None:
        """except Exception in _emergency_shutdown when is_finalizing() raises.

        Patching _sys.is_finalizing to raise exercises the except block that
        emits a debug log.  caplog captures the standard-library logger _log.
        """
        import logging

        import pramanix.worker as _wk_mod

        def _boom_finalizing() -> bool:
            raise RuntimeError("is_finalizing bombed — deliberate test exception")

        monkeypatch.setattr(_wk_mod._sys, "is_finalizing", _boom_finalizing)

        executor = ThreadPoolExecutor(max_workers=1)
        with caplog.at_level(logging.DEBUG, logger="pramanix.worker"):
            WorkerPool._emergency_shutdown([executor])

        assert any(
            "is_finalizing" in r.message.lower() for r in caplog.records
        ), "except Exception in _emergency_shutdown must emit a debug log"
        executor.shutdown(wait=False)

    def test_emergency_shutdown_when_is_finalizing_true(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """731->747: when is_finalizing() returns True, skip the warning block.

        `if not _sys.is_finalizing():` evaluates to False when is_finalizing()
        is True → the warning log block is skipped; control jumps directly to
        `with contextlib.suppress(Exception): executor.shutdown(wait=False)`.
        """
        import pramanix.worker as _wk_mod

        monkeypatch.setattr(_wk_mod._sys, "is_finalizing", lambda: True)

        executor = ThreadPoolExecutor(max_workers=1)
        WorkerPool._emergency_shutdown([executor])
        executor.shutdown(wait=False)


# ── WorkerPool.shutdown — finalizer.detach + None executor ───────────────────


class TestWorkerPoolShutdownBranches:
    def test_shutdown_detaches_finalizer(self) -> None:
        """shutdown() calls finalizer.detach() when finalizer is alive."""
        pool = WorkerPool(
            mode="async-thread",
            max_workers=1,
            max_decisions_per_worker=1000,
            warmup=False,
        )
        pool.spawn()
        assert hasattr(pool, "_finalizer"), "spawn must register _finalizer"
        assert pool._finalizer.alive
        pool.shutdown()
        assert not pool._finalizer.alive

    def test_shutdown_with_none_executor_returns_early(self) -> None:
        """shutdown() returns when executor is None after spawn."""
        pool = WorkerPool(
            mode="async-thread",
            max_workers=1,
            max_decisions_per_worker=1000,
            warmup=False,
        )
        pool.spawn()
        pool._executor = None
        pool._alive = True
        pool.shutdown()  # must not raise

    def test_shutdown_finalizer_none_skips_detach(self) -> None:
        """790->792: when _finalizer is absent, shutdown() skips detach and proceeds.

        Manually initialises the pool (no spawn()) so _finalizer is never set.
        shutdown() must call getattr(self, '_finalizer', None) → None → skip
        detach → the branch 790->792 is taken.
        """
        pool = WorkerPool(
            mode="async-thread",
            max_workers=1,
            max_decisions_per_worker=1000,
            warmup=False,
        )
        pool._executor = ThreadPoolExecutor(max_workers=1)
        pool._alive = True
        pool.shutdown()  # _finalizer absent → 790->792 branch taken


# ── WorkerPool.submit_solve — rate_limited ────────────────────────────────────


class TestWorkerPoolRateLimited:
    def test_submit_solve_sheds_when_pool_saturated(self) -> None:
        """submit_solve returns rate_limited when limiter.acquire() is False."""
        pool = WorkerPool(
            mode="async-thread",
            max_workers=1,
            max_decisions_per_worker=1000,
            warmup=False,
        )
        pool.spawn()
        pool._shed_limiter._max_outstanding = 0  # force immediate rejection

        result = pool.submit_solve(_P, {"amount": Decimal("50")}, 5000)

        pool._shed_limiter._max_outstanding = pool.max_workers * 8
        pool.shutdown()

        assert not result.allowed
        assert result.status == SolverStatus.RATE_LIMITED


# ── WorkerPool.submit_solve — process mode success ───────────────────────────


class TestWorkerPoolProcessModeSuccess:
    def test_process_mode_valid_seal_hits_dict_to_decision(self) -> None:
        """Process-mode success path: _dict_to_decision is called after _unseal_decision.

        Replaces the executor with a synchronous ThreadPoolExecutor shim that
        runs _worker_solve_sealed in the calling thread.  The host's _RESULT_SEAL_KEY
        is used for both sealing and verification, so _unseal_decision succeeds
        and the else-branch (_dict_to_decision) is reached.

        NO ProcessPoolExecutor is created — avoids OS-process spawning that
        interferes with subsequent process-kill tests on Python 3.13 spawn pools.
        The 790->792 branch (finalizer=None → skip detach) is also covered here
        because the pool is initialised manually without spawn().
        """
        from pramanix.worker import _worker_solve_sealed  # noqa: F401 (confirms importable)

        class _SyncSealedExecutor(ThreadPoolExecutor):
            """Runs _worker_solve_sealed synchronously in the calling thread."""

            def submit(self, fn: Any, *args: Any, **kwargs: Any) -> Future:  # type: ignore[override]
                real_future: Future = Future()
                try:
                    result = fn(*args, **kwargs)
                    real_future.set_result(result)
                except Exception as exc:
                    real_future.set_exception(exc)
                return real_future

        pool = WorkerPool(
            mode="async-process",
            max_workers=1,
            max_decisions_per_worker=1000,
            warmup=False,
        )
        # Manual initialisation: no spawn() → no ProcessPoolExecutor created.
        # _finalizer is intentionally absent so the 790->792 branch is covered.
        pool._executor = _SyncSealedExecutor(max_workers=1)
        pool._alive = True
        pool._counter = 0

        result = pool.submit_solve(_P, {"amount": Decimal("50")}, 5000)
        pool.shutdown()

        assert result.allowed


# ── WorkerPool.submit_solve — WorkerError re-raise ───────────────────────────


class TestWorkerPoolWorkerErrorReRaise:
    def test_worker_error_released_from_shed_limiter_and_re_raised(self) -> None:
        """WorkerError is re-raised after releasing the shed limiter.

        Setting _executor to None while _alive=True causes self.executor (the
        property) to raise WorkerError.  submit_solve catches it, calls
        _shed_limiter.release(), and re-raises.
        """
        pool = WorkerPool(
            mode="async-thread",
            max_workers=1,
            max_decisions_per_worker=1000,
            warmup=False,
        )
        pool.spawn()
        pool._executor = None
        pool._alive = True

        with pytest.raises(WorkerError):
            pool.submit_solve(_P, {"amount": Decimal("50")}, 5000)

        pool._alive = False


# ── WorkerPool._recycle ───────────────────────────────────────────────────────


class TestWorkerPoolRecycleWarmupPaths:
    def test_recycle_with_warmup_true_runs_warmup_on_new_executor(self) -> None:
        """_recycle with warmup=True runs _run_warmup on new executor."""
        pool = WorkerPool(
            mode="async-thread",
            max_workers=1,
            max_decisions_per_worker=1,
            warmup=True,
        )
        pool.spawn()
        result = pool.submit_solve(_P, {"amount": Decimal("50")}, 5000)
        assert result.allowed
        pool.shutdown()

    def test_recycle_warmup_failure_is_logged_not_raised(self, caplog: Any) -> None:
        """Warmup failure during _recycle is logged, not propagated.

        _run_warmup is replaced with a raising function AFTER spawn() so the
        initial spawn's warmup succeeds.  Next _recycle triggers the broken
        warmup, exercising the except-and-log path.  caplog captures standard-
        library WARNING records emitted by the real pramanix.worker._log.
        """
        import logging

        pool = WorkerPool(
            mode="async-thread",
            max_workers=1,
            max_decisions_per_worker=1,
            warmup=True,
        )
        pool.spawn()

        def _boom_warmup() -> None:
            raise RuntimeError("warmup crash — deliberate test failure")

        pool._run_warmup = _boom_warmup  # type: ignore[method-assign]
        pool._counter = 1

        with caplog.at_level(logging.WARNING, logger="pramanix.worker"):
            pool._recycle()

        assert any(
            "warmup" in r.message.lower() for r in caplog.records
        ), "warmup failure during _recycle must emit a warning log record"
        pool.shutdown()

    def test_recycle_without_active_executor_cell_skips_cell_update(self) -> None:
        """967->972: _recycle() skips cell update when _active_executor_cell is absent.

        When a pool is manually initialised (no spawn()), _active_executor_cell
        is never set.  _recycle() must skip the `if hasattr(...)` body and
        continue to the warmup check at line 972 — branch 967->972 is taken.
        """
        pool = WorkerPool(
            mode="async-thread",
            max_workers=1,
            max_decisions_per_worker=1,  # recycle after every call
            warmup=False,
        )
        pool._executor = ThreadPoolExecutor(max_workers=1)
        pool._alive = True
        pool._counter = 0

        # A single submit triggers recycle (max_decisions_per_worker=1).
        # _active_executor_cell is absent → branch 967->972 is taken.
        result = pool.submit_solve(_P, {"amount": Decimal("50")}, 5000)
        assert result.allowed
        pool.shutdown()


# ── WorkerPool.executor property — raises when not spawned ───────────────────


class TestWorkerPoolExecutorPropertyNotSpawned:
    def test_executor_property_raises_worker_error_when_not_spawned(self) -> None:
        """WorkerError raised when accessing executor before spawn()."""
        pool = WorkerPool(
            mode="async-thread",
            max_workers=1,
            max_decisions_per_worker=1000,
            warmup=False,
        )
        with pytest.raises(WorkerError, match="not spawned"):
            _ = pool.executor


# ── _ppid_watchdog — counter IS not None → inc() path (lines 344-345) ────────


class TestPpidWatchdogCounterIncPath:
    def test_ppid_watchdog_exception_with_counter_not_none(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Lines 344-345: when counter IS not None, inc() is called after exception.

        Does NOT patch _WORKER_WATCHDOG_ERROR_COUNTER so the real Counter is
        available → the True branch of `if counter is not None:` runs,
        covering lines 344-345 (_WORKER_WATCHDOG_ERROR_COUNTER.inc()).
        """
        import os
        import time as _time_mod

        import pramanix.worker as _wk_mod
        from pramanix.worker import _ppid_watchdog

        if _wk_mod._WORKER_WATCHDOG_ERROR_COUNTER is None:
            pytest.skip("prometheus_client not installed")

        call_count = [0]
        stable_ppid = 77777

        def _fake_getppid() -> int:
            call_count[0] += 1
            if call_count[0] == 1:
                return stable_ppid  # initial_ppid
            elif call_count[0] == 2:
                raise RuntimeError("forced exception — covers counter.inc() path")
            else:
                return stable_ppid + 1  # PPID changed → exit

        exit_called = threading.Event()

        def _fake_exit(code: int) -> None:
            exit_called.set()
            raise SystemExit(code)

        monkeypatch.setattr(os, "getppid", _fake_getppid)
        monkeypatch.setattr(os, "_exit", _fake_exit)
        monkeypatch.setattr(_time_mod, "sleep", lambda _s: None)
        # Counter stays as-is (not None) — True branch covers lines 344-345.

        def _run_watchdog() -> None:
            try:
                _ppid_watchdog()
            except SystemExit:
                pass

        t = threading.Thread(target=_run_watchdog, daemon=True, name="test-ppid-wdog-counter")
        t.start()
        assert exit_called.wait(timeout=5.0)
        t.join(timeout=2.0)


# ── _worker_solve — UNSAFE (block) decision path (lines 495-497) ─────────────


class TestWorkerSolveUnsafePath:
    def test_worker_solve_block_decision_covers_unsafe_path(self) -> None:
        """Lines 495-497: _worker_solve returns a BLOCK dict for violated invariants.

        Passes amount=-1 which violates the `amount >= 0` invariant.  The solver
        returns UNSAT → _worker_solve constructs the violated-invariant list and
        returns Decision.unsafe().to_dict(), covering lines 495-497.
        """
        from pramanix.worker import _worker_solve

        result = _worker_solve(_P, {"amount": Decimal("-1")}, 5000)
        assert result["status"] == "unsafe"
        assert not result["allowed"]
        assert "ok" in result.get("violated_invariants", [])


# ── WorkerPool._emergency_shutdown — executor=None early return (line 729) ────


class TestEmergencyShutdownExecutorNone:
    def test_emergency_shutdown_executor_none_returns_early(self) -> None:
        """Line 729: _emergency_shutdown returns immediately when executor is None.

        Passes [None] as the active_executor_cell so the `if executor is None:`
        branch is taken and the function returns at line 729.
        """
        WorkerPool._emergency_shutdown([None])  # must not raise


# ── WorkerPool host-deadline FutureTimeoutError paths ────────────────────────


class _ImmediateTimeoutFuture(Future):
    """Future whose result() immediately raises FutureTimeoutError."""

    def result(self, timeout: float | None = None) -> Any:  # type: ignore[override]
        raise FutureTimeoutError()


class TestWorkerPoolHostDeadlineTimeout:
    def test_process_mode_host_deadline_exceeded(self) -> None:
        """Lines 856-862: process-mode FutureTimeoutError is caught and returns error.

        Uses _ImmediateTimeoutFuture so future.result() raises immediately,
        covering the except FutureTimeoutError block in process mode without
        waiting 60+ seconds for the real host timeout.
        """

        class _TimeoutProcessExecutor(ThreadPoolExecutor):
            def submit(self, fn: Any, *args: Any, **kwargs: Any) -> Future:  # type: ignore[override]
                return _ImmediateTimeoutFuture()

        pool = WorkerPool(
            mode="async-process",
            max_workers=1,
            max_decisions_per_worker=1000,
            warmup=False,
        )
        pool._executor = _TimeoutProcessExecutor(max_workers=1)
        pool._alive = True
        pool._counter = 0

        result = pool.submit_solve(_P, {"amount": Decimal("50")}, 5000)
        pool.shutdown()

        assert not result.allowed
        assert "timeout" in result.explanation.lower() or "deadline" in result.explanation.lower()

    def test_thread_mode_host_deadline_exceeded(self) -> None:
        """Lines 888-894: thread-mode FutureTimeoutError is caught and returns error.

        Uses _ImmediateTimeoutFuture so future.result() raises immediately,
        covering the except FutureTimeoutError block in thread mode without
        waiting 60+ seconds for the real host timeout.
        """

        class _TimeoutThreadExecutor(ThreadPoolExecutor):
            def submit(self, fn: Any, *args: Any, **kwargs: Any) -> Future:  # type: ignore[override]
                return _ImmediateTimeoutFuture()

        pool = WorkerPool(
            mode="async-thread",
            max_workers=1,
            max_decisions_per_worker=1000,
            warmup=False,
        )
        pool.spawn()
        old = pool._executor
        old.shutdown(wait=True)
        pool._executor = _TimeoutThreadExecutor(max_workers=1)

        result = pool.submit_solve(_P, {"amount": Decimal("50")}, 5000)
        pool._executor.shutdown(wait=False)
        pool._alive = False

        assert not result.allowed
        assert "timeout" in result.explanation.lower() or "deadline" in result.explanation.lower()
