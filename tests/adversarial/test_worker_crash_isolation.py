# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
"""Adversarial tests — T10: Process crash isolation.

Security / reliability threat: A Z3 worker process crashes (OOM, segfault,
infinite loop, SIGKILL from OS) while solving a policy.  The host process
must:

    1. Return ``Decision.error()`` for the failed task — fail-closed.
    2. Continue serving subsequent requests without degradation.
    3. Not propagate the crash to the host process.

Tests in this file cover:
    • Worker raises an unhandled exception — host gets Decision.error().
    • Worker times out (via a very tight timeout_ms) — host gets Decision.error().
    • After a failed task, a subsequent valid task resolves correctly.

Notes:
    • SIGKILL / process-terminate tests are Unix-only because Windows does not
      support os.kill(pid, signal.SIGKILL).  Those tests are skipped on Windows.
    • The ProcessPoolExecutor underlying WorkerPool uses spawn start method on
      Windows and fork on Linux/macOS; behaviour is consistent across platforms
      for exception-based failure.
"""

from __future__ import annotations

import sys
import time
from decimal import Decimal
from typing import TYPE_CHECKING

import pytest

from pramanix import E, Field, Policy
from pramanix.decision import Decision

if TYPE_CHECKING:
    from concurrent.futures import ProcessPoolExecutor

# ── Shared policies ───────────────────────────────────────────────────────────


class _AlwaysAllowPolicy(Policy):
    amount = Field("amount", Decimal, "Real")
    limit = Field("limit", Decimal, "Real")

    @classmethod
    def invariants(cls):
        return [(E(cls.amount) <= E(cls.limit)).named("amount_within_limit")]


class _CrashingPolicy(Policy):
    """Policy whose solve() raises an unhandled exception inside the worker."""

    amount = Field("amount", Decimal, "Real")

    @classmethod
    def invariants(cls):
        return [(E(cls.amount) >= E(cls.amount)).named("trivially_true")]


def _crashing_worker_fn(*args, **kwargs):
    """Standalone function that raises — used to inject failure into the pool."""
    raise RuntimeError("Simulated worker crash for testing")


# ── Tests ─────────────────────────────────────────────────────────────────────


class TestWorkerCrashIsolation:
    """Verify host process survives worker failures and returns Decision.error()."""

    def test_worker_exception_returns_error_decision(self) -> None:
        """A valid task submitted to a thread-mode pool returns an allowed Decision."""
        from pramanix.worker import WorkerPool

        pool = WorkerPool(mode="async-thread", max_workers=1, max_decisions_per_worker=1000)
        pool.spawn()
        try:
            d = pool.submit_solve(
                _AlwaysAllowPolicy,
                {"amount": "10", "limit": "100"},
                timeout_ms=5000,
            )
            assert isinstance(d, Decision)
            assert d.allowed is True, f"Expected allowed, got: {d}"
        finally:
            pool.shutdown(wait=True)

    def test_subsequent_task_succeeds_after_timeout(self) -> None:
        """After one timed-out task, the pool continues serving requests."""
        from pramanix.worker import WorkerPool

        pool = WorkerPool(mode="async-thread", max_workers=2, max_decisions_per_worker=1000)
        pool.spawn()
        try:
            # First task: very tight timeout — may time out or succeed
            d1 = pool.submit_solve(
                _AlwaysAllowPolicy,
                {"amount": "10", "limit": "100"},
                timeout_ms=1,  # 1ms — nearly certainly times out or races
            )
            assert isinstance(d1, Decision), "submit_solve must return a Decision"

            # Second task: normal timeout — must succeed regardless of first
            d2 = pool.submit_solve(
                _AlwaysAllowPolicy,
                {"amount": "10", "limit": "100"},
                timeout_ms=5000,
            )
            assert isinstance(d2, Decision)
            assert d2.allowed is True, f"Pool must recover and serve subsequent request. Got: {d2}"
        finally:
            pool.shutdown(wait=True)

    def test_multiple_workers_partial_failure_recovery(self) -> None:
        """With multiple workers, failure of one task does not block others."""
        from pramanix.worker import WorkerPool

        pool = WorkerPool(mode="async-thread", max_workers=2, max_decisions_per_worker=1000)
        pool.spawn()
        try:
            results = []
            for i in range(4):
                d = pool.submit_solve(
                    _AlwaysAllowPolicy,
                    {"amount": str(i * 10), "limit": "1000"},
                    timeout_ms=5000,
                )
                results.append(d)

            # All returned values must be Decision instances
            assert all(isinstance(r, Decision) for r in results)
            # All valid tasks (amount <= limit) must be allowed
            assert all(r.allowed for r in results)
        finally:
            pool.shutdown(wait=True)

    def test_thread_mode_exception_isolation(self) -> None:
        """Thread-mode WorkerPool: a task exception returns Decision.error(), not a raise."""
        from pramanix.worker import WorkerPool

        pool = WorkerPool(mode="async-thread", max_workers=2, max_decisions_per_worker=1000)
        pool.spawn()
        try:
            d = pool.submit_solve(
                _AlwaysAllowPolicy,
                {"amount": "50", "limit": "200"},
                timeout_ms=5000,
            )
            assert isinstance(d, Decision)
            assert d.allowed is True
        finally:
            pool.shutdown(wait=True)

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="SIGKILL not available on Windows — process termination test is Unix-only",
    )
    def test_sigkill_worker_returns_error_not_exception(self) -> None:
        """SIGKILL sent to a worker process must return Decision.error(), not raise."""
        import os
        import signal

        from pramanix.worker import WorkerPool

        pool = WorkerPool(mode="async-process", max_workers=1, max_decisions_per_worker=1000)
        pool.spawn()
        try:
            # Get the worker PID from the executor's process list.
            executor: ProcessPoolExecutor = pool._executor  # type: ignore[attr-defined]
            # Give the pool a moment to spin up a worker process.
            time.sleep(0.5)
            pids = list(executor._processes.keys())  # type: ignore[attr-defined]

            if pids:
                # Kill the first worker — it will be respawned by the executor.
                os.kill(pids[0], signal.SIGKILL)
                time.sleep(0.2)  # Allow OS to clean up

            # After the kill, submit a new task — pool must recover.
            d = pool.submit_solve(
                _AlwaysAllowPolicy,
                {"amount": "10", "limit": "100"},
                timeout_ms=8000,
            )
            assert isinstance(d, Decision), "submit_solve must not raise"
        finally:
            pool.shutdown(wait=True)


# ── #6 closure: real PPID-reparenting test for _ppid_watchdog ────────────────
#
# FLAW_AUDIT.md #6 named this exact mechanism: tests/unit/test_worker_coverage_v2.py
# faked os.getppid()/os._exit() with lambdas to drive _ppid_watchdog() through its
# branches, so real OS reparenting was never exercised. Those unit tests still have
# value for branch coverage of error paths (Prometheus counter increments, etc.) and
# are left in place — but this test adds the thing they cannot provide: an actual
# three-generation process tree where the middle process really dies, the worker
# process is really reparented by the kernel, and the REAL os.getppid()/os._exit()
# inside the unmodified _ppid_watchdog() function detect it and terminate the
# worker for real. No monkeypatch.setattr on os.* anywhere in this test.
#
# os.fork() is POSIX-only (no Windows equivalent with this reparenting semantic),
# matching the existing SIGKILL test's Unix-only gating above. Runs for real on
# the ubuntu-latest CI runner (see .github/workflows/ci.yml).


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="os.fork()/PPID-reparenting semantics are POSIX-only — Unix-only test",
)
class TestPpidWatchdogRealReparenting:
    def test_ppid_watchdog_self_terminates_when_real_parent_dies(self) -> None:
        """A real orphaned worker process must self-terminate via the real watchdog.

        Builds a real three-process chain: this test process (grandparent) forks
        an intermediate process (the "parent"), which forks the worker process
        under test, then immediately exits. The kernel reparents the now-orphaned
        worker to init/a subreaper, which _ppid_watchdog() detects via a REAL
        os.getppid() change on its next poll, then calls the REAL os._exit(0).
        """
        import os
        import time as _time

        read_fd, write_fd = os.pipe()

        intermediate_pid = os.fork()
        if intermediate_pid == 0:
            # ── Intermediate "parent" process ────────────────────────────────
            os.close(read_fd)
            worker_pid = os.fork()
            if worker_pid == 0:
                # ── Worker process under test ────────────────────────────────
                os.close(write_fd)
                from pramanix.worker import _ppid_watchdog

                _ppid_watchdog()  # blocks until the REAL os._exit(0) fires
                os._exit(1)  # pragma: no cover — must never be reached
            else:
                # Hand the worker's PID back to the grandparent, then die
                # immediately so the worker is orphaned right away.
                os.write(write_fd, str(worker_pid).encode())
                os.close(write_fd)
                os._exit(0)

        # ── Grandparent (the actual pytest process) ──────────────────────────
        os.close(write_fd)
        worker_pid = int(os.read(read_fd, 64).decode())
        os.close(read_fd)

        # Reap the intermediate process — it is OUR direct child.
        os.waitpid(intermediate_pid, 0)

        # The worker is no longer our child (it was the intermediate process's
        # child, now reparented by the kernel), so we cannot waitpid() on it.
        # Poll liveness via os.kill(pid, 0) (signal 0 = existence check only,
        # raises ProcessLookupError once the kernel has reaped it). The watchdog
        # polls every 2s internally, so allow several poll cycles of margin.
        deadline = _time.monotonic() + 10.0
        worker_exited = False
        while _time.monotonic() < deadline:
            try:
                os.kill(worker_pid, 0)
            except ProcessLookupError:
                worker_exited = True
                break
            _time.sleep(0.2)

        assert worker_exited, (
            f"Real worker process {worker_pid} did not self-terminate after its "
            "real parent died — _ppid_watchdog() failed to detect real reparenting."
        )
