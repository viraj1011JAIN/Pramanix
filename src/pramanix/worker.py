# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Worker pool for async Guard execution modes.

Architecture
------------
* **Thread mode** (``execution_mode="async-thread"``):
  ``ThreadPoolExecutor`` — workers share memory, Z3 GIL is
  released during solving so concurrency is genuine.

* **Process mode** (``execution_mode="async-process"``):
  ``ProcessPoolExecutor`` with ``"spawn"`` context — each process
  has a private Z3 context; no forked-state corruption.

Critical design invariants
--------------------------
1. **No Z3 objects cross the process boundary.**
   ``_worker_solve`` receives only ``(policy_cls, values_dict, timeout_ms)``
   and reconstructs the entire formula tree inside the child process.
   This is safe because ``policy_cls`` is a class reference — picklable
   via its fully-qualified import name.

2. **No IPC counter.**
   The decision counter is a plain ``int`` in the *host process*, guarded
   by a ``threading.Lock``.  Zero contention, zero IPC.

3. **Zombie-safe recycle.**
   When a slot is recycled, the old executor is handed to a daemon
   background thread.  ``_drain_executor`` waits ``_RECYCLE_GRACE_S``
   seconds for clean shutdown; then sends ``SIGKILL`` / ``.kill()`` to
   any surviving ``multiprocessing.Process`` objects.  The event loop
   is **never** blocked.
"""
from __future__ import annotations

import logging
import threading
from concurrent.futures import Future, ProcessPoolExecutor, ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from pramanix.decision import Decision
from pramanix.exceptions import WorkerError

if TYPE_CHECKING:
    from concurrent.futures import Executor

    from pramanix.policy import Policy

__all__ = ["WorkerPool"]

_log = logging.getLogger(__name__)

# Grace period before force-killing stalled processes during recycle.
_RECYCLE_GRACE_S: float = 10.0


# ── Module-level free functions (must be picklable for ProcessPoolExecutor) ────


def _warmup_worker() -> None:
    """Submit one trivial Z3 solve to prime the JIT and load libz3.

    This function runs *inside* the worker (thread or process).  It is a
    module-level free function so that ``ProcessPoolExecutor`` can pickle it
    as an import reference rather than a closure.
    """
    import z3  # — intentional local import inside worker

    s = z3.Solver()
    s.set("timeout", 1_000)
    s.add(z3.Real("__warmup_x") >= 0)
    s.check()
    del s


def _worker_solve(
    policy_cls: type[Policy],
    values: dict[str, Any],
    timeout_ms: int,
) -> dict[str, Any]:
    """Run ``solve()`` inside a worker and return a plain ``Decision`` dict.

    **Nothing Z3-flavoured enters or leaves this function via the
    process boundary.**  ``policy_cls`` is a class reference (picklable).
    ``values`` is a plain Python dict.  The return value is a plain dict
    produced by ``Decision.to_dict()``.

    Args:
        policy_cls: The :class:`~pramanix.policy.Policy` subclass to verify.
            The class is re-imported inside the child process.
        values:     Merged ``{field_name: value}`` dict (intent + state).
        timeout_ms: Per-solver Z3 timeout in milliseconds.

    Returns:
        ``Decision.to_dict()`` — a JSON-serialisable plain dict.
    """
    from pramanix.decision import Decision
    from pramanix.exceptions import PramanixError, SolverTimeoutError
    from pramanix.solver import solve

    try:
        invariants = policy_cls.invariants()
        result = solve(invariants, values, timeout_ms)
        if result.sat:
            return Decision.safe(solver_time_ms=result.solver_time_ms).to_dict()
        filtered = [inv for inv in result.violated if inv.label]
        explanation = "; ".join(inv.label for inv in filtered if inv.label)
        return Decision.unsafe(
            violated_invariants=tuple(inv.label for inv in filtered if inv.label),
            explanation=explanation or "Invariant(s) violated.",
            solver_time_ms=result.solver_time_ms,
        ).to_dict()
    except SolverTimeoutError as exc:
        return Decision.timeout(label=exc.label, timeout_ms=exc.timeout_ms).to_dict()
    except PramanixError as exc:
        return Decision.error(reason=str(exc)).to_dict()
    except Exception as exc:  # fail-safe: worker never propagates raw exceptions
        return Decision.error(
            reason=f"Unexpected worker error ({type(exc).__name__}): {exc}"
        ).to_dict()


def _drain_executor(executor: Executor, grace_s: float) -> None:
    """Shut down *executor*, waiting up to *grace_s* seconds.

    Runs in a daemon background thread so the event loop stays unblocked.
    For ``ProcessPoolExecutor``, any processes still alive after the grace
    period are force-killed.
    """
    # Request clean shutdown (don't cancel pending futures — they may be
    # mid-solve; let them complete or timeout naturally).
    shutdown_event = threading.Event()

    def _do_shutdown() -> None:
        try:
            executor.shutdown(wait=True)
        except Exception:
            pass
        finally:
            shutdown_event.set()

    t = threading.Thread(target=_do_shutdown, daemon=True)
    t.start()
    t.join(timeout=grace_s)

    if not shutdown_event.is_set():
        _log.warning(
            "worker.drain: executor did not shut down within %.1fs grace period — "
            "force-killing surviving processes.",
            grace_s,
        )
        # Force-kill any surviving child processes (process mode only).
        if isinstance(executor, ProcessPoolExecutor):
            _force_kill_processes(executor)


def _force_kill_processes(executor: ProcessPoolExecutor) -> None:
    """Send SIGKILL to all surviving worker processes in *executor*."""
    try:
        # ProcessPoolExecutor exposes ._processes (dict: pid→Process) in CPython.
        procs = getattr(executor, "_processes", {})
        for proc in procs.values():
            if proc.is_alive():
                try:
                    proc.kill()
                    _log.warning("worker.drain: killed hung process pid=%s", proc.pid)
                except Exception as exc:
                    _log.error(
                        "worker.drain: failed to kill pid=%s: %s", proc.pid, exc
                    )
    except Exception as exc:
        _log.error("worker.drain: unexpected error during force-kill: %s", exc)


# ── WorkerPool ────────────────────────────────────────────────────────────────


@dataclass
class WorkerPool:
    """Managed pool of workers (threads or processes) for async Guard dispatch.

    This class is *not* part of the public API — it is created and owned by
    :class:`~pramanix.guard.Guard`.

    Args:
        mode:                     ``"async-thread"`` or ``"async-process"``.
        max_workers:              Number of parallel workers.
        max_decisions_per_worker: Recycle all workers after this many calls.
        warmup:                   If ``True``, run a trivial Z3 solve on each
                                  new worker to eliminate cold-start JIT spikes.
        grace_s:                  Grace period (seconds) before force-killing
                                  stalled processes during recycle.
    """

    mode: str
    max_workers: int
    max_decisions_per_worker: int
    warmup: bool = True
    grace_s: float = _RECYCLE_GRACE_S

    # Internals — not in constructor parameters.
    _executor: Executor = field(init=False, repr=False)
    _counter: int = field(init=False, default=0, repr=False)
    _lock: threading.Lock = field(init=False, default_factory=threading.Lock, repr=False)
    _alive: bool = field(init=False, default=False, repr=False)

    def __post_init__(self) -> None:
        self._lock = threading.Lock()
        self._counter = 0
        self._alive = False

    # ── Lifecycle ──────────────────────────────────────────────────────────────

    def spawn(self) -> None:
        """Create the executor and, optionally, warm each worker slot.

        Is idempotent when called on an already-alive pool.

        Raises:
            WorkerError: If executor creation fails (wraps original exception).
        """
        if self._alive:
            return
        try:
            self._executor = self._make_executor()
            if self.warmup:
                self._run_warmup()
            self._counter = 0
            self._alive = True
        except Exception as exc:
            raise WorkerError(
                f"WorkerPool.spawn failed ({type(exc).__name__}): {exc}"
            ) from exc

    def shutdown(self, wait: bool = True) -> None:
        """Gracefully shut down the pool.

        Safe to call multiple times (idempotent after first call).

        Args:
            wait: If ``True``, block until all pending work finishes.
        """
        if not self._alive:
            return
        self._alive = False
        try:
            self._executor.shutdown(wait=wait)
        except Exception as exc:
            _log.error("WorkerPool.shutdown error: %s", exc)

    # ── Public solve interface ─────────────────────────────────────────────────

    def submit_solve(
        self,
        policy_cls: type[Policy],
        values: dict[str, Any],
        timeout_ms: int,
    ) -> Decision:
        """Submit one verification to the pool and block until complete.

        The counter is tracked host-side (no IPC).  Recycling is triggered
        if the counter reaches ``max_decisions_per_worker``.

        Args:
            policy_cls: The Policy *class* (not instance) — picklable.
            values:     Merged plain-dict of all field values.
            timeout_ms: Z3 per-solver timeout.

        Returns:
            A :class:`~pramanix.decision.Decision`.  Never raises.
        """
        if not self._alive:
            return Decision.error(reason="WorkerPool is not running.")
        try:
            future: Future[dict[str, Any]] = self._executor.submit(
                _worker_solve, policy_cls, values, timeout_ms
            )
            result_dict = future.result()  # blocks until worker returns
            decision = self._dict_to_decision(result_dict)
        except WorkerError:
            raise
        except Exception as exc:
            _log.error("WorkerPool.submit_solve error: %s", exc)
            decision = Decision.error(
                reason=f"Worker dispatch failed ({type(exc).__name__}): {exc}"
            )

        # Host-side counter — zero IPC, zero lock contention on fast path.
        with self._lock:
            self._counter += 1
            should_recycle = self._counter >= self.max_decisions_per_worker

        if should_recycle:
            self._recycle()

        return decision

    # ── Internals ─────────────────────────────────────────────────────────────

    def _make_executor(self) -> Executor:
        if self.mode == "async-thread":
            return ThreadPoolExecutor(max_workers=self.max_workers)
        if self.mode == "async-process":
            import multiprocessing

            mp_ctx = multiprocessing.get_context("spawn")
            return ProcessPoolExecutor(
                max_workers=self.max_workers, mp_context=mp_ctx
            )
        raise WorkerError(f"Unknown worker mode: {self.mode!r}")

    def _run_warmup(self) -> None:
        """Submit ``_warmup_worker`` to every slot.  Best-effort."""
        futures = [
            self._executor.submit(_warmup_worker)
            for _ in range(self.max_workers)
        ]
        for fut in futures:
            try:
                fut.result(timeout=30.0)
            except Exception as exc:
                _log.warning("WorkerPool warmup slot failed: %s", exc)

    def _recycle(self) -> None:
        """Non-blocking recycle: swap in a fresh executor, drain the old one.

        The old executor is handed to ``_drain_executor`` running in a
        daemon thread.  The event loop is **never** blocked.
        """
        _log.info(
            "WorkerPool.recycle: counter=%d >= max_decisions_per_worker=%d — recycling.",
            self.max_decisions_per_worker,
            self.max_decisions_per_worker,
        )
        with self._lock:
            if self._counter < self.max_decisions_per_worker:
                return  # another thread already recycled
            old_executor = self._executor
            try:
                self._executor = self._make_executor()
                if self.warmup:
                    self._run_warmup()
                self._counter = 0
            except Exception as exc:
                _log.error("WorkerPool.recycle: failed to create new executor: %s", exc)
                # Restore the old executor so callers keep working.
                self._executor = old_executor
                return

        # Fire-and-forget drain of the old executor.
        threading.Thread(
            target=_drain_executor,
            args=(old_executor, self.grace_s),
            daemon=True,
            name="pramanix-drain",
        ).start()

    @staticmethod
    def _dict_to_decision(d: dict[str, Any]) -> Decision:
        """Reconstruct a :class:`Decision` from its ``to_dict()`` representation."""
        from pramanix.decision import SolverStatus

        return Decision(
            allowed=d["allowed"],
            status=SolverStatus(d["status"]),
            violated_invariants=tuple(d.get("violated_invariants", [])),
            explanation=d.get("explanation", ""),
            solver_time_ms=d.get("solver_time_ms", 0.0),
            metadata=d.get("metadata", {}),
        )

    # ── Accessor ──────────────────────────────────────────────────────────────

    @property
    def executor(self) -> Executor:
        """The underlying :class:`~concurrent.futures.Executor`."""
        return self._executor
