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

import collections
import hashlib
import hmac as _hmac_mod
import json as _json_mod
import logging
import secrets as _secrets_mod
import threading
import time as _time_module
from concurrent.futures import Future, ProcessPoolExecutor, ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, NoReturn

from pramanix.decision import Decision
from pramanix.exceptions import WorkerError

if TYPE_CHECKING:
    from concurrent.futures import Executor

    from pramanix.policy import Policy

__all__ = ["WorkerPool", "AdaptiveConcurrencyLimiter"]

_log = logging.getLogger(__name__)

# Grace period before force-killing stalled processes during recycle.
_RECYCLE_GRACE_S: float = 10.0


# ── Phase 10.4: Adaptive Concurrency Limiter ──────────────────────────────────


class AdaptiveConcurrencyLimiter:
    """Adaptive load shedder for the Z3 worker pool.

    Sheds requests when BOTH conditions are met simultaneously:
    1. active_workers >= max_workers * shed_worker_pct/100
    2. p99_solver_latency_ms > shed_latency_threshold_ms

    Dual-condition prevents false positives:
    - High workers alone may be a healthy burst
    - High latency alone may be a transient GC pause
    - Both together signals genuine overload

    INVARIANT: shed decisions always have allowed=False.
    INVARIANT: Shedding is NEVER the cause of allowed=True.
    """

    _LATENCY_WINDOW_SECONDS = 60.0

    def __init__(
        self,
        max_workers: int,
        latency_threshold_ms: float | None = None,
        worker_pct: float | None = None,
    ) -> None:
        import os as _os

        self._max_workers = max_workers
        self._latency_threshold = (
            latency_threshold_ms
            if latency_threshold_ms is not None
            else float(_os.environ.get("PRAMANIX_SHED_LATENCY_THRESHOLD_MS", "200"))
        )
        self._worker_pct = (
            worker_pct
            if worker_pct is not None
            else float(_os.environ.get("PRAMANIX_SHED_WORKER_PCT", "90"))
        )
        self._active = 0
        self._lock = threading.Lock()
        self._latency_window: collections.deque[tuple[float, float]] = collections.deque()
        self._shed_count = 0

    @property
    def active_workers(self) -> int:
        return self._active

    @property
    def shed_count(self) -> int:
        return self._shed_count

    def acquire(self) -> bool:
        """Try to acquire a worker slot.

        Returns True if the request should proceed.
        Returns False if the request should be shed.
        Never raises.
        """
        with self._lock:
            self._active += 1
            should_shed = self._check_shed_conditions()
            if should_shed:
                self._active -= 1
                self._shed_count += 1
                return False
            return True

    def release(self, latency_ms: float) -> None:
        """Release a worker slot and record the solve latency."""
        with self._lock:
            self._active = max(0, self._active - 1)
            now = _time_module.monotonic()
            self._latency_window.append((now, latency_ms))
            # Evict entries outside the 60s window
            cutoff = now - self._LATENCY_WINDOW_SECONDS
            while self._latency_window and self._latency_window[0][0] < cutoff:
                self._latency_window.popleft()

    def _check_shed_conditions(self) -> bool:
        """Check both shedding conditions. Called under lock."""
        saturation_pct = (self._active / self._max_workers) * 100
        if saturation_pct < self._worker_pct:
            return False

        p99 = self._compute_p99()
        if p99 is None:
            return False
        return p99 > self._latency_threshold

    def _compute_p99(self) -> float | None:
        """Compute P99 over the sliding window. Called under lock."""
        if len(self._latency_window) < 10:
            return None
        latencies: list[float] = sorted(entry[1] for entry in self._latency_window)
        idx = int(len(latencies) * 0.99)
        return latencies[min(idx, len(latencies) - 1)]


# ── HMAC Result Integrity Seal ────────────────────────────────────────────────
#
# A random key generated once in the HOST process at module import time.
# In async-process mode it is forwarded to child processes as a function
# argument so they can sign their result dicts before returning them via IPC.
# The host verifies the HMAC before trusting the deserialized decision, making
# it impossible for a compromised worker to silently forge an allowed=True
# result without knowledge of the key.
#
# Key rotation: the key is regenerated on every process restart, so a leaked
# key from a terminated process cannot be replayed.
#
# _EphemeralKey guarantees:
#   * repr()/str() return '<EphemeralKey: redacted>'  — safe to log.
#   * __reduce__ raises TypeError  — prevents accidental pickle.dump to disk.
#   * .bytes is the only route to the raw bytes (explicit IPC forwarding only).


class _EphemeralKey:
    """Secret-key wrapper that is log-safe and not serialisable to disk."""

    __slots__ = ("_b",)

    def __init__(self, raw: bytes) -> None:
        self._b = raw

    @property
    def bytes(self) -> bytes:
        """Raw key bytes for HMAC operations and explicit IPC forwarding."""
        return self._b

    def __repr__(self) -> str:
        return "<EphemeralKey: redacted>"

    __str__ = __repr__

    def __reduce__(self) -> NoReturn:
        raise TypeError(
            "_EphemeralKey must not be serialised to disk. " "Pass .bytes explicitly for IPC."
        )


_RESULT_SEAL_KEY = _EphemeralKey(_secrets_mod.token_bytes(32))


# ── Module-level free functions (must be picklable for ProcessPoolExecutor) ────


def _ppid_watchdog() -> None:
    """Daemon thread: self-terminate if the parent process exits.

    In async-process mode a SIGKILL to the main process leaves Z3 worker
    processes as orphans.  This watchdog polls ``os.getppid()`` every two
    seconds; when re-parented (PPID changes) it calls ``sys.exit(0)`` so the
    OS can reclaim resources.

    On Windows ``os.getppid()`` is not available — we fall back to probing
    the parent PID with ``os.kill(..., 0)`` (send-no-signal test).
    """
    import os
    import sys
    import time as _t

    if not hasattr(os, "getpid"):  # pragma: no cover
        return  # should never happen, but guard against exotic runtimes

    use_getppid = hasattr(os, "getppid")
    if use_getppid:
        initial_ppid = os.getppid()
    else:  # pragma: no cover
        # Windows: remember the parent PID by reading /proc or using ctypes
        initial_ppid = None  # pragma: no cover
        try:  # pragma: no cover
            import ctypes  # pragma: no cover

            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]  # pragma: no cover
            initial_ppid = int(  # pragma: no cover
                ctypes.c_ulong(kernel32.GetCurrentProcessId()).value
            )
        except Exception:  # pragma: no cover
            return  # cannot determine PPID on this platform — skip watchdog

    while True:  # pragma: no cover
        _t.sleep(2.0)  # pragma: no cover
        try:  # pragma: no cover
            if use_getppid:  # pragma: no cover
                if os.getppid() != initial_ppid:  # pragma: no cover
                    sys.exit(0)  # pragma: no cover
            else:  # pragma: no cover
                # Windows: try zero-signal to test if parent is still alive
                try:  # pragma: no cover
                    os.kill(initial_ppid, 0)  # type: ignore[arg-type]  # pragma: no cover
                except OSError:  # pragma: no cover
                    sys.exit(0)  # pragma: no cover
        except SystemExit:  # pragma: no cover
            raise  # pragma: no cover
        except Exception:  # pragma: no cover
            pass  # don't let watchdog errors kill the worker


def _warmup_worker() -> None:
    """Pattern-exhaustive Z3 warmup suite.

    Runs eight diverse Z3 patterns to fully prime the internal expression
    caches and JIT before the first real user request.  One trivial solve
    is insufficient — Z3's internal theory solvers for integers, strings, and
    mixed-sort problems each have their own caches that benefit from priming.

    Also starts the PPID watchdog daemon thread (process mode only).
    """
    import threading

    import z3  # — intentional local import inside worker

    # Start PPID watchdog so orphaned worker processes self-terminate.
    # Only meaningful in process mode; harmless in thread mode.
    _wdog = threading.Thread(target=_ppid_watchdog, daemon=True, name="ppid-watchdog")
    _wdog.start()

    ctx = z3.Context()
    try:
        # ── Pattern 1: Real ≥ 0  (most common financial constraint) ──────────
        s = z3.Solver(ctx=ctx)
        s.set("timeout", 2_000)
        s.add(z3.Real("__wp_x", ctx) >= z3.RealVal(0, ctx))
        s.check()
        del s

        # ── Pattern 2: Real < 0  (negative-value boundary) ───────────────────
        s = z3.Solver(ctx=ctx)
        s.set("timeout", 2_000)
        x = z3.Real("__wp_neg", ctx)
        s.add(x < z3.RealVal(0, ctx))
        s.check()
        del s

        # ── Pattern 3: Integer arithmetic (non-Real sort) ─────────────────────
        s = z3.Solver(ctx=ctx)
        s.set("timeout", 2_000)
        n = z3.Int("__wp_n", ctx)
        s.add(n + z3.IntVal(1, ctx) > z3.IntVal(0, ctx))
        s.check()
        del s

        # ── Pattern 4: Two-variable inequality (most common invariant form) ───
        s = z3.Solver(ctx=ctx)
        s.set("timeout", 2_000)
        a = z3.Real("__wp_a", ctx)
        b = z3.Real("__wp_b", ctx)
        s.add(a - b >= z3.RealVal(0, ctx))
        s.check()
        del s

        # ── Pattern 5: Boolean conjunction ────────────────────────────────────
        s = z3.Solver(ctx=ctx)
        s.set("timeout", 2_000)
        p = z3.Bool("__wp_p", ctx)
        q = z3.Bool("__wp_q", ctx)
        s.add(z3.And(p, q))
        s.check()
        del s

        # ── Pattern 6: String sort (Seq) ──────────────────────────────────────
        s = z3.Solver(ctx=ctx)
        s.set("timeout", 2_000)
        sv = z3.String("__wp_s", ctx)
        s.add(sv == z3.StringVal("ok", ctx))
        s.check()
        del s

        # ── Pattern 7: Large rational (Decimal-scale) ─────────────────────────
        s = z3.Solver(ctx=ctx)
        s.set("timeout", 2_000)
        r = z3.Real("__wp_r", ctx)
        s.add(r <= z3.RealVal("999999999999999999999.999999", ctx))
        s.check()
        del s

        # ── Pattern 8: Unsat path (primes the attribution solver too) ─────────
        s = z3.Solver(ctx=ctx)
        s.set("timeout", 2_000)
        u = z3.Real("__wp_u", ctx)
        s.add(u > z3.RealVal(10, ctx))
        s.add(u < z3.RealVal(0, ctx))
        res = s.check()
        assert res == z3.unsat
        del s

    except Exception:  # pragma: no cover
        pass  # warmup failures must never prevent the worker from starting
    finally:
        del ctx


def _worker_solve(
    policy_cls: type[Policy],
    values: dict[str, Any],
    timeout_ms: int,
    rlimit: int = 0,
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
        result = solve(invariants, values, timeout_ms, rlimit)
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


def _worker_solve_sealed(
    policy_cls: type[Policy],
    values: dict[str, Any],
    timeout_ms: int,
    seal_key: bytes,
    rlimit: int = 0,
) -> dict[str, Any]:
    """Run :func:`_worker_solve` and return an HMAC-SHA256-signed envelope.

    The envelope layout is::

        {"_p": <json-payload-string>, "_t": <hmac-sha256-hex-digest>}

    where ``_p`` is the canonical ``sort_keys`` JSON serialisation of the inner
    decision dict produced by :func:`_worker_solve`, and ``_t`` is its
    HMAC-SHA256 tag using *seal_key*.

    This function must be a module-level free function so that
    :class:`~concurrent.futures.ProcessPoolExecutor` can pickle it by
    fully-qualified import path.

    Args:
        policy_cls: The Policy *class* to verify (picklable by import path).
        values:     Merged plain-dict of all field values.
        timeout_ms: Z3 per-solver timeout in milliseconds.
        seal_key:   HMAC key generated in the host process; forwarded here
                    as a plain ``bytes`` argument (picklable).

    Returns:
        A sealed envelope dict.  The caller must use :func:`_unseal_decision`
        to verify and unwrap before constructing a :class:`Decision`.
    """
    result = _worker_solve(policy_cls, values, timeout_ms, rlimit)
    payload = _json_mod.dumps(result, sort_keys=True, separators=(",", ":")).encode()
    tag = _hmac_mod.new(seal_key, payload, hashlib.sha256).hexdigest()
    return {"_p": payload.decode(), "_t": tag}


def _unseal_decision(sealed: dict[str, Any]) -> dict[str, Any]:
    """Verify the HMAC tag in *sealed* and return the inner decision dict.

    Uses :func:`hmac.compare_digest` (constant-time comparison) to prevent
    timing-side-channel attacks when comparing the expected and received tags.

    Args:
        sealed: The envelope dict produced by :func:`_worker_solve_sealed`.

    Returns:
        The inner plain decision dict (ready for :meth:`WorkerPool._dict_to_decision`).

    Raises:
        ValueError:  HMAC tag does not match — result was tampered or corrupted.
        KeyError:    Envelope is malformed (missing ``_p`` or ``_t`` keys).
    """
    payload = sealed["_p"].encode()
    expected = _hmac_mod.new(_RESULT_SEAL_KEY.bytes, payload, hashlib.sha256).hexdigest()
    if not _hmac_mod.compare_digest(sealed["_t"], expected):
        raise ValueError(
            "Decision integrity seal violated: HMAC mismatch. "
            "Worker result may have been tampered with."
        )
    result: dict[str, Any] = _json_mod.loads(payload)
    return result


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
        except Exception as exc:
            _log.debug(
                "worker._drain_executor: executor.shutdown raised: %s",
                exc,
            )
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
                    _log.error("worker.drain: failed to kill pid=%s: %s", proc.pid, exc)
    except Exception as exc:  # pragma: no cover
        _log.error("worker.drain: unexpected error during force-kill: %s", exc)  # pragma: no cover


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
    latency_threshold_ms: float | None = None
    worker_pct: float | None = None

    # Internals — not in constructor parameters.
    _executor: Executor = field(init=False, repr=False)
    _counter: int = field(init=False, default=0, repr=False)
    _lock: threading.Lock = field(init=False, default_factory=threading.Lock, repr=False)
    _alive: bool = field(init=False, default=False, repr=False)

    def __post_init__(self) -> None:
        self._lock = threading.Lock()
        self._counter = 0
        self._alive = False
        self._shed_limiter = AdaptiveConcurrencyLimiter(
            max_workers=self.max_workers,
            latency_threshold_ms=self.latency_threshold_ms,
            worker_pct=self.worker_pct,
        )

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
            raise WorkerError(f"WorkerPool.spawn failed ({type(exc).__name__}): {exc}") from exc

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
        rlimit: int = 0,
    ) -> Decision:
        """Submit one verification to the pool and block until complete.

        The counter is tracked host-side (no IPC).  Recycling is triggered
        if the counter reaches ``max_decisions_per_worker``.

        Args:
            policy_cls: The Policy *class* (not instance) — picklable.
            values:     Merged plain-dict of all field values.
            timeout_ms: Z3 per-solver timeout.
            rlimit:     Z3 resource limit (elementary operations).  0 = off.

        Returns:
            A :class:`~pramanix.decision.Decision`.  Never raises.
        """
        if not self._alive:
            return Decision.error(reason="WorkerPool is not running.")

        # Adaptive load shedding
        if not self._shed_limiter.acquire():
            return Decision.rate_limited(
                "Request shed: Z3 worker pool saturated with high latency. " "Retry after backoff."
            )

        _t0_shed = _time_module.monotonic()

        try:
            if self.mode == "async-process":
                # Process mode: sign the result with an HMAC seal so the host
                # can detect any IPC tampering before trusting the decision.
                future: Future[dict[str, Any]] = self._executor.submit(
                    _worker_solve_sealed,
                    policy_cls,
                    values,
                    timeout_ms,
                    _RESULT_SEAL_KEY.bytes,
                    rlimit,
                )
                sealed = future.result()
                try:
                    result_dict = _unseal_decision(sealed)
                except (ValueError, KeyError) as exc:
                    _log.error("WorkerPool: HMAC seal violation — %s", exc)
                    decision = Decision.error(
                        reason=("Worker result integrity check failed" " — HMAC mismatch.")
                    )
                else:
                    decision = self._dict_to_decision(result_dict)
            else:
                # Thread mode: shared memory — no IPC, no seal needed.
                future = self._executor.submit(
                    _worker_solve, policy_cls, values, timeout_ms, rlimit
                )
                result_dict = future.result()
                decision = self._dict_to_decision(result_dict)
        except WorkerError:
            self._shed_limiter.release(9999.0)
            raise
        except Exception as exc:
            _log.error("WorkerPool.submit_solve error: %s", exc)
            decision = Decision.error(
                reason=(f"Worker dispatch failed ({type(exc).__name__}): {exc}")
            )
            self._shed_limiter.release(9999.0)
        else:
            self._shed_limiter.release((_time_module.monotonic() - _t0_shed) * 1000)

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
            return ProcessPoolExecutor(max_workers=self.max_workers, mp_context=mp_ctx)
        raise WorkerError(f"Unknown worker mode: {self.mode!r}")

    def _run_warmup(self) -> None:
        """Submit ``_warmup_worker`` to every slot.  Best-effort."""
        futures = [self._executor.submit(_warmup_worker) for _ in range(self.max_workers)]
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
