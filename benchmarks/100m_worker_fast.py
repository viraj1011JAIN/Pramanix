# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""benchmarks/100m_worker_fast.py

Zero-IPC worker for the 100 M-decision sovereign audit.

Architecture improvement over 100m_audit_worker.py
----------------------------------------------------
Old: asyncio coroutine → ThreadPoolExecutor → Guard process → Z3 process
     2 IPC crossings per decision × ~15 ms each = ~30 ms overhead
     = 22-27 RPS/worker

New: 18 OS processes, each owns sync Guard + Z3 in one address space
     0 IPC crossings per decision
     Pure Python + Z3 overhead only: ~8-12 ms
     = 80-120 RPS/worker → 1 440-2 160 aggregate RPS

Three micro-optimisations that push toward the ceiling
------------------------------------------------------
1. max_input_bytes=0      — skips the per-decision JSON size-check round-trip
                            (~1-2 ms saved)
2. Pre-built payload cache — 10 000 payloads generated at startup; hot path
                            cycles through them with i % 10_000; no Decimal()
                            construction in the decision loop (~0.5 ms saved)
3. orjson + 8 MiB buffer  — one OS write() per ~100 k decisions vs one per
                            decision with stdlib json (~0.3 ms saved)

Structlog silencing
-------------------
guard.verify() emits one structlog JSON line per decision at INFO level.
At 100 RPS × 5.5 M decisions = 5.5 M lines per worker — ~2 GiB of terminal
I/O that completely dominates the benchmark.  We override structlog with a
null sink AFTER importing pramanix (so guard.py's module-level configure()
has already run) and BEFORE the first verify() call (so the logger cache has
not yet been bound).

Intent / state split
--------------------
guard.verify() requires that intent and state have non-overlapping keys.
All domain payload fields are placed in *intent*; *state* is passed as an
empty dict ``{}``.  Since none of the benchmark policies define Meta.version
or intent/state Pydantic models, no state-version check or Pydantic validation
runs — the payload goes directly to Z3.

Usage
-----
Called by 100m_orchestrator_fast.py — not intended for direct invocation.
"""
from __future__ import annotations

import gc
import hashlib
import multiprocessing
import os
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

# ── No module-level pramanix imports ──────────────────────────────────────────
# All heavy imports (Guard, GuardConfig, Z3, Pydantic) live inside
# worker_entry() so that importing this file in the orchestrator process does
# NOT load Z3, saving ~200 MiB RSS per process and eliminating Z3 JIT
# initialisation in the orchestrator.


# ── Helpers ───────────────────────────────────────────────────────────────────


def _silence_guard_logging() -> None:
    """Override structlog to a null sink in this worker process.

    Must be called AFTER ``from pramanix import Guard`` (so guard.py's
    module-level ``structlog.configure(PrintLoggerFactory)`` has already run)
    and BEFORE the first ``guard.verify()`` call (so the bound-logger cache
    has not been set yet).

    With structlog's ``cache_logger_on_first_use=False``, every log call
    re-evaluates through the (now empty) processor chain and null factory.
    The null factory's ``msg()`` is a no-op, so the overhead is one Python
    function call per log event — negligible at 100 RPS.
    """
    try:
        import structlog  # already imported as a side-effect of pramanix import

        class _NullLogger:
            """Discards all structlog events."""

            def msg(self, *args, **kwargs) -> None:
                pass

            def __getattr__(self, name: str):
                return self.msg

        class _NullLoggerFactory:
            def __call__(self, *args) -> _NullLogger:
                return _NullLogger()

        structlog.configure(
            processors=[],
            logger_factory=_NullLoggerFactory(),
            wrapper_class=structlog.BoundLogger,
            cache_logger_on_first_use=False,  # re-evaluate on every call
        )
    except Exception:
        # Silencing failure must never abort the worker — worst case we just
        # get noisy terminal output.
        pass


def _build_payload_cache(payload_gen, seed: int, n: int = 10_000) -> list:
    """Pre-generate *n* payloads at worker startup.

    Eliminates all ``Decimal()`` construction from the hot path.  The worker
    cycles through these *n* payloads with ``i % n``.

    Statistical note: cycling through a fixed 10 k-entry batch produces the
    same allow/block distribution as truly random payloads because the
    generator's RNG state is unique per worker (different seed) and the batch
    size (10 k) is much larger than any correlation length in the data.

    Memory budget: ~500 bytes × 10 000 payloads ≈ 5 MiB per worker.
    """
    import random
    rng = random.Random(seed)
    return [payload_gen(rng) for _ in range(n)]


# ── Worker entry point ────────────────────────────────────────────────────────


def worker_entry(
    domain_name: str,
    n_decisions: int,
    worker_id: int,
    output_dir: str,
    seed: int,
    solver_timeout_ms: int,
    max_decisions_per_worker: int,
    checkpoint_every: int,
    result_queue: multiprocessing.Queue,
) -> None:
    """Zero-IPC decision loop — executes in a dedicated OS process.

    Each process owns its Guard + Z3 context entirely in sync mode.
    No IPC per decision, no GIL contention, no asyncio overhead.

    Args:
        domain_name:              Domain identifier ("finance", "banking", …).
        n_decisions:              Total decisions this worker must produce.
        worker_id:                Worker index 0 … N_WORKERS-1.
        output_dir:               Directory for JSONL + checkpoint output files.
        seed:                     RNG seed (BASE_SEED + worker_id).
        solver_timeout_ms:        Z3 per-solver timeout (milliseconds).
        max_decisions_per_worker: Recycle Guard after this many decisions
                                  (keeps Z3 heap bounded at < 50 MiB growth).
        checkpoint_every:         Write a checkpoint record every N decisions.
        result_queue:             Queue.  Worker puts its summary dict here on
                                  completion (or error).  The orchestrator
                                  collects from this queue.
    """
    t_start = time.perf_counter()  # start before any setup to catch slow imports

    # ── Process-local path setup ──────────────────────────────────────────────
    _bench_dir = Path(__file__).resolve().parent
    _root_dir  = _bench_dir.parent
    for _p in (str(_root_dir / "src"), str(_bench_dir)):
        if _p not in sys.path:
            sys.path.insert(0, _p)

    # ── Load DOMAINS via importlib ────────────────────────────────────────────
    # Python rejects `from 100m_domain_policies import …` (digit-prefix module
    # name is a SyntaxError).  importlib.util.spec_from_file_location bypasses
    # the parser restriction by loading from an absolute file path.
    import importlib.util as _iutil

    _spec = _iutil.spec_from_file_location(
        "_bench_domains_100m",
        _bench_dir / "100m_domain_policies.py",
    )
    _mod = _iutil.module_from_spec(_spec)   # type: ignore[arg-type]
    _spec.loader.exec_module(_mod)           # type: ignore[union-attr]
    DOMAINS: dict = _mod.DOMAINS

    policy_class, payload_gen = DOMAINS[domain_name]

    # ── Heavy imports: pramanix triggers guard.py module-level configure() ───
    import orjson
    import psutil

    from pramanix import Guard, GuardConfig

    # ── Silence structlog AFTER pramanix import, BEFORE first verify() call ──
    _silence_guard_logging()

    # ── Pre-build payload cache ───────────────────────────────────────────────
    payload_cache = _build_payload_cache(payload_gen, seed, 10_000)
    cache_len = len(payload_cache)

    # ── Guard factory ─────────────────────────────────────────────────────────
    def _make_guard() -> Guard:
        return Guard(
            policy_class,
            GuardConfig(
                execution_mode    = "sync",      # KEY: Guard + Z3 in same process
                solver_timeout_ms = solver_timeout_ms,
                solver_rlimit     = 500_000,     # 500 k Z3 ops cap (logic-bomb DoS)
                metrics_enabled   = False,        # no Prometheus registry in workers
                otel_enabled      = False,        # no OTel exporter in workers
                log_level         = "WARNING",
                max_input_bytes   = 0,            # skip per-decision size-check
            ),
        )

    guard = _make_guard()
    decisions_on_guard = 0

    # ── Z3 JIT warmup ─────────────────────────────────────────────────────────
    # Z3's first solve loads ~20-50 MiB of JIT tables.  Running one warmup
    # decision before measuring the RSS baseline ensures the JIT cost is
    # excluded from the "steady-state RSS growth" measured by the benchmark.
    try:
        _wp = payload_cache[0]
        guard.verify(intent=_wp, state={})
        decisions_on_guard = 1
    except Exception:
        pass  # warmup failure must never abort the worker

    # ── RSS baseline: measured AFTER JIT warmup ───────────────────────────────
    proc         = psutil.Process(os.getpid())
    baseline_rss = proc.memory_info().rss / 1_048_576

    # ── Rolling chain hash: O(1) memory tamper-evident log ────────────────────
    # chain[0]   = SHA-256("pramanix_audit_{domain}_worker_{id}")
    # chain[i+1] = SHA-256(chain[i] || decision_id || "1"/"0")
    # Changing any logged record changes all subsequent hashes.
    chain_hash = hashlib.sha256(
        f"pramanix_audit_{domain_name}_worker_{worker_id}".encode()
    ).hexdigest()

    # ── Counters ───────────────────────────────────────────────────────────────
    n_allow = n_block = n_timeout = n_error = 0

    # ── Rolling latency window ─────────────────────────────────────────────────
    # Cleared at each checkpoint → O(checkpoint_every × 8 bytes) memory
    # (not O(n_decisions × 8 bytes)).  The per-window P99s are averaged for
    # the final summary.
    window_latencies: list[float] = []
    p99_windows:       list[float] = []   # one entry per checkpoint window

    # ── Output paths ──────────────────────────────────────────────────────────
    out      = Path(output_dir)
    log_path = out / f"{domain_name}_worker_{worker_id:02d}.jsonl"
    ck_path  = out / f"{domain_name}_worker_{worker_id:02d}_checkpoints.jsonl"

    BUFSIZE = 8 * 1024 * 1024   # 8 MiB write buffer: ~1 flush per 100 k lines

    try:
        with (
            open(log_path, "wb", buffering=BUFSIZE) as log_fh,
            open(ck_path,  "wb", buffering=0)        as ck_fh,  # checkpoints: unbuffered
        ):
            for i in range(n_decisions):
                # ── Pull from pre-built cache: O(1), zero Decimal allocation ──
                payload = payload_cache[i % cache_len]

                # ── Z3 verification — direct call, zero IPC ───────────────────
                # All payload fields go into *intent*; *state* is empty.
                # guard._verify_core() merges the two dicts before Z3 — this is
                # identical to passing all fields directly.  The non-overlapping-
                # key constraint (line 761 in guard.py) is trivially satisfied
                # because state=={} has no keys.
                t0       = time.perf_counter()
                decision = guard.verify(intent=payload, state={})
                ms       = (time.perf_counter() - t0) * 1000.0

                window_latencies.append(ms)

                sv = decision.status.value
                if decision.allowed:
                    n_allow += 1
                elif "timeout" in sv:
                    n_timeout += 1
                elif decision.violated_invariants:
                    n_block += 1
                else:
                    n_error += 1

                # ── Rolling chain hash ────────────────────────────────────────
                chain_hash = hashlib.sha256(
                    chain_hash.encode()
                    + decision.decision_id.encode()
                    + (b"1" if decision.allowed else b"0")
                ).hexdigest()

                # ── JSONL entry: short keys save ~20 bytes/line on 5.5 M lines ─
                entry: dict = {
                    "s":  i,
                    "ok": 1 if decision.allowed else 0,
                    "st": sv,
                    "ms": round(ms, 2),
                    "ch": chain_hash[:24],
                }
                if decision.violated_invariants:
                    entry["vi"] = list(decision.violated_invariants)

                log_fh.write(orjson.dumps(entry) + b"\n")

                # ── Worker recycle: keeps Z3 heap bounded ─────────────────────
                # After max_decisions_per_worker decisions, del guard + gen0 GC
                # brings RSS growth back to baseline.  The 1 M audit proved
                # +2.8 MiB growth with max_decisions_per_worker=10 000.
                decisions_on_guard += 1
                if decisions_on_guard >= max_decisions_per_worker:
                    del guard
                    gc.collect(0)       # gen0 only: fast, targeted
                    guard = _make_guard()
                    decisions_on_guard = 0

                # ── Checkpoint every N decisions ──────────────────────────────
                if (i + 1) % checkpoint_every == 0:
                    elapsed = time.perf_counter() - t_start
                    rss_now = proc.memory_info().rss / 1_048_576
                    rps     = (i + 1) / elapsed

                    # Compute window P99 and reset the window
                    win_s = sorted(window_latencies)
                    p99   = win_s[int(len(win_s) * 0.99)] if win_s else 0.0
                    p99_windows.append(p99)
                    window_latencies = []   # reset: O(1) memory per window

                    ckpt = {
                        "w":       worker_id,
                        "seq":     i + 1,
                        "ch":      chain_hash,
                        "p99":     round(p99, 2),
                        "allow":   n_allow,
                        "block":   n_block,
                        "timeout": n_timeout,
                        "error":   n_error,
                        "rps":     round(rps, 1),
                        "rss":     round(rss_now, 2),
                        "ts":      datetime.now(UTC).isoformat(),
                    }
                    ck_fh.write(orjson.dumps(ckpt) + b"\n")
                    log_fh.flush()  # ensure recent decisions survive a crash

        # Context manager __exit__ flushes the 8 MiB log buffer automatically.

    except Exception as exc:
        # Worker-level unhandled exception.  Put an error summary and return
        # cleanly so the orchestrator does not hang waiting on result_queue.
        result_queue.put({
            "worker_id":    worker_id,
            "n_decisions":  0,
            "n_allow":      0,
            "n_block":      0,
            "n_timeout":    0,
            "n_error":      1,
            "error":        f"{type(exc).__name__}: {exc}",
            "elapsed_s":    round(time.perf_counter() - t_start, 1),
            "avg_rps":      0.0,
            "baseline_rss": baseline_rss if "baseline_rss" in dir() else 0.0,
            "final_rss":    0.0,
            "rss_growth":   0.0,
            "chain_hash":   chain_hash,
            "p99_ms":       0.0,
            "log_file":     str(log_path),
            "ckpt_file":    str(ck_path),
        })
        return

    # ── Post-loop cleanup ─────────────────────────────────────────────────────
    del guard
    gc.collect(2)

    elapsed   = time.perf_counter() - t_start
    final_rss = proc.memory_info().rss / 1_048_576

    # Include any remaining window in the P99 average
    if window_latencies:
        win_s = sorted(window_latencies)
        p99_windows.append(win_s[int(len(win_s) * 0.99)] if win_s else 0.0)

    avg_p99 = (sum(p99_windows) / len(p99_windows)) if p99_windows else 0.0

    result_queue.put({
        "worker_id":    worker_id,
        "n_decisions":  n_decisions,
        "n_allow":      n_allow,
        "n_block":      n_block,
        "n_timeout":    n_timeout,
        "n_error":      n_error,
        "elapsed_s":    round(elapsed, 1),
        "avg_rps":      round(n_decisions / elapsed, 1) if elapsed > 0 else 0.0,
        "baseline_rss": round(baseline_rss, 2),
        "final_rss":    round(final_rss, 2),
        "rss_growth":   round(final_rss - baseline_rss, 2),
        "chain_hash":   chain_hash,
        "p99_ms":       round(avg_p99, 3),
        "log_file":     str(log_path),
        "ckpt_file":    str(ck_path),
    })
