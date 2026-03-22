# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""benchmarks/100m_audit_worker.py

Async worker coroutine + synchronous Z3 decision loop for the 100 M audit.

Architecture
------------
``run_worker`` is an ``async def`` coroutine awaited by the orchestrator via
``asyncio.gather()``.  It offloads the CPU-bound decision loop to a thread
(via ``asyncio.to_thread``) so that 18 workers run truly in parallel without
blocking the event loop.

Each worker is completely independent:
  * Its own seeded ``random.Random`` instance (deterministic, reproducible).
  * Its own invocations of ``pramanix.solver.solve()`` — which creates a
    fresh ``z3.Context()`` per call, making all Z3 operations thread-safe.
  * Its own JSONL output file and checkpoint file.
  * Its own rolling SHA-256 hash chain (O(1) memory: only ``prev_chain_hash``
    is kept between decisions).

Audit integrity
---------------
Tamper-evident log via a rolling hash chain::

    chain[0] = SHA256("pramanix|{domain}|w{id}|s{seed}")
    chain[i] = SHA256(chain[i-1] + "|" + fingerprint[i])

Changing any record changes all subsequent hashes.  The chain hash at every
checkpoint is added to a ``MerkleAnchor``; the resulting Merkle root
(~56 leaves per worker) goes into the worker summary and ``summary.json``.

Memory budget per worker
------------------------
  * Rolling latency window: CHECKPOINT_EVERY x 8 bytes = 800 KiB (cleared).
  * Chain hash: one 64-char hex string.
  * Merkle leaves: ~56 x 64 bytes < 4 KiB.
  * JSONL write buffer: 8 MiB (OS-managed).
  * Z3 Context: created and destroyed per solve() call.

Output files per worker
-----------------------
  {output_dir}/{domain}_worker_{id:02d}.jsonl
  {output_dir}/{domain}_worker_{id:02d}_checkpoints.jsonl
"""
from __future__ import annotations

import asyncio
import gc
import hashlib
import json
import random
import sys
import time
from pathlib import Path
from typing import Any, Callable

import psutil

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))

from pramanix.audit.merkle import MerkleAnchor  # noqa: E402
from pramanix.exceptions import SolverTimeoutError  # noqa: E402
from pramanix.solver import solve  # noqa: E402

__all__ = ["run_worker"]

# JSONL record key aliases (short keys reduce file size significantly):
#   s  = seq          – decision sequence number, 0-based
#   ok = allowed      – 1 if ALLOW, 0 if BLOCK
#   st = status       – "safe" / "unsafe" / "timeout" / "error"
#   ms = solver_ms    – wall-clock Z3 time in milliseconds (3 d.p.)
#   ch = chain_tag    – first 24 hex chars of chain hash (96-bit tamper tag)
#   vi = violated     – invariant labels (only written on non-safe outcomes)


def _sync_decision_loop(
    domain_name: str,
    policy_class: type,
    payload_generator: Callable[[random.Random], dict[str, Any]],
    n_decisions: int,
    worker_id: int,
    output_dir: Path,
    seed: int,
    solver_timeout_ms: int,
    checkpoint_every: int,
) -> dict[str, Any]:
    """Blocking Z3 decision loop — runs inside a dedicated OS thread.

    Args:
        domain_name:       Domain identifier string.
        policy_class:      Policy subclass whose invariants() are verified.
        payload_generator: Callable(rng) -> dict of field values.
        n_decisions:       Total decisions this worker must complete.
        worker_id:         Worker index (0-17).
        output_dir:        Directory for JSONL + checkpoint files.
        seed:              RNG seed (BASE_SEED + worker_id).
        solver_timeout_ms: Z3 per-solver timeout in milliseconds.
        checkpoint_every:  Emit a checkpoint record every N decisions.

    Returns:
        Worker summary dict consumed by the orchestrator aggregation step.
    """
    # ── Invariants: precomputed once per worker ───────────────────────────────
    # ConstraintExpr objects are immutable Python data structures.  The
    # transpiler creates new Z3 AST nodes per call inside each decision's own
    # z3.Context(), so sharing this list across decisions is thread-safe.
    invariants = policy_class.invariants()

    # ── Seeded RNG: deterministic, reproducible ───────────────────────────────
    rng = random.Random(seed)

    # ── Z3 JIT warmup BEFORE measuring the RSS baseline ──────────────────────
    # Z3's first-ever solve loads ~20-50 MiB of JIT + internal tables.
    # Running the warmup first ensures this one-time cost is excluded from
    # the "decision-loop growth" measured by the rss_bounded verdict check.
    proc = psutil.Process()
    try:
        import z3 as _z3
        _wctx = _z3.Context()
        _ws = _z3.Solver(ctx=_wctx)
        _ws.set("timeout", 2_000)
        _x = _z3.Real("__w", _wctx)
        _ws.add(_x >= _z3.RealVal(0, _wctx))
        _ws.check()
        del _ws, _x, _wctx
        gc.collect()
    except Exception:
        pass  # warmup failure must never abort the worker

    # ── RSS baseline: measured AFTER warmup ───────────────────────────────────
    rss_before_mib = proc.memory_info().rss / 1_048_576

    # ── Rolling hash chain: O(1) memory tamper-evident log ───────────────────
    chain_hash = hashlib.sha256(
        f"pramanix|{domain_name}|w{worker_id}|s{seed}".encode()
    ).hexdigest()

    # ── Merkle anchor over checkpoint chain hashes ───────────────────────────
    # ceil(n_decisions / checkpoint_every) leaves: ~56 per worker.
    merkle = MerkleAnchor()

    # ── Counters and rolling latency window ───────────────────────────────────
    n_allow = n_block = n_timeout = n_error = 0
    latencies: list[float] = []   # cleared at each checkpoint
    max_p99_ms: float = 0.0       # worst P99 across all windows

    # ── Output paths ──────────────────────────────────────────────────────────
    prefix = f"{domain_name}_worker_{worker_id:02d}"
    jsonl_path = output_dir / f"{prefix}.jsonl"
    cp_path = output_dir / f"{prefix}_checkpoints.jsonl"

    t_start = time.perf_counter()

    # ── Main decision loop ────────────────────────────────────────────────────
    # 8 MiB write buffer reduces syscall overhead across 5.5 M lines.
    with (
        open(jsonl_path, "w", buffering=8 * 1024 * 1024,
             encoding="utf-8") as jf,
        open(cp_path, "w", buffering=65_536, encoding="utf-8") as cpf,
    ):
        for seq in range(n_decisions):
            payload = payload_generator(rng)

            # ── Z3 solve ─────────────────────────────────────────────────────
            t0 = time.perf_counter()
            vi_list: list[str] = []
            try:
                result = solve(invariants, payload, solver_timeout_ms)
                lat_ms = (time.perf_counter() - t0) * 1000.0

                if result.sat:
                    status = "safe"
                    allowed = 1
                    n_allow += 1
                else:
                    status = "unsafe"
                    allowed = 0
                    vi_list = [
                        inv.label
                        for inv in result.violated
                        if inv.label
                    ]
                    n_block += 1

            except SolverTimeoutError as exc:
                lat_ms = (time.perf_counter() - t0) * 1000.0
                status = "timeout"
                allowed = 0
                vi_list = [exc.label] if exc.label else []
                n_timeout += 1

            except Exception as exc:
                lat_ms = (time.perf_counter() - t0) * 1000.0
                status = "error"
                allowed = 0
                vi_list = [type(exc).__name__]
                n_error += 1

            # ── Advance chain hash ────────────────────────────────────────────
            # Binds: sequence + outcome + latency (3 d.p.) + previous hash.
            fingerprint = f"{seq}|{allowed}|{status}|{lat_ms:.3f}"
            chain_hash = hashlib.sha256(
                (chain_hash + "|" + fingerprint).encode()
            ).hexdigest()

            # ── Write JSONL record ────────────────────────────────────────────
            rec: dict[str, Any] = {
                "s": seq,
                "ok": allowed,
                "st": status,
                "ms": round(lat_ms, 3),
                "ch": chain_hash[:24],  # 96-bit tamper tag
            }
            if vi_list:
                rec["vi"] = vi_list

            jf.write(json.dumps(rec, separators=(",", ":")) + "\n")

            # ── Accumulate rolling latency window ─────────────────────────────
            latencies.append(lat_ms)

            # ── Checkpoint ───────────────────────────────────────────────────
            if (seq + 1) % checkpoint_every == 0:
                sorted_lats = sorted(latencies)
                idx = min(
                    int(len(sorted_lats) * 0.99),
                    len(sorted_lats) - 1,
                )
                p99_ms = sorted_lats[idx]
                if p99_ms > max_p99_ms:
                    max_p99_ms = p99_ms

                merkle.add(chain_hash)

                cp_rec = {
                    "w": worker_id,
                    "seq": seq + 1,
                    "ch": chain_hash,       # full 64-char hash at checkpoint
                    "p99": round(p99_ms, 3),
                    "allow": n_allow,
                    "block": n_block,
                    "timeout": n_timeout,
                    "error": n_error,
                    "ts": time.strftime(
                        "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
                    ),
                }
                cpf.write(
                    json.dumps(cp_rec, separators=(",", ":")) + "\n"
                )
                cpf.flush()  # durable flush per checkpoint

                # Free rolling window — key to bounded RSS growth.
                latencies = []

        # ── Flush trailing decisions not covered by the last checkpoint ───────
        # Occurs when n_decisions is not an exact multiple of checkpoint_every.
        if latencies:
            sorted_lats = sorted(latencies)
            idx = min(
                int(len(sorted_lats) * 0.99),
                len(sorted_lats) - 1,
            )
            p99_ms = sorted_lats[idx]
            if p99_ms > max_p99_ms:
                max_p99_ms = p99_ms
            merkle.add(chain_hash)
            cp_rec = {
                "w": worker_id,
                "seq": n_decisions,
                "ch": chain_hash,
                "p99": round(p99_ms, 3),
                "allow": n_allow,
                "block": n_block,
                "timeout": n_timeout,
                "error": n_error,
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
            cpf.write(
                json.dumps(cp_rec, separators=(",", ":")) + "\n"
            )
            latencies = []

    # ── Final RSS + GC ────────────────────────────────────────────────────────
    gc.collect(2)
    rss_after_mib = proc.memory_info().rss / 1_048_576
    elapsed_s = time.perf_counter() - t_start

    return {
        "worker_id": worker_id,
        "domain": domain_name,
        "n_decisions": n_allow + n_block + n_timeout + n_error,
        "n_allow": n_allow,
        "n_block": n_block,
        "n_timeout": n_timeout,
        "n_error": n_error,
        "p99_ms": round(max_p99_ms, 3),
        "rss_before": round(rss_before_mib, 2),
        "rss_growth": round(rss_after_mib - rss_before_mib, 2),
        "elapsed_s": round(elapsed_s, 1),
        "final_chain_hash": chain_hash,
        "merkle_root": merkle.root() or "",
        "failed": False,
    }


async def run_worker(
    domain_name: str,
    policy_class: type,
    payload_generator: Callable[[random.Random], dict[str, Any]],
    n_decisions: int,
    worker_id: int,
    output_dir: Path,
    seed: int,
    solver_timeout_ms: int,
    max_decisions_per_worker: int,  # reserved — kept for API compatibility
    checkpoint_every: int,
) -> dict[str, Any]:
    """Async wrapper: runs ``_sync_decision_loop`` in the default executor.

    The orchestrator registers a ``ThreadPoolExecutor(max_workers=N_WORKERS)``
    as the event loop's default executor before calling ``asyncio.gather()``.
    Each coroutine offloads its CPU-bound Z3 loop to a dedicated OS thread,
    giving genuine parallelism (Z3 releases the GIL during solving).

    Args:
        max_decisions_per_worker: Unused in sync-direct mode (retained for
            API compatibility with the orchestrator's run_meta logging).
    """
    return await asyncio.to_thread(
        _sync_decision_loop,
        domain_name,
        policy_class,
        payload_generator,
        n_decisions,
        worker_id,
        output_dir,
        seed,
        solver_timeout_ms,
        checkpoint_every,
    )
