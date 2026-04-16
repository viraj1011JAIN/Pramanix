# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""benchmarks/100m_orchestrator_fast.py

Spawns 18 OS processes (multiprocessing.Process) to run 100 M Z3 decisions
for one domain.  Run once per domain for the full 500 M sovereign audit.

Architecture
------------
  Old (100m_audit_orchestrator.py):
    1 Python process → asyncio.gather(18 coroutines) → 18 ThreadPool threads
    Each thread calls Guard in "async-thread" mode → Guard spawns a Z3 worker
    process → 2 IPC crossings per decision → ~22-27 RPS/worker

  New (this file):
    18 independent OS processes, each owns a sync Guard + Z3 in one address
    space.  Zero IPC crossings per decision.  No GIL contention between workers
    (separate processes).  ~80-120 RPS/worker → 1 440-2 160 aggregate RPS.

Windows multiprocessing note
----------------------------
Python on Windows uses "spawn" (not "fork") as the default multiprocessing
start method.  In spawn mode, child processes import the *main* module to
reconstruct pickled functions.  Two requirements follow:

  1. ``multiprocessing.freeze_support()`` must be called at the very start of
     ``if __name__ == "__main__":`` or the processes will recursively spawn.

  2. The ``target`` function passed to ``Process(target=…)`` must be defined at
     MODULE LEVEL (not nested inside a function), so pickle can locate it as
     ``__main__.worker_entry``.

The module-level ``worker_entry`` defined below is a thin one-shot dispatcher
that uses importlib to load ``100m_worker_fast.py`` (whose name starts with a
digit and therefore cannot be imported with a regular ``import`` statement) and
delegates to its ``worker_entry`` implementation.

Usage
-----
    python benchmarks/100m_orchestrator_fast.py --domain finance
    python benchmarks/100m_orchestrator_fast.py --domain banking
    python benchmarks/100m_orchestrator_fast.py --domain fintech
    python benchmarks/100m_orchestrator_fast.py --domain healthcare
    python benchmarks/100m_orchestrator_fast.py --domain infra

Each invocation:
  * Runs a pre-flight health check (disk, RAM, CPU idle, sleep disabled).
  * Creates a timestamped output directory under benchmarks/results/.
  * Writes run_meta.json immediately at startup (survives a crash).
  * Spawns 18 multiprocessing.Process workers (daemon=False).
  * Collects results from a shared Queue as workers finish.
  * Writes summary.json and prints a verdict table when all workers complete.
"""
from __future__ import annotations

import argparse
import gc
import importlib.util as _iutil
import json
import multiprocessing
import os
import sys
import time
from datetime import datetime
from pathlib import Path

import psutil

# ── Constants ─────────────────────────────────────────────────────────────────

DECISIONS_PER_DOMAIN      = 100_000_000
N_WORKERS                 = 18
# Use ceiling division so N_WORKERS × DECISIONS_PER_WORKER ≥ DECISIONS_PER_DOMAIN
DECISIONS_PER_WORKER      = (DECISIONS_PER_DOMAIN + N_WORKERS - 1) // N_WORKERS  # 5_555_556
SOLVER_TIMEOUT_MS         = 150
MAX_DECISIONS_PER_WORKER  = 10_000       # DO NOT CHANGE — keeps RSS bounded
CHECKPOINT_EVERY          = 100_000
BASE_SEED                 = 42
RESULTS_ROOT              = Path("benchmarks/results")

# Domain names: hardcoded to avoid a module-level importlib call that would
# execute in every child process.
_DOMAIN_NAMES = ["finance", "banking", "fintech", "healthcare", "infra"]


# ── Module-level worker_entry (Windows spawn requirement) ─────────────────────
#
# On Windows, multiprocessing.Process pickles the target function as
# ("<module>", "<qualname>").  The child process unpickles by importing the
# module and looking up the function by name.  Because this file is the
# __main__ module, pickle serialises worker_entry as ("__main__", "worker_entry").
#
# The child process re-imports __main__ (i.e., re-executes this script up to
# the `if __name__ == "__main__":` guard) to find the function.  The guard
# prevents the spawning block from running again — no infinite recursion.
#
# The function must be at module level; nested functions are not picklable.

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
    """Module-level dispatcher — loads 100m_worker_fast.py and delegates.

    This thin wrapper exists solely to satisfy Windows multiprocessing's
    requirement that the target function be importable from the main module.
    The real worker logic lives in 100m_worker_fast.py.
    """
    _bench_dir = Path(__file__).resolve().parent
    _spec = _iutil.spec_from_file_location(
        "_bench_worker_fast_100m",
        _bench_dir / "100m_worker_fast.py",
    )
    _mod = _iutil.module_from_spec(_spec)   # type: ignore[arg-type]
    _spec.loader.exec_module(_mod)           # type: ignore[union-attr]
    _mod.worker_entry(
        domain_name, n_decisions, worker_id, output_dir, seed,
        solver_timeout_ms, max_decisions_per_worker, checkpoint_every,
        result_queue,
    )


# ── Pre-flight checks ─────────────────────────────────────────────────────────


def preflight(domain_name: str) -> bool:
    """System health checks before committing to a ~12-15 hour run.

    Checks disk space, available RAM, CPU idle %, and Windows sleep settings.
    Returns True only if all checks pass.
    """
    print(f"\n{'=' * 60}")
    print(f"  PRE-FLIGHT: {domain_name.upper()}")
    print(f"{'=' * 60}")

    checks: dict[str, bool] = {}

    # 1. Disk space — uncompressed JSONL: ~7-20 GB per domain run.
    disk = psutil.disk_usage("C:\\")
    free_gb = disk.free / 1024 ** 3
    checks["disk_25gb"] = free_gb >= 25
    tag = "[OK]" if checks["disk_25gb"] else "[NO]"
    print(f"  {tag} Disk free  : {free_gb:.1f} GB  (need >= 25)")

    # 2. Available RAM — 18 processes × ~200 MiB each ≈ 3.6 GiB.
    mem = psutil.virtual_memory()
    free_ram_gb = mem.available / 1024 ** 3
    checks["ram_4gb"] = free_ram_gb >= 4
    tag = "[OK]" if checks["ram_4gb"] else "[NO]"
    print(f"  {tag} RAM free   : {free_ram_gb:.1f} GB  (need >= 4)")

    # 3. CPU idle — no competing heavy workloads.
    cpu_pct = psutil.cpu_percent(interval=2)
    checks["cpu_idle"] = cpu_pct < 30
    tag = "[OK]" if checks["cpu_idle"] else "[NO]"
    print(f"  {tag} CPU idle   : {100 - cpu_pct:.0f}%  (need > 70%)")

    # 4. Windows sleep disabled — prevents OS from sleeping mid-run.
    try:
        import subprocess
        result = subprocess.run(
            ["powercfg", "-query", "SCHEME_CURRENT", "SUB_SLEEP"],
            capture_output=True, text=True, timeout=10,
        )
        sleep_ok = "0x00000000" in result.stdout
        checks["sleep_disabled"] = sleep_ok
        tag = "[OK]" if sleep_ok else "[NO]"
        print(f"  {tag} Sleep off  : {'YES' if sleep_ok else 'NO  (run: powercfg -change -standby-timeout-ac 0)'}")
    except Exception:
        checks["sleep_disabled"] = True  # can't check on non-Windows
        print("  [~~] Sleep off : check skipped (non-Windows or powercfg unavailable)")

    # 5. Prior completed runs (informational only — never blocks).
    existing = sorted(RESULTS_ROOT.glob(f"run_{domain_name}_*"), key=lambda d: d.name)
    completed = [d for d in existing if (d / "summary.json").exists()]
    if completed:
        print(f"\n  [!!] {len(completed)} prior completed run(s) found for '{domain_name}':")
        for c in completed[-3:]:   # show last 3 only
            print(f"       {c.name}")
        print("       A NEW timestamped run will be created (prior runs untouched).")

    all_pass = all(checks.values())
    verdict  = "  GO  [OK]" if all_pass else "  NO-GO [!!]"
    note     = "Safe to proceed." if all_pass else "Fix issues above before running."
    print(f"\n{verdict}  {note}")
    print(f"{'=' * 60}\n")
    return all_pass


# ── Directory setup ───────────────────────────────────────────────────────────


def make_run_dir(domain_name: str) -> Path:
    """Create a unique timestamped output directory for this domain run."""
    ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = RESULTS_ROOT / f"run_{domain_name}_{ts}"
    (run_dir / "workers").mkdir(parents=True, exist_ok=True)
    return run_dir


# ── Domain runner ─────────────────────────────────────────────────────────────


def run_domain(domain_name: str, run_dir: Path) -> dict:
    """Spawn 18 OS processes and collect results for one domain.

    Args:
        domain_name: One of the five benchmark domain names.
        run_dir:     Timestamped output directory (already created).

    Returns:
        summary dict written to ``run_dir / summary.json``.
    """
    workers_dir = run_dir / "workers"
    proc         = psutil.Process(os.getpid())
    baseline_rss = proc.memory_info().rss / 1_048_576

    # Write run_meta.json before spawning — survives a crash.
    meta: dict = {
        "domain":                   domain_name,
        "architecture":             "18 × multiprocessing.Process + sync Guard (zero IPC)",
        "decisions_target":         DECISIONS_PER_DOMAIN,
        "n_workers":                N_WORKERS,
        "decisions_per_worker":     DECISIONS_PER_WORKER,
        "max_decisions_per_worker": MAX_DECISIONS_PER_WORKER,
        "solver_timeout_ms":        SOLVER_TIMEOUT_MS,
        "checkpoint_every":         CHECKPOINT_EVERY,
        "base_seed":                BASE_SEED,
        "baseline_rss_mib":         round(baseline_rss, 2),
        "started_at":               datetime.now().isoformat(),
        "run_dir":                  str(run_dir),
    }
    with open(run_dir / "run_meta.json", "w") as f:
        json.dump(meta, f, indent=2)

    proj_rps  = N_WORKERS * 100          # conservative estimate
    proj_h    = DECISIONS_PER_DOMAIN / proj_rps / 3600
    print(f"\n[{domain_name.upper()}] launching {N_WORKERS} OS processes...")
    print(f"  {DECISIONS_PER_WORKER:,} decisions/worker x {N_WORKERS} workers = "
          f"{N_WORKERS * DECISIONS_PER_WORKER:,} total")
    print(f"  projected: ~{proj_rps:,} aggregate RPS -> ~{proj_h:.1f}h\n")

    t0 = time.perf_counter()

    # One Queue shared by all workers — results arrive as workers finish.
    result_queue: multiprocessing.Queue = multiprocessing.Queue()

    processes: list[multiprocessing.Process] = []
    for w in range(N_WORKERS):
        p = multiprocessing.Process(
            target=worker_entry,
            args=(
                domain_name,
                DECISIONS_PER_WORKER,
                w,
                str(workers_dir),
                BASE_SEED + w,
                SOLVER_TIMEOUT_MS,
                MAX_DECISIONS_PER_WORKER,
                CHECKPOINT_EVERY,
                result_queue,
            ),
            daemon=False,       # non-daemon: survives orchestrator sleep/wait
            name=f"{domain_name}_w{w:02d}",
        )
        p.start()
        processes.append(p)

    print(f"  all {N_WORKERS} processes started. PIDs: {[p.pid for p in processes]}\n")

    # ── Collect results as workers finish ─────────────────────────────────────
    worker_results: list[dict] = []
    finished = 0
    consecutive_timeouts = 0
    MAX_CONSECUTIVE_TIMEOUTS = 1080  # 1080 × 60 s = 18 hours wait max per worker

    while finished < N_WORKERS:
        try:
            result = result_queue.get(timeout=60)
            worker_results.append(result)
            finished += 1
            consecutive_timeouts = 0

            elapsed_so_far = time.perf_counter() - t0
            done_decisions = sum(r.get("n_decisions", 0) for r in worker_results)
            agg_rps = done_decisions / elapsed_so_far if elapsed_so_far > 0 else 0.0

            err_flag = " [ERROR]" if result.get("error") else ""
            print(
                f"  worker {result['worker_id']:02d} done{err_flag}  "
                f"RPS={result.get('avg_rps', 0):.0f}  "
                f"P99={result.get('p99_ms', 0):.1f}ms  "
                f"RSS+{result.get('rss_growth', 0):+.1f}MiB  "
                f"({finished}/{N_WORKERS} complete  "
                f"cumulative_rps={agg_rps:.0f})"
            )
        except Exception:
            # Queue.get() timed out — check for crashed workers.
            consecutive_timeouts += 1
            alive = [p for p in processes if p.is_alive()]
            dead  = [
                p for p in processes
                if not p.is_alive() and p.exitcode not in (0, None)
            ]
            if dead:
                print(f"  [WARN] {len(dead)} worker(s) crashed: "
                      f"{[(p.name, p.exitcode) for p in dead]}")
            print(f"  waiting... {len(alive)} workers still running  "
                  f"(timeout #{consecutive_timeouts})")

            if consecutive_timeouts >= MAX_CONSECUTIVE_TIMEOUTS:
                # Something is catastrophically wrong -- orphan all workers.
                print(f"  [FATAL] no result for {consecutive_timeouts * 60}s -- "
                      "terminating remaining workers")
                for p in alive:
                    p.terminate()
                break

    # Wait for all processes to fully exit before aggregating.
    for p in processes:
        p.join(timeout=60)
        if p.is_alive():
            p.terminate()
            p.join(timeout=5)

    elapsed   = time.perf_counter() - t0
    final_rss = proc.memory_info().rss / 1_048_576

    # ── Aggregate statistics ───────────────────────────────────────────────────
    good    = [r for r in worker_results if "error" not in r]
    errored = [r for r in worker_results if "error" in r]

    n_decisions = sum(r.get("n_decisions", 0) for r in good)
    n_allow     = sum(r.get("n_allow",     0) for r in good)
    n_block     = sum(r.get("n_block",     0) for r in good)
    n_timeout   = sum(r.get("n_timeout",   0) for r in good)
    n_error     = sum(r.get("n_error",     0) for r in good) + len(errored)

    rss_growths = [r["rss_growth"] for r in good if "rss_growth" in r]
    all_p99     = [r["p99_ms"]     for r in good if "p99_ms"     in r]
    all_rps     = [r["avg_rps"]    for r in good if "avg_rps"    in r]

    agg_rps = n_decisions / elapsed if elapsed > 0 else 0.0

    # Verdict: all five sub-checks must pass.
    verdict_complete    = n_decisions >= DECISIONS_PER_DOMAIN
    verdict_no_timeouts = n_timeout == 0
    verdict_no_errors   = n_error == 0
    verdict_no_crashes  = len(errored) == 0 and len(good) == N_WORKERS
    verdict_rss_bounded = (max(rss_growths) < 50) if rss_growths else False

    summary = {
        **meta,
        "completed_at":           datetime.now().isoformat(),
        "elapsed_s":              round(elapsed, 1),
        "elapsed_hours":          round(elapsed / 3600, 3),
        "agg_rps":                round(agg_rps, 1),
        "n_decisions":            n_decisions,
        "n_allow":                n_allow,
        "n_block":                n_block,
        "n_timeout":              n_timeout,
        "n_error":                n_error,
        "baseline_rss_mib":       round(baseline_rss, 2),
        "final_orchestrator_rss": round(final_rss, 2),
        "max_worker_rss_growth":  round(max(rss_growths), 2) if rss_growths else None,
        "avg_worker_p99_ms":      round(sum(all_p99)  / len(all_p99),  2) if all_p99 else None,
        "min_worker_rps":         round(min(all_rps), 1) if all_rps else None,
        "max_worker_rps":         round(max(all_rps), 1) if all_rps else None,
        "workers":                worker_results,
        "verdict": {
            "complete":       verdict_complete,
            "no_timeouts":    verdict_no_timeouts,
            "no_errors":      verdict_no_errors,
            "no_crashes":     verdict_no_crashes,
            "rss_bounded":    verdict_rss_bounded,
            "pass":           all([
                verdict_complete,
                verdict_no_timeouts,
                verdict_no_errors,
                verdict_no_crashes,
                verdict_rss_bounded,
            ]),
        },
    }

    with open(run_dir / "summary.json", "w") as f:
        json.dump(summary, f, indent=2)

    gc.collect(2)
    return summary


# ── Reporting ─────────────────────────────────────────────────────────────────


def print_summary(s: dict) -> None:
    """Print a human-readable verdict table for one domain run."""
    v = s["verdict"]
    d = s["domain"].upper()

    print(f"\n{'=' * 60}")
    print(f"  COMPLETE: {d}")
    print(f"{'=' * 60}")
    print(f"  decisions   : {s['n_decisions']:,}  "
          f"(target: {DECISIONS_PER_DOMAIN:,})")
    print(f"  elapsed     : {s['elapsed_hours']:.3f}h  "
          f"({s['elapsed_s']:.0f}s)")
    print(f"  agg RPS     : {s['agg_rps']:.0f}")
    print(f"  allow/block : {s['n_allow']:,} / {s['n_block']:,}  "
          f"({100*s['n_allow']/max(s['n_decisions'],1):.1f}% allow)")
    print(f"  timeouts    : {s['n_timeout']}")
    print(f"  errors      : {s['n_error']}")
    _rss = s.get("max_worker_rss_growth")
    print(f"  max RSS/wkr : {f'{_rss:+.1f}' if _rss is not None else 'N/A'} MiB")
    _p99 = s.get("avg_worker_p99_ms")
    print(f"  avg P99     : {f'{_p99:.1f}' if _p99 is not None else 'N/A'} ms")
    _rmin = s.get("min_worker_rps")
    _rmax = s.get("max_worker_rps")
    print(f"  RPS range   : {f'{_rmin:.0f}' if _rmin is not None else 'N/A'} - "
          f"{f'{_rmax:.0f}' if _rmax is not None else 'N/A'} per worker")
    print()
    for check, passed in v.items():
        if check == "pass":
            continue
        icon = "[OK]" if passed else "[NO]"
        print(f"  {icon} {check}")
    print()
    overall = "PASS [OK]" if v["pass"] else "FAIL [!!]"
    print(f"  VERDICT: {overall}")
    print(f"{'=' * 60}\n")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # REQUIRED on Windows: prevents recursive process spawning.
    # Must be the FIRST statement inside if __name__ == "__main__":
    multiprocessing.freeze_support()

    parser = argparse.ArgumentParser(
        description="Run 100 M Z3 policy decisions for one domain.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--domain",
        choices=_DOMAIN_NAMES,
        required=True,
        help="Domain to benchmark (finance / banking / fintech / healthcare / infra).",
    )
    parser.add_argument(
        "--skip-preflight",
        action="store_true",
        help="Skip the pre-flight health checks (disk, RAM, CPU, sleep).",
    )
    args = parser.parse_args()

    if not args.skip_preflight:
        if not preflight(args.domain):
            sys.exit(1)
        input("  Press ENTER to start, Ctrl-C to abort: ")

    RESULTS_ROOT.mkdir(parents=True, exist_ok=True)
    run_dir = make_run_dir(args.domain)
    print(f"\n  Output directory: {run_dir}")

    summary = run_domain(args.domain, run_dir)
    print_summary(summary)
