# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""benchmarks/100m_audit_orchestrator.py

Runs ONE domain of 100 M decisions across 18 worker threads.
Called once per domain — 5 separate invocations for the full 500 M audit.

Usage
-----
    python benchmarks/100m_audit_orchestrator.py --domain finance
    python benchmarks/100m_audit_orchestrator.py --domain banking
    python benchmarks/100m_audit_orchestrator.py --domain fintech
    python benchmarks/100m_audit_orchestrator.py --domain healthcare
    python benchmarks/100m_audit_orchestrator.py --domain infra

Each invocation:
  * Runs a pre-flight health check (disk, RAM, CPU idle, temperature).
  * Creates a timestamped output directory under benchmarks/results/.
  * Writes run_meta.json at the start (survives a crash).
  * Spawns 18 OS threads via a dedicated ThreadPoolExecutor.
  * Runs asyncio.gather() over 18 coroutines, each offloaded to a thread.
  * Writes summary.json on completion (verdict + all aggregate stats).
  * Writes run_{domain}.log capturing all terminal output (Google Drive sync).
  * Forces GC after the run for a clean cooldown baseline.

Why importlib instead of `from 100m_X import ...`
-------------------------------------------------
Python module names that start with a digit are syntactically invalid in
`import` and `from ... import` statements.
``importlib.util.spec_from_file_location`` loads by absolute file path,
bypassing the lexer restriction.

Thread pool sizing
------------------
N_WORKERS = 18 threads are created explicitly via ThreadPoolExecutor and
registered as the asyncio event loop's default executor BEFORE gather() runs.
This guarantees that asyncio.to_thread() — used inside each run_worker
coroutine — dispatches to the correct pool instead of the OS default
(which is capped at min(32, cpu_count+4) and may be smaller than 18).
"""
from __future__ import annotations

import argparse
import asyncio
import concurrent.futures
import gc
import importlib.util
import json
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path

import psutil

# ── Logging (WARNING level: suppress per-decision noise) ─────────────────────
logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

DECISIONS_PER_DOMAIN = 100_000_000
N_WORKERS = 18
DECISIONS_PER_WORKER = DECISIONS_PER_DOMAIN // N_WORKERS   # 5 555 555
SOLVER_TIMEOUT_MS = 150
MAX_DECISIONS_PER_WORKER = 10_000   # logged in metadata; unused in sync mode
CHECKPOINT_EVERY = 100_000
BASE_SEED = 42

RESULTS_ROOT = Path("benchmarks/results")

# ── Module loader helper ───────────────────────────────────────────────────────


def _load_module(filename: str):
    """Load a .py file by path, bypassing digit-prefix naming restriction."""
    path = Path(__file__).parent / filename
    if not path.exists():
        raise FileNotFoundError(f"Benchmark module not found: {path}")
    spec = importlib.util.spec_from_file_location("_bench_module", path)
    mod = importlib.util.module_from_spec(spec)   # type: ignore[arg-type]
    spec.loader.exec_module(mod)                   # type: ignore[union-attr]
    return mod


# ── Pre-flight checks ─────────────────────────────────────────────────────────


def check_preflight(domain_name: str) -> bool:
    """Run system health checks before committing to a ~4-15 hour run.

    Returns True only if every check passes.  Prints a GO / NO-GO banner.
    """
    print(f"\n{'=' * 60}")
    print(f"  PRE-FLIGHT: {domain_name.upper()} DOMAIN")
    print(f"{'=' * 60}")

    checks: dict[str, bool] = {}

    # 1. Disk space — minimum 25 GB free (uncompressed JSONL: ~7-20 GB).
    disk = psutil.disk_usage("C:\\")
    free_gb = disk.free / (1024 ** 3)
    checks["disk_space_25gb"] = free_gb >= 25
    tag = "[OK]" if checks["disk_space_25gb"] else "[NO]"
    print(f"  {tag} Disk free: {free_gb:.1f} GB (need >= 25)")

    # 2. CPU temperature — machine must have cooled between runs.
    try:
        temps = psutil.sensors_temperatures()
        if temps:
            all_temps = [
                t.current
                for readings in temps.values()
                for t in readings
            ]
            max_temp = max(all_temps)
            checks["cpu_cooled"] = max_temp < 60
            tag = "[OK]" if checks["cpu_cooled"] else "[NO]"
            print(f"  {tag} CPU temp: {max_temp:.0f} C (need < 60)")
        else:
            checks["cpu_cooled"] = True
            print("  [~~] CPU temp: not readable on Windows (assumed OK)")
    except Exception:
        checks["cpu_cooled"] = True
        print("  [~~] CPU temp: sensor read failed (assumed OK)")

    # 3. RAM — need at least 4 GB free for 18 worker threads + Z3 overhead.
    mem = psutil.virtual_memory()
    free_ram_gb = mem.available / (1024 ** 3)
    checks["ram_available"] = free_ram_gb >= 4
    tag = "[OK]" if checks["ram_available"] else "[NO]"
    print(f"  {tag} RAM free: {free_ram_gb:.1f} GB (need >= 4)")

    # 4. CPU idle — no competing heavy workloads.
    total_cpu = psutil.cpu_percent(interval=2)
    checks["cpu_idle"] = total_cpu < 20
    tag = "[OK]" if checks["cpu_idle"] else "[NO]"
    print(f"  {tag} CPU idle: {100 - total_cpu:.0f}% (need > 80% idle)")

    # 5. Prior runs (informational only — never blocks the run).
    existing = sorted(
        RESULTS_ROOT.glob(f"run_{domain_name}_*"),
        key=lambda d: d.name,
    )
    completed = [d for d in existing if (d / "summary.json").exists()]
    if completed:
        print(f"  [!!] Existing completed runs for '{domain_name}':")
        for c in completed:
            print(f"       {c.name}")
        print("       A NEW run will be created (existing runs untouched).")
    checks["domain_check"] = True

    all_pass = all(checks.values())
    verdict = "GO  [OK]" if all_pass else "NO-GO [!!]"
    safe = "Safe to proceed." if all_pass else "Fix issues above first."
    print(f"\n  {verdict} — {safe}")
    print(f"{'=' * 60}\n")
    return all_pass


def make_run_dir(domain_name: str) -> Path:
    """Create a unique timestamped output directory for this run."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = RESULTS_ROOT / f"run_{domain_name}_{ts}"
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


# ── Domain runner ─────────────────────────────────────────────────────────────


async def run_domain(
    domain_name: str,
    run_dir: Path,
    run_worker,    # noqa: ANN001  — imported from 100m_audit_worker
    DOMAINS: dict,  # noqa: ANN001  — imported from 100m_domain_policies
) -> dict:
    """Run 100 M decisions for one domain across 18 worker threads.

    Sets the event loop's default executor to a custom ThreadPoolExecutor
    with exactly N_WORKERS threads before dispatching any work.  This
    ensures that ``asyncio.to_thread()`` (called inside each ``run_worker``
    coroutine) uses the correct pool rather than the OS default (which may
    be smaller than 18).
    """
    policy_class, payload_gen = DOMAINS[domain_name]

    workers_dir = run_dir / "workers"
    workers_dir.mkdir(exist_ok=True)

    # Register a dedicated thread pool BEFORE any workers are dispatched.
    loop = asyncio.get_running_loop()
    executor = concurrent.futures.ThreadPoolExecutor(
        max_workers=N_WORKERS,
        thread_name_prefix=f"pramanix-bench-{domain_name}",
    )
    loop.set_default_executor(executor)

    # RSS baseline in the orchestrator process (before threads start Z3).
    proc = psutil.Process(os.getpid())
    baseline_rss = proc.memory_info().rss / 1_048_576

    run_meta = {
        "domain": domain_name,
        "decisions": DECISIONS_PER_DOMAIN,
        "n_workers": N_WORKERS,
        "decisions_per_worker": DECISIONS_PER_WORKER,
        "max_decisions_per_worker": MAX_DECISIONS_PER_WORKER,
        "solver_timeout_ms": SOLVER_TIMEOUT_MS,
        "checkpoint_every": CHECKPOINT_EVERY,
        "base_seed": BASE_SEED,
        "baseline_rss_mib": round(baseline_rss, 2),
        "started_at": datetime.now().isoformat(),
        "run_dir": str(run_dir),
    }

    # Write run_meta immediately — crash-resilient record of intent.
    with open(run_dir / "run_meta.json", "w") as f:
        json.dump(run_meta, f, indent=2)

    log.warning(
        "[%s] Starting: %s decisions across %d workers. JSONL -> %s",
        domain_name.upper(),
        f"{DECISIONS_PER_DOMAIN:,}",
        N_WORKERS,
        workers_dir,
    )

    t0 = time.perf_counter()

    tasks = [
        run_worker(
            domain_name=domain_name,
            policy_class=policy_class,
            payload_generator=payload_gen,
            n_decisions=DECISIONS_PER_WORKER,
            worker_id=w,
            output_dir=workers_dir,
            seed=BASE_SEED + w,
            solver_timeout_ms=SOLVER_TIMEOUT_MS,
            max_decisions_per_worker=MAX_DECISIONS_PER_WORKER,
            checkpoint_every=CHECKPOINT_EVERY,
        )
        for w in range(N_WORKERS)
    ]

    results = await asyncio.gather(*tasks, return_exceptions=True)

    elapsed = time.perf_counter() - t0
    final_rss = proc.memory_info().rss / 1_048_576

    # ── Aggregate worker results ───────────────────────────────────────────────
    worker_summaries: list[dict] = []
    for i, r in enumerate(results):
        if isinstance(r, Exception):
            log.error("Worker %d FAILED: %s", i, r)
            worker_summaries.append({
                "worker_id": i,
                "error": str(r),
                "failed": True,
                # Zero-value keys so aggregation never KeyErrors.
                "n_decisions": 0, "n_allow": 0, "n_block": 0,
                "n_timeout": 0, "n_error": 0,
                "rss_growth": 0.0, "p99_ms": 0.0,
                "final_chain_hash": "", "merkle_root": "",
            })
        else:
            worker_summaries.append(r)

    good = [s for s in worker_summaries if not s.get("failed")]

    n_decisions = sum(s["n_decisions"] for s in good)
    n_allow = sum(s["n_allow"] for s in good)
    n_block = sum(s["n_block"] for s in good)
    n_timeout = sum(s["n_timeout"] for s in good)
    n_error = sum(s["n_error"] for s in good)
    rss_growths = [s["rss_growth"] for s in good]
    all_p99 = [s["p99_ms"] for s in good]

    # Per-worker Merkle roots (one per worker).
    merkle_roots = {s["worker_id"]: s["merkle_root"] for s in good}
    final_chains = {s["worker_id"]: s["final_chain_hash"] for s in good}

    max_rss_growth = round(max(rss_growths), 2) if rss_growths else None
    avg_p99 = round(sum(all_p99) / len(all_p99), 3) if all_p99 else None
    max_p99 = round(max(all_p99), 3) if all_p99 else None
    avg_rps = round(n_decisions / elapsed, 1) if elapsed > 0 else 0

    host_rss_growth = round(final_rss - baseline_rss, 2)

    # rss_bounded: workers run as threads in one process — per-thread RSS is
    # not isolable.  Use the host-level delta divided by N_WORKERS as an
    # unbiased per-worker estimate.  Threshold: 50 MiB per worker.
    estimated_per_worker_rss = (
        host_rss_growth / N_WORKERS if N_WORKERS > 0 else host_rss_growth
    )
    rss_bounded = estimated_per_worker_rss < 50

    summary = {
        **run_meta,
        "completed_at": datetime.now().isoformat(),
        "elapsed_s": round(elapsed, 1),
        "elapsed_hours": round(elapsed / 3600, 3),
        "avg_rps": avg_rps,
        "n_decisions": n_decisions,
        "n_allow": n_allow,
        "n_block": n_block,
        "n_timeout": n_timeout,
        "n_error": n_error,
        "baseline_rss_mib": round(baseline_rss, 2),
        "final_rss_mib": round(final_rss, 2),
        "host_rss_growth_mib": host_rss_growth,
        "estimated_per_worker_rss_mib": round(estimated_per_worker_rss, 2),
        "max_worker_rss_growth": max_rss_growth,
        "avg_p99_ms": avg_p99,
        "max_p99_ms": max_p99,
        "merkle_roots": merkle_roots,
        "final_chain_hashes": final_chains,
        "workers": worker_summaries,
        "verdict": {
            "complete": n_decisions >= DECISIONS_PER_DOMAIN,
            "no_timeouts": n_timeout == 0,
            "no_errors": n_error == 0,
            "rss_bounded": rss_bounded,
        },
    }
    summary["verdict"]["pass"] = all(summary["verdict"].values())

    with open(run_dir / "summary.json", "w") as f:
        json.dump(summary, f, indent=2)

    # Clean slate for the cooldown period.
    gc.collect(2)
    executor.shutdown(wait=False)   # let OS reclaim threads asynchronously

    return summary


# ── Terminal summary printer ───────────────────────────────────────────────────


def print_run_summary(summary: dict) -> None:
    v = summary["verdict"]
    domain = summary["domain"].upper()
    sep = "=" * 62

    print(f"\n{sep}")
    print(f"  RUN COMPLETE: {domain}")
    print(f"{sep}")
    print(f"  Decisions   : {summary['n_decisions']:,}")
    print(f"  Elapsed     : {summary['elapsed_hours']:.3f} h")
    print(f"  Avg RPS     : {summary['avg_rps']:,.0f}")
    print(f"  Allow/Block : {summary['n_allow']:,} / {summary['n_block']:,}")
    print(f"  Timeouts    : {summary['n_timeout']}")
    print(f"  Errors      : {summary['n_error']}")
    print(f"  Host RSS d  : {summary['host_rss_growth_mib']:+.2f} MiB")

    mrss = summary.get("max_worker_rss_growth")
    if mrss is not None:
        print(f"  Max RSS/wkr : {mrss:+.2f} MiB")
    else:
        print("  Max RSS/wkr : N/A")

    p99 = summary.get("avg_p99_ms")
    if p99 is not None:
        print(f"  Avg P99     : {p99:.3f} ms")
    else:
        print("  Avg P99     : N/A")

    p99m = summary.get("max_p99_ms")
    if p99m is not None:
        print(f"  Max P99     : {p99m:.3f} ms")
    else:
        print("  Max P99     : N/A")

    print()

    def ok(b: bool) -> str:
        return "[OK]" if b else "[NO]"

    ndec = summary["n_decisions"]
    print(f"  {ok(v['complete'])}    decisions_complete"
          f"  ({ndec:,} >= {DECISIONS_PER_DOMAIN:,})")
    print(f"  {ok(v['no_timeouts'])} no_timeouts")
    print(f"  {ok(v['no_errors'])}   no_errors")
    print(f"  {ok(v['rss_bounded'])} rss_bounded  (< 50 MiB / worker)")
    print()
    verdict_str = "PASS [OK]" if v["pass"] else "FAIL [NO]"
    print(f"  VERDICT: {verdict_str}")
    print(f"  Output : {summary['run_dir']}")
    print(f"{sep}\n")

    if v["pass"]:
        print("  Machine can be powered down / cooled before the next run.")
        print("  Recommended cooldown: 30-60 min.\n")
    else:
        print("  Review failures above before proceeding to the next domain.\n")


# ── Entry point ───────────────────────────────────────────────────────────────


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run 100 M Pramanix Z3 decisions for one domain."
    )
    parser.add_argument(
        "--domain",
        choices=["finance", "banking", "fintech", "healthcare", "infra"],
        required=True,
        help="Domain to run.",
    )
    parser.add_argument(
        "--skip-preflight",
        action="store_true",
        help="Skip pre-flight checks (not recommended).",
    )
    args = parser.parse_args()

    # ── Load sibling modules by file path (digit-prefix safe) ─────────────────
    _dp = _load_module("100m_domain_policies.py")
    _aw = _load_module("100m_audit_worker.py")
    DOMAINS = _dp.DOMAINS
    run_worker = _aw.run_worker

    if args.domain not in DOMAINS:
        parser.error(f"Domain '{args.domain}' not found in DOMAINS registry.")

    # ── Pre-flight ────────────────────────────────────────────────────────────
    RESULTS_ROOT.mkdir(parents=True, exist_ok=True)

    if not args.skip_preflight:
        if not check_preflight(args.domain):
            print("Pre-flight failed. Aborting.")
            sys.exit(1)
        try:
            input(
                "  Press ENTER to confirm and start the run,"
                " or Ctrl+C to abort: "
            )
        except KeyboardInterrupt:
            print("\n  Aborted by user.")
            sys.exit(0)

    # ── Create run directory ──────────────────────────────────────────────────
    run_dir = make_run_dir(args.domain)
    print(f"\n  Run output directory: {run_dir}\n")

    # ── Tee stdout + logging to a persistent run log ──────────────────────────
    # Captures: pre-flight banner, all print() output, WARNING-level log lines.
    # Flushed line-by-line (buffering=1) so Google Drive Desktop syncs
    # partial output while the run is still in progress.
    log_path = run_dir / f"run_{args.domain}.log"

    class _Tee:
        """Duplicate writes to both *a* (original stdout) and *b* (log file)."""

        def __init__(self, a, b):  # noqa: ANN001
            self._a, self._b = a, b

        def write(self, s: str) -> int:
            self._a.write(s)
            return self._b.write(s)

        def flush(self) -> None:
            self._a.flush()
            self._b.flush()

        def isatty(self) -> bool:
            return False

    _log_fh = open(log_path, "w", buffering=1, encoding="utf-8")
    _orig_stdout = sys.stdout
    sys.stdout = _Tee(sys.stdout, _log_fh)  # type: ignore[assignment]

    # Mirror WARNING-level log records to the same file.
    _fh = logging.FileHandler(log_path, encoding="utf-8")
    _fh.setFormatter(logging.Formatter(
        "%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    ))
    logging.getLogger().addHandler(_fh)

    # ── Run ───────────────────────────────────────────────────────────────────
    try:
        summary = asyncio.run(
            run_domain(args.domain, run_dir, run_worker, DOMAINS)
        )
        print_run_summary(summary)
    finally:
        sys.stdout = _orig_stdout
        logging.getLogger().removeHandler(_fh)
        _log_fh.close()

    print(f"  Run log  : {log_path}")
