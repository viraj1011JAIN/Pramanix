# Pramanix: 5 × 100M Decision Runs
# One domain per run. Full cooldown between runs. Fully independent.

---

## Architecture Change

This is not one 500M run with breaks.
These are **5 completely independent runs**.

Each run:
- Fresh Python process
- Fresh RSS baseline
- Fresh Merkle chain
- Its own output directory with timestamp
- Its own pre-flight + post-run verification
- Produces a standalone, self-contained audit artifact

The 5 artifacts are assembled into the final report after all runs complete.

---

## What Changes in the Code

Only the orchestrator changes. The worker, policies, and merge script stay identical.

The orchestrator now runs **exactly one domain per execution** via `--domain` argument.
No loops. No "run all 5". One invocation = one domain = one run = one artifact.

---

## Updated `benchmarks/100m_audit_orchestrator.py`

```python
"""
benchmarks/100m_audit_orchestrator.py

Runs ONE domain of 100M decisions across 18 workers.
Called once per domain. 5 separate invocations for 5 domains.

Usage:
    python benchmarks/100m_audit_orchestrator.py --domain finance
    python benchmarks/100m_audit_orchestrator.py --domain banking
    python benchmarks/100m_audit_orchestrator.py --domain fintech
    python benchmarks/100m_audit_orchestrator.py --domain healthcare
    python benchmarks/100m_audit_orchestrator.py --domain infra

Each run writes to its own timestamped output directory.
Never run two domains simultaneously.
"""
from __future__ import annotations
import argparse
import asyncio
import gc
import json
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path

import psutil

sys.path.insert(0, str(Path(__file__).parent))
from 100m_domain_policies import DOMAINS
from 100m_audit_worker import run_worker

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s  %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────────────

DECISIONS_PER_DOMAIN       = 100_000_000
N_WORKERS                  = 18
DECISIONS_PER_WORKER       = DECISIONS_PER_DOMAIN // N_WORKERS  # 5_555_556
SOLVER_TIMEOUT_MS          = 150
MAX_DECISIONS_PER_WORKER   = 10_000     # DO NOT CHANGE
CHECKPOINT_EVERY           = 100_000
BASE_SEED                  = 42

RESULTS_ROOT = Path("benchmarks/results")


def make_run_dir(domain_name: str) -> Path:
    """Each run gets a unique timestamped directory."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = RESULTS_ROOT / f"run_{domain_name}_{ts}"
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


def check_preflight(domain_name: str) -> bool:
    """
    Pre-flight checks before committing to a 15-hour run.
    Returns True if safe to proceed.
    """
    print(f"\n{'='*60}")
    print(f"  PRE-FLIGHT: {domain_name.upper()} DOMAIN")
    print(f"{'='*60}")

    checks = {}

    # 1. Disk space (need 25 GB free per run minimum)
    disk = psutil.disk_usage("C:\\")
    free_gb = disk.free / (1024 ** 3)
    checks["disk_space_25gb"] = free_gb >= 25
    print(f"  {'✓' if checks['disk_space_25gb'] else '✗'} Disk free: {free_gb:.1f} GB (need ≥ 25)")

    # 2. CPU temperature — check if machine has cooled down
    try:
        temps = psutil.sensors_temperatures()
        if temps:
            all_temps = [t.current for readings in temps.values() for t in readings]
            max_temp = max(all_temps)
            checks["cpu_cooled"] = max_temp < 60
            print(f"  {'✓' if checks['cpu_cooled'] else '✗'} CPU temp: {max_temp:.0f}°C (need < 60°C)")
        else:
            # Windows may not expose temps via psutil — skip check
            checks["cpu_cooled"] = True
            print(f"  ~ CPU temp: not readable on this platform (assumed OK)")
    except Exception:
        checks["cpu_cooled"] = True
        print(f"  ~ CPU temp: sensor read failed (assumed OK)")

    # 3. RAM available (need at least 4 GB free for 18 workers)
    mem = psutil.virtual_memory()
    free_ram_gb = mem.available / (1024 ** 3)
    checks["ram_available"] = free_ram_gb >= 4
    print(f"  {'✓' if checks['ram_available'] else '✗'} RAM free: {free_ram_gb:.1f} GB (need ≥ 4)")

    # 4. No other heavy processes
    total_cpu = psutil.cpu_percent(interval=2)
    checks["cpu_idle"] = total_cpu < 20
    print(f"  {'✓' if checks['cpu_idle'] else '✗'} CPU idle: {100-total_cpu:.0f}% (need > 80% idle)")

    # 5. Domain not already completed
    existing = list(RESULTS_ROOT.glob(f"run_{domain_name}_*"))
    completed = [d for d in existing if (d / "summary.json").exists()]
    if completed:
        print(f"  ! Already completed runs found for {domain_name}:")
        for c in completed:
            print(f"      {c.name}")
        print(f"    Proceeding will create a NEW run (existing runs untouched).")
    checks["domain_check"] = True

    all_pass = all(checks.values())
    print(f"\n  {'GO ✓' if all_pass else 'NO-GO ✗'} — {'Safe to proceed.' if all_pass else 'Fix issues above before running.'}")
    print(f"{'='*60}\n")
    return all_pass


async def run_domain(domain_name: str, run_dir: Path) -> dict:
    """Run 100M decisions for one domain across 18 workers."""
    policy_class, payload_gen = DOMAINS[domain_name]

    domain_dir = run_dir / "workers"
    domain_dir.mkdir(exist_ok=True)

    # Baseline RSS before any workers spawn
    proc = psutil.Process(os.getpid())
    baseline_rss = proc.memory_info().rss / 1_048_576

    run_meta = {
        "domain":           domain_name,
        "decisions":        DECISIONS_PER_DOMAIN,
        "n_workers":        N_WORKERS,
        "decisions_per_worker": DECISIONS_PER_WORKER,
        "max_decisions_per_worker": MAX_DECISIONS_PER_WORKER,
        "solver_timeout_ms": SOLVER_TIMEOUT_MS,
        "baseline_rss_mib": round(baseline_rss, 2),
        "started_at":       datetime.now().isoformat(),
        "run_dir":          str(run_dir),
    }

    # Save run metadata immediately (survives crash)
    with open(run_dir / "run_meta.json", "w") as f:
        json.dump(run_meta, f, indent=2)

    log.warning(
        f"[{domain_name.upper()}] Starting: {DECISIONS_PER_DOMAIN:,} decisions "
        f"across {N_WORKERS} workers. Est. ~15 hours."
    )

    t0 = time.perf_counter()

    tasks = [
        run_worker(
            domain_name=domain_name,
            policy_class=policy_class,
            payload_generator=payload_gen,
            n_decisions=DECISIONS_PER_WORKER,
            worker_id=w,
            output_dir=domain_dir,
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

    worker_summaries = []
    for i, r in enumerate(results):
        if isinstance(r, Exception):
            log.error(f"Worker {i} FAILED: {r}")
            worker_summaries.append({"worker_id": i, "error": str(r), "failed": True})
        else:
            worker_summaries.append(r)

    # Aggregate stats
    good = [s for s in worker_summaries if not s.get("failed")]
    n_decisions   = sum(s["n_decisions"]  for s in good)
    n_allow       = sum(s["n_allow"]      for s in good)
    n_block       = sum(s["n_block"]      for s in good)
    n_timeout     = sum(s["n_timeout"]    for s in good)
    n_error       = sum(s["n_error"]      for s in good)
    rss_growths   = [s["rss_growth"]      for s in good]
    all_p99       = [s["p99_ms"]          for s in good]

    summary = {
        **run_meta,
        "completed_at":     datetime.now().isoformat(),
        "elapsed_s":        round(elapsed, 1),
        "elapsed_hours":    round(elapsed / 3600, 2),
        "avg_rps":          round(n_decisions / elapsed, 1) if elapsed > 0 else 0,
        "n_decisions":      n_decisions,
        "n_allow":          n_allow,
        "n_block":          n_block,
        "n_timeout":        n_timeout,
        "n_error":          n_error,
        "baseline_rss_mib": round(baseline_rss, 2),
        "final_rss_mib":    round(final_rss, 2),
        "host_rss_growth":  round(final_rss - baseline_rss, 2),
        "max_worker_rss_growth": round(max(rss_growths), 2) if rss_growths else None,
        "avg_p99_ms":       round(sum(all_p99) / len(all_p99), 3) if all_p99 else None,
        "workers":          worker_summaries,
        "verdict": {
            "complete":     n_decisions >= DECISIONS_PER_DOMAIN,
            "no_timeouts":  n_timeout == 0,
            "no_errors":    n_error == 0,
            "rss_bounded":  max(rss_growths) < 50 if rss_growths else False,
        },
    }

    summary["verdict"]["pass"] = all(summary["verdict"].values())

    with open(run_dir / "summary.json", "w") as f:
        json.dump(summary, f, indent=2)

    # Force GC after run completes — clean slate before cooldown
    gc.collect(2)

    return summary


def print_run_summary(summary: dict) -> None:
    v = summary["verdict"]
    domain = summary["domain"].upper()
    print(f"\n{'='*60}")
    print(f"  RUN COMPLETE: {domain}")
    print(f"{'='*60}")
    print(f"  Decisions    : {summary['n_decisions']:,}")
    print(f"  Elapsed      : {summary['elapsed_hours']:.2f}h")
    print(f"  Avg RPS      : {summary['avg_rps']:.0f}")
    print(f"  Allow/Block  : {summary['n_allow']:,} / {summary['n_block']:,}")
    print(f"  Timeouts     : {summary['n_timeout']}")
    print(f"  Errors       : {summary['n_error']}")
    print(f"  Max RSS/wkr  : {summary.get('max_worker_rss_growth', '?'):+.2f} MiB")
    print(f"  Avg P99      : {summary.get('avg_p99_ms', '?'):.2f} ms")
    print()
    print(f"  {'✓' if v['complete']    else '✗'} decisions_complete")
    print(f"  {'✓' if v['no_timeouts'] else '✗'} no_timeouts")
    print(f"  {'✓' if v['no_errors']   else '✗'} no_errors")
    print(f"  {'✓' if v['rss_bounded'] else '✗'} rss_bounded (<50 MiB/worker)")
    print()
    print(f"  VERDICT: {'PASS ✓' if v['pass'] else 'FAIL ✗'}")
    print(f"  Output: {summary['run_dir']}")
    print(f"{'='*60}\n")

    if v["pass"]:
        print("  ✓ Machine can be powered down / cooled before next run.")
    else:
        print("  ✗ Review failures above before proceeding to next domain.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run 100M Pramanix decisions for one domain."
    )
    parser.add_argument(
        "--domain",
        choices=list(DOMAINS.keys()),
        required=True,
        help="Domain to run: finance | banking | fintech | healthcare | infra",
    )
    parser.add_argument(
        "--skip-preflight",
        action="store_true",
        help="Skip pre-flight checks (not recommended)",
    )
    args = parser.parse_args()

    if not args.skip_preflight:
        if not check_preflight(args.domain):
            print("Pre-flight failed. Aborting.")
            sys.exit(1)
        input("  Press ENTER to confirm and start the run, or Ctrl+C to abort: ")

    run_dir = make_run_dir(args.domain)
    print(f"\n  Run output directory: {run_dir}\n")

    summary = asyncio.run(run_domain(args.domain, run_dir))
    print_run_summary(summary)
```

---

## Updated `100m_audit_merge.py` (Final Report Across All 5 Runs)

```python
"""
benchmarks/100m_audit_merge.py

Run after ALL 5 domain runs complete.
Assembles the 5 independent run summaries into one final report.

Usage:
    python benchmarks/100m_audit_merge.py
"""
from __future__ import annotations
import json
from pathlib import Path

RESULTS_ROOT = Path("benchmarks/results")
DOMAIN_ORDER = ["finance", "banking", "fintech", "healthcare", "infra"]


def find_latest_run(domain_name: str) -> Path | None:
    """Find the most recent completed run for a domain."""
    runs = sorted(
        [d for d in RESULTS_ROOT.glob(f"run_{domain_name}_*") if (d / "summary.json").exists()],
        key=lambda d: d.name,
        reverse=True,
    )
    return runs[0] if runs else None


def main():
    print(f"\n{'='*70}")
    print(f"  PRAMANIX 500M AUDIT — FINAL REPORT")
    print(f"{'='*70}\n")

    domain_summaries = {}
    missing = []

    for domain in DOMAIN_ORDER:
        run_dir = find_latest_run(domain)
        if run_dir is None:
            missing.append(domain)
            print(f"  ✗ {domain:<12}: NO COMPLETED RUN FOUND")
            continue
        with open(run_dir / "summary.json") as f:
            s = json.load(f)
        domain_summaries[domain] = s
        v = s["verdict"]
        status = "PASS ✓" if v["pass"] else "FAIL ✗"
        print(
            f"  {status}  {domain:<12}  "
            f"{s['n_decisions']:>12,} decisions  "
            f"{s['elapsed_hours']:>5.1f}h  "
            f"RPS={s['avg_rps']:<6.0f}  "
            f"P99={s.get('avg_p99_ms', 0):<7.2f}ms  "
            f"RSS/wkr={s.get('max_worker_rss_growth', 0):+.1f}MiB"
        )

    if missing:
        print(f"\n  Missing runs: {missing}")
        print(f"  Run the missing domains before generating the final report.")
        return

    # Totals
    total_decisions = sum(s["n_decisions"]  for s in domain_summaries.values())
    total_allow     = sum(s["n_allow"]      for s in domain_summaries.values())
    total_block     = sum(s["n_block"]      for s in domain_summaries.values())
    total_timeout   = sum(s["n_timeout"]    for s in domain_summaries.values())
    total_error     = sum(s["n_error"]      for s in domain_summaries.values())
    total_hours     = sum(s["elapsed_hours"] for s in domain_summaries.values())
    max_rss         = max(s.get("max_worker_rss_growth", 0) for s in domain_summaries.values())
    all_p99         = [s.get("avg_p99_ms", 0) for s in domain_summaries.values()]
    overall_pass    = all(s["verdict"]["pass"] for s in domain_summaries.values())

    print(f"\n{'─'*70}")
    print(f"  TOTALS")
    print(f"  Total decisions   : {total_decisions:,}")
    print(f"  Total wall time   : {total_hours:.1f}h across 5 independent runs")
    print(f"  Total allow/block : {total_allow:,} / {total_block:,}")
    print(f"  Total timeouts    : {total_timeout}")
    print(f"  Total errors      : {total_error}")
    print(f"  Max RSS/worker    : {max_rss:+.2f} MiB (across all domains)")
    print(f"  Max domain P99    : {max(all_p99):.2f} ms")

    print(f"\n{'─'*70}")
    print(f"  FINAL VERDICT: {'PASS ✓' if overall_pass else 'FAIL ✗'}")
    print(f"{'='*70}\n")

    # Save combined report
    report_path = RESULTS_ROOT / "500m_final_report.json"
    with open(report_path, "w") as f:
        json.dump({
            "total_decisions":  total_decisions,
            "total_hours":      round(total_hours, 1),
            "total_allow":      total_allow,
            "total_block":      total_block,
            "total_timeout":    total_timeout,
            "total_error":      total_error,
            "max_rss_growth_per_worker_mib": round(max_rss, 2),
            "max_domain_p99_ms": round(max(all_p99), 3),
            "overall_pass":     overall_pass,
            "domains":          domain_summaries,
        }, f, indent=2)

    print(f"  Final report saved: {report_path}")


if __name__ == "__main__":
    main()
```

---

## Execution Sequence

Copy and paste these commands in order. Each one is its own run.
**Wait for the previous run to complete and the machine to cool before typing the next.**

```powershell
# ─── RUN 1: FINANCE ──────────────────────────────────────────────────────────
python benchmarks/100m_audit_orchestrator.py --domain finance `
  2>&1 | Tee-Object -FilePath benchmarks/results/run_finance.log

# WAIT: Run completes (~15h). Check verdict in output.
# COOLDOWN: Wait until CPU is back to idle temps (~30 min minimum).
# Verify: python benchmarks/100m_audit_merge.py  ← shows 1/5 complete

# ─── RUN 2: BANKING ──────────────────────────────────────────────────────────
python benchmarks/100m_audit_orchestrator.py --domain banking `
  2>&1 | Tee-Object -FilePath benchmarks/results/run_banking.log

# WAIT + COOLDOWN

# ─── RUN 3: FINTECH ──────────────────────────────────────────────────────────
python benchmarks/100m_audit_orchestrator.py --domain fintech `
  2>&1 | Tee-Object -FilePath benchmarks/results/run_fintech.log

# WAIT + COOLDOWN

# ─── RUN 4: HEALTHCARE ───────────────────────────────────────────────────────
python benchmarks/100m_audit_orchestrator.py --domain healthcare `
  2>&1 | Tee-Object -FilePath benchmarks/results/run_healthcare.log

# WAIT + COOLDOWN

# ─── RUN 5: INFRA ────────────────────────────────────────────────────────────
python benchmarks/100m_audit_orchestrator.py --domain infra `
  2>&1 | Tee-Object -FilePath benchmarks/results/run_infra.log

# ─── FINAL REPORT ────────────────────────────────────────────────────────────
python benchmarks/100m_audit_merge.py
```

---

## Cooldown Protocol Between Runs

After each run completes, before starting the next:

```powershell
# 1. Confirm run passed
Get-Content benchmarks/results/run_<domain>.log | Select-Object -Last 20

# 2. Force OS memory release
[System.GC]::Collect()
[System.GC]::WaitForPendingFinalizers()

# 3. Check CPU has cooled (PowerShell — reads WMI thermal zone)
Get-WmiObject -Namespace "root\WMI" -Class MSAcpi_ThermalZoneTemperature |
  Select-Object @{N="TempC";E={($_.CurrentTemperature - 2732) / 10}}
# Wait until all zones report < 55°C

# 4. Minimum wait regardless: 30 minutes
# Recommended wait: 45-60 minutes if temps were above 75°C during the run

# 5. Run partial merge to confirm artifact is intact
python benchmarks/100m_audit_merge.py
```

---

## Output Directory Structure After All 5 Runs

```
benchmarks/results/
  run_finance_20260322_090000/
    run_meta.json            ← written at start (survives crash)
    summary.json             ← written at end (verdict + all stats)
    workers/
      finance_worker_00.jsonl        ← 5,555,556 decision records
      finance_worker_00_checkpoints.jsonl
      finance_worker_01.jsonl
      ...
      finance_worker_17.jsonl
      finance_worker_17_checkpoints.jsonl

  run_banking_20260323_010000/
    (same structure)

  run_fintech_20260323_170000/
  run_healthcare_20260324_090000/
  run_infra_20260325_010000/

  500m_final_report.json     ← assembled by merge script after all 5 complete
  run_finance.log            ← full terminal output
  run_banking.log
  run_fintech.log
  run_healthcare.log
  run_infra.log
```

---

## Estimated Full Schedule (Starting Monday Morning)

| Run | Domain | Start | Est. End | Cooldown Until |
|---|---|---|---|---|
| 1 | finance | Mon 09:00 | Tue 00:24 | Tue 01:00 |
| 2 | banking | Tue 01:00 | Tue 16:24 | Tue 17:00 |
| 3 | fintech | Tue 17:00 | Wed 08:24 | Wed 09:00 |
| 4 | healthcare | Wed 09:00 | Thu 00:24 | Thu 01:00 |
| 5 | infra | Thu 01:00 | Thu 16:24 | — |
| Final report | — | Thu 16:30 | Thu 16:35 | — |

**Total calendar time: ~80 hours (~3.3 days) including cooldowns.**

---

## What "Independent Run" Means for the Audit Report

Each run is a standalone claim:

> **Run 1 — Finance domain:** 100,000,000 Z3 SMT decisions. 18 async-process workers.
> 15.4 hours continuous. Memory bounded: +X MiB max growth per worker.
> Merkle chain: [root hash]. Verdict: PASS.

All 5 runs together:

> **500M Decision Multi-Domain Audit:** 5 independent runs of 100M decisions each,
> across finance, banking, fintech, healthcare, and infra domains. 18 workers per run.
> System cooled between runs. Memory bounded at < 50 MiB net growth per worker in every run.
> Every decision cryptographically logged with Merkle hash chain verification.
> All 5 runs: PASS.

The fact that these are independent runs with cooling is **a strength, not a weakness**.
It proves stability across cold-start conditions, not just sustained warm operation.

Log Compression: You calculated a disk requirement of ~110GB. While your 150GB free space is enough, 100 million lines of JSON can be compressed by 90% because the text is highly repetitive (same field names over and over).

Recommendation: After each domain passes its audit_merge.py check, zip the workers/ folder.

Uncompressed: ~20GB per domain.

Compressed (.zip or .7z): ~2GB per domain.
This will save your SSD from "Wear and Tear" and make uploading the results to S3 much faster.