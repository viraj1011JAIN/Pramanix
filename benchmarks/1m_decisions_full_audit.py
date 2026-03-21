#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""1 000 000 decisions -- full audit benchmark.

Tracks:
  * RSS every second  (background thread, 1 Hz)
  * RSS spikes        (any second-over-second delta > SPIKE_THRESHOLD_MiB)
  * GC collections    (gen0/gen1/gen2 counts at every checkpoint)
  * Latency           (per-decision, P50/P95/P99/P99.9 at each 100k point)
  * Throughput        (RPS at each checkpoint and overall)

Outputs:
  * Live terminal (colour-coded, updated every second)
  * benchmarks/results/1m_audit_timeline.jsonl   -- 1 row per second
  * benchmarks/results/1m_audit_checkpoints.json -- per-100k stats
  * benchmarks/results/1m_audit_summary.json     -- final README numbers
  * benchmarks/results/1m_audit_full.log         -- full debug log

Usage:
    cd C:\\Pramanix
    .venv\\Scripts\\activate
    python benchmarks/1m_decisions_full_audit.py

Options:
    --n         total decisions (default 1_000_000)
    --warmup    warmup decisions before timing starts (default 500)
    --spike     RSS spike threshold in MiB (default 1.0)
    --no-color  disable ANSI colours (CI / piped output)
"""
from __future__ import annotations

import argparse
import gc
import json
import logging
import math
import queue
import sys
import threading
import time
from decimal import Decimal
from pathlib import Path
from typing import Any

# ---- path setup -------------------------------------------------------------
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))

# ---- psutil (required) ------------------------------------------------------
try:
    import psutil
except ImportError:
    print(
        "ERROR: psutil is required.  Run:  pip install psutil",
        file=sys.stderr,
    )
    sys.exit(1)

from pramanix import Field, Guard, GuardConfig, Policy
from pramanix.expressions import E

# ---- policy -----------------------------------------------------------------


class _AuditPolicy(Policy):
    """Single-invariant policy -- minimal overhead, pure Z3 measurement."""

    balance = Field("balance", Decimal, "Real")
    amount = Field("amount", Decimal, "Real")

    @classmethod
    def invariants(cls):
        return [
            (
                E(cls.balance) - E(cls.amount) >= Decimal("0")
            ).named("non_negative_balance"),
        ]


# ---- constants --------------------------------------------------------------
CHECKPOINT_EVERY = 100_000
RSS_POLL_HZ = 1
SPIKE_THRESHOLD_MiB = 1.0
RESULTS_DIR = ROOT / "benchmarks" / "results"

# ---- ANSI colour helpers ----------------------------------------------------
_USE_COLOR = sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    if not _USE_COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"


def GREEN(t: str) -> str:  # noqa: N802
    return _c("32", t)


def YELLOW(t: str) -> str:  # noqa: N802
    return _c("33", t)


def RED(t: str) -> str:  # noqa: N802
    return _c("31;1", t)


def CYAN(t: str) -> str:  # noqa: N802
    return _c("36", t)


def BOLD(t: str) -> str:  # noqa: N802
    return _c("1", t)


def DIM(t: str) -> str:  # noqa: N802
    return _c("2", t)


# ---- helpers ----------------------------------------------------------------


def _rss_mib(proc: psutil.Process) -> float:
    return proc.memory_info().rss / (1024 * 1024)


def _pct(data: list[float], p: float) -> float:
    """Return the p-th percentile (0-100) of a sorted list."""
    if not data:
        return 0.0
    idx = min(int(len(data) * p / 100), len(data) - 1)
    return data[idx]


def _gc_counts() -> tuple[int, int, int]:
    stats = gc.get_count()
    return stats[0], stats[1], stats[2]


def _fmt_mib(v: float) -> str:
    sign = "+" if v >= 0 else ""
    return f"{sign}{v:.2f} MiB"


def _fmt_ms(v: float) -> str:
    return f"{v:.3f} ms"


# ---- logging setup ----------------------------------------------------------


def _setup_logging(log_path: Path) -> logging.Logger:
    log = logging.getLogger("1m_audit")
    log.setLevel(logging.DEBUG)
    log.propagate = False

    fh = logging.FileHandler(log_path, mode="w", encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(
        logging.Formatter(
            "%(asctime)s.%(msecs)03d  %(levelname)-7s  %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
    )
    log.addHandler(fh)

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.WARNING)
    log.addHandler(ch)

    return log


# ---- background RSS sampler -------------------------------------------------


class _RssSampler(threading.Thread):
    """Polls RSS every second. Writes to timeline_q and detects spikes."""

    def __init__(
        self,
        proc: psutil.Process,
        rss_baseline: float,
        spike_threshold: float,
        timeline_q: queue.Queue[dict[str, Any]],
        log: logging.Logger,
        stop_event: threading.Event,
        start_time: float,
    ) -> None:
        super().__init__(daemon=True, name="rss-sampler")
        self._proc = proc
        self._baseline = rss_baseline
        self._spike_threshold = spike_threshold
        self._q = timeline_q
        self._log = log
        self._stop = stop_event
        self._start = start_time
        self._prev_rss: float = rss_baseline

        # written by main thread under lock; read here for live display
        self.decisions_done: int = 0
        self.lock = threading.Lock()

    def run(self) -> None:
        while not self._stop.is_set():
            elapsed = time.perf_counter() - self._start
            rss = _rss_mib(self._proc)
            growth = rss - self._baseline
            delta = rss - self._prev_rss
            is_spike = abs(delta) >= self._spike_threshold

            with self.lock:
                done = self.decisions_done

            rps = done / elapsed if elapsed > 0 else 0.0

            record: dict[str, Any] = {
                "t_s": round(elapsed, 3),
                "rss_mib": round(rss, 3),
                "growth_mib": round(growth, 3),
                "delta_mib": round(delta, 3),
                "decisions": done,
                "rps": round(rps, 1),
                "spike": is_spike,
            }
            self._q.put(record)
            self._log.debug(
                "t=%.1fs  RSS=%.2f MiB  growth=%s  delta=%s  "
                "done=%d  RPS=%.0f%s",
                elapsed,
                rss,
                _fmt_mib(growth),
                _fmt_mib(delta),
                done,
                rps,
                "  *** SPIKE ***" if is_spike else "",
            )

            if is_spike:
                self._log.warning(
                    "RSS SPIKE at t=%.1fs: %.2f -> %.2f MiB (delta=%s)",
                    elapsed,
                    self._prev_rss,
                    rss,
                    _fmt_mib(delta),
                )
                print(
                    f"  {RED('!!! RSS SPIKE !!!')}  "
                    f"t={elapsed:.1f}s  "
                    f"{self._prev_rss:.2f} -> {rss:.2f} MiB  "
                    f"delta={_fmt_mib(delta)}",
                    flush=True,
                )
            else:
                g_str = (
                    GREEN(_fmt_mib(growth))
                    if growth < 5
                    else YELLOW(_fmt_mib(growth))
                )
                print(
                    f"  {DIM(f't={elapsed:6.1f}s')}  "
                    f"RSS={CYAN(f'{rss:.2f} MiB')}  "
                    f"growth={g_str}  "
                    f"RPS={BOLD(f'{rps:,.0f}')}",
                    flush=True,
                )

            self._prev_rss = rss
            time.sleep(1.0 / RSS_POLL_HZ)


# ---- checkpoint stats -------------------------------------------------------


def _checkpoint_stats(
    i: int,
    latencies_window: list[float],
    latencies_all: list[float],
    t_start: float,
    rss_baseline: float,
    proc: psutil.Process,
    log: logging.Logger,
) -> dict[str, Any]:
    elapsed = time.perf_counter() - t_start
    rss = _rss_mib(proc)
    growth = rss - rss_baseline
    rps = i / elapsed if elapsed > 0 else 0.0

    win = sorted(latencies_window)
    total = sorted(latencies_all)
    gc0, gc1, gc2 = _gc_counts()

    stats: dict[str, Any] = {
        "decision": i,
        "elapsed_s": round(elapsed, 3),
        "rss_mib": round(rss, 3),
        "growth_mib": round(growth, 3),
        "rps": round(rps, 1),
        "gc_gen0": gc0,
        "gc_gen1": gc1,
        "gc_gen2": gc2,
        "window": {
            "n": len(win),
            "p50_ms": round(_pct(win, 50), 3),
            "p95_ms": round(_pct(win, 95), 3),
            "p99_ms": round(_pct(win, 99), 3),
            "p999_ms": round(_pct(win, 99.9), 3),
            "min_ms": round(win[0], 3) if win else 0.0,
            "max_ms": round(win[-1], 3) if win else 0.0,
        },
        "cumulative": {
            "n": len(total),
            "p50_ms": round(_pct(total, 50), 3),
            "p95_ms": round(_pct(total, 95), 3),
            "p99_ms": round(_pct(total, 99), 3),
            "p999_ms": round(_pct(total, 99.9), 3),
        },
    }

    sep = "-" * 72
    print(f"\n{sep}", flush=True)
    print(
        BOLD(f"  CHECKPOINT  {i:>9,} decisions")
        + f"  elapsed={elapsed:.1f}s  RPS={rps:,.0f}",
        flush=True,
    )
    print(
        f"  RSS={CYAN(f'{rss:.2f} MiB')}  "
        f"growth={_fmt_mib(growth)}  "
        f"GC gen0={gc0} gen1={gc1} gen2={gc2}",
        flush=True,
    )
    w = stats["window"]
    c = stats["cumulative"]
    print(
        f"  Window latency (last {len(win):,}):  "
        f"P50={BOLD(_fmt_ms(w['p50_ms']))}  "
        f"P95={_fmt_ms(w['p95_ms'])}  "
        f"P99={_fmt_ms(w['p99_ms'])}  "
        f"P99.9={YELLOW(_fmt_ms(w['p999_ms']))}  "
        f"max={RED(_fmt_ms(w['max_ms']))}",
        flush=True,
    )
    print(
        f"  Cumulative ({len(total):,}):  "
        f"P50={BOLD(_fmt_ms(c['p50_ms']))}  "
        f"P95={_fmt_ms(c['p95_ms'])}  "
        f"P99={_fmt_ms(c['p99_ms'])}  "
        f"P99.9={YELLOW(_fmt_ms(c['p999_ms']))}",
        flush=True,
    )
    print(f"{sep}\n", flush=True)

    log.info(
        "CHECKPOINT %d: elapsed=%.1fs RPS=%.0f RSS=%.2f MiB "
        "growth=%s P50=%s P95=%s P99=%s P99.9=%s",
        i,
        elapsed,
        rps,
        rss,
        _fmt_mib(growth),
        _fmt_ms(w["p50_ms"]),
        _fmt_ms(w["p95_ms"]),
        _fmt_ms(w["p99_ms"]),
        _fmt_ms(w["p999_ms"]),
    )

    return stats


# ---- main -------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(description="1M decisions full audit")
    parser.add_argument("--n", type=int, default=1_000_000)
    parser.add_argument("--warmup", type=int, default=500)
    parser.add_argument("--spike", type=float, default=SPIKE_THRESHOLD_MiB)
    parser.add_argument("--no-color", action="store_true")
    args = parser.parse_args()

    global _USE_COLOR
    if args.no_color:
        _USE_COLOR = False

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    log_path = RESULTS_DIR / "1m_audit_full.log"
    log = _setup_logging(log_path)

    # ---- guard setup --------------------------------------------------------
    guard = Guard(_AuditPolicy, GuardConfig(execution_mode="sync"))
    intent = {"amount": Decimal("100")}
    state = {"balance": Decimal("1000")}
    proc = psutil.Process()

    # ---- header -------------------------------------------------------------
    print(BOLD("\n" + "=" * 72), flush=True)
    print(BOLD("  Pramanix  --  1 M Decisions Full Audit"), flush=True)
    print(BOLD("=" * 72), flush=True)
    print(f"  Total decisions : {args.n:,}", flush=True)
    print(f"  Warmup calls    : {args.warmup:,}", flush=True)
    print(
        f"  RSS sample rate : {RSS_POLL_HZ} Hz (every second)",
        flush=True,
    )
    print(
        f"  Spike threshold : {args.spike} MiB",
        flush=True,
    )
    print(f"  Log file        : {log_path}", flush=True)
    print(BOLD("=" * 72 + "\n"), flush=True)

    log.info("=== 1M DECISIONS FULL AUDIT START ===")
    log.info(
        "n=%d  warmup=%d  spike_threshold=%.1f MiB",
        args.n,
        args.warmup,
        args.spike,
    )

    # ---- warmup -------------------------------------------------------------
    print(
        f"  Warming up ({args.warmup:,} calls) ...",
        end=" ",
        flush=True,
    )
    for _ in range(args.warmup):
        guard.verify(intent=intent, state=state)
    gc.collect()
    print(GREEN("done"), flush=True)
    log.info("Warmup complete (%d calls)", args.warmup)

    # ---- baseline -----------------------------------------------------------
    gc.collect()
    rss_baseline = _rss_mib(proc)
    gc_baseline = _gc_counts()
    print(
        f"\n  Baseline RSS : {CYAN(f'{rss_baseline:.3f} MiB')}",
        flush=True,
    )
    print(
        f"  Baseline GC  : "
        f"gen0={gc_baseline[0]}  "
        f"gen1={gc_baseline[1]}  "
        f"gen2={gc_baseline[2]}\n",
        flush=True,
    )
    log.info(
        "Baseline RSS=%.3f MiB  GC gen0=%d gen1=%d gen2=%d",
        rss_baseline,
        *gc_baseline,
    )

    # ---- background sampler -------------------------------------------------
    timeline_q: queue.Queue[dict[str, Any]] = queue.Queue()
    stop_event = threading.Event()
    t_start = time.perf_counter()

    sampler = _RssSampler(
        proc=proc,
        rss_baseline=rss_baseline,
        spike_threshold=args.spike,
        timeline_q=timeline_q,
        log=log,
        stop_event=stop_event,
        start_time=t_start,
    )
    sampler.start()

    # ---- main loop ----------------------------------------------------------
    latencies_all: list[float] = []
    latencies_window: list[float] = []
    checkpoints: list[dict[str, Any]] = []
    spike_count = 0

    print("  Running ... (RSS sampled every second below)\n", flush=True)
    log.info("Main loop started")

    for i in range(1, args.n + 1):
        t0 = time.perf_counter()
        guard.verify(intent=intent, state=state)
        lat_ms = (time.perf_counter() - t0) * 1000

        latencies_all.append(lat_ms)
        latencies_window.append(lat_ms)

        with sampler.lock:
            sampler.decisions_done = i

        if i % CHECKPOINT_EVERY == 0:
            cp = _checkpoint_stats(
                i,
                latencies_window,
                latencies_all,
                t_start,
                rss_baseline,
                proc,
                log,
            )
            checkpoints.append(cp)
            latencies_window = []

    # ---- stop sampler -------------------------------------------------------
    stop_event.set()
    sampler.join(timeout=3)

    # ---- drain timeline queue -----------------------------------------------
    timeline: list[dict[str, Any]] = []
    while not timeline_q.empty():
        rec = timeline_q.get_nowait()
        timeline.append(rec)
        if rec.get("spike"):
            spike_count += 1

    # ---- final stats --------------------------------------------------------
    t_total = time.perf_counter() - t_start
    rss_final = _rss_mib(proc)
    gc_final = _gc_counts()
    rss_growth = rss_final - rss_baseline

    lat_sorted = sorted(latencies_all)
    p50 = _pct(lat_sorted, 50)
    p95 = _pct(lat_sorted, 95)
    p99 = _pct(lat_sorted, 99)
    p999 = _pct(lat_sorted, 99.9)
    p9999 = _pct(lat_sorted, 99.99)
    lat_min = lat_sorted[0]
    lat_max = lat_sorted[-1]
    lat_mean = sum(lat_sorted) / len(lat_sorted)
    lat_stdev = math.sqrt(
        sum((x - lat_mean) ** 2 for x in lat_sorted) / len(lat_sorted)
    )
    avg_rps = args.n / t_total

    rss_values = [r["rss_mib"] for r in timeline]
    rss_max = max(rss_values) if rss_values else rss_final
    rss_min = min(rss_values) if rss_values else rss_baseline

    summary: dict[str, Any] = {
        "version": "1.0",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "config": {
            "n": args.n,
            "warmup": args.warmup,
            "policy": "_AuditPolicy (1 invariant)",
            "execution_mode": "sync",
        },
        "throughput": {
            "total_decisions": args.n,
            "total_elapsed_s": round(t_total, 3),
            "avg_rps": round(avg_rps, 1),
        },
        "latency_ms": {
            "min": round(lat_min, 3),
            "mean": round(lat_mean, 3),
            "stdev": round(lat_stdev, 3),
            "p50": round(p50, 3),
            "p95": round(p95, 3),
            "p99": round(p99, 3),
            "p99_9": round(p999, 3),
            "p99_99": round(p9999, 3),
            "max": round(lat_max, 3),
        },
        "memory": {
            "baseline_mib": round(rss_baseline, 3),
            "final_mib": round(rss_final, 3),
            "peak_mib": round(rss_max, 3),
            "min_mib": round(rss_min, 3),
            "growth_mib": round(rss_growth, 3),
            "spike_count": spike_count,
            "spike_threshold_mib": args.spike,
        },
        "gc": {
            "baseline": {
                "gen0": gc_baseline[0],
                "gen1": gc_baseline[1],
                "gen2": gc_baseline[2],
            },
            "final": {
                "gen0": gc_final[0],
                "gen1": gc_final[1],
                "gen2": gc_final[2],
            },
            "delta": {
                "gen0": gc_final[0] - gc_baseline[0],
                "gen1": gc_final[1] - gc_baseline[1],
                "gen2": gc_final[2] - gc_baseline[2],
            },
        },
        "verdict": {
            "memory_stable": rss_growth < 50.0,
            "no_major_spikes": spike_count == 0,
            "p99_under_100ms": p99 < 100.0,
            "p50_under_25ms": p50 < 25.0,
            "overall_pass": (
                rss_growth < 50.0 and p99 < 100.0 and p50 < 25.0
            ),
        },
    }

    # ---- terminal final summary ---------------------------------------------
    sep = "=" * 72
    print(f"\n{BOLD(sep)}", flush=True)
    print(BOLD("  FINAL SUMMARY  --  1 000 000 DECISIONS"), flush=True)
    print(BOLD(sep), flush=True)

    print("\n  Throughput", flush=True)
    print(f"    Total time : {t_total:.2f}s", flush=True)
    print(f"    Avg RPS    : {BOLD(f'{avg_rps:,.0f}')}", flush=True)

    print("\n  Latency", flush=True)
    print(f"    Min           : {_fmt_ms(lat_min)}", flush=True)
    print(f"    P50           : {BOLD(_fmt_ms(p50))}", flush=True)
    print(f"    P95           : {_fmt_ms(p95)}", flush=True)
    print(f"    P99           : {_fmt_ms(p99)}", flush=True)
    print(f"    P99.9         : {YELLOW(_fmt_ms(p999))}", flush=True)
    print(f"    P99.99        : {YELLOW(_fmt_ms(p9999))}", flush=True)
    print(f"    Max           : {RED(_fmt_ms(lat_max))}", flush=True)
    print(
        f"    Mean +/- StdDev : "
        f"{_fmt_ms(lat_mean)} +/- {_fmt_ms(lat_stdev)}",
        flush=True,
    )

    print("\n  RSS Memory", flush=True)
    print(f"    Baseline : {rss_baseline:.3f} MiB", flush=True)
    print(f"    Final    : {rss_final:.3f} MiB", flush=True)
    print(f"    Peak     : {rss_max:.3f} MiB", flush=True)
    g_str = (
        GREEN(_fmt_mib(rss_growth))
        if rss_growth < 5
        else RED(_fmt_mib(rss_growth))
    )
    print(f"    Growth   : {g_str}", flush=True)
    sc_str = str(spike_count) if spike_count == 0 else RED(str(spike_count))
    print(
        f"    Spikes (>{args.spike} MiB) : {sc_str}",
        flush=True,
    )

    print("\n  GC Collections", flush=True)
    gcd = summary["gc"]["delta"]
    print(f"    gen0 delta : {gcd['gen0']}", flush=True)
    print(f"    gen1 delta : {gcd['gen1']}", flush=True)
    print(f"    gen2 delta : {gcd['gen2']}", flush=True)

    v = summary["verdict"]
    overall = GREEN("PASS") if v["overall_pass"] else RED("FAIL")
    print(f"\n  Verdict : {BOLD(overall)}", flush=True)
    yes_no = lambda b: GREEN("YES") if b else RED("NO")  # noqa: E731
    print(
        f"    memory stable (<50 MiB) : {yes_no(v['memory_stable'])}",
        flush=True,
    )
    print(
        f"    no major spikes         : {yes_no(v['no_major_spikes'])}",
        flush=True,
    )
    print(
        f"    P99 < 100 ms            : {yes_no(v['p99_under_100ms'])}",
        flush=True,
    )
    print(
        f"    P50 < 25 ms             : {yes_no(v['p50_under_25ms'])}",
        flush=True,
    )
    print(BOLD(f"\n{sep}\n"), flush=True)

    # ---- write output files -------------------------------------------------
    timeline_path = RESULTS_DIR / "1m_audit_timeline.jsonl"
    with open(timeline_path, "w", encoding="utf-8") as f:
        for rec in timeline:
            f.write(json.dumps(rec) + "\n")

    cp_path = RESULTS_DIR / "1m_audit_checkpoints.json"
    with open(cp_path, "w", encoding="utf-8") as f:
        json.dump(checkpoints, f, indent=2)

    summary_path = RESULTS_DIR / "1m_audit_summary.json"
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    log.info("=== 1M DECISIONS FULL AUDIT COMPLETE ===")
    log.info(
        "Verdict: %s",
        "PASS" if v["overall_pass"] else "FAIL",
    )
    log.info(
        "avg_rps=%.0f  P50=%s  P99=%s  growth=%s  spikes=%d",
        avg_rps,
        _fmt_ms(p50),
        _fmt_ms(p99),
        _fmt_mib(rss_growth),
        spike_count,
    )

    print("  Output files:", flush=True)
    print(
        f"    {timeline_path}",
        flush=True,
    )
    print(f"    {cp_path}", flush=True)
    print(
        f"    {summary_path}   <- copy numbers to README",
        flush=True,
    )
    print(
        f"    {log_path}       <- full debug log\n",
        flush=True,
    )


if __name__ == "__main__":
    main()
