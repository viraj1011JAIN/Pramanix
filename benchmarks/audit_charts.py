# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""benchmarks/audit_charts.py

Post-run chart generator for the Pramanix 500 M Sovereign Audit.

Run during the cooldown period after each domain completes:

    python benchmarks/audit_charts.py --domain finance
    python benchmarks/audit_charts.py --domain banking
    # ... etc.

Or for all completed domains at once:

    python benchmarks/audit_charts.py --all

Outputs (written to the run's directory under benchmarks/results/):

    charts/p99_latency_over_time.png
        P99 latency (ms) vs checkpoint index for every worker.
        Each worker is a separate line.  Reveals any degradation over time.

    charts/allow_block_rate_over_time.png
        Cumulative allow % vs checkpoint index for every worker.
        Should remain stable (random seed → stable statistical rate).

    charts/worker_p99_comparison.png
        Bar chart: max P99 per worker across the full run.
        Reveals load imbalance between threads.

    charts/latency_distribution.png
        Histogram of all per-checkpoint P99 values across all workers.
        Visual proof that the tail is bounded.

Upload to Google Drive:
    Pramanix_V1_Sovereign_Audit_500M/03_Telemetry_and_Visuals/Charts/
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")   # headless — no display needed
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker

RESULTS_ROOT = Path("benchmarks/results")
DOMAIN_ORDER = ["finance", "banking", "fintech", "healthcare", "infra"]

# ── Colour palette (one colour per worker, cycles for > 10 workers) ───────────
_CMAP = plt.get_cmap("tab20")


def _worker_color(worker_id: int):
    return _CMAP(worker_id % 20)


# ── Data loading ──────────────────────────────────────────────────────────────


def find_latest_run(domain_name: str) -> Path | None:
    """Return the most recent completed run dir, or None."""
    candidates = sorted(
        [
            d for d in RESULTS_ROOT.glob(f"run_{domain_name}_*")
            if d.is_dir() and (d / "summary.json").exists()
        ],
        key=lambda d: d.name,
        reverse=True,
    )
    return candidates[0] if candidates else None


def load_checkpoints(run_dir: Path) -> dict[int, list[dict]]:
    """Return {worker_id: [checkpoint_record, ...]} sorted by seq."""
    workers_dir = run_dir / "workers"
    data: dict[int, list[dict]] = {}
    for cp_file in sorted(workers_dir.glob("*_checkpoints.jsonl")):
        records: list[dict] = []
        for line in cp_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                records.append(json.loads(line))
        if records:
            wid = records[0]["w"]
            data[wid] = sorted(records, key=lambda r: r["seq"])
    return data


def load_summary(run_dir: Path) -> dict:
    with open(run_dir / "summary.json") as f:
        return json.load(f)


# ── Chart 1: P99 latency over time ────────────────────────────────────────────


def chart_p99_over_time(
    run_dir: Path,
    checkpoints: dict[int, list[dict]],
    domain_name: str,
) -> Path:
    out_dir = run_dir / "charts"
    out_dir.mkdir(exist_ok=True)

    fig, ax = plt.subplots(figsize=(14, 6))

    for wid in sorted(checkpoints):
        recs = checkpoints[wid]
        xs = list(range(1, len(recs) + 1))
        ys = [r["p99"] for r in recs]
        ax.plot(xs, ys, color=_worker_color(wid), linewidth=0.8,
                alpha=0.75, label=f"w{wid:02d}")

    ax.set_title(
        f"Pramanix — {domain_name.upper()} — P99 Latency per Checkpoint",
        fontsize=13, fontweight="bold",
    )
    ax.set_xlabel("Checkpoint index (every 100 k decisions)", fontsize=11)
    ax.set_ylabel("P99 latency (ms)", fontsize=11)
    ax.yaxis.set_major_formatter(mticker.FormatStrFormatter("%.1f ms"))
    ax.axhline(y=150, color="red", linestyle="--", linewidth=1,
               label="Z3 timeout threshold (150 ms)")
    ax.legend(loc="upper right", fontsize=7, ncol=3)
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    fig.tight_layout()

    out = out_dir / "p99_latency_over_time.png"
    fig.savefig(out, dpi=150)
    plt.close(fig)
    return out


# ── Chart 2: Allow rate over time ─────────────────────────────────────────────


def chart_allow_rate_over_time(
    run_dir: Path,
    checkpoints: dict[int, list[dict]],
    domain_name: str,
) -> Path:
    out_dir = run_dir / "charts"
    out_dir.mkdir(exist_ok=True)

    fig, ax = plt.subplots(figsize=(14, 6))

    for wid in sorted(checkpoints):
        recs = checkpoints[wid]
        xs = list(range(1, len(recs) + 1))
        ys = []
        for r in recs:
            total = r["allow"] + r["block"] + r.get("timeout", 0)
            rate = (r["allow"] / total * 100) if total > 0 else 0.0
            ys.append(rate)
        ax.plot(xs, ys, color=_worker_color(wid), linewidth=0.8,
                alpha=0.75, label=f"w{wid:02d}")

    ax.set_title(
        f"Pramanix — {domain_name.upper()} — Cumulative Allow Rate",
        fontsize=13, fontweight="bold",
    )
    ax.set_xlabel("Checkpoint index (every 100 k decisions)", fontsize=11)
    ax.set_ylabel("Allow rate (%)", fontsize=11)
    ax.set_ylim(0, 100)
    ax.yaxis.set_major_formatter(mticker.FormatStrFormatter("%.0f%%"))
    ax.legend(loc="upper right", fontsize=7, ncol=3)
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    fig.tight_layout()

    out = out_dir / "allow_block_rate_over_time.png"
    fig.savefig(out, dpi=150)
    plt.close(fig)
    return out


# ── Chart 3: Per-worker max P99 bar chart ─────────────────────────────────────


def chart_worker_p99_comparison(
    run_dir: Path,
    summary: dict,
    domain_name: str,
) -> Path:
    out_dir = run_dir / "charts"
    out_dir.mkdir(exist_ok=True)

    workers = [w for w in summary.get("workers", []) if not w.get("failed")]
    if not workers:
        raise ValueError("No successful workers in summary.")

    workers = sorted(workers, key=lambda w: w["worker_id"])
    wids = [w["worker_id"] for w in workers]
    p99s = [w["p99_ms"] for w in workers]
    colors = [_worker_color(wid) for wid in wids]

    fig, ax = plt.subplots(figsize=(16, 5))
    bars = ax.bar(
        [f"w{wid:02d}" for wid in wids], p99s,
        color=colors, edgecolor="white", linewidth=0.5,
    )

    # Annotate each bar with the value
    for bar, val in zip(bars, p99s, strict=False):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 0.3,
            f"{val:.1f}",
            ha="center", va="bottom", fontsize=7,
        )

    ax.axhline(y=150, color="red", linestyle="--", linewidth=1,
               label="Timeout threshold (150 ms)")
    ax.set_title(
        f"Pramanix — {domain_name.upper()} — Max P99 per Worker",
        fontsize=13, fontweight="bold",
    )
    ax.set_xlabel("Worker ID", fontsize=11)
    ax.set_ylabel("Max P99 latency (ms)", fontsize=11)
    ax.legend(fontsize=9)
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    fig.tight_layout()

    out = out_dir / "worker_p99_comparison.png"
    fig.savefig(out, dpi=150)
    plt.close(fig)
    return out


# ── Chart 4: P99 distribution histogram ───────────────────────────────────────


def chart_latency_distribution(
    run_dir: Path,
    checkpoints: dict[int, list[dict]],
    domain_name: str,
) -> Path:
    out_dir = run_dir / "charts"
    out_dir.mkdir(exist_ok=True)

    all_p99: list[float] = []
    for recs in checkpoints.values():
        all_p99.extend(r["p99"] for r in recs)

    fig, ax = plt.subplots(figsize=(12, 5))
    ax.hist(all_p99, bins=60, color="#2196F3", edgecolor="white",
            linewidth=0.4, alpha=0.85)
    ax.axvline(x=150, color="red", linestyle="--", linewidth=1.2,
               label="Timeout threshold (150 ms)")

    # Mark percentiles
    if all_p99:
        sorted_p99 = sorted(all_p99)
        n = len(sorted_p99)
        p50 = sorted_p99[int(n * 0.50)]
        p95 = sorted_p99[int(n * 0.95)]
        p99 = sorted_p99[min(int(n * 0.99), n - 1)]
        for val, lbl, color in [
            (p50, "P50", "#4CAF50"),
            (p95, "P95", "#FF9800"),
            (p99, "P99", "#9C27B0"),
        ]:
            ax.axvline(x=val, color=color, linestyle=":", linewidth=1.2,
                       label=f"{lbl} = {val:.1f} ms")

    ax.set_title(
        f"Pramanix — {domain_name.upper()} — P99 Latency Distribution"
        " (all checkpoints)",
        fontsize=13, fontweight="bold",
    )
    ax.set_xlabel("P99 latency (ms)", fontsize=11)
    ax.set_ylabel("Number of checkpoints", fontsize=11)
    ax.legend(fontsize=9)
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    fig.tight_layout()

    out = out_dir / "latency_distribution.png"
    fig.savefig(out, dpi=150)
    plt.close(fig)
    return out


# ── Runner ────────────────────────────────────────────────────────────────────


def generate_charts_for_domain(domain_name: str) -> None:
    run_dir = find_latest_run(domain_name)
    if run_dir is None:
        print(f"  [SKIP] {domain_name}: no completed run found.")
        return

    print(f"\n  [{domain_name.upper()}] {run_dir.name}")

    try:
        checkpoints = load_checkpoints(run_dir)
        summary = load_summary(run_dir)
    except Exception as exc:
        print(f"  [ERR]  Failed to load data: {exc}")
        return

    if not checkpoints:
        print("  [WARN] No checkpoint files found — charts skipped.")
        return

    charts_produced: list[str] = []

    try:
        p = chart_p99_over_time(run_dir, checkpoints, domain_name)
        charts_produced.append(p.name)
        print(f"  [OK]   {p.name}")
    except Exception as exc:
        print(f"  [ERR]  p99_latency_over_time: {exc}")

    try:
        p = chart_allow_rate_over_time(run_dir, checkpoints, domain_name)
        charts_produced.append(p.name)
        print(f"  [OK]   {p.name}")
    except Exception as exc:
        print(f"  [ERR]  allow_block_rate_over_time: {exc}")

    try:
        p = chart_worker_p99_comparison(run_dir, summary, domain_name)
        charts_produced.append(p.name)
        print(f"  [OK]   {p.name}")
    except Exception as exc:
        print(f"  [ERR]  worker_p99_comparison: {exc}")

    try:
        p = chart_latency_distribution(run_dir, checkpoints, domain_name)
        charts_produced.append(p.name)
        print(f"  [OK]   {p.name}")
    except Exception as exc:
        print(f"  [ERR]  latency_distribution: {exc}")

    if charts_produced:
        charts_dir = run_dir / "charts"
        print(f"\n  Charts written to: {charts_dir}")
        print(
            "  Upload to Google Drive: "
            "Pramanix_V1_Sovereign_Audit_500M/"
            "03_Telemetry_and_Visuals/Charts/"
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate audit charts for completed Pramanix domain runs."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--domain",
        choices=DOMAIN_ORDER,
        help="Generate charts for a single domain.",
    )
    group.add_argument(
        "--all",
        action="store_true",
        help="Generate charts for all completed domains.",
    )
    args = parser.parse_args()

    print(f"\n{'=' * 60}")
    print("  PRAMANIX AUDIT CHART GENERATOR")
    print(f"{'=' * 60}")

    domains = DOMAIN_ORDER if args.all else [args.domain]
    for domain in domains:
        generate_charts_for_domain(domain)

    print(f"\n{'=' * 60}\n")


if __name__ == "__main__":
    main()
