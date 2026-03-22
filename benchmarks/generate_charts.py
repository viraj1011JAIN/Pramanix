#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Generate benchmark visualisation charts from 1M audit results.

Outputs (PNG, 150 dpi) saved to public/:
  1m_rss_timeline.png        -- RSS over time (sampled from timeline.jsonl)
  1m_latency_percentiles.png -- P50/P95/P99 across 10 checkpoints
  1m_rps_progression.png     -- RPS across 10 checkpoints
  1m_latency_distribution.png -- latency percentile bar chart (final)
  1m_gc_cycles.png           -- GC collections bar chart

Usage:
    cd C:\\Pramanix
    .venv\\Scripts\\activate
    python benchmarks/generate_charts.py
"""
from __future__ import annotations

import json
from pathlib import Path

# ---- paths ------------------------------------------------------------------
ROOT = Path(__file__).parent.parent
RESULTS = ROOT / "benchmarks" / "results"
PUBLIC = ROOT / "public"
PUBLIC.mkdir(exist_ok=True)

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.ticker as ticker
except ImportError:
    print("ERROR: pip install matplotlib")
    raise

# ---- colour palette (dark, clean) -------------------------------------------
BG = "#0d1117"
GRID = "#21262d"
TEXT = "#c9d1d9"
ACCENT = "#58a6ff"
GREEN = "#3fb950"
YELLOW = "#d29922"
RED = "#f85149"
ORANGE = "#e3b341"
PURPLE = "#bc8cff"


def _style(fig: plt.Figure, ax: plt.Axes, title: str) -> None:
    fig.patch.set_facecolor(BG)
    ax.set_facecolor(BG)
    ax.set_title(title, color=TEXT, fontsize=13, fontweight="bold", pad=14)
    ax.tick_params(colors=TEXT, labelsize=9)
    ax.xaxis.label.set_color(TEXT)
    ax.yaxis.label.set_color(TEXT)
    for spine in ax.spines.values():
        spine.set_edgecolor(GRID)
    ax.grid(color=GRID, linestyle="--", linewidth=0.6, alpha=0.8)


def _save(fig: plt.Figure, name: str) -> None:
    path = PUBLIC / name
    fig.savefig(path, dpi=150, bbox_inches="tight", facecolor=BG)
    plt.close(fig)
    print(f"  saved: {path}")


# ---- load data --------------------------------------------------------------
with open(RESULTS / "1m_audit_timeline.jsonl") as f:
    timeline_raw = [json.loads(line) for line in f]

with open(RESULTS / "1m_audit_checkpoints.json") as f:
    checkpoints = json.load(f)

with open(RESULTS / "1m_audit_summary.json") as f:
    summary = json.load(f)

# ---- 1. RSS timeline (sample every 60th row = 1 point per minute) -----------
print("Generating RSS timeline chart ...")
SAMPLE = 60
tl = timeline_raw[::SAMPLE]
t_hrs = [r["t_s"] / 3600 for r in tl]
rss = [r["rss_mib"] for r in tl]
baseline = summary["memory"]["baseline_mib"]
final = summary["memory"]["final_mib"]
peak = summary["memory"]["peak_mib"]

fig, ax = plt.subplots(figsize=(11, 4))
ax.plot(t_hrs, rss, color=ACCENT, linewidth=0.9, alpha=0.85, label="RSS (MiB)")
ax.axhline(baseline, color=GREEN, linewidth=1.2, linestyle="--",
           label=f"Baseline {baseline:.1f} MiB")
ax.axhline(final, color=YELLOW, linewidth=1.2, linestyle="--",
           label=f"Final {final:.1f} MiB")
ax.axhline(peak, color=RED, linewidth=0.8, linestyle=":",
           label=f"Peak {peak:.1f} MiB")
ax.fill_between(t_hrs, rss, baseline, alpha=0.08, color=ACCENT)
ax.set_xlabel("Elapsed time (hours)")
ax.set_ylabel("RSS (MiB)")
ax.legend(facecolor=GRID, labelcolor=TEXT, fontsize=8, loc="upper right")
ax.xaxis.set_major_formatter(ticker.FormatStrFormatter("%.1fh"))
_style(fig, ax,
       "RSS Memory Timeline — 1,000,000 Decisions (1 sample/min shown)")
# Truncate to 2 d.p. (not round) to match the terminal output value of 2.80
growth_display = int(summary["memory"]["growth_mib"] * 100) / 100
note = (
    f"Net growth: +{growth_display:.2f} MiB  |  "
    f"Platform: Windows 11 / Python 3.13.7 / z3-solver 4.16.0 / "
    f"single thread, single CPU core"
)
fig.text(0.5, -0.04, note, ha="center", fontsize=7.5, color=TEXT, alpha=0.7)
_save(fig, "1m_rss_timeline.png")

# ---- 2. Latency percentiles across 10 checkpoints --------------------------
print("Generating latency percentiles chart ...")
ck_labels = [f"{c['decision'] // 1000}K" for c in checkpoints]
p50w = [c["window"]["p50_ms"] for c in checkpoints]
p95w = [c["window"]["p95_ms"] for c in checkpoints]
p99w = [c["window"]["p99_ms"] for c in checkpoints]

fig, ax = plt.subplots(figsize=(11, 5))
x = range(len(ck_labels))
ax.plot(x, p50w, color=GREEN, marker="o", markersize=5, linewidth=1.8,
        label="P50 (window)")
ax.plot(x, p95w, color=YELLOW, marker="s", markersize=5, linewidth=1.8,
        label="P95 (window)")
ax.plot(x, p99w, color=RED, marker="^", markersize=5, linewidth=1.8,
        label="P99 (window)")
ax.axhline(100, color=RED, linewidth=0.8, linestyle=":",
           label="P99 target (<100 ms)")
ax.set_xticks(list(x))
ax.set_xticklabels(ck_labels)
ax.set_xlabel("Decisions completed")
ax.set_ylabel("Latency (ms)")
ax.legend(facecolor=GRID, labelcolor=TEXT, fontsize=9)
_style(fig, ax,
       "Per-Window Latency Percentiles across 10 × 100K Checkpoints")
_save(fig, "1m_latency_percentiles.png")

# ---- 3. RPS progression across checkpoints ----------------------------------
print("Generating RPS progression chart ...")
rps_vals = [c["rps"] for c in checkpoints]

fig, ax = plt.subplots(figsize=(11, 4))
bars = ax.bar(list(x), rps_vals, color=ACCENT, alpha=0.85, width=0.6)
for bar, val in zip(bars, rps_vals):
    ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1,
            f"{val:.0f}", ha="center", va="bottom", color=TEXT, fontsize=8)
ax.set_xticks(list(x))
ax.set_xticklabels(ck_labels)
ax.set_xlabel("Decisions completed")
ax.set_ylabel("Decisions / second")
ax.set_ylim(0, max(rps_vals) * 1.25)
_style(fig, ax,
       "Throughput (RPS) at Each 100K Checkpoint — Single Core")
_save(fig, "1m_rps_progression.png")

# ---- 4. Final latency distribution bar chart --------------------------------
print("Generating final latency distribution chart ...")
lat = summary["latency_ms"]
labels = ["Min", "P50", "P95", "P99", "P99.9", "P99.99", "Max"]
values = [
    lat["min"], lat["p50"], lat["p95"], lat["p99"],
    lat["p99_9"], lat["p99_99"], lat["max"],
]
colours = [GREEN, GREEN, YELLOW, YELLOW, ORANGE, RED, RED]

fig, ax = plt.subplots(figsize=(10, 5))
bars = ax.bar(labels, values, color=colours, alpha=0.88, width=0.6)
for bar, val in zip(bars, values):
    ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 5,
            f"{val:.1f} ms", ha="center", va="bottom", color=TEXT, fontsize=8)
ax.axhline(100, color=RED, linewidth=1, linestyle="--",
           label="100 ms reference")
ax.set_ylabel("Latency (ms)")
ax.set_yscale("log")
ax.yaxis.set_major_formatter(ticker.ScalarFormatter())
ax.legend(facecolor=GRID, labelcolor=TEXT, fontsize=9)
_style(fig, ax,
       "Latency Distribution — 1,000,000 Decisions (log scale)")
_save(fig, "1m_latency_distribution.png")

# ---- 5. GC cycles bar chart -------------------------------------------------
print("Generating GC cycles chart ...")
gc_d = summary["gc"]
gens = ["gen0", "gen1", "gen2"]
baseline_gc = [gc_d["baseline"][g] for g in gens]
final_gc = [gc_d["final"][g] for g in gens]
delta_gc = [gc_d["delta"][g] for g in gens]

fig, ax = plt.subplots(figsize=(7, 4))
bar_w = 0.28
xg = [0, 1, 2]
b1 = ax.bar([p - bar_w for p in xg], baseline_gc, width=bar_w,
            color=ACCENT, alpha=0.8, label="Baseline")
b2 = ax.bar(xg, final_gc, width=bar_w,
            color=GREEN, alpha=0.8, label="Final")
b3 = ax.bar([p + bar_w for p in xg], delta_gc, width=bar_w,
            color=YELLOW, alpha=0.8, label="Delta (during 1M run)")
for bars in (b1, b2, b3):
    for bar in bars:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2, h + 0.2,
                str(int(h)), ha="center", va="bottom", color=TEXT, fontsize=9)
ax.set_xticks(xg)
ax.set_xticklabels(["gen0\n(young)", "gen1\n(mid)", "gen2\n(old)"])
ax.set_ylabel("GC cycles")
ax.set_ylim(0, max(final_gc) * 1.5 + 5)
ax.legend(facecolor=GRID, labelcolor=TEXT, fontsize=9)
_style(fig, ax,
       "Python GC Collection Cycles — Before vs After 1M Decisions")
note2 = (
    "Only 6 gen0 cycles in 1M decisions. "
    "del ctx after each call = near-zero garbage."
)
fig.text(0.5, -0.04, note2, ha="center", fontsize=8, color=TEXT, alpha=0.7)
_save(fig, "1m_gc_cycles.png")

print("\nAll charts saved to public/")
