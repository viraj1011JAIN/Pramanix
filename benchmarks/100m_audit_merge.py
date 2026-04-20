# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""benchmarks/100m_audit_merge.py

Assembles the five independent domain run summaries into the final
500 M decision audit report.

Run after ALL 5 domain runs complete:

    python benchmarks/100m_audit_merge.py

The script:
  * Locates the most recent COMPLETED (has summary.json) run for each domain.
  * Validates that all 5 runs passed their individual verdicts.
  * Aggregates totals (decisions, allow/block, timeouts, errors, RSS, P99).
  * Prints the final report to the terminal.
  * Saves benchmarks/results/500m_final_report.json.

It is also safe to run PARTIALLY — if only 2 of 5 domains are done, it will
print the completed ones, report the missing ones, and exit without saving the
final report.  Use this as a progress check between runs:

    python benchmarks/100m_audit_merge.py  # after run 1
    python benchmarks/100m_audit_merge.py  # after run 2
    # ...
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

RESULTS_ROOT = Path("benchmarks/results")
DOMAIN_ORDER = ["finance", "banking", "fintech", "healthcare", "infra"]

_SEP_WIDE   = "=" * 72
_SEP_NARROW = "-" * 72


def find_latest_run(domain_name: str) -> Path | None:
    """Return the most recent completed run directory for *domain_name*, or None."""
    candidates = sorted(
        [
            d for d in RESULTS_ROOT.glob(f"run_{domain_name}_*")
            if d.is_dir() and (d / "summary.json").exists()
        ],
        key=lambda d: d.name,
        reverse=True,
    )
    return candidates[0] if candidates else None


def _fmt_verdict(v: bool) -> str:
    return "PASS [OK]" if v else "FAIL [NO]"


def main() -> None:
    print(f"\n{_SEP_WIDE}")
    print("  PRAMANIX 500 M AUDIT — FINAL REPORT")
    print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{_SEP_WIDE}\n")

    domain_summaries: dict[str, dict] = {}
    missing: list[str] = []

    # ── Locate and validate each domain run ──────────────────────────────────
    for domain in DOMAIN_ORDER:
        run_dir = find_latest_run(domain)
        if run_dir is None:
            missing.append(domain)
            print(f"  [NO]  {domain:<12} : NO COMPLETED RUN FOUND")
            continue

        with open(run_dir / "summary.json") as f:
            s = json.load(f)
        domain_summaries[domain] = s

        v      = s["verdict"]
        vpass  = v.get("pass", False)
        p99    = s.get("avg_p99_ms") or s.get("max_p99_ms") or 0.0
        mrss   = s.get("max_worker_rss_growth") or 0.0
        elh    = s.get("elapsed_hours", 0.0)
        rps    = s.get("avg_rps", 0.0)
        ndec   = s.get("n_decisions", 0)

        print(
            f"  {'PASS [OK]' if vpass else 'FAIL [NO]'}  "
            f"{domain:<12}  "
            f"{ndec:>13,} dec  "
            f"{elh:>6.2f}h  "
            f"RPS={rps:<7,.0f}  "
            f"P99={p99:<8.3f}ms  "
            f"RSS/wkr={mrss:+.1f}MiB"
        )

    # ── Partial-run exit ──────────────────────────────────────────────────────
    if missing:
        print(f"\n{_SEP_NARROW}")
        print(f"  Domains not yet complete: {', '.join(missing)}")
        print("  Run the missing domains before generating the 500 M report.")
        print(f"{_SEP_NARROW}\n")
        return

    # ── Aggregate totals ──────────────────────────────────────────────────────
    total_decisions = sum(s["n_decisions"]    for s in domain_summaries.values())
    total_allow     = sum(s["n_allow"]        for s in domain_summaries.values())
    total_block     = sum(s["n_block"]        for s in domain_summaries.values())
    total_timeout   = sum(s["n_timeout"]      for s in domain_summaries.values())
    total_error     = sum(s["n_error"]        for s in domain_summaries.values())
    total_hours     = sum(s["elapsed_hours"]  for s in domain_summaries.values())

    max_rss  = max(
        (s.get("max_worker_rss_growth") or 0.0) for s in domain_summaries.values()
    )
    all_p99  = [
        (s.get("avg_p99_ms") or s.get("max_p99_ms") or 0.0)
        for s in domain_summaries.values()
    ]
    max_p99      = max(all_p99)
    overall_pass = all(s["verdict"].get("pass", False) for s in domain_summaries.values())

    # ── Merkle summary (one root per worker per domain) ───────────────────────
    all_merkle_roots: dict[str, dict] = {}
    for domain, s in domain_summaries.items():
        all_merkle_roots[domain] = s.get("merkle_roots", {})

    # ── Terminal totals ───────────────────────────────────────────────────────
    print(f"\n{_SEP_NARROW}")
    print("  TOTALS")
    print(f"  Total decisions   : {total_decisions:,}")
    print(f"  Total wall time   : {total_hours:.2f}h across 5 independent runs")
    print(f"  Total allow/block : {total_allow:,} / {total_block:,}")
    print(f"  Total timeouts    : {total_timeout}")
    print(f"  Total errors      : {total_error}")
    print(f"  Max RSS / worker  : {max_rss:+.2f} MiB  (across all domains)")
    print(f"  Max domain P99    : {max_p99:.3f} ms")

    print(f"\n{_SEP_NARROW}")
    print("  INDIVIDUAL VERDICTS")
    for domain in DOMAIN_ORDER:
        s = domain_summaries[domain]
        v = s["verdict"]
        print(f"  {domain:<12} : complete={v['complete']}  no_timeouts={v['no_timeouts']}  "
              f"no_errors={v['no_errors']}  rss_bounded={v['rss_bounded']}")

    print(f"\n{_SEP_NARROW}")
    print(f"  FINAL VERDICT: {_fmt_verdict(overall_pass)}")
    print(f"{_SEP_WIDE}\n")

    # ── Save combined report ──────────────────────────────────────────────────
    report_path = RESULTS_ROOT / "500m_final_report.json"
    report = {
        "generated_at":                  datetime.now().isoformat(),
        "total_decisions":               total_decisions,
        "total_hours":                   round(total_hours, 3),
        "total_allow":                   total_allow,
        "total_block":                   total_block,
        "total_timeout":                 total_timeout,
        "total_error":                   total_error,
        "max_rss_growth_per_worker_mib": round(max_rss, 3),
        "max_domain_p99_ms":             round(max_p99, 3),
        "overall_pass":                  overall_pass,
        "merkle_roots_per_domain":       all_merkle_roots,
        "domains":                       domain_summaries,
    }
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"  Final report saved: {report_path}")

    if overall_pass:
        print("\n  All 5 domains PASS. The 500 M audit is complete.\n")
    else:
        failed = [d for d in DOMAIN_ORDER if not domain_summaries[d]["verdict"].get("pass")]
        print(f"\n  Failed domains: {', '.join(failed)}")
        print("  Investigate the individual summary.json files for each failed domain.\n")


if __name__ == "__main__":
    main()
