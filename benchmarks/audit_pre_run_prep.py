# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""benchmarks/audit_pre_run_prep.py

Pre-run preparation for the Pramanix 500 M Sovereign Audit.

Run ONCE before the first domain:

    python benchmarks/audit_pre_run_prep.py

Outputs (all written to benchmarks/results/00_environment/):

    hardware_specs.txt         — CPU, RAM, disk, OS, Python, Z3, Pramanix versions
    pramanix_code_snapshot.zip — compressed snapshot of src/pramanix/ + benchmarks/

Upload the contents of 00_environment/ to Google Drive:
    Pramanix_V1_Sovereign_Audit_500M/00_The_Environment/

This establishes an immutable, timestamped record of the exact code and hardware
configuration that generated the 500 M decisions.  If any code changes after this
snapshot, an auditor can diff the zip against the live repo to detect tampering.
"""
from __future__ import annotations

import datetime
import platform
import sys
import zipfile
from pathlib import Path

import psutil

ROOT = Path(__file__).parent.parent
OUT  = ROOT / "benchmarks" / "results" / "00_environment"
OUT.mkdir(parents=True, exist_ok=True)

_SEP = "-" * 60


def _collect_hardware_specs() -> str:
    """Return a multi-line string of hardware and software specs."""
    lines: list[str] = []

    ts = datetime.datetime.now().isoformat(timespec="seconds")
    lines += [
        "=" * 60,
        "  PRAMANIX 500 M SOVEREIGN AUDIT — ENVIRONMENT SNAPSHOT",
        f"  Generated: {ts}",
        "=" * 60,
        "",
    ]

    # ── Operating System ──────────────────────────────────────────────────────
    lines += [
        _SEP,
        "  OPERATING SYSTEM",
        _SEP,
        f"  System      : {platform.system()} {platform.release()}",
        f"  Version     : {platform.version()}",
        f"  Architecture: {platform.machine()}",
        f"  Node        : {platform.node()}",
        "",
    ]

    # ── CPU ───────────────────────────────────────────────────────────────────
    logical_cores  = psutil.cpu_count(logical=True)
    physical_cores = psutil.cpu_count(logical=False)
    cpu_freq       = psutil.cpu_freq()
    freq_str = (
        f"{cpu_freq.current:.0f} MHz  (max {cpu_freq.max:.0f} MHz)"
        if cpu_freq else "N/A"
    )
    lines += [
        _SEP,
        "  CPU",
        _SEP,
        f"  Model       : {platform.processor() or 'N/A'}",
        f"  Logical     : {logical_cores} cores",
        f"  Physical    : {physical_cores} cores",
        f"  Frequency   : {freq_str}",
        "",
    ]

    # ── Memory ────────────────────────────────────────────────────────────────
    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    lines += [
        _SEP,
        "  MEMORY",
        _SEP,
        f"  RAM Total   : {mem.total  / (1024**3):.2f} GB",
        f"  RAM Avail   : {mem.available / (1024**3):.2f} GB",
        f"  Swap Total  : {swap.total / (1024**3):.2f} GB",
        "",
    ]

    # ── Disk ──────────────────────────────────────────────────────────────────
    try:
        disk = psutil.disk_usage("C:\\")
        disk_str = (
            f"{disk.total / (1024**3):.0f} GB total, "
            f"{disk.used / (1024**3):.0f} GB used, "
            f"{disk.free / (1024**3):.0f} GB free"
        )
    except Exception:
        disk_str = "N/A"

    lines += [
        _SEP,
        "  DISK (C:)",
        _SEP,
        f"  C: Drive    : {disk_str}",
        "",
    ]

    # ── Python ────────────────────────────────────────────────────────────────
    lines += [
        _SEP,
        "  SOFTWARE VERSIONS",
        _SEP,
        f"  Python      : {sys.version}",
        f"  Executable  : {sys.executable}",
    ]

    # ── Z3 ────────────────────────────────────────────────────────────────────
    try:
        import z3
        lines.append(f"  Z3          : {z3.get_version_string()}")
    except ImportError:
        lines.append("  Z3          : NOT INSTALLED")

    # ── Pramanix ──────────────────────────────────────────────────────────────
    try:
        sys.path.insert(0, str(ROOT / "src"))
        import pramanix
        pver = getattr(pramanix, "__version__", "dev")
        lines.append(f"  Pramanix    : {pver}")
    except ImportError:
        lines.append("  Pramanix    : not importable (check src/ path)")

    # ── Key packages ──────────────────────────────────────────────────────────
    for pkg in ("psutil", "pydantic", "structlog", "matplotlib"):
        try:
            mod = __import__(pkg)
            ver = getattr(mod, "__version__", "?")
            lines.append(f"  {pkg:<12}: {ver}")
        except ImportError:
            lines.append(f"  {pkg:<12}: NOT INSTALLED")

    lines += [
        "",
        "=" * 60,
        "  END OF ENVIRONMENT SNAPSHOT",
        "=" * 60,
    ]

    return "\n".join(lines)


def _create_code_snapshot(zip_path: Path) -> int:
    """Zip src/pramanix/ and benchmarks/ into *zip_path*.

    Returns the total number of files included.
    Excludes: __pycache__/, *.pyc, *.pyo, .git/, results/ (runtime output).
    """
    EXCLUDE_DIRS  = {"__pycache__", ".git", "results", ".venv", ".mypy_cache"}
    EXCLUDE_EXTS  = {".pyc", ".pyo", ".pyd"}

    folders = [
        ROOT / "src" / "pramanix",
        ROOT / "benchmarks",
    ]

    count = 0
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for folder in folders:
            if not folder.exists():
                print(f"  [!!] Folder not found, skipping: {folder}")
                continue
            for p in sorted(folder.rglob("*")):
                if not p.is_file():
                    continue
                # Exclude directories by name
                if any(part in EXCLUDE_DIRS for part in p.parts):
                    continue
                # Exclude binary/cache extensions
                if p.suffix in EXCLUDE_EXTS:
                    continue
                arcname = p.relative_to(ROOT)
                zf.write(p, arcname)
                count += 1

    return count


def main() -> None:
    print(f"\n{'=' * 60}")
    print("  PRAMANIX PRE-RUN AUDIT PREPARATION")
    print(f"{'=' * 60}\n")
    print(f"  Output directory: {OUT}\n")

    # ── 1. hardware_specs.txt ─────────────────────────────────────────────────
    hw_path = OUT / "hardware_specs.txt"
    specs   = _collect_hardware_specs()
    hw_path.write_text(specs, encoding="utf-8")
    print(f"  [OK] hardware_specs.txt written")
    print()

    # Echo the specs to terminal as well
    print(specs)
    print()

    # ── 2. pramanix_code_snapshot.zip ─────────────────────────────────────────
    zip_path = OUT / "pramanix_code_snapshot.zip"
    print("  Creating code snapshot...")
    n_files  = _create_code_snapshot(zip_path)
    size_mb  = zip_path.stat().st_size / (1024 * 1024)
    print(f"  [OK] pramanix_code_snapshot.zip  ({n_files} files, {size_mb:.2f} MB)")

    # ── 3. Instructions ───────────────────────────────────────────────────────
    print(f"\n{'=' * 60}")
    print("  NEXT STEPS")
    print(f"{'=' * 60}")
    print(f"""
  1. Upload the following to Google Drive:
       Pramanix_V1_Sovereign_Audit_500M/00_The_Environment/

       {hw_path.name}
       {zip_path.name}

  2. (Optional) Take a screenshot of Task Manager / system info
     and upload alongside these files.

  3. Start Google Drive Desktop sync:
       Local:   C:\\Pramanix\\benchmarks\\results\\
       Drive:   Pramanix_V1_Sovereign_Audit_500M/01_Live_Execution_Logs/

  4. Run the first domain:
       python benchmarks/100m_audit_orchestrator.py --domain finance

  The run_meta.json will appear on Google Drive within seconds of
  the run starting, establishing a cryptographic start timestamp.
""")


if __name__ == "__main__":
    main()
