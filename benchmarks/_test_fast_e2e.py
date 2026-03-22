"""End-to-end smoke test for the fast worker architecture.

Run with:  python benchmarks/_test_fast_e2e.py
"""
import importlib.util
import multiprocessing
import sys
from pathlib import Path

# Load 100m_worker_fast.py so we can delegate to its worker_entry.
_spec = importlib.util.spec_from_file_location(
    "_wf100m", Path(__file__).parent / "100m_worker_fast.py"
)
_wf_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_wf_mod)


def worker_entry(*args, **kwargs):
    """Module-level wrapper — required for Windows spawn pickling."""
    _wf_mod.worker_entry(*args, **kwargs)


if __name__ == "__main__":
    multiprocessing.freeze_support()

    out = Path(__file__).parent / "results" / "smoke_e2e" / "workers"
    out.mkdir(parents=True, exist_ok=True)

    N_WORKERS            = 3
    DECISIONS_PER_WORKER = 300

    result_queue = multiprocessing.Queue()
    processes = []
    for w in range(N_WORKERS):
        p = multiprocessing.Process(
            target=worker_entry,
            args=("banking", DECISIONS_PER_WORKER, w, str(out),
                  42 + w, 200, 150, 100, result_queue),
            daemon=False,
            name=f"smoke_w{w}",
        )
        p.start()
        processes.append(p)

    results = []
    for _ in range(N_WORKERS):
        r = result_queue.get(timeout=120)
        results.append(r)

    for p in processes:
        p.join(timeout=30)

    total   = sum(r["n_decisions"] for r in results)
    errors  = sum(r["n_error"]     for r in results)
    t_outs  = sum(r["n_timeout"]   for r in results)
    avg_rps = sum(r["avg_rps"]     for r in results) / len(results)
    p99s    = [r["p99_ms"] for r in results]

    print(f"decisions   : {total}")
    print(f"avg RPS     : {avg_rps:.0f}")
    print(f"avg P99 ms  : {sum(p99s)/len(p99s):.1f}")
    print(f"errors      : {errors}")
    print(f"timeouts    : {t_outs}")
    print(f"RSS growths : {[r['rss_growth'] for r in results]}")

    for w in range(N_WORKERS):
        f = out / f"banking_worker_{w:02d}.jsonl"
        lines = [l for l in f.read_bytes().split(b"\n") if l.strip()]
        print(f"  worker {w}: {len(lines)} JSONL lines  chain={results[w]['chain_hash'][:16]}...")

    assert errors == 0,  f"ERRORS: {[r.get('error') for r in results]}"
    assert t_outs == 0,  f"TIMEOUTS detected"
    assert total == N_WORKERS * DECISIONS_PER_WORKER, f"Decision count: {total}"
    print("\nSMOKE TEST: PASS")
