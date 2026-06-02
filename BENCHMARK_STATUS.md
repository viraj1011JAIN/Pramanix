# BENCHMARK_STATUS.md — Pramanix Performance Evidence

> **Purpose**: Honest, evidence-backed record of Pramanix performance characteristics.
> Every number here must be measured, not estimated. "Expected" or "target" values are
> explicitly labelled as such — they are not measurements.
>
> **CRITICAL CAVEAT**: All measurements below are from in-process benchmarks on
> development hardware. No production deployment metrics exist. These numbers indicate
> what the system can achieve in isolation, not under real production load.
>
> **Last Updated**: 2026-06-02
> **Benchmark File**: `tests/benchmarks/test_solver_latency.py`
> **Perf Tests**: `tests/perf/test_memory_stability.py`

---

## Benchmark Infrastructure

### Test Location

| File | Purpose | Mark |
|------|---------|------|
| `tests/benchmarks/test_solver_latency.py` | Z3 solve latency, throughput | `benchmark` |
| `tests/perf/test_memory_stability.py` | Memory leak detection | `perf` |
| `tests/perf/` (3 files total) | Performance regression | `perf` |

### CI Gate

Benchmarks run in CI via:

```yaml
pytest tests/perf/ tests/benchmarks/ -m "not slow" --tb=short
```

(Added in `ci.yml` — commit `143189b`)

### Hardware (Dev Machine — NOT Production)

| Spec | Value |
|------|-------|
| OS | Windows 11 Home |
| Python | 3.13.7 |
| Z3 version | 4.16.0.0 |

---

## Measured Performance (TODO: Run Fresh)

> **STATUS**: The benchmark suite is wired and runnable. The numbers below are
> **targets / expected ranges**, not measurements. Fresh benchmark runs are needed
> before release to populate actual median/p95/p99 values.
>
> **To measure**: `pytest tests/benchmarks/ -v --tb=short`

### Z3 Solve Latency

| Scenario | Target Median | Target p95 | Measured Median | Measured p95 | Date |
|----------|--------------|-----------|-----------------|-------------|------|
| Single invariant (SAT) | < 1 ms | < 5 ms | NOT YET MEASURED | — | — |
| Single invariant (UNSAT) | < 5 ms | < 20 ms | NOT YET MEASURED | — | — |
| 10 invariants (SAT) | < 5 ms | < 25 ms | NOT YET MEASURED | — | — |
| 10 invariants (UNSAT + attribution) | < 20 ms | < 100 ms | NOT YET MEASURED | — | — |
| Cold start (first call) | < 500 ms | < 1000 ms | NOT YET MEASURED | — | — |

### Worker Pool Throughput

| Scenario | Target | Measured | Date |
|----------|--------|----------|------|
| Serial decisions/sec (ThreadPool, 4 workers) | > 100/s | NOT YET MEASURED | — |
| Concurrent decisions/sec (ThreadPool, 4 workers) | > 200/s | NOT YET MEASURED | — |

### Fast Path Performance

| Scenario | Target | Measured | Date |
|----------|--------|----------|------|
| Numeric fast-path (SAT, no Z3) | < 0.1 ms | NOT YET MEASURED | — |
| Numeric fast-path (UNSAT, no Z3) | < 0.1 ms | NOT YET MEASURED | — |

---

## Memory Stability

| Test | Status | Notes |
|------|--------|-------|
| `test_memory_stability.py` | ⚠️ Not run this session | Run: `pytest tests/perf/ -v` |
| Memory leak check (1000 decisions) | Target: < 10 MB growth | Not measured |
| Z3 context cleanup after decision | Expected: ~0 residual | `delete solver + vars` pattern in `solver.py` |

---

## Published Performance Claims vs Evidence

This table tracks every performance claim made in README, whitepaper, or marketing materials,
and whether it is backed by measurements.

| Claim | Source | Evidence Level | Measurement |
|-------|--------|---------------|-------------|
| "Sub-millisecond Z3 evaluation for simple invariants" | README expected | Target only | NOT MEASURED |
| "< 5ms median for 10-invariant SAT check" | WHITEPAPER target | Target only | NOT MEASURED |
| "< 500ms cold start (including JVM warmup)" | Design intent | Target only | NOT MEASURED |

**Honest status**: No performance claim has been validated against measured production data.
All numbers are engineering targets based on Z3's known characteristics.

---

## How to Run Benchmarks

```powershell
# Windows (PowerShell)
& "C:\Pramanix\.venv\Scripts\python.exe" -m pytest tests/benchmarks/ -v --tb=short

# With detailed timing output:
& "C:\Pramanix\.venv\Scripts\python.exe" -m pytest tests/benchmarks/ tests/perf/ -v --tb=short -s
```

---

## Competitive Context (Honest)

| SDK | Verification | Latency |
|-----|-------------|---------|
| **Pramanix** | Z3 formal (deterministic) | Unknown — not measured |
| NeMo Guardrails | LLM-based (probabilistic) | ~200-500ms (LLM round-trip) |
| Guardrails AI | Regex + validators | < 1ms (keyword); ~200ms (LLM) |
| LangChain callbacks | None (hooks only) | < 1ms |

**Note**: NeMo and Guardrails AI latencies are from their published benchmarks, not measured by Pramanix.
The comparison should not be made without Pramanix's own measured latency.

---

## Update Procedure

After running a benchmark session:

1. Run `pytest tests/benchmarks/ -v -s --tb=short 2>&1 | tee benchmark_run.txt`
2. Extract median/p95 from output
3. Update the "Measured" columns in this file
4. Record date and hardware spec
5. Commit with message: `perf(bench): update benchmark measurements YYYY-MM-DD`
6. Update `WORK_LEDGER.md` Phase 9 status
