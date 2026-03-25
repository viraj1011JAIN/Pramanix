# Pramanix -- Performance Reference

> **Version:** v0.8.0
> **Platform (Phase 4 benchmarks):** Windows 11, Python 3.13.7, z3-solver 4.x, pytest 7.4.4
> **Test harness:** `tests/integration/test_cold_start_warmup.py`, `benchmarks/`

---

## 1. Benchmark Results Summary

### Phase 4 -- Steady-State and Recycle Benchmarks

Policy under test: single-invariant (`balance - amount >= 0`). Measures Pramanix overhead, not policy complexity. All measurements via `time.perf_counter()` (100 ns resolution on Windows).

| Scenario | P50 | P99 | Mean | Config |
|----------|-----|-----|------|--------|
| Steady-state, warmup=True | 5.5 ms | 8.2 ms | 5.6 ms | 2 workers, async-thread, 5 000 ms timeout, n=30 |
| Steady-state, warmup=False | 6.2 ms | 9.7 ms | 6.4 ms | same |
| Post-recycle, warmup=True | -- | 14.6 ms | -- | at recycle boundary |
| Post-recycle, warmup=False | -- | < 500 ms | -- | cold-start spike visible |

- **Recycle P99 guarantee:** Integration test suite enforces P99 < 200 ms at recycle boundary.
- **Warmup impact:** On a machine with warm OS page cache, the difference is modest. Cold Docker containers show 50-150 ms first-call reduction with warmup.

### Multi-Worker Finance Pilot Run

**Run:** `run_finance_20260322_045923` (2026-03-22, 3 workers, 1,002 decisions)

This was a short integration run to validate the multi-worker infrastructure (subprocess isolation, HMAC-sealed IPC, per-worker Merkle anchoring, RSS tracking). It is not a 100M-decision benchmark. Full-scale runs are in progress and results will be published when complete.

| Metric | Value |
|--------|-------|
| Total decisions | 1,002 |
| Elapsed wall time | 4.1 s |
| Throughput | 247 decisions/second |
| ALLOW / BLOCK | 704 / 298 |
| Timeouts | 0 |
| Errors | 0 |
| Max P99 (across workers) | 54.467 ms |
| Avg P99 (across workers) | 45.637 ms |
| Max per-worker RSS growth | +1.37 MiB |
| Verdict | PASS |

**Per-worker breakdown:**

| Worker | Decisions | Allow | Block | P99 (ms) | RSS Growth (MiB) |
|--------|-----------|-------|-------|----------|-----------------|
| 0 | 334 | 231 | 103 | 54.467 | +1.37 |
| 1 | 334 | 244 | 90 | 39.89 | -13.39 (GC reclaim) |
| 2 | 334 | 229 | 105 | 42.553 | -12.22 (GC reclaim) |

**Merkle roots (tamper-evident chain anchors):**
- Worker 0: `09d082c0...`
- Worker 1: `026d6f93...`
- Worker 2: `ea92a8cb...`

---

## 2. Latency Budget -- Per Pipeline Stage

All times are approximate for a single-invariant policy in `async-thread` mode on commodity hardware.

### API Mode (structured input, no LLM)

```
Stage                              Typical cost
---------------------------------------------------
Payload size check                  < 0.05 ms
Pydantic validation (intent)        0.1 - 0.5 ms
Async field resolver cache hit      < 0.1 ms
Worker queue dispatch               0.1 - 0.3 ms
DSL -> Z3 AST transpile             0.2 - 1.0 ms   (first call; cached after)
Z3 solver (shared, SAT path)        1.0 - 5.0 ms   (depends on invariant count)
Decision object construction        < 0.1 ms
SHA-256 decision_hash               < 0.1 ms
Ed25519 sign (if enabled)           < 0.5 ms
HMAC seal (async-process only)      < 0.1 ms
Structured log emit                 < 0.2 ms
---------------------------------------------------
P50 total (warmup=True)             ~5.5 ms
P99 total (warmup=True)             ~8.2 ms
P99 at recycle boundary             ~14.6 ms
```

### NLP Mode (natural language input, LLM enabled)

```
Stage                              Typical cost
---------------------------------------------------
Input sanitisation (NFKC + scan)    < 1 ms
Dual-model LLM extraction           200 - 2000 ms  (network-dependent)
Consensus validation                < 1 ms
Injection scoring                   < 1 ms
Pydantic validation                 0.1 - 0.5 ms
... (same as API mode above)
---------------------------------------------------
P50 total                           ~500 ms - 2 s  (dominated by LLM latency)
```

- **NLP mode latency is dominated by LLM network round-trip time, not Pramanix overhead.**
- If latency matters, use API mode (pre-structured input). LLM extraction is an optional layer on top.

---

## 3. Worker Warmup

**Why warmup is necessary:**
- Z3 uses a native shared library (`libz3`).
- On the first `z3.Solver()` call in a fresh Python interpreter, the OS loads `libz3` into memory, the JIT warms up, and page faults occur.
- This first-call spike is 50-200 ms and is invisible in steady-state benchmarks.
- Without warmup, the first real request after a worker starts or recycles takes the full spike.

**What warmup does:**
- `WorkerPool.spawn()` submits one trivial solve per worker slot before accepting any real requests.
- The warmup solve uses a private `z3.Context()` (avoids sharing Z3's global context across concurrent warmup calls in thread mode).
- The Z3 library is loaded and JIT-warmed before the first real request arrives.

**Warmup latency cost:**
- Warmup itself takes the spike (50-200 ms once per worker per startup/recycle).
- Clients are never queued during warmup -- warmup fires on the replacement executor before requests are routed to it.

---

## 4. Worker Recycling

**Why recycling is necessary:**
- Z3 accumulates solver metadata (learned clauses, internal term tables, reference-counted expression objects) across calls.
- In long-running processes, RSS grows without bound as each decision adds to the Z3 heap.
- Worker recycling caps this growth by replacing the entire executor after `max_decisions_per_worker` evaluations.

**RSS growth characterization (measured):**

| Decisions (no recycle) | Approximate RSS delta |
|-----------------------|----------------------|
| 0 to 1,000 | < 10 MiB |
| 0 to 10,000 | < 50 MiB |
| 0 to 100,000 | 200-500 MiB (unbounded) |

**Default:** `PRAMANIX_MAX_DECISIONS_PER_WORKER=10000`

- Caps RSS growth to < 50 MiB per worker before recycle.
- Keeps memory flat in steady-state deployments.
- Old executor handed to a background daemon thread for clean shutdown -- main thread never blocks during recycle.

---

## 5. Tuning Guide

### max_workers (`PRAMANIX_MAX_WORKERS`, default: 4)

- **Increase** when CPU utilization is consistently > 70% under load.
- **Optimal value:** 2x number of physical CPU cores for Z3 workloads (Z3 is CPU-bound, not I/O-bound).
- **Cap:** At very high counts, Python's GIL becomes the bottleneck in `async-thread` mode. Switch to `async-process` for true parallelism beyond 8 workers.
- **Memory cost:** Each worker baseline RSS is 50-90 MiB.

### solver_timeout_ms (`PRAMANIX_SOLVER_TIMEOUT_MS`, default: 5000)

- **This is the per-call Z3 timeout, not a request timeout.**
- **Reduce** for adversarial environments where you want to aggressively shed DoS probes. Minimum recommended: 150 ms for simple policies.
- **Increase** only for policies with many invariants (10+) where Z3 legitimately needs more time.
- **Any solver that exceeds the timeout returns `status=TIMEOUT` with `allowed=False`.** This is a safe default.

### max_decisions_per_worker (`PRAMANIX_MAX_DECISIONS_PER_WORKER`, default: 10000)

- **Decrease** for memory-constrained environments (e.g., containers with < 512 MiB limit).
- **Increase** for lower-churn workloads where cold-start cost matters and memory is abundant.
- **Trade-off:** Lower value = lower peak RSS but more frequent recycle + warmup cycles.

### worker_warmup (`PRAMANIX_WORKER_WARMUP`, default: true)

- **Always leave enabled in production.** The only reason to disable is benchmarking the cold-start spike itself.
- Without warmup, the first request after any worker startup or recycle takes the full JIT spike.

### execution_mode

| Mode | When to use |
|------|------------|
| `sync` | Single-threaded scripts, testing, CLI tools. No worker pool. |
| `async-thread` | Web APIs, concurrent workloads. Z3 runs in `ThreadPoolExecutor`. Python GIL limits true parallelism above 4-8 workers. |
| `async-process` | High-security environments, True parallelism beyond 8 workers. Z3 runs in spawned subprocesses with HMAC-sealed IPC. Higher per-call overhead (~2-5 ms) due to IPC. |

### fast_path_enabled (`PRAMANIX_FAST_PATH_ENABLED`, default: false)

- Enables O(1) pre-Z3 screening using up to 5 configurable rules.
- Requests that match a fast-path BLOCK rule are rejected without Z3 involvement (< 1 ms).
- Use for high-volume workloads where common BLOCK patterns are known in advance.
- Fast-path can only produce BLOCK decisions -- ALLOW always requires Z3 proof.

---

## 6. API Mode vs NLP Mode

| Consideration | API Mode | NLP Mode |
|---------------|----------|----------|
| Input format | Pre-structured dict | Natural language string |
| Latency | P99 ~8-15 ms | P50 ~500 ms - 2 s |
| LLM dependency | None | GPT-4o or Claude required |
| Injection surface | Zero (no LLM involved) | 5-layer defence required |
| Cost | Zero (no LLM API calls) | LLM token cost per call |
| Best for | Internal services, agent-to-agent, microservices | Human-facing interfaces, chatbots |
| Additional config | None | `translator_enabled=True`, LLM API keys |

**Decision rule:** If your callers can provide structured field values, always use API mode. NLP mode adds latency, cost, and an injection surface that API mode avoids entirely.

---

## 7. Performance Invariants (Enforced by CI)

These gates run in `tests/perf/` on every commit and fail the build if violated:

| Invariant | Threshold | Test |
|-----------|-----------|------|
| API mode P99 latency | < 15 ms | `test_perf_gates.py::test_p99_api_mode` |
| Fast-path decision | < 1 ms | `test_perf_gates.py::test_fast_path_sub_ms` |
| InvariantMeta cache hit | No recompile on second call | `test_perf_gates.py::test_compiled_metadata` |
| Recycle boundary P99 | < 200 ms | `test_cold_start_warmup.py::test_post_recycle_p99` |
| Worker RSS growth (1000 decisions) | < 10 MiB | `test_perf_gates.py::test_rss_growth` |
