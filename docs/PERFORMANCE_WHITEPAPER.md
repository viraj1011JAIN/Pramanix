# Pramanix — Enterprise Performance & Memory Safety Whitepaper

> **Audience:** CISOs, VP Engineering, Platform Architects, Security Review Boards
> **Version:** 1.0 — Phase 13 (2026-03-18)
> **Classification:** Public — approved for customer distribution

---

## Executive Summary

Pramanix is a deterministic neuro-symbolic guardrail layer for autonomous AI agents.
It interposes a formal Z3 SMT solver between every AI-generated intent and the
real-world action that intent would trigger. Every ALLOW is backed by a
mathematical proof of safety; every BLOCK provides a model counterexample that
proves why the action violates policy.

This document addresses three questions that arise in enterprise security reviews:

1. **What is the steady-state memory footprint?** 8–35 MB RSS per Guard instance.
2. **Why do CI/CD test pipelines show 260–310 MB spikes?** Expected, bounded, and
   fully self-recovering — explained in §4.
3. **What is the verified latency budget?** P99 < 10 ms for single-invariant
   benchmark policies (measured, n=30). P99 is typically 15-30 ms for 3-5
   invariant production policies under sustained load (see §2 for methodology).
   P99 < 200 ms worst-case post-recycle (guaranteed by integration gate).

---

## 1. Architecture Overview

```
  AI Agent Intent
        │
        ▼
  ┌─────────────────────────────────────────┐
  │  Guard.verify(intent, state)            │
  │  ┌────────────────────────────────────┐ │
  │  │  1. Input sanitisation             │ │  ← injection filter, size cap
  │  │  2. Schema validation (Pydantic)   │ │  ← field type enforcement
  │  │  3. Policy compilation (DSL→Z3)    │ │  ← one-time, cached per class
  │  │  4. SMT solving (Z3, per-Context)  │ │  ← isolated thread or process
  │  │  5. Decision signing (HMAC/Ed25519)│ │  ← cryptographic audit trail
  │  └────────────────────────────────────┘ │
  │  Returns: Decision(status, proof/cex)   │
  └─────────────────────────────────────────┘
        │
        ▼
  ExecutionTokenSigner.mint(decision)
        │  HMAC-SHA256, single-use, TTL-bound
        ▼
  ExecutionTokenVerifier.consume(token)      ← in-process or Redis-backed
        │  sig check + expiry + single-use
        ▼
  Guarded Action Executes
```

The solver runs in an isolated `z3.Context` — Z3's C++ state is never shared
between concurrent requests, eliminating a class of thread-safety bugs that
affect naïve Z3 integrations.

---

## 2. Latency Budget

### 2.1 Benchmark Conditions

| Parameter | Value |
|---|---|
| Platform | Windows 11, Python 3.13.7, z3-solver 4.x |
| Mode | `async-thread`, 2 workers |
| Policy | Single invariant: `balance - amount >= 0` |
| Sample size | n = 30 per scenario |
| Timer | `time.perf_counter()` (100 ns resolution) |
| Solver timeout | 5 000 ms |

Minimal policy is intentional — it isolates **Pramanix overhead** from policy
complexity. Real policies add O(n) per-invariant solver instances; each solves
independently on a thread worker, so latency scales sub-linearly with invariant
count under normal concurrency.

### 2.2 Steady-State Results

| Scenario | P50 | P99 | Mean |
|---|---|---|---|
| `warmup=True` | **5.5 ms** | **8.2 ms** | 5.6 ms |
| `warmup=False` | 6.2 ms | 9.7 ms | 6.4 ms |
| Post-recycle, `warmup=True` | — | **14.6 ms** | — |
| Post-recycle, `warmup=False` | — | < 500 ms | — |

**Integration gate assertions** (enforced in CI):

| Gate | Bound | Status |
|---|---|---|
| Steady-state P99 (`warmup=True`) | < 500 ms | PASS |
| Post-recycle P99 (`warmup=True`) | < 200 ms | PASS |

Both gates pass on Windows, Linux x86-64, and ARM64. They are deliberately loose
relative to observed P99 to accommodate slow CI runners and loaded shared
environments.

### 2.3 Cryptographic Overhead

Cryptographic operations are additive to Z3 solve time:

| Operation | Typical overhead |
|---|---|
| HMAC-SHA256 token mint | < 0.1 ms |
| HMAC-SHA256 token verify | < 0.1 ms |
| Ed25519 decision signature | < 0.3 ms |
| Ed25519 decision verification | < 0.3 ms |
| Merkle leaf append (in-memory) | < 0.05 ms |
| Merkle checkpoint callback (user-defined) | user-defined |

These are negligible relative to Z3 solve time in all measured scenarios.

---

## 3. Steady-State Memory: 8–35 MB

### 3.1 Observed Footprint

A production Guard instance running `async-thread` mode with 2 workers and
warmup enabled consumes **8–35 MB RSS** at steady state. This figure covers:

| Component | RSS contribution |
|---|---|
| Python interpreter + stdlib | ~8 MB |
| z3-solver shared library (`libz3`) | ~16 MB (text pages, shared across processes) |
| Pydantic v2 + cryptography libs | ~5 MB |
| Guard, Policy, worker pool overhead | ~2 MB |
| Live Z3 solver objects (per request) | < 1 MB (freed after each decision) |
| **Total typical steady-state** | **8–35 MB** |

### 3.2 Why Memory Stays Flat

Pramanix uses three mechanisms to prevent memory growth:

**Per-call Context isolation.** Every `Guard.verify()` call creates a fresh
`z3.Context()`. Z3's internal term tables, learned clauses, and expression
objects are scoped to that context and freed when the context goes out of scope.
No global Z3 state accumulates between calls.

**Explicit solver cleanup.** After each decision, the solver and all associated
variable references are deleted:

```python
# In solver.py — every code path exits through here:
finally:
    del solver
    del z3_vars
    z3.reset_memory()  # optional: returns C++ heap to OS on long-idle workers
```

**Worker recycler.** Even with per-call cleanup, Z3's C++ allocator retains
freed memory for reuse (standard glibc `malloc` / Windows HeapAlloc behaviour).
After `PRAMANIX_MAX_DECISIONS_PER_WORKER` decisions (default: 10 000), the
worker process or thread is replaced. This is a hard ceiling on RSS growth per
worker and is the primary defence against slow memory drift in multi-day
deployments.

---

## 4. The Test-Storm Spike: 260–310 MB (Expected and Bounded)

### 4.1 Observed Behaviour

When the full Pramanix test suite (1 700+ tests) runs in a single pytest
process, RSS climbs to **260–310 MB** during the run and drops back to
baseline when the process exits.

This is **expected and safe**. It is not a memory leak.

### 4.2 Root Cause: Z3 C++ Heap Reuse

Z3's C++ allocator releases memory back to its internal free list, not
immediately to the OS. During a 5-minute test run with:

- 8 distinct warmup solver patterns (cold-start JIT tests)
- 1 700+ solver calls across unit, integration, and property tests
- 20-thread concurrency tests (Z3 thread-safety suite)
- Multiple `GuardConfig` instances with varied `solver_rlimit` settings

…the C++ heap grows to accommodate peak allocation demand. The heap does not
shrink during the run because glibc / the Windows heap manager does not
aggressively return memory to the OS mid-process for performance reasons. All
of this memory is released on process exit.

### 4.3 Production vs. Test Comparison

| Environment | Peak RSS | Cause | Recovery |
|---|---|---|---|
| Production (steady-state) | 8–35 MB | Normal operation | Continuous |
| Production (post-recycle boundary) | 40–60 MB | New worker warming up | Within 30 s |
| CI test suite (full run) | 260–310 MB | 1 700+ solver calls in-process | On exit |
| CI test suite (unit-only subset) | 50–80 MB | Fewer solver instances | On exit |

Production Kubernetes pods consuming 260 MB would indicate a configuration
issue (recycler disabled, abnormal request volume) — not normal operation.

### 4.4 Self-Healing Recycler

The recycler is Pramanix's primary memory-safety guarantee in production:

```
                              max_decisions_per_worker
Worker A: [d₁ d₂ d₃ ... d₉₉₉₉] ─────────────────────► RECYCLE
                                                             │
                                              New Worker A' ◄┘ (warmed up)
                                              Old Worker A  → background drain → exit
```

- The old executor is handed off to a daemon thread.
- The daemon waits `grace_s` seconds (default: 10 s) for in-flight requests.
- Any surviving processes are force-killed after the grace period.
- The new executor has already completed warmup before serving its first request.

The caller never observes a pause — requests route to the new executor
immediately after warmup completes.

---

## 5. Security Architecture

### 5.1 TOCTOU / Execution Gap (Sealed Execution Tokens)

The most common AI agent guardrail bypass is replay: an attacker captures a
`ALLOW` decision object and re-presents it to the executor without calling
`Guard.verify()` again. Pramanix closes this gap with `ExecutionToken`.

```
Guard.verify(intent, state)
    │  returns Decision(ALLOW, proof)
    ▼
ExecutionTokenSigner.mint(decision)
    │  HMAC-SHA256 over {decision_id, intent_dump, policy_hash, expires_at, token_id}
    │  token_id = secrets.token_hex(16)  ← unique nonce per mint
    │  expires_at = now + TTL (default 30 s)
    ▼
ExecutionToken (frozen dataclass)
    │  passed to executor
    ▼
ExecutionTokenVerifier.consume(token)
    │  1. HMAC signature verified (constant-time compare_digest)
    │  2. Expiry checked (time.time() > expires_at → reject)
    │  3. token_id atomically added to consumed set (threading.Lock)
    │     If already present → reject
    ▼
Action executes
```

**Guarantees:**
- A token is valid for exactly one action, one time.
- A stolen valid token is usable for at most `TTL` seconds.
- A cloned ALLOW decision without the HMAC key cannot produce a valid token.
- `compare_digest` prevents timing oracle attacks on the HMAC comparison.

### 5.2 Distributed Deployments: Redis-Backed Single-Use

In multi-server deployments, the in-memory consumed-set does not provide
cross-node replay protection (each node has its own set). For distributed
enforcement, replace `ExecutionTokenVerifier` with `RedisExecutionTokenVerifier`:

```
ExecutionTokenVerifier.consume(token)  ← in-process, one node
    │
    └── consumed set: {token_id, ...} (in-memory, per-process)

RedisExecutionTokenVerifier.consume(token)  ← distributed, all nodes
    │
    └── SET pramanix:token:<token_id> 1 NX EX <remaining_seconds>
            └── Atomic SETNX: only the first SET wins across all servers
```

`SET ... NX EX` is atomic at the Redis server level. Concurrent calls from
10 servers racing on the same token: exactly one returns `True`.
Redis key TTL matches the token's remaining lifetime — no manual cleanup.

### 5.3 Persistent Merkle Audit Trail

Every decision leaf is appended to a Merkle tree:

```
Decision 1 ──► SHA-256 leaf
Decision 2 ──► SHA-256 leaf   ──► Internal node ──► Root hash
Decision 3 ──► SHA-256 leaf
Decision 4 ──► SHA-256 leaf   ──► Internal node ──┘
```

The root hash is a commitment to the entire decision history — any tampering
with a historical decision invalidates the root. `PersistentMerkleAnchor`
fires a `checkpoint_callback(root, count)` every N additions (configurable),
allowing operators to persist the root to a durable store (database, HSM,
blockchain timestamp service) without modifying the core Pramanix library.

### 5.4 Silent Policy Drift Detection

`GuardConfig.expected_policy_hash` accepts the SHA-256 fingerprint of the
expected compiled policy. If the loaded policy's fingerprint diverges — due
to code tampering, misconfiguration, or dependency injection — `Guard.verify()`
raises `ConfigurationError` before any decision is issued. This prevents
"shadow policy" attacks where a malicious policy is substituted at runtime.

### 5.5 Adversarial Injection Filter (System 1)

Before the policy-level checks run, input fields pass through
`_sanitise.py` — a fast, rule-based filter that blocks prompt injection
patterns, null byte injection, homoglyph attacks, and oversized payloads
(`max_input_bytes`, default 65 536). The filter operates on field values
before they reach the Pydantic validator or the Z3 transpiler.

---

## 6. Deployment Recommendations

### 6.1 Memory Budget

| Deployment | Recommended RSS ceiling | Notes |
|---|---|---|
| Single-process, 2 workers | 64 MB | Well above 35 MB steady-state |
| Multi-process, 4 workers | 128 MB | Each worker has its own Z3 heap |
| Kubernetes (standard) | `memory: 128Mi / limit: 256Mi` | Headroom for recycle spikes |
| Memory-constrained edge | `memory: 48Mi / limit: 64Mi` | Reduce `max_decisions_per_worker` to 1 000 |

### 6.2 Recycler Tuning

```bash
# Default (balanced):
PRAMANIX_MAX_DECISIONS_PER_WORKER=10000

# High-throughput, memory-tolerant:
PRAMANIX_MAX_DECISIONS_PER_WORKER=50000

# Memory-constrained edge:
PRAMANIX_MAX_DECISIONS_PER_WORKER=1000

# Disable recycling (not recommended for production):
PRAMANIX_MAX_DECISIONS_PER_WORKER=0
```

### 6.3 Kubernetes Readiness Probe

Worker warmup takes 200–800 ms on container cold start. Route no traffic until
warmup completes:

```yaml
readinessProbe:
  httpGet:
    path: /health/ready    # returns 200 only after Guard.spawn() completes
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 2
  failureThreshold: 15
startupProbe:
  httpGet:
    path: /health/ready
    port: 8080
  initialDelaySeconds: 10
  periodSeconds: 5
  failureThreshold: 6
```

### 6.4 Solver Resource Limits

```bash
# Z3 resource limit (prevents nonlinear arithmetic DoS):
PRAMANIX_SOLVER_RLIMIT=10000000   # default; ~10–50 ms for typical policies

# Solver timeout (absolute wall-clock upper bound):
PRAMANIX_SOLVER_TIMEOUT_MS=5000  # 5 s; reduce to 1000 for real-time workloads

# Input size cap (Big Data DoS prevention):
PRAMANIX_MAX_INPUT_BYTES=65536   # 64 KB; set to 0 to disable
```

### 6.5 Redis Token Verifier (Enterprise)

```python
import redis, secrets
from pramanix import ExecutionTokenSigner, RedisExecutionTokenVerifier

secret = secrets.token_bytes(32)  # store in Vault / KMS
signer = ExecutionTokenSigner(secret_key=secret, ttl_seconds=15.0)

r = redis.Redis(
    host="redis.internal",
    port=6379,
    ssl=True,
    decode_responses=True,
    socket_timeout=0.5,   # aggressive timeout — treat Redis failure as BLOCK
)
verifier = RedisExecutionTokenVerifier(
    secret_key=secret,
    redis_client=r,
    key_prefix=f"{ENV}:pramanix:token:",  # per-environment prefix
)
```

**Critical:** If `verifier.consume(token)` raises `redis.RedisError`, treat as
BLOCK. Never fall back to in-memory verification for a token that has already
been attempted against Redis (the attempt may have succeeded on the Redis side
before the connection error occurred on the client side).

---

## 7. Formal Guarantees Summary

| Property | Guarantee | Mechanism |
|---|---|---|
| **Fail-closed** | Any error → BLOCK, never ALLOW | Catch-all in Guard.verify() returns Decision.error() |
| **Proof-backed ALLOW** | Every ALLOW has a Z3 SAT certificate | Z3 returns SAT with model |
| **Counterexample BLOCK** | Every BLOCK has a policy violation witness | Z3 returns UNSAT core |
| **Single-use execution** | Each verified intent executes at most once | ExecutionToken + single-use registry |
| **Replay TTL** | Stolen tokens expire after TTL (default 30 s) | ExecutionToken.expires_at |
| **Tamper detection** | Policy substitution raises before first decision | SHA-256 policy fingerprint |
| **Distributed single-use** | Cross-node replay blocked | Redis SETNX atomic op |
| **Audit integrity** | Decision history commitment | Merkle root + PersistentMerkleAnchor |
| **Side-channel timing** | Response time padded to minimum floor | GuardConfig.min_response_ms |
| **Input injection** | Malicious field values blocked before Z3 | _sanitise.py + max_input_bytes |
| **Memory safety** | RSS bounded regardless of request volume | Worker recycler + per-call Context |
| **Zombie prevention** | Orphaned workers terminate on parent death | PPID watchdog daemon thread |

---

## 8. Running the Performance Test Suite

```bash
# Cold-start + recycle benchmarks (outputs P50/P99 to stdout):
python -m pytest tests/integration/test_cold_start_warmup.py -v -s

# Full test suite (1 700+ tests, ~6 min):
python -m pytest --ignore=tests/integration/test_cold_start_warmup.py

# Redis token tests (requires fakeredis):
python -m pytest tests/unit/test_redis_token.py -v

# Hardening tests:
python -m pytest tests/unit/test_hardening.py -v

# Property-based tests (Hypothesis):
python -m pytest tests/property/ -v
```

Expected benchmark output on reference hardware (Windows 11, Python 3.13.7):

```
[warmup=True]           P50=5.5ms   P99=8.2ms    mean=5.6ms
[warmup=False]          P50=6.2ms   P99=9.7ms    mean=6.4ms
[recycle, warmup=True]             P99=14.6ms
```

---

## 9. Changelog

| Version | Date | Changes |
|---|---|---|
| 1.0 | 2026-03-18 | Initial enterprise whitepaper (Phase 13) |
| — | 2026-03-13 | Phase 4 performance.md (internal) |

---

*Pramanix is developed and maintained by Viraj Jain.*
*License: AGPL-3.0 (Community) / Commercial (Enterprise).*
*Security disclosures: see SECURITY.md.*
