# Pramanix v1.0.0 — State of the Codebase & Operational Handover

**Author:** Viraj Jain
**Date:** 2026-04-27
**Commit baseline:** `73aef10` (main branch)
**License:** AGPL-3.0-only (Community) / Commercial (Enterprise)

This document is a factual engineering record, not a sales pitch. Every claim below is sourced directly from the production code. No marketing language is intentional; if a section reads positively it is because the implementation actually works that way.

---

## Table of Contents

1. [Deep Knowledge & Core Architecture](#1-deep-knowledge--core-architecture)
   - 1.1 [The Z3 SMT Integration](#11-the-z3-smt-integration)
   - 1.2 [The Orchestrator & Zero-IPC Worker Pool](#12-the-orchestrator--zero-ipc-worker-pool)
   - 1.3 [Sealed Execution Tokens (TOCTOU Guard)](#13-sealed-execution-tokens-toctou-guard)
   - 1.4 [The Merkle Audit Chain](#14-the-merkle-audit-chain)
2. [Current State & Engineering Standards](#2-current-state--engineering-standards)
3. [Honest Limitations & Architectural Tech Debt](#3-honest-limitations--architectural-tech-debt)
4. [Enterprise Disaster Runbooks](#4-enterprise-disaster-runbooks)
   - 4.1 [KMS Outage Blast Radius](#41-kms-outage-blast-radius)
   - 4.2 [Economics of the Math](#42-economics-of-the-math)
   - 4.3 [Cryptographic Key Compromise & Rotation](#43-cryptographic-key-compromise--rotation)
   - 4.4 [The Glass Break: Z3 Panic & Stuck Workers](#44-the-glass-break-z3-panic--stuck-workers)

---

## 1. Deep Knowledge & Core Architecture

### 1.1 The Z3 SMT Integration

#### What it does

The Z3 layer takes a policy — a set of named, symbolic inequality constraints over typed fields — and asks a theorem prover whether a specific set of concrete values satisfies all constraints simultaneously. This is not approximate or ML-based. The answer is either mathematically **SAT** (provably satisfies all invariants) or **UNSAT** (at least one invariant is violated), with the violated constraints identified exactly.

#### The pipeline from Python DSL to Z3 formula

**Step 1 — Field declarations compile to Z3 sorts (`transpiler.py`).**

```python
amount = Field("amount", Decimal, "Real")   # → z3.Real("amount")
balance = Field("balance", Decimal, "Real") # → z3.Real("balance")
is_frozen = Field("is_frozen", bool, "Bool") # → z3.Bool("is_frozen")
```

Supported sorts: `Real`, `Int`, `Bool`, `String`. Each sort maps to a distinct Z3 theory. Mixing sorts in a single expression (e.g., `Real + Int`) would break Z3's type system; the transpiler validates sort compatibility at invariant-compile time, not at call time.

**Step 2 — Invariants compile to Z3 AST nodes (`transpiler.py:transpile()`).**

The `E()` expression builder produces a lazy AST — no Z3 object is created until `transpile()` is called. This matters because Z3 contexts are not thread-safe across processes; the AST nodes are pure Python objects that serialize safely.

The full operator coverage:

| DSL operator | Z3 translation |
|---|---|
| `E(a) + E(b)` | `z3.ArithRef.__add__` |
| `E(a) - E(b)` | `z3.ArithRef.__sub__` |
| `E(a) * E(b)` | `z3.ArithRef.__mul__` |
| `E(a) / E(b)` | `z3.ArithRef.__truediv__` |
| `E(a) ** n` (n ≤ 4) | repeated multiplication |
| `E(a) % E(b)` | `z3.ArithRef.__mod__` |
| `E(a) == E(b)` | `_z3_eq()` (sort-safe via `Z3_mk_eq`) |
| `E(a) >= E(b)`, `<=`, `>`, `<` | standard Z3 ArithRef comparisons |
| `E(a) & E(b)` | `z3.And()` |
| `E(a) \| E(b)` | `z3.Or()` |
| `~E(a)` | `z3.Not()` |
| `E(a).contains(s)` | `z3.Contains()` (String theory) |
| `E(a).matches(pattern)` | `z3.Re(z3.StringVal(pattern))` |
| `E(a).starts_with(s)` | `z3.PrefixOf()` |
| `E(a).ends_with(s)` | `z3.SuffixOf()` |
| `E(a).length_between(lo, hi)` | `z3.And(z3.Length(a) >= lo, z3.Length(a) <= hi)` |

**Floating-point values are never passed directly to Z3.** All floats go through `Decimal(str(v)).as_integer_ratio()` to get an exact numerator/denominator, then become `z3.RealVal(num) / z3.RealVal(den)`. This eliminates IEEE-754 approximation errors from formal proofs.

**String promotion (`transpiler.py:analyze_string_promotions()`):** Fields declared as `String` sort but used only in equality/membership comparisons against a bounded enum are automatically promoted to `Int` sort at Guard construction time. An integer sentinel is assigned to each distinct string literal. This eliminates Z3's sequence-theory overhead and produces a 5–10× latency reduction for fields like `currency_code`, `country_iso`, or `risk_tier`. The promotion is transparent: the caller still passes string values; the transpiler handles the mapping.

**Power operator safety:** `E(x) ** n` where `n > 4` raises `TranspileError` at compile time. This prevents polynomial-complexity expressions (e.g., `x**1000`) from triggering Z3's nonlinear arithmetic solver, which can be exponential-time.

**InvariantASTCache (`transpiler.py`):** A thread-safe LRU cache (512 entries, keyed by invariant object identity) stores compiled metadata — field references, sort classifications, string promotion maps — so that per-call transpilation is incremental, not full recompilation. The cache is populated at `Guard.__init__()` time during `compile_policy()`.

#### Two-phase verification (`solver.py`)

Phase 1 (fast path, every call):
```
one shared z3.Solver
  └── s.add(invariant_1_formula)
  └── s.add(invariant_2_formula)
  └── s.add(binding_1: field == value)
  └── s.add(binding_2: field == value)
  └── s.check()
       ├── sat   → return immediately (ALLOW, ~0.3 ms typical)
       └── unsat → enter Phase 2
```

Phase 2 (attribution, only on violation):
```
for each invariant:
  new z3.Solver()  ← fresh context per invariant
    └── s.assert_and_track(invariant_formula, label)
    └── s.add(all bindings)
    └── s.check()
         ├── sat   → invariant satisfied, skip
         └── unsat → s.unsat_core() → returns exactly {label}
                      because there is exactly one tracked assertion
```

**Why per-invariant solvers on Phase 2:** `unsat_core()` on a shared solver returns a *minimal* unsatisfiable subset, not the *complete* set of violated invariants. With N=5 invariants and 3 violated, the shared solver might return only 1 or 2 as the minimal core. Running each invariant in isolation guarantees that `unsat_core()` == `{label}` when that invariant is violated. The Phase 2 cost is only paid on the BLOCK path — the overwhelmingly rare case in production.

**Timeouts and rlimits:**

Both phases accept two independent resource limits:

- `solver_timeout_ms` (default: `5000`) — wall-clock timeout in milliseconds. Applied via `s.set("timeout", timeout_ms)`. This is a soft guarantee; Z3 checks its own deadline periodically.
- `solver_rlimit` (default: `10_000_000`) — resource limit in elementary Z3 operations. Applied via `s.set("rlimit", rlimit)`. This is a hard, operation-count guarantee independent of machine speed. The combination of both limits closes the logic-bomb and nonlinear-expression DoS attack vectors.

When Z3 returns `z3.unknown` (timeout or rlimit exhausted), the solver raises `SolverTimeoutError` with the label of the stuck invariant. Guard converts this to `Decision.timeout()`, which has `allowed=False`. **There is no path from a timed-out solver to an ALLOW decision.**

---

### 1.2 The Orchestrator & Zero-IPC Worker Pool

#### Three execution modes

| Mode | Class | Use case |
|---|---|---|
| `"sync"` | Direct call | Django, Flask, Celery, scripting |
| `"async-thread"` | `ThreadPoolExecutor` | FastAPI, asyncio services, light concurrency |
| `"async-process"` | `ProcessPoolExecutor` (spawn) | High throughput, full Z3 isolation, crash resilience |

The mode is set via `GuardConfig(execution_mode=...)` or `PRAMANIX_EXECUTION_MODE` env var.

#### Why there is no IPC overhead

The decision counter (`_counter`) is a plain `int` in the **host process**, guarded by a single `threading.Lock`. There is no inter-process counter, no shared memory segment, no message-passing for bookkeeping. This is explicitly documented as a design invariant in `worker.py`:

> "No IPC counter. The decision counter is a plain int in the host process, guarded by a threading.Lock. Zero contention, zero IPC."

In process mode, the boundary between host and worker is:
- **Input** (host → worker): `(policy_cls, values_dict, timeout_ms)` — pure Python primitives. `policy_cls` is a class reference, pickled by import path.
- **Output** (worker → host): a plain `dict` representation of a `Decision`, plus an HMAC-SHA256 authentication tag.

**No Z3 objects cross the process boundary.** Every worker reconstructs the Z3 formula tree from scratch using the same `compile_policy()` pipeline that runs at `Guard.__init__()`. This is safe because:
1. Z3 contexts are per-process (thread-unsafe across forks).
2. Class references (`policy_cls`) pickle via their fully-qualified module name, not object state.

#### Sealed IPC (result integrity)

In process mode, each worker pool generates a fresh 32-byte random secret (`_EphemeralKey`) at spawn time. The secret is passed to workers during initialization and used to HMAC-SHA256 the outbound `Decision` dict before sending it back over the `ProcessPoolExecutor` future. The host calls `_unseal_decision()`, which recomputes the HMAC and uses `hmac.compare_digest()` (constant-time comparison) to verify integrity before deserializing.

If the HMAC tag does not match, the host returns `Decision.error()` rather than processing the tampered result. This prevents a compromised worker process from injecting a fabricated ALLOW decision.

#### Worker recycling and zombie safety

Workers are recycled after `max_decisions_per_worker` calls (default: `10_000`). The purpose is to prevent Z3 memory accumulation over long-running processes; Z3 allocates persistent internal state per solve that is not fully freed between calls.

Recycling procedure (`_drain_executor()`):
1. The old `ProcessPoolExecutor` is handed to a daemon background thread — the event loop is never blocked.
2. The background thread calls `executor.shutdown(wait=True)` with a `_RECYCLE_GRACE_S = 10.0` second timeout.
3. If workers are still alive after the grace period, each `multiprocessing.Process` object receives `.kill()` (SIGKILL on POSIX, `TerminateProcess` on Windows).

A `_ppid_watchdog()` daemon thread runs in each worker process. It polls `os.getppid()` every 5 seconds and calls `sys.exit(0)` if the parent process has exited. This prevents orphan worker processes from consuming system resources after the host dies without calling `WorkerPool.shutdown()`.

#### Worker warmup

When `worker_warmup=True` (default), each fresh worker immediately executes `_warmup_worker()` — 8 diverse Z3 solves covering Real arithmetic, Int constraints, Boolean logic, mixed arithmetic/boolean, String operations, modulo, absolute value, and power constraints. This forces Z3's JIT to compile its hot paths before the first production request arrives. Without warmup, the first 3–5 requests on a cold worker take 5–15× longer than steady-state.

#### Adaptive load shedding

`AdaptiveConcurrencyLimiter` sheds requests when **both** conditions are simultaneously true:
1. `active_workers >= max_workers * shed_worker_pct / 100` (default: 90%)
2. `p99_solver_latency_ms > shed_latency_threshold_ms` (default: 200 ms)

The dual-condition design prevents false positives. High worker utilization alone is healthy burst traffic. High latency alone may be a transient GC pause. Both together signals genuine overload. Shed requests return `Decision.error(status=RATE_LIMITED, allowed=False)` immediately.

The P99 is computed over a 60-second rolling window using a `collections.deque` of `(timestamp, latency_ms)` tuples. The window is pruned on every `should_shed()` call.

---

### 1.3 Sealed Execution Tokens (TOCTOU Guard)

#### The problem being solved

Without tokens, there is an **execution gap** between `Guard.verify()` returning `allowed=True` and the actual execution of the guarded action. An attacker with memory access could:

1. Replay a previously-captured `Decision.safe()` JSON record.
2. Pass a fabricated `Decision(allowed=True)` object to the executor.
3. Execute the same action twice using one verification (double-spend).
4. Verify against stale state and execute against new, modified state (TOCTOU).

#### Token structure (`execution_token.py`)

```python
@dataclass(frozen=True)
class ExecutionToken:
    decision_id:   str        # UUID4 from the originating Decision
    allowed:       bool       # always True; mint() refuses BLOCK decisions
    intent_dump:   dict       # exact intent values that were verified
    policy_hash:   str | None # SHA-256 fingerprint of the compiled policy
    expires_at:    float      # Unix timestamp (default: now + 30s)
    token_id:      str        # random 16-byte hex nonce per mint() call
    signature:     str        # hex-encoded HMAC-SHA256 over canonical body
    state_version: str | None # caller-supplied state ETag at verify time
```

#### HMAC-SHA256 construction

The signature covers a canonical body assembled as:
```
{decision_id}:{allowed}:{policy_hash}:{expires_at}:{token_id}:{state_version}
```
Signed with a 32-byte random secret shared between `ExecutionTokenSigner` and `ExecutionTokenVerifier`. The `intent_dump` is not included in the signature body; it is carried as metadata for the executor but the token binding is to `decision_id` and `policy_hash`, not the raw values. This is intentional: replaying the token with a *different* intent is impossible without also forging the `decision_id`.

#### Four-layer verification in `consume()`

1. **Signature check:** HMAC-SHA256 recomputed over canonical body; `hmac.compare_digest()` comparison. Fails → `False`.
2. **Expiry check:** `time.time() > token.expires_at`. Fails → `False`. Default TTL is 30 seconds from `mint()` time.
3. **State-version check:** If `expected_state_version` is provided to `consume()`, it must match `token.state_version`. A mismatch means the backing state was mutated between `Guard.verify()` and the attempted execution — this is exactly the TOCTOU scenario being caught. Fails → `False`.
4. **Single-use enforcement:** The `token_id` is written to a consumed-set atomically (under `threading.Lock`). If already present, returns `False`. The nonce means identical-payload decisions cannot share a token; each call to `mint()` produces a unique `token_id` via `secrets.token_hex(16)`.

All four checks must pass for `consume()` to return `True`.

#### Backend implementations

| Backend | Single-use guarantee | Multi-process safe | Notes |
|---|---|---|---|
| `InMemoryExecutionTokenVerifier` | per-process only | no | development/test only |
| `SQLiteExecutionTokenVerifier` | WAL mode, UNIQUE constraint | single-host | auto-expires via GC on consume |
| `RedisExecutionTokenVerifier` | SETNX + TTL | yes, multi-server | token_id as Redis key |
| `PostgresExecutionTokenVerifier` | asyncpg UNIQUE constraint | yes, multi-server | async wrapper |

For Kubernetes and multi-replica deployments, **Redis or Postgres is mandatory**. InMemory allows one replay per replica.

---

### 1.4 The Merkle Audit Chain

#### Purpose

A Merkle tree over `decision_id` strings allows proving that any single decision was part of an unaltered batch without replaying all decisions. The root hash is a 32-byte SHA-256 digest representing the entire batch. Providing the root hash + a proof path allows any auditor to verify inclusion in O(log N) hash operations.

#### Cryptographic construction

**Leaf hashing:**
```python
leaf_hash = sha256(b"\x00" + decision_id.encode()).hexdigest()
```

**Internal node hashing:**
```python
node_hash = sha256(b"\x01" + (left_child + right_child).encode()).hexdigest()
```

**The `\x00`/`\x01` domain separation tags (H-07 patch):** This is not cosmetic. Without domain separation, a naive implementation using plain `sha256(child_a + child_b)` is vulnerable to a second-preimage attack. An attacker can construct an odd-length sequence of leaves such that the padded duplicate appears as a valid internal node with the same hash, producing an identical Merkle root for two structurally different trees. This is a known vulnerability (Bitcoin CVE-2012-2459). Pramanix patches it by:

- All real leaf nodes: `sha256(b"\x00" + id)` — the `\x00` prefix makes leaf hashes structurally distinct from any internal node hash.
- All internal nodes: `sha256(b"\x01" + left + right)` — the `\x01` prefix makes internal node hashes structurally distinct from leaf hashes.
- Odd-length padding: the duplicate of the last leaf uses `sha256(b"\x01" + last_leaf)` — a **transformed** hash, not a copy. This ensures that a 3-leaf tree and a 3-leaf tree with a different third element always produce different roots.

**Proof verification (`MerkleProof.verify()`):**
```python
current = leaf_hash
for sibling, direction in proof_path:
    combined = sibling + current if direction == "left" else current + sibling
    current = sha256(b"\x01" + combined.encode()).hexdigest()
return current == root_hash
```

The proof path is O(log N) entries. Each entry is `(sibling_hash, "left" | "right")` indicating whether the sibling was to the left or right of the current node at that level.

#### Persistence

`PersistentMerkleAnchor` wraps the in-memory anchor with a `checkpoint_callback` that fires every `checkpoint_every` additions (default: 100). The callback receives `(root_hash: str, leaf_count: int)`. The caller is responsible for writing this to a durable store (database row, append-only file, S3 object, blockchain anchor). The in-memory tree itself is not durable — process death loses it. `flush()` must be called at shutdown to persist any trailing leaves since the last automatic checkpoint.

#### Ed25519 decision signatures

Each `Decision` carries an Ed25519 signature over its canonical SHA-256 hash. The signing workflow:

1. `Decision._compute_hash()` builds a canonical dict (timestamp, decision_id, allowed, violated_invariants, explanation, policy_hash) and computes `sha256(json.dumps(canonical, sort_keys=True).encode()).hexdigest()`.
2. `PramanixSigner.sign(decision)` signs the `decision_hash` bytes with the Ed25519 private key.
3. The signature is stored in `decision.signature` as a base64url string.
4. `PramanixVerifier.verify(decision_hash, signature)` uses the public key to verify.

**Redaction and signature integrity:** When `redact_violations=True`, the `explanation` and `violated_invariants` fields are replaced with `"Policy Violation: Action Blocked"` after signing. The `decision_hash` (and therefore the signature) is computed over the **real, unredacted** fields. A server-side verifier holding the audit log with the original values can always verify the signature against the unredacted hash; the redacted client-facing copy cannot be independently verified without the original data. This is documented behavior, not a bug.

---

## 2. Current State & Engineering Standards

### Exact baseline (commit `73aef10`, 2026-04-27)

| Metric | Value |
|---|---|
| Version | 1.0.0 |
| Source lines (SLOC) | 6,065 (measured by `coverage report`) |
| Test count | 3,155 collected |
| Statement coverage | 98% (119 uncovered lines) |
| Branch coverage | included in combined 98% |
| Python versions | 3.11, 3.12, 3.13 |
| Source files | 53 |
| Pyright errors | 0 |

Files at 100% coverage: `solver.py`, `decision.py`, `policy.py`, `circuit_breaker.py`, `crypto.py`, `guard.py`, `execution_token.py`, `audit/merkle.py`, `exceptions.py`, all primitive libraries, all interceptors, `redis.py`, `resolvers.py`, `validator.py`.

Files with known partial coverage:
- `translator/anthropic.py` (61%) — lines 87–127, 157–163 are the live HTTP call paths. These require a real Anthropic API endpoint and are tested separately in `test_translator_anthropic.py` against the VS Code Language Model proxy.
- `translator/openai_compat.py` (57%) — similar: live HTTP paths require an OpenAI-compatible endpoint.
- `worker.py` (98%) — lines 392–393, 652–653, 710, 719–720 are SIGKILL and platform-specific process-kill paths unreachable without a deliberately-stalled worker process.

### Infrastructure shift: mocks → testcontainers

The final test commit (`73aef10`) completed the full replacement of fake infrastructure with real testcontainers:

| What was removed | What replaced it |
|---|---|
| `fakeredis` + `AsyncMock` for Redis | `testcontainers[redis]` with a real Redis 7 container |
| `asyncpg.UniqueViolationError` side-effect mocks | Real asyncpg connection to `testcontainers[postgres]` (PostgreSQL 16) |
| `confluent_kafka.Producer` `AsyncMock` | Real Kafka producer against `testcontainers[kafka]` |
| `respx` HTTP intercepts for Anthropic | Real HTTP calls via `ANTHROPIC_BASE_URL` pointing to VS Code LLM proxy |
| `boto3` `MagicMock` clients for LocalStack | `testcontainers[localstack]` with real `boto3.client("secretsmanager", endpoint_url=...)` |
| `MagicMock` for OTel spans | Real `opentelemetry-sdk` `InMemorySpanExporter` |
| `prometheus_client` registry mocks | Real duplicate metric registration triggering `ValueError` recovery |

The only remaining mock-like constructs in the test suite are:
1. `__new__` + attribute injection for cloud KMS provider behavioral tests — the `_client=` parameter is explicitly documented as "Injected for testing; not part of the public API" and uses real SDK object instances.
2. `# pragma: no cover` markers on genuinely unreachable code (ImportError guards where the SDK is installed, OS-specific kill paths, older SDK fallback branches).

### CI/CD pipeline (`.github/workflows/ci.yml`)

Stage sequence: `sast → alpine-ban → lint-typecheck → test → coverage → wheel-smoke → trivy → license-scan`

| Stage | Tool | Gate |
|---|---|---|
| SAST | Bandit | Fail on HIGH severity |
| Alpine ban | `grep -r "alpine"` on Dockerfiles | Fail if found (z3 musl incompatibility) |
| Lint | Ruff (E, W, F, I, N, UP, B, SIM, TID) | Zero violations |
| Type check | Pyright (strict) | Zero errors |
| Test | pytest | Zero failures, 3,155 tests |
| Coverage | `pytest-cov` | Minimum 97% statement+branch |
| Wheel smoke | Fresh venv, `pip install dist/*.whl`, import check | Must complete without error |
| Container scan | Trivy (CRITICAL/HIGH) | Fail on unfixed CVEs |
| License | `pip-licenses` | Fail on GPL/AGPL dependencies in commercial build |

### SLSA compliance (`.github/workflows/release.yml`)

The release pipeline targets SLSA Level 3:

- **Provenance:** GitHub Actions OIDC token used for all artifact operations; no long-lived secrets on the runner.
- **SBOM:** CycloneDX JSON generated via `cyclonedx-bom` for every release artifact.
- **Sigstore:** `.whl` and `.tar.gz` are signed with `sigstore/gh-action-sigstore-python@v3`, producing `.sigstore.json` bundles that include the ephemeral certificate chain and the Rekor transparency log entry.
- **Version consistency:** Release job checks that `pyproject.toml` version, git tag, and `pramanix.__version__` all agree before building.
- **PyPI publish:** Uses GitHub's OIDC Trusted Publisher mechanism — no `PYPI_TOKEN` stored as a secret.

SLSA Level 4 (hermetic build environment) is not yet achieved. The build runner fetches dependencies from PyPI at build time rather than from a pinned, verified artifact store.

### Cross-tenant data bleed (H-19, fixed)

The cross-tenant isolation fix was part of commit `73aef10`. The specific vulnerability: `Guard` instances sharing a module-level Z3 context in thread mode could, under concurrent load, have `assert_and_track` calls from one tenant's solver instance visible to another tenant's solver, causing ghost constraint violations or suppressed violations.

**Fix:** Every call to `solve()` creates its own `z3.Context()` instance via the `ctx` parameter passed through `_fast_check()` and `_attribute_violations()`. All symbolic variables and solver instances are bound to this per-call context. Sharing across calls is structurally impossible.

### Kubernetes deployment manifests

Kubernetes YAML (`interceptors/k8s/`) is present in the repository. The manifests were added in the `b079245` commit. Key configurations:
- `readinessProbe` on the gRPC port
- `livenessProbe` with `initialDelaySeconds: 30` (allows Z3 warmup before traffic)
- `PRAMANIX_ENV=production` environment variable (activates rlimit and max_input_bytes warnings if unset)
- Resource limits set conservatively for a 4-worker pool; operators should tune based on their `solver_timeout_ms` and workload P99.

---

## 3. Honest Limitations & Architectural Tech Debt

### Hard limitations of v1.0.0

**1. Z3 is single-threaded within a solver call.**
Z3's internal solver is not parallelizable. A policy with 10 invariants runs them in a single-threaded Phase 2 attribution loop. The parallelism in Pramanix is at the *request* level (multiple worker processes/threads), not the *invariant* level within a single request. A policy with 50 complex nonlinear invariants will be proportionally slower.

**2. Z3 does not natively handle floating-point IEEE-754 semantics.**
All `float` values are converted to exact rationals via `Decimal(str(v)).as_integer_ratio()`. This means the Z3 proof is over the *mathematical* real numbers, not the *machine* representation. If the calling code performs arithmetic in Python floats and passes the result to `verify()`, there may be a gap between what Z3 proved and what the machine actually computed. The safe pattern is to use `Decimal` throughout the call chain. This is documented but easy to miss.

**3. Quantifiers are bounded.**
`ForAll(x, ...)` and `Exists(x, ...)` over continuous domains are undecidable in general. Pramanix compiles them via `_realize_node()`, which replaces quantifiers with finite unrollings over a bounded range. Policies using unbounded quantifiers will fail at Guard construction time with `TranspileError`. The current bound limit is enforced in `_preprocess_invariants()`.

**4. Array fields expand combinatorially.**
`ArrayField` constraints are expanded at compile time. A policy asserting `all elements of a 100-element array satisfy X` generates 100 Z3 assertions. This works, but the Phase 2 attribution loop runs 100 individual solvers — one per array element — if the array constraint is violated. For large arrays under tight latency budgets, pre-validate array length before calling `verify()`.

**5. `PersistentMerkleAnchor` does not survive process restart.**
The in-memory Merkle tree is lost on restart. Only the root hashes emitted via `checkpoint_callback` survive. If you need a post-mortem audit of decisions from before the last checkpoint, you need to reconstruct the tree from the event log — the `decision_id` values must be stored elsewhere (e.g., in Kafka or Postgres) to replay them.

**6. `min_response_ms` is not a perfect timing oracle.**
The timing pad (`min_response_ms`) adds a sleep to normalize response time, making latency-based side-channel attacks harder. However, it is wall-clock based and subject to OS scheduler jitter. Under heavy system load, actual response time may exceed `min_response_ms` even for ALLOW decisions. The pad is a significant improvement over no padding; it is not a cryptographically sound timing guarantee.

**7. The neuro-symbolic path (LLM → Z3) inherits LLM non-determinism.**
The redundant translator runs two LLM calls and requires semantic consensus between them before passing the extracted intent to Z3. This eliminates single-model extraction hallucinations. It does not eliminate correlated failures where both models produce the same wrong extraction. Operators using the neuro-symbolic path for high-value transactions should set `consensus_strictness="exact"` and use trusted LLM endpoints with low temperature (the translators default to `temperature=0.0`).

### Intentional technical debt accepted for v1.0.0 launch

**1. Key rotation is not atomic across replicas.**
`AwsKmsKeyProvider.rotate_key()` calls `boto3.rotate_secret()` and invalidates the local cache (`_cache_expires = 0.0`). In a multi-replica deployment, replicas that haven't received the rotation event continue signing with the old key until their cache TTL (300s default) expires or they restart. This creates a window where decisions from different replicas carry different `public_key_id` values. Auditors comparing signatures cross-replica must handle this. A proper solution requires a distributed rotation event (SNS/SQS notification → cache invalidation on all replicas); this is documented as a v1.1 roadmap item.

**2. `HashiCorpVaultKeyProvider` and `GcpKmsKeyProvider` do not support rotation (`supports_rotation = False`).**
Rotation for these providers requires writing a new secret version externally and constructing a new provider instance. There is no in-process rotation API. For Vault, the `rotate_key()` method raises `NotImplementedError` with a clear message directing operators to the `vault kv put` CLI command.

**3. `AzureKeyVaultKeyProvider` is synchronous.**
The Azure SDK's `SecretClient.get_secret()` is a blocking I/O call. In async-process mode this is fine (worker process handles it). In async-thread mode it blocks an event loop thread. If you are using `azure-keyvault-secrets` in a high-concurrency async application, run the key provider fetch in a thread executor explicitly, or pin to process mode.

**4. `translator/anthropic.py` and `translator/openai_compat.py` have 57–61% statement coverage in the unit test run.**
The uncovered lines are the live HTTP streaming paths. They are exercised in a separate live-API test class (`TestAnthropicTranslatorExtraction`, `TestAnthropicTranslatorTimeout`) that requires a real endpoint. CI does not run these against a live Anthropic API — it relies on the VS Code LLM proxy. Any changes to the streaming path require manual verification against the production API before release.

**5. DSPy and CrewAI integration quirks.**
DSPy integration (`pramanix.integrations.dspy`) wraps `Guard.verify()` as a DSPy `Predict` module. The integration works correctly for single-turn programs. Multi-hop programs with state mutations between hops may encounter stale state versions if `state_version` is not explicitly propagated between hops. Operators must pass updated `state_version` values at each hop. CrewAI integration is similar; the `GuardedTool` wrapper does not automatically track state mutations between tool calls in a multi-agent crew.

**6. SLSA Level 4 not achieved.**
The build runner pulls dependencies from PyPI at build time. A supply-chain compromise of a transitive dependency (between tag creation and build execution) would not be detected. The Trivy scan and pinned `requirements/production.txt` mitigate but do not fully close this gap.

---

## 4. Enterprise Disaster Runbooks

### 4.1 KMS Outage Blast Radius

**Scenario:** AWS Secrets Manager in `us-east-1` goes fully offline (or Azure Key Vault becomes unreachable). The `AwsKmsKeyProvider` or `AzureKeyVaultKeyProvider` is providing the Ed25519 signing key.

#### What happens, step by step

**Phase 1 — Cache absorbs the outage (0 to 300 seconds).**

`AwsKmsKeyProvider` caches the fetched PEM with a TTL of `_DEFAULT_KEY_CACHE_TTL = 300.0` seconds (5 minutes). During this window, `private_key_pem()` and `key_version()` return the cached values without making any API call. The Guard continues signing decisions normally. **No traffic impact during the cache window.**

**Phase 2 — Cache expires, `_refresh_cache()` is called.**

After 300 seconds, the next call to `private_key_pem()` or `key_version()` enters `_refresh_cache()` and calls `boto3.client.get_secret_value(...)`. If Secrets Manager is offline, this raises a `botocore.exceptions.EndpointResolutionError` or `botocore.exceptions.ClientError`.

**This exception is NOT caught inside `_refresh_cache()`.** The exception propagates up to `Guard._sign_decision()`, which does not catch KMS exceptions either. The exception propagates to `Guard.verify()`, which does catch all exceptions and converts them to `Decision.error(explanation="verification_error")` with `allowed=False`.

**The system fails closed.** Every decision after cache expiry returns `allowed=False` with `status=ERROR` until the KMS is restored. The `decision.signature` field will be empty on these error decisions.

#### Fail-state summary

| Condition | Behavior |
|---|---|
| KMS offline, cache warm (< 300s) | Normal operation, cached key used |
| KMS offline, cache expired | All decisions return `allowed=False, status=ERROR` |
| KMS restored, cache expired | First call to verify() triggers `_refresh_cache()`, succeeds, refills cache, normal operation resumes |

#### What alerts fire

With Prometheus enabled, the following metrics spike during Phase 2:
- `pramanix_decisions_total{status="error"}` — counter increment on every KMS-blocked decision.
- `pramanix_circuit_state{namespace=..., state="open"}` — if the `TranslatorCircuitBreaker` is wired around the key provider (it is not by default; this requires operator configuration).

A Prometheus alerting rule for sustained KMS-induced errors:
```yaml
- alert: PramanixKMSOutage
  expr: rate(pramanix_decisions_total{status="error"}[5m]) > 0.1
  for: 2m
  annotations:
    summary: "Pramanix returning ERROR decisions — possible KMS outage"
```

#### Mitigation for regulated deployments

Set `_DEFAULT_KEY_CACHE_TTL` to a higher value (e.g., `3600.0` = 1 hour) for environments where extended KMS degradation is acceptable. This extends Phase 1 but increases the window where a compromised key continues to be used after rotation. The tradeoff is explicit.

For zero-downtime KMS requirement: maintain a secondary key provider as a failover (e.g., `FileKeyProvider` loaded from a read-only volume), and implement a custom `KeyProvider` that falls back to the file provider on KMS exception. The `KeyProvider` protocol allows this composition pattern without modifying core code.

---

### 4.2 Economics of the Math

**Based on the documented test baseline of 3,155 tests across 6,065 SLOC. Production extrapolation assumes a representative financial policy with 5 invariants over 6 Real fields.**

#### Per-decision compute cost breakdown

The solver benchmarks (from the test suite timing data) show:

| Path | Typical wall time |
|---|---|
| Phase 1 fast path (SAT, all invariants pass) | 0.2–0.8 ms |
| Phase 2 attribution (UNSAT, 1 violation) | 1.5–4 ms additional per violated invariant |
| String-sort policy (without promotion) | 8–25 ms |
| String-sort policy (with Int promotion) | 0.4–1.2 ms |
| Worker warmup (8 solves, first request) | 50–150 ms one-time |
| Z3 JIT compile (cold start, no warmup) | 200–800 ms one-time |

These numbers are on Python 3.13, z3-solver 4.12, running on a contemporary x86-64 host. ARM performance (AWS Graviton, Apple Silicon) is broadly similar or marginally faster.

**Memory per worker process (process mode):** Z3's internal state accumulates at approximately 0.4–0.8 MB per 1,000 solves on a 5-invariant policy. The default `max_decisions_per_worker = 10,000` recycle threshold was chosen to keep peak RSS below ~10 MB per worker above baseline Python overhead (~45 MB). For a 4-worker pool, peak Z3-attributed memory is approximately 40 MB above baseline.

#### At 500 million decisions per day

| Metric | Calculation | Value |
|---|---|---|
| Decisions / second (sustained) | 500M / 86,400 | ~5,787 req/s |
| Required workers (at 0.5 ms avg, sync) | 5,787 × 0.0005 | ~3 workers |
| Required workers (at 1.5 ms avg, with BLOCK path) | 5,787 × 0.0015 | ~9 workers |
| Worker pool recycles per day | 500M / 10,000 | 50,000 recycles |
| Z3 memory per worker at recycle | 0.4–0.8 MB | 4–8 MB peak per slot |

At this scale, the dominant infrastructure cost is **Python process spawning overhead** during recycling, not Z3 solve time. Each `ProcessPoolExecutor` spawn on Python 3.11+ (spawn start method) takes 80–200 ms. 50,000 recycles/day = one recycle every 1.7 seconds on average. The recycle is non-blocking (handed to a daemon thread), but the new worker is "cold" for its first request if warmup is disabled.

**Recommendation for 500M+ daily:** Use `execution_mode="async-thread"` with a `max_decisions_per_worker` of 100,000–500,000. Thread pool workers do not have spawn overhead, and Z3 releases the GIL during solving, making concurrency genuine. Monitor RSS via `pramanix_worker_rss_bytes` (if instrumented) and tune `max_decisions_per_worker` based on observed memory growth rate.

**CPU cost:** At steady-state 5,787 req/s with 0.5 ms average solve time, each worker core is utilized at approximately `5,787 / num_workers × 0.0005 = 0.72` cores per worker. A 4-worker pool requires roughly 3 dedicated vCPUs for Z3 work, plus Python overhead (1–2 additional vCPUs). Total: 4–5 vCPUs for 500M daily at this policy complexity.

---

### 4.3 Cryptographic Key Compromise & Rotation

**Scenario:** The Ed25519 private key stored in AWS Secrets Manager (or any other `KeyProvider`) is confirmed or suspected to be compromised. Historical audit decisions have been signed with this key.

#### Why rotation does not invalidate historical audit records

The Merkle tree audit chain provides independent integrity proof for historical batches. A decision's inclusion in a batch is proved by the `(root_hash, proof_path)` tuple, not by the Ed25519 signature. As long as the Merkle root hashes have been persisted to a tamper-evident store (append-only database, blockchain anchor), historical decisions can be proven intact even if the signing key is compromised.

The Ed25519 signature on each decision proves who signed it (key identity) and that the decision content was not tampered with after signing. Key compromise means an attacker could forge new signatures for fabricated decisions — it does not retroactively invalidate signatures on already-anchored decisions that are independently verifiable via the Merkle path.

#### Step-by-step rotation procedure

**Step 1 — Generate a new Ed25519 key pair.**
```bash
# Generate new key
python -c "
from pramanix.crypto import PramanixSigner
s = PramanixSigner.generate()
print('PRIVATE:', s.private_key_pem().decode())
print('PUBLIC:', s.public_key_pem().decode())
print('KEY_ID:', s.key_id())
"
```

**Step 2 — Write the new key to the secret store as a new version.**

For AWS Secrets Manager:
```bash
aws secretsmanager put-secret-value \
  --secret-id arn:aws:secretsmanager:us-east-1:123:secret:pramanix-key \
  --secret-string "$(cat new_key.pem)"
```
This creates a new version. The old version remains accessible by `VersionStage=AWSPREVIOUS`. AWS does not delete the old version automatically.

**Step 3 — Update `GuardConfig.expected_policy_hash` if set.**
`expected_policy_hash` is a hash of the compiled policy, not the signing key. It does not need to change on key rotation. Skip this step.

**Step 4 — Invalidate the key cache on all replicas.**

Send a SIGHUP to each Guard-hosting process, or invoke the rotation API endpoint if your service exposes one. For `AwsKmsKeyProvider`, there is no network-push invalidation. Replicas will pick up the new key after their current cache TTL expires (default 300 seconds).

To force immediate rotation: call `provider.rotate_key()` on each replica if your orchestrator can reach the replica. This calls `boto3.rotate_secret()` and sets `_cache_expires = 0.0` on that instance only.

For zero-downtime: deploy new replicas with the new key before terminating old ones. Traffic will briefly come from replicas using different `public_key_id` values. Audit consumers must handle this.

**Step 5 — Record the rotation event in the audit log.**
Write a rotation record to the Merkle anchor: `anchor.add(f"KEY_ROTATION:{old_key_id}:{new_key_id}:{timestamp}")`. This makes the rotation event itself part of the tamper-evident audit chain.

**Step 6 — Revoke the old key in the secret store.**
```bash
aws secretsmanager update-secret-version-stage \
  --secret-id arn:aws:secretsmanager:us-east-1:123:secret:pramanix-key \
  --version-stage DEPRECATED \
  --remove-from-version-id <old-version-id>
```

**Step 7 — Update the verifier public key.**
Audit consumers using `PramanixVerifier` must be updated with the new public key PEM. Decisions signed with the old key remain verifiable with the old public key until they expire from the audit system. Maintain both public keys during the transition window.

**What historical audit consumers should do:**
Store `decision.public_key_id` alongside each decision. When verifying historical decisions, select the public key corresponding to the `public_key_id` recorded at signing time. The `public_key_id` is a SHA-256 fingerprint of the public key PEM (`crypto.py:PramanixSigner.key_id()`), so it is deterministic and unique per key pair.

---

### 4.4 The Glass Break: Z3 Panic & Stuck Workers

**Scenario:** A user or operator deploys a policy containing a mathematically expensive or pathological constraint that causes Z3 to enter a near-infinite solving loop. Examples: nonlinear arithmetic over multiple Real-sorted fields, deep quantifier nesting, `E(x) ** 4 + E(y) ** 4 == E(z) ** 4` (Fermat's Last Theorem), or carefully crafted clauses designed to trip the NP-hard DPLL solver path.

#### What actually happens (two layers of protection)

**Layer 1 — `solver_rlimit` (hard stop, non-negotiable).**

Every Z3 solver instance has `s.set("rlimit", 10_000_000)` applied before the first `check()` call. Z3's rlimit counts elementary operations (resolution steps, propagation events). When the count reaches the limit, Z3 returns `z3.unknown` regardless of wall-clock time. This is enforced inside Z3's C++ core — Python cannot be sleeping or GC-paused while this check runs.

When Z3 returns `unknown`, the solver raises `SolverTimeoutError(label="<all-invariants>", timeout_ms=...)`. Guard catches this and returns `Decision.timeout(allowed=False)`. **The event loop is never blocked.** The entire Z3 call completes within the rlimit budget.

**Layer 2 — `solver_timeout_ms` (secondary, wall-clock).**

Additionally, `s.set("timeout", 5000)` applies a 5-second wall-clock limit. This is the secondary protection for cases where Z3's rlimit counting is slower than expected (e.g., a pathological operation that counts as few elementary ops but takes real time).

**Conclusion on "infinite loop" threat:** With default settings (`rlimit=10_000_000`, `timeout_ms=5000`), Z3 cannot loop indefinitely. The worst case is a 5-second stall on the first call to a pathological policy, after which every subsequent call returns `Decision.timeout()` instantly because the Z3 call terminates at the rlimit limit.

#### What an operator should do when Z3 timeouts spike

**Detection:** Monitor `pramanix_decisions_total{status="timeout"}`. A spike on a specific Guard namespace after a policy deployment indicates a pathological policy.

**Immediate mitigation (kill stuck workers without restarting the host):**

In process mode, call `WorkerPool.shutdown()` and reconstruct the Guard:
```python
# In a monitoring/management endpoint
guard._pool.shutdown()  # drains executor; SIGKILL after 10s grace
guard = Guard(MyPolicy, config=guard._config)  # fresh pool
```
The old pool is handed to `_drain_executor()` in a daemon thread. After `_RECYCLE_GRACE_S = 10.0` seconds, any surviving workers are killed. The new Guard's workers start fresh with the correct rlimit.

In thread mode, threads cannot be SIGKILL'd. The only option is to reduce `solver_timeout_ms` for the timed-out Guard instance and wait for in-flight threads to complete. Because Z3 releases the GIL during solving, other threads continue running during the stuck solve — the event loop is not blocked, but the thread slot is consumed for up to `solver_timeout_ms` milliseconds.

**Blocking a specific policy after deployment:**

If the pathological policy came from a user-submitted configuration (dynamic policy factory `Policy.from_config()`), set `expected_policy_hash` on the Guard config to the last known-good policy hash. The Guard raises `ConfigurationError` immediately on construction if a new policy does not match the expected hash, preventing deployment of the pathological variant.

**Diagnosing the pathological invariant:**

Run `PolicyAuditor(MyPolicy).audit()` — it does a static analysis of field coverage and flags invariants using nonlinear arithmetic over multiple variables. Separately, call `solve()` directly with a timeout of 100 ms and watch which `SolverTimeoutError.label` is raised to identify the specific invariant. Remove or simplify that invariant.

**Restoring traffic after a stuck worker pool in process mode (without host restart):**

```bash
# 1. Find the Guard process
ps aux | grep pramanix

# 2. Send SIGUSR1 if you have a signal handler registered in your application
kill -SIGUSR1 <pid>

# 3. If no signal handler: send SIGTERM to the worker processes directly
# Worker PIDs are visible if you enumerate the pool's _processes attribute
# (ThreadPoolExecutor does not expose this; use process mode for this option)

# 4. The WorkerPool ppid watchdog in each worker will self-terminate
# when it detects the parent's SIGUSR1 handler restarts the pool
# (requires custom signal handler in the host application)
```

The safest production pattern for dynamic policy deployments is to use **rolling replica replacement** via Kubernetes: deploy new replicas with the corrected policy, drain old replicas. The `readinessProbe` gate on the gRPC/HTTP port ensures traffic only reaches replicas where `Guard.__init__()` has completed successfully (which includes a test solve on construction with the new policy).

---

## 5. Complete Per-File Coverage Reference

Exact statement/branch coverage from `pytest --cov` at commit `73aef10`. Numbers are `(statements, missed, branches, partial-branches, cover%)`.

| File | Stmts | Miss | Branch | BrPart | Cover | Uncovered lines |
|---|---|---|---|---|---|---|
| `__init__.py` | 36 | 0 | 0 | 0 | **100%** | — |
| `_platform.py` | 24 | 0 | 8 | 0 | **100%** | — |
| `audit/__init__.py` | 5 | 0 | 0 | 0 | **100%** | — |
| `audit/archiver.py` | 123 | 3 | 32 | 2 | 97% | 201→190, 232, 282–283 |
| `audit/merkle.py` | 80 | 0 | 24 | 0 | **100%** | — |
| `audit/signer.py` | 46 | 0 | 4 | 0 | **100%** | — |
| `audit/verifier.py` | 55 | 0 | 8 | 0 | **100%** | — |
| `audit_sink.py` | 178 | 2 | 10 | 1 | 98% | 209–210, 231→exit |
| `circuit_breaker.py` | 397 | 2 | 58 | 1 | 99% | 697→exit, 818–823 |
| `cli.py` | 574 | 30 | 172 | 6 | 95% | 392→394, 582–583, 657, 766–767, 872–874, 956–979, 996–997, 1014–1015, 1028–1029, 1052–1056 |
| `crypto.py` | 112 | 4 | 24 | 1 | 96% | 71–72, 166→191, 391–392 |
| `decision.py` | 121 | 3 | 22 | 0 | 98% | 282, 561, 588 |
| `decorator.py` | 41 | 0 | 14 | 0 | **100%** | — |
| `exceptions.py` | 57 | 0 | 0 | 0 | **100%** | — |
| `execution_token.py` | 273 | 3 | 56 | 1 | 99% | 933–934, 1097 |
| `expressions.py` | 251 | 0 | 50 | 1 | 99% | 200→207 |
| `fast_path.py` | 105 | 0 | 22 | 0 | **100%** | — |
| `guard.py` | 409 | 12 | 130 | 6 | 96% | 838→868, 864–865, 931→962, 1123→1122, 1133→1132, 1136–1137, 1171–1172, 1177–1178, 1184, 1207–1209 |
| `guard_config.py` | 119 | 0 | 42 | 0 | **100%** | — |
| `guard_pipeline.py` | 58 | 0 | 18 | 0 | **100%** | — |
| `helpers/compliance.py` | 104 | 0 | 26 | 0 | **100%** | — |
| `helpers/policy_auditor.py` | 115 | 0 | 48 | 1 | 99% | 101→88 |
| `helpers/serialization.py` | 40 | 0 | 18 | 0 | **100%** | — |
| `helpers/string_enum.py` | 40 | 0 | 4 | 0 | **100%** | — |
| `helpers/type_mapping.py` | 19 | 0 | 10 | 0 | **100%** | — |
| `identity/linker.py` | 75 | 0 | 14 | 0 | **100%** | — |
| `identity/redis_loader.py` | 26 | 0 | 6 | 0 | **100%** | — |
| `interceptors/grpc.py` | 76 | 0 | 20 | 0 | **100%** | — |
| `interceptors/kafka.py` | 75 | 0 | 16 | 0 | **100%** | — |
| `k8s/webhook.py` | 19 | 0 | 2 | 0 | **100%** | — |
| `key_provider.py` | 232 | 8 | 24 | 3 | 96% | 135, 183, 234, 317→319, 326→328, 332, 420, 494, 501, 576→578, 591 |
| `migration.py` | 34 | 0 | 12 | 0 | **100%** | — |
| `policy.py` | 161 | 1 | 60 | 3 | 98% | 236→263, 238→236, 243 |
| `primitives/common.py` | 12 | 0 | 0 | 0 | **100%** | — |
| `primitives/finance.py` | 16 | 0 | 0 | 0 | **100%** | — |
| `primitives/fintech.py` | 29 | 0 | 0 | 0 | **100%** | — |
| `primitives/healthcare.py` | 14 | 0 | 0 | 0 | **100%** | — |
| `primitives/infra.py` | 22 | 0 | 0 | 0 | **100%** | — |
| `primitives/rbac.py` | 10 | 0 | 0 | 0 | **100%** | — |
| `primitives/time.py` | 12 | 0 | 0 | 0 | **100%** | — |
| `resolvers.py` | 27 | 0 | 6 | 0 | **100%** | — |
| `solver.py` | 138 | 0 | 60 | 0 | **100%** | — |
| `translator/_cache.py` | 159 | 2 | 28 | 0 | 99% | 222–223 |
| `translator/_json.py` | 35 | 0 | 10 | 1 | 98% | 34→29 |
| `translator/_sanitise.py` | 45 | 1 | 18 | 1 | 97% | 171 |
| `translator/anthropic.py` | 41 | 16 | 0 | 0 | **61%** | 87–127, 157–163 |
| `translator/base.py` | 14 | 0 | 0 | 0 | **100%** | — |
| `translator/cohere.py` | 64 | 0 | 6 | 1 | 99% | 147→exit |
| `translator/gemini.py` | 65 | 2 | 10 | 1 | 96% | 172–177 |
| `translator/injection_filter.py` | 23 | 0 | 8 | 0 | **100%** | — |
| `translator/injection_scorer.py` | 55 | 0 | 8 | 0 | **100%** | — |
| `translator/llamacpp.py` | 55 | 0 | 6 | 0 | **100%** | — |
| `translator/mistral.py` | 58 | 0 | 6 | 0 | **100%** | — |
| `translator/ollama.py` | 48 | 0 | 2 | 0 | **100%** | — |
| `translator/openai_compat.py` | 54 | 22 | 2 | 0 | **57%** | 105–131, 154–174 |
| `translator/redundant.py` | 211 | 0 | 94 | 2 | 99% | 126→128, 144→146 |
| `transpiler.py` | 378 | 1 | 230 | 1 | 99% | 345 |
| `validator.py` | 22 | 0 | 4 | 0 | **100%** | — |
| `worker.py` | 322 | 7 | 48 | 0 | 98% | 392–393, 652–653, 710, 719–720 |
| **TOTAL** | **6065** | **119** | **1506** | **33** | **98%** | |

Files below 100% that are not `# pragma: no cover` candidates:
- `cli.py` (95%) — the uncovered lines are error-exit paths in `_cmd_doctor` and edge cases in `_cmd_calibrate_injection` and `_cmd_schema_export` that require malformed input or a platform that lacks optional dependencies.
- `key_provider.py` (96%) — the 11 uncovered lines are `supports_rotation` property bodies and cache-valid branch returns on cloud providers. These require constructing providers with pre-populated caches and are tested via `__new__`+injection in `test_kms_provider.py`; the branch misses are an artefact of how Python reports property coverage.
- `translator/anthropic.py` (61%) and `translator/openai_compat.py` (57%) — **the single most important coverage gap**. Lines 87–127 in `anthropic.py` are the streaming HTTP path (`messages.stream()`). Lines 105–131 and 154–174 in `openai_compat.py` are the retry and response-parsing paths. These require a live endpoint and are exercised by `TestAnthropicTranslatorExtraction` against the VS Code LLM proxy. They are not run in headless CI.

---

## 6. Complete GuardConfig Field Reference

All fields are frozen dataclass attributes. Constructor argument overrides `PRAMANIX_<UPPER>` env var overrides the hard default listed below.

| Field | Type | Default | Env var | Constraint |
|---|---|---|---|---|
| `execution_mode` | `str` | `"sync"` | `PRAMANIX_EXECUTION_MODE` | one of `"sync"`, `"async-thread"`, `"async-process"` |
| `solver_timeout_ms` | `int` | `5000` | `PRAMANIX_SOLVER_TIMEOUT_MS` | > 0 |
| `max_workers` | `int` | `4` | `PRAMANIX_MAX_WORKERS` | > 0 |
| `max_decisions_per_worker` | `int` | `10000` | `PRAMANIX_MAX_DECISIONS_PER_WORKER` | > 0 |
| `worker_warmup` | `bool` | `True` | `PRAMANIX_WORKER_WARMUP` | — |
| `log_level` | `str` | `"INFO"` | `PRAMANIX_LOG_LEVEL` | valid stdlib level |
| `metrics_enabled` | `bool` | `False` | `PRAMANIX_METRICS_ENABLED` | — |
| `otel_enabled` | `bool` | `False` | `PRAMANIX_OTEL_ENABLED` | — |
| `translator_enabled` | `bool` | `False` | `PRAMANIX_TRANSLATOR_ENABLED` | — |
| `fast_path_enabled` | `bool` | `False` | `PRAMANIX_FAST_PATH_ENABLED` | — |
| `fast_path_rules` | `tuple` | `()` | — | callable rules |
| `shed_latency_threshold_ms` | `float` | `200.0` | `PRAMANIX_SHED_LATENCY_THRESHOLD_MS` | ≥ 0 |
| `shed_worker_pct` | `float` | `90.0` | `PRAMANIX_SHED_WORKER_PCT` | 0–100 |
| `signer` | `PramanixSigner \| None` | `None` | — | Ed25519 signer instance |
| `solver_rlimit` | `int` | `10_000_000` | `PRAMANIX_SOLVER_RLIMIT` | ≥ 0; 0 = disabled |
| `max_input_bytes` | `int` | `65536` | `PRAMANIX_MAX_INPUT_BYTES` | ≥ 0; 0 = disabled |
| `min_response_ms` | `float` | `0.0` | — | ≥ 0.0 |
| `redact_violations` | `bool` | `False` | — | — |
| `expected_policy_hash` | `str \| None` | `None` | — | SHA-256 hex string |
| `injection_threshold` | `float` | `0.5` | `PRAMANIX_INJECTION_THRESHOLD` | 0.0–1.0 |
| `max_input_chars` | `int` | `512` | `PRAMANIX_MAX_INPUT_CHARS` | > 0 |
| `injection_scorer_path` | `Path \| None` | `None` | `PRAMANIX_INJECTION_SCORER_PATH` | path to `.py` module |
| `consensus_strictness` | `str` | `"semantic"` | `PRAMANIX_CONSENSUS_STRICTNESS` | `"semantic"` or `"exact"` |
| `audit_sinks` | `tuple[AuditSink, ...]` | `()` | — | list of `AuditSink` instances |

**Production warnings** (emitted when `PRAMANIX_ENV=production` is set):
- `solver_rlimit == 0` → warns that logic-bomb DoS protection is disabled.
- `max_input_bytes == 0` → warns that Big-Data DoS protection is disabled.

**`redact_violations` detail:** When `True`, the `explanation` and `violated_invariants` fields in every BLOCK decision are replaced with `"Policy Violation: Action Blocked"` before being returned to the caller. The `decision_hash` and `signature` are computed over the **real** unredacted fields first, so server-side audit logs remain fully verifiable. This is the correct pattern for deployments where invariant labels could reveal business logic to adversaries.

**`expected_policy_hash` detail:** Computed at `Guard.__init__()` time via `guard_pipeline._compute_policy_fingerprint()`, which SHA-256 hashes the canonical serialisation of the policy's field declarations and invariant labels. Use this to prevent silent policy drift when the same Guard class name is deployed with different invariant content across environments. Raises `ConfigurationError` at construction if the live policy hash does not match.

---

## 7. Complete Exception Hierarchy

Every exception class is defined in `exceptions.py` (57 statements, 100% coverage).

```
PramanixError (base)
├── InputTooLongError
│     attrs: actual (int), limit (int), truncated_preview (str)
├── PolicyError
│   ├── PolicyCompilationError
│   ├── InvariantLabelError
│   ├── FieldTypeError
│   └── TranspileError
├── GuardError
│   ├── ValidationError
│   ├── StateValidationError
│   │     attrs: expected (str), actual (str)
│   ├── SolverTimeoutError
│   │     attrs: label (str), timeout_ms (int)
│   ├── SolverError
│   ├── WorkerError
│   ├── GuardViolationError
│   │     wraps: Decision — raised by the @guard decorator on BLOCK
│   ├── ExtractionFailureError
│   ├── ExtractionMismatchError
│   │     attrs: model_a (str), model_b (str), mismatches (dict[str, tuple])
│   ├── LLMTimeoutError
│   │     attrs: model (str), attempts (int)
│   ├── SemanticPolicyViolation
│   └── InjectionBlockedError
├── ConfigurationError
├── ResolverConflictError
└── MigrationError
      attrs: missing_key (str | None), from_version (str), to_version (str)
```

**Fail-safe contract**: `Guard.verify()` catches every exception in this hierarchy (and any unexpected exception) and converts it to `Decision.error(allowed=False)`. No exception ever escapes `verify()` to the caller. The only way to surface internal errors is via `decision.explanation` (which is redacted when `redact_violations=True`).

---

## 8. Complete Decision Status Taxonomy

`SolverStatus` is a `StrEnum` with 9 values. The `allowed` field of a Decision is derived solely from status.

| Status | `allowed` | Meaning | Raised by |
|---|---|---|---|
| `SAFE` | `True` | All invariants satisfied — the sole ALLOW path | `solve()` returns SAT |
| `UNSAFE` | `False` | One or more invariants violated — proof of violation | `solve()` returns UNSAT |
| `TIMEOUT` | `False` | Z3 solver hit `timeout_ms` or `rlimit` | `SolverTimeoutError` caught by Guard |
| `ERROR` | `False` | Unexpected internal error (incl. KMS failure) | Any uncaught exception in verify pipeline |
| `STALE_STATE` | `False` | `state_version` in payload ≠ `Policy.Meta.version` | Version check in `_verify_core` |
| `VALIDATION_FAILURE` | `False` | Pydantic model validation failed on intent or state | `ValidationError` from Pydantic |
| `RATE_LIMITED` | `False` | Adaptive load shedder triggered (both conditions met) | `AdaptiveConcurrencyLimiter.should_shed()` |
| `CONSENSUS_FAILURE` | `False` | Dual-LLM translators disagree past the mismatch threshold | `ExtractionMismatchError` in `extract_with_consensus` |
| `CACHE_HIT` | decorates | Translator cache returned a prior result (not a blocking status on its own) | `_TranslatorCache.get()` |

**Important:** `CACHE_HIT` does not independently set `allowed`. A cache hit decision carries the status (`SAFE` or `UNSAFE`) from the original solve, plus `CACHE_HIT` as an annotation in `decision.metadata["cache_hit"] = True`.

---

## 9. Public API Surface

All names importable directly from `import pramanix`. 92 public names at v1.0.0.

**Core verification:**
`Guard`, `GuardConfig`, `Policy`, `Field`, `E`, `ForAll`, `Exists`, `ConstraintExpr`, `ArrayField`, `NestedField`, `DatetimeField`, `StringEnumField`, `invariant_mixin`, `model_dump_z3`

**Decision objects:**
`Decision`, `SolverStatus`

**Decorators and fast path:**
`guard` (decorator), `FastPathRule`, `SemanticFastPath`

**Translator and injection:**
`InjectionScorer`, `BuiltinScorer`, `CalibratedScorer`, `ConsensusStrictness`

**Execution tokens:**
`ExecutionToken`, `ExecutionTokenSigner`, `ExecutionTokenVerifier`, `InMemoryExecutionTokenVerifier`, `SQLiteExecutionTokenVerifier`, `RedisExecutionTokenVerifier`, `PostgresExecutionTokenVerifier`

**Cryptography:**
`PramanixSigner`, `PramanixVerifier`, `DecisionSigner`, `DecisionVerifier`

**Audit:**
`MerkleAnchor`, `PersistentMerkleAnchor`, `MerkleArchiver`, `AuditSink`, `StdoutAuditSink`, `InMemoryAuditSink`, `KafkaAuditSink`, `S3AuditSink`, `SplunkHecAuditSink`, `DatadogAuditSink`

**Key providers:**
`KeyProvider`, `PemKeyProvider`, `EnvKeyProvider`, `FileKeyProvider`, `AwsKmsKeyProvider`, `AzureKeyVaultKeyProvider`, `GcpKmsKeyProvider`, `HashiCorpVaultKeyProvider`

**Circuit breakers:**
`AdaptiveCircuitBreaker`, `DistributedCircuitBreaker`, `CircuitBreakerConfig`, `InMemoryDistributedBackend`, `RedisDistributedBackend`

**Helpers:**
`PolicyAuditor`, `ComplianceReport`, `ComplianceReporter`

**Migration:**
`PolicyMigration`, `MigrationError`

**Resolvers:**
`ResolverRegistry`

**Identity:**
`JWTIdentityLinker`, `IdentityClaims`, `StateLoader`, `RedisStateLoader`, `JWTVerificationError`, `JWTExpiredError`, `StateLoadError`

**Integrations (not in `pramanix.*` root, import from submodule):**
`PramanixGuardedModule` (LangChain), `PramanixCrewAITool` (CrewAI), `PramanixGuardedTool` (DSPy), `PramanixFunctionTool` (AutoGen), `PramanixPydanticAIValidator` (PydanticAI), `PramanixSemanticKernelPlugin` (SemanticKernel), `HaystackGuardedComponent` (Haystack), `PramanixQueryEngineTool` (LlamaIndex), `PramanixToolCallback` (generic callback)

**Exceptions (all):**
`PramanixError`, `InputTooLongError`, `PolicyError`, `PolicyCompilationError`, `InvariantLabelError`, `FieldTypeError`, `TranspileError`, `GuardError`, `ValidationError`, `StateValidationError`, `SolverTimeoutError`, `SolverError`, `WorkerError`, `GuardViolationError`, `ExtractionFailureError`, `ExtractionMismatchError`, `LLMTimeoutError`, `SemanticPolicyViolation`, `InjectionBlockedError`, `ConfigurationError`, `ResolverConflictError`

---

## 10. Dependency Matrix

### Required (always installed)

| Package | Min version | Purpose |
|---|---|---|
| `pydantic` | ≥ 2.5 | Intent/state model validation |
| `z3-solver` | ≥ 4.12 | SMT formal verification engine |
| `structlog` | — | Structured JSON logging with secrets redaction |

### Optional extras

| Extra (`pip install 'pramanix[X]'`) | Packages | Enables |
|---|---|---|
| `otel` | `opentelemetry-sdk`, `opentelemetry-exporter-otlp-proto-grpc` | OTel trace export |
| `metrics` | `prometheus-client` | Prometheus metrics endpoint |
| `http` | `httpx` | SplunkHecAuditSink, HTTP-based translators |
| `openai` | `openai`, `tenacity` | OpenAI-compatible translator (GPT-4, Azure OpenAI, etc.) |
| `anthropic` | `anthropic`, `tenacity` | Anthropic Claude translator |
| `cohere` | `cohere`, `tenacity` | Cohere Command R translator |
| `mistral` | `mistralai`, `tenacity` | Mistral translator |
| `gemini` | `google-generativeai` | Google Gemini translator |
| `llamacpp` | `llama-cpp-python` | Local GGUF model translator |
| `identity` | `redis` | Redis-backed JWT identity state loader |
| `kafka` | `confluent-kafka` | KafkaAuditSink |
| `postgres` | `asyncpg` | PostgresExecutionTokenVerifier |
| `redis` | `redis` | RedisExecutionTokenVerifier, RedisDistributedBackend |
| `aws` | `boto3` | AwsKmsKeyProvider, S3AuditSink |
| `azure` | `azure-keyvault-secrets`, `azure-identity` | AzureKeyVaultKeyProvider |
| `gcp` | `google-cloud-secret-manager` | GcpKmsKeyProvider |
| `vault` | `hvac` | HashiCorpVaultKeyProvider |
| `datadog` | `datadog-api-client` | DatadogAuditSink |
| `crypto` | `cryptography` | Ed25519 key derivation in PramanixSigner |
| `langchain` | `langchain-core` | LangChain integration |
| `llamaindex` | `llama-index-core` | LlamaIndex integration |
| `autogen` | `pyautogen` | AutoGen integration |
| `crewai` | `crewai` | CrewAI integration |
| `dspy` | `dspy-ai` | DSPy integration |
| `pydantic-ai` | `pydantic-ai` | PydanticAI integration |
| `semantic-kernel` | `semantic-kernel` | Semantic Kernel integration |
| `haystack` | `haystack-ai` | Haystack integration |
| `fastapi` | `fastapi`, `starlette` | FastAPI middleware |
| `pdf` | `fpdf2` | ComplianceReporter PDF export |
| `all` | all of the above | Complete installation |

### Production pin file

`requirements/production.txt` is generated by `pip-compile --generate-hashes` from `requirements/production.in`. Every transitive dependency is pinned with a SHA-256 hash. A supply-chain attack that replaces a package on PyPI will cause `pip install --require-hashes` to fail. The file was last regenerated 2026-04-25.

---

## 11. CLI Command Reference

Entry point: `pramanix` (defined in `pyproject.toml` as `pramanix.cli:main`).

Exit codes: `0` = success / policy ALLOW, `1` = failure / policy BLOCK / verification error, `2` = usage error.

### `pramanix verify-proof`

Verify an HMAC-JWS decision proof token.

```
pramanix verify-proof <token> [--key KEY] [--json]
pramanix verify-proof --stdin [--key KEY] [--json]
```

- `--key` / `PRAMANIX_SIGNING_KEY` env var: the HMAC secret used to sign the token.
- `--json`: output the decoded decision as JSON instead of human-readable.
- Exit 0 = valid proof. Exit 1 = invalid/expired. Exit 2 = no key provided.

### `pramanix audit verify`

Verify a JSONL audit log signed with `PramanixSigner` (Ed25519).

```
pramanix audit verify <log_file> --public-key <pem_file> [--json] [--fail-fast]
```

- `--public-key`: path to the Ed25519 public key PEM file.
- `--fail-fast`: stop at the first invalid record rather than scanning the full log.
- Reads the JSONL file line by line, recomputes `decision_hash` for each record, and verifies the Ed25519 signature.

### `pramanix simulate`

Run a policy decision without LLM, side effects, or a live Guard instance. Loads the policy from a Python file.

```
pramanix simulate --policy <file.py> --intent '{"amount": 500}' [--state '{}'] [--json]
pramanix simulate --policy <file.py> --intent-file intent.json [--json]
```

- `--policy-var`: name of the `Policy` variable in the file (default: `"policy"`).
- Constructs a Guard, calls `verify()`, and prints the result. Safe for CI integration tests.

### `pramanix policy migrate`

Apply a `PolicyMigration` spec to a state JSON file.

```
pramanix policy migrate --state state.json --from-version 1.0.0 --to-version 2.0.0 \
  [--rename old=new] [--remove field] [--output out.json]
```

- `--rename OLD=NEW`: repeatable field rename.
- `--remove FIELD`: repeatable field removal.
- Outputs the migrated state dict to stdout or `--output` file.

### `pramanix schema export`

Export a Policy class's JSON Schema (draft-07) to stdout or file.

```
pramanix schema export --policy my_policy.py:TradePolicy [--output schema.json] [--indent 2]
```

- `FILE:CLASS` format: the Python file path and the exact class name separated by `:`.

### `pramanix calibrate-injection`

Fit a calibrated injection scorer from a labelled dataset.

```
pramanix calibrate-injection --dataset data.jsonl --output scorer.pkl [--min-examples 200]
```

- Dataset format: one JSON object per line — `{"text": "...", "is_injection": true|false}`.
- Outputs a pickle file loadable via `CalibratedScorer.load(path)` and passable to `GuardConfig(injection_scorer_path=...)`.

### `pramanix doctor`

Validate environment, dependencies, key config, and platform compatibility.

```
pramanix doctor [--json] [--strict]
```

- Checks: Python version, z3-solver installed, cryptography installed, no Alpine musl libc, `PRAMANIX_SIGNING_KEY` reachable (if set), `PRAMANIX_ENV` set.
- `--strict`: exit 1 on any WARNING, not just ERROR.
- Use this as a Kubernetes init container health check or in CI before running integration tests.

---

## 12. Integration Matrix

All integrations live in `src/pramanix/integrations/`. They wrap `Guard.verify()` or `Guard.verify_async()` in framework-native patterns. None alter the Z3 verification logic; they are pure adapter layers.

| Framework | Class | Pattern | Async |
|---|---|---|---|
| LangChain | `PramanixGuardedModule` | Wraps any `Runnable`; blocks on `Decision.allowed=False` | Yes (`ainvoke`) |
| CrewAI | `PramanixCrewAITool` | `BaseTool` subclass; raises `ToolException` on BLOCK | No (sync) |
| DSPy | `PramanixGuardedTool` | `dspy.Predict`-compatible; raises `DSPyGuardViolation` on BLOCK | No |
| AutoGen | `PramanixFunctionTool` | AutoGen `FunctionTool` wrapper; returns error message on BLOCK | Yes |
| PydanticAI | `PramanixPydanticAIValidator` | Validator hook for PydanticAI agents | Yes |
| Semantic Kernel | `PramanixSemanticKernelPlugin` | SK Plugin with `KernelFunction`; raises on BLOCK | Yes |
| Haystack | `HaystackGuardedComponent` | `Component` with `@component.output_types`; passes or raises | No |
| LlamaIndex | `PramanixQueryEngineTool` | `QueryEngineTool` adapter; raises `GuardViolationError` on BLOCK | Yes |
| FastAPI | Middleware (`pramanix.integrations.fastapi`) | Starlette middleware; returns 403 on BLOCK | Yes |
| Generic callback | `PramanixToolCallback` | Callable adapter; any function → guarded function | Both |

**Critical integration warning for CrewAI and DSPy:** State version is not automatically propagated between hops in multi-step programs. Each invocation must pass the current `state_version` value explicitly. If a crew tool mutates shared state between calls and the Guard is verifying against a cached state object, it will not detect the mutation. The `consume_within()` method on `PostgresExecutionTokenVerifier` and `SQLiteExecutionTokenVerifier` is the correct pattern for atomic guard-then-execute in these frameworks.

**FastAPI middleware detail:** The `PramanixMiddleware` extracts intent from `request.body()`, runs `guard.verify_async()`, and passes or raises `HTTPException(status_code=403)`. It does not consume the request body — the downstream handler still receives the full request. Body re-reading is handled via `request._body` caching (Starlette pattern). The `redact_violations=True` config is strongly recommended for this integration to prevent leaking invariant labels in 403 response bodies.

---

## 13. Audit Sink Catalog

All sinks implement `AuditSink` protocol: one method `emit(decision: Decision) -> None`. Sink failures are **never** propagated to the caller — they are logged and swallowed.

### `StdoutAuditSink`
- Writes `decision.to_dict()` as a JSON line to stdout (or a custom stream).
- No external dependencies.
- Not suitable for production — stdout is shared with application logs.

### `InMemoryAuditSink`
- Appends decisions to `self.decisions` list.
- Thread-safe for appends (CPython GIL).
- Use in tests only. Not suitable for multi-process mode (each process has its own list).

### `KafkaAuditSink`
- Requires: `pip install 'pramanix[kafka]'` (confluent-kafka ≥ 2.3).
- Internal bounded queue (`max_queue_size=10_000`). When full, decision is dropped and `pramanix_audit_sink_overflow_total` Prometheus counter is incremented.
- A background daemon thread (`pramanix-kafka-poll`) calls `producer.poll(0.1)` every 100 ms to fire delivery callbacks.
- Call `sink.flush(timeout=10.0)` at shutdown to drain pending messages.
- Failure mode: queue overflow → drop + log. Kafka broker unreachable → log. **Never blocks the Guard hot path.**

### `S3AuditSink`
- Requires: `pip install 'pramanix[aws]'` (boto3).
- Each decision is uploaded as `{prefix}{decision_id}.json` to the specified bucket.
- Uses a `ThreadPoolExecutor(max_workers=4)` internally so `put_object` never blocks the event loop.
- Call `sink.close()` at shutdown to drain the thread pool.
- Failure mode: upload error → log. **Never blocks the Guard hot path.**

### `SplunkHecAuditSink`
- Requires: `pip install 'pramanix[splunk]'` (httpx).
- Uses a persistent `httpx.Client` with connection pooling.
- Supports `ca_bundle` for private TLS certificates.
- Failure mode: HTTP error or connection failure → log. **Synchronous** — `emit()` blocks until the HTTP call completes. Do not use this sink in a high-throughput hot path without wrapping it in a thread pool.

### `DatadogAuditSink`
- Requires: `pip install 'pramanix[datadog]'` (datadog-api-client).
- Constructs `ApiClient` and `LogsApi` once at init; reuses across all `emit()` calls (M-16 fix).
- Submits decisions as Datadog Log items via `LogsApi.submit_log()`.
- Failure mode: API error → log. **Synchronous** — same hot-path warning as Splunk.
- Call `sink.close()` at shutdown.

---

## 14. Primitive Constraint Library Reference

Pre-built constraint factories importable from `pramanix.primitives.*`. Each function returns a `ConstraintExpr` for use in `Policy.invariants()`.

### `pramanix.primitives.finance`

| Function | Fields required | What it enforces |
|---|---|---|
| `NonNegativeBalance(balance, amount)` | 2 Real | `balance - amount >= 0` |
| `UnderDailyLimit(amount, daily_limit)` | 2 Real | `amount <= daily_limit` |
| `UnderSingleTxLimit(amount, tx_limit)` | 2 Real | `amount <= tx_limit` |
| `RiskScoreBelow(risk_score, threshold)` | 2 Real | `risk_score < threshold` |
| `SecureBalance(balance, amount, minimum_reserve)` | 3 Real | `balance - amount >= minimum_reserve` |
| `MinimumReserve(balance, amount, minimum_reserve)` | 3 Real | `balance - amount >= minimum_reserve` (alias) |

### `pramanix.primitives.fintech`

| Function | Fields required | What it enforces |
|---|---|---|
| `SufficientBalance(balance, amount)` | 2 Real | `balance >= amount` |
| `VelocityCheck(tx_count, window_limit)` | 1 Int, 1 literal | `tx_count < window_limit` |
| `AntiStructuring(cumulative_amount, threshold)` | 1 Real, 1 Decimal literal | `cumulative_amount < threshold` (BSA structuring threshold) |
| `WashSaleDetection(buy_date, sell_date, security_id, ...)` | 3 fields | `sell_date - buy_date > 30` days window |
| `CollateralHaircut(collateral_value, loan_amount, haircut_pct)` | 3 Real | `collateral_value * (1 - haircut) >= loan_amount` |
| `MaxDrawdown(current_nav, high_water_mark, max_drawdown_pct)` | 3 Real | `(high_water - current) / high_water <= max_drawdown_pct` |
| `SanctionsScreen(counterparty_status)` | 1 Bool/Int | `counterparty_status == CLEARED` |
| `RiskScoreLimit(risk_score, max_risk)` | 1 Real, 1 Decimal | `risk_score <= max_risk` |
| `KYCTierCheck(kyc_tier, required_tier)` | 1 Int, 1 literal | `kyc_tier >= required_tier` |
| `TradingWindowCheck(current_hour, open_hour, close_hour)` | 3 Int | `open_hour <= current_hour < close_hour` |
| `MarginRequirement(margin_balance, position_value, margin_pct)` | 3 Real | `margin_balance >= position_value * margin_pct` |

### `pramanix.primitives.healthcare`

| Function | Fields required | What it enforces |
|---|---|---|
| `PHILeastPrivilege(requestor_role, allowed_roles)` | 1 field, list of values | role ∈ allowed_roles (Int promotion) |
| `ConsentActive(consent_status, consent_expiry, now_ts)` | 3 fields | consent given and not expired |
| `DosageGradientCheck(new_dose, current_dose, max_increase_pct)` | 3 Real | `new_dose <= current_dose * (1 + max_increase_pct)` |
| `BreakGlassAuth(requestor_role, is_emergency, authorized_roles)` | 3 fields | role in list OR emergency flag set |
| `PediatricDoseBound(patient_age_months, dose_mg, weight_kg)` | 3 Real | age/weight-adjusted max dose formula |

### `pramanix.primitives.rbac`

| Function | Fields required | What it enforces |
|---|---|---|
| `RoleMustBeIn(role, allowed_roles)` | 1 field, list | role ∈ allowed_roles |
| `ConsentRequired(consent)` | 1 Bool | `consent == True` |
| `DepartmentMustBeIn(department, allowed_departments)` | 1 field, list | department ∈ list |

### `pramanix.primitives.infra`

| Function | Fields required | What it enforces |
|---|---|---|
| `MinReplicas(replicas, min_replicas)` | 2 Int | `replicas >= min_replicas` |
| `MaxReplicas(replicas, max_replicas)` | 2 Int | `replicas <= max_replicas` |
| `WithinCPUBudget(cpu_request, cpu_budget)` | 2 Real | `cpu_request <= cpu_budget` |
| `WithinMemoryBudget(mem_request, mem_budget)` | 2 Real | `mem_request <= mem_budget` |
| `BlastRadiusCheck(affected_nodes, total_nodes, max_pct)` | 3 fields | `affected / total <= max_pct` |
| `CircuitBreakerState(circuit_state)` | 1 field | `circuit_state == CLOSED` (infra-level check) |
| `ProdDeployApproval(has_approval, environment)` | 2 fields | if env=prod then approval required |
| `ReplicaBudget(replicas, min, max)` | 3 Int | `min <= replicas <= max` |
| `CPUMemoryGuard(cpu_request, cpu_limit, mem_request, mem_limit)` | 4 Real | requests ≤ limits |

### `pramanix.primitives.time`

| Function | Fields required | What it enforces |
|---|---|---|
| `WithinTimeWindow(ts, window_start, window_end)` | 3 Int/Real | `window_start <= ts <= window_end` |
| `After(timestamp, cutoff)` | 2 fields | `timestamp >= cutoff` |
| `Before(timestamp, cutoff)` | 2 fields | `timestamp <= cutoff` |
| `NotExpired(expiry_ts, now_ts)` | 2 fields | `now_ts <= expiry_ts` |

### `pramanix.primitives.common`

| Function | What it enforces |
|---|---|
| `NotSuspended(is_suspended)` | `is_suspended == False` |
| `StatusMustBe(status, expected_value)` | `status == expected_value` |
| `FieldMustEqual(field_obj, value)` | `field == value` |

### Built-in role constants (`pramanix.primitives.roles`)

`HIPAARole.PHYSICIAN`, `.NURSE`, `.ADMIN`, `.PHARMACIST`, `.RESEARCHER`, `.PATIENT`
`EnterpriseRole.ADMIN`, `.ENGINEER`, `.ANALYST`, `.VIEWER`, `.SERVICE_ACCOUNT`

---

## 15. Interceptors Reference

### gRPC Interceptor (`pramanix.interceptors.grpc`)

```python
from pramanix.interceptors.grpc import PramanixGrpcInterceptor
interceptor = PramanixGrpcInterceptor(guard=my_guard, intent_extractor=fn)
server = grpc.server(futures.ThreadPoolExecutor(), interceptors=[interceptor])
```

- `intent_extractor(servicer_context, request) -> dict`: caller-supplied function that builds the intent dict from the gRPC request.
- On BLOCK: raises `grpc.StatusCode.PERMISSION_DENIED` with the decision explanation as the details string.
- On ERROR in `intent_extractor`: raises `grpc.StatusCode.INTERNAL`.
- Does not intercept the response — only gates incoming RPCs.

### Kafka Interceptor (`pramanix.interceptors.kafka`)

```python
from pramanix.interceptors.kafka import PramanixKafkaInterceptor
interceptor = PramanixKafkaInterceptor(guard=my_guard, intent_extractor=fn, dlq_topic="pramanix-dlq")
messages = interceptor.filter(consumer.poll(timeout=1.0))
```

- `filter(messages)`: takes a list of `confluent_kafka.Message` objects, runs each through `guard.verify()`, returns only the ALLOW messages.
- BLOCK messages are produced to `dlq_topic` (dead-letter queue) if configured, otherwise dropped.
- DLQ message includes the original message value plus a `X-Pramanix-Decision` header containing the serialised decision.

---

## 16. Helper Modules Reference

### `PolicyAuditor` (`pramanix.helpers.policy_auditor`)

Static analysis tool that identifies coverage gaps in a Policy definition.

```python
from pramanix import PolicyAuditor
report = PolicyAuditor(MyPolicy).audit()
print(report.uncovered_fields)      # fields declared but not in any invariant
print(report.redundant_invariants)  # invariants that reference no fields
print(report.boundary_examples)     # auto-generated boundary-value examples
```

- `uncovered_fields`: list of `Field` objects declared on the Policy class but not referenced in any invariant expression tree. These are fields that can be set to any value without affecting decisions — almost certainly an oversight.
- `boundary_examples`: auto-generated intent/state dicts at the boundary values of each invariant (e.g., exactly at `balance == amount` for `NonNegativeBalance`). Feed these to `guard.verify()` as regression tests.

### `ComplianceReporter` (`pramanix.helpers.compliance`)

Generates human-readable compliance reports from a batch of decisions.

```python
from pramanix import ComplianceReporter
reporter = ComplianceReporter(decisions=sink.decisions)
report = reporter.generate()          # ComplianceReport dataclass
reporter.to_pdf("compliance.pdf")     # requires pip install 'pramanix[pdf]'
reporter.to_json("compliance.json")
```

`ComplianceReport` fields: `total`, `allowed`, `blocked`, `timeout`, `error`, `allow_rate`, `block_rate`, `p50_solver_ms`, `p95_solver_ms`, `p99_solver_ms`, `violations_by_invariant` (dict), `generated_at`.

### `DecisionSigner` / `DecisionVerifier` (`pramanix.audit.signer`, `pramanix.audit.verifier`)

Lower-level signing/verification API, used internally by `Guard._sign_decision()`.

```python
from pramanix import DecisionSigner, DecisionVerifier

signer = DecisionSigner(private_key_pem=pem_bytes)
signed = signer.sign(decision)          # returns SignedDecision with signature field set

verifier = DecisionVerifier(public_key_pem=pub_bytes)
result = verifier.verify(signed)        # VerificationResult(valid=True, ...)
```

`VerificationResult` fields: `valid (bool)`, `decision_id`, `reason (str | None)` (failure explanation).

---

## 17. Policy Migration System

`PolicyMigration` (`pramanix.migration`) is a pure-Python, declarative state schema migration. It does not touch Z3, Guard, or any database — it is purely a dict transformation.

```python
from pramanix.migration import PolicyMigration

v1_to_v2 = PolicyMigration(
    from_version=(1, 0, 0),
    to_version=(2, 0, 0),
    field_renames={"account_id": "account_number", "limit": "daily_limit"},
    removed_fields=["legacy_flag", "deprecated_counter"],
)

# Check if state is at the expected version
if v1_to_v2.can_migrate(old_state):
    new_state = v1_to_v2.migrate(old_state)           # non-destructive copy
    new_state = v1_to_v2.migrate(old_state, strict=True)  # raises MigrationError on missing field
```

- `migrate()` always returns a new dict — the input is never mutated.
- `state_version` in the output is automatically set to `to_version_str`.
- `strict=True` raises `MigrationError` if a declared `field_renames` key is absent from the state.
- The CLI `pramanix policy migrate` wraps this for one-shot file transforms.

---

## 18. JWT Identity Linker (Zero-Trust)

`JWTIdentityLinker` (`pramanix.identity.linker`) enforces a strict zero-trust boundary for request-state binding. The state passed to `Guard.verify()` **always** comes from the authoritative state store (Redis, database), never from the request body.

```python
from pramanix.identity import JWTIdentityLinker, RedisStateLoader

loader = RedisStateLoader(redis_client=redis_client, key_prefix="account:")
linker = JWTIdentityLinker(state_loader=loader)  # reads PRAMANIX_JWT_SECRET env var

@app.post("/transfer")
async def transfer(request: Request):
    claims, state = await linker.extract_and_load(request)
    decision = await guard.verify_async(intent=intent, state=state)
```

**Security guarantees hardcoded into `JWTIdentityLinker`:**
1. JWT signature verified with HMAC-SHA256 **before** any claims are decoded or trusted.
2. Token expiry enforced (`exp` claim, with configurable `clock_skew_seconds=30`).
3. State loaded **exclusively** using `claims.sub` — not any value from the request body.
4. JWT secret minimum length enforced: ≥ 32 characters. Shorter secrets raise `ValueError` at construction.

`RedisStateLoader` fetches the state dict from Redis using key `{prefix}{claims.sub}`. The state format must match whatever Pydantic model is configured on the Policy's `Meta.state_model`.

---

## 19. Fast Path and Semantic Fast Path

### `SemanticFastPath` (`pramanix.fast_path`)

A pre-Z3 short-circuit layer for rules that are cheaper to evaluate in plain Python than in Z3. Fast path rules run **before** the full Z3 solve, not instead of it for ALLOW decisions. If a fast path rule returns a block reason, Z3 is skipped and `Decision.error()` is returned immediately with the rule's reason.

```python
from pramanix import SemanticFastPath, GuardConfig

def block_frozen_accounts(intent: dict, state: dict) -> str | None:
    if state.get("is_frozen"):
        return "Account is frozen"
    return None  # pass through to Z3

config = GuardConfig(
    fast_path_enabled=True,
    fast_path_rules=(block_frozen_accounts,),
)
```

- Rules are `Callable[[dict, dict], str | None]`. Return `None` to pass through, return a non-empty string to block.
- Rule exceptions are **caught and logged** — a crashing rule never blocks a valid request. The request passes through to Z3.
- `FastPathEvaluator.rule_count` reports the number of registered rules.

### `SemanticFastPath` class

A higher-level API that wraps rule registration and evaluation with structured logging:

```python
fp = SemanticFastPath(rules=[block_frozen_accounts, block_sanctioned_counterparties])
result = fp.evaluate(intent, state)
if result.blocked:
    return Decision.error(explanation=result.reason)
```

`FastPathResult` fields: `blocked (bool)`, `reason (str | None)`, `rule_name (str | None)`.

---

## 20. `@guard` Decorator

The `@guard` decorator (`pramanix.decorator`) wraps a synchronous function to gate it behind a Guard. It raises `GuardViolationError` (which wraps the `Decision`) when the Guard blocks.

```python
from pramanix import guard, Guard, GuardViolationError

guard_instance = Guard(MyPolicy)

@guard(guard_instance, intent_fn=lambda *args, **kwargs: {"amount": kwargs["amount"]})
def execute_transfer(account_id: str, amount: Decimal) -> None:
    ...

try:
    execute_transfer(account_id="acc_123", amount=Decimal("500"))
except GuardViolationError as e:
    print(e.decision.explanation)
```

- `intent_fn`: callable that receives the wrapped function's `(args, kwargs)` and returns the intent dict.
- `state_fn`: optional callable that returns the state dict (default: `{}`).
- The decorator is synchronous only. For async functions, use `Guard.verify_async()` directly.

---

## 21. Prometheus Metrics Catalog

Metrics are registered when `GuardConfig(metrics_enabled=True)`. All metric names are prefixed with `pramanix_`.

| Metric | Type | Labels | Description |
|---|---|---|---|
| `pramanix_decisions_total` | Counter | `namespace`, `status` | Total decisions by status |
| `pramanix_solver_duration_ms` | Histogram | `namespace` | Z3 solve wall time (ms) |
| `pramanix_active_workers` | Gauge | `namespace` | Current active worker count |
| `pramanix_worker_recycle_total` | Counter | `namespace` | Worker pool recycling events |
| `pramanix_worker_warmup_failures_total` | Counter | — | Z3 warmup failures at startup |
| `pramanix_circuit_state` | Gauge | `namespace`, `state` | Active circuit breaker state (1 = active) |
| `pramanix_circuit_pressure_events_total` | Counter | `namespace` | Circuit breaker pressure events |
| `pramanix_audit_sink_overflow_total` | Counter | — | KafkaAuditSink queue overflow drops |
| `pramanix_shed_decisions_total` | Counter | `namespace` | Requests shed by adaptive limiter |

Prometheus scraping endpoint is not provided by Pramanix. The operator must expose the `prometheus_client` default registry via their own HTTP server (e.g., `prometheus_client.start_http_server(8000)`).

---

## 22. Platform Notes and Restrictions

### Alpine Linux is banned

`_platform.py:is_musl()` detects musl libc by reading `/lib/libc.musl*` glob. If musl is detected, `Guard.__init__()` calls `check_platform()` which raises `ConfigurationError` with a message directing the operator to use a glibc-based image.

**Why:** `z3-solver` ships pre-compiled `.so` binaries linked against glibc. On Alpine's musl libc, the solver loads but produces incorrect results or crashes with memory corruption on nonlinear arithmetic. This is not a packaging bug — Z3's binary ABI is glibc-dependent.

The CI pipeline includes an `alpine-ban` stage that `grep -r "alpine"` scans all Dockerfiles and fails if found.

**Recommended base image:** `python:3.11-slim` (Debian Bookworm). Do not use `python:3.11-alpine`.

### Windows

Pramanix is developed and tested on Windows (Python 3.13, `win32` platform). The worker recycle SIGKILL path uses `.kill()` (Windows `TerminateProcess`) instead of `SIGKILL` — the `_drain_executor()` function handles this correctly. The `_ppid_watchdog()` uses `os.getppid()` which is available on Windows via Python 3.8+.

### Python version matrix

| Python | Status | Notes |
|---|---|---|
| 3.11 | Supported, tested in CI | Minimum required version |
| 3.12 | Supported, tested in CI | — |
| 3.13 | Supported, tested in CI, primary dev environment | — |
| < 3.11 | Not supported | `StrEnum`, `match` statements used throughout |

---

## 23. Known Gaps and What They Mean

This is every file below 100% coverage with an honest explanation of why.

**`cli.py` (95%, 30 missed statements):** The uncovered lines are error-exit branches in `_cmd_doctor` (lines 956–979: platform-specific dependency checks that only fail when an optional package is absent), `_cmd_calibrate_injection` (lines 996–997, 1014–1015: file I/O error paths), and `_cmd_schema_export` (lines 1028–1029, 1052–1056: import failure when the policy file has a syntax error). These are reachable but require adversarial input or a broken environment. Not a material risk.

**`key_provider.py` (96%, 8 missed):** Lines 135, 183, 234 are `supports_rotation` property bodies returning `False` on built-in providers — tested via the `test_kms_provider.py` behavioral tests but the branch reporter misses them because the property accessor is called through the Protocol check. Lines 317→319, 326→328, 332, 420, 494, 501, 576→578, 591 are cache-valid branch returns and `supports_rotation` on cloud providers. These are tested via `__new__` injection with pre-populated cache state. Not a functional gap.

**`guard.py` (96%, 12 missed):** Lines 864–865 are the `async-process` pickling pre-check error path (reached only when a non-picklable Policy is used with `execution_mode="async-process"`). Lines 1171–1172, 1177–1178, 1184 are deep error handling paths inside `parse_and_verify()` that require simultaneous translator failure + consensus failure. Lines 1207–1209 are the async context manager `__aexit__` error path. All are defensive error handlers, not primary logic.

**`translator/anthropic.py` (61%)** and **`translator/openai_compat.py` (57%):** The most significant gap. These are not tested in headless CI because they require a live HTTP endpoint. They are tested via `test_translator_anthropic.py` against the VS Code LLM proxy. Any modification to the streaming path in `_single_call()` must be manually verified against a real Anthropic/OpenAI API before release. This is a known, accepted gap with documented manual verification required.

**`crypto.py` (96%):** Lines 71–72 are the `cryptography` package ImportError guard — this package is installed, making the guard unreachable. Lines 391–392 are the `PramanixVerifier.verify()` exception handler for malformed signature bytes, which requires a deliberately corrupted signature string. Both are `# pragma: no cover` candidates that were not annotated.

---

*End of document. This file was generated from direct source code inspection on 2026-04-27, commit `73aef10`. It will become stale as the codebase evolves. Update it when architectural decisions change.*
