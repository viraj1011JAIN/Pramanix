# Architecture Notes

**Pramanix 1.0.0** — Deterministic Neuro-Symbolic Guardrails for Autonomous AI Agents
**Python ≥ 3.13 · Z3 ≥ 4.12 · Pydantic v2 · AGPL-3.0-only**

This document describes what each subsystem owns, its boundaries, its invariants, and what it does on failure. It is written from code, not aspirations. If the code and this document disagree, the code is correct.

---

## Subsystem Map

```
User code
   │
   ├─ Guard (guard.py)
   │    ├─ GuardConfig (guard_config.py)
   │    ├─ _platform.py          ← import-time musl check
   │    ├─ validator.py          ← Pydantic strict-mode validation
   │    ├─ fast_path.py          ← O(1) Python pre-screen (optional)
   │    ├─ guard_pipeline.py     ← semantic post-consensus check, fingerprinting
   │    ├─ solver.py             ← Z3 wrapper (two-phase)
   │    │    └─ transpiler.py    ← DSL AST → Z3 AST
   │    ├─ worker.py             ← ThreadPoolExecutor / ProcessPoolExecutor
   │    ├─ decision.py           ← immutable result
   │    ├─ audit_sink.py         ← pluggable emit (Kafka, S3, Splunk, DD)
   │    └─ audit/                ← Ed25519 signing, Merkle anchoring
   │
   ├─ policy.py                  ← Policy base class (schema + invariants + Meta)
   ├─ expressions.py             ← DSL (Field, E, ConstraintExpr, ForAll, Exists)
   ├─ crypto.py                  ← PramanixSigner / PramanixVerifier
   ├─ key_provider.py            ← KeyProvider protocol + cloud providers
   ├─ execution_token.py         ← HMAC-SHA256 single-use token (TOCTOU gap)
   ├─ circuit_breaker.py         ← Adaptive CB (CLOSED→OPEN→HALF_OPEN→ISOLATED)
   ├─ resolvers.py               ← ContextVar-based lazy field resolution
   ├─ migration.py               ← Declarative schema migration
   ├─ translator/                ← LLM intent extraction + injection defence
   ├─ integrations/              ← FastAPI, LangChain, LlamaIndex, AutoGen adapters
   ├─ interceptors/              ← gRPC / Kafka transport interceptors
   ├─ primitives/                ← Pre-built Policy mixins
   ├─ helpers/compliance.py      ← Regulatory citation reporter + PDF
   └─ cli.py                     ← `pramanix` CLI
```

---

## Subsystem Details

### Guard (`guard.py`)

**Owns:** The verification orchestration pipeline. Instantiated once per Policy type at application startup.

**Construction-time work:**
1. `policy.validate()` — raises `PolicyError` / `InvariantLabelError` immediately on bad policy definition.
2. Pydantic model extraction from `Policy.Meta`.
3. SHA-256 policy fingerprint computation (`_compute_policy_fingerprint`). If `GuardConfig.expected_policy_hash` is set and mismatches, raises `ConfigurationError` — catches silent policy drift across replicas.
4. `WorkerPool` spawn for `async-thread` / `async-process` modes.
5. `FastPathEvaluator` construction if `fast_path_enabled=True`.
6. Expression tree pre-compilation via `transpiler.compile_policy`.

**`verify()` pipeline (in order):**
```
1. Pydantic strict-mode validation (intent + state)
2. Fast-path O(1) pre-screen (if enabled) — can only BLOCK
3. Translator consensus extraction (if translator_enabled=True)
4. guard_pipeline semantic post-consensus check
5. Z3 solve via solver.py
6. Decision construction
7. Ed25519 signing (_sign_decision)
8. Audit sink emit (all configured sinks, failures caught and logged)
9. Structlog emission
10. OTel span close (if otel extra installed)
11. Prometheus counter/histogram update (if prometheus extra installed)
12. ResolverRegistry.clear_cache() in finally block
```

**Boundary:** `Guard.verify()` **never raises**. Every exception — including unexpected ones from user-defined `invariants()` — is caught and returned as `Decision.error()` with `allowed=False`. `Decision(allowed=True)` is never returned from any error handler.

**Failure model:**
- Pydantic validation failure → `Decision(status=VALIDATION_FAILURE, allowed=False)`
- Z3 timeout → `Decision(status=TIMEOUT, allowed=False)`
- Z3 exception → `Decision(status=ERROR, allowed=False)`
- Worker crash (async-process) → `Decision(status=ERROR, allowed=False)`
- Signing failure → `Decision(status=ERROR, allowed=False)` (not an unsigned decision)
- Sink failure → logged, decision already returned to caller

---

### GuardConfig (`guard_config.py`)

**Owns:** Immutable configuration dataclass for Guard. Environment variable ingestion (`PRAMANIX_*` prefix). Prometheus counter/histogram initialisation. OTel `_span()` context manager. Structlog secrets-redaction processor.

**`__post_init__` validates (raises `ConfigurationError`):**
- `solver_timeout_ms > 0`
- `max_workers > 0`
- `execution_mode` in `{"sync", "async-thread", "async-process"}`
- `solver_rlimit >= 0`
- `max_input_bytes >= 0`
- `max_input_chars > 0`
- `min_response_ms >= 0.0`
- `injection_threshold` in `(0.0, 1.0]`
- `consensus_strictness` in `{"semantic", "strict"}`
- `injection_scorer_path` exists if set
- `shed_worker_pct` in `(0.0, 100.0]`
- `shed_latency_threshold_ms > 0.0`

**`__post_init__` emits `UserWarning` (does not raise):**
- `metrics_enabled=True` without `prometheus_client` installed
- `otel_enabled=True` without `opentelemetry-sdk` installed
- `execution_mode` in `{"sync", "async-thread"}` with `PRAMANIX_ENV=production`
- `signer=None` with `PRAMANIX_ENV=production`
- `audit_sinks=()` with `PRAMANIX_ENV=production`
- `solver_rlimit=0` with `PRAMANIX_ENV=production`
- `max_input_bytes=0` with `PRAMANIX_ENV=production`

**Boundary:** GuardConfig is a frozen dataclass (immutable after construction). All env-var reading happens at construction time.

---

### Policy (`policy.py`)

**Owns:** Base class combining field schema, invariants, and Meta. The only authoring surface users subclass.

**Three parts a subclass provides:**
1. Class-level `Field(name, python_type, z3_sort)` attributes — typed schema
2. `invariants()` classmethod — returns `list[ConstraintExpr]`, each `.named(label)`
3. Optional inner `Meta` class with `version`, `semver`, `intent_model`, `state_model`

**Boundary:** Policy classes are passed as class references (not instances) to Guard. They cross process boundaries via pickle (class reference only — no Z3 objects). `Policy.validate()` is called by Guard at construction time and raises immediately on empty invariants or duplicate/missing labels.

---

### DSL / Expressions (`expressions.py`)

**Owns:** The Python-level constraint DSL. Field descriptors, `E()` expression builder, `ConstraintExpr`, `ForAll`, `Exists`, `ArrayField`, `DatetimeField`, `NestedField`.

**Boundary:** Pure Python — zero Z3 imports. The transpiler is the sole site that converts DSL nodes to Z3 AST. No `eval`, `exec`, or `ast.parse` is used anywhere.

---

### Transpiler (`transpiler.py`)

**Owns:** DSL AST → Z3 AST lowering. This is the only file in the codebase that calls `z3.*` from DSL nodes.

**Design invariants:**
- Floats are never passed to Z3 directly. Every float goes through `Decimal(str(v)).as_integer_ratio()` to get an exact rational.
- Integer literals default to `z3.RealVal` for compatibility with Real-sorted fields.
- `InvariantASTCache` (`compile_policy`) pre-walks the expression tree at Guard construction time and caches field references and metadata. This eliminates repeated tree walks at request time.

**Boundary:** Called only by `solver.py` (and `Guard.__init__` for pre-compilation). Never called by user code.

---

### Solver (`solver.py`)

**Owns:** Z3 invocation. Two-phase verification strategy.

**Phase 1 (fast path, all-invariants):**
- One shared `z3.Solver` with all invariants added via `add()`.
- If result is `sat` → return SAFE immediately. This is the common case.
- If result is `unsat` → proceed to Phase 2.

**Phase 2 (attribution, per-invariant):**
- Each invariant gets its own `z3.Solver` with `assert_and_track`. One assertion per solver so `unsat_core()` is always `{label}` — complete violation attribution, no minimal-core ambiguity.

**Failure model:**
- `z3.unknown` (timeout) on either phase → `SolverTimeoutError` with the invariant label. Caught by Guard, returned as `Decision(status=TIMEOUT)`.
- Every Z3 instance has `set("timeout", timeout_ms)` applied. If `solver_rlimit > 0`, `set("rlimit", solver_rlimit)` is also applied.

**Boundary:** Internal module (`__all__ = []`). Called only by `guard.py`.

---

### Worker (`worker.py`)

**Owns:** Async execution modes. Thread pool (`async-thread`) and process pool (`async-process`).

**Critical invariants:**
1. No Z3 objects cross the process boundary. Workers receive `(policy_cls, values_dict, timeout_ms)` and reconstruct the formula tree inside the child.
2. `policy_cls` is a class reference — picklable via its fully-qualified import name.
3. Decision counter is a plain `int` in the host process, guarded by `threading.Lock`. Zero IPC.
4. Stalled-process recycle: the old executor is handed to a daemon background thread. `_drain_executor` waits `_RECYCLE_GRACE_S` seconds then force-kills surviving processes. The event loop is never blocked.

**Failure model:**
- Worker crash → `Decision.error()` returned to caller. Fail-closed.
- Worker pool `shed` (load-shedding) when P99 latency exceeds threshold → `Decision.block()` returned. Never `allowed=True`.

---

### Fast Path (`fast_path.py`)

**Owns:** O(1) Python pre-screen before Z3.

**Invariants (enforced in code, not just comments):**
- Fast-path rules can only BLOCK — they return a string reason or `None`.
- Only Z3 can produce `Decision(allowed=True)`.
- A fast-path BLOCK means Z3 is not invoked at all.
- A fast-path PASS means Z3 is invoked normally.
- Runs after Pydantic validation, before Z3.

**Target:** < 0.1 ms per request. False positive rate: 0% (no legitimate requests blocked).

---

### Decision (`decision.py`)

**Owns:** The immutable, JSON-serialisable result type.

**Invariant enforced in `__post_init__`:** `allowed=True ↔ status=SAFE`. No other combination is valid.

**Status values:**
| Status | allowed | Cause |
|---|---|---|
| `SAFE` | `True` | Z3 proved all invariants hold |
| `UNSAFE` | `False` | Z3 found a counterexample |
| `TIMEOUT` | `False` | Z3 exceeded time budget |
| `ERROR` | `False` | Unexpected internal error |
| `STALE_STATE` | `False` | `state_version` field mismatch |
| `VALIDATION_FAILURE` | `False` | Pydantic model validation failed |
| `CONSENSUS_FAILURE` | `False` | Dual-model LLM consensus disagreement |
| `RATE_LIMITED` | `False` | Load-shedding threshold exceeded |
| `CACHE_HIT` | `False` | Reserved; not currently returned by Guard |

**Canonical hash (`decision_hash`):** SHA-256 over `decision_id + status + allowed + violated_invariants + explanation`. Computed via `orjson` (or stdlib `json` if orjson not installed). Deterministic regardless of key ordering.

---

### Audit (`audit/`)

**Owns:** Cryptographic tamper detection and batch provability.

**Components:**
- `DecisionSigner` — signs `decision.decision_hash` with Ed25519 (via `PramanixSigner`). Called by Guard for every decision if a signer is configured.
- `DecisionVerifier` — verifies Ed25519 signature offline using public key only.
- `MerkleAnchor` — in-memory Merkle tree. `add(decision_id)` → `root()` → `prove(decision_id)` → `proof.verify()`. Proves any single decision was part of an unaltered batch without replaying all decisions.
- `PersistentMerkleAnchor` — same API + `checkpoint_callback` every N additions.
- `MerkleArchiver` — bulk export and pruning of anchored batches.

**Boundary:** Signing failure in `Guard._sign_decision()` returns `Decision.error()` rather than an unsigned decision. The audit trail never silently contains unsigned records.

---

### Crypto (`crypto.py`)

**Owns:** Ed25519 key pair management and sign/verify for Decision objects.

**Key lifecycle:** Old public keys must be archived. Decision records embed `public_key_id` so historical signatures remain verifiable after rotation. `PramanixSigner.generate()` creates a new ephemeral key pair (warns on stderr in production). Production deployments should use `KeyProvider`.

**Dependency:** `cryptography` package (optional extra `crypto`). If not installed, `PramanixSigner` is unavailable. Guard works without signing but emits `UserWarning` in production.

---

### Key Provider (`key_provider.py`)

**Owns:** `KeyProvider` protocol and all implementations. Abstracts key sourcing from `PramanixSigner`.

**Built-in (no extra deps):** `PemKeyProvider`, `EnvKeyProvider`, `FileKeyProvider`

**Cloud (require extras):**
- `AwsKmsKeyProvider` — AWS Secrets Manager (`pip install 'pramanix[aws]'`)
- `AzureKeyVaultKeyProvider` — Azure Key Vault (`pip install 'pramanix[azure]'`)
- `GcpKmsKeyProvider` — GCP Secret Manager (`pip install 'pramanix[gcp]'`)
- `HashiCorpVaultKeyProvider` — HashiCorp Vault KV v2 (`pip install 'pramanix[vault]'`)

**Testability:** All cloud providers accept an injected `_client` parameter so tests can mock the cloud SDK without real credentials.

---

### Execution Token (`execution_token.py`)

**Owns:** HMAC-SHA256 single-use token that closes the TOCTOU gap between `Guard.verify()` and execution.

**Problem it solves:** Without tokens, a replayed or stolen `Decision(allowed=True)` could trigger the guarded action without a fresh verification.

**Token contents:** `decision_id`, `intent_dump`, `policy_hash`, `expires_at` (default 30 s), `token_id` (per-mint nonce), `signature` (HMAC-SHA256 over canonical body).

**Single-use guarantee:** `ExecutionTokenVerifier.consume()` checks signature + expiry + removes `token_id` from an in-memory set under `threading.Lock`. A token can be consumed exactly once.

**Gap:** The consumed-set is in-memory only. A process restart clears it — replay is possible if a token was minted before restart and consumed after. `RedisExecutionTokenVerifier` closes this for Redis deployments. See `KNOWN_GAPS.md § 1`.

---

### Audit Sinks (`audit_sink.py`)

**Owns:** `AuditSink` protocol and all built-in implementations.

**Protocol:** `emit(decision: Decision) -> None`. Must not raise. Implementations catch all exceptions internally.

**Built-in:** `StdoutAuditSink`, `InMemoryAuditSink`

**Enterprise (require extras):** `KafkaAuditSink` (`kafka`), `S3AuditSink` (`s3`/`aws`), `SplunkHecAuditSink` (`splunk`), `DatadogAuditSink` (`datadog`)

**Failure model:** Sink failures are caught by Guard and logged via structlog. They never propagate to the caller and never affect the returned Decision.

---

### Circuit Breaker (`circuit_breaker.py`)

**Owns:** Adaptive fail-closed circuit breaker protecting the Z3 solver under load.

**State machine:**
```
CLOSED → OPEN (pressure detected) → HALF_OPEN (probe) → CLOSED (recovery)
3 consecutive OPEN episodes → ISOLATED (requires manual reset())
```

**Invariant:** Always fail-closed. `ALLOW_WITH_AUDIT` is a deprecated alias for `BLOCK_ALL` — it emits `DeprecationWarning` at construction time. The circuit breaker never returns `allowed=True` without a successful Z3 solve.

---

### Resolver Registry (`resolvers.py`)

**Owns:** Lazy field resolution with per-request context isolation.

**Problem it solves:** In async servers (FastAPI/Uvicorn), concurrent requests share an OS thread. `threading.local` would let Task B see Task A's resolved values (P0 data-bleed). `contextvars.ContextVar` is Task-scoped under asyncio and thread-scoped under threading — each request owns an independent cache namespace.

**Invariant:** Guard calls `ResolverRegistry.clear_cache()` in its `finally` block after every `verify()` call. No resolved value survives across requests.

---

### Translator (`translator/`)

**Owns:** LLM intent extraction with 5-layer prompt injection defence.

**5 layers (in order):**
1. Unicode NFKC normalisation (`_sanitise.py`) — collapses homoglyphs
2. Input length enforcement (`InputTooLongError` at `max_input_chars`)
3. Control-character stripping
4. Injection pattern detection (regex, `_INJECTION_RE`)
5. Dual-model consensus (`redundant.py`) — two LLMs must agree before any result is used

**Dual-model consensus (`extract_with_consensus`):** Calls two translators concurrently. Both results are validated against the intent Pydantic schema. If they disagree on required fields, raises `ExtractionMismatchError`. Agreement modes: `strict_keys` (default), `lenient`, `unanimous`.

**Injection scorer (`injection_scorer.py`):** `BuiltinScorer` wraps the heuristic. `CalibratedScorer` requires scikit-learn and must be trained on labelled examples. Scorer path configurable via `GuardConfig.injection_scorer_path`.

**Status:** Beta. Requires two LLM API keys for full protection. See `KNOWN_GAPS.md § 7`.

---

### Platform Check (`_platform.py`)

**Owns:** Import-time compatibility validation.

**What it checks:** Presence of `/lib/ld-musl-*.so.1` (Alpine Linux / musl libc). Z3 ships glibc-compiled wheels that segfault or run 3–10× slower on musl.

**When it runs:** Once at `import pramanix.guard` (before any Guard construction).

**Bypass:** `PRAMANIX_SKIP_MUSL_CHECK=1`. If you set this on Alpine, Z3 segfaults are your problem.

---

### CLI (`cli.py`)

**Commands:**
- `verify-proof` — offline Ed25519 signature verification
- `audit verify` — replay and verify a Merkle proof
- `simulate` — dry-run a policy against a JSON payload
- `policy migrate` — apply a PolicyMigration to a state JSON file
- `schema export` — dump Policy JSON schema
- `calibrate-injection` — train a CalibratedScorer on a labelled JSONL dataset
- `doctor` — 10-check environment diagnostic. Exits 0 if clean. `--json` for machine-readable output. `--strict` to fail on warnings.

---

### Primitives (`primitives/`)

**Owns:** Pre-built Policy base classes covering common domains. Users `invariant_mixin` these into their own policies.

**Modules:** `fintech.py`, `healthcare.py`, `finance.py`, `rbac.py`, `time.py`, `infra.py`, `common.py`

These are library code — they define invariants but own no state and make no external calls.

---

### Integrations (`integrations/`)

**Owns:** Thin adapter layers for external frameworks.

**Coverage:** FastAPI, LangChain, LlamaIndex, AutoGen, CrewAI, DSPy, Haystack, Pydantic AI, Semantic Kernel (the last five are stubs — see `KNOWN_GAPS.md § 8`).

**Boundary:** Adapters call `Guard.verify()`. They do not contain policy logic. All policy enforcement happens inside Guard.

---

### IFC — Information-Flow Control (`ifc/`)

**Owns:** Lattice-based information-flow enforcement between trust levels.

**Components:**
- `FlowPolicy` — defines `FlowRule` entries mapping `(source_label, dest_label)` pairs to `ALLOW` or `DENY`.
- `FlowEnforcer` — evaluates a `ClassifiedData` object against a `FlowPolicy`. Returns `FlowDecision`.
- `TrustLabel` — string-typed enum of security classification levels (e.g. `"PUBLIC"`, `"CONFIDENTIAL"`, `"SECRET"`).

**Boundary:** `FlowEnforcer` operates independently of `Guard`. It is the caller's responsibility to consult `FlowEnforcer` before allowing data to cross a trust boundary. No automatic coupling to `Guard.verify()` exists.

**Status:** Beta. No integration tests with Guard. See `KNOWN_GAPS.md § 13`.

---

### Privilege Separation (`privilege/`)

**Owns:** Tool capability manifests and execution scope enforcement.

**Components:**
- `CapabilityManifest` — declares which `ToolCapability` entries an agent is permitted to invoke.
- `ExecutionScope` — a frozen set of permitted capabilities for one execution context.
- `ScopeEnforcer` — raises `PrivilegeEscalationError` if a tool invocation is not in scope.

**Boundary:** `ScopeEnforcer.enforce()` must be called at the point of tool invocation. It is not called by Guard automatically.

**Status:** Beta. No integration tests with Guard. See `KNOWN_GAPS.md § 13`.

---

### Human Oversight (`oversight/`)

**Owns:** Approval workflows for actions that require a human decision before execution.

**Components:**
- `InMemoryApprovalWorkflow` — stores pending `ApprovalRequest` objects in memory. `approve()` / `reject()` transition them to `ApprovalDecision`.
- `EscalationQueue` — ordered queue for time-sensitive approval requests.
- `OversightRecord` — immutable record of the approval decision and approver identity.

**Boundary:** `OversightRequiredError` is raised when an action reaches the oversight gate without a valid approval. Guard does not consult the oversight subsystem — callers must wire it in.

**Status:** Beta. In-memory only. No persistence. No integration tests. See `KNOWN_GAPS.md § 13`.

---

### Secure Memory (`memory/`)

**Owns:** Scoped, access-controlled memory partitions for agent state.

**Components:**
- `SecureMemoryStore` — root store. Creates and manages `ScopedMemoryPartition` instances.
- `ScopedMemoryPartition` — isolated key-value namespace. Cross-partition reads raise `MemoryViolationError`.
- `MemoryEntry` — typed, timestamped entry with a `classification` label.

**Boundary:** Partitions are isolated by label at the application level. No OS-level memory protection. Serialisation to disk is not implemented — store contents are lost on process exit.

**Status:** Beta. No integration tests. See `KNOWN_GAPS.md § 13`.

---

### Policy Lifecycle (`lifecycle/`)

**Owns:** Policy version diffing and shadow evaluation.

**Components:**
- `PolicyDiff` — compares two Policy versions and produces `FieldChange` and `InvariantChange` records.
- `ShadowEvaluator` — runs a new policy version in shadow (no-op) mode alongside the current version. Returns `ShadowResult` with both decisions for comparison.

**Boundary:** `ShadowEvaluator` does not affect the Guard's actual decision. It runs the shadow policy in a separate `Guard` instance and logs the difference.

**Status:** Beta. No integration tests against real rolling deployments. See `KNOWN_GAPS.md § 13`.

---

### Provenance (`provenance.py`)

**Owns:** Chain-of-custody records for agent actions.

**Components:**
- `ProvenanceRecord` — immutable record of one agent action: `agent_id`, `action`, `inputs`, `decision_id`, `timestamp`.
- `ProvenanceChain` — ordered list of `ProvenanceRecord` entries with append-only semantics. `verify_chain()` checks hash-linking between consecutive records.

**Boundary:** The chain is in-memory. Persistence is the caller's responsibility.

**Status:** Beta. Hash-linking verified in unit tests. No end-to-end tests under concurrent write load. See `KNOWN_GAPS.md § 13`.

---

## Cross-Cutting Invariants

1. `Guard.verify()` never raises. Always returns `Decision`.
2. `Decision(allowed=True)` only when `status=SAFE`. Enforced in `Decision.__post_init__`.
3. Audit sinks never propagate failures to callers.
4. The fast path can only BLOCK, never ALLOW.
5. No Z3 objects cross process boundaries.
6. Resolver cache is cleared after every `verify()` call.
7. Structlog secrets-redaction processor runs before any renderer — secrets never reach disk.
8. Policy fingerprint mismatch on Guard construction raises `ConfigurationError` — no silent drift.
9. Alpine/musl is rejected at import time unless explicitly bypassed.
10. HMAC-sealed IPC: worker results in `async-process` mode are tagged with an ephemeral key. The host verifies the tag before trusting `allowed`. A forged `allowed=True` from a compromised worker requires knowledge of the in-process ephemeral key.
11. `ConstraintExpr.__bool__` raises `PolicyCompilationError` — accidental `and`/`or` in a policy is caught at compile time, not silently mis-evaluated.
12. `min_response_ms` timing pad is applied unconditionally to both ALLOW and BLOCK — not just BLOCK — to prevent timing oracle attacks.

---

## Environment Variables

All read at `GuardConfig()` construction time via `_env_*` helpers in `guard_config.py`.

| Variable | Default | Type |
|---|---|---|
| `PRAMANIX_EXECUTION_MODE` | `sync` | str |
| `PRAMANIX_SOLVER_TIMEOUT_MS` | `5000` | int |
| `PRAMANIX_MAX_WORKERS` | `4` | int |
| `PRAMANIX_MAX_DECISIONS_PER_WORKER` | `10000` | int |
| `PRAMANIX_WORKER_WARMUP` | `true` | bool |
| `PRAMANIX_LOG_LEVEL` | `INFO` | str |
| `PRAMANIX_METRICS_ENABLED` | `false` | bool |
| `PRAMANIX_OTEL_ENABLED` | `false` | bool |
| `PRAMANIX_TRANSLATOR_ENABLED` | `false` | bool |
| `PRAMANIX_FAST_PATH_ENABLED` | `false` | bool |
| `PRAMANIX_SHED_LATENCY_THRESHOLD_MS` | `200` | float |
| `PRAMANIX_SHED_WORKER_PCT` | `90` | float |
| `PRAMANIX_SOLVER_RLIMIT` | `10000000` | int |
| `PRAMANIX_MAX_INPUT_BYTES` | `65536` | int |
| `PRAMANIX_MAX_INPUT_CHARS` | `512` | int |
| `PRAMANIX_INJECTION_THRESHOLD` | `0.5` | float |
| `PRAMANIX_CONSENSUS_STRICTNESS` | `semantic` | str |
| `PRAMANIX_INJECTION_SCORER_PATH` | _(empty)_ | path |
| `PRAMANIX_ENV` | _(unset)_ | str (`production` triggers extra warnings) |
| `PRAMANIX_SIGNING_KEY_PEM` | _(unset)_ | str (PEM-encoded Ed25519 private key) |
| `PRAMANIX_REDIS_URL` | _(unset)_ | str |
| `PRAMANIX_SKIP_MUSL_CHECK` | _(unset)_ | `1` to bypass Alpine detection |
