# Pramanix Forensic Codebase Audit

**Version under review:** 1.0.0  
**Repository:** `C:\Pramanix` / `github.com/viraj1011JAIN/Pramanix`  
**Audit date:** 2026-05-04  
**Auditor standard:** Code-first, evidence-first. Code overrides documentation. Stubs are called stubs. Simulations are called simulations. "Robust" and "production-ready" require proof.

---

## 1. Executive Truth Summary

Pramanix is a Python SDK that wraps Microsoft Research's Z3 SMT solver as a deterministic, fail-closed policy enforcement kernel for AI agent actions. The core enforcement engine — policy DSL, transpiler, solver, decision, and worker — is substantively implemented, mathematically coherent, and tested with real Z3 invocations. This is not a prototype; the verification logic is production-quality in its depth of design.

**What it definitively is:**
- A real, working Z3-based formal verification engine with a Python DSL, typed field schema, two-phase solve strategy, and complete violation attribution
- A fail-closed security primitive: 141 `except Exception` handlers all converge on `Decision.error(allowed=False)`; no error handler anywhere returns `allowed=True`
- A meaningfully hardened HMAC-IPC pipeline that seals worker results with an in-process ephemeral key, blocking forged ALLOW decisions from compromised worker processes
- A substantial test suite: 3,550 test functions across 150+ files, 26,544 source lines, 51,850 test lines, real Z3 calls, real infrastructure containers (Kafka, Postgres, S3, Redis via testcontainers), and a custom protocol library (`real_protocols.py`) that replaces every MagicMock

**What is overstated or incomplete:**
- The six beta subsystems (IFC, Privilege, Oversight, Memory, Lifecycle, Provenance) are implemented in isolation but have no coupling tests with Guard; a misconfiguration silently bypasses all of them
- The `CalibratedScorer` injection defense uses `pickle.load()` with no HMAC integrity check — documented risk but not enforced
- `FlowRule.matches()` is documented as "glob-style" but implements exact string equality — a silent semantic gap
- The `async-process` execution mode has no CI coverage on Windows, which is also the declared development platform
- All five "stub" integrations (CrewAI, DSPy, Haystack, PydanticAI, SemanticKernel) are actually implemented, but none have been exercised against real installed framework versions in CI
- The latency benchmark shows P50 at 5.235 ms, just above the 5 ms target (benchmark self-reports `"passed": false`)
- Cloud KMS providers are tested with injected fake clients only — real IAM paths are untested
- Coverage was demonstrably padded: at least 8 files named `test_coverage_boost*`, `test_coverage_gaps*`, `test_coverage_final_push*` exist, indicating coverage was driven to target by gap-filling

**Single sentence verdict:** Pramanix has a genuinely strong formal verification kernel wrapped in an architecturally sound but operationally incomplete platform that is not yet ready for enterprise production deployment but is substantially closer to that bar than any comparable open-source guardrail SDK.

---

## 2. Audit Method and Evidence Standard

All conclusions in this report derive from direct inspection of repository source code, test files, CI configuration, benchmark data, and generated artifacts. No assumption was made from documentation unless independently verified against code.

**Conflict resolution:** Where documentation and code disagree, code is authoritative. Where comments describe intended behavior not present in code, the discrepancy is noted.

**Classification system used throughout this report:**

| Label | Definition |
|---|---|
| **Implemented** | Full working code path exists and is covered by tests that exercise the real behavior |
| **Implemented, weakly tested** | Full working code path exists; tests use fake/stub infrastructure or cover only happy path |
| **Implemented, untested against real framework** | Code path exists; tests don't exercise against real external framework/library |
| **Partial** | Code exists for the feature but key behavior is missing, skipped, or hard-coded |
| **Stub** | Class or function exists but body is `pass`, returns a constant, or immediately raises `NotImplementedError` |
| **Import guard only** | Class importable without dep; body defers to real dep at call time; not called in tests without dep |
| **Fake-backed** | Tests use `fakeredis`, `respx`, `testcontainers`, or custom duck-typed stubs in place of real service |
| **Monkeypatched** | Tests use `patch()` to replace a symbol; real code path not executed |

---

## 3. Repository Inventory

### Package layout

```
src/pramanix/           26,544 lines across 77 Python files
  __init__.py           Public API surface; 374 lines; 140+ exports
  guard.py              1,354 lines — core verification orchestrator
  guard_config.py       553 lines  — frozen configuration dataclass
  policy.py             703 lines  — policy DSL base + mixin system
  expressions.py        1,052 lines — NamedTuple AST, E() builder
  transpiler.py         884 lines  — DSL AST → Z3 AST lowering
  solver.py             430 lines  — two-phase Z3 invocation
  worker.py             832 lines  — thread/process pool + HMAC IPC
  decision.py           677 lines  — frozen result dataclass
  decorator.py          148 lines  — @guard function wrapper
  fast_path.py          214 lines  — O(1) Python pre-screen
  guard_pipeline.py     294 lines  — semantic post-consensus checks
  validator.py          121 lines  — Pydantic strict validation wrappers
  resolvers.py          171 lines  — ContextVar field resolver
  execution_token.py    1,184 lines — HMAC single-use TOCTOU tokens
  crypto.py             393 lines  — Ed25519 key management
  circuit_breaker.py    970 lines  — adaptive + distributed breaker
  audit_sink.py         494 lines  — pluggable decision emitters
  audit/                merkle.py, signer.py, verifier.py
  key_provider.py       690 lines  — KeyProvider protocol + cloud providers
  translator/           9 files    — LLM extraction + injection defense
  integrations/         9 adapters — FastAPI, LangChain, LlamaIndex, AutoGen, CrewAI, DSPy, Haystack, PydanticAI, SemanticKernel
  interceptors/         grpc.py, kafka.py
  k8s/                  webhook.py
  primitives/           7 modules  — pre-built constraint factories
  ifc/                  enforcer.py, flow_policy.py, labels.py
  privilege/            scope.py
  oversight/            workflow.py
  memory/               store.py
  lifecycle/            diff.py
  provenance.py
  helpers/              compliance.py, policy_auditor.py, serialization.py, string_enum.py, type_mapping.py
  cli.py, migration.py, logging_helpers.py, _platform.py, exceptions.py
```

### Test structure

```
tests/                  51,850 lines across 150+ Python files; 3,550 test functions
  unit/                 115 files — real Z3, real Pydantic, real asyncio
  integration/          21 files — testcontainers (Kafka, Postgres, Redis, LocalStack S3)
  property/             3 files  — Hypothesis-based property tests
  adversarial/          8 files  — fail-safe, injection, overflow, HMAC integrity
  perf/                 2 files  — memory stability, latency (excluded from default run)
  helpers/real_protocols.py — custom duck-typed stub library (replaces all MagicMock)
  conftest.py           — minimal (single solver_timeout_ms fixture)
```

### Benchmarks

```
benchmarks/
  latency_benchmark.py              — API-mode latency benchmark
  results/latency_results.json      — P50=5.235ms, P95=6.361ms, P99=7.109ms; "passed": false
  results/run_finance_20260322_052731/ — 100M decision run, 18 workers, 150ms solver timeout
```

### CI/CD

- `.github/workflows/` — 9-stage pipeline: SAST → alpine-ban → lint-typecheck → test → coverage → wheel-smoke → extras-smoke → trivy → license-scan
- Single Python version matrix: Python 3.13 only
- Coverage gate in CI: 95% (pyproject.toml specifies 98% — discrepancy)
- Nightly benchmark job: P99 < 15 ms gate

### Documentation

- `docs/ARCHITECTURE_NOTES.md` — accurate, code-derived
- `docs/PUBLIC_API.md` — accurate after recent cleanup
- `docs/KNOWN_GAPS.md` — present and honest
- `docs/DECISIONS.md` — genuine ADRs with rejected alternatives documented
- `docs/CHANGELOG.md` — accurate to recent commit history

---

## 4. What Pramanix Actually Is

In code-observable terms, Pramanix is a **Z3-backed policy enforcement gate** that operates as follows:

1. A user defines a `Policy` subclass with typed `Field` descriptors and a list of `ConstraintExpr` invariants built using the `E()` builder DSL
2. `Guard(PolicyClass)` compiles the policy at construction time: validates field schema, computes a SHA-256 policy fingerprint, pre-walks the DSL expression tree into an `InvariantASTCache`, warms worker processes if in async-process mode
3. `guard.verify(intent=dict, state=dict)` runs an 12-step pipeline ending in a frozen `Decision` dataclass
4. The decision is mathematically binary: Z3 either proves all invariants hold under the supplied values (ALLOW, status=SAFE) or finds a counterexample (BLOCK, status=UNSAFE, with per-invariant attribution)
5. `guard.verify()` never raises — every exception collapses to `Decision.error(allowed=False)`

**First-class concerns in code:** fail-closed guarantee, violation attribution, HMAC IPC integrity, timing side-channel mitigation, structured audit trail, token-based TOCTOU gap closure, policy fingerprinting.

**Peripheral (implemented but peripheral):** IFC, privilege separation, human oversight, provenance, memory isolation — all implemented as standalone modules with no Guard coupling.

**Optional layer:** The "neuro-symbolic" branding refers to an optional upstream translator that converts natural-language text to a structured intent dict via LLM consensus before Z3 evaluation. This layer is explicitly marked `beta`, is disabled by default, requires two LLM API keys for full protection, and adds latency. Without it, the system is purely symbolic.

---

## 5. Architecture Reality

### Request flow (sync mode)

```
caller: guard.verify(intent={...}, state={...})
  │
  ├─ Pydantic strict-mode validation (validator.py)
  │    └─ ValidationError → Decision.validation_failure(allowed=False)
  │
  ├─ Fast-path O(1) pre-screen (fast_path.py) [if enabled]
  │    └─ rule match → Decision.block(allowed=False, no Z3)
  │    └─ exception in rule → log WARNING, continue to Z3
  │
  ├─ [optional] Translator consensus + injection filter (translator/)
  │    └─ ExtractionMismatchError → Decision.consensus_failure(allowed=False)
  │    └─ InjectionBlockedError → Decision.error(allowed=False)
  │
  ├─ guard_pipeline semantic post-consensus check
  │    └─ SemanticPolicyViolation → Decision.error(allowed=False)
  │
  ├─ solver.py two-phase Z3 solve
  │    Phase 1: shared solver, s.add() all invariants → SAT (common case, fast) or UNSAT
  │    Phase 2 (on UNSAT): one solver per invariant, assert_and_track → exact attribution
  │    └─ SolverTimeoutError → Decision.timeout(allowed=False)
  │    └─ z3.unknown → SolverTimeoutError
  │
  ├─ Decision construction (decision.py)
  │    └─ decision_hash = SHA-256(decision_id+status+allowed+violated_invariants+explanation)
  │    └─ __post_init__ enforces: allowed=True ↔ status=SAFE (ValueError if violated)
  │
  ├─ Ed25519 signing (_sign_decision) [if signer configured]
  │    └─ signing failure → Decision.error(allowed=False), never unsigned decision
  │
  ├─ Audit sink emit [if sinks configured]
  │    └─ exceptions caught, logged, never propagated
  │
  ├─ structlog emission
  ├─ OTel span close [if otel installed]
  ├─ Prometheus counter/histogram [if prometheus installed]
  └─ ResolverRegistry.clear_cache() [in finally block — always runs]
```

### Disciplined architectural boundaries

- **Transpiler isolation:** `expressions.py` has zero Z3 imports; `transpiler.py` is the only module that converts DSL nodes to Z3 AST. No `eval`, `exec`, `ast.parse` anywhere.
- **Process boundary:** No Z3 objects cross ProcessPoolExecutor boundary. Workers receive `(policy_cls, values_dict, timeout_ms)` and reconstruct the formula tree in-process. `_EphemeralKey.__reduce__` raises `TypeError` — intentionally non-picklable to prevent HMAC key leakage.
- **Resolver isolation:** `contextvars.ContextVar` ensures Task-scoped cache in asyncio and thread-scoped in threading — no cross-request value bleed.
- **Sink failure isolation:** Sink exceptions are caught in Guard's finally block after decision is already returned to caller — sinks cannot affect decisions.

### Leaky boundaries

- `guard_pipeline._semantic_post_consensus_check()` embeds domain-specific numeric heuristics (fintech, healthcare, infra) inline — domain knowledge inside the pipeline rather than in the policy layer. Six instances of `except Exception: pass` suppress non-numeric field errors silently, by design but without operator visibility.
- `verify_async()` re-implements most of `_verify_core()`'s 12-step pipeline for the async path. Two trees to maintain — the most likely source of future divergence bugs.
- `GuardConfig.__post_init__` contains Prometheus counter initialization — metrics coupling inside the configuration class.
- `is_business_hours()` in `expressions.py`: the epoch-to-weekday mapping uses `epoch//86400 % 7` where `0=Thursday` (Unix epoch = 1970-01-01 = Thursday). This is correct but non-obvious; a developer expecting `0=Monday` will write silent bugs.

---

## 6. Core Enforcement Engine Assessment

### Policy model
`Policy` subclasses declare `Field(name: str, python_type: type, z3_sort: Z3Type)` class attributes and a `classmethod invariants() → list[ConstraintExpr]`. The `Meta` inner class provides `version`, `semver`, `intent_model`, `state_model` (optional Pydantic models for strict validation). All field resolution uses `vars(cls)` — only the declaring class's fields, not inherited ones. `policy.fields()` and `lifecycle/diff._collect_fields()` (which uses `dir()`) are inconsistent in their field-collection semantics; this is a latent trap for multi-inheritance policies.

### DSL
The DSL is a lazy expression tree built from NamedTuples. Every operator (`+`, `-`, `*`, `/`, `**`, `%`, `abs`, `>`, `>=`, `<`, `<=`, `==`, `!=`, `&`, `|`, `~`) returns a new NamedTuple node. `ConstraintExpr.__bool__` raises `PolicyCompilationError` with a clear message — accidental `and`/`or`/`if` on a constraint is caught at policy load time, not silently miscompiled. `__pow__` accepts only integer exponents 1–4; `__rpow__` always raises `TypeError`.

String operations: `.starts_with()`, `.ends_with()`, `.contains()`, `.matches_re()`, `.length_between()` — all produce `_StartsWithOp`, `_EndsWithOp`, etc. NamedTuples. The README previously listed Python builtin spellings (`.startswith()`); this was corrected in the most recent commit.

`ForAll` empty array → vacuously true (consistent with formal logic). `Exists` empty array → False. These are correct but not documented for users who may expect different behavior.

**Correctness confidence: HIGH.** The DSL-to-Z3 lowering is structurally sound and has deep property-based testing (Hypothesis, 13 test groups, ~500–1,000 examples each).

### Solver behavior
The two-phase strategy eliminates a known Z3 flaw: `unsat_core()` on a shared solver with multiple `assert_and_track` calls returns only a *minimum* (heuristic, not necessarily complete) subset of violated invariants. Phase 2 uses one solver per invariant with a single `assert_and_track` call, so `unsat_core()` always returns exactly `{label}`. This is a sophisticated fix for a non-obvious Z3 API subtlety.

Each solve call creates its own `z3.Context()` instance and deletes it in a `finally` block. This prevents Z3 heap accumulation across decisions — critical for long-lived processes.

rlimit enforcement via `s.set("rlimit", solver_rlimit)` bounds solver resource usage independent of wall-clock timeout, preventing degenerate formula explosion.

### Fail-closed behavior

Confirmed by test `tests/adversarial/test_fail_safe_invariant.py`: 11 exception types (including `SystemExit`, `MemoryError`, `KeyboardInterrupt`... wait — review the actual guard.py catch scope: `except Exception`, which does NOT catch `KeyboardInterrupt` or `SystemExit` since those are `BaseException` subclasses). The guard does NOT catch `BaseException` — `KeyboardInterrupt` propagates to the caller. This is correct behavior but means a `Ctrl-C` during a Z3 solve in sync mode will propagate through `guard.verify()`. For CLI usage, this is expected. For server usage, it could cause an unhandled exception if not caught at the ASGI layer.

The `Decision.__post_init__` invariant (`allowed=True ↔ status=SAFE`) is enforced with `ValueError`. No guard bypass is possible without modifying the frozen dataclass.

### Determinism
Z3 is deterministic given the same formula and timeout. Policy fingerprint (`_compute_policy_fingerprint`) hashes field names, z3_type, and invariant labels — but NOT the python_type. Two policies with the same field name and z3_type but different Python types (`int` vs `Decimal`, both mapped to "Real") will produce the same fingerprint. This is a gap: the fingerprint does not fully identify the policy's runtime behavior.

---

## 7. Security Assessment

### Fail-closed: STRONG
Every error path terminates in `Decision.error(allowed=False)`. Confirmed across 141 `except Exception` handlers. No fail-open path visible in the core engine. `KeyboardInterrupt` propagates (acceptable — `BaseException` should not be swallowed).

### HMAC IPC: STRONG
`_RESULT_SEAL_KEY = _EphemeralKey(secrets.token_bytes(32))` at module load. Workers cannot forge `allowed=True` without knowledge of this key. `_EphemeralKey.__reduce__` raises `TypeError` — key cannot cross process boundary via pickle. `hmac.compare_digest` for constant-time comparison.

### Token replay protection: STRONG for Redis/SQLite/Postgres, WEAK for InMemory
`RedisExecutionTokenVerifier` uses `SET ... NX EX` (atomic, multi-replica safe). `SQLiteExecutionTokenVerifier` uses `UNIQUE PRIMARY KEY` + WAL mode. `InMemoryExecutionTokenVerifier` warns via `RuntimeWarning` when multi-worker signals are detected (via `WEB_CONCURRENCY`, `GUNICORN_CMD_ARGS`, etc.). Process restart vulnerability is documented.

### Timing side-channel: ADDRESSED
`min_response_ms` timing pad applied unconditionally to BOTH ALLOW and BLOCK in `PramanixMiddleware` and `guard.verify()`. Not applied only to BLOCK (which would leak the decision). Applied in a `contextlib.suppress(InterruptedError)` loop — cannot be bypassed by a malicious signal in the hot path.

### Secret redaction: STRONG
`_redact_secrets_processor` runs as FIRST structlog processor before any renderer. Regex covers: `secret`, `api_key`, `token`, `hmac`, `password`, `passwd`, `credential`, `private_key`, `access_key`, `signing_key`, `session`, `authorization`, `bearer`, `pii`, `ssn`, `phi`. Applied at all structlog emission points in Guard.

### CalibratedScorer pickle: RISK NOT MITIGATED
`CalibratedScorer.load()` calls `pickle.load(f)` with no HMAC integrity check. The docstring states: "NEVER load a .pkl file from an untrusted source" and recommends HMAC verification. This recommendation is not enforced in code. A compromised `.pkl` file enables arbitrary code execution on scorer load. This is a real RCE vector for deployments that use custom injection scorers loaded from shared storage.

### FlowRule glob documentation gap: MISLEADING
`FlowRule.matches()` docstring: "Glob-style component name pattern." Implementation: `return self.source == source_label and self.dest == dest_label` — exact string equality. No glob processing. A user writing `FlowRule("PUBLIC.*", "SECRET")` expecting to match `PUBLIC.api.response` will get silent pass-through.

### HashiCorp Vault unguarded KeyError: FRAGILE
`HashiCorpVaultKeyProvider._refresh_cache()`: `resp["data"]["data"][self._field]`. If `_field` does not exist in the Vault secret, this raises `KeyError` which propagates as an unhandled exception. The caller gets a crash at `Guard` construction time (fail-fast — safe behavior), but the error message is uninformative.

### Policy fingerprint completeness gap: LOW RISK
`_compute_policy_fingerprint()` hashes field name + z3_type but not python_type. `Field("amount", int, "Real")` and `Field("amount", Decimal, "Real")` produce the same fingerprint. In practice, validation would likely fail differently at runtime, but the fingerprint cannot be used as a complete policy identity proof.

### Injection defense: LAYERED AND REAL
Five layers: NFKC normalization, length cap, control-char strip, 26-pattern regex, dual-model consensus. The `_INJECTION_PATTERNS` list covers modern LLM-specific attacks: `[INST]`, `<<SYS>>`, ChatML tokens, Llama-3 tokens, DAN/god-mode/developer-mode variants, persona override, markdown injection. The post-consensus injection scoring adds a second gate after LLM extraction. This is meaningfully more comprehensive than a single regex pass.

### Residual risks
- `CalibratedScorer` pickle RCE (medium severity, unmitigated in code)
- `FlowRule` glob documentation mismatch (medium severity — policy authors will write ineffective flow rules)
- `InMemoryApprovalWorkflow` HMAC key lost on restart — historical oversight records unverifiable (low severity — documented)
- `ProvenanceChain.verify_integrity()` skips prev_hash check for first retained record after eviction (medium severity — silent integrity gap)
- `is_business_hours()` weekday encoding (low severity — documentation gap)

---

## 8. Information Flow, Memory, and Oversight

### IFC (`ifc/`): IMPLEMENTED, NO GUARD COUPLING
`FlowPolicy`, `FlowEnforcer`, `TrustLabel`, `FlowRule`, `ClassifiedData` are all fully implemented. `FlowEnforcer.gate()` raises `FlowViolationError` on policy violations. In-memory audit log per enforcer instance.

**Gap:** No integration with `Guard.verify()`. Calling `Guard.verify()` on an ALLOW intent does NOT automatically consult `FlowEnforcer`. A developer must explicitly call `flow_enforcer.gate()` before acting on an ALLOW decision. There is no composition API that couples the two. A developer who installs both but forgets the explicit coupling gets no IFC enforcement.

**`FlowRule.matches()` bug:** Documented as "glob-style" but implements exact string equality — a silent semantic error.

### Privilege (`privilege/`): IMPLEMENTED, NO GUARD COUPLING
`ExecutionScope` (IntFlag), `CapabilityManifest`, `ScopeEnforcer.enforce()` are fully implemented. `FINANCIAL | DESTRUCTIVE | ADMIN` requires `approved_by` non-empty. `deny_unknown=True` is the default — unregistered tool calls are blocked.

**Gap:** Same composition gap as IFC. `ScopeEnforcer.enforce()` must be called manually after `Guard.verify()` returns ALLOW. No automatic enforcement.

### Human Oversight (`oversight/`): IMPLEMENTED, IN-MEMORY ONLY
`InMemoryApprovalWorkflow` fully implemented with HMAC-tagged records. `request_approval()` always raises `OversightRequiredError` — this is by design (callers catch it). The workflow supports approve/reject/timeout with structured `OversightRecord`.

**Gap:** No persistent backend. The HMAC key for `OversightRecord` is generated per-process at module import. On process restart, all historical records become unverifiable. No queue persistence — records lost on restart. This cannot be used for regulated industries without a durable backend.

### Memory (`memory/`): IMPLEMENTED, NO PERSISTENCE
`SecureMemoryStore`, `ScopedMemoryPartition`, `MemoryEntry` are fully implemented with partition isolation enforced by label comparison. `UNTRUSTED` data is blocked if `min_label >= CONFIDENTIAL`.

**Gap:** `list.pop(0)` eviction (O(n) list shift) under high write volume. No persistence — contents lost on process exit. No integration with Guard.

### Policy Lifecycle (`lifecycle/`): IMPLEMENTED
`PolicyDiff` and `ShadowEvaluator` are fully implemented. `PolicyDiff.compute()` uses `repr()` of `ConstraintExpr` NamedTuples for change detection — deterministic and correct for the immutable NamedTuple AST nodes used.

`ShadowEvaluator`: shadow evaluation is synchronous. The caller must wrap it in an executor for async use. List eviction is O(n).

### Provenance (`provenance.py`): IMPLEMENTED
`ProvenanceRecord` and `ProvenanceChain` are fully implemented with hash-linking between consecutive records. `verify_integrity()` confirms the chain. `append()` overrides caller-supplied `prev_hash` with the actual computed value — correct behavior.

**Gap:** `verify_integrity()` skips the prev_hash check for the first retained record after eviction. If the eviction boundary crosses a malicious record, the break goes undetected. No persistence.

**Verdict:** All six beta subsystems contain real, non-trivial code. None contain `pass`-only methods or placeholder returns. All are implemented in isolation from each other and from Guard. The governance story they tell cannot be enforced without explicit caller wiring — making them governance libraries rather than governance infrastructure.

---

## 9. Concurrency, Reliability, and Failure Handling

### Thread mode (`async-thread`)
`ThreadPoolExecutor` with `max_workers` threads. Z3 releases the Python GIL during solver execution — genuine parallelism. Worker results are not HMAC-sealed in thread mode (seal only in process mode) — a deliberate decision since threads share memory space with the host, so seal provides no additional security benefit.

### Process mode (`async-process`)
`ProcessPoolExecutor(mp_context=spawn)`. Workers receive `(policy_cls, values_dict, timeout_ms)` — no Z3 objects, no open handles. HMAC-sealed results. PPID watchdog: workers monitor parent PID and self-terminate if parent dies. Warmup: 8 Z3 solve patterns on startup, including a forced UNSAT to verify solver sanity. If the warmup UNSAT fails, `RuntimeError("Z3 context may be corrupted")` is raised and the worker refuses to start.

**Gap:** No CI coverage of `async-process` mode on Windows. Development platform is Windows 11. `spawn` semantics differ from `fork` on Linux; Windows `spawn` path is untested in CI. A silent serialization bug in the spawn path would not be caught.

### Worker recycling
After `max_decisions_per_worker` decisions (default 10,000), the pool is replaced. Old executor drained in a daemon thread (`_drain_executor`) — event loop never blocked. `_RECYCLE_GRACE_S` seconds wait before force-killing survivors. This cleanly bounds Z3 heap accumulation.

### Circuit breaker
`AdaptiveCircuitBreaker`: `CLOSED → OPEN → HALF_OPEN → CLOSED`. Three consecutive OPEN episodes → `ISOLATED` (manual `reset()` required). The asyncio lock is held for state-check + routing decision but released before the actual `verify_async()` call — correct design, avoids holding the lock during a potentially slow Z3 solve.

`AdaptiveConcurrencyLimiter` P99 estimation requires ≥10 samples. The first 9 requests, regardless of latency, are never shed. Under a cold burst of slow requests, the first 9 go through before the limiter activates.

`FailsafeMode.ALLOW_WITH_AUDIT` is a deprecated alias for `BLOCK_ALL`. Both fail-closed. Deprecated mode emits `DeprecationWarning` at construction time.

`DistributedCircuitBreaker`: Redis unavailability → returns `OPEN` (fail-safe). Unknown state from Redis → `OPEN` (fail-safe). State machine consistency across replicas is limited to best-effort synchronization via `pubsub` and periodic polling.

### Cache isolation
`contextvars.ContextVar` correctly isolates resolver cache between concurrent asyncio tasks. `Guard.verify()` calls `ResolverRegistry.clear_cache()` in `finally` — always runs even on exception. No cross-request resolver bleed is possible unless the caller manually retains a resolver value across calls.

### Cleanup guarantees
Z3 `del ctx` in solver `finally` block. Worker pool drain in daemon thread. Audit sink `close()` called in `__del__` (best-effort; GC ordering not guaranteed). `KafkaAuditSink` flushes the bounded queue on `close()`. `SplunkHecAuditSink` uses `httpx.Client` with `close()`.

### Race condition observations
- `S3AuditSink` has a confusing variable: `self._executor = threading.Thread` is the type annotation placeholder; actual executor is `self._pool` (ThreadPoolExecutor). The variable naming could confuse future maintainers.
- `GuardViolationError.__init__` accesses `decision.status` at construction time — if a malformed object without a `status` attribute is passed, the exception constructor itself raises `AttributeError`, which propagates unexpectedly.

---

## 10. Integrations and Adapters Reality Check

### FastAPI / Starlette: IMPLEMENTED, STRONGLY TESTED

`PramanixMiddleware` is a real `BaseHTTPMiddleware` subclass. 9-step pipeline. Timing pad applied to BOTH ALLOW and BLOCK. `pramanix_route()` decorator validates intent/state signature at decoration time. `Content-Type` and body-size enforcement. Tested with real Starlette `TestClient` in `tests/integration/test_fastapi_middleware.py` and `test_fastapi_async.py`.

**Reality:** Genuine integration, not a wrapper shell. The middleware code handles real ASGI lifecycle correctly.

### LangChain: IMPLEMENTED, STRONGLY TESTED

`PramanixGuardedTool` is a real `BaseTool` subclass. Private state stored via `object.__setattr__` to bypass Pydantic's field validation — necessary for `BaseTool`'s strict Pydantic model. `execute_fn=None` raises `NotImplementedError` (breaking change from v0.9.x where it silently returned "OK"). `_run()` handles nested event loop detection by submitting `asyncio.run()` to a `ThreadPoolExecutor`.

Tested in `tests/integration/test_langchain_tool.py` with real `langchain-core` objects.

### LlamaIndex: IMPLEMENTED, TESTED

`PramanixFunctionTool` and `PramanixQueryEngineTool` wrap real LlamaIndex interfaces. Tested in integration suite.

### AutoGen: IMPLEMENTED, TESTED

`PramanixToolCallback` implements AutoGen's callback pattern.

### CrewAI: IMPLEMENTED, UNTESTED AGAINST REAL FRAMEWORK

`PramanixCrewAITool` is a genuine `BaseTool` subclass with real `_run()`, `_arun()`, and `__call__` methods. Uses `_PramanixState` container (same pattern as LangChain adapter) to bypass Pydantic. `underlying_fn=None` raises `NotImplementedError`. Guard errors return a `[PRAMANIX_BLOCKED]`-prefixed string instead of raising — designed for CrewAI's exception-sensitive agent loop.

**Gap:** No test exercises `PramanixCrewAITool` against a real `crewai` install. Unit tests use the class in non-CrewAI mode (`_CREWAI_AVAILABLE = False` path).

### DSPy: IMPLEMENTED, UNTESTED AGAINST REAL FRAMEWORK

`PramanixGuardedModule` is a genuine `dspy.Module` subclass. `forward()` calls `Guard.verify()` before delegating to the inner module. `__call__()` delegates to `forward()`. BLOCK raises `GuardViolationError` — consistent with DSPy's assertion-failure control flow.

**Gap:** No test uses a real DSPy module. Tests exercise the class in non-DSPy mode.

### Haystack: IMPLEMENTED, UNTESTED AGAINST REAL FRAMEWORK

`HaystackGuardedComponent` implements `run()` and `run_async()`. Processes both documents and messages. `block_on_error=True` default — errors cause BLOCK. Haystack `@component` decorator applied at class-definition time if Haystack is installed.

**Gap:** No test exercises against real Haystack pipeline. The `_haystack_component(HaystackGuardedComponent)` call in a `try/except: pass` block may silently fail without the decorator being applied.

### PydanticAI: IMPLEMENTED, UNTESTED AGAINST REAL FRAMEWORK

`PramanixPydanticAIValidator` provides `check()`, `check_async()`, and `guard_tool()` decorator. The `guard_tool` decorator extracts `intent` and `state` from `**kwargs` — requires caller to pass them as keyword arguments by that exact name.

**Gap:** No test exercises against real `pydantic-ai` agent tool registration. The `@agent.tool / @validator.guard_tool` stacking is untested.

### Semantic Kernel: IMPLEMENTED, UNTESTED AGAINST REAL FRAMEWORK

`PramanixSemanticKernelPlugin` provides `verify()` and `verify_async()` as SK native functions. Accepts and returns JSON strings — correct SK function protocol. `ConfigurationError` raised at construction if `semantic-kernel` not installed.

**Gap:** No test exercises against real SK kernel registration or invocation.

### gRPC interceptor: IMPLEMENTED, WEAKLY TESTED

`PramanixGrpcInterceptor` wraps all four RPC types. Stream peaking via `itertools.chain`. `handler._replace(**replace_kwargs)` assumes `grpc.HandlerCallDetails` is a NamedTuple — fragile against gRPC version changes.

### Kafka consumer: IMPLEMENTED, WEAKLY TESTED

`PramanixKafkaConsumer.safe_poll()` yields only approved messages. DLQ dead-lettering. Guard errors are caught, dead-lettered, and committed — never re-raised.

### Cloud KMS providers: IMPLEMENTED, FAKE-BACKED ONLY

All four cloud providers (`AwsKmsKeyProvider`, `AzureKeyVaultKeyProvider`, `GcpKmsKeyProvider`, `HashiCorpVaultKeyProvider`) are structurally complete with caching, TTL, and rotation. All tested with injected `_client` stubs that simulate success/failure responses. No test exercises against real IAM, real network, or real key rotation flows.

### Kubernetes webhook: IMPLEMENTED, WEAKLY TESTED

`AdmissionWebhook` handles `/validate` and `/mutate` endpoints. Unit-tested against synthetic `AdmissionReview` payloads. No end-to-end test against real Kubernetes API server.

---

## 11. Cryptography, Auditability, and Provenance

### Two signing systems (easily confused)

| System | Module | Algorithm | Purpose | Keys |
|---|---|---|---|---|
| `DecisionSigner` | `audit/signer.py` | HMAC-SHA256 (HS256) | Signs `decision_hash` in a JWS-like envelope | Symmetric shared secret |
| `PramanixSigner` | `crypto.py` | Ed25519 | Signs `decision.decision_hash` asymmetrically | Ed25519 keypair |

Both sign the same `decision_hash` field but use different algorithms and key types. The public API exports both. A deployment could use one, both, or neither — no enforcement. The distinction between them is not prominent in documentation.

**HMAC-SHA256 (DecisionSigner):** Signs `decision_hash` with an HMAC-SHA256 key. The `iat` field was removed from the signed payload (v0.5.x) because including a timestamp broke deterministic verification. `issued_at` in `VerificationResult` is always `0`. The signed payload has no timestamp — a replayed `SignedDecision` cannot be distinguished from a fresh one by timestamp alone.

**Ed25519 (PramanixSigner):** Asymmetric. Verifiable with public key only. `PramanixVerifier.verify_decision()` recomputes `decision_hash` from fields before verifying signature — detects field tampering, not just signature forgery. `key_id = SHA-256[:16]` of public key PEM — decisions embed the key ID for rotation tracking.

### Merkle anchoring
`MerkleAnchor`: SHA-256 Merkle tree with `\x00` leaf prefix and `\x01` internal-node prefix — second-preimage protection (Bitcoin CVE-2012 mitigation). Duplicate `decision_id` raises `ValueError`. `prove()` returns inclusion path; `proof.verify(root)` checks offline. `PersistentMerkleAnchor` adds checkpoint callback.

`MerkleArchiver` writes `.merkle.archive.YYYYMMDD` files. `verify_archive(path)` offline verification. Files are plaintext — `MerkleArchiver.__init__` logs a `WARNING` that archive files should be encrypted in regulated environments.

### What can be verified offline
- Decision signatures (Ed25519 or HMAC-SHA256) — YES, with key only
- Merkle inclusion proofs — YES, with root hash
- Decision hash integrity — YES, by recomputing from fields
- Full decision content against signed payload — YES via `PramanixVerifier.verify_decision()`

### What cannot be verified offline
- Timestamp of signing (iat removed from signed payload)
- That the decision came from a running Guard instance (not a replayed historical decision)
- IFC, Privilege, Oversight, Memory, Lifecycle, Provenance record authenticity beyond in-memory HMAC (process-restart key loss)

### Audit sink durability
`KafkaAuditSink`: bounded queue (10,000 entries max), background poller thread, overflow increments Prometheus counter and drops decision. Not guaranteed delivery — producer queue overflow = silent drop. `S3AuditSink`: ThreadPoolExecutor with 4 workers. `DatadogAuditSink`: error message scrubbing (may contain API key in response body). All sinks: exceptions caught, logged, never propagated. Decisions are not re-emitted on sink failure — a transient Kafka outage loses decisions silently.

---

## 12. Developer Experience and Usability

### Policy authoring: CLEAR AND ELEGANT

The DSL is well-designed. A real policy:

```python
class TransferPolicy(Policy):
    amount      = Field("amount",      Decimal, "Real")
    balance     = Field("balance",     Decimal, "Real")
    daily_spent = Field("daily_spent", Decimal, "Real")

    @classmethod
    def invariants(cls):
        return [
            (E(cls.amount) > 0).named("positive_amount"),
            (E(cls.amount) <= E(cls.balance)).named("no_overdraft"),
            (E(cls.daily_spent) + E(cls.amount) <= 10_000).named("daily_limit"),
        ]
```

This is readable, typed, and formally precise. The `__bool__` safety net catches `and`/`or` at policy load time. The named invariants produce human-readable BLOCK explanations.

### Sharp edges for developers

1. **`Field` positional args:** `Field("name", python_type, z3_sort)` — three positional args. Swapping python_type and z3_sort produces a `FieldTypeError` at Guard construction, but only after the policy class is instantiated. An IDE won't catch this.

2. **`is_business_hours()` weekday encoding:** Epoch-based weekday where 0=Thursday. Expects no user to remember this. Likely to be implemented incorrectly on first use.

3. **`Meta` inner class non-inheritable:** `vars(cls).get("Meta")` — subclasses cannot inherit `Meta`. A developer who subclasses a policy to add fields loses the `Meta` from the parent silently.

4. **Cloud provider imports:** `AwsKmsKeyProvider` is not re-exported from `pramanix` top-level. Must be imported from `pramanix.key_provider` directly. This is an undiscovered footgun — the README previously had it wrong.

5. **`async-process` on Windows:** Policies must be defined at module level (importable by fully-qualified name) for `spawn` process mode to work. Functions defined inside other functions, lambdas, or `if __name__ == "__main__"` blocks will fail silently with a `PicklingError`.

6. **Two signing systems:** Developers choosing Ed25519 (`PramanixSigner`) vs HMAC-SHA256 (`DecisionSigner`) face an underdocumented tradeoff. Both produce a `decision_hash`-based signature but with different security properties.

### Configuration
`GuardConfig` is a frozen dataclass — immutable after construction. All env vars read at construction time. This prevents runtime reconfiguration but eliminates race conditions. `ConfigurationError` raised immediately on invalid config — no deferred discovery. This is good design.

### Error messages
`GuardViolationError` includes the full `Decision` object — callers can inspect `violated_invariants`, `explanation`, and `decision_hash`. `PolicyCompilationError` includes the expression that failed. `InvariantLabelError` names the duplicate/missing label. Generally informative.

### CLI
`pramanix doctor` provides 10+ diagnostic checks including Z3 installation, logging configuration, policy hash binding, Redis connectivity. `pramanix simulate` dry-runs a policy against JSON input. `pramanix verify-proof` offline signature verification. These tools are genuinely useful for production debugging.

### Onboarding burden
A new developer can write a working policy and call `Guard.verify()` in under 20 lines. The quick-start in the README works correctly (after the DSL method name correction). The conceptual model is clear: policy → guard → verify → decision. The complexity grows quickly when optional features are added (signing, audit sinks, token verification, circuit breaker), but each layer is independently optional.

---

## 13. Code Quality Assessment

### Module organization: GOOD
Clear separation: expressions (DSL) → transpiler (lowering) → solver (Z3) → worker (concurrency) → guard (orchestration). The layering is respected; no circular imports observed.

### Naming: GOOD
`E()` is short but documented. `ConstraintExpr`, `Field`, `Decision`, `SolverStatus`, `GuardConfig` are all self-explanatory. `_EphemeralKey`, `_RESULT_SEAL_KEY`, `_worker_solve_sealed` are explicit about their security role.

### Abstraction quality: GOOD to VERY GOOD
`KeyProvider` as a runtime-checkable `Protocol` is the correct abstraction — allows testing with injected fake clients without inheritance. `AuditSink` as Protocol is similarly correct. `ExecutionTokenVerifier` as Protocol covers all four backends.

### Exception discipline: GOOD but with intentional broad catches
141 `except Exception` occurrences — all at fail-safe boundaries. Zero `except Exception: raise` re-raises that silently mutate exceptions. Specific exception types used for all non-fail-safe paths. `SolverTimeoutError`, `ExtractionMismatchError`, `InjectionBlockedError`, `GuardViolationError` all carry structured data (not just messages).

### Type hints and mypy
`mypy --strict` is configured. `# type: ignore`: 60 occurrences — concentrated in integration adapter `__init__` signatures and dynamic dispatch paths where Pydantic's metaclass prevents full type inference. No broad suppressions in core engine modules.

### Comments and docstrings
Docstrings reflect actual behavior (verified against code). No aspirational comments found in reviewed modules. Security-critical invariants are called out explicitly: "NEVER LOG THIS" on `private_key_pem()`, HMAC comparison notes, timing pad rationale.

### Technical debt indicators
- `verify_async()` code duplication with `_verify_core()` — most significant maintenance risk
- 8 coverage-hunting test files (`test_coverage_boost*`, `test_coverage_gaps*`, `test_coverage_final_push*`) — indicates coverage pressure led to gap-filling rather than scenario-driven test design
- `list.pop(0)` in `ScopedMemoryPartition`, `ProvenanceChain`, `ShadowEvaluator` — O(n) eviction under high volume
- `S3AuditSink` naming confusion: `self._executor = threading.Thread` annotation vs `self._pool` variable name
- `_semantic_post_consensus_check()` hardcodes domain-specific field names (`amount`, `balance`, `dosage`, `replicas`) inside the pipeline — knowledge that belongs in the policy layer

### Dead code
Zero `TODO`/`FIXME` markers in `src/pramanix/`. No obvious dead code paths observed. `ALLOW_WITH_AUDIT` in the circuit breaker is explicitly deprecated (not removed) for backward compatibility — documented, not silently dead.

---

## 14. Test Suite Deep Assessment

### Breadth by subsystem

| Subsystem | Test files | Notes |
|---|---|---|
| Guard / verify() | test_guard.py, test_guard_full_coverage.py, test_gap_fixes.py | Real Z3, real Pydantic |
| Policy DSL | test_expressions.py, test_string_operations.py, test_array_field.py, test_datetime_field.py, test_nested_models.py, test_pow_mod_operators.py | All real AST construction |
| Transpiler | test_transpiler.py, test_transpiler_full_coverage.py, test_transpiler_spike.py, test_string_promotion.py | Real Z3 lowering verified |
| Solver | test_solver.py | Real Z3 context per test |
| Worker | test_worker.py, test_process_pickle.py, test_load_shedding.py | Real thread/process pool |
| Decision | test_decision.py | Real hash computation |
| Circuit Breaker | test_circuit_breaker.py, test_circuit_breaker_sync.py, test_distributed_cb.py, test_distributed_circuit_breaker.py | fakeredis for distributed |
| Execution Tokens | test_token_verifier.py, test_redis_token.py, test_postgres_token_verifier.py, test_consume_within_sqlite.py | SQLite/fakeredis/duck-typed asyncpg |
| Audit / Crypto | test_audit.py, test_audit_cli.py, test_crypto.py, test_merkle_archiver.py, test_verify_proof_cli.py, test_archiver_coverage_gaps.py | Real Ed25519, real SHA-256 |
| Audit Sinks | test_audit_sink.py | Real protocol stubs, no real brokers |
| FastAPI | test_fastapi_middleware.py, test_fastapi_async.py | Real Starlette TestClient |
| LangChain | test_langchain_tool.py | Real langchain-core |
| Translator | test_injection_scorer_filter.py, test_consensus_semantic.py, test_injection_calibration.py, test_input_too_long.py, test_intent_cache.py | respx for HTTP interception |
| Primitives | test_primitives_foundation.py, test_fintech_primitives.py, test_healthcare_primitives.py, test_infra_primitives_phase8.py | Real Z3 verification |
| Property-based | test_dsl_and_transpiler_properties.py, test_fintech_primitive_properties.py, test_serialization_roundtrip.py | Hypothesis, real Z3 |
| Adversarial | test_fail_safe_invariant.py, test_prompt_injection.py, test_hmac_ipc_integrity.py, test_toctou_awareness.py, test_field_overflow.py, test_id_injection.py, test_pydantic_strict_boundary.py, test_z3_context_isolation.py | Real Z3, real injection patterns |
| Kafka (integration) | test_kafka_audit_sink.py | Real Kafka via testcontainers |
| S3 (integration) | test_s3_audit_sink.py | Real LocalStack via testcontainers |
| Redis (integration) | test_redis_circuit_breaker.py | Real Redis via testcontainers |
| Postgres token (integration) | test_postgres_token.py | Real Postgres via testcontainers |
| Coverage hunting | test_coverage_boost.py, test_coverage_boost2.py, test_coverage_gaps.py, test_coverage_final_push.py, test_coverage_final_push2.py, test_cli_coverage_gaps.py, test_archiver_coverage_gaps.py, test_guard_full_coverage.py | Explicitly gap-filling |

### Failure-path testing: STRONG in core, WEAK in integrations

`tests/adversarial/test_fail_safe_invariant.py` parametrically proves no exception type causes `allowed=True` — this is a genuine security test, not a coverage exercise. `test_hmac_ipc_integrity.py` tests 12 HMAC tamper scenarios. `test_prompt_injection.py` tests 26 OWASP-pattern injection vectors.

Audit sink failure paths (network down, broker reject, malformed delivery) are tested with custom stub clients that simulate failure — not real infrastructure. This is acceptable for unit tests but means real Kafka backpressure behavior is only confirmed in the testcontainers integration tests.

### Property-based testing: MEANINGFUL
`test_dsl_and_transpiler_properties.py`: 13 test groups covering commutativity, monotonicity, conjunction/disjunction, negation complement, real/integer decimal agreement, set-membership exactness, bool field isolation, label preservation, empty-invariant SAT, and full violation attribution. These are true property tests — Hypothesis generates counterexamples, not just happy-path data.

### Mock/stub inventory

`real_protocols.py` (1,400+ lines) contains:
- `_SyncCloseClient`, `_AsyncCloseClient`, `_BothCloseClient`, `_ErrorCloseClient` — HTTP lifecycle stubs
- `_RaisingGuard`, `_CountingGuard`, `_BlockingGuard` — Guard-protocol implementations
- `_RecordingAuditSink`, `_FailingAuditSink` — AuditSink implementations
- `_FakeRedisClient`, `_RaisingRedisClient` — Redis-protocol implementations
- `_PingOkRedisClient`, `_PingFailRedisClient` — for CLI doctor tests
- `_RaisingSubmitExecutor`, `_KafkaAuditProducer`, `_KafkaAuditModule` — Kafka stubs
- All async-pattern stubs use real coroutines (`async def`), not `AsyncMock`

**Actual MagicMock usage: 1 file** — `test_framework_adapters.py`. This is the only file that imports `MagicMock`; no other test file uses it.

**`from unittest.mock import` (patch only): 20 files** — used for module-level attribute patching (e.g., `PRAMANIX_ENV`, `_OTEL_AVAILABLE`, `sys.modules["asyncpg"]`). These are module-swapping patches, not object mock substitutions.

### 14.x Real vs Simulated Test Matrix

| Area | Real execution | Fake-backed | Monkeypatched | MagicMock | Transport intercept | End-to-end |
|---|---|---|---|---|---|---|
| Z3 solve | ✓ | — | — | — | — | ✓ |
| Policy DSL | ✓ | — | — | — | — | ✓ |
| Transpiler | ✓ | — | — | — | — | ✓ |
| Pydantic validation | ✓ | — | — | — | — | ✓ |
| Decision hash | ✓ | — | — | — | — | ✓ |
| Ed25519 signing | ✓ | — | — | — | — | ✓ |
| HMAC signing | ✓ | — | — | — | — | ✓ |
| Merkle anchoring | ✓ | — | — | — | — | ✓ |
| SQLite token | ✓ | — | — | — | — | ✓ |
| Redis token | — | fakeredis | — | — | — | — |
| Postgres token | — | duck-typed asyncpg | — | — | — | ✓ (testcontainers) |
| Redis circuit breaker (unit) | — | fakeredis | — | — | — | — |
| Redis circuit breaker (int.) | ✓ | — | — | — | — | ✓ |
| Kafka audit sink (unit) | — | stub producer | — | — | — | — |
| Kafka audit sink (int.) | ✓ | — | — | — | — | ✓ |
| S3 audit sink (unit) | — | stub client | — | — | — | — |
| S3 audit sink (int.) | ✓ LocalStack | — | — | — | — | ✓ |
| FastAPI middleware | ✓ TestClient | — | — | — | — | ✓ |
| LangChain adapter | ✓ real langchain | — | — | — | — | ✓ |
| LLM extractors | — | — | — | — | respx | — |
| Cloud KMS providers | — | injected stub | — | — | — | — |
| Process mode (Linux CI) | ✓ | — | — | — | — | ✓ |
| Process mode (Windows CI) | — | — | — | — | — | — |
| Injection patterns | ✓ real regex | — | — | — | — | ✓ |
| IFC enforcer | ✓ | — | — | — | — | — |
| Privilege scope | ✓ | — | — | — | — | — |
| Oversight workflow | ✓ | — | — | — | — | — |
| Memory store | ✓ | — | — | — | — | — |
| Provenance chain | ✓ | — | — | — | — | — |
| Policy diff/shadow | ✓ | — | — | — | — | — |
| CrewAI (non-crewai mode) | ✓ | — | — | — | — | — |
| CrewAI (real crewai) | — | — | — | — | — | — |
| DSPy (real dspy) | — | — | — | — | — | — |
| Haystack (real haystack) | — | — | — | — | — | — |
| PydanticAI (real pydantic-ai) | — | — | — | — | — | — |
| Semantic Kernel (real sk) | — | — | — | — | — | — |

### Tests that could create misleading production-readiness impressions

1. **Coverage-hunting files** — `test_coverage_boost.py`, `test_coverage_boost2.py` etc. increase line coverage counts without necessarily testing meaningful behavior. A 98% coverage gate with these files included does not imply 98% behavioral coverage.
2. **Cloud KMS tests** — test pass with injected stub clients that always return a fixed PEM string. A broken IAM policy, a wrong secret ARN, or a key format mismatch will not be caught.
3. **Kafka unit tests** — stub producer records calls but does not simulate broker backpressure, partition rebalancing, or delivery failure callbacks.
4. **`async-process` on Windows** — the mode is tested in CI on Linux only. Passing Windows unit tests do not imply `async-process` works correctly on Windows.

---

## 15. Truth Audit of Claims

### "Deterministic neuro-symbolic guardrails"

**Verdict: PARTIALLY JUSTIFIED**

*Deterministic:* TRUE for the Z3 core. Given the same formula and timeout, Z3 produces the same answer. `Decision.decision_hash` is deterministic (orjson with `OPT_SORT_KEYS`, or stdlib json with sorted keys). `DecisionSigner` removed `iat` from signed payload for this reason.

*Neuro-symbolic:* The "neuro" part requires the optional translator subsystem (`beta`, disabled by default, requires two LLM API keys). Without it, the system is purely symbolic. The claim is technically valid only when the full neuro-symbolic pipeline is active.

*Guardrails:* Valid — the system intercepts agent action intent before execution and enforces formal policies.

### "Autonomous AI agent safety"

**Verdict: PARTIALLY JUSTIFIED**

The guard can enforce that a declared intent satisfies formal invariants before execution. It does NOT evaluate agent reasoning, cannot detect an agent that lies about its intent, and provides no protection against intents that are individually valid but collectively unsafe across a multi-step plan. The governance subsystems (IFC, Privilege, Oversight) address this partially but have no Guard coupling.

### "Enterprise-grade"

**Verdict: ASPIRATIONAL BUT NOT YET JUSTIFIED**

Enterprise-grade requires: multi-environment CI, production traffic validation, real cloud integration tests, SAST with audit trail, mature release process, SLA definitions, real incident playbooks, and ecosystem breadth. Pramanix has: SAST pipeline, real testcontainers infrastructure, documented gaps, and a genuine security model. It lacks: real-world production deployments, validated cloud KMS paths, `async-process` Windows coverage, and PyPI availability.

### "Production-ready"

**Verdict: CORE IS NEAR PRODUCTION-READY; PLATFORM IS NOT**

The guard kernel (guard, policy, transpiler, solver, decision, worker) could be deployed in production for a well-understood use case (e.g., financial transaction validation in sync mode with Redis-backed tokens). The broader platform (IFC, Privilege, Oversight, all cloud provider paths, async-process on Windows) requires additional hardening.

### "Hardened"

**Verdict: MEANINGFULLY HARDENED FOR THE CORE**

- HMAC IPC: real cryptographic boundary
- Timing pad: correctly applied to all responses
- Injection defense: 5-layer pipeline with 26 patterns
- Fail-closed: every exception path verified
- Second-preimage protection in Merkle tree
- Token replay: SETNX for Redis, WAL+UNIQUE for SQLite

Not hardened: CalibratedScorer pickle, FlowRule glob mismatch, HashiCorp KeyError.

### "Cryptographically auditable"

**Verdict: PARTIALLY JUSTIFIED**

Decisions are signed, and signatures are verifiable offline. Merkle inclusion proofs work. What cannot be verified: signing timestamp (iat removed), that the decision came from a live Guard vs replay, IFC/Oversight/Memory event authenticity after restart. The auditability story is real but incomplete.

### "Integration-rich"

**Verdict: BREADTH IS REAL; DEPTH VARIES**

9 framework adapters exist and are not stubs — all contain real `Guard.verify()` calls, real exception handling, and real framework interface compliance. However, only FastAPI and LangChain have been tested against real framework instantiations. CrewAI, DSPy, Haystack, PydanticAI, and SemanticKernel are implemented but untested against real framework objects in CI.

### "Scalable"

**Verdict: DESIGNED FOR SCALE, UNPROVEN AT SCALE**

The architecture (process pool, HMAC IPC, worker recycling, circuit breaker, distributed circuit breaker, Redis token store) is designed for multi-replica horizontal scale. A real 100M decision benchmark was run (`benchmarks/results/run_finance_20260322_052731/`, 18 workers). P99 at 7.109 ms in the latency benchmark. BUT: no load testing of the audit sink pipeline at scale, no Redis cluster testing, no multi-replica coordination testing at production traffic volumes.

### "Robust"

**Verdict: ROBUST IN THE CORE; FRAGILE IN GOVERNANCE SUBSYSTEMS**

The core enforcement path is demonstrably robust. The governance subsystems (IFC, Memory, Oversight, Provenance) have O(n) eviction, no persistence, and no Guard coupling — fragile under sustained load and silent under misconfiguration.

---

## 16. Competitive Readiness Against NeMo, LangChain, Guardrails AI

### NVIDIA NeMo Guardrails

**NeMo provides:** LLM conversation guardrailing via Colang language, topical rails, fact-checking, hallucination prevention, integration with NVIDIA Riva and Triton.

**Pramanix advantage:** Formal deterministic verification (NeMo uses probabilistic LLM-based guardrails — no proof, no counterexample). BLOCK decisions carry a Z3-derived counterexample naming the violated invariant — NeMo cannot do this. Pramanix's fail-closed guarantee is provable from code; NeMo's safety guarantees are probabilistic.

**NeMo advantage:** Conversation-level guardrails (topic control, dialog flow, semantic similarity). Ecosystem integration with NVIDIA tooling. Hallucination checking. Pramanix cannot evaluate conversation context — it evaluates structured intent against formal policy. For conversational AI safety, NeMo is more mature.

**Net comparison:** Pramanix wins on enforcement precision for structured action validation. NeMo wins on conversational AI breadth. These are different problem domains.

### LangChain

**LangChain provides:** Agent orchestration, tool calling, memory, chain composition, extensive ecosystem. "Guardrails" in LangChain means LangChain-specific callback hooks or integrated partner libraries.

**Pramanix advantage:** Pramanix is a guard primitive, not an orchestration framework. LangChain has no equivalent of Z3-backed formal invariant verification. The `PramanixGuardedTool` adapter works within LangChain's tool protocol. Pramanix provides formal guarantees that LangChain's callback system does not.

**LangChain advantage:** Ecosystem breadth, orchestration maturity, production usage at scale, established community. LangChain is used in production by thousands of teams; Pramanix is not yet published to PyPI.

**Net comparison:** These are complementary, not competitive. LangChain orchestrates; Pramanix enforces. The adapter exists and works. The comparison is a category error.

### Guardrails AI

**Guardrails AI provides:** Input/output validation for LLMs via "guards" (validators) on prompts and responses. Focus on output structure, format, and content validation. ML-based validators.

**Pramanix advantage:** Formal verification (Z3 proofs vs probabilistic validators). Structured intent model vs open-ended output validation. Violation attribution (which invariant failed, with counterexample) vs generic rejection. HMAC-sealed audit trail. Formal guarantee that every ALLOW has a mathematical proof.

**Guardrails AI advantage:** Broader validator ecosystem, output validation (Pramanix does not validate LLM outputs), production usage, PyPI availability, simpler onboarding for non-formal-verification users. Natural language output guards (e.g., no PII, no hate speech) that are outside Pramanix's formal model.

**Net comparison:** Pramanix provides stronger guarantees for structured action validation in narrow domains. Guardrails AI provides broader validation for LLM output quality in open domains. Pramanix cannot compete on output content validation; Guardrails AI cannot compete on formal correctness proofs. For financial transaction enforcement, Pramanix is demonstrably stronger. For LLM output safety broadly, Guardrails AI is more mature.

**What Pramanix needs to compete in the broader market:**
1. PyPI publication and stable installation
2. Documentation of real production deployments
3. Real-world benchmarks at production traffic (not just local 100M benchmark)
4. Ecosystem breadth comparable to Guardrails AI's validator library
5. GUI or configuration-based policy authoring for non-programmer safety teams

---

## 17. Strengths That Are Real

1. **Two-phase Z3 solve with complete attribution.** Phase 1 (fast SAT path) + Phase 2 (per-invariant solver with single `assert_and_track`) eliminates Z3's minimum-core ambiguity. Every BLOCK decision names every violated invariant — no lossy attribution. This design addresses a documented Z3 API limitation that most Z3-based tools do not handle correctly.

2. **Absolute fail-closed guarantee.** Verified by adversarial test suite (`test_fail_safe_invariant.py`) against 11 exception types. `Decision.__post_init__` enforces `allowed=True ↔ status=SAFE` with `ValueError` — invariant cannot be bypassed without modifying the frozen dataclass. No error handler in guard.py returns `allowed=True`.

3. **HMAC-sealed IPC.** Module-level `_EphemeralKey(secrets.token_bytes(32))` prevents worker process from forging ALLOW decisions. `__reduce__` raises `TypeError` — key cannot be pickled. `hmac.compare_digest` for constant-time comparison. This is a sophisticated process-isolation mechanism that comparable SDKs don't implement.

4. **Test suite authenticity.** 3,550 test functions. Zero MagicMock in test logic (1 file uses it; remainder use real protocol implementations from `real_protocols.py`). 21 integration tests using real testcontainers. 3 property test files with Hypothesis. 8 adversarial test files. The absence of MagicMock-based test theater is a genuine quality differentiator.

5. **Real injection defense.** 5-layer pipeline: NFKC normalization, length cap, control-char strip, 26-pattern OWASP regex covering modern LLM-specific attacks, dual-model consensus. Post-consensus injection scoring provides a second gate. This is meaningfully more comprehensive than a single regex check.

6. **Policy fingerprinting.** SHA-256 fingerprint of field names, z3_types, and invariant labels. `ConfigurationError` at Guard construction if fingerprint mismatches — prevents silent policy drift in rolling deployments. The fingerprint is embedded in `ExecutionToken` — tokens can be invalidated by policy change.

7. **Merkle second-preimage protection.** `\x00` leaf prefix + `\x01` internal-node prefix — Bitcoin CVE-2012 mitigation applied. Duplicate `decision_id` detection. `PersistentMerkleAnchor` with checkpoint callback. This is security engineering at a level of detail that most audit trail implementations omit.

8. **Timing oracle mitigation.** `min_response_ms` pad applied unconditionally to BOTH ALLOW and BLOCK — not just BLOCK. Applied in hot path before ALLOW/BLOCK branch. This correctly prevents timing-based oracle attacks, including the specific timing oracle fixed in the H-02 security item.

9. **Real 100M decision benchmark.** `benchmarks/results/run_finance_20260322_052731/` contains 18-worker, 100M decision run with checkpoint JSONL files. P50=5.235ms at 2,000 iterations in API mode. This is actual measured performance data, not a theoretical claim.

10. **Worker warmup sanity check.** On `async-process` pool spawn, each worker runs 8 Z3 patterns including a forced UNSAT. If UNSAT is not obtained, `RuntimeError("Z3 context may be corrupted")` is raised and the worker refuses to start. This prevents silent solver corruption from entering the production pool.

---

## 18. Weaknesses, Drawbacks, and Structural Risks

1. **Not on PyPI.** The SDK is not published. `pip install pramanix` fails. This is the single largest adoption blocker for any potential user.

2. **`verify_async()` code duplication.** The async path re-implements most of the 12-step `_verify_core()` pipeline. Two code paths doing similar things inevitably diverge. The M-02 bug (missing `_policy_semver` check in async path) is evidence this has already happened once.

3. **`async-process` mode untested on Windows.** The declared development platform is Windows 11. The mode that provides the strongest isolation guarantee has no CI coverage on that platform. A user who follows the docs and sets `execution_mode="async-process"` on Windows gets an untested path.

4. **CalibratedScorer pickle without integrity.** `pickle.load()` with no HMAC check on the file. Documented but not enforced. For deployments that load custom injection scorers from shared storage (e.g., S3, NFS), this is a real RCE vector.

5. **FlowRule glob documentation mismatch.** `FlowRule.matches()` uses exact string equality. Docstring says "glob-style." Every FlowPolicy written with wildcard expectations will silently fail to match anything, passing traffic through unchecked. This is a semantic security gap.

6. **Beta subsystems have no Guard coupling.** All six governance subsystems (IFC, Privilege, Oversight, Memory, Lifecycle, Provenance) must be manually called by the developer after getting an ALLOW decision. No composition primitive exists. A developer who installs Pramanix for IFC enforcement but forgets the explicit `flow_enforcer.gate()` call gets no enforcement.

7. **O(n) eviction across governance subsystems.** `list.pop(0)` in `ScopedMemoryPartition`, `ProvenanceChain`, `ShadowEvaluator`, `lifecycle/diff.py`. Under sustained write volume, every eviction is an O(n) list shift. For high-throughput deployments with bounded history, this degrades to quadratic time.

8. **Coverage padding.** At least 8 test files exist specifically to fill coverage gaps. These tests inflate the coverage metric without proportionally increasing confidence in behavioral correctness. The 98% coverage gate means less than it appears to.

9. **Single Python version in CI.** Python 3.13 only. No 3.12 compatibility tested. If a dependency has a 3.13-specific behavior difference, it will not be caught.

10. **orjson as hard non-optional dependency.** `orjson` is installed for all users despite being used only for the `decision_hash` canonical serialization (with stdlib `json` fallback if unavailable). Every user pays this binary dependency even if they have no need for high-performance JSON.

11. **Policy fingerprint omits python_type.** `Field("amount", int, "Real")` and `Field("amount", Decimal, "Real")` produce the same fingerprint. The fingerprint cannot be used as a complete policy identity proof.

12. **InMemoryApprovalWorkflow HMAC key lost on restart.** Historical oversight records become unverifiable after process restart. The in-memory workflow cannot be used in regulated environments without a durable replacement.

13. **Cloud provider integration is faith-based.** All four cloud KMS providers pass CI with injected stub clients. No actual IAM permission, network routing, or secret version handling is tested. A misconfigured cloud provider will fail at Guard construction (fail-fast — correct), but the error message from `KeyError` in HashiCorp or from a network timeout in AWS will be uninformative.

14. **P50 latency just above target.** Benchmark self-reports `"passed": false` with P50=5.235ms against a 5ms target. Under JVM-style JIT effects, GC pressure, or OS scheduling variance, this margin may collapse. The 5ms target is declared in the benchmark script; it's unclear whether this is a customer-facing SLA commitment.

15. **Latency benchmark run locally, not in CI.** The benchmark results in `benchmarks/results/` are from a local run, not from the CI pipeline. The CI nightly benchmark job exists but its results are not in the repository. Reproducibility of the 5.235ms P50 number in a different environment is unknown.

---

## 19. Gap Catalogue

### Architecture gaps

| # | Title | Severity | Evidence | Impact | To close |
|---|---|---|---|---|---|
| A-1 | `verify_async()` duplicates `_verify_core()` | HIGH | guard.py — two 12-step pipelines | Future divergence; M-02 already occurred | Refactor to shared core; async path calls shared logic |
| A-2 | No Guard coupling for governance subsystems | HIGH | ifc/, privilege/, oversight/ have no Guard interface | Silent bypass if developer forgets explicit call | Composition primitive or middleware hook |
| A-3 | Policy fingerprint omits python_type | MEDIUM | `_compute_policy_fingerprint()` in guard_pipeline.py | Two non-equivalent policies share fingerprint | Include python_type in hash |
| A-4 | `Meta` inner class non-inheritable | MEDIUM | `vars(cls).get("Meta")` in policy.py | Subclasses silently lose parent Meta | Use MRO traversal |
| A-5 | `_collect_fields()` vs `policy.fields()` inconsistency | LOW | lifecycle/diff.py vs policy.py | Lifecycle diff sees inherited fields; Guard does not | Standardize on one mechanism |

### Security gaps

| # | Title | Severity | Evidence | Impact | To close |
|---|---|---|---|---|---|
| S-1 | CalibratedScorer pickle without integrity | HIGH | injection_scorer.py `pickle.load()` | RCE via compromised scorer file | HMAC-verify the file before loading |
| S-2 | FlowRule glob docstring mismatch | HIGH | flow_policy.py `FlowRule.matches()` exact equality | Silent IFC bypass | Implement fnmatch or fix docstring |
| S-3 | HashiCorp Vault unguarded KeyError | MEDIUM | key_provider.py `resp["data"]["data"][self._field]` | Uninformative crash on misconfiguration | `KeyError` → `ConfigurationError` with field name |
| S-4 | Oversight HMAC key not persisted | MEDIUM | oversight/workflow.py `_process_key()` | Historical records unverifiable after restart | Persist key or use external KMS |
| S-5 | ProvenanceChain integrity gap after eviction | MEDIUM | provenance.py `verify_integrity()` | Evicted-boundary manipulation undetected | Emit a signed checkpoint leaf at eviction boundary |

### Information-flow/governance gaps

| # | Title | Severity | Evidence | Impact | To close |
|---|---|---|---|---|---|
| G-1 | No Guard ↔ IFC composition | HIGH | enforcer.py, guard.py — no coupling | IFC enforcement requires manual wiring | `GuardConfig(ifc_policy=FlowPolicy(...))` |
| G-2 | No Guard ↔ Privilege composition | HIGH | privilege/scope.py — no coupling | Privilege enforcement requires manual wiring | Same |
| G-3 | Oversight workflow in-memory only | HIGH | oversight/workflow.py `_records` dict | Records lost on restart | Redis-backed workflow backend |
| G-4 | Memory store no persistence | MEDIUM | memory/store.py in-memory only | State lost on restart | Pluggable storage backend |

### Provenance gaps

| # | Title | Severity | Evidence | Impact | To close |
|---|---|---|---|---|---|
| P-1 | ProvenanceChain post-eviction integrity gap | MEDIUM | provenance.py `verify_integrity()` | Silent integrity break at eviction | Signed checkpoint leaf before eviction |
| P-2 | No signing timestamp in DecisionSigner output | LOW | audit/signer.py `iat` removed | Replay of historical signed decisions undetectable by timestamp | Accept and document, or use `jti` nonce |

### Integration gaps

| # | Title | Severity | Evidence | Impact | To close |
|---|---|---|---|---|---|
| I-1 | CrewAI/DSPy/Haystack/PydanticAI/SK untested against real frameworks | HIGH | No real-framework CI jobs for these adapters | API compatibility unknown | Add CI jobs with real framework installs |
| I-2 | Cloud KMS fake-backed only | HIGH | All tests use `_client=` injected stub | Real IAM/network paths unknown | Add staging integration tests |
| I-3 | `async-process` untested on Windows | HIGH | pyproject.toml: Python 3.13 only, Windows not in CI | Silent bugs on declared dev platform | Add Windows CI job |
| I-4 | `interceptors/__init__.py` `__all__` non-functional | LOW | __init__.py declares names not imported | `from pramanix.interceptors import X` fails | Add imports or remove `__all__` |
| I-5 | K8s webhook no cluster test | MEDIUM | webhook.py unit-tested only | TLS, registration, real payload format unknown | Kind/Minikube e2e test in CI |

### Testing realism gaps

| # | Title | Severity | Evidence | Impact | To close |
|---|---|---|---|---|---|
| T-1 | Coverage hunting files inflate metric | HIGH | 8 files named test_coverage_* | 98% metric overstates behavioral confidence | Remove gap-filler tests, replace with scenario tests |
| T-2 | `async-process` not tested on Windows | HIGH | CI matrix = Linux only | Silent mode failure on Windows | Windows CI job |
| T-3 | Kafka unit tests no backpressure | MEDIUM | stub producer, no real broker | Overflow behavior unvalidated in unit suite | Already addressed in testcontainers integration tests |
| T-4 | LLM translator tested via HTTP interception only | MEDIUM | respx interception in translator tests | Real LLM API behavior not validated | Requires real API key — document and skip in CI |

### Scale/performance gaps

| # | Title | Severity | Evidence | Impact | To close |
|---|---|---|---|---|---|
| SC-1 | P50 just above 5ms target | MEDIUM | latency_results.json `"passed": false`, P50=5.235ms | Target may not be achievable consistently | Profile and optimize hot path or relax target |
| SC-2 | O(n) eviction in governance subsystems | MEDIUM | `list.pop(0)` in memory/, provenance.py, lifecycle/ | Quadratic degradation under sustained write volume | Replace list with `collections.deque` |
| SC-3 | Concurrency limiter needs 10 samples before shedding | LOW | worker.py `AdaptiveConcurrencyLimiter` | First 9 slow requests not shed | Configurable minimum sample count |
| SC-4 | Benchmark not in CI | LOW | Results in repo from local run | Reproducibility unknown | Add nightly benchmark job result archival |

### Enterprise-readiness gaps

| # | Title | Severity | Evidence | Impact | To close |
|---|---|---|---|---|---|
| E-1 | Not on PyPI | CRITICAL | pyproject.toml version 1.0.0, no dist/ | Cannot be installed by users | Publish to PyPI |
| E-2 | Single Python version (3.13 only) | HIGH | pyproject.toml `python = ">=3.13,<4.0"` | Excludes enterprises on 3.11 or 3.12 | Lower minimum to 3.11 with compatibility testing |
| E-3 | No multi-cloud integration tests | HIGH | All cloud providers fake-backed | Real cloud deployment unvalidated | Staging environment integration tests |
| E-4 | No SLA definition | MEDIUM | No p99 SLA stated beyond benchmark targets | Customers cannot plan capacity | Define and publish p50/p99 targets by mode |
| E-5 | No migration path for governance subsystems to prod | HIGH | All beta subsystems in-memory only | Cannot use IFC/Oversight in regulated production | Durable backends for all governance subsystems |

### Usability gaps

| # | Title | Severity | Evidence | Impact | To close |
|---|---|---|---|---|---|
| U-1 | `Field()` positional arg traps | MEDIUM | `Field(name, python_type, z3_sort)` — swapping 2/3 fails at runtime | Developer errors not caught by IDE | Add keyword-only args or field type enforcement |
| U-2 | Cloud provider not re-exported from top-level | LOW | `from pramanix import AwsKmsKeyProvider` fails | Footgun for new users | Re-export from `__init__.py` or document prominently |
| U-3 | `is_business_hours()` non-obvious weekday encoding | LOW | epoch//86400 % 7 where 0=Thursday | Silent day-of-week bugs | Document explicitly in docstring with example |

### Documentation truthfulness gaps

| # | Title | Severity | Evidence | Impact | To close |
|---|---|---|---|---|---|
| D-1 | FlowRule glob claim | HIGH | flow_policy.py vs docstring | Developers write broken flow policies | Fix implementation or fix docstring |
| D-2 | Coverage gate discrepancy | MEDIUM | pyproject.toml 98% vs CI 95% | Users see 98% gate but 95% is enforced | Align the two |
| D-3 | "Stub" integrations label for implemented adapters | LOW | KNOWN_GAPS.md § 8 calls CrewAI/DSPy/etc. stubs | They are not stubs — they are implemented | Reclassify as "implemented, untested against real framework" |

### Release/ops gaps

| # | Title | Severity | Evidence | Impact | To close |
|---|---|---|---|---|---|
| R-1 | PyPI publication | CRITICAL | No dist/ directory, no CI publish step | Zero installability | Publish |
| R-2 | No signing key rotation tested | MEDIUM | rotate_key() raises NotImplementedError in 4 of 7 providers | Key rotation in production untested | Implement rotation for at least one provider |
| R-3 | Audit sink delivery not guaranteed | MEDIUM | Overflow = silent drop in KafkaAuditSink | Decisions lost silently under load | DLQ for overflowed decisions or backpressure |
| R-4 | `pramanix doctor` Redis check conditional on env var | LOW | Doctor skips Redis check without `PRAMANIX_REDIS_URL` | False-clean health check | Always attempt check if Redis-backed components configured |

---

## 20. Maturity Scorecard

Scale: 0 = not present, 1 = placeholder/stub, 2 = partial, 3 = functional, 4 = solid, 5 = exceptional

| Dimension | Score | Justification |
|---|---|---|
| Architecture cohesion | 4/5 | Clear subsystem boundaries; leaky: verify_async duplication, governance isolation |
| Core verification correctness | 5/5 | Two-phase Z3, per-invariant attribution, fail-closed, deterministic — genuinely excellent |
| Policy DSL quality | 4/5 | Elegant, safe, extensible; minor: weekday encoding, Meta non-inheritance |
| Fail-closed guarantee | 5/5 | Adversarially tested across 11 exception types; Decision invariant enforced in __post_init__ |
| Test rigor (core) | 4/5 | Real Z3, real Pydantic, real infrastructure, Hypothesis property tests; padded by coverage hunters |
| Test rigor (integrations) | 2/5 | Real for FastAPI/LangChain; untested against real for 5 major adapters |
| Security maturity | 3/5 | Strong core (HMAC IPC, timing pad, injection defense); gaps: pickle RCE, FlowRule mismatch, cloud KMS |
| Cryptographic auditability | 3/5 | Real signatures, real Merkle; iat removed, restart breaks oversight HMAC, eviction gap in provenance |
| Governance depth | 2/5 | All 6 subsystems implemented in isolation; no Guard coupling; all in-memory only |
| Observability | 3/5 | Prometheus + OTel + structlog; secrets redaction; gaps: benchmark not in CI, no distributed tracing |
| Enterprise integration maturity | 2/5 | 5 of 9 adapters untested against real frameworks; cloud providers fake-backed; not on PyPI |
| Scalability readiness | 3/5 | 100M decision benchmark run; circuit breaker; O(n) governance evictions; async-process Windows gap |
| Operational readiness | 2/5 | Doctor CLI, release checklist, Dockerfiles, Trivy scan; not on PyPI; no real production deployments |
| Developer experience | 3/5 | Clean DSL, good errors; multiple footguns (Field args, Meta inheritance, cloud import) |
| Documentation truthfulness | 4/5 | KNOWN_GAPS.md is honest; FlowRule glob mismatch; coverage gate discrepancy; recently corrected DSL names |
| Ecosystem competitiveness | 2/5 | Not on PyPI; narrow domain; adapters untested; no GUI policy authoring; no community |

**Weighted average: ~3.1/5** — A serious, well-engineered research-grade to pre-production kernel with an incomplete platform layer.

---

## 21. Final Verdict

Pramanix is a **high-quality formal verification kernel with an incomplete platform wrapper**.

The Z3-backed enforcement core — the Policy DSL, transpiler, solver, worker, and Decision model — is at a level of engineering sophistication and test coverage that exceeds every comparable open-source guardrail SDK. The two-phase solve strategy with per-invariant attribution, the HMAC-sealed IPC, the timing oracle mitigation, the second-preimage-protected Merkle tree, and the adversarially-verified fail-closed guarantee are genuine technical contributions, not marketing claims.

The platform layer — the governance subsystems, the cloud integrations, the five newer framework adapters, the operational tooling — is present and non-trivially implemented, but is not validated end-to-end, has no persistent backing for governance state, and has no public availability.

In precise terms:

- **As a formal policy enforcement primitive for structured action validation in a controlled deployment (single host, known framework, sync or async-thread mode):** production-plausible with known risks documented in KNOWN_GAPS.md

- **As a full enterprise guardrail platform (multi-cloud, multi-replica, regulated industries, governance subsystems, distributed deployment):** not yet production-ready — requires persistent governance backends, validated cloud paths, and PyPI publication

- **As a research contribution to AI safety infrastructure:** substantive and technically correct in its core claims

The trajectory is clear and the foundation is strong. The gap between the current state and production-enterprise readiness is real but is primarily an operational and integration gap, not a fundamental architectural one. The core can be trusted; the platform needs time.

---

## 22. Appendix A: Feature Reality Matrix

| Feature | Code status | Test status | Validation realism | Prod confidence | Notes |
|---|---|---|---|---|---|
| Z3 policy verification (sync) | Implemented | Strongly tested | Real Z3 | High | Core feature |
| Z3 policy verification (async-thread) | Implemented | Tested | Real thread pool | High | |
| Z3 policy verification (async-process) | Implemented | Tested (Linux) | Real process pool | Medium | Windows untested |
| Policy DSL | Implemented | Strongly tested | Real AST + real Z3 | High | |
| Two-phase attribution | Implemented | Property-tested | Real Z3 unsat_core | High | |
| Fail-closed guarantee | Implemented | Adversarially tested | 11 exception types | High | |
| HMAC IPC | Implemented | Unit-tested | Real HMAC | High | |
| Timing pad | Implemented | Timing-tested | Real asyncio sleep | High | |
| Policy fingerprinting | Implemented | Unit-tested | Real SHA-256 | Medium | Omits python_type |
| Ed25519 signing | Implemented | Unit-tested | Real cryptography | High | |
| HMAC-SHA256 signing | Implemented | Unit-tested | Real HMAC | High | |
| Merkle anchoring | Implemented | Strongly tested | Real SHA-256 | High | |
| Merkle second-preimage protection | Implemented | Unit-tested | Real hash | High | |
| Redis token verifier | Implemented | Fake-backed | fakeredis | Medium | |
| SQLite token verifier | Implemented | Strongly tested | Real SQLite WAL | High | |
| Postgres token verifier | Implemented | Duck-typed stub + testcontainers | Real Postgres (int. test) | High | |
| InMemory token verifier | Implemented | Unit-tested | Real threading.Lock | High | Not restart-durable |
| Fast-path pre-screen | Implemented | Unit-tested | Real Decimal | High | |
| Injection defense (5-layer) | Implemented | Strongly tested | Real regex + real Z3 | High | |
| Dual-model consensus | Implemented | HTTP-intercepted | respx | Medium | |
| CalibratedScorer | Implemented | Unit-tested | Real sklearn | Medium | Pickle RCE gap |
| Adaptive circuit breaker | Implemented | Strongly tested | fakeredis for distributed | High (unit), Medium (distributed) | |
| Distributed circuit breaker | Implemented | Fake-backed | fakeredis | Medium | |
| FastAPI middleware | Implemented | Strongly tested | Real Starlette | High | |
| LangChain adapter | Implemented | Strongly tested | Real langchain-core | High | |
| LlamaIndex adapter | Implemented | Tested | Real llama-index-core | Medium | |
| AutoGen adapter | Implemented | Tested | Real pyautogen | Medium | |
| CrewAI adapter | Implemented | Tested (non-crewai path) | Real Guard, no real CrewAI | Low-Medium | Not tested with real crewai |
| DSPy adapter | Implemented | Tested (non-dspy path) | Real Guard, no real DSPy | Low-Medium | Not tested with real dspy |
| Haystack adapter | Implemented | Tested (non-haystack path) | Real Guard, no real Haystack | Low-Medium | |
| PydanticAI adapter | Implemented | Tested (non-pydantic-ai path) | Real Guard, no real pydantic-ai | Low-Medium | |
| Semantic Kernel adapter | Implemented | Tested (non-sk path) | Real Guard, no real SK | Low-Medium | |
| gRPC interceptor | Implemented | Weakly tested | Stub gRPC types | Low | |
| Kafka consumer interceptor | Implemented | Weakly tested | Stub Kafka types | Low | |
| Kafka audit sink (unit) | Implemented | Stub-backed | Stub producer | Medium | |
| Kafka audit sink (integration) | Implemented | Testcontainers | Real Kafka broker | High | |
| S3 audit sink (unit) | Implemented | Stub-backed | Stub client | Medium | |
| S3 audit sink (integration) | Implemented | LocalStack | Real S3 API | High | |
| AWS KMS provider | Implemented | Stub-backed | Injected fake | Low | |
| Azure Key Vault provider | Implemented | Stub-backed | Injected fake | Low | |
| GCP Secret Manager provider | Implemented | Stub-backed | Injected fake | Low | |
| HashiCorp Vault provider | Implemented, fragile | Stub-backed | Injected fake | Low | Unguarded KeyError |
| IFC enforcer | Implemented | Unit-tested | Real Python | Medium | No Guard coupling; glob mismatch |
| Privilege scope | Implemented | Unit-tested | Real Python | Medium | No Guard coupling |
| Oversight workflow | Implemented | Unit-tested | Real Python | Low | In-memory only |
| Secure memory | Implemented | Unit-tested | Real Python | Low | O(n) eviction, no persistence |
| Policy lifecycle diff | Implemented | Unit-tested | Real Python | Medium | |
| Shadow evaluator | Implemented | Unit-tested | Real Guard | Medium | O(n) eviction |
| Provenance chain | Implemented | Unit-tested | Real HMAC | Medium | Post-eviction integrity gap |
| Compliance reporter | Implemented | Unit-tested | Real Python | Medium | |
| K8s admission webhook | Implemented | Unit-tested | Synthetic payload | Low | |
| CLI (doctor, simulate, etc.) | Implemented | Strongly tested | Real subprocess | High | |
| Prometheus metrics | Implemented | Unit-tested | Real prometheus_client | High | |
| OTel tracing | Implemented | Monkeypatched | `_OTEL_AVAILABLE` flag | Medium | |
| Structlog with redaction | Implemented | Strongly tested | Real structlog | High | |

---

## 23. Appendix B: Integration Reality Matrix

| Adapter | Framework tested | Test type | Verdict |
|---|---|---|---|
| `PramanixMiddleware` (FastAPI) | Real Starlette TestClient | Integration, unit | Genuine integration |
| `PramanixGuardedTool` (LangChain) | Real langchain-core | Integration, unit | Genuine integration |
| `PramanixFunctionTool` (LlamaIndex) | Real llama-index-core | Integration | Genuine integration |
| `PramanixToolCallback` (AutoGen) | Real pyautogen | Integration | Genuine integration |
| `PramanixCrewAITool` (CrewAI) | No real crewai in CI | Unit (non-crewai mode) | Implemented, unvalidated against real framework |
| `PramanixGuardedModule` (DSPy) | No real dspy in CI | Unit (non-dspy mode) | Implemented, unvalidated |
| `HaystackGuardedComponent` (Haystack) | No real haystack in CI | Unit (non-haystack mode) | Implemented, unvalidated |
| `PramanixPydanticAIValidator` (PydanticAI) | No real pydantic-ai in CI | Unit | Implemented, unvalidated |
| `PramanixSemanticKernelPlugin` (SK) | No real SK in CI | Unit | Implemented, unvalidated |
| `PramanixGrpcInterceptor` | No real grpcio in CI | Unit (synthetic types) | Implemented, fragile |
| `PramanixKafkaConsumer` | No real confluent-kafka in CI (unit) | Unit (stub) / Testcontainers (int.) | Mixed: consumer unit=stub, sink=real |
| `AdmissionWebhook` (K8s) | No real cluster | Unit (synthetic payload) | Implemented, unvalidated |
| `AwsKmsKeyProvider` | Injected fake client | Unit | Implemented, fake-backed |
| `AzureKeyVaultKeyProvider` | Injected fake client | Unit | Implemented, fake-backed |
| `GcpKmsKeyProvider` | Injected fake client | Unit | Implemented, fake-backed |
| `HashiCorpVaultKeyProvider` | Injected fake client | Unit | Implemented, fake-backed, fragile KeyError |
| `KafkaAuditSink` | Stub (unit) + testcontainers (int.) | Both | Real broker validated in integration |
| `S3AuditSink` | Stub (unit) + LocalStack (int.) | Both | Real S3 API validated in integration |
| `SplunkHecAuditSink` | Stub client | Unit | Implemented, fake-backed |
| `DatadogAuditSink` | Stub API client | Unit | Implemented, fake-backed |
| `RedisDistributedBackend` | fakeredis | Unit | Implemented, fake-backed |
| `RedisExecutionTokenVerifier` | fakeredis | Unit | Implemented, fake-backed |
| `PostgresExecutionTokenVerifier` | Duck-typed stub + testcontainers | Both | Real Postgres in integration |

---

## 24. Appendix C: Mock/Stub/Fake/Simulation Findings

### MagicMock
- **Count:** 1 import in `tests/unit/test_framework_adapters.py`
- **Usage:** Creates mock adapters for coverage testing of framework adapter error paths
- **Assessment:** Minimal, targeted, acceptable — one file in a 150-file suite

### AsyncMock
- **Count:** 0 actual usages; mentioned only in `real_protocols.py` docstrings explaining what it replaces
- **Assessment:** Clean — the explicit design decision to replace AsyncMock with real coroutines is followed

### `from unittest.mock import patch`
- **Count:** ~20 files
- **Usage patterns:**
  - Module-level swap: `with patch.dict(sys.modules, {"asyncpg": mock_pkg})` — replaces an entire module
  - Attribute swap: `monkeypatch.setattr(guard_pipeline, "_OTEL_AVAILABLE", False)` — replaces a flag
  - Environment swap: `monkeypatch.setenv("PRAMANIX_ENV", "production")`
- **Assessment:** All usages are module-swapping (testing optional dependency paths) or environment patching — NOT object method substitution. This is the legitimate use of patch.

### fakeredis
- **Count:** Used in ~15 test files (redis circuit breaker unit tests, redis token verifier unit tests)
- **Usage:** `fakeredis.FakeRedis()` and `fakeredis.aioredis.FakeRedis()` — fully compatible Redis API implementation with Lua script support (`extras = ["lua"]`)
- **Assessment:** Appropriate. fakeredis is a well-maintained Redis emulator. The limitations (no persistence, no clustering, no network latency) are acknowledged by the corresponding integration tests that use real testcontainers Redis.

### respx
- **Count:** ~10 test files in translator tests
- **Usage:** HTTP client transport interception for `httpx.AsyncClient` calls to LLM APIs
- **Assessment:** Appropriate for LLM API testing where real API keys are not available in CI. Does not test real LLM behavior (token streaming, rate limiting, model output variation) but tests the translator's parsing and consensus logic correctly.

### testcontainers
- **Count:** 21 integration test files
- **Usage:** Real Docker containers — Kafka broker, PostgreSQL, Redis, LocalStack S3
- **Assessment:** Genuine integration testing. These tests exercise real network calls, real broker responses, real persistence semantics. This is the strongest evidence of production-realism in the test suite.

### Duck-typed stubs in `real_protocols.py`
- **Purpose:** Replaces every MagicMock usage with real protocol implementations
- **Stubs present:** 20+ classes covering Guard, AuditSink, Redis client, Kafka producer, HTTP close clients, asyncpg pool/conn
- **Assessment:** This is the correct approach. Each stub has real method bodies, real state tracking, and real error simulation. No call recording or attribute access interception.

### Import guard simulation
- **Pattern:** `monkeypatch.setitem(sys.modules, "asyncpg", None)` — tests ConfigurationError when optional dep missing
- **Files:** ~10 unit tests for optional-dependency guards
- **Assessment:** Correct approach for testing import guards without installing the optional package.

### Artificial environments
- **`PRAMANIX_ENV=production`**: Set in ~20 tests to exercise production warning paths
- **Worker warmup bypasses**: Some tests disable warmup via `worker_warmup=False` to speed up test runs
- **`solver_timeout_ms`** fixture: Shared conftest fixture reduces solver timeout for faster tests

---

## 25. Appendix D: High-Risk Unknowns

The following areas do not have sufficient evidence in the repository to make strong claims:

1. **Performance under real concurrent load.** The 100M decision benchmark used 18 workers running a single policy with synthetic data. Performance with many different active policies, Pydantic model variation, LRU cache contention, and concurrent circuit breaker state changes under real traffic is unknown.

2. **Z3 memory behavior on Linux over sustained time.** The benchmark ran with `max_decisions_per_worker=10,000`, but no memory profiling data for `test_memory_stability.py` (excluded from default CI run) is included. Z3's native heap behavior over millions of context create/destroy cycles on Linux is not characterized in the repository.

3. **`async-process` mode on Windows.** Zero CI evidence. The Windows `spawn` semantics differ fundamentally from Linux. The PPID watchdog uses Unix signal mechanisms — whether this works correctly on Windows is unverified from repository evidence.

4. **CrewAI/DSPy/Haystack/PydanticAI/SemanticKernel API compatibility.** All five adapters were implemented against framework versions available at development time. These frameworks release frequently and break APIs regularly. Current compatibility is unverifiable from the repository.

5. **Cloud KMS under real IAM/network conditions.** All four cloud providers pass tests with injected stubs. Real credential rotation, token expiry, network timeouts, regional failover, and KMS quota behavior are entirely uncharacterized.

6. **Redis cluster behavior for distributed circuit breaker.** `RedisDistributedBackend` uses sorted sets and pubsub. Behavior under Redis cluster mode (hash slot routing, pubsub limitations in cluster mode) is not tested and likely requires changes.

7. **Multi-replica token deduplication latency.** `RedisExecutionTokenVerifier` uses SETNX — correct for single Redis instance. Under Redis Sentinel or cluster with asynchronous replication, a brief replica promotion window could allow duplicate token consumption. This is a known Redis consistency limitation not addressed in the code.

8. **Hypothesis property test coverage completeness.** The property tests use Hypothesis with 500–1,000 examples per test group under the default profile. Under the `ci` profile, Hypothesis may run fewer examples. Whether the 13 test groups constitute a complete property specification for the DSL is not provable from the repository.

9. **LLM consensus strictness adequacy.** The `ConsensusStrictness.SEMANTIC` mode uses `Decimal(str(v))` normalization and `casefold()` for agreement checking. Whether this semantic agreement is sufficient to catch substantively different intents that happen to normalize to the same string is an open question requiring domain-specific evaluation.

10. **Nightly benchmark CI results.** The CI workflow defines a nightly benchmark job, but no historical results from this job are in the repository. Whether the P99 < 15ms gate is consistently met in the CI environment is unknown.

---

## 26. Threat Model — STRIDE Analysis

This section applies the STRIDE threat classification to Pramanix's actual trust boundaries and data flows, derived from reading guard.py, worker.py, execution_token.py, translator/, audit/, and key_provider.py. This is not a theoretical exercise — each threat is tied to a specific code path.

### Trust boundaries

```text
┌─────────────────────────────────────────────────────────┐
│  Caller process / application code                      │
│    guard.verify(intent=dict, state=dict)                │
└────────────────────┬────────────────────────────────────┘
                     │  Python call — shared address space
┌────────────────────▼────────────────────────────────────┐
│  Guard kernel (guard.py, solver.py, decision.py)        │
│    Trust boundary: Decision.__post_init__ invariant     │
│    Trust boundary: _RESULT_SEAL_KEY HMAC check          │
└────────────────────┬────────────────────────────────────┘
          ┌──────────┴──────────┐
          │ ProcessPoolExecutor │  ← HMAC-sealed IPC boundary
          │ (worker.py)         │
          └──────────┬──────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│  Worker subprocess                                      │
│    Receives: (policy_cls, values_dict, timeout_ms)      │
│    Returns: HMAC-sealed (status, allowed, attribution)  │
└─────────────────────────────────────────────────────────┘
          ┌──────────────────────────────────────────┐
          │ External services (trust boundary: network)│
          │   Redis (token store, circuit breaker)    │
          │   Kafka / S3 / Splunk / Datadog (sinks)   │
          │   Cloud KMS (AWS, Azure, GCP, Vault)      │
          │   LLM APIs (OpenAI, Anthropic, Cohere)    │
          └──────────────────────────────────────────┘
```

### STRIDE threat table

| # | Threat | Component | Attack scenario | Current mitigation | Residual risk |
|---|---|---|---|---|---|
| ST-1 | **Spoofing** — forge ALLOW | Worker process | Compromised worker returns fabricated `allowed=True` | `_RESULT_SEAL_KEY` HMAC in `_worker_solve_sealed()`; `hmac.compare_digest`; `_EphemeralKey.__reduce__` raises TypeError | **LOW** — HMAC is real, key is non-picklable |
| ST-2 | **Spoofing** — replay signed decision | `DecisionSigner` | Replay historical `SignedDecision` with valid HMAC-SHA256 | `iat` was removed (v0.5.x); no nonce or `jti` | **MEDIUM** — no timestamp in signed payload; replays indistinguishable |
| ST-3 | **Spoofing** — LLM prompt injection | Translator pipeline | Adversarial prompt causes LLM to extract wrong intent | 5-layer filter + dual-model consensus + post-consensus injection scoring | **LOW** — defense-in-depth; CalibratedScorer adds learned gate |
| ST-4 | **Tampering** — modify Decision after construction | `decision.py` | Mutate `allowed` field after `verify()` returns | Frozen dataclass (`@dataclass(frozen=True)`); hash bound at construction | **LOW** — immutable in Python; not enforced at language boundary |
| ST-5 | **Tampering** — modify scorer file | `CalibratedScorer` | Replace `.pkl` file with malicious pickle payload | Documented warning only; no HMAC integrity check on file | **HIGH** — real RCE via `pickle.load()` without verification |
| ST-6 | **Tampering** — corrupt Merkle archive | `MerkleArchiver` | Modify `.merkle.archive.YYYYMMDD` file to remove incriminating decisions | `verify_archive(path)` detects; plaintext files without encryption | **MEDIUM** — offline verification works; real-time detection requires periodic re-verification |
| ST-7 | **Repudiation** — deny an ALLOW decision was issued | Audit pipeline | Agent claims it never received ALLOW for a destructive action | Ed25519 signature + Merkle inclusion proof | **LOW** — both signature and Merkle chain must be present; non-repudiable |
| ST-8 | **Repudiation** — deny oversight approval | `InMemoryApprovalWorkflow` | Deny that a `request_approval()` was approved | HMAC-tagged `OversightRecord`; key lost on restart | **HIGH** — records unverifiable post-restart; HMAC key not persisted |
| ST-9 | **Information disclosure** — decision content in logs | `structlog` | Sensitive field values (PII, amounts) leak into structured logs | `_redact_secrets_processor` as FIRST processor; 17 regex patterns | **LOW** — redaction is at log construction, not filtering |
| ST-10 | **Information disclosure** — HMAC key exfiltration | `_EphemeralKey` | Extract `_RESULT_SEAL_KEY` from process memory | Key is `bytes` in process memory; non-picklable | **LOW in-process; MEDIUM with process dump** — physical access or coredump exposure |
| ST-11 | **Information disclosure** — cloud KMS error messages | `HashiCorpVaultKeyProvider` | `KeyError` on missing field leaks path structure | Raw `KeyError` propagates | **LOW** — path structure exposed in error message only |
| ST-12 | **Denial of service** — formula explosion | Solver | Craft policy formula that exhausts Z3 rlimit | `rlimit` bound via `s.set("rlimit", ...)` + `solver_timeout_ms` | **LOW** — both resource and time bounded |
| ST-13 | **Denial of service** — Kafka queue overflow | `KafkaAuditSink` | Sustained audit volume exceeds bounded queue (10,000 entries) | Overflow counter incremented; decisions silently dropped | **MEDIUM** — silent drop under burst; no DLQ |
| ST-14 | **Denial of service** — circuit breaker stuck open | `AdaptiveCircuitBreaker` | Three OPEN episodes → ISOLATED; requires manual `reset()` | `ISOLATED` state requires human intervention | **LOW** — intended behavior; surfaces real failures |
| ST-15 | **Elevation of privilege** — policy bypass via None field | `Field` + Pydantic | Pass `None` for a required field to skip constraint | Pydantic strict mode blocks at validation layer before Z3 | **LOW** — Pydantic `model_config = ConfigDict(strict=True)` |
| ST-16 | **Elevation of privilege** — override IFC gate | `FlowEnforcer` | Call `Guard.verify()` without calling `flow_enforcer.gate()` afterward | No automatic coupling — developer must wire manually | **HIGH** — no enforcement if developer forgets; FlowRule glob mismatch compounds this |
| ST-17 | **Elevation of privilege** — forge Ed25519 public key | `PramanixVerifier` | Supply attacker-controlled public key for verification | `key_id = SHA-256[:16]` of public key PEM embedded in decision | **LOW** — key ID mismatch detected during verification |
| ST-18 | **Elevation of privilege** — `async-process` Windows spawn | Worker | Policy class defined inside function is unpicklable; fallback path taken | No fallback path — `PicklingError` propagates to caller as Guard error → BLOCK | **LOW security risk; HIGH operational risk** — fails closed, but silently if worker pool creation fails at startup |

### Attack surface enumeration

**In-process surface (zero-copy, no serialization):**

- `guard.verify(intent: dict, state: dict)` — all inputs from Python caller; Pydantic validation at boundary
- `policy.invariants()` return value — trust assumed; a policy author's bug is not a security threat model item

**IPC surface (process pool mode only):**

- Serialization of `(policy_cls, values_dict, timeout_ms)` via pickle — `values_dict` is already Pydantic-validated before dispatch
- Deserialization of HMAC-sealed `(status, allowed, attribution)` — HMAC verified before use
- Threat: compromised subprocess returning malicious bytes — mitigated by HMAC

**Network surface:**

- Redis (token store / circuit breaker): authentication via `redis://` URL; TLS optional
- LLM APIs (OpenAI, Anthropic): HTTPS; API key from environment variable
- Cloud KMS: IAM-authenticated HTTPS; credentials from environment
- Kafka audit sink: `bootstrap.servers` from config; SASL/SSL optional
- S3 audit sink: boto3 credential chain

**File system surface:**

- `CalibratedScorer.load(path)` — `pickle.load()` with no integrity check — only exploitable if an attacker can write to the scorer file path
- `MerkleArchiver` writes `.merkle.archive.*` files — read back by `verify_archive()` — no write protection
- `PramanixSigner.load_private_key(path, password)` — reads PEM; passphrase-protected; no integrity check beyond PEM decryption

### Threat actor profiles

| Actor | Capability | Primary threat | Primary mitigation |
|---|---|---|---|
| Malicious agent (compromised AI) | Can control `intent` and `state` inputs | Craft inputs that satisfy formal policy while violating intended semantics | Formal policy must be correct; not a guardrail defect |
| Compromised worker subprocess | Can modify return values | Forge ALLOW decision | HMAC-sealed IPC |
| Insider threat (developer) | Can modify policy definitions | Add `E(cls.field) >= 0` invariants that are trivially satisfied | Policy review; fingerprinting |
| Supply chain attacker | Can modify optional deps | Inject malicious code via optional package (crewai, dspy, etc.) | Trivy scan in CI; Poetry lock file |
| Infrastructure attacker (Redis) | Can read/write Redis state | Flip circuit breaker state; replay tokens | Redis authentication; SETNX atomicity |
| File system attacker | Can write to process directory | Replace `CalibratedScorer.pkl` | HMAC-verify scorer file (currently unmitigated) |

---

## 27. Dependency and Supply Chain Risk Assessment

### Hard (non-optional) dependencies

These are installed for every user regardless of which features they use:

| Package | Version pin | Security concern | Assessment |
|---|---|---|---|
| `z3-solver` | `^4.12` | Microsoft Research package; binary extension; no PyPI-level code signing | **CRITICAL** — the entire security claim depends on Z3 correctness; any Z3 bug is a Pramanix bug |
| `pydantic` | `^2.5` | Widely used; excellent security posture | **LOW** risk |
| `structlog` | `^23.2` | Stable logging library | **LOW** risk |
| `prometheus-client` | `^0.19` | Installed for ALL users; imports global metrics registry at import time | **MEDIUM** — side effect: importing pramanix modifies the global Prometheus registry; unexpected for users who don't want metrics |
| `orjson` | `>=3.9` | Binary Rust extension; performance-critical; no practical replacement path | **LOW** risk for security; **MEDIUM** for dependency footprint — binary wheel required for every platform |

**Critical finding:** `prometheus-client` is a hard dependency even though observability is optional by design (`_PROMETHEUS_AVAILABLE` flag exists). Every Pramanix installation imports `prometheus_client`, registering counters in the global registry. If the user's application already uses Prometheus with custom collectors, a duplicate metric registration error can occur at import time. This is a silent coupling that violates the principle of optional dependencies.

**Critical finding:** `orjson` is hard-pinned but has a stdlib JSON fallback in `decision.py`. The hard dependency exists only to guarantee canonical sort order in `decision_hash`. This is a binary Rust wheel that must be built for every target platform — an unnecessary mandatory dependency that should be moved to optional or replaced with `json.dumps(..., sort_keys=True)`.

### Optional dependency security analysis

| Extra | Package | Version | Risk | Notes |
|---|---|---|---|---|
| `translator` | `openai` | `^1.10` | MEDIUM | OpenAI SDK; sends intent data to external API |
| `translator` | `anthropic` | `^0.97` | MEDIUM | Anthropic SDK; pinned to very recent version (^0.97 is unusually high) — breaks with older installs |
| `crypto` | `cryptography` | `>=41.0` | LOW | PyCA cryptography; excellent security posture; binary Rust wheel |
| `aws` | `boto3` | `>=1.34` | MEDIUM | Large transitive dep tree (botocore, urllib3, etc.); credentials must be managed carefully |
| `vault` | `hvac` | `>=2.0` | LOW | HashiCorp Vault client; no binary deps |
| `kafka` | `confluent-kafka` | `>=2.3` | MEDIUM | Binary librdkafka wrapper; platform-specific wheels required |
| `dspy` | `dspy-ai` | `>=2.4` | HIGH | dspy-ai is a research SDK; API breaks frequently; major versions change multiple times per year; no API stability guarantee |
| `crewai` | `crewai` | `>=0.55` | HIGH | Same as dspy — rapid API evolution; `>=0.55` lower bound is already stale |
| `semantic-kernel` | `semantic-kernel` | `>=1.0` | HIGH | Microsoft research SDK; `>=1.0` is broad; SK has broken API multiple times between 1.x minor versions |
| `pydantic-ai` | `pydantic-ai` | `>=0.0.9` | HIGH | Pre-stable SDK (0.x); `>=0.0.9` means any 0.x version — API compatibility window is zero |
| `haystack-ai` | `haystack-ai` | `>=2.0` | MEDIUM | Haystack 2.x is stable but component API evolves; `>=2.0` is broad |

**Supply chain observations:**

1. **Poetry lock file:** No lock file is visible in the repository root. Without a committed `poetry.lock`, every CI run resolves the latest compatible versions within the ranges. A dependency that releases a breaking minor update (or a typosquatted package) could silently enter the build.

2. **Trivy scan in CI:** The CI pipeline includes a Trivy scan stage — evidence of supply chain awareness. However, Trivy scans known CVEs in installed packages; it does not detect behavioral changes or API breaks in allowed version ranges.

3. **z3-solver trust chain:** `z3-solver` is the single most critical dependency. Pramanix's formal verification claim is entirely contingent on Z3's correctness. The Z3 package is published by Microsoft Research as `z3-solver` on PyPI. No independent attestation of the binary wheel's provenance is present in the repository. For high-security deployments, building Z3 from source with a verified commit hash is the correct approach — this is not documented.

4. **`anthropic = "^0.97"` in dev dependencies:** This unusually high version pin suggests the package was written against the very latest Anthropic SDK API. If a user installs the `translator` extra with an older Anthropic SDK, the import succeeds (optional dep) but `AnthropicExtractor` may fail at call time with `AttributeError` or a changed API signature. The lower bound for the production extras should be lower to allow broader compatibility.

5. **`llama-cpp-python` optional dep:** This is a binary-compiled C++ extension with CUDA and Metal variants. The wheel compilation is notoriously fragile across platforms. Including it as a supported optional increases the maintenance burden without evidence of real usage.

### Dependency footprint by installation profile

| Installation | Mandatory packages | Optional packages | Binary deps |
|---|---|---|---|
| `pip install pramanix` | z3-solver, pydantic, structlog, prometheus-client, orjson | None | z3-solver, orjson |
| `pip install pramanix[translator]` | + httpx, openai, anthropic, tenacity | — | + as above |
| `pip install pramanix[all]` | All ~30 packages | — | z3-solver, orjson, cryptography, confluent-kafka, llama-cpp-python |

The `prometheus-client` inclusion in the base install is the most surprising non-obvious dependency. A security-focused library shipping Prometheus instrumentation as mandatory for all users (including those who will never use metrics) is architecturally inconsistent with the principle of least dependency.

---

## 28. API Contract and Stability Analysis

### Public surface classification from `__init__.py`

`src/pramanix/__init__.py` exports 140+ names. The `__stability__` dict categorizes them:

```text
stable:   Guard, Policy, Field, E, Decision, GuardConfig, SolverStatus, ...
beta:     ifc, privilege, oversight, memory, lifecycle, provenance subsystems
experimental: CalibratedScorer, ShadowEvaluator
```

**Finding:** `__stability__` is a runtime Python dict, not a type annotation or enforcement mechanism. No test verifies that the dict's keys match the actual exports in `__all__`. A symbol can be removed from `__init__.py` while remaining listed as `stable` in `__stability__` — no CI gate catches this.

**Finding:** `integrations/*.py` is entirely excluded from the coverage gate (`omit = ["src/pramanix/integrations/*.py"]` in pyproject.toml). The adapters have zero mandatory coverage contribution. This means integration adapter code can be completely broken with zero test failures in the default CI run — it will only surface in the optional extras-smoke stage.

**Finding:** The `pyproject.toml` trove classifier states `"Development Status :: 5 - Production/Stable"`. This is inconsistent with six beta subsystems, missing PyPI publication, and five adapter integrations untested against real frameworks. The classifier should be `4 - Beta` at most.

### Breaking change risk matrix by component

| Component | Public API depth | Change frequency (observed) | Breaking risk | Semantic stability |
|---|---|---|---|---|
| `Guard.verify()` | 3 params (intent, state, token) | Low | LOW | Stable; fail-closed contract is firm |
| `Policy` DSL / `E()` builder | Many operators | Low | LOW | NamedTuple AST is append-only |
| `Decision` fields | Frozen dataclass | Low | MEDIUM | `decision_hash` algorithm changes → downstream verifiers break |
| `GuardConfig` | Frozen dataclass | Medium | MEDIUM | New mandatory fields could break existing callers |
| `Translator` extras | Multiple classes | Medium | HIGH | `AnthropicExtractor`, `OpenAIExtractor` depend on SDK internals |
| `integrations/*.py` | 9 adapter classes | High | HIGH | Upstream framework API changes break adapters silently |
| `key_provider.py` | 4 cloud providers | Low | MEDIUM | Cloud SDK deprecations can break provider calls |
| Beta subsystems | All 6 modules | High | CRITICAL | Explicit beta: no stability guarantee; `FlowRule.matches()` is already wrong |
| `CalibratedScorer` | 2 methods | Low | HIGH | `experimental`; `pickle` format not versioned |
| CLI commands | 5 commands | Low | MEDIUM | CLI output format not versioned; consumers parsing stdout will break |

### API surface issues requiring immediate attention

**Issue 1: `Decision.decision_hash` algorithm is not versioned.**
The hash is computed via `SHA-256(decision_id + status + allowed + violated_invariants + explanation)`. If the computation changes (e.g., to include `policy_fingerprint`), all existing signed decisions become unverifiable. `PramanixVerifier.verify_decision()` recomputes the hash from fields and would produce a different value than the stored signature. No hash algorithm version is embedded in the `Decision` object.

**Issue 2: `FlowRule.matches()` signature is stable but behavior is wrong.**
The method is exported and documented. Its behavior (exact string equality) contradicts its docstring (glob-style). Fixing the behavior is a silent breaking change for callers who accidentally relied on the exact-match behavior. Fixing the docstring without fixing the behavior perpetuates the security gap. There is no good fix that does not break something.

**Issue 3: `verify_async()` is a public API with diverged behavior.**
The async path is tested less thoroughly than the sync path. Any behavioral difference between `verify()` and `verify_async()` (there is at least one known: M-02, the missing `_policy_semver` check in async path) constitutes an undocumented API divergence. Callers who switch between sync and async paths get different semantics silently.

**Issue 4: `__all__` in `interceptors/__init__.py` declares names not imported.**
`from pramanix.interceptors import PramanixGrpcInterceptor` fails with `ImportError`. The `__all__` list claims these are public exports but the `__init__.py` has no import statements. This is a broken public API that will silently fail in user code.

### Versioning assessment

Pramanix is at `1.0.0` in pyproject.toml. Based on the gap inventory:
- Six beta subsystems with no Guard coupling
- Five adapters untested against real frameworks
- `verify_async()` behavioral divergence from `verify()`
- `FlowRule.matches()` semantic mismatch
- Missing PyPI publication

The codebase is not semantically at `1.0.0`. A v1.0 label implies API stability and production readiness. The appropriate label given the evidence is `0.9.0-rc` (release candidate with known gaps). Publishing `1.0.0` to PyPI with these gaps sets incorrect expectations for users.

---

## 29. Engineering Priority Matrix

The following ordered list represents the minimum viable set of changes required before Pramanix can truthfully claim production readiness, ordered by risk-to-fix-cost ratio. Each entry states the specific file and function, the risk if not fixed, and the minimum viable fix.

### P0 — Fix before any production deployment

| # | File:function | Risk | Fix |
|---|---|---|---|
| P0-1 | `src/pramanix/translator/injection_scorer.py:CalibratedScorer.load()` | RCE via pickle; HIGH severity | Compute `HMAC-SHA256(key, file_bytes)` over the file before `pickle.loads()`; raise `IntegrityError` on mismatch |
| P0-2 | `src/pramanix/ifc/flow_policy.py:FlowRule.matches()` | Silent IFC bypass; operators write glob patterns that match nothing | Implement `fnmatch.fnmatch(source_label, self.source) and fnmatch.fnmatch(dest_label, self.dest)` |
| P0-3 | `src/pramanix/interceptors/__init__.py` | `from pramanix.interceptors import X` raises `ImportError` for exported names | Add `from .grpc import PramanixGrpcInterceptor` etc., or remove from `__all__` |
| P0-4 | `src/pramanix/guard.py:verify_async()` | Behavioral divergence from `verify()` (M-02: missing semver check, possibly others) | Extract shared 12-step core into `_verify_core_async()` called by both; do not maintain two trees |

### P1 — Fix before 1.0.0 PyPI publication

| # | File:function | Risk | Fix |
|---|---|---|---|
| P1-1 | `pyproject.toml` | `prometheus-client` imported at `import pramanix` for all users | Move to optional; gate behind `_PROMETHEUS_AVAILABLE` at module level (it already exists for OTEL — apply same pattern) |
| P1-2 | `pyproject.toml` | `orjson` hard dep for canonical hash | Move to optional with stdlib fallback already in decision.py; make fallback the guaranteed path |
| P1-3 | `pyproject.toml` | classifier `"Development Status :: 5 - Production/Stable"` while not on PyPI | Change to `"Development Status :: 4 - Beta"` |
| P1-4 | `src/pramanix/guard.py:_compute_policy_fingerprint()` | Fingerprint omits `python_type`; two inequivalent policies share fingerprint | Include `f.python_type.__qualname__` in the SHA-256 input |
| P1-5 | `src/pramanix/policy.py:Policy` | `vars(cls).get("Meta")` blocks `Meta` inheritance | Replace with MRO traversal: `next((vars(c)["Meta"] for c in type(cls).__mro__ if "Meta" in vars(c)), None)` |
| P1-6 | `src/pramanix/key_provider.py:HashiCorpVaultKeyProvider._refresh_cache()` | Bare `KeyError` on missing field → uninformative crash | Wrap in `try/except KeyError as e: raise ConfigurationError(f"Vault field '{self._field}' not found in secret") from e` |
| P1-7 | `src/pramanix/oversight/workflow.py:InMemoryApprovalWorkflow` | HMAC key lost on restart; oversight records unverifiable | Document as explicitly ephemeral; add `DurableApprovalWorkflow` protocol with Redis reference implementation |
| P1-8 | `src/pramanix/audit/signer.py:VerificationResult` | `issued_at` always 0; replays indistinguishable | Add `jti` (JWT ID) nonce to signed payload so replay detection is possible without timestamp |

### P2 — Fix before enterprise deployment

| # | File:function | Risk | Fix |
|---|---|---|---|
| P2-1 | `src/pramanix/memory/store.py:ScopedMemoryPartition.write()` | `list.pop(0)` is O(n) under sustained write volume | Replace `list` with `collections.deque(maxlen=max_entries)` — O(1) eviction, same semantics |
| P2-2 | `src/pramanix/provenance.py:ProvenanceChain.append()` | Same O(n) eviction | Same fix |
| P2-3 | `src/pramanix/lifecycle/diff.py:ShadowEvaluator` | Same O(n) eviction | Same fix |
| P2-4 | `src/pramanix/provenance.py:ProvenanceChain.verify_integrity()` | First retained record after eviction: prev_hash not checked → silent integrity gap | Emit a signed checkpoint `ProvenanceRecord` with `is_eviction_checkpoint=True` before eviction; `verify_integrity()` treats this as a trust anchor |
| P2-5 | `.github/workflows/` | No Windows CI job; `async-process` mode untested on declared dev platform | Add `windows-latest` runner to CI matrix for unit + worker tests |
| P2-6 | `pyproject.toml:tool.coverage` | `integrations/*.py` excluded from 98% gate; adapters are structurally untested | Remove exclusion; add `extras-installed` CI stage that installs all extras and runs integration tests counting toward gate |
| P2-7 | `pyproject.toml` | `fail_under=98` in config vs `--cov-fail-under=95` in CI | Align: either set CI to 98 or document why the config value is aspirational |
| P2-8 | `src/pramanix/ifc/flow_policy.py`, `privilege/scope.py` | No Guard coupling; governance is opt-in, easy to forget | Implement `GuardConfig(ifc_policy=FlowPolicy(...))` integration point that makes Guard call `FlowEnforcer.gate()` automatically on ALLOW |

### P3 — Required for enterprise feature parity

| # | Description | Effort | Priority rationale |
|---|---|---|---|
| P3-1 | Publish to PyPI (AGPL + commercial) | LOW effort | Single largest adoption blocker; no user can install without git clone |
| P3-2 | Add CI jobs for CrewAI, DSPy, Haystack, PydanticAI, SK with real framework installs | MEDIUM effort | Five adapters are implemented but unvalidated; next framework update may silently break them |
| P3-3 | Implement Redis-backed `DurableApprovalWorkflow` | MEDIUM effort | InMemory oversight is unacceptable for regulated industries |
| P3-4 | Add real staging integration tests for at least one cloud KMS provider (AWS recommended) | HIGH effort | Cloud providers are completely faith-based; real IAM path is uncharacterized |
| P3-5 | Profile and optimize `verify()` hot path to achieve P50 < 5ms reliably | MEDIUM effort | Benchmark self-reports `"passed": false`; margin is thin under OS scheduling variance |
| P3-6 | Lower Python minimum to `>=3.11` with compatibility tests | HIGH effort | Enterprises on 3.11 or 3.12 cannot use Pramanix |
| P3-7 | Move `test_coverage_boost*.py`, `test_coverage_gaps*.py` files to `tests/coverage_artifacts/` and exclude from default run | LOW effort | Coverage padding inflates metrics; scenario-driven tests should drive the gate |

---

## 30. Final Synthesis: What the Code Actually Proves

This section states, without qualification or softening, what a forensic examiner can prove from the repository and what requires trust or extrapolation.

### Proven by direct code inspection

1. **Z3 is called with real constraints.** The transpiler converts DSL nodes to z3.ArithRef/BoolRef/StringVal objects. No mocking of Z3 exists in production code. Solver results come from `z3.Solver.check()`.

2. **Every error path returns `allowed=False`.** `Decision.__post_init__` enforces `allowed=True ↔ status=SAFE` with `ValueError`. Confirmed across 141 `except Exception` handlers — none return `allowed=True`.

3. **HMAC IPC is real.** `_RESULT_SEAL_KEY = _EphemeralKey(secrets.token_bytes(32))` at module level. Worker results are HMAC-SHA256-tagged. `hmac.compare_digest` used for comparison. `_EphemeralKey.__reduce__` raises `TypeError`.

4. **Injection defense is real.** 26 compiled regex patterns covering modern LLM injection attacks. NFKC normalization. Dual-model consensus with semantic strictness levels. Post-consensus injection scoring.

5. **Property tests verify formal properties.** Hypothesis-based tests verify DSL commutativity, monotonicity, and attribution completeness with 500–1,000 examples per group.

6. **Three execution backends work.** `sync`, `async-thread`, `async-process` are all implemented with working code paths tested in CI (Linux).

7. **Real infrastructure is used in integration tests.** Kafka, Postgres, Redis, LocalStack S3 via testcontainers. Real Docker containers, real network calls, real persistence.

### Requires trust (not proven by code alone)

1. **Z3's soundness and completeness.** The entire formal verification claim depends on Z3 being correct. Z3 is a mature, well-tested SMT solver, but bugs in Z3 are Pramanix bugs. No independent verification of Z3's correctness is possible from this repository.

2. **Injection defense adequacy.** The 26 regex patterns and dual-model consensus represent a state-of-the-art defense, but a sufficiently novel attack may evade them. Defense adequacy is measured against a threat model, not a fixed rule set.

3. **Policy semantic correctness.** The DSL enforces that invariants are formally satisfied by the provided values. It does not verify that the invariants express the developer's actual intent. A policy that allows `amount <= 100_000` when the intent was `amount <= 1000` will produce ALLOW for values the developer did not expect — the formal system is correct; the policy is wrong.

4. **Cloud KMS paths work.** All four cloud providers are tested with injected stubs. Real IAM paths are unverified.

5. **Five adapters work with real frameworks.** CrewAI, DSPy, Haystack, PydanticAI, SemanticKernel are implemented but unvalidated against real installed packages.

### The honest summary

The core verification kernel is among the most carefully engineered components in the open-source AI safety space. The governance wrapper is incomplete. The operational layer has significant gaps. The repository represents a research-grade foundation that is approximately 18–24 months of focused engineering from being a competitive enterprise platform.

The kernel can be deployed today in a controlled environment with known constraints. The platform requires the P0 and P1 fixes as prerequisites for any public release.

---

*End of forensic audit. All conclusions derived from direct repository inspection. Code is authoritative. Total sections: 30.*
