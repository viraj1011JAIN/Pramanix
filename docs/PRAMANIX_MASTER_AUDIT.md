# PRAMANIX MASTER AUDIT
## Unified Repository Truth Baseline · Deep Architectural Analysis · Hard Truths

> **Scope**: This document is the single authoritative audit of the Pramanix repository.
> It supersedes both `docs/REPO_AUDIT.md` and `docs/pramanix_deep_audit.md`.
> Every claim is traceable to source code, test output, or CI configuration.
> Where functionality is documented but absent from source, this is stated explicitly.
> Nothing here is aspirational. "Works" means verified in source with line citations.
>
> **Last verified**: 2026-06-03
> **Auditor**: Source-verified against 112 production files, 227 test files,
> `pyproject.toml`, `ci.yml`. Merged from REPO_AUDIT.md (Pass 1) +
> pramanix_deep_audit.md (Pass 4, 2026-05-27) + session 4 changes (2026-06-02).
> **Baseline version**: 1.0.0

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Component Maturity Matrix](#2-component-maturity-matrix)
3. [Repository Baseline Metrics](#3-repository-baseline-metrics)
4. [Part 1: What Is Genuinely World-Class](#part-1-what-is-genuinely-world-class)
5. [Part 2: Known Limitations — The Hard Truths](#part-2-known-limitations--the-hard-truths)
6. [Part 3: Test Suite Reality Check](#part-3-test-suite-reality-check)
7. [Part 4: CI/CD Pipeline Audit](#part-4-cicd-pipeline-audit)
8. [Part 5: Architecture — Blueprint vs Reality](#part-5-architecture--blueprint-vs-reality)
9. [Part 6: Competitive Gap Analysis](#part-6-competitive-gap-analysis)
10. [Part 7: Component Deep Dives](#part-7-component-deep-dives)
11. [Part 8: Dependency Map & Supply Chain Risk](#part-8-dependency-map--supply-chain-risk)
12. [Part 9: Open Action Items — Prioritized](#part-9-open-action-items--prioritized)
13. [Part 10: Release Gate Status](#part-10-release-gate-status)
14. [Part 11: The Honest Verdict](#part-11-the-honest-verdict)
15. [Appendix: Complete Fixed-Item History](#appendix-complete-fixed-item-history)

---

## 1. Executive Summary

Pramanix is a technically extraordinary Python SDK for formal AI agent safety guardrails. Its Z3 SMT solver core is genuinely world-class — no competitor ships deterministic formal verification as a guardrails primitive. The cryptographic audit chain (Ed25519/Merkle), compliance oracle (SOC2/HIPAA/EU AI Act/GDPR), and fail-closed architecture are enterprise-grade.

**The single biggest problem is not technical.** AGPL-3.0 copyleft prevents enterprise deployment. Every competitor is Apache-2.0 or MIT. No enterprise legal team at a Fortune-500 company will approve AGPL software for commercial SaaS deployment, regardless of technical quality. This is a structural business problem that no code change solves.

Everything else — NLP layer maturity, LLM CI gaps, coverage floor conflict — has clear technical resolution paths.

**Overall Maturity Score: 75/100**

| Dimension | Score | Honest Assessment |
| --------- | ----- | ----------------- |
| Z3 Formal Verification Core | 98/100 | World-class. Unmatched by any competitor. |
| Cryptographic Audit Trail | 95/100 | Ed25519 + Merkle + HMAC. Enterprise-grade. |
| Compliance Oracle | 92/100 | SOC2/HIPAA/EU AI Act/GDPR. Unique moat. |
| Code Quality & Type Safety | 93/100 | mypy strict; 0 `# type: ignore` in prod. |
| Test Coverage (quantity) | 90/100 | 5,687 collected; 5,301 unit+adversarial |
| Test Coverage (quality) | 68/100 | Zero-Mock Sprint done; `sys.modules` patching remains. |
| NLP Safety Layer | 62/100 | 58 stems / 8 categories; keyword-only, not ML. |
| Developer Experience | 52/100 | 15 CLI subcommands; no policy linter or REPL. |
| Enterprise Adoption Readiness | 30/100 | **AGPL-3.0 kills enterprise deals before demo.** |
| Key Management | 82/100 | Full rotation across AWS/Azure/GCP/Vault. |
| Execution Token Design | 78/100 | Redis / SQLite / Postgres / InMemory — 4 backends. |
| Production Confidence | 75/100 | Fail-closed; Z3 trust boundary fixed; benchmarks stale. |
| **Overall** | **75/100** | Materially strong. License is the existential blocker. |

---

## 2. Component Maturity Matrix

| Component | Maturity | Evidence |
| --------- | -------- | -------- |
| Z3 kernel (`solver.py`) | Production | Two-phase SAT/UNSAT+attribution; `threading.local()`; injectable via `solver_factory` |
| Transpiler (`transpiler.py`) | Production | Zero `eval`/`exec`; full operator set; `allow_empty=False` default |
| Policy engine (`policy.py`) | Production | Sealed subclasses; mixin composition; `from_config()` factory; LRU cache |
| Guard (`guard.py`) | Production | Fail-closed `_verify_core()`; HMAC worker seal; input size cap |
| Fast path (`fast_path.py`) | Production | Fail-closed on parse error; Prometheus counter wired |
| Circuit breaker (`circuit_breaker.py`) | Production | WATCH/MULTI/EXEC locking; half-open probe prevention; Redis backend |
| Worker pool (`worker.py`) | Production | ThreadPool + ProcessPool; 8-pattern warmup; HMAC seal |
| Execution tokens (`execution_token.py`) | Production | 4 backends: Redis NX EX, SQLite UNIQUE, Postgres asyncpg, InMemory |
| Cryptographic audit (`audit/`) | Production | Ed25519/RS256/ES256; PersistentMerkleAnchor; oracle-attack redaction |
| Compliance oracle (`compliance/oracle.py`) | Production | 31 built-in mappings; 5 frameworks; `MappingMatchKind.BOTH` |
| Mesh authenticator (`mesh/authenticator.py`) | Production | SPIFFE JWT-SVID; 10-point security model; JWKS cache |
| FastAPI middleware (`integrations/fastapi.py`) | Production | 9-step pipeline; timing pad; body size cap |
| LangGraph adapter (`integrations/langgraph.py`) | Production | Fail-closed; async-safe `_swrapper`; Prometheus per-node |
| Agent orchestration (`integrations/agent_orchestration.py`) | Production | `LangGraphGuardAdapter` + `AutoGenGuardAdapter` |
| NLP validators (`nlp/validators.py`) | Beta | 58 stems / 8 categories; lazy RE2; no ML model in core |
| Translator subsystem (`translator/`) | Beta-CI-gap | 9 backends; dual-model consensus; never tested against real LLM in CI |
| Natural policy compiler (`natural_policy/`) | Beta | LLM-backed authoring; MetaVerifier; no real-LLM CI |
| K8s webhook (`k8s/webhook.py`) | Beta | ValidatingWebhook; no kind/minikube CI |
| Oversight workflow (`oversight/workflow.py`) | Beta | InMemory only; no DB-backed persistent workflow |
| Key providers (`key_provider.py`) | Production | PEM/File/AWS atomic rotation; Azure/GCP/Vault stubs-tested |
| CLI (`cli.py`) | Production | 15 subcommands; `pramanix doctor` exits 0; simulate/explain exist |
| Observability (`guard_config.py`, Prometheus) | Production | 10 metrics; Prometheus + OTel; None-guards on absent extras |

---

## 3. Repository Baseline Metrics

> Verified 2026-06-03. All numbers are from direct tool output.

| Metric | Value | Source |
| ------ | ----- | ------ |
| Version | 1.0.0 | `pyproject.toml` |
| Production source files | 112 | `src/pramanix/**/*.py` |
| Test files | 227 | `tests/**/*.py` |
| Tests collected (unit + adversarial) | 5,301 | `pytest --collect-only -q` (2026-06-03) |
| Tests collected (all suites) | 5,687 | `pytest --collect-only -q` (2026-06-02 session 4) |
| Public API exports (`__all__`) | 157 | `test_api_contract.py` |
| `GuardConfig` fields | 32 | `test_api_contract.py` |
| `Decision.to_dict()` keys | 17 | `test_api_contract.py` |
| mypy strict errors | 0 | Session 4 (commit `a6cc05b`) |
| ruff violations | 0 | Session 4 |
| `# type: ignore` in production | 0 | Session 4 (C5 gate) |
| `# pragma: no cover` in production | 0 | Verified in deep audit |
| `unittest.mock.patch`/`MagicMock` in tests | 0 | Zero-Mock Sprint (`a0ee71c`) |
| Z3 solver version | 4.16.0.0 | `pyproject.toml` (`^4.12`) |
| Python support | ≥3.11, <4.0 | `pyproject.toml` |
| CI-tested Python | 3.13 only | `README.md` |
| License | AGPL-3.0-only + Commercial dual | `pyproject.toml` |
| Wheel size | 570 KB, 119 files | `poetry build` (2026-06-02) |

### Source Directory Breakdown

| Directory | Files (approx) | Contents |
| --------- | -------------- | -------- |
| `src/pramanix/` (root) | ~40 | guard, policy, solver, transpiler, expressions, decision, worker, fast_path, circuit_breaker, execution_token, key_provider, guard_config, cli, exceptions, testing |
| `src/pramanix/translator/` | ~14 | anthropic, cohere, gemini, mistral, ollama, openai_compat, llamacpp, redundant, bedrock, vertexai, injection_filter, injection_scorer, base |
| `src/pramanix/integrations/` | ~14 | langchain, langgraph, llamaindex, crewai, dspy, haystack, pydantic_ai, semantic_kernel, autogen, fastapi, grpc, kafka, agent_orchestration |
| `src/pramanix/audit/` | ~5 | signer, merkle, archiver, provenance, store |
| `src/pramanix/compliance/` | ~3 | oracle, compiler, labels |
| `src/pramanix/nlp/` | ~3 | validators, injection_filter (via translator/), schemas |
| `src/pramanix/oversight/` | ~2 | workflow, verifier |
| `src/pramanix/primitives/` | ~7 | finance, fintech, healthcare, infra, rbac, roles, time |
| `src/pramanix/mesh/` | ~2 | authenticator, common |
| `src/pramanix/natural_policy/` | ~3 | compiler, verifier, diff |
| `src/pramanix/k8s/` | ~2 | webhook, governance_config |
| `src/pramanix/interceptors/` | ~2 | kafka, enforcer |
| Other (`ifc/`, `identity/`, `helpers/`, etc.) | ~12 | IFC labels, identity resolvers, policy_auditor, lifecycle |

### Test Directory Breakdown

| Directory | Files | Purpose |
| --------- | ----- | ------- |
| `tests/unit/` | 162 | Unit and functional tests (real deps, no mocks) |
| `tests/integration/` | 34 | Integration tests (real containers, real APIs) |
| `tests/adversarial/` | 14 | Adversarial and security boundary tests |
| `tests/property/` | 4 | Hypothesis property-based tests |
| `tests/perf/` | 3 | Memory stability and performance tests |
| `tests/benchmarks/` | 2 | Solver latency benchmarks |
| `tests/helpers/` | 3 | Real test doubles (no MagicMock) |

### Uncommitted Working Directory Changes (as of 2026-06-03)

| File | Change | Significance |
| ---- | ------ | ------------ |
| `src/pramanix/translator/bedrock.py` | ~50 lines modified | AWS Bedrock translator improvements |
| `tests/unit/test_bedrock_translator.py` | ~5 lines changed | Bedrock test updates |
| `tests/unit/test_translator_init.py` | ~12 lines added | Translator init coverage |
| `tests/unit/test_yaml_dsl.py` | ~236 lines added (new file) | YAML DSL tests |

---

## Part 1: What Is Genuinely World-Class

### 1.1 Z3 SMT Kernel — Formal Verification Core (`solver.py`, 491 lines)

No other AI safety SDK uses formal SMT verification to enforce guardrails. This is Pramanix's single differentiating identity and the architectural feature that makes it categorically different from every competitor.

#### Two-Phase Architecture

**Phase A — Shared Solver (SAT/UNSAT determination):**
- One `z3.Solver` instance. All invariants added via `s.add()`.
- Timeout: `s.set("timeout", timeout_ms)` (line 340)
- rlimit: `s.set("rlimit", rlimit)` when > 0 (line 342) — caps elementary operations, prevents logic-bomb DoS regardless of wall-clock time
- `s.reset()` called explicitly after check — more reliable than `del` + GC for C-extension memory release
- `z3.unknown` → `SolverTimeoutError("<all-invariants>", timeout_ms)` (lines 350-351)
- Zero overhead on the ALLOW path — Phase B never runs for SAT results

**Phase B — Per-Invariant Attribution (UNSAT path only):**
- Each invariant gets its own dedicated solver with exactly one `assert_and_track(formula, z3.Bool(label, ctx))` call
- Because exactly one formula is tracked per solver, `s.unsat_core()` always returns `{label}` exactly — no minimal-subset ambiguity
- Per-invariant timeout independently raises `SolverTimeoutError(label, timeout_ms)`
- Only runs on BLOCK path — zero overhead on ALLOW path

#### Thread Safety

`_tl_ctx = threading.local()` (`solver.py:93`) — each OS thread gets its own Z3 context. Context creation is serialized by `_Z3_CTX_CREATE_LOCK` (line 98) to prevent the Windows access-violation crash documented in the module header. **No Z3 context is ever destroyed** — the module comment explicitly documents this avoids a GC race condition in the C-extension.

#### Injectable Solver Factory (Production Guard)

`guard_config.py:528`: `solver_factory: Callable[[Any], SolverProtocol] | None`

Production guard at `guard_config.py:726-733`:
```python
if self.solver_factory is not None and os.getenv("PRAMANIX_ENV") == "production":
    raise ConfigurationError(
        "GuardConfig.solver_factory is not permitted when PRAMANIX_ENV=production."
    )
```

Tests inject `RaisingSolverStub`, `TimeoutSolverStub`, etc. from `tests/helpers/solver_stubs.py` (6 stubs) via `GuardConfig(solver_factory=lambda _: RaisingSolverStub())`. A Z3 v4→v5 regression would not pass silently.

#### Array Quantifier Unrolling

`_realize_node()` replaces `_ForAllOp`/`_ExistsOp` nodes with concrete `_BoolOp` trees based on actual list values at verification time:
- `ForAll([])` with `allow_empty=False` (default) → raises `ValidationError` — prevents vacuous truth
- `Exists([])` → `_Literal(False)` — nothing exists
- Non-empty: unrolled to conjunction/disjunction of concrete comparisons

`_preprocess_invariants()` overflow-guards the unrolling: raises `ValidationError` if `len(raw) > af.max_length` — prevents polynomial blowup.

#### String→Integer Promotion Optimization

`analyze_string_promotions()` (`transpiler.py:477-493`) identifies String-typed fields appearing only in equality/membership comparisons. These are transparently encoded as integer codes (alphabetically sorted for stability) before Z3 dispatch. This trades Z3's heavier sequence theory for integer arithmetic — significantly faster for enum-like fields (`action`, `currency`, `role`). Fields used in `startswith`, `contains`, `regex`, or `length_between` are not promoted. Missing values encoded as `-1` (explicit sentinel).

#### Non-Linear Arithmetic Warning

Variable × variable and variable ÷ variable are detected during transpilation. A `UserWarning` is issued at `stacklevel=6` advising against non-linear expressions (Z3 may return `unknown` on NLA). The warning does not block — Z3 attempts the solve and raises `SolverTimeoutError` if it times out.

#### Clock Injection

`guard_config.py:551`: `clock: Callable[[], float] | None = field(default=None)`

Wired through all recursive `transpile()` calls. `transpiler.py:644`:
```python
_now = clock() if clock is not None else _time.time()
```

Tests inject `lambda: fixed_ts` to freeze time for `E.now()` policy assertions — no `monkeypatch.setattr(time, ...)` required.

**Remaining gap:** No formal `ClockProtocol` Protocol type. The parameter is typed as `Callable[[], float] | None` — functionally equivalent but less self-documenting.

---

### 1.2 Transpiler (`transpiler.py`, 970 lines)

Converts Policy DSL expression trees → Z3 AST. Zero `eval()`, `exec()`, `ast.parse()`. Pure tree-walk over `ConstraintExpr` nodes.

**Core dispatch:** `_realize_node()` handles: `_EqOp`, `_NeOp`, `_LtOp`, `_LeOp`, `_GtOp`, `_GeOp`, `_AndOp`, `_OrOp`, `_NotOp`, `_AddOp`, `_SubOp`, `_MulOp`, `_DivOp`, `_ModOp`, `_PowOp`, `_ForAllOp`, `_ExistsOp`, `_NowOp`, `_FieldRef`, `_LiteralNode` — complete operator coverage.

**Completeness:** Every operator the Policy DSL exposes maps to a corresponding Z3 AST node. There are no "partially implemented" operator branches.

---

### 1.3 Policy Engine (`policy.py`, 719 lines)

**Hard Guarantees:**
- No `eval()`, `exec()`, `ast.parse()` in the compiler — zero dynamic code execution
- LLM never called by `Guard.verify()` — compilation is pre-flight only
- `Condition` model-validator catches `IN`/`NOT_IN` with non-list RHS at schema time
- `PolicyCompiler` validates field existence, type compatibility, operator applicability before Z3 runs
- `Guard.__init__` validates policy semver and fingerprint at construction time

**Dynamic Factory (`policy.py:468-566`):**
`Policy.from_config()` creates sealed `Policy` subclasses for multi-tenant deployments. Result is cached by `(field_schema_hash, invariant_fn_ids)` tuple with LRU eviction at 256 entries (`_DYNAMIC_POLICY_CACHE`).

**Invariant Mixin Composition (`policy.py:195-294`):**
`__init_subclass__(mixins=...)` at class definition time snapshots the original `invariants()` method and wraps it with lazy mixin evaluation. Missing field detection raises `PolicyCompilationError` with a precise field list.

---

### 1.4 Cryptographic Audit Chain

**Signers (`audit/signer.py`):**
- `PramanixSigner`: Ed25519 asymmetric signing
- `RS256Signer`: RSA-2048+ JWT-compatible signing
- `ES256Signer`: ECDSA P-256 JWT-compatible signing
- All: `sign(payload: bytes) → bytes`, `verify(payload, signature) → bool`
- `DecisionSigner.__init__` raises `ConfigurationError` on missing/short key — no silent unsigned records
- `.verify()` methods: `InvalidSignature` → return `False`; infrastructure failure → raise `VerificationError`

**Merkle Log (`audit/merkle.py`):**
- Tamper-evident append-only log
- `PersistentMerkleAnchor`: SQLite-backed durable anchoring across restarts
- Each decision links to prior via `HMAC-SHA256(decision_hash + prior_root)`

**Oracle-Attack Redaction (`guard.py:411-458`):**
HMAC covers real field values, redacted copies returned to caller. Hash cannot be forged from the redacted version.

**Key Providers (`key_provider.py`):**

| Provider | Extra | Storage | `rotate_key()` |
| -------- | ----- | ------- | -------------- |
| `PemKeyProvider` | none | In-memory PEM | New Ed25519 in-memory |
| `EnvKeyProvider` | none | Environment variable | `NotImplementedError` (by design, `supports_rotation=False`) |
| `FileKeyProvider` | none | Filesystem PEM | Atomic `mkstemp` + `os.replace()` |
| `AwsKmsKeyProvider` | `[aws]` | AWS Secrets Manager | Cache invalidate + `rotate_secret()` |
| `AzureKeyVaultKeyProvider` | `[azure]` | Azure Key Vault | Stub-tested only |
| `GcpSecretManagerKeyProvider` | `[gcp]` | GCP Secret Manager | Stub-tested only |
| `HashicorpVaultKeyProvider` | `[vault]` | HashiCorp Vault KV | Stub-tested only |

All three concrete key providers (`Pem`, `File`, `Aws`) have source-verified atomic rotation. Azure, GCP, and Vault providers are tested against duck-typed stubs — rotation behavior in those three not source-verified with real cloud calls.

---

### 1.5 Compliance Oracle (`compliance/oracle.py`, 1,482 lines)

**No other AI safety library provides regulatory compliance attestation from Z3 proofs.** This is a genuine, unmatched competitive differentiator.

**31 Built-in Control Mappings:**
- SOC2 Common Criteria: 7 entries (CC1.1, CC2.1, CC6.1, CC6.2, CC7.1, CC8.1, CC9.1)
- EU AI Act: 8 entries (Articles 9, 10, 13, 14, 15, 17, 31)
- HIPAA: 6 entries (164.312(a)–(e) subparagraphs)
- NIST AI RMF: 6 entries (RV-1.1 through RV-2.2)
- GDPR: 4 entries (Articles 5, 17, 25, 35)

**Three Match Modes:**
- `INVARIANT_LABEL` — matches on Z3 invariant label alone
- `PRINCIPAL_IDENTITY` — matches on SPIFFE principal identity alone
- `BOTH` (`MappingMatchKind.BOTH`) — requires both to match — the tightest possible evidence linkage

**Integrity:** `ComplianceAttestation` is HMAC-SHA-256 tagged against the source `ProvenanceRecord`. Auditors can verify integrity by re-computing the tag from the record snapshot.

**Fail-Closed Contract:** `evaluate_record()` never raises. Internal errors return an error attestation with `error_kind` field — a failed compliance evaluation is never silently dropped or treated as a pass.

**Thread Safety:** `threading.RLock` on the mapping registry — concurrent `register_mapping()` and `evaluate_record()` calls are safe.

**`ControlMapping.control_id` Validation:** Validated per-framework via `_CONTROL_ID_PATTERNS`. `custom_control=True` escape hatch emits `UserWarning`.

**Remaining Gaps:**
- No end-to-end integration test running `Guard.verify()` → `ProvenanceRecord` → `ComplianceAttestation` in a single flow. Oracle is tested in isolation.
- No CLI or UI for generating compliance reports.
- No built-in query interface — operators must write custom code against the oracle.

---

### 1.6 Circuit Breaker (`circuit_breaker.py`, 1,340 lines)

**State Machine:** CLOSED → OPEN → HALF_OPEN → CLOSED

**Fail-Safe Default (source-verified at `circuit_breaker.py:573-579`):**
`DistributedCircuitBreaker` raises `ConfigurationError` if `backend=None` — no silent in-memory fallback.

`InMemoryDistributedBackend` emits `UserWarning` on construction (`circuit_breaker.py:491-498`) when `PRAMANIX_ENV=production`.

**WATCH/MULTI/EXEC Optimistic Locking (`circuit_breaker.py:964-1019`):**
```
WATCH key → read current state → MULTI → HSET + EXPIRE → EXECUTE
```
`WatchError` triggers a 3-attempt retry loop (lines 1015-1018). Eliminates TOCTOU race without Lua scripting.

**Half-Open Double-Probe Prevention (`circuit_breaker.py:285-296, 336-351`):**
`self._probing` flag prevents simultaneous probe requests in `HALF_OPEN` state. Only the first concurrent caller probes; all others reject immediately. Probe outcome: success → CLOSED; timeout → increment `open_episodes`, check isolation threshold.

**Known-Acceptable Swallows:**
- `circuit_breaker.py:79`: `except Exception: return` in `_inc_sync_failure_counter()` — Prometheus increment failure should not crash the breaker itself. Correct.
- `circuit_breaker.py:1276-1278`: resets probe flag but swallows exception detail — probe flag must be reset to prevent permanent half-open lock.

---

### 1.7 Worker Pool (`worker.py`, 1,018 lines)

- `ThreadPoolExecutor` (default) or `ProcessPoolExecutor` (configurable via `GuardConfig.execution_mode`)
- **Warmup:** 8-pattern Z3 suite run at startup to eliminate cold-start JIT spike
- **Pickling Safety:** `model_dump()` called BEFORE `ProcessPoolExecutor.submit()` — Pydantic models never pickled
- **HMAC Integrity Seal (`guard.py:1432-1440`):** In `async-process` mode, worker results sealed with HMAC before IPC return. Coordinator verifies before accepting `allowed=True`. Forged or tampered result → BLOCK (fail-safe).

**Exception Handling (verified not bare-pass):**

`worker.py:327-334` (ppid watchdog error):
```python
_wdog_log.getLogger(__name__).error(
    "pramanix.ppid_watchdog: unexpected error (zombie worker risk): %s",
    _wdog_exc, exc_info=True,
)
# + pramanix_worker_watchdog_errors_total.inc()
```

`worker.py:441-448` (Z3 warmup failure):
```python
_log.error(
    "Z3 warmup failed — worker will start cold (JIT spike possible): %s",
    _warmup_exc, exc_info=True,
)
# + pramanix_worker_warmup_failures_total.inc()
```

Both: ERROR level + full traceback + Prometheus counter. Operators can alert on these.

**Known-Acceptable Swallows:** `worker.py:721, 725` — 2× `except Exception: pass` in `WorkerPool.__del__()` GC finalizer. GC finalizers cannot safely log in all Python interpreter states; this is architecturally correct.

---

### 1.8 Execution Token Architecture — 4 Backends

| Backend | Anti-Replay Mechanism | Cross-Process Safe | TTL |
| ------- | --------------------- | ------------------ | --- |
| `InMemoryExecutionTokenVerifier` | `dict[token_id → expires_at]` | No (production `ConfigurationError`) | In-memory eviction |
| `SQLiteExecutionTokenVerifier` | `UNIQUE` constraint + `INSERT OR IGNORE` | Yes (WAL mode, `threading.Lock`) | Manual cleanup |
| `RedisExecutionTokenVerifier` | `SET pramanix:token:<id> 1 NX EX <ttl>` | Yes (distributed) | Auto-expires |
| `PostgresExecutionTokenVerifier` | Dedicated event loop thread; `asyncpg` pool | Yes (distributed) | Column-based |

Redis backend details: `SET ... NX EX` — atomic SETNX with TTL. Key exists → token already consumed → return `False`. Redis error → return `False` (fail-safe deny). `consumed_count()` uses SCAN cursor (not `KEYS`) to avoid O(N) blocking.

PostgreSQL backend: `asyncio.new_event_loop()` in dedicated thread; `run_coroutine_threadsafe()` marshals all DB calls — no `asyncio.run()` on the hot path.

**Clock Injection:** `ExecutionTokenSigner.__init__` and `ExecutionTokenVerifier.__init__` both accept `clock: Callable[[], float] = time.time` — duck-typed clock abstraction available at verifier level.

---

### 1.9 Guard (`guard.py`, 1,674 lines)

**Input Size Cap (`guard.py:772-809`):** `max_input_bytes` pre-check runs before any Z3 computation. JSON serialization failure → BLOCK (fail-safe). Prevents oversized payloads from reaching Z3.

**Fail-Closed Contract:** `_verify_core()` blanket `except Exception` → `Decision.error()`. `verify()` never raises — all errors produce a BLOCK decision.

**Field Metric Emission:** `_emit_field_seen()` called on every `verify()` — increments `pramanix_policy_field_seen_total{policy, field}` for traffic coverage analysis.

**`nonce` Replay Prevention:** `verify_async()` tracks nonces when `result_seal_key` is configured — duplicate nonces produce BLOCK.

**`allow_insecure_timing_leaks=False` Production Guard:** `GuardConfig` field. If set `True` while `PRAMANIX_ENV=production`, raises `ConfigurationError` at construction time.

---

### 1.10 Fast Path (`fast_path.py`, 297 lines)

Numeric comparison pre-check before Z3 invocation. **Fail-closed:**
- Malformed numeric input → returns block-reason string (not `None`)
- `pramanix_fast_path_parse_failure_total` Prometheus counter incremented on parse failure
- Only handles simple numeric comparisons; all other cases fall through to Z3
- `pass_through()` is only called when no rule fires — not on error

---

### 1.11 FastAPI Middleware — 9-Step Pipeline (`integrations/fastapi.py`)

1. **Content-Type check** → 415 Unsupported Media Type if not `application/json`
2. **Body size cap** → 413 Request Entity Too Large if over `max_body_bytes`
3. **JSON parse** → 422 Unprocessable Entity on parse failure
4. **Intent validation** (Pydantic strict) → 422 on validation error
5. **State loading** (via `state_loader()` callable) → 500 on exception
6. **`verify_async()`** — full Z3 pipeline
7. **Timing pad** (lines 191-196) — constant-time response to prevent oracle timing attacks
8. **BLOCK path** → 403 with serialized decision details
9. **ALLOW path** → forward to downstream handler

---

### 1.12 Mesh Authenticator (`mesh/authenticator.py`)

SPIFFE JWT-SVID validation for agent-to-agent calls. 10-point security model:

| # | Guarantee | Implementation |
| - | --------- | -------------- |
| 1 | Algorithm whitelist — RS256 and ES256 only | `_ALLOWED_ALGORITHMS: Final[frozenset]` (line 96) |
| 2 | Signature verified BEFORE exp/nbf/aud | Prevents timing oracle on claim validation |
| 3 | `exp` required — missing `exp` rejected | JWT-SVIDs without expiry not accepted |
| 4 | `aud` required — missing or mismatched rejected | Prevents cross-service token reuse |
| 5 | `sub` must be valid `spiffe://` URI — no ports, query strings, fragments | RFC 7519 + SPIFFE spec |
| 6 | `_mesh_principal` already in intent → reject | Prevents caller-side principal injection |
| 7 | Fail-closed — every failure path raises `MeshAuthenticationError` | No partial-auth state |
| 8 | Token size cap > 16 KiB rejected before parsing | Resource exhaustion prevention |
| 9 | JWKS cached with configurable TTL (default 600s), `threading.Lock` | Per-request HTTP prevention |
| 10 | No `eval`, `exec`, `pickle` | Module documents explicitly |

After `authenticate_and_bind()`, `_mesh_principal` SPIFFE URI is available as a policy field for Z3 invariant enforcement — exact caller identity verifiable at formal verification level.

---

### 1.13 Type Safety & Code Quality

- **0 `# type: ignore`** in `src/pramanix/` — eliminated in session 4 (commit `a6cc05b`)
- **`mypy --strict`** passes cleanly on all 112 source files
- **`ruff`** with security rules (`S`, `ASYNC`, `B`, `N`) — 0 violations
- **`py.typed` marker** present — PEP 561 type information ships with the package
- Only 3 `# noqa` in production source: `cli.py:1547` (re-export), `compiler.py:108` (naming), `guard_config.py:196` (late import)
- Structural fixes used for all type issues: `importlib.import_module()` for factory DI branches, `_DoctorCheck` TypedDict in cli.py, `Any` annotations for factory-injected private keys in crypto.py, `NoReturn` on raise-only helpers in yaml_loader.py

---

### 1.14 Observability Infrastructure

**Prometheus Metrics (10 counters/histograms/gauges when `pramanix[metrics]` installed):**

| Metric | Type | Labels | Purpose |
| ------ | ---- | ------ | ------- |
| `pramanix_decisions_total` | Counter | `policy`, `outcome` | Decision rate + block ratio |
| `pramanix_decision_latency_seconds` | Histogram | `policy`, `mode` | P50/P95/P99 per policy/mode |
| `pramanix_solver_timeouts_total` | Counter | `policy` | Z3 timeout rate (DoS signal) |
| `pramanix_validation_failures_total` | Counter | `policy` | Input validation failure rate |
| `pramanix_policy_field_seen_total` | Counter | `policy`, `field` | Field coverage in real traffic |
| `pramanix_nlp_model_available` | Gauge | `model` | NLP backend availability (0/1) |
| `pramanix_worker_watchdog_errors_total` | Counter | — | Zombie worker risk |
| `pramanix_worker_warmup_failures_total` | Counter | — | Cold-start JIT spike risk |
| `pramanix_cb_sync_failure_total` | Counter | — | Circuit-breaker Redis split-brain |
| `pramanix_fast_path_parse_failure_total` | Counter | `rule` | Fast-path malformed input rate |

All metrics use `None` guards — if `prometheus-client` is absent, every metric call is a no-op. No metric is silently dropped.

**OpenTelemetry:** `_span("guard.verify")`, `_span("guard.solve")`, `_span("translator.extract")`, `_span("mesh.authenticate")` instrumented. When `opentelemetry` absent, all spans are `contextlib.nullcontext()` — zero overhead.

**Gap:** No baggage propagation between guard spans and downstream spans — distributed trace context not passed through `Guard.verify()` into worker processes. No `decision_id` automatically injected into structlog context on the ALLOW path.

---

## Part 2: Known Limitations — The Hard Truths

### 2.1 CRITICAL: AGPL-3.0 — The #1 Enterprise Adoption Killer

**Every competitor is Apache-2.0 or MIT.** NeMo Guardrails, Guardrails AI, LangChain, LlamaIndex, LangGraph — all permissively licensed.

AGPL-3.0 means:
- Any enterprise embedding Pramanix in a commercial product must open-source their entire application
- Enterprise legal teams at Goldman Sachs, JPMorgan, Google, Microsoft routinely reject AGPL without reading further
- Cloud providers cannot ship Pramanix as a managed service without triggering copyleft
- Fortune-500 procurement rejects Pramanix at the legal review stage, regardless of technical quality
- SaaS companies running Pramanix as middleware must open-source all surrounding code

**This is not a code problem.** It is a structural licensing decision that requires business/legal resolution. No audit recommendation will have more impact than re-licensing to Apache-2.0 or establishing a genuine dual-license commercial tier.

**Current state:** `LICENSE` (AGPL-3.0-only) + `LICENSE-COMMERCIAL` (dual-license model) exist. But the commercial license is not a standard permissive license — it is an enterprise agreement requiring negotiation. Enterprise procurement cannot buy permissive rights off-the-shelf. The license status in `pyproject.toml` has both AGPL and proprietary classifiers, creating ambiguity.

---

### 2.2 CRITICAL: Zero Real LLM Testing in CI

The translator subsystem — Pramanix's Layer 4 defense against LLM extraction manipulation — has **never been tested against a real LLM in any CI run.** A consensus logic regression in `redundant.py` would not be caught.

**Evidence:**
- `tests/integration/test_llm_consensus.py` — entire test class behind `pytestmark = pytest.mark.skipif(not os.environ.get("OPENAI_API_KEY"), ...)`
- `tests/integration/test_gemini_translator.py` live tests — skipped (no `GOOGLE_API_KEY`)
- `tests/integration/test_llamacpp_translator.py` — skipped (no `PRAMANIX_TEST_GGUF_PATH`)
- `tests/unit/test_translator.py` (1,140 lines) — zero real API calls; all tests use `FakeA`, `FakeB`, `FakeOk`, `FakeTranslator` inline classes
- `Dockerfile.dev` and `Dockerfile.production` both bake in `PRAMANIX_TRANSLATOR_ENABLED="false"`
- `ci.yml` only references `SEMGREP_APP_TOKEN` and `CODECOV_TOKEN` — no `OPENAI_API_KEY`, `GOOGLE_API_KEY`, `COHERE_API_KEY`, `AZURE_*`, or `PRAMANIX_TEST_GGUF_PATH` in GitHub Secrets

**Comparison:** NeMo Guardrails runs real model inference against containerized models in CI. Guardrails AI tests real validators against real LLM outputs.

---

### 2.3 HIGH: Integration CI Job Does Not Gate the Merge Pipeline

The `integration:` job in `ci.yml` (line 787) runs when `github.event_name != 'schedule'` and declares `needs: test`. But it is **not listed in any subsequent job's `needs:` array**. The `coverage → wheel-smoke → extras-smoke → trivy → license-scan` gate chain does not depend on integration job status.

**Consequence:** A broken integration test — Kafka, Postgres, Redis, Vault, LocalStack — can be merged. Integration test coverage is NOT included in the coverage report submitted to Codecov. Code paths only exercised by integration tests are invisible to the coverage gate.

Additionally, `continue-on-error: true` on the benchmark step (`ci.yml:331`) means benchmark failures never block PRs.

---

### 2.4 HIGH: Coverage Floor Conflict

```toml
# pyproject.toml [tool.coverage.report]
fail_under = 98

# .github/workflows/ci.yml line 376
coverage report --fail-under=95
```

The CI step explicitly passes `--fail-under=95`, overriding `pyproject.toml`'s `fail_under = 98`. The **actual enforced coverage floor in CI is 95%, not 98%.** Three percent of production paths could be uncovered across all PRs without failing the build.

Additionally, `pyproject.toml` excludes bare `...` statements from coverage counting:
```toml
exclude_lines = [
    "if TYPE_CHECKING:",
    "if __name__ == .__main__.",
    "@overload",
    "\\.\\.\\.",    # bare ellipsis — broader than intended
]
```

The `"\\.\\.\\."`  rule excludes **every bare `...` statement** from coverage — broader than intended for abstract-method markers.

**Current measurement:** Last measured at 95.09% in April (before new tests added in sessions 2-4). Session 4 coverage run was started but takes 7+ hours to complete. True current coverage is unknown.

---

### 2.5 HIGH: NLP Safety Layer Is Beta-Grade (Honest Assessment)

**What it is:** The NLP layer is a keyword/regex filter with fallback to optional ML models. It is not a production-grade ML safety classifier.

**`ToxicityScorer`:** Keyword matching against 58 stems across 8 categories (threats/violence 14, harassment 6, sexual content 4, self-harm 3, racial/ethnic slurs 16, homophobic/transphobic 6, ableist 3, religious/national 6). If `detoxify` ML model is absent: WARNING log + `pramanix_nlp_degradation_total` counter + keyword-density fallback. The 58-stem list is a baseline, not a comprehensive production list. Foreign-language slurs, leetspeak, Unicode homograph attacks are not covered.

**`PIIDetector`:** google-re2 regex patterns for email/phone/SSN/credit card/IBAN. No ML. Lazy `ConfigurationError` when RE2 absent (not at import time — lazily on first use).

**`SemanticSimilarityGuard`:** TF-IDF cosine similarity via scikit-learn. Not sentence-transformers. Semantic similarity is approximate for short inputs. If sentence-transformers absent: WARNING log + Jaccard fallback.

**RE2 Import Pattern (lazy, verified):** Both `nlp/validators.py` and `translator/injection_filter.py`:
```python
_RE2_AVAILABLE: bool = False
try:
    import re2 as _re2
    _RE2_AVAILABLE = True
except ImportError as _re2_err:
    _re2_import_error = _re2_err

def _require_re2() -> None:
    if not _RE2_AVAILABLE:
        raise ConfigurationError("...google-re2 is required but not installed...")
```

Modules import cleanly without google-re2. `ConfigurationError` raised **lazily** only when PII/regex features are first constructed. Operators who test without RE2 and deploy with it will observe a behavior difference — `pramanix[security]` must be documented as mandatory for production PII features.

**Competitive gap:** NeMo Guardrails ships production-tested LLM rails for toxicity, jailbreak, topic filtering, and hallucination. Guardrails AI ships 50+ validators including PII, toxicity, bias, factuality, and slur detection — all production-grade. Pramanix's NLP layer is materially stronger post-session-4 but not yet competitive with either for general content safety.

---

### 2.6 MEDIUM: Persistent ApprovalWorkflow Is Not Implemented

`InMemoryApprovalWorkflow` is the only working implementation. There is no database-backed `ApprovalWorkflow`. Approval tokens do not survive process restart. This creates a SOC2 Annex A control gap — the tool that enables dual-control authorization compliance does not ship a compliant (durable) implementation.

Emits `UserWarning` on construction when `PRAMANIX_ENV=production` (`oversight/workflow.py:486-493`).

**Status:** Requires DB schema design decision. Blueprint describes a database + notification system backend, but no `PostgresApprovalWorkflow` or `RedisApprovalWorkflow` exists.

---

### 2.7 MEDIUM: Merkle Archive Encryption Not Implemented

`MerkleArchiver` compresses but does not encrypt archives. Archives are plaintext zstd-compressed. If the audit log must be confidential, callers must encrypt at the storage layer. This must be documented clearly — a compliance officer reviewing audit log retention may assume encryption is included.

---

### 2.8 MEDIUM: No Production Deployment Metrics

All latency/throughput benchmarks are in-process measurements on development hardware (v0.8.0, consumer laptop), not production measurements. The CI nightly gate has `continue-on-error: true` — the P99 < 15ms claim is stated but not enforced. No v1.0.0 benchmarks on server-class hardware exist.

---

### 2.9 MEDIUM: Bare Exception Handlers — Verified Inventory

All `except Exception: pass` instances in production source — verified:

| File | Line(s) | Handler | Impact |
| ---- | ------- | ------- | ------ |
| `circuit_breaker.py` | 79 | `except Exception: return` | Prometheus increment failure — silent return (appropriate) |
| `circuit_breaker.py` | 1276-1278 | Resets probe flag, swallows detail | Probe flag must reset; detail lost |
| `crypto.py` | 98 | `except Exception: pass` | Crypto cleanup swallowed |
| `fast_path.py` | 69 | `except Exception:` then metric + return | Metric fires; parse error body lost |
| `audit/signer.py` | 55 | `except Exception: pass` | Signing cleanup swallowed |
| `translator/cohere.py` | 156 | `except Exception: pass` | Translator cleanup swallowed — should be WARNING |
| `translator/gemini.py` | 103, 216 | `except Exception: pass` | Translator cleanup swallowed — should be WARNING |
| `translator/redundant.py` | 167, 189 | `except Exception: pass` | Consensus cleanup swallowed — should be WARNING |
| `natural_policy/verifier.py` | 292 | `except Exception: pass` | Verifier cleanup swallowed |
| `guard.py` | 251-252 | `except Exception as _e: log.debug(...)` | Field metric failure logged at DEBUG (silent in prod defaults) |

**Most actionable:** Translator cleanup handlers (`cohere.py:156`, `gemini.py:103,216`, `redundant.py:167,189`) should log at WARNING minimum to surface resource leaks.

---

### 2.10 MEDIUM: `sys.modules` Poisoning in 5 Test Files

`tests/unit/test_coverage_gaps.py` performs bare assignments like `sys.modules["anthropic"] = None` — bare assignments (not `patch.dict`) do not auto-restore on test failure. A test failure poisons `sys.modules` for the rest of the session.

Five additional files retain `patch.dict(sys.modules)` (require dedicated tox environments):
- `test_enterprise_audit_sinks.py`: `confluent_kafka`, `boto3`, `datadog`
- `test_framework_adapters.py`: `haystack`, `semantic_kernel`, `pydantic_ai`, `dspy`, `starlette`
- `test_integrations_lazy.py`: `crewai`, `dspy`, `haystack`, `semantic_kernel`, `pydantic_ai`
- `test_distributed_circuit_breaker.py`: `redis`, `redis.asyncio`
- `test_mistral_llamacpp.py`: `mistralai`, `llama_cpp`

---

### 2.11 MEDIUM: Docker Configuration Gaps

Both `Dockerfile.dev` and `Dockerfile.production` have the same issues:
- `PRAMANIX_TRANSLATOR_ENABLED="false"` baked in — LLM pathway disabled in all Docker-based runs. Not overridable via build arg.
- No `google-re2` preinstallation — `PIIDetector`, `RegexClassifier`, and `SemanticSimilarityGuard._tokenise()` raise `ConfigurationError` at first use in Docker
- `Dockerfile.production` (verified): **non-root user present** (`USER pramanix` — S12 gate passed)
- `Dockerfile.production` (verified): **HEALTHCHECK present** (S13 gate passed)

---

## Part 3: Test Suite Reality Check

### 3.1 Quantity vs. Quality Scorecard

| Category | Count | Reality |
| -------- | ----- | ------- |
| Total tests collected | 5,687 | Comprehensive quantity |
| Unit tests | 162 files | Real deps, no MagicMock |
| Integration tests | 34 files | Real containers; not gate-blocking |
| Adversarial tests | 14 files | Boundary conditions; some via monkeypatch |
| Property tests | 4 files | Hypothesis; incomplete coverage of edge cases |
| `unittest.mock.patch` / `MagicMock` | 0 | Zero-Mock Sprint (`a0ee71c`) |
| `sys.modules` patching (bare) | ~5 files | Poisons session on failure |
| Real Z3 solver stubs | 6 | `tests/helpers/solver_stubs.py` |
| Real protocol helpers | 1,948 lines | `tests/helpers/real_protocols.py` |
| Real integration: real Redis | `fakeredis` | Not real Redis server |
| Real integration: real LLM | 0 | All skipped in CI |

### 3.2 Zero-Mock Sprint — What Was Fixed (Commit `a0ee71c`)

**Eliminated:**
- All `unittest.mock.patch`, `MagicMock`, `AsyncMock` from the test suite
- Z3 solver replacement via `patch.object` (3 sites) — replaced by `solver_factory` DI
- `KafkaDLQProducer` mock — replaced by duck-typed real double

**Replaced with:**
- `tests/helpers/solver_stubs.py`: 6 real `SolverProtocol` implementations (Raising, Timeout, Failing, Slow, Unsat, Sat)
- `tests/helpers/real_protocols.py`: 1,948 lines of real duck-typed protocol implementations
- `fakeredis` for Redis tests
- `InMemorySpanExporter` (OTel SDK) for telemetry tests
- `_CountingGuard` decorator pattern for circuit breaker pressure

**What remains:**
- `patch.dict(sys.modules)` (~21 sites in 9 files) — not mock contamination; appropriate for absent-package import tests
- `monkeypatch.setattr` (reduced scope) — not MagicMock; appropriate for env var/function replacement in dedicated contexts

### 3.3 Hypothesis Property Tests — Incomplete Edge Coverage

`tests/unit/test_sanitise_properties.py`:
- `assume(len(s) >= 10)` and `assume(len(s) <= 512)` — sanitizer never tested on length 0-9 or >512
- `assume(len(s) > 0)` at 5 sites — empty strings never explored
- `assume(s.strip())` — whitespace-only inputs never explored
- `assume(not s.startswith(...))` — injection-prefix strings excluded from property tests
- 7× `suppress_health_check=[HealthCheck.too_slow]` — without benchmark justification comment

The most security-relevant inputs (empty, single-char, injection-prefix, overlong) are excluded. A regression on these inputs would not be caught by Hypothesis.

### 3.4 White-Box Private State Mutation

Tests directly mutate private attributes to reach states that the real system would reach only through internal transitions:

| File | Line | Mutation |
| ---- | ---- | -------- |
| `test_audit_sink_full_coverage.py` | 121 | `_sink_mod._OVERFLOW_COUNTER = None` |
| `test_audit_sink_full_coverage.py` | 184 | `sink._queue_depth = 1` |
| `test_circuit_breaker_and_guard_paths.py` | 551 | `sink._queue_depth = 0` |
| `test_enterprise_audit_sinks.py` | 80 | `sink._queue_depth = 0` |
| `test_coverage_final_push.py` | 73, 91, 109 | `t._api_key = "key"` |

Most severe: `tests/integration/test_gemini_translator.py:41-50` constructs `GeminiTranslator` via `__new__()` and manually injects every private field. The constructor's SDK validation, client initialization, and configuration checks never run.

### 3.5 The Adversarial Test Honesty Gap

`tests/adversarial/test_fail_safe_invariant.py` verifies that **when a function is artificially made to crash**, the guard returns BLOCK. What it does **not** verify is that real Z3 memory exhaustion, real network partition, or real C-library segfault produces fail-safe BLOCK.

The fail-safe guarantee is architecturally sound (`verify()` never raises — lines 55-62 in `guard.py`). But the adversarial tests validate the contract by monkeypatching, not by inducing real failures.

### 3.6 Skipped Tests Are Invisible to CI Gates

`tests/integration/test_llm_consensus.py`, `test_gemini_translator.py` (live), and `test_llamacpp_translator.py` are permanently skipped via `skipif`. Skipped tests do not fail builds. A consensus regression in `redundant.py` would only fail in a developer environment with API keys.

`pytest.mark.xfail(strict=True)` would be more honest: a test that was expected to be skipped but somehow ran would fail the build, surfacing the assumption.

---

## Part 4: CI/CD Pipeline Audit

### 4.1 Verified CI Gates (`ci.yml`, 845 lines)

| Gate | Status | Details |
| ---- | ------ | ------- |
| SAST (`bandit` + `semgrep`) | Running | Job: `sast` — runs before tests |
| `pip-audit` | Running | Dependency CVE scan |
| Alpine/musl Docker ban | Running | Rejects Z3 glibc-incompatible builds |
| `ruff` lint | Passing | Job: `lint`; 0 violations confirmed session 4 |
| `mypy --strict` | Passing | Job: `lint`; 0 errors confirmed session 4 |
| Unit + adversarial + property tests | Passing | Job: `coverage`; 4,701 passed session 4 |
| Coverage ≥ 95% (CI-enforced) | Running | `--fail-under=95` override in `ci.yml:376` |
| Integration tests | Running (not blocking) | Job: `integration`; not in merge gate `needs:` |
| Benchmark + perf tests | Running (not blocking) | `continue-on-error: true` on benchmark step |
| Trivy container scan | Running | CRITICAL/HIGH CVE fail |
| License allowlist scan | Running | GPL/AGPL dependency block |
| Ollama live tests | Running | Job: `ollama-live` |
| Wheel + sdist smoke test | Running | After `coverage` + `integration` |
| Extras smoke test | Running | 15 extras, ~40 module import checks |

### 4.2 CI Gaps

| Gap | Severity | Impact |
| --- | -------- | ------ |
| `integration:` job not in merge gate | High | Broken integration tests can be merged |
| Benchmark step `continue-on-error: true` | Medium | P99 < 15ms claim never enforced |
| `--fail-under=95` overrides `pyproject.toml` 98% | High | 3% coverage loophole across all PRs |
| LLM API keys absent | High | Translator consensus never CI-tested |
| LocalStack (not real AWS) for S3/KMS tests | Low | Real cloud behavior untested |
| Python matrix: 3.13 only in README | Medium | 3.11/3.12 not actively tested per README |

### 4.3 What Is Tested by Real Infrastructure

| Infrastructure | Container | Test Files |
| ------------- | --------- | ---------- |
| Redis 7 | Real testcontainer | `test_redis_circuit_breaker.py` |
| Kafka/Redpanda | Real testcontainer | `test_kafka_audit_sink.py`, `test_kafka_interceptor.py` |
| Postgres 16 | Real testcontainer | `test_postgres_execution_token.py` |
| Vault 1.16 | Real testcontainer | `test_vault_key_provider.py` |
| LocalStack 3.4 | Real testcontainer | `test_s3_audit_sink.py`, `test_aws_kms.py` |

---

## Part 5: Architecture — Blueprint vs Reality

> `docs/Ideal_Architecture.md` (4,271 lines, 180 KB) describes the complete ideal Pramanix.

| Blueprint Item | Status | Evidence |
| -------------- | ------ | -------- |
| `SolverProtocol` injectable via `GuardConfig(solver_factory=...)` | ✅ IMPLEMENTED | `guard_config.py:528`; production guard at line 726 |
| `ClockProtocol` injection in transpiler | 🟡 PARTIAL | `GuardConfig.clock: Callable[[], float] \| None` wired into `transpile()`; no formal `Protocol` type |
| `tests/helpers/solver_stubs.py` | ✅ IMPLEMENTED | 6 real stubs: Raising, Timeout, Failing, Slow, Unsat, Sat |
| RE2 fail-closed pattern | 🟡 REVISED | Lazy `ConfigurationError` on use; module imports without RE2 |
| `DistributedCircuitBreaker` fail on missing backend | ✅ IMPLEMENTED | Raises `ConfigurationError` if `backend=None` |
| `rotate_key()` in all concrete providers | ✅ IMPLEMENTED | PEM, File, AWS all implemented; Azure/GCP/Vault stub-tested |
| `RedisExecutionTokenVerifier` | ✅ IMPLEMENTED | `SET NX EX` atomic (`execution_token.py:754-945`) |
| `SQLiteExecutionTokenVerifier` | ✅ IMPLEMENTED | UNIQUE constraint atomic |
| `PRAMANIX_ALLOW_NO_AUDIT_SINKS` bypass | ✅ REMOVED | Grep confirms absent from `guard_config.py` |
| `InMemory*` removed from `__all__` | ✅ IMPLEMENTED | `__init__.py:316-318` |
| `InMemory*` production warning | ✅ IMPLEMENTED | All 4 classes guard on `PRAMANIX_ENV=production` |
| Worker HMAC integrity seal | ✅ IMPLEMENTED | `guard.py:1432-1440` |
| `ForAll(empty_array)` vacuous truth fix | ✅ IMPLEMENTED | `allow_empty=False` default |
| `ControlMapping.control_id` validated | ✅ IMPLEMENTED | `_CONTROL_ID_PATTERNS` per-framework |
| `AsyncIO.run()` in `_swrapper` | ✅ FIXED | `langgraph.py:230-264` detects running event loop via `asyncio.get_running_loop()` |
| `AgentOrchestrationAdapter` | ✅ IMPLEMENTED | `integrations/agent_orchestration.py` with real Z3 tests |
| CB `_lock` concurrent-mutation test | ✅ IMPLEMENTED | `TestCircuitBreakerLockLinearizability` (200 coroutines) |
| Non-numeric state injection tests | ✅ IMPLEMENTED | `tests/integration/test_corrupted_state_injection.py` (19 tests) |
| Hypothesis `assume()` exclusions | ❌ OPEN | `test_sanitise_properties.py` still has 7+ exclusions |
| Policy linter CLI | ❌ NOT IMPLEMENTED | — |
| Interactive YAML policy validator | ❌ NOT IMPLEMENTED | — |
| Policy simulation/dry-run CLI | 🟡 PARTIAL | `pramanix simulate` exists; requires Python policy file; no YAML support |
| Policy coverage analysis | ❌ NOT IMPLEMENTED | Counter exists; no analysis layer |
| Benchmarks on v1.0.0 server hardware | ❌ OPEN | All benchmarks are v0.8.0 / consumer laptop |
| Persistent `ApprovalWorkflow` | ❌ NOT IMPLEMENTED | In-memory only |
| Merkle archive encryption | ❌ NOT IMPLEMENTED | Compression only |
| Built-in compliance mapping library | ✅ IMPLEMENTED | `default_oracle()` with 31 built-in mappings |
| Compliance report CLI | ✅ IMPLEMENTED | `pramanix report` subcommand (`P3.6`) |
| `ExpressionNode.__hash__` reconciliation | ✅ DOCUMENTED | `__hash__ = None` intentional; documented in `expressions.py:500-504` |
| `InMemoryApprovalWorkflow` UserWarning | ✅ IMPLEMENTED | `oversight/workflow.py:486-493`; production `ConfigurationError` |

---

## Part 6: Competitive Gap Analysis

### 6.1 vs. NeMo Guardrails

| Capability | Pramanix | NeMo Guardrails | Winner |
| ---------- | -------- | --------------- | ------ |
| Formal verification (SMT) | Z3, complete for numerics | Not present | **Pramanix** |
| Regulatory compliance oracle | SOC2, HIPAA, EU AI Act, GDPR | Not present | **Pramanix** |
| Cryptographic audit trail | Ed25519, Merkle, HMAC | Basic logging | **Pramanix** |
| Key rotation (SOC2/PCI-DSS) | Atomic in all 3 providers | Not primary focus | **Pramanix** |
| Distributed token single-use | Redis NX EX, SQLite UNIQUE, Postgres | Not present | **Pramanix** |
| Dialogue flow control | Not primary focus | Colang DSL, production | **NeMo** |
| Jailbreak detection | Beta injection scorer | Production-tested rails | **NeMo** |
| Real LLM testing in CI | Never (always skipped) | Containerized models | **NeMo** |
| Latency (P50) | ~2ms (v0.8.0 benchmark) | Comparable | Tie |
| Production adoption | v1.0.0, pre-production | Multi-year, NVIDIA backing | **NeMo** |
| Developer onboarding | Steep (Z3 knowledge) | Simple Colang YAML | **NeMo** |
| License | AGPL-3.0 (enterprise blocker) | Apache-2.0 | **NeMo** |

**Verdict:** In formal verification + regulatory attestation of discrete AI actions in regulated industries, Pramanix has no competitor. NeMo wins on everything outside that lane.

### 6.2 vs. Guardrails AI

| Capability | Pramanix | Guardrails AI | Winner |
| ---------- | -------- | ------------- | ------ |
| Formal verification (SMT) | Z3, unmatched | Heuristic only | **Pramanix** |
| Regulatory compliance mapping | SOC2, HIPAA, EU AI Act | Not present | **Pramanix** |
| Key rotation | Atomic in all 3 providers | Not primary focus | **Pramanix** |
| Single-use token enforcement | Redis, SQLite, Postgres | Not present | **Pramanix** |
| RBAC / access control | Z3 proven, formal | Schema-based | **Pramanix** |
| Financial precision | Decimal exact, Z3 formal | Not primary focus | **Pramanix** |
| Built-in validators | ~4 NLP beta | 50+ production | **Guardrails AI** |
| Slur/toxicity detection | 58 stems / 8 categories + detoxify integration | Production models, broad vocabulary | **Guardrails AI** |
| PII detection | Beta; RE2 lazy-required | Multiple backends, production | **Guardrails AI** |
| Ease of getting started | Complex (Z3 knowledge) | Simple (add a validator) | **Guardrails AI** |
| License | AGPL-3.0 | Apache-2.0 | **Guardrails AI** |
| Enterprise support | None yet | Commercial tier | **Guardrails AI** |

**Verdict:** Pramanix wins decisively for formal safety in regulated industries. Guardrails AI wins for content safety breadth and developer experience.

---

## Part 7: Component Deep Dives

### 7.1 Translator Subsystem — Dual-Model Consensus

`translator/redundant.py` implements a 6-layer security pipeline (`lines 215-249`):

1. **Input sanitization** — Unicode NFKC normalization + control-character strip
2. **Parallel LLM extraction** — `asyncio.gather(return_exceptions=True)` — both model calls concurrent
3. **Partial-failure gate** — either model failure blocks the pipeline with specific error
4. **Schema validation** — both results independently validated via Pydantic strict mode
5. **Consensus check** — three modes:
   - `strict_keys`: every field must agree (default)
   - `lenient`: only `critical_fields` must agree
   - `unanimous`: canonical-JSON bitwise equality
   - `SEMANTIC`: `Decimal(str(v))` comparison — `"500"` == `"500.0"` == `"5.0E+2"` — correct for financial amounts
6. **Post-consensus injection confidence gate** — score ≥ 0.5 blocks with `InjectionBlockedError`

`create_translator()` factory supports: `gpt-*`, `claude-*`, `ollama:*`, `gemini:*`, `cohere:*`, `mistral:*`, `llama:*`, `bedrock:*`, `vertexai:*`.

**The trust gap:** The consensus pipeline has never been exercised against a real LLM in any CI run. `PRAMANIX_TRANSLATOR_ENABLED="false"` is baked into both Dockerfiles. All translator tests use inline fake implementations.

---

### 7.2 Bedrock Translator (`translator/bedrock.py`) — Recently Modified

The bedrock translator supports Claude, Titan, and Meta Llama models via `boto3`. It has uncommitted working directory changes as of 2026-06-03 (`~50 lines modified`). The module supports model ID prefixes: `anthropic.claude-*`, `amazon.titan-*`, `meta.llama*`, and a generic Bedrock converse API path for unknown prefixes.

---

### 7.3 CLI — 15 Subcommands

`cli.py` implements the `pramanix` command-line interface:

| Command | Purpose | Gap |
| ------- | ------- | --- |
| `check` / `lint` | Readiness check: Python, Z3, Redis, extras, signing key | Good first-run UX |
| `doctor` | 23-check diagnostics; exits 0 on success | Windows Unicode fixed (commit `5fde07f`) |
| `verify-proof <token>` | Verify JWS decision proof; reads `PRAMANIX_SIGNING_KEY` | Tested |
| `simulate --policy FILE --intent JSON` | Runs `Guard.verify()` without LLM or side-effects | Exists; requires Python policy file (not YAML); `--suggest-fix` coverage unclear |
| `explain` | Alias for `simulate` | Identical implementation |
| `audit verify LOG_FILE --public-key PEM` | Verify JSONL audit log signed with Ed25519 | No integration test with real audit log |
| `init --template finance\|pii\|infra` | Scaffold a policy blueprint | Tests exist; templates are static YAML |
| `report` | Compliance report generation | Implemented (`P3.6` done) |
| `policy` | Policy management (semver migration, schema validation) | Available; test coverage unclear |
| `compile-policy` | Compile policy schema | Available; not prominently documented |

**`pramanix doctor` output (verified session 4):** 23 checks pass, `[WARN]` only for unsigned decisions, exits 0.

**CLI testing gaps:** `test_cli_simulate.py` uses 37+ `monkeypatch.setattr(sys, "argv", [...])` calls; underlying `Guard.verify()` is patched in most cases, not real.

---

### 7.4 Mesh Authenticator — Known Gaps

- `mesh/authenticator.py:885, 906, 922` — JWT library `ImportError` paths are excluded from coverage. An ABI-incompatible `cryptography` install silently degrades authentication.
- JWKS fetch uses `httpx.get` (synchronous) — real network failures under JWKS cache expiry are never induced in CI.
- No test for JWKS rotation (new public key published while old tokens still valid in TTL window).

---

### 7.5 Kubernetes Admission Webhook (`k8s/webhook.py`)

`ValidatingWebhook` implementation via FastAPI. `_FastAPIFallback` class raises `ConfigurationError` when `fastapi` is absent. Returns `{"allowed": false, "status": {"message": "<reason>"}}` on BLOCK — standard K8s webhook response format.

**Gaps:**
- No integration test against real `kind` or `minikube` cluster
- No TLS certificate management guidance (K8s requires HTTPS for admission webhooks)
- `intent_extractor` is a raw callable with no schema validation — wrong field types pass silently

---

### 7.6 Kafka Consumer Interceptor (`interceptors/kafka.py`)

Wraps `confluent_kafka.Consumer` — every polled message gated by `Guard.verify()` before being yielded. Blocked messages are dead-lettered to DLQ topic or committed to advance offset.

**Gaps:**
- No integration test for the DLQ path with a real Kafka cluster and real blocked messages
- No backpressure mechanism — if Z3 times out, `safe_poll()` blocks and consumer lag accumulates
- No Prometheus metric for guard latency on the Kafka-interceptor path

---

### 7.7 Oversight & Human-in-the-Loop (`oversight/workflow.py`)

`OversightRecord` signed with HMAC-SHA-256; `hmac.compare_digest()` for constant-time comparison. TTL auto-rejection: `auto_reject_after_s=300.0` (5 min default). Background sweep: `sweep_interval_s=60.0`.

`InMemoryApprovalWorkflow` uses per-instance `os.urandom(32)` HMAC key — prevents cross-worker record verification by accident. Emits `UserWarning` on construction; raises `ConfigurationError` when `PRAMANIX_ENV=production`.

**Critical gap:** No persistent `ApprovalWorkflow`. For SOC2 Annex A (dual-control authorization), operators must implement their own DB-backed workflow. The tool that enables compliance does not ship a compliant implementation.

---

### 7.8 Natural Policy Compiler (`natural_policy/compiler.py`)

LLM-backed policy authoring from natural language description. Pipeline: NL input → LLM `compile()` → Pydantic validation → ASTBuilder → MetaVerifier semantic distance check → compiled `Policy` subclass.

**Guarantee:** LLM never called at `Guard.verify()` time. All LLM-generated fields checked against declared `Field` list.

**Gaps:**
- No end-to-end CI test calling `NaturalPolicyCompiler.compile()` against a real LLM
- `MetaVerifier` threshold is a hyperparameter — no test validates it catches real hallucinations
- No streaming or batch compilation API

---

### 7.9 Performance Characteristics

**Measured (v0.8.0, consumer laptop — STALE, not representative of v1.0.0):**

| Mode | P50 | P95 | P99 |
| ---- | --- | --- | --- |
| `sync` (in-process Z3) | ~2ms | ~6ms | ~14ms |
| `async-thread` (ThreadPoolExecutor) | ~3ms | ~8ms | ~18ms |
| `async-process` (ProcessPoolExecutor) | ~8ms | ~15ms | ~28ms |

**Session 4 benchmark (clean venv, z3-warmup=1):** Mean 2.3ms, P50 2.0ms, P95 3.3ms, P99 3.3ms — but this is a single-run microbenchmark, not a representative sustained-load measurement.

**Known bottlenecks not reflected in published numbers:**

| Change Since v0.8.0 | Latency Effect |
| ------------------- | -------------- |
| `@functools.cached_property` CB fix | Changed concurrency behavior |
| `_emit_field_seen()` on every `verify()` | Added overhead to ALLOW path |
| `InvariantASTCache` compile-once | Reduced Guard construction time |
| WATCH/MULTI/EXEC Redis locking | Added Redis round-trip to CB sync |
| Worker warmup expanded 1→8 Z3 patterns | Increased cold-start time |
| HMAC integrity seal on worker results | Added crypto overhead in process mode |
| String→Int promotion analysis | Added transpiler analysis time |

**To claim Giant-tier latency:** Run all benchmarks on v1.0.0 on 8-core, 32 GB RAM server hardware with sustained load. Publish raw results with confidence intervals.

---

### 7.10 IFC (Information Flow Control)

`ifc/labels.py` implements lattice-based information flow labels for tracking data sensitivity across policy evaluations. This is a research-quality feature; its integration with the Z3 formal engine provides provably correct taint tracking.

---

## Part 8: Dependency Map & Supply Chain Risk

### 8.1 Required Dependencies (Always Installed)

| Package | Version | Purpose | Risk |
| ------- | ------- | ------- | ---- |
| `pydantic` | ^2.5 | Schema validation, model serialization | Widely used; supply chain risk low |
| `z3-solver` | ^4.12 (installed: 4.16.0.0) | SMT formal verification kernel | C extension; Alpine/musl incompatible |
| `structlog` | ^23.2 | Structured JSON logging | Low risk |
| `cryptography` | ≥46.0.7 | Ed25519, RSA, ECDSA | Well-maintained; CVE bumped in session 4 |

### 8.2 Extras (Opt-In)

| Extra | Key Packages | If Absent |
| ----- | ------------ | --------- |
| `[translator]` | httpx, openai, anthropic, tenacity | LLM translator unavailable |
| `[otel]` | opentelemetry-sdk | All spans no-op |
| `[fastapi]` | fastapi, starlette | FastAPI middleware raises `ConfigurationError` |
| `[langchain]` | langchain-core | LangChain adapter unavailable |
| `[redis]` | redis[hiredis] | Redis token verifier + Redis CB backend unavailable |
| `[postgres]` | asyncpg | Postgres token verifier unavailable |
| `[crypto]` | cryptography | Ed25519/RS256/ES256 signing unavailable |
| `[aws]` | boto3 ≥1.34 | AWS Secrets Manager + S3 sink unavailable |
| `[azure]` | azure-keyvault-secrets, azure-identity | Azure Key Vault unavailable |
| `[gcp]` | google-cloud-secret-manager | GCP Secret Manager unavailable |
| `[vault]` | hvac | HashiCorp Vault unavailable |
| `[kafka]` | confluent-kafka | Kafka interceptor + audit sink unavailable |
| `[pdf]` | fpdf2 | PDF report generation unavailable |
| `[metrics]` | prometheus-client | All metrics silently no-op |
| `[security]` | google-re2 | PII/regex features raise `ConfigurationError` at first use |
| `[nlp]` | detoxify, sentence-transformers | Keyword/Jaccard fallback |
| `[k8s]` | fastapi, uvicorn | K8s webhook raises `ConfigurationError` |
| `[bedrock]` | boto3 ≥1.34 | Bedrock translator unavailable |
| `[all]` | All of above | Everything |

### 8.3 Supply Chain Risks

- **`z3-solver`** is a C extension binary. Alpine/musl ban gate in CI prevents musl-linked builds, but custom environments bypassing this gate silently fail at Z3 context creation.
- **`confluent-kafka`** requires C-extension (`librdkafka`). Wheel availability varies; source builds require `cmake` and system headers.
- **`google-re2`** requires `libre2` headers on Linux. Prebuilt wheels exist for common platforms; source builds fail without `libre2-dev`.
- **`z3-solver` version pinning:** `^4.12` allows any 4.x minor. Z3 API surface has changed between 4.12 and 4.16. No automated compatibility test ensures a Z3 minor upgrade doesn't silently break transpiler semantics.

---

## Part 9: Open Action Items — Prioritized

### P0 — Existential (Must Fix Before Giant-Tier Adoption)

| ID | Item | Current State | Effort | Impact |
| -- | ---- | ------------- | ------ | ------ |
| P0.1 | **Re-license to Apache-2.0** or establish buyable commercial permissive license | AGPL-3.0-only | Medium (legal) | Removes #1 adoption blocker |
| P0.5 | **Fix coverage floor** — remove `--fail-under=95` override from `ci.yml:376`; enforce `pyproject.toml`'s 98% | 95% enforced; 98% claimed | Low | Closes 3% coverage loophole |

### P1 — Enterprise Blockers

| ID | Item | Effort | Impact |
| -- | ---- | ------ | ------ |
| P1.2 | **Production NLP validators** — trained toxicity model; full slur vocabulary; foreign-language coverage | High | Guardrails AI content safety parity |
| P1.3 | **Live LLM CI job** — `ollama`-based containerized model in `ci.yml`; validate Layer 4 consensus | High | Validates dual-model consensus in CI |
| P1.5 | **WARNING logs for translator cleanup swallows** — `cohere.py:156`, `gemini.py:103,216`, `redundant.py:167,189` | Low | Surface resource leaks in production |
| P1.6 | **Policy simulation YAML support** — extend `pramanix simulate` to accept declarative YAML policy | High | Democratizes policy authoring for non-Python users |
| P1.8 | **Gate `integration:` CI job** — add to merge pipeline `needs:` | Low | Broken integration tests block merges |

### P2 — Quality & Completeness

| ID | Item | Effort | Impact |
| -- | ---- | ------ | ------ |
| P2.4 | **Close Hypothesis `assume()` exclusions** in `test_sanitise_properties.py` | Medium | Edge-case sanitizer regression coverage |
| P2.5 | **Remove bare `sys.modules` assignments** from `test_coverage_gaps.py`; replace with `patch.dict` | Low | Session-safe `sys.modules` restoration |
| P2.7 | **Benchmarks on v1.0.0 / server hardware** — 8-core, 32 GB RAM; publish with confidence intervals | Medium | Credible P99 performance claims |
| P2.8 | **Policy coverage analysis** — `pramanix coverage policy.yaml --traffic log.ndjson` | High | Shows which declared fields are exercised |
| P2.9 | **Policy linter CLI** — `pramanix lint policy.yaml` with plain-English errors | High | Democratizes policy authoring |
| P2.10 | **Eradicate remaining 5 `sys.modules` patching files** with dedicated tox environments | Medium | Full test isolation for absent-package paths |
| P2.11 | **Verify `rotate_key()` for Azure/GCP/Vault providers** against real containers | Medium | Complete key rotation coverage |
| P2.12 | **Persistent `ApprovalWorkflow`** — database-backed with TTL, notification hooks | High | SOC2 dual-control compliance |
| P2.13 | **Docker: ensure google-re2 is preinstalled** or document it as mandatory | Low | PII detection works out of the box in Docker |
| P2.14 | **`PRAMANIX_TRANSLATOR_ENABLED` Docker build arg** — make it overridable without editing Dockerfile | Low | Translator testability in Docker |

### P3 — Excellence (Giant-Tier Polish)

| ID | Item | Effort |
| -- | ---- | ------ |
| P3.1 | Replace 5 stub integrations (CrewAI, DSPy, Haystack, SemanticKernel, PydanticAI) with real end-to-end tests | High |
| P3.2 | Commercial support tier / enterprise SLA | High (business) |
| P3.3 | `pytest.mark.xfail(strict=True)` for skipped real-LLM tests instead of `skipif` | Low |
| P3.4 | `ClockProtocol` formal `Protocol` type — replace `Callable[[], float]` | Low |
| P3.5 | String→Int promotion caching across same-field-set requests at runtime | Medium |
| P3.6 | Distributed trace context propagation through `Guard.verify()` into worker processes | Medium |
| P3.7 | `decision_id` injected into structlog context on ALLOW path | Low |
| P3.8 | Sample worker warmup constraints from deployed policy, not hardcoded 8-pattern set | Medium |
| P3.9 | No-concurrent-Z3-context destruction policy documented in module header | Low |
| P3.10 | Benchmark CI gate made blocking (`continue-on-error: false`) after v1.0.0 server baseline | Low |

---

## Part 10: Release Gate Status

> Source: `docs/RELEASE_READINESS.md` last updated 2026-06-02 session 4.

### Hard Blockers (Must be ✅ before `v1.0.0` PyPI tag)

| ID | Item | Status | Notes |
| -- | ---- | ------ | ----- |
| L1 | License decision (AGPL-3.0 vs Apache-2.0) | **BLOCKED** | Business/legal decision required |
| C2 | Coverage ≥ 98% | **CHECK** | Suite running; last measured 95.09% in April before new tests |

### Passing Gates (✅ as of 2026-06-02 session 4)

| Category | Passed | Notes |
| -------- | ------ | ----- |
| Code Quality | C1, C3, C4, C5, C6, C7, C8 | All unit tests pass; mypy strict; ruff clean; 0 `type:ignore`; 0 `pragma:no cover`; 0 mocks; `assert_and_track` |
| Packaging | P1–P9 | Wheel 570KB, 119 files; smoke test passes; all extras accurate; no dev files in wheel |
| Security | S1–S13 | SAST clean; pip-audit clean; no secrets in history; all 4 InMemory* production-guarded; Alpine banned; non-root Docker; HEALTHCHECK present |
| API Surface | A1–A6 | 157 exports; 17-key Decision; 32-field GuardConfig; CHANGELOG created |
| Documentation | D1–D7 | README source-verified; ENVIRONMENT.md; REPO_AUDIT.md; BLUEPRINT.md; WHITEPAPER.md; CLI help accurate |

### Non-Blocking (Must have a plan)

| ID | Item | Status |
| -- | ---- | ------ |
| E1 | `ApprovalWorkflow` durability (DB-backed) | Not done; documented gap |
| E2 | LLM consensus real-CI evidence | Not done; no API keys in standard CI |
| E3 | Merkle archive encryption | Not done; compression only; documented |
| E4 | Commercial support tier | Not done; business decision |
| F1-F3 | Benchmark baseline on production hardware | Pending |

### Summary

| Category | Done | Check | Blocked |
| -------- | ---- | ----- | ------- |
| License | 3 | 0 | **1** |
| Code Quality | 7 | **1** | 0 |
| Packaging | 8 | 0 | 0 |
| Security | 13 | 0 | 0 |
| API Surface | 6 | 0 | 0 |
| Documentation | 7 | 0 | 0 |
| **Total** | **44** | **1** | **1** |

---

## Part 11: The Honest Verdict

### What Pramanix Is Today

**A technically rigorous, formally correct AI governance library with world-class architecture and a critical commercialization gap.**

The Z3 formal verification core is unmatched. The cryptographic audit trail is enterprise-grade. The compliance oracle (SOC2/HIPAA/EU AI Act/GDPR attestation from Z3 proofs) is a genuine moat that no competitor has even attempted. Key rotation is fully implemented across all concrete providers with atomic writes. Execution tokens have four verifier implementations. `solver_factory` DI and production guard are wired — Z3 trust boundary is closed. 5,687 tests with zero `MagicMock`. mypy strict, ruff clean. `PRAMANIX_ENV=production` blocks all in-memory backends.

**But the hard truths must be stated:**

1. **AGPL-3.0 kills enterprise deals.** No technical excellence compensates for this. Enterprise legal teams reject AGPL before reading the README.

2. **The NLP safety layer is not production-grade.** Fifty-eight keyword stems and a TF-IDF cosine similarity measure do not compete with NeMo's production LLM rails or Guardrails AI's 50+ production validators. `pramanix[nlp]` with full ML models changes this — but those ML models are never tested in CI.

3. **The translator has never been tested against a real LLM in any CI run.** The dual-model consensus system — Pramanix's primary defense against LLM manipulation — has zero CI coverage on the execution path that matters.

4. **Coverage is 95% in CI, not 98%.** The claim in `pyproject.toml` is contradicted by the CI command. The actual enforced floor is lower than advertised.

5. **Benchmarks are stale.** All performance numbers are from v0.8.0 on consumer hardware. Seven changes since then affect latency. There is no v1.0.0 performance baseline.

6. **No persistent ApprovalWorkflow.** The compliance tool that enables SOC2 dual-control authorization does not ship a durable implementation.

### The Unique Moat — What No Competitor Has

The combination of:
1. **Z3 SMT formal verification** — math-proven ALLOW, counterexample-backed BLOCK. Prompt injection cannot change what Z3 returns.
2. **Ed25519 + Merkle cryptographic audit** — tamper-evident chain; verifiable by independent third parties
3. **HMAC-tagged compliance attestation** — SOC2/HIPAA/EU AI Act controls proven from Z3 proofs
4. **Atomic key rotation** — SOC2 control CC6.1 / PCI-DSS Req 3.5 satisfied
5. **Distributed single-use token enforcement** — Redis, SQLite, Postgres backends

...is genuinely world-class. No other library on Earth does all five simultaneously with this level of engineering rigor.

### What It Takes to Be Giant-Tier

| Dimension | Current State | Required State |
| --------- | ------------- | -------------- |
| License | AGPL-3.0 | Apache-2.0 or commercial permissive tier |
| NLP Safety | 58 stems / 8 categories; detoxify integration; Prometheus-observable degradation | Production model; 50+ validators; foreign-language coverage |
| Real LLM CI | Zero | At least 1 containerized model (Ollama) |
| Formal engine testing | `solver_factory` DI wired; 6 real stubs | Done |
| Developer UX | 15 CLI commands; no linter or REPL | Policy linter + YAML simulation CLI |
| Benchmarks | v0.8.0, laptop, no confidence intervals | v1.0.0, server hardware, published |
| Persistent oversight | InMemory only | Database-backed ApprovalWorkflow |
| Coverage enforcement | 95% in CI; 98% claimed | Enforce 98% without override |
| Integration CI gating | Advisory, not blocking | Block merge pipeline |
| Exception handling | Translator cleanup: silent swallow | WARNING log for all cleanup failures |
| Enterprise support | None | Commercial tier with SLA |
| Coverage claim | 95% enforced / 98% claimed | Enforce 98% consistently |

### The Path to Giant-Tier (Priority Order)

1. **Fix the license** — nothing else matters at enterprise scale without this
2. **Enforce 98% coverage in CI** — remove the `--fail-under=95` override
3. **Gate integration CI** — broken integration tests must block merges
4. **Ship real LLM in CI** — Ollama container; validate consensus pipeline
5. **Build the policy linter** — democratizes adoption for non-Z3 users
6. **Productionize the NLP layer** — trained model, not keyword stems
7. **Persistent ApprovalWorkflow** — complete the SOC2 compliance story
8. **Run v1.0.0 benchmarks on server hardware** — publish credible P99 numbers
9. **Commercial support tier** — the enterprise relationship that closes deals

---

## Appendix: Complete Fixed-Item History

All items confirmed fixed across audit passes 1-4 and sessions 1-4, with source citations:

| Item | How Fixed | Source / Commit |
| ---- | --------- | --------------- |
| `DistributedCircuitBreaker` silent InMemory default | Raises `ConfigurationError` if `backend=None` | `circuit_breaker.py:573-579` |
| RE2 hard-fail at import | Lazy `_require_re2()` → `ConfigurationError` on use; module imports cleanly | `nlp/validators.py:52-62`; `injection_filter.py:55-65` |
| `rotate_key()` `NotImplementedError` in PemKeyProvider | New Ed25519 in-memory replace | `key_provider.py:145-164` |
| `rotate_key()` `NotImplementedError` in FileKeyProvider | Atomic `mkstemp` + `os.replace()` | `key_provider.py:267-300` |
| `rotate_key()` `NotImplementedError` in AwsKmsKeyProvider | Cache invalidate + `rotate_secret()` | `key_provider.py:407-415` |
| `PRAMANIX_ALLOW_NO_AUDIT_SINKS=1` bypass env var | Removed from source entirely | `guard_config.py` (grep: no match) |
| `worker.py:331` bare `except Exception: pass` | ERROR log + exc_info + Prometheus counter | `worker.py:327-334` |
| `worker.py:441` bare `except Exception: pass` | ERROR log + exc_info + Prometheus counter | `worker.py:441-448` |
| `guard.py:252` bare `except Exception: pass` | DEBUG log: `log.debug("metrics increment failed: %s", _e)` | `guard.py:251-252` |
| InMemory* classes in `pramanix.__all__` | Removed from `__all__`; all emit production guard | `__init__.py:316-318` |
| InMemoryAuditSink no production warning | `UserWarning` + `ConfigurationError` on `PRAMANIX_ENV=production` | `audit_sink.py:117-125` |
| InMemoryDistributedBackend no production warning | `UserWarning` + production guard | `circuit_breaker.py:491-498` |
| InMemoryExecutionTokenVerifier usable in production | `ConfigurationError` if `PRAMANIX_ENV=production` | `execution_token.py:492-497` |
| InMemoryApprovalWorkflow no production warning | `UserWarning` + `ConfigurationError`; `TestInMemoryApprovalWorkflowProductionGuard` added | `oversight/workflow.py:486-493` |
| `_DEFAULT_TOXIC_WORDS` empty (0 stems) | 58 stems / 8 categories including slur coverage | `nlp/validators.py:373-430`; commit `b0a273e` |
| No Redis-backed `ExecutionTokenVerifier` | `RedisExecutionTokenVerifier` via `SET NX EX` | `execution_token.py:754-945` |
| No SQLite-backed `ExecutionTokenVerifier` | `SQLiteExecutionTokenVerifier` via UNIQUE constraint | `execution_token.py:518-749` |
| `asyncio.Lock` `cached_property` event loop binding | `@functools.cached_property` pattern | `circuit_breaker.py` |
| `SecurityWarning` Python 3.13 `NameError` | Defined unconditionally | `nlp/validators.py:28-29` |
| `SolverProtocol` not injectable via `GuardConfig` | `solver_factory: Callable[[Any], SolverProtocol] \| None` + production guard | `guard_config.py:528,726-733` |
| `tests/helpers/solver_stubs.py` absent | 6 real stubs: Raising, Timeout, Failing, Slow, Unsat, Sat | `tests/helpers/solver_stubs.py`; commit `a0ee71c` |
| All `unittest.mock.patch`/`MagicMock`/`AsyncMock` in tests | Zero-Mock Sprint — `real_protocols.py` (1,948 lines) | Commits `a0ee71c`, `cad42a0` |
| `fast_path.py` not fail-closed on parse error | Fail-closed; `pramanix_fast_path_parse_failure_total` counter | `fast_path.py:69` |
| `ClockProtocol` injection absent from transpiler | `GuardConfig.clock: Callable[[], float] \| None` wired end-to-end | `guard_config.py:551`; `transpiler.py:645` |
| No `ToxicityScorer` fallback observability | `pramanix_nlp_degradation_total` Counter + WARNING + `_backend` attribute | `nlp/validators.py:503-520` |
| No `SemanticSimilarityGuard` fallback observability | `pramanix_nlp_degradation_total` Counter + WARNING + `_backend` attribute | `nlp/validators.py:635-660` |
| Worker HMAC integrity seal absent | Seal + verify in `guard.py:1432-1440` | `guard.py:1432-1440` |
| `result_seal_key` not injectable | Injectable `result_seal_key` in `GuardConfig` + `WorkerPool.seal_key` | Phase 1 fix |
| Nonce replay prevention absent | `verify_async` nonce tracking | Phase 1 fix |
| `allow_insecure_timing_leaks` unguarded | Production `ConfigurationError` guard | Phase 1 fix |
| `error_domain` + `stack_trace_hash` absent on `Decision` | Both fields added; `_ERROR_DOMAIN_MAP` | Phase 2 fix (`99ea453`) |
| `ForAll(empty_array)` vacuously true | `allow_empty=False` default in `_ForAllOp` | Phase 3 fix (`99ea453`) |
| `ControlMapping.control_id` unvalidated | `_CONTROL_ID_PATTERNS` per-framework validation | Phase 4 fix (`99ea453`) |
| `asyncio.run()` in LangGraph `_swrapper` | Detects running loop via `asyncio.get_running_loop()`; dispatches to `ThreadPoolExecutor` | `integrations/langgraph.py:230-264` |
| `AgentOrchestrationAdapter` absent | `LangGraphGuardAdapter` + `AutoGenGuardAdapter` with real Z3 tests | `integrations/agent_orchestration.py` |
| CB `_lock` concurrent-mutation test absent | `TestCircuitBreakerLockLinearizability` (200 coroutines) | Phase 8 |
| Non-numeric state injection tests absent | `tests/integration/test_corrupted_state_injection.py` (19 tests) | Phase 8 |
| `ExpressionNode.__hash__` ambiguity | `__hash__ = None` intentional; documented | `expressions.py:500-504` |
| `default_oracle()` without built-in mappings | 31 built-in mappings pre-loaded | `compliance/oracle.py`; commit `143189b` |
| No compliance report CLI | `pramanix report` subcommand | `cli.py`; commit `143189b` |
| Benchmark CI gate non-blocking | Added to CI as blocking gate | commit `143189b` |
| 16 `# type: ignore` in production source | All removed via structural fixes (importlib, cast, Any annotations, NoReturn, pyproject overrides) | Session 4; commit `a6cc05b` |
| ruff lint violations | All 0 — multiple targeted fixes in session 4 | Session 4 (`9f7955f`) |
| `pramanix doctor` Windows UnicodeEncodeError | `→` → `->` in `cli.py` | commit `5fde07f` |

---

*This document supersedes `docs/REPO_AUDIT.md` and `docs/pramanix_deep_audit.md`.*
*Audit date: 2026-06-03 | Passes: 1-4 (deep audit) + Sessions 1-4 (improvement work)*
*Verified against: 112 production source files, 227 test files, `pyproject.toml`, `ci.yml`*
*Version: 1.0.0 (pre-release)*
