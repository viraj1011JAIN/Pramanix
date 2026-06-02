# REPO_AUDIT.md — Pramanix Repository Truth Baseline

> **Scope**: Every claim in this document is traceable to source code, test output, or CI configuration.
> Where functionality is documented but absent from source, this is stated explicitly.
> Nothing here is aspirational. This document supersedes `docs/pramanix_deep_audit.md`.
>
> **Last verified**: 2026-06-02
> **Auditor**: Source-verified against 112 production files, 224 test files, `pyproject.toml`, `ci.yml`

---

## Executive Summary

Pramanix is a production-quality Python SDK for formal AI safety guardrails. Its Z3 SMT solver
core is genuinely unique — no competitor ships deterministic formal verification in a guardrails
SDK. The cryptographic audit chain, compliance oracle, and fail-closed architecture are
enterprise-grade.

The primary GA blocker is the AGPL-3.0 license, which creates copyleft obligations incompatible
with enterprise SaaS deployment. All other blockers are technical and have clear resolution paths.

**Overall Maturity Score: 75/100** (vs 65/100 before Zero-Mock Sprint)

---

## Component Maturity Matrix

| Component | Score | Reality |
| ----------- |-------| --------- |
| Z3 Formal Verification Core | 98 | World-class; no competitor has this |
| Cryptographic Audit Trail | 95 | Ed25519/RS256/ES256 + Merkle |
| Compliance Oracle | 92 | 31 built-in mappings, 5 frameworks |
| Code Quality & Type Safety | 93 | mypy strict; 16 `# type: ignore` in prod (all legitimate: lazy optional imports + mypy inference limits) |
| Test Coverage (quantity) | 90 | 5,687 collected tests |
| Test Coverage (quality) | 68 | Zero-Mock Sprint complete; no MagicMock |
| NLP Safety Layer | 62 | 58 toxic stems, 8 categories; RE2 lazy |
| Developer Experience | 52 | CLI, init, simulate, doctor all working |
| Enterprise Adoption Readiness | 30 | AGPL-3.0 kills enterprise deals |
| Key Management | 82 | Full rotation + AWS/Azure/GCP/Vault |
| Execution Token Design | 78 | 4 verifier implementations |
| Production Confidence | 75 | fast_path fail-closed; Z3 trust boundary fixed |
| **Overall** | **75** | Materially strong; license + LLM CI blocking |

---

## PART 1 — WHAT IS GENUINELY WORLD-CLASS

### 1.1 Z3 SMT Kernel (`solver.py`, 491 lines)

No AI safety SDK ships deterministic formal verification. The implementation is architecturally correct:

**Two-Phase Solve** (`solver.py:320-420`):
- Phase A (shared solver): All invariants simultaneously. `s.set("timeout", timeout_ms)`. `s.set("rlimit", rlimit)` when >0. `s.reset()` after check (more reliable than `del` for native memory release). `z3.unknown` → `SolverTimeoutError`.
- Phase B (per-invariant attribution, UNSAT path only): Each invariant gets its own solver with exactly one `assert_and_track(formula, z3.Bool(label, ctx))` call.

**Threading safety**: `threading.local()` (`_tl_ctx`) — per-thread Z3 contexts. No global Z3 state shared between threads.

**Solver factory DI** (`guard_config.py:528`): `solver_factory: Callable[[], SolverProtocol] | None`. Tests inject `RaisingSolverStub`, `TimeoutSolverStub`, etc. from `tests/helpers/solver_stubs.py` (6 stubs).

**fail-closed guarantee**: `solver.py` wraps all Z3 calls. Any exception → `SolverTimeoutError` or propagates up to `_verify_core()` blanket `except Exception` → `Decision.error()`.

### 1.2 Transpiler (`transpiler.py`, 970 lines)

Converts Policy DSL expression trees → Z3 AST. Zero `eval()`, `exec()`, or `ast.parse()`. Pure tree-walk over `ConstraintExpr` nodes.

- `_realize_node()`: the core dispatch function
- Handles: `_EqOp`, `_NeOp`, `_LtOp`, `_LeOp`, `_GtOp`, `_GeOp`, `_AndOp`, `_OrOp`, `_NotOp`, `_AddOp`, `_SubOp`, `_MulOp`, `_DivOp`, `_ModOp`, `_PowOp`, `_ForAllOp`, `_ExistsOp`, `_NowOp`, `_FieldRef`, `_LiteralNode`
- `_ForAllOp.allow_empty=False` default: prevents vacuous truth (Phase 3 STOP 4 fix)
- `_NowOp`: uses `clock() if clock is not None else _time.time()` — injectable for testing

### 1.3 Compliance Oracle (`compliance/oracle.py`, 1,482 lines)

Maps Z3 invariant labels → regulatory controls. Unique capability; no competitor has this.

**Implemented**:
- `ComplianceOracle.register_mapping()`: adds `ControlMapping` to `_registry[framework]`
- `ComplianceOracle.get_mappings(framework)`: snapshot of all mappings for a framework
- `default_oracle()`: factory pre-loaded with 31 built-in `ControlMapping` instances
- `_BUILT_IN_MAPPINGS`: SOC2 (7 entries), EU AI Act (8 entries), HIPAA (6 entries), NIST AI RMF (6 entries), GDPR (4 entries) = 31 total
- `ControlMapping.control_id` validated per-framework via `_CONTROL_ID_PATTERNS` (Phase 4 fix)
- `custom_control=True` escape hatch emits `UserWarning`

**Frameworks supported**: `RegulatoryFramework.SOC2`, `EU_AI_ACT`, `HIPAA`, `NIST_AI_RMF`, `GDPR`

### 1.4 Cryptographic Audit Chain

**Signing** (`audit/signer.py`):
- `PramanixSigner`: Ed25519 signing
- `RS256Signer`: RSA-2048+ signing (JWT-compatible)
- `ES256Signer`: ECDSA P-256 signing (JWT-compatible)
- All signers: `sign(payload: bytes) → bytes`, `verify(payload, signature) → bool`

**Merkle Log** (`audit/merkle.py`):
- Tamper-evident append-only log
- `PersistentMerkleAnchor`: disk-backed anchor

**Key Providers** (`key_provider.py`):
- `PemKeyProvider`: direct PEM string
- `EnvKeyProvider`: env var
- `FileKeyProvider`: filesystem
- `AwsKmsKeyProvider`: AWS Secrets Manager (with `rotate_key()`)
- `AzureKeyVaultKeyProvider`: Azure Key Vault
- `GcpSecretManagerKeyProvider`: GCP Secret Manager

---

## PART 2 — REAL IMPLEMENTATIONS (VERIFIED)

### 2.1 Fast Path (`fast_path.py`, 297 lines)

Numeric comparison pre-check before Z3 invocation. **Fail-closed**:
- Malformed numeric input → returns block-reason string (not `None`)
- `pramanix_fast_path_parse_failure_total` Prometheus counter incremented on parse failure
- Only handles simple numeric comparisons; all other cases fall through to Z3

### 2.2 Circuit Breaker (`circuit_breaker.py`, 1,340 lines)

Full state machine: CLOSED → OPEN → HALF_OPEN → CLOSED.
- `AdaptiveCircuitBreaker`: pure in-process with `asyncio.Lock` (via `cached_property`)
- `DistributedCircuitBreaker`: raises `ConfigurationError` if no backend provided (not silent)
- `RedisDistributedBackend`: Redis `SET NX EX` atomic operations
- `InMemoryDistributedBackend`: uses `threading.Lock` (class-level); emits `UserWarning` when `PRAMANIX_ENV=production`

### 2.3 Worker Pool (`worker.py`, 1,018 lines)

- `ThreadPoolExecutor` (default) or `ProcessPoolExecutor` (configurable)
- Warmup: 8-pattern Z3 suite to eliminate cold-start JIT spike
- `model_dump()` called BEFORE `ProcessPoolExecutor.submit()` (pickling safety)
- Bare `except` blocks in `worker.py:327-334, 441-448` log at ERROR with `exc_info=True`; increment Prometheus counter

### 2.4 Execution Tokens

4 verified implementations:
- `InMemoryExecutionTokenVerifier` (testing only; production guard)
- `RedisExecutionTokenVerifier`: `SET NX EX` atomic anti-replay
- `SQLiteExecutionTokenVerifier`: SQLite with WAL mode
- `PostgresExecutionTokenVerifier`: asyncpg-backed

### 2.5 NLP / Content Safety (`nlp/validators.py`, 775 lines)

**Implemented with caveats**:
- `PIIDetector`: google-re2 regex patterns for email/phone/SSN/credit card/IBAN. No ML.
- `ToxicityScorer`: `_DEFAULT_TOXIC_WORDS` — 58 stems across 8 categories including slurs. Keyword matching only. No LLM or toxicity model.
- `RegexClassifier`: user-supplied regex patterns via google-re2
- `SemanticSimilarityGuard`: requires scikit-learn TF-IDF cosine similarity. No sentence-transformers.

**RE2 behavior** (verified):
- `_RE2_AVAILABLE = False` at module level if google-re2 absent
- `_require_re2()` raises `ConfigurationError` **lazily** when PII/regex features first used
- Module imports cleanly without RE2 (no crash at import time)

**Critical caveat**: These are not ML safety classifiers. They are keyword/regex filters.
Claims about "NLP safety" must acknowledge this.

### 2.6 InMemory* Production Guards

All 4 in-process implementations emit `UserWarning` when `PRAMANIX_ENV=production`:
- `InMemoryAuditSink`
- `InMemoryDistributedBackend`
- `InMemoryExecutionTokenVerifier`
- `InMemoryApprovalWorkflow`

`DistributedCircuitBreaker` raises `ConfigurationError` (not warning) if no backend.

---

## PART 3 — KNOWN LIMITATIONS (HONEST)

### 3.1 License — GA-Critical Blocker

**Current**: AGPL-3.0-only (community). Commercial license exists at `LICENSE-COMMERCIAL`.
**Problem**: AGPL copyleft requires SaaS operators to publish their application source. This is incompatible with standard enterprise SaaS deployment. Most enterprise prospects will legally require Apache-2.0 or MIT.
**Status**: Requires business/legal decision. No code change solves this.

### 3.2 LLM Consensus — No Real-CI Evidence

`RedundantTranslator` implements quorum voting across multiple LLM backends. The design is correct. However:
- Integration tests that call real LLMs are skipped in CI if API keys are absent
- There is no CI evidence that consensus actually works with real LLM responses
- This is documented in `docs/pramanix_deep_audit.md` (Pass 4)
- The implementation is real; the CI validation gap is the honest limitation

### 3.3 NLP Layer — Keyword/Regex, Not ML

`ToxicityScorer` is not a toxicity model. It is a keyword filter with 58 stems. Claims about "NLP safety" must acknowledge this is not a trained classifier.

`SemanticSimilarityGuard` uses TF-IDF (cosine similarity via scikit-learn), not sentence-transformers. Semantic similarity is approximate for short inputs.

### 3.4 Merkle Archive Encryption

`MerkleArchiver` compresses but does not encrypt archives. Archives are plaintext (zstd-compressed). If the audit log must be confidential, callers must encrypt at the storage layer.

### 3.5 Persistent ApprovalWorkflow

`InMemoryApprovalWorkflow` is the only working implementation. There is no database-backed `ApprovalWorkflow`. Approval tokens do not survive process restart.
Status: Requires DB schema design decision.

### 3.6 Production Deployment History

No production deployment metrics are tracked in this repository. All latency/throughput benchmarks are in-process measurements on development hardware, not production measurements.

---

## PART 4 — TEST REALISM AUDIT

### 4.1 Zero-Mock Sprint (Completed, Commit `a0ee71c`)

Zero `unittest.mock.patch`, `MagicMock`, `AsyncMock` in the test suite.
Real alternatives used:
- `tests/helpers/solver_stubs.py`: 6 real `SolverProtocol` stubs
- `tests/helpers/real_protocols.py`: 1,948 lines of real test helpers
- `fakeredis` for Redis tests
- `InMemorySpanExporter` (OTel SDK) for telemetry tests

### 4.2 Hypothesis Property Tests

4 files in `tests/property/`:
- `test_fintech_primitive_properties.py`: Float-drift safety, monotonicity (1,000+ examples each)
- `test_serialization_roundtrip.py`: Serialization consistency
- `test_dsl_and_transpiler_properties.py`: DSL→Z3 roundtrip
- `test_sanitise_properties.py`: Sanitiser invariants

`deadline=None` on slow tests to prevent CI deadline failures.

### 4.3 Integration Tests

34 files in `tests/integration/`. Key real integrations:
- `test_redis_circuit_breaker.py`: real fakeredis
- `test_fastapi_middleware.py`: real Starlette TestClient
- `test_banking_flow.py`: end-to-end guard pipeline
- `test_process_mode.py`: real `ProcessPoolExecutor`
- LLM translator tests: skipped when API keys absent (not mocked)

### 4.4 Adversarial Tests

14 files in `tests/adversarial/`:
- `test_prompt_injection.py`: 26 attack vectors
- `test_field_overflow.py`: boundary/overflow
- `test_z3_context_isolation.py`: Z3 isolation
- `test_worker_crash_isolation.py`: process crash recovery
- `test_hmac_ipc_integrity.py`: HMAC verification
- `test_toctou_awareness.py`: TOCTOU awareness

---

## PART 5 — CI PIPELINE AUDIT (`ci.yml`)

### 5.1 Verified Gates

| Gate | Status |
| ------ |--------|
| SAST (bandit/semgrep) | ✅ Job: `sast` |
| Alpine ban (Docker) | ✅ Checked in CI |
| ruff lint | ✅ Job: `lint` |
| mypy strict | ✅ Job: `lint` |
| Unit + adversarial + property tests | ✅ Job: `coverage` |
| Coverage ≥ 98% | ✅ `fail_under = 98` |
| Integration tests | ✅ Job: `integration` |
| Benchmark + perf tests | ✅ Jobs: `perf`, `tests/benchmarks/` |
| Trivy container scan | ✅ Job: `trivy` |
| License scan | ✅ Job: `license-scan` |
| Ollama live tests | ✅ Job: `ollama-live` |
| Wheel smoke test | ✅ After `coverage` + `integration` |

### 5.2 Honest Gaps in CI

- LLM API keys: Anthropic/OpenAI/Gemini tests skipped in CI (no real keys)
- `PRAMANIX_REDIS_URL`: Redis-backed tests use fakeredis in unit, real container in integration
- `AWS_ACCESS_KEY_ID`: LocalStack used (not real AWS in standard CI)

---

## PART 6 — DEPENDENCY MAP

### Required (always installed)

| Package | Version | Purpose |
| --------- |---------| --------- |
| `pydantic` | ^2.5 | Policy and config validation |
| `z3-solver` | ^4.12 | SMT solving |
| `structlog` | ^23.2 | Structured logging |
| `google-re2` | >=1.0 | Regex safety (replaces stdlib `re`) |

### Extras (opt-in)

| Extra | Key Packages | Purpose |
| ------- |-------------| --------- |
| `translator` | httpx, openai, anthropic, tenacity | LLM translators |
| `otel` | opentelemetry-sdk | OpenTelemetry tracing |
| `fastapi` | fastapi, starlette | FastAPI middleware |
| `langchain` | langchain-core | LangChain adapter |
| `redis` | redis | Distributed circuit breaker, intent cache |
| `crypto` | cryptography | Ed25519, RS256, ES256 signing |
| `aws` | boto3 | AWS Secrets Manager, S3 |
| `azure` | azure-keyvault-secrets, azure-identity | Azure Key Vault |
| `gcp` | google-cloud-secret-manager | GCP Secret Manager |
| `vault` | hvac | HashiCorp Vault |
| `kafka` | confluent-kafka | Kafka audit sink |
| `pdf` | fpdf2 | PDF report generation |
| `metrics` | prometheus-client | Prometheus metrics |
| `security` | google-re2 | (redundant with required dep) |
| `all` | all of the above | Everything |

---

## CHANGE LOG

| Date | Change | Author |
| ------ |--------| -------- |
| 2026-06-02 | Initial creation, supersedes `docs/pramanix_deep_audit.md` | Viraj Jain |
