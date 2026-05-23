# Pramanix SDK — Hard Reality Audit  
## Full 360° Deep Audit · Every Angle · No Sugar-Coating  
### Benchmarked Against: NeMo Guardrails & Guardrails AI  
### Pass 2 — Complete Source Verification

> **Auditor scope:** All 47 source modules read in full. 166 test files. 4 Dockerfiles. `ci.yml` (845 lines). `pyproject.toml` (396 lines). `flaws.md` (753 lines). `gaps.md` (926 lines). `docs/Ideal_Architecture.md` (180 KB). All integration, compliance, oversight, circuit-breaker, translator, NLP, key-provider, guard, solver, and execution-token modules. Zero skipped files.

---

## 🔴 Executive Summary — The Hard Truth

Pramanix is **technically extraordinary and productively dangerous at the same time.**

The formal verification core (Z3 SMT solver) is genuinely world-class — no competitor ships this. The cryptographic audit chain (Ed25519 / Merkle) is enterprise-grade. The compliance oracle (`compliance/oracle.py` — 1,482 lines) maps Z3 invariant labels to SOC2, EU AI Act, HIPAA, NIST AI RMF, ISO 42001, and GDPR controls — a differentiating capability no competitor has. The test suite at **4,494 passing tests** with mypy strict-mode clean and 0 `# type: ignore` in production source represents serious engineering discipline.

But when measured against **what it takes to actually reach NeMo or Guardrails AI parity**, the SDK has critical gaps that prevent serious enterprise adoption today.

| Dimension | Score | Reality |
|-----------|-------|---------|
| Core Formal Engine | 98/100 | World-class, unmatched |
| Cryptographic Audit Trail | 95/100 | Excellent |
| Compliance/Regulatory Mapping | 90/100 | Unique advantage — nobody else has this |
| Code Quality & Type Safety | 93/100 | Very strong |
| Test Coverage (quantity) | 85/100 | Large but mock-heavy |
| Test Coverage (quality/realism) | 52/100 | Serious gaps |
| NLP Safety Coverage | 38/100 | Beta / placeholder |
| Developer Experience | 45/100 | Steep learning curve |
| Enterprise Adoption Readiness | 28/100 | AGPL kills deals |
| Competitive Parity (NeMo) | 40/100 | Different lane, losing NLP |
| Competitive Parity (Guardrails AI) | 44/100 | Schema safety: losing |
| Production Confidence | 58/100 | Core strong, edges thin |
| **Overall Pramanix Score** | **60/100** | **Strong foundation, incomplete SDK** |

---

## PART 1: WHAT IS GENUINELY WORLD-CLASS

### 1.1 The Z3 SMT Kernel — Your Single Biggest Advantage

No other AI safety SDK in the world uses formal verification (SMT solving) to enforce guardrails. This is your differentiated identity and the only reason a Fortune-500 CISO would pick you over Guardrails AI.

**What's excellent:**
- Two-phase architecture: Phase A (shared solver, all invariants) → Phase B (per-invariant attribution on UNSAT path only) — the correct design
- Thread-local Z3 contexts via `_tl_ctx: threading.local` with `_Z3_CTX_CREATE_LOCK` for safe context allocation — correct for Windows Z3 race conditions
- `_Z3_CTX_CREATE_LOCK` serialises Z3 context construction globally — addresses the Windows access-violation crash documented in `solver.py` lines 94-98
- Exact `Decimal.as_integer_ratio()` → `z3.RatVal(n, d, ctx)` conversion — correct financial arithmetic without floating point error
- Fail-safe DENY on solver failure: `Guard.verify()` **never raises**, always returns `Decision(allowed=False)` on any exception path
- `InvariantASTCache` at `Guard.__init__` time — compile once, evaluate on every request
- Per-invariant isolation on BLOCK path for precise named violation reporting
- `SolverTimeoutError` surfaces to caller rather than silently blocking
- Array quantifiers (`ForAll`, `Exists`) realized to bounded unrolling before Z3 dispatch — correct design for finite-domain array constraints
- `rlimit` resource limit (Z3 elementary operations) as DoS protection — prevents logic-bomb / non-linear explosion regardless of wall-clock time
- `_z3_eq()` using `Z3_mk_eq` directly to bypass `SeqRef.__eq__` Python bool trap

**Real gaps that still exist:**
- **No `SolverProtocol` injection interface.** All 3+ test files still `patch("z3.Solver")` rather than injecting a `FailingSolverStub`. A Z3 v4→v5 regression producing wrong constraint results would pass all tests silently. The `SolverProtocol` is defined in `solver.py:66-77` (a structural Protocol with `set`, `add`, `assert_and_track`, `check`, `unsat_core`) but is never injected via `GuardConfig` — it's documentation only.
- **No `ClockProtocol`.** Nine direct `time.time()` call sites in `execution_token.py` and one in `transpiler.py` have no injection seam. Testing TTL expiry requires real `time.sleep()` or `monkeypatch.setattr(time, "time", ...)`.
- **No concurrent-mutation integration test** for the circuit-breaker `_lock` after the `@functools.cached_property` fix.

### 1.2 Cryptographic Audit Chain

- Ed25519 (`PramanixSigner`), RS256, ES256 asymmetric signers — production-grade cryptographic foundation
- Merkle anchoring: each decision links to prior via `HMAC-SHA256(decision_hash + prior_root)`
- `DecisionSigner.__init__` raises `ConfigurationError` on missing/short key — no silent unsigned records
- `PersistentMerkleAnchor` with SQLite backend — durable audit anchoring
- `_sign_decision()` in `guard.py:411-458` applies oracle-attack redaction **after** signing — hash covers real fields, redacted values returned to caller. Correct implementation.
- All `.verify()` methods distinguish `InvalidSignature` (return `False`) from infrastructure failures (raise `VerificationError`) — correct behavior

### 1.3 Compliance Oracle — Genuine Differentiator

The `compliance/oracle.py` (1,482 lines, 59 KB) is a genuine competitive differentiator that **no other AI safety library provides**:

- Maps Z3 invariant labels + SPIFFE principal identities → SOC2, EU AI Act, HIPAA, NIST AI RMF, ISO 42001, and GDPR controls
- `ComplianceAttestation` is cryptographically linked to `ProvenanceRecord` via HMAC-SHA-256 tag
- `ControlMapping` supports `INVARIANT_LABEL`, `PRINCIPAL_IDENTITY`, and `BOTH` matching modes
- `MappingMatchKind.BOTH` — requires both invariant label AND principal identity to match — the tightest possible evidence linkage
- Thread-safe via `threading.RLock` on the mapping registry
- Fail-closed: `evaluate_record()` never raises — internal errors return an error attestation, not a pass
- Completely offline/batch-capable: no Guard calls, no network, usable in async pipelines

**Gaps in compliance oracle:**
- No end-to-end integration test that produces a real `ComplianceAttestation` from a real `Guard.verify()` call. The oracle is well-designed but tested in isolation.
- No UI or CLI for generating compliance reports. Operators need to write custom code to use the oracle.
- GDPR and HIPAA mappings are supported by the framework but no built-in mapping library ships with the SDK — operators must define all mappings themselves.

### 1.4 Policy Engine Architecture

The `PolicyIR` → `PolicyCompiler` → `ConstraintExpr` pipeline is well-designed:
- **LLM never called by Guard.verify()** — the compilation step is pre-flight only
- **No `eval()`, no `exec()`**, no dynamic code generation — the compiler is pure-Python deterministic
- `Condition` model-validator catches `IN`/`NOT_IN` with non-list RHS at schema validation time
- `PolicyCompiler` validates field existence, type compatibility, and operator applicability before Z3 runs
- `NaturalPolicyCompiler` with `MetaVerifier` (STRICT mode) catches LLM hallucination via semantic distance check
- Policy fingerprinting (`_compute_policy_fingerprint`) detects policy drift between deployments
- `Guard.__init__` validates policy semver and fingerprint at construction time — authoring errors surface immediately

### 1.5 Circuit Breaker — Now Fail-Safe by Default (P0.3 ALREADY FIXED)

> ⚠️ **CORRECTION FROM PREVIOUS AUDIT:** The `InMemoryDistributedBackend` default issue **has already been fixed.**

From `circuit_breaker.py:573-579`:
```python
if backend is None:
    from pramanix.exceptions import ConfigurationError
    raise ConfigurationError(
        "DistributedCircuitBreaker requires an explicit backend. "
        "Pass backend=RedisDistributedBackend(...) for production, "
        "or backend=InMemoryDistributedBackend() in test code."
    )
```

`DistributedCircuitBreaker` now **refuses to construct** without an explicit backend. This eliminates the silent in-memory default trap. P0.3 is closed.

The `RedisDistributedBackend.set_state()` uses `WATCH`/`MULTI`/`EXEC` optimistic locking (lines 964-1017) — eliminates the TOCTOU race on distributed state updates without Lua scripting. Excellent.

### 1.6 LangGraph Integration — Well-Designed

`integrations/langgraph.py` (450 lines) provides:
- `PramanixGuardNode` with fail-closed `on_fail="halt"` and shadow `on_fail="warn"` modes
- `bypass_on_timeout=True` default — prevents Z3 timeouts from halting long-running agent workflows
- Structured policy verdict sidecar injected into node state
- Prometheus metrics per node+policy combination
- `@pramanix_node(...)` decorator — zero-friction integration with existing LangGraph nodes
- `GuardNodeAdapterProtocol` as a structural runtime-checkable interface

**Gap:** The `_swrapper` for sync LangGraph nodes calls `asyncio.run()` (line 231-238). This will raise `RuntimeError` if called from within an existing async event loop (e.g., a Jupyter notebook or FastAPI async context). No guard or documentation for this.

### 1.7 Dual-Model Consensus — Sophisticated Security Pipeline

`translator/redundant.py` implements a 6-layer security pipeline:
1. System 1 fast-path injection filter (regex, sub-ms)
2. Unicode NFKC sanitization + control-char strip
3. Parallel LLM extraction via `asyncio.gather(return_exceptions=True)` — both failures diagnosed separately
4. Schema validation on both results
5. Consensus check with `strict_keys`, `lenient`, or `unanimous` modes
6. Post-consensus injection confidence gate

`ConsensusStrictness.SEMANTIC` compares numeric values via `Decimal(str(v))` — `"500"` == `"500.0"` == `"5.0E+2"` — semantically correct for financial amounts.

`create_translator()` factory supports: `gpt-*`, `claude-*`, `ollama:*`, `gemini:*`, `cohere:*`, `mistral:*`, `llama:*` — broad model support.

### 1.8 Type Safety & Code Quality

- **0 `# type: ignore` in `src/pramanix/`** — eliminated entirely
- `mypy --strict` passes cleanly
- `ruff` with security rules (`S`, `ASYNC`, `B`) passes
- `py.typed` marker present — SDK ships with type stubs
- `SecurityWarning` defined unconditionally (Python 3.13 `NameError` fixed)
- `structlog` structured logging throughout

### 1.9 CI/CD — Thorough but with Gaps

The `ci.yml` (845 lines) is among the most thorough CI pipelines I've seen for a Python SDK:
- SAST first: `pip-audit` + `bandit` + `semgrep` run before any tests
- Alpine/musl ban gate — prevents Z3 glibc incompatibility at CI level
- Lint + mypy strict before tests
- Matrix: Python 3.11, 3.12, 3.13
- Coverage gate (98% in `pyproject.toml`, CI currently enforces **95%** — see §2.9)
- Wheel + sdist install smoke tests in clean venvs
- Extras smoke test (15 extras, ~40 module import checks)
- Trivy container CVE scan (CRITICAL/HIGH fail)
- License allowlist enforcement
- Nightly P99 < 15ms benchmark gate
- Real infrastructure integration tests with testcontainers (Redis, Kafka, Postgres, Vault, LocalStack)

---

## PART 2: WHAT IS GENUINELY BROKEN OR MISSING

### 2.1 🔴 CRITICAL: AGPL-3.0 — The #1 Adoption Killer

Every competitor — NeMo, Guardrails AI, LangChain, LlamaIndex, LangGraph — is **Apache-2.0 or MIT**.

AGPL-3.0 means:
- Any enterprise that embeds Pramanix in a commercial product must open-source their **entire application**
- Enterprise legal teams at Google, Microsoft, Goldman Sachs, JPMorgan **routinely reject AGPL** without reading further
- Cloud providers cannot ship Pramanix as a managed service without triggering AGPL copyleft
- Fortune-500 procurement rejects Pramanix at the legal review stage, even if the technology is superior

**This is not a code problem. It is the #1 reason Pramanix cannot reach NeMo or Guardrails AI adoption levels regardless of technical quality.** No audit recommendation will matter more than re-licensing to Apache-2.0 or establishing a dual-license commercial tier.

### 2.2 🔴 CRITICAL: Zero Real LLM Testing in CI

- `tests/integration/test_llm_consensus.py` — **always skipped** in CI (requires `OPENAI_API_KEY`)
- `tests/integration/test_gemini_translator.py` live tests — **always skipped** in CI (requires `GOOGLE_API_KEY`)
- `tests/integration/test_llamacpp_translator.py` — **always skipped** in CI (requires `PRAMANIX_TEST_GGUF_PATH`)
- `tests/unit/test_translator.py` (1,140 lines) — **zero real API calls**; 100% fake translators
- `PRAMANIX_TRANSLATOR_ENABLED="false"` is baked into **both** `Dockerfile.dev` and `Dockerfile.production`

The Layer 4 dual-model consensus system — Pramanix's defense against LLM extraction manipulation — **has never been tested against a real LLM in any CI run**. A regression in consensus logic would not be caught.

**NeMo Guardrails** runs real model inference in its CI against containerised models. **Guardrails AI** tests real validators against real LLM outputs.

### 2.3 🔴 CRITICAL: `rotate_key()` Raises `NotImplementedError` in All Concrete KMS Providers

```python
# src/pramanix/key_provider.py
class PemKeyProvider:
    def rotate_key(self) -> None:
        raise NotImplementedError  # line 147

class FileKeyProvider:
    def rotate_key(self) -> None:
        raise NotImplementedError  # line 200

class AwsKmsKeyProvider:
    def rotate_key(self) -> None:
        raise NotImplementedError  # line 254
```

Any automated key rotation pipeline calling `.rotate_key()` will **crash at runtime** with zero advance warning. The abstract base class requires this method, concrete classes pretend to implement it, and the test suite never calls it against real rotation flows.

This is a HIGH-severity production risk for any security team with automated key rotation (which is every team operating under SOC2 or PCI-DSS).

### 2.4 🔴 CRITICAL: Integration CI Job Does Not Gate Merges

Looking at the `ci.yml` dependency graph:
```
sast → alpine-ban → lint-typecheck → test → { coverage, integration } → wheel-smoke → extras-smoke → trivy → license-scan
```

The `wheel-smoke` job has `needs: [coverage, integration]` — this means **integration IS a merge gate**. However:
- `integration` runs **again separately** from the main `test` job
- The integration job installs dev dependencies separately from the main test matrix
- This means a flaky integration test environment can fail a PR that passed all unit tests

**Real gap confirmed:** The integration job's test count and coverage is NOT included in the coverage report. Integration-only code paths are invisible to the coverage gate.

### 2.5 🟠 HIGH: `ExecutionTokenVerifier` In-Memory Registry — Replay Attack in Multi-Process

`execution_token.py` module docstring (lines 62-68) documents this explicitly:
```
The ExecutionTokenVerifier consumed-set is in-memory only.
In a multi-process deployment each process has its own registry;
a token minted in process A can be consumed once in process A and
once in process B.
```

The module provides `PostgresExecutionTokenVerifier` (requires `asyncpg`) for distributed single-use enforcement. However:
- There is no Redis-backed verifier despite Redis already being a first-class dependency
- There is no `ConfigurationWarning` when `ExecutionTokenVerifier` (in-memory) is used in a production deployment
- The operator must discover the limitation in the docstring

### 2.6 🟠 HIGH: NLP Safety Layer Is Effectively Placeholder-Grade

The `ToxicityScorer`, `PIIDetector`, and `SemanticSimilarityGuard` in `nlp/validators.py` have cascading fallback degradation:

| Model Missing | Fallback | Evasion Risk |
|---------------|----------|-------------|
| `detoxify` absent | Keyword-density heuristic | Synonyms, obfuscation, foreign language all evade |
| `sentence-transformers` absent | Jaccard word-overlap | Paraphrasing trivially evades |
| `google-re2` absent | Stdlib `re` | **Now raises `RuntimeError` immediately (fixed!)** |

**New finding:** `nlp/validators.py:43-48` — the module now **raises `RuntimeError` at import time** if `google-re2` is not installed, instead of falling back to stdlib `re`. This is the correct hardened behavior. `google-re2` absence is now a hard failure, not a silent downgrade.

**Still broken:**
```python
# nlp/validators.py line 363
# Slurs (placeholder stems — extend via extra_words in production)
# Intentionally limited here to avoid reproducing a comprehensive slur list.
```
`_DEFAULT_TOXIC_WORDS` contains **zero slur stems**. The `ToxicityScorer` in keyword mode will never catch slurs. The comment instructs operators to supply their own list but there is no enforcement mechanism — `ToxicityScorer()` constructs successfully with an empty toxic word set and silently provides false confidence.

**NeMo Guardrails** ships with production-tested LLM rails for toxicity, jailbreak detection, topic filtering, and hallucination detection — all working out of the box. **Guardrails AI** ships with 50+ built-in validators including PII, toxicity, bias, and factuality — all production-grade. Pramanix's NLP layer, in its current state, is not competitive with either.

### 2.7 🟠 HIGH: `PRAMANIX_ALLOW_NO_AUDIT_SINKS=1` Bypass

Setting `PRAMANIX_ALLOW_NO_AUDIT_SINKS=1` **disables the production audit-trail enforcement entirely**. Any developer who sets this in a `.env` file or CI environment can accidentally ship a production deployment with no audit persistence. The docstring comment is the only safeguard.

### 2.8 🟠 HIGH: Bare Exception Handlers in Production Source

Critical bare exception handlers in production code:
- `circuit_breaker.py:85, 253, 701, 764, 1257, 1285` — six handlers with no log
- `guard.py:252` — `_emit_field_seen_metric()` still has `except Exception: pass` with `log.debug` (marginally acceptable)
- `worker.py:727` — GC finalizer `pass`
- `interceptors/kafka.py:126` — Kafka GC finalizer

Production debugging is impossible when these handlers fire silently.

### 2.9 🟠 HIGH: Coverage Floor Conflict

```toml
# pyproject.toml
fail_under = 98

# .github/workflows/ci.yml line 376
coverage report --fail-under=95
```

The CI overrides `pyproject.toml` with a lower threshold. The actual enforced coverage floor in CI is **95%, not 98%**. Three percent of production paths could be uncovered across all PRs without failing the build.

### 2.10 🟡 MEDIUM: `PramanixGuardNode` Sync Wrapper AsyncIO Incompatibility

`langgraph.py:231-238`:
```python
def _swrapper(state: Any, *args: Any, **kwargs: Any) -> Any:
    return asyncio.run(
        self._run(...)
    )
```

`asyncio.run()` raises `RuntimeError: This event loop is already running` when called from within an async context (FastAPI, Jupyter, pytest-asyncio). Any synchronous LangGraph node used inside an async FastAPI endpoint will crash. No documentation or guard against this.

### 2.11 🟡 MEDIUM: Orchestration Depth Gap vs. LangGraph/LangChain

Pramanix is an **execution firewall** — it gates individual tool invocations. It does not:
- Track agent reasoning chains
- Manage multi-step workflow state
- Route between tools based on policy outcomes
- Monitor cross-agent handoffs

LangGraph and AutoGen outperform in multi-step agent workflows by a wide margin. Pramanix has no `AgentOrchestrationAdapter` protocol, no graph-state awareness, and no published integration pattern for using Pramanix as a gate within a multi-step LangGraph state machine.

---

## PART 3: TEST QUALITY REALITY CHECK

### 3.1 Quantity vs. Quality

**4,494 passing tests** is impressive. But the test suite has a structural problem: **breadth is achieved via mocking, not reality**.

The complete mock inventory:

| Mock Pattern | Count | Reality |
|-------------|-------|---------|
| `patch()` / `patch.object()` replacing real callables | 50+ occurrences (15+ files) | Real code paths not exercised |
| `patch.dict(sys.modules)` hiding real packages | 40+ occurrences (20+ files) | Real import failures never induced |
| `monkeypatch.setattr` replacing real functions | 80+ occurrences (46 files) | Real function bodies never run |
| Duck-typed test doubles (not `MagicMock` but still fakes) | 60+ classes | Real implementations not tested |
| All LLM translator tests | 1,140-line file | Zero real API calls |
| Z3 solver replacement | 4 locations | Real Z3 never exercised in failure tests |

### 3.2 The Z3 Trust Boundary Violation

This is the most serious test quality gap. Z3 is Pramanix's security kernel. Tests that `patch("z3.Solver")` or `monkeypatch.setattr(guard, "solve", ...)` **bypass the security kernel entirely**. If Z3 v4→v5 produces wrong constraint results, every one of these tests would pass while Pramanix silently allows unsafe actions in production.

The `SolverProtocol` is defined in `solver.py:66-77` — a perfect structural interface. But it's never injected via `GuardConfig(solver=...)`. Until it is, the Z3 security boundary cannot be tested without patching.

### 3.3 The Adversarial Test Illusion

`tests/adversarial/test_fail_safe_invariant.py` has 15+ `monkeypatch.setattr` calls replacing `validate_intent`, `validate_state`, `flatten_model`, and `solve`.

These tests verify that **when a function is artificially made to crash**, the guard returns BLOCK. What they **do not verify** is that a real Z3 memory exhaustion, a real network partition (in distributed mode), or a real C-library segfault produces fail-safe BLOCK.

### 3.4 `sys.modules` Poisoning

Tests in `test_coverage_gaps.py` perform bare `sys.modules["anthropic"] = None` assignments — raw assignment, not `patch.dict`. These don't auto-restore on test failure or `KeyboardInterrupt`, meaning a test failure can poison `sys.modules` for the rest of the session.

### 3.5 Hypothesis Property Tests — Incomplete

`tests/unit/test_sanitise_properties.py` still has:
- `assume(len(s) >= 10)` and `assume(len(s) <= 512)` — sanitizer never tested on length 0-9 or >512
- `assume(len(s) > 0)` (5× sites) — empty strings never explored
- `7× suppress_health_check=[HealthCheck.too_slow]` — without benchmark justification

The most security-relevant inputs (empty, single-char, injection-prefix) are excluded from property testing.

---

## PART 4: ARCHITECTURE GAPS vs. IDEAL

### 4.1 What the `Ideal_Architecture.md` Blueprint Defines vs. What Exists

The `docs/Ideal_Architecture.md` is a 4,271-line, 180 KB blueprint describing a perfect version of Pramanix. Current status:

| Blueprint Item | Status |
|---------------|--------|
| `SolverProtocol` with injectable stubs | 🟡 Protocol defined in source, NOT injectable via GuardConfig |
| `ClockProtocol` with `FakeClock` | ❌ NOT IMPLEMENTED in source |
| `tests/helpers/solver_stubs.py` | ❌ NOT IMPLEMENTED in source |
| `DistributedCircuitBreaker` default backend fail | ✅ FIXED — now raises ConfigurationError |
| Policy linter with plain-English errors | ❌ NOT IMPLEMENTED |
| Interactive YAML policy validator in CLI | ❌ NOT IMPLEMENTED |
| `AgentOrchestrationAdapter` protocol | ❌ NOT IMPLEMENTED |
| Policy coverage metric (fields in traffic vs. declared) | ❌ NOT IMPLEMENTED |
| Policy simulation/dry-run mode | ❌ NOT IMPLEMENTED |
| `rotate_key()` implementations | ❌ NOT IMPLEMENTED in 3 providers |
| Concurrent-mutation integration test for `_lock` | ❌ NOT IMPLEMENTED |
| Non-numeric state injection integration tests | ❌ NOT IMPLEMENTED |
| Benchmarks on v1.0.0 / server-class hardware | ❌ Benchmarks on v0.8.0 / consumer laptop |
| Redis-backed `ExecutionTokenVerifier` | ❌ Only Postgres (`asyncpg`) provided |

### 4.2 The Worker Architecture

The `async-process` execution mode (spawning subprocess workers) has notable gaps:
- `worker.py:331, 441` — 2× `except Exception: pass` around Prometheus counter increments
- `worker.py:721, 725` — 2× `except Exception: pass` in `WorkerPool.__del__()` GC finalizer
- Worker warmup uses hardcoded trivially-satisfied constraints rather than a representative sample from the deployed policy

### 4.3 The Translator Subsystem

The translator subsystem has a structural trust issue:
```
PRAMANIX_TRANSLATOR_ENABLED="false"  ← baked into BOTH Dockerfiles
```

This means the entire LLM translation pathway — including injection detection, dual-model consensus, and adversarial scoring — **never runs in Docker-based test environments**. The test suite for the translator is entirely stub-based.

---

## PART 5: COMPETITIVE GAP ANALYSIS — HEAD TO HEAD

### 5.1 vs. NeMo Guardrails

| Capability | Pramanix | NeMo Guardrails | Winner |
|-----------|----------|-----------------|--------|
| Formal verification (SMT) | ✅ Z3, complete for numerics | ❌ Not present | **Pramanix** |
| Regulatory compliance oracle | ✅ SOC2, HIPAA, EU AI Act, GDPR | ❌ Not present | **Pramanix** |
| Cryptographic audit trail | ✅ Ed25519, Merkle | 🟡 Basic logging | **Pramanix** |
| Dialogue flow control | ❌ Not a primary focus | ✅ Colang DSL, production | **NeMo** |
| Jailbreak detection | 🟡 Beta injection scorer | ✅ Production-tested rails | **NeMo** |
| Real LLM testing in CI | ❌ Always skipped | ✅ Containerized models | **NeMo** |
| Latency (P50) | 🟡 ~4ms (benchmark v0.8.0) | 🟡 Comparable | Tie |
| Production adoption | 🟡 v1.0.0, limited | ✅ Multi-year, NVIDIA backing | **NeMo** |
| Developer onboarding | 🟡 Steep (Z3 knowledge) | ✅ Simple Colang YAML | **NeMo** |
| License | ❌ AGPL-3.0 | ✅ Apache-2.0 | **NeMo** |

**Honest verdict:** In Pramanix's unique lane (formal verification + regulatory attestation of discrete AI actions in regulated industries), Pramanix has no competitor. But NeMo wins on everything outside that lane.

### 5.2 vs. Guardrails AI

| Capability | Pramanix | Guardrails AI | Winner |
|-----------|----------|---------------|--------|
| Formal verification (SMT) | ✅ Z3, unmatched | ❌ Heuristic only | **Pramanix** |
| Regulatory compliance mapping | ✅ SOC2, HIPAA, EU AI Act | ❌ Not present | **Pramanix** |
| Built-in validators | 🟡 ~4 NLP beta | ✅ 50+ production validators | **Guardrails AI** |
| PII detection | 🟡 Beta, re2 required | ✅ Production, multiple backends | **Guardrails AI** |
| Toxicity detection | 🟡 Beta, keyword fallback | ✅ Production, fine-tuned models | **Guardrails AI** |
| Schema output validation | 🟡 Pydantic strict | ✅ Native + many validators | **Guardrails AI** |
| RBAC / access control | ✅ Z3 proven, formal | 🟡 Schema-based | **Pramanix** |
| Financial policy enforcement | ✅ Decimal precision, formal | ❌ Not a primary focus | **Pramanix** |
| Ease of getting started | 🟡 Complex (policy authoring) | ✅ Simple (add a validator) | **Guardrails AI** |
| License | ❌ AGPL-3.0 | ✅ Apache-2.0 | **Guardrails AI** |
| Enterprise support | ❌ None yet | ✅ Commercial tier | **Guardrails AI** |

---

## PART 6: COMPLETE GAP CLOSURE PRIORITY MATRIX

### 🔴 P0 — Existential (Do These First)

| # | Gap | Current State | Effort | Impact |
|---|-----|--------------|--------|--------|
| P0.1 | **Re-license to Apache-2.0** (or dual commercial) | AGPL-3.0 | Medium | Removes #1 adoption blocker |
| P0.2 | **Make `SolverProtocol` injectable via `GuardConfig(solver=...)`** | Protocol exists but not injectable | High | Validates security kernel under regression |
| ~~P0.3~~ | ~~`DistributedCircuitBreaker` warns on `InMemoryDistributedBackend`~~ | ✅ **ALREADY FIXED** — raises `ConfigurationError` | — | — |
| P0.4 | **Implement `rotate_key()`** in `PemKeyProvider`, `FileKeyProvider`, `AwsKmsKeyProvider` | `NotImplementedError` in all 3 | Medium | Key rotation = SOC2/PCI-DSS requirement |
| P0.5 | **Fix coverage floor**: remove `--fail-under=95` from CI; enforce `pyproject.toml`'s `fail_under=98` | 95% enforced, 98% claimed | Low | Eliminates 3% coverage loophole |

### 🟠 P1 — Enterprise Blockers (Required for Serious Adoption)

| # | Gap | Effort | Impact |
|---|-----|--------|--------|
| P1.1 | **Implement `ClockProtocol`** — inject into 9 `time.time()` sites in `execution_token.py` | Medium | Deterministic TTL testing |
| P1.2 | **Real NLP validators** — replace keyword-density fallback with lightweight model | High | Guardrails AI parity on content safety |
| P1.3 | **Add live LLM integration test job in CI** — `ollama`-based containerised model | High | Validates Layer 4 consensus in CI |
| P1.4 | **Fix `PRAMANIX_ALLOW_NO_AUDIT_SINKS`** — refuse startup if `PRAMANIX_ENV=production` and flag is set | Low | Prevents audit bypass in production |
| P1.5 | **Close remaining bare `pass` handlers** — add `_log.debug("swallowed: %s", exc)` minimum | Medium | Production debuggability |
| P1.6 | **Policy simulation/dry-run CLI command** | High | Democratizes policy authoring |
| P1.7 | **Fix `asyncio.run()` in `_swrapper`** (LangGraph sync nodes) — detect and document async context incompatibility | Low | Prevents silent crashes in FastAPI/async |

### 🟡 P2 — Quality & Completeness (Required for v2.0 Claim)

| # | Gap | Effort | Impact |
|---|-----|--------|--------|
| P2.1 | **Add concurrent-mutation test for CB `_lock`** | Medium | Validates `@cached_property` fix |
| P2.2 | **Add `tests/helpers/solver_stubs.py`** as designed | Medium | Foundation for Z3 boundary tests |
| P2.3 | **Add non-numeric state injection integration tests** | Low | Closes §4.12 residual gap |
| P2.4 | **Close `hypothesis.assume()` exclusions** in `test_sanitise_properties.py` | Medium | Covers empty/injection-prefix inputs |
| P2.5 | **Add `asyncpg` and JWT `ImportError` coverage** — remove `# pragma: no cover` | Low | Closes import-failure blind spots |
| P2.6 | **Implement `AgentOrchestrationAdapter` protocol** with LangGraph example | High | Unlocks multi-agent use cases |
| P2.7 | **Add Redis-backed `ExecutionTokenVerifier`** | Medium | Distributed single-use enforcement |
| P2.8 | **Benchmarks on v1.0.0 / server hardware** | Medium | Credible P99 performance claims |
| P2.9 | **Policy coverage metric** — track which fields in declared policy appear in real traffic | High | Formal completeness visibility |
| P2.10 | **Policy linter CLI** — `pramanix lint policy.yaml` | High | Democratizes policy authoring |
| P2.11 | **Fix `sys.modules` poisoning** in `test_coverage_gaps.py` — use `patch.dict` not bare assignment | Low | Prevents test session state corruption |

### 🟢 P3 — Excellence (Giant-Tier Polish)

| # | Gap | Effort |
|---|-----|--------|
| P3.1 | Replace 5 stub integrations (CrewAI, DSPy, Haystack, SemanticKernel, PydanticAI) with real end-to-end tests | High |
| P3.2 | Add `GuardConfig(nlp_require_re2=True)` explicit option (google-re2 is already hard-required) | Low |
| P3.3 | Populate `_DEFAULT_TOXIC_WORDS` with curated seed list or make `ToxicityScorer` refuse to construct without `detoxify` | Medium |
| P3.4 | Establish commercial support tier / enterprise SLA documentation | High |
| P3.5 | Add `pytest.mark.xfail(strict=True)` for known failing real-LLM tests instead of `skipif` | Low |
| P3.6 | Built-in compliance mapping library (pre-built SOC2, HIPAA, EU AI Act control sets) to reduce operator onboarding friction | High |
| P3.7 | Compliance report UI / CLI exporter | High |

---

## PART 7: THE BENCHMARKS — WHAT THEY SHOW AND WHAT THEY HIDE

### What the Benchmarks Cover
- `100m_audit_merge.py` — 100M decision Merkle merge throughput
- `100m_orchestrator_fast.py` — orchestrator latency at scale
- `100m_worker_fast.py` — async-process worker throughput
- `latency_benchmark.py` — P50/P95/P99 guard latency

### The Problem
The benchmark `results/` directory shows results from **v0.8.0 on consumer laptop hardware**. Since then:
- The `@functools.cached_property` circuit-breaker lock fix changed concurrency behavior
- The 8× guard_pipeline fix changed BLOCK path latency
- The `_emit_field_seen_metric()` added overhead to every `verify()` call
- The `InvariantASTCache` compile-once optimization was added
- The `WATCH/MULTI/EXEC` Redis optimistic locking added Redis round-trip to circuit-breaker state sync

None of these are reflected in the published benchmark numbers. **To claim Giant-tier:** Run all benchmarks on v1.0.0 on 8-core, 32 GB RAM server hardware. Publish the raw results in `PROOF_DOSSIER.md`.

---

## PART 8: WHAT IS FIXED SINCE LAST PASS (CONFIRMED)

The following items from the previous audit are **confirmed fixed** by direct source inspection:

| Item | How Fixed |
|------|-----------|
| `DistributedCircuitBreaker` defaults to `InMemoryDistributedBackend` | ✅ Now raises `ConfigurationError` if no backend provided |
| `google-re2` absent falls back to stdlib `re` (ReDoS risk) | ✅ Now raises `RuntimeError` at import time — hard failure |
| `asyncio.Lock` cached_property event loop binding | ✅ Fixed via `@functools.cached_property` pattern |
| `SecurityWarning` Python 3.13 `NameError` | ✅ Defined unconditionally in `validators.py:28-29` |
| Prometheus metric duplicate registration crash | ✅ Handled via `_prom_register()` helper |
| `_emit_translator_metric()` silently swallowing failures | ✅ Now logs at WARNING level |

---

## PART 9: THE HONEST OVERALL VERDICT

### What Pramanix Is Today

**A technically brilliant, production-incomplete, enterprise-undeployable, formally-correct AI governance library that happens to have the best idea in the entire AI safety space.**

The Z3 formal verification core is unmatched. The cryptographic audit trail is enterprise-grade. The compliance oracle (SOC2, HIPAA, EU AI Act, GDPR, NIST AI RMF, ISO 42001 attestation from Z3 proofs) is a genuine competitive moat that NeMo and Guardrails AI don't even attempt.

But:
- The license kills enterprise deals before any technical discussion happens
- The NLP safety layer is placeholder-grade compared to either Giant competitor
- The translator system has never been tested against a real LLM in any CI run
- Three `rotate_key()` methods crash at runtime
- The ideal architecture blueprint is ahead of the actual implementation by ~18-24 months of engineering work

### What It Takes to Be Giant-Tier

| Milestone | Current State | Required State |
|-----------|--------------|----------------|
| License | AGPL-3.0 | Apache-2.0 or dual |
| NLP Safety | Beta keyword | Production model |
| Real LLM CI | Zero | At least 1 containerized model |
| Formal engine testing | Protocol defined, not injectable | `GuardConfig(solver=...)` injection |
| Developer UX | Steep (Z3 required) | Policy linter + simulation |
| Benchmarks | v0.8.0, laptop | v1.0.0, server |
| Key rotation | NotImplementedError | Real implementations |
| Execution token registry | In-memory only | Redis-backed option |
| Enterprise support | None | Commercial tier |
| Compliance mapping | Oracle engine only | Built-in mapping library |

### The Unique Moat

Pramanix has the architectural right to be the **de facto standard for formal AI governance in regulated industries** (fintech, healthcare, infrastructure, defense). The combination of Z3 formal verification + Ed25519 cryptographic audit + HMAC-tagged compliance attestation is genuinely world-class. No other library on Earth does all three simultaneously with this level of engineering rigor.

The path to becoming a Giant is not more features — it is:
1. Fix the license (existential)
2. Productionize the NLP layer (competitive parity)
3. Test real LLMs in CI (trust)
4. Ship `SolverProtocol` injection (correctness)
5. Build a policy linter (adoption)
6. Ship a built-in compliance mapping library (differentiator activation)

Everything else is optimization.

---

*Audit completed: Pass 2 | Scope: full codebase, all test files, CI/CD, compliance oracle, circuit breaker, translator, NLP, guard, solver, execution-token, oversight | 47 source modules read in full, 166 test files, 4 Dockerfiles, 3 CI workflows*
