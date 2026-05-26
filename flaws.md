# Pramanix — Deep-Penetration Technical Audit

**Scope**: All source under `src/pramanix/` and `tests/`. Live codebase as of the current checkout.
**Purpose**: Exhaustive enumeration of every mock, stub, fake, pragma, suppression, and hidden flaw that remains open or is only partially addressed.
**Cleared debt** (do NOT count): `tests/helpers/real_protocols.py` (1,900-line duck-typed helper library; real implementations, zero MagicMock), `pytest.importorskip` for genuinely optional extras, `monkeypatch.setenv/delenv` for environment isolation, `respx` HTTP-level intercepts (deterministic network simulation, not MagicMock), testcontainers containers that back real protocol tests, `hypothesis.assume()` used for domain-constraint filtering in property tests.

---

## 1. Mocking & Stubbing Layer

### 1.1 Standard Mocks & Stubs (unittest.mock, patch)

✅ **FULLY FIXED — 2026-05-26**

Zero `unittest.mock.patch`, `patch.dict`, `MagicMock`, or `AsyncMock` calls remain anywhere in the test suite (verified by exhaustive grep). All previously-flagged files have been cleaned:

- `test_circuit_breaker_and_guard_paths.py` — Z3/solve patches removed; `_ErrorSolver` uses `solver_factory` DI
- `test_consensus_robustness.py` — module-level class replacement removed
- `test_translator_and_interceptor_paths.py` — all `patch()` calls removed; `monkeypatch.setattr` used where needed
- `test_platform_check.py` — `patch("glob.glob", ...)` calls removed
- `test_doctor_cli.py` — `patch("redis.from_url", ...)` calls removed
- `test_hardening.py` — `patch("multiprocessing.current_process", ...)` removed
- `test_coverage_gaps.py` — bare `sys.modules[...] = None` assignments removed; `monkeypatch.setitem` used
- `test_pragma_free_paths.py` — `_FakeModel` duck-types remain but no `patch()` calls
- `test_llm_backends_real.py` — `_FakeLlama` duck-types remain but no `patch()` calls
- `test_cohere_translator.py` / `test_gemini_translator.py` — `patch.dict(sys.modules, ...)` replaced with `monkeypatch.setitem`

Remaining duck-type classes (`_FakeLlama`, `_FakeModel`, inline `FakeA`/`FakeB` translators) use real method bodies without `unittest.mock`. They are covered under §12 (Duck-Typed Test Doubles).

---

### 1.2 MagicMock & Dynamic Proxies

The `tests/helpers/real_protocols.py` file explicitly replaced all MagicMock usages with real duck-typed implementations (cleared debt). Previously flagged items now confirmed fixed:

- **`tests/unit/test_coverage_final_push.py` line 1032** — `mock_pydantic` MagicMock removed. ✅ FIXED.
- **`tests/unit/test_circuit_breaker_half_open.py` line 270** — `_FakeBackend` is a real duck-type: two real async methods returning real `_DistributedState` objects. No MagicMock, no hardcoded scalars. ✅ ACCEPTABLE.

---

### 1.3 Hardcoded Return Values

Locations where test doubles return fixed scalars, bypassing real computation:

- **`tests/helpers/real_protocols.py` line 479** — `_MistralClientStub`: all async calls return a hardcoded `_mistral_ok()` payload.
- **`tests/helpers/real_protocols.py` line 1225** — `_CohereChatV5Stub`: returns hardcoded Cohere V5 response structure.
- **`tests/helpers/real_protocols.py` lines 1385, 1397** — `_ExecutorStub` and `_NoProcessesExecutorStub`: `submit()` returns futures that immediately resolve; no process pool scheduling.
- **`tests/unit/test_translator.py` lines 296–395** — All inline `FakeA`/`FakeB`/`FakeOk` translator classes return `"ALLOW"` or `"BLOCK"` as hardcoded strings.
- **`tests/unit/test_guard_dark_paths.py` line 703** — `_FakeTranslator.translate()` returns a fixed `TranslationResult` with hardcoded fields.
- **`tests/unit/test_llm_backends_real.py` respx blocks** — Lines 76, 90, 112, 128, 140, 188, 211, 252, 270, 282, 320, 332, 350, 369, 382, 400 — `respx.post(...).respond(...)` returns static JSON payloads as Mistral/Cohere API responses.
- **`tests/unit/test_enterprise_audit_sinks.py` lines 167, 187** — `respx.mock(base_url="http://splunk:8088")` with static HTTP 200 responses; Splunk HEC endpoint fully simulated.
- **`tests/unit/test_translator_and_interceptor_paths.py` line 950** — `respx.mock(base_url="http://splunk:8088")` — same pattern.

---

## 2. Fakes, Simulations & Artificial Environments

### 2.1 Fake Integrations

#### Production source — inline stub base classes
- **`src/pramanix/k8s/webhook.py` line 51** — `class FastAPI:  # type: ignore[no-redef]` — if `fastapi` is absent, a 1-line empty class is used as the base; real FastAPI request handling silently fails.
- **`src/pramanix/integrations/langchain.py` line 33** — `class BaseTool:  # type: ignore[no-redef]` — fallback stub base class; `_run`/`_arun` now raise `ConfigurationError` (fixed 2026-05-25) but the class itself is still exported as a stub when `langchain-core` is absent. ⚠️ PARTIALLY FIXED.
- **`src/pramanix/integrations/llamaindex.py` lines 58, 67** — `class ToolMetadata:` and `class ToolOutput:` — two stub classes silently exported; downstream importer gets structurally incorrect objects with no type error at import time.
- **`src/pramanix/integrations/crewai.py` line 82** — `class PramanixCrewAITool(_CrewAIBase):  # type: ignore[misc]` — inherits from either the real crewai base or a fallback stub.
- **`src/pramanix/integrations/dspy.py` line 79** — `class PramanixGuardedModule(_ModuleBase):  # type: ignore[misc]` — same pattern.
- **`src/pramanix/interceptors/grpc.py` line 55** — `class PramanixGrpcInterceptor(_InterceptorBase):  # type: ignore[misc]` — inherits from either real gRPC interceptor base or a fallback.
- **`src/pramanix/translator/mistral.py` line 58** — `from mistralai import Mistral as _Mistral  # type: ignore[no-redef]` — if v1 SDK is absent the outer `_Mistral` fallback is a structurally-incompatible class.

#### Test — inline fake modules
- **`tests/unit/test_translator_and_interceptor_paths.py` line 301** — `sys.modules["cohere"] = _FakeCohereModule()` — real Cohere SDK replaced with a hand-built class hierarchy.
- **`tests/helpers/real_protocols.py` lines 1721–1830** — 9 module-stub classes (`_Boto3ModuleStub`, `_AzureModuleStub`, `_AzureIdentityModuleStub`, `_AzureKVModuleStub`, `_AzureKVSecretsModuleStub`, `_GcpModuleStub`, `_GcpCloudModuleStub`, `_GcpSecretManagerModuleStub`, `_GeminiGenaiModuleStub`) — have real method logic but still replace real cloud SDKs; cannot reproduce real transport errors, authentication challenges, or quota limits. ⚠️ PARTIALLY CLEARED.
- **`tests/helpers/real_protocols.py` line 1821** — `_HvacModuleStub` — HashiCorp Vault client replaced with a stub that stores secrets in a dict.

### 2.2 Fake Containers & Ephemeral Environments

- **`tests/unit/conftest.py` lines 42–43** — `pytest.importorskip("testcontainers")` — entire Redis testcontainer fixture is skipped silently if `testcontainers` is not installed.
- **`tests/integration/conftest.py` lines 53–203** — 6 session-scoped testcontainer fixtures (Kafka, Postgres, Redis, Vault, LocalStack, second Redis) — all guarded by `pytest.importorskip`; absent Docker or missing images cause silent skip cascades.

### 2.3 Deterministic Simulation Overrides

- **`tests/unit/test_platform_check.py` lines 25–103** — 9 `patch("glob.glob", ...)` calls simulate musl library presence/absence; real filesystem never queried.
- **`tests/unit/test_translator_and_interceptor_paths.py` lines 57–83** — `patch("sys.platform", ...)` + `patch("glob.glob")` + `patch("ctypes.CDLL")` calls removed. ✅ FIXED.
- **`tests/unit/test_hardening.py` line 268** — `patch("multiprocessing.current_process", ...)` removed. ✅ FIXED.
- **`tests/unit/test_translator_and_interceptor_paths.py` line 1446** — `patch("tempfile.mkstemp", ...)` removed. ✅ FIXED.
- **`src/pramanix/transpiler.py` `_NowOp`** — `clock` injection is implemented: `_now = clock() if clock is not None else _time.time()`. `GuardConfig.clock: Callable[[], float] | None` exposes it. ✅ FIXED.

---

## 3. Pragma Directives, Suppressions & Silence Rules

### 3.1 Inline Pragmas & Linter Disables (`# noqa`)

**`src/pramanix/cli.py` line 1547** — `Ed25519PrivateKey,  # noqa: F401` — unused import suppressed; key type imported for side-effects (type availability) only.

**`src/pramanix/k8s/webhook.py` line 110** — `body: dict[str, Any] = _fastapi.Body(...),  # noqa: B008` — B008 silenced; the `Body(...)` sentinel is a FastAPI convention but the suppression hides a linting concern for non-FastAPI consumers.

**`src/pramanix/natural_policy/compiler.py` lines 649–650** — two `# noqa: E402` suppressions on late pydantic imports after module-level try-except blocks; structural design issue (imports not at top of file).

**`src/pramanix/translator/injection_scorer.py` line 363** — `import sklearn  # noqa: F401` — sklearn imported for its side-effect of registering the backend; suppression hides implicit coupling to sklearn's global state.

**`pyproject.toml` lines 345–365** — `filterwarnings` block silences:
- `pydantic.warnings.PydanticDeprecatedSince20` — Cohere SDK V1 API deprecation swallowed.
- `(?s).*google.generativeai.*:FutureWarning` — Google SDK self-deprecation warning swallowed globally.
- `coroutine 'AsyncClient.aclose' was never awaited:RuntimeWarning` — leaked async client coroutines silenced; potential resource leak masked.
- `GuardConfig:UserWarning` — `PRAMANIX_ENV=production` advisory silenced for tests.
- `urllib3.*doesn't match a supported version` — version mismatch swallowed.
- `chardet.*doesn't match a supported version` — chardet/charset_normalizer version mismatch swallowed.
- `Non-linear arithmetic detected:UserWarning` — Z3 non-linear arithmetic advisory silenced; emitted when constraints fall outside the decidable linear fragment.

**Not suppressed (50 warnings per full test run as of 2026-05-25):** `InMemoryAuditSink:UserWarning` (×12), `InMemoryApprovalWorkflow:UserWarning` (×19), `InMemoryExecutionTokenVerifier:UserWarning` (×10), `InMemoryDistributedBackend:UserWarning` (×3) — intentionally visible production-safety advisories. `RequestsDependencyWarning` (×1, pre-collection) — urllib3/chardet version mismatch in `requests/__init__.py`, not captured by pytest filterwarnings.

---

### 3.2 Ignored & Skipped Tests

#### `pytest.mark.skipif` conditional skips
- **`tests/unit/conftest.py` line 28** — `requires_docker = pytest.mark.skipif(not _DOCKER_AVAILABLE, ...)` — entire Docker-backed test battery skipped when Docker is absent; **215 tests skipped in the 2026-05-25 baseline** (129 unit Docker skips + 86 integration/adversarial skips) out of 4748 collected; 50 UserWarnings surface per run (see §3.1).

#### `pytest.importorskip` skips (dependencies absent = silent skip)
- **`tests/unit/conftest.py` line 42** — `pytest.importorskip("testcontainers")`
- **`tests/integration/test_zero_trust_identity.py` line 32** — `pytest.importorskip("testcontainers", ...)`
- **`tests/integration/conftest.py`** — each of the 6 container fixtures calls `pytest.importorskip`; any absent package silently drops the entire integration suite.
- **All 37 optional-dependency extras** — each `pytest.importorskip` guarding `asyncpg`, `confluent_kafka`, `cohere`, `anthropic`, `google-generativeai`, `mistralai`, `hvac`, `boto3`, `azure-keyvault-secrets`, `sentence-transformers`, `detoxify`, `re2`, `redis`, `prometheus_client`, `opentelemetry` etc. results in silent test elision; the CI matrix does not enumerate all combinations.

---

## 4. Hidden Architecture Flaws & Technical Debt

### 4.1 Z3 State Leakage and Trust Boundary Violation via Direct Patching

✅ **FULLY FIXED — 2026-05-26**

All `patch("pramanix.guard.solve", …)` and `patch("z3.Solver", …)` calls have been removed from the test suite. Z3 solver failures are now injected via `GuardConfig(solver_factory=…)` using `RaisingSolverStub` / `TimeoutSolverStub` — real `SolverProtocol` implementations that raise deterministic exceptions from `check()` without bypassing the transpiler or Z3 C-extension.

Fixed files:
- `tests/adversarial/test_fail_safe_invariant.py` — all `solve` patches replaced (2026-05-26)
- `tests/unit/test_guard.py::TestGuardFailSafe` — `_patch_solve()` helper removed; replaced with `_guard_raising()` using `solver_factory` DI (2026-05-26)
- `tests/unit/test_circuit_breaker_and_guard_paths.py` — already using `_ErrorSolver` via `solver_factory`
- `tests/unit/test_translator_and_interceptor_paths.py` — previously flagged line now uses `fast_path_rules`, not `z3.Solver` patch

Remaining architectural note: `solver.py` uses `threading.local()` (`_tl_ctx`) for per-thread Z3 contexts; no test exercises a cross-thread Z3 global context collision. This is a documentation gap, not a test-isolation failure.

---

## 5. Open Action Items

All previously-listed actionable code items are resolved:

- **`_emit_field_seen_metric()` log level** — `guard.py` line 259 already logs at `WARNING` (not DEBUG). ✅ FIXED.

---

## 6. Competitive Gap Analysis — Pramanix vs LangChain / LangGraph / NeMo Guardrails / Guardrails AI / LlamaIndex

This section maps every dimension on which Pramanix must equal or exceed its peer frameworks to reach enterprise production grade. Only rows with remaining open gaps are retained below.

| Symbol | Meaning |
|--------|---------|
| ✅ | Industry-leading or at full parity with the best competitor in this area |
| 🟡 | Partial / beta / present but incomplete compared to the best competitor |
| ❌ | Absent, not implemented, or too immature to be production-relied-upon |
| 🔵 | Not applicable by design |

Competitors abbreviated: **LC** = LangChain, **LG** = LangGraph, **NeMo** = NVIDIA NeMo Guardrails, **GrAI** = Guardrails AI, **LlIdx** = LlamaIndex.

---

### 6.1 Safety & Correctness (Open Gaps Only)

| Area | Pramanix | LC | LG | NeMo | GrAI | LlIdx | Open Gap | Priority |
|------|----------|----|----|------|------|-------|----------|----------|
| **NLP safety coverage** | 🟡 | 🟡 | 🔵 | ✅ | ✅ | 🟡 | NeMo and GrAI are stronger for broad text moderation, PII redaction, toxicity, jailbreak detection, topic filtering. Validators remain beta-grade; full GrAI/NeMo parity not reached | High |
| **Real LLM adversarial validation** | 🟡 | 🟡 | 🟡 | ✅ | 🟡 | 🔵 | Layer 4 dual-model consensus is never exercised in CI with real LLMs; all injection tests use stub translators. Pramanix's adversarial robustness against live model outputs is unverified | High |
| **Policy correctness assurance** | 🟡 | 🔵 | 🔵 | 🔵 | 🟡 | 🔵 | No competitor solves intent-verification. Pramanix gap: syntactic well-formedness ≠ semantic correctness; an incorrectly encoded policy passes all CI checks silently | Medium |
| **Unstructured text / content safety** | 🟡 | 🟡 | 🔵 | ✅ | ✅ | 🟡 | Guardrails AI and NeMo are stronger for generic prompt/output moderation. Pramanix is not a content safety classifier | Medium |

---

### 6.2 Architecture & Design (Open Gaps Only)

| Area | Pramanix | LC | LG | NeMo | GrAI | LlIdx | Open Gap | Priority |
|------|----------|----|----|------|------|-------|----------|----------|
| **Orchestration depth** | 🟡 | ✅ | ✅ | 🟡 | 🟡 | 🟡 | LangChain and LangGraph outperform in multi-step agent workflows, graph orchestration, tool routing, memory pipelines. Pramanix gates discrete tool invocations; it does not monitor reasoning chains | High |
| **Multi-agent workflow support** | 🟡 | ✅ | ✅ | 🟡 | 🟡 | 🟡 | LangGraph is graph-native; LangChain LCEL supports branching. Pramanix composes guards but does not manage graph state, agent handoffs, or cross-agent memory | High |
| **Memory tooling** | 🟡 | 🟡 | 🟡 | 🔵 | 🔵 | ✅ | LlamaIndex is stronger for retrieval, indexing, chunking, RAG-centric workflows. Pramanix memory components are beta and not a retrieval stack | Medium |

---

### 6.3 Ecosystem & Adoption (Open Gaps Only)

| Area | Pramanix | LC | LG | NeMo | GrAI | LlIdx | Open Gap | Priority |
|------|----------|----|----|------|------|-------|----------|----------|
| **Ecosystem breadth** | 🟡 | ✅ | ✅ | 🟡 | 🟡 | ✅ | LangChain, LangGraph, and LlamaIndex have far broader connector ecosystems and community plugins. Four stub integrations (CrewAI, DSPy, Haystack, SemanticKernel, PydanticAI) labelled "beta / stub-level" but still ship as stubs | High |
| **Deployment surface** | 🟡 | ✅ | ✅ | ✅ | 🟡 | 🟡 | LangChain/LlamaIndex/LangGraph have more community plugins and surrounding tooling (Helm charts, cloud-provider bundles, managed SaaS). 4 stub integrations limit deployment breadth | Medium |
| **Enterprise adoption** | 🟡 | ✅ | ✅ | ✅ | ✅ | ✅ | **AGPL-3.0 is the single largest adoption blocker.** Every competitor is Apache-2.0 or MIT. Enterprise legal teams routinely reject AGPL-3.0 for commercial products. A commercial licence or re-licence to Apache-2.0 is required for Fortune-500 adoption | **Critical** |
| **Benchmark freshness** | 🟡 | ✅ | 🟡 | 🟡 | 🟡 | 🟡 | Benchmarks were collected on v0.8.0 on consumer laptop hardware. Public performance narrative is outdated relative to competitors' current claims | Medium |

---

### 6.4 Engineering Quality (Open Gaps Only)

| Area | Pramanix | LC | LG | NeMo | GrAI | LlIdx | Open Gap | Priority |
|------|----------|----|----|------|------|-------|----------|----------|
| **Reliability** | ✅ | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | Remaining gap: no hyperscale battle-tested production deployment | Medium |

---

### 6.5 Developer Experience (Open Gaps Only)

| Area | Pramanix | LC | LG | NeMo | GrAI | LlIdx | Open Gap | Priority |
|------|----------|----|----|------|------|-------|----------|----------|
| **Developer UX / Onboarding** | 🟡 | ✅ | ✅ | 🟡 | ✅ | ✅ | Policy authoring requires typed fields, explicit invariants, LLM translator configuration, and human review of policy correctness. Pramanix's learning curve is higher for teams not familiar with formal methods | High |
| **Policy authoring UX for non-experts** | 🟡 | ✅ | 🟡 | 🟡 | ✅ | 🔵 | Guardrails AI and LangChain are easier for teams that want quick schema-light setup. Pramanix requires explicit field declarations, invariant proofs, and understanding of Z3 semantics | High |
| **General developer onboarding** | 🟡 | ✅ | ✅ | 🟡 | ✅ | ✅ | LangChain and LlamaIndex have years of community tutorials, YouTube content, blog posts, and template projects. Pramanix has high-quality official examples but minimal external community content | High |

---

### 6.6 Maturity & Ecosystem (Open Gaps Only)

| Area | Pramanix | LC | LG | NeMo | GrAI | LlIdx | Open Gap | Priority |
|------|----------|----|----|------|------|-------|----------|----------|
| **Ecosystem maturity** | 🟡 | ✅ | ✅ | ✅ | ✅ | ✅ | All competitors have multi-year production track records, wider PyPI adoption, established SLAs, and commercial support. Pramanix is technically rigorous but not yet battle-tested at hyperscale | High |
| **Production confidence of secondary layers** | 🟡 | ✅ | ✅ | ✅ | ✅ | ✅ | NLP validators, memory components, and some integrations are beta. GrAI and NeMo are more complete for broad safety pipelines | High |
| **Formal completeness scope** | ✅ | 🔵 | 🔵 | 🔵 | 🔵 | 🔵 | Completeness is only within the policy author's encoding; unencoded invariants are uncovered. Competitors do not match Z3 arithmetic completeness but are less narrow | Medium |

---

### 6.7 Open Gaps Scorecard

**Last updated**: 2026-05-26. Only rows with remaining open or partially-open gaps are listed.

| # | Area | Pramanix vs Best Competitor | Severity | Status | Minimum Action to Close Gap |
|---|------|-----------------------------|----------|--------|-----------------------------|
| 1 | Enterprise adoption / Licence | AGPL-3.0 vs Apache-2.0 (all competitors) | 🔴 Critical | 🔴 Open | Re-licence core to Apache-2.0 or introduce a commercial licence; update pyproject.toml, README, LICENCE, PROOF_DOSSIER |
| 2 | NLP safety coverage | Beta validators vs GrAI/NeMo production-grade moderation | 🟠 High | ⚠️ Partial | `pramanix_nlp_model_available` gauge and load-failure warnings added. Validators remain beta-grade; full GrAI/NeMo moderation parity not reached |
| 3 | Real LLM adversarial validation | Stub CI tests vs NeMo production-tested rails | 🟠 High | 🔴 Open | Add CI integration tests with real (or containerised) LLM endpoints for consensus and injection detection; remove Layer 4 stub dependency |
| 4 | Orchestration depth | Single-action gate vs LangGraph graph-native workflows | 🟠 High | 🔴 Open | Define and publish a public AgentOrchestrationAdapter protocol; document Pramanix-as-gate pattern for LangGraph state nodes |
| 5 | Developer UX / Policy authoring | Z3-knowledge required vs no-code schema in GrAI | 🟠 High | 🔴 Open | Add policy linter with plain-English error messages; add interactive YAML policy validator to CLI |
| 6 | Benchmark freshness | v0.8.0 consumer laptop vs current hardware | 🟡 Medium | 🔴 Open | Re-run all benchmarks on v1.0.0 on server-class hardware (8-core, 32 GB RAM); publish in PROOF_DOSSIER.md |
| 7 | Policy correctness assurance | No intent-verification vs formal proof | 🟡 Medium | 🔴 Open | Add a policy simulation/dry-run mode that shows which intents would be allowed/denied with example data |
| 8 | Memory tooling | Beta SecureMemoryStore vs LlamaIndex production RAG | 🟡 Medium | ⚠️ Partial | `SecureMemoryStore` public interface defined; `MIGRATION.md § MM-01` covers 6 LlamaIndex patterns. Memory components remain beta; not a retrieval/RAG stack |
| 9 | Formal completeness scope | Only covers encoded policy predicates | 🟡 Medium | 🔴 Open | Add a policy coverage metric: which fields and predicates are declared vs which appear in real traffic; surface uncovered paths in observability dashboard |
