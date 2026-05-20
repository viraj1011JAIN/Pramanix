# Pramanix — Deep-Penetration Technical Audit

**Scope**: All source under `src/pramanix/` and `tests/`. Live codebase as of the current checkout.
**Purpose**: Exhaustive enumeration of every mock, stub, fake, pragma, suppression, and hidden flaw.
**Cleared debt** (do NOT count): `tests/helpers/real_protocols.py` (1,900-line duck-typed helper library; real implementations, zero MagicMock), `pytest.importorskip` for genuinely optional extras, `monkeypatch.setenv/delenv` for environment isolation, `respx` HTTP-level intercepts (deterministic network simulation, not MagicMock), testcontainers containers that back real protocol tests, `hypothesis.assume()` used for domain-constraint filtering in property tests.

---

## 1. Mocking & Stubbing Layer

### 1.1 Standard Mocks & Stubs (unittest.mock, patch)

Every `unittest.mock.patch` call that replaces a real collaborator with a scripted impostor. Organised by file.

#### `tests/unit/test_circuit_breaker_and_guard_paths.py`
- **Line 1067** — `patch("pramanix.guard.solve", side_effect=RuntimeError(...))` — replaces Z3 solve at the guard module boundary; test bypasses the solver entirely and calls a fake RuntimeError path.
- **Lines 1418–1419** — `patch("z3.Solver", side_effect=RuntimeError("z3 down"))` — replaces the Z3 C-library binding with a scripted failure; no Z3 constraint resolution occurs.
- **Lines 285–333** — `patch("pramanix.guard_config._PROM_AVAILABLE", True)` with prometheus_client counters replaced by `MagicMock()` — metrics calls are discarded, Prometheus state is never exercised.
- **Lines 501–521** — Additional prometheus_client patch block; same pattern as above.
- **Lines 1121–1129** — Third prometheus_client patch block replacing counter `inc()` calls.

#### `tests/unit/test_fail_safe_invariant.py`
- **15+ `monkeypatch.setattr` calls** replacing `pramanix.guard.validate_intent`, `pramanix.guard.validate_state`, `pramanix.guard.flatten_model`, `pramanix.guard.solve` — all four internal Z3 pipeline stages are individually swapped to test fail-safe defaults; real constraint solving never runs in these paths.

#### `tests/unit/test_consensus_robustness.py`
- **Line 92** — `gem_mod.GeminiTranslator = _RecordingGeminiTranslator` with `# type: ignore[assignment]` — module-level class replacement; all GeminiTranslator instances created after this line are recording fakes, not the real translator.
- **Line 114** — Same pattern for a second GeminiTranslator replacement in a different test method.

#### `tests/unit/test_translator_and_interceptor_paths.py`
- **Lines 57–83** — Triple-patch block: `patch("sys.platform", "win32")`, `patch("glob.glob", return_value=[...])`, `patch("ctypes.CDLL", return_value=MagicMock())` — OS, filesystem, and native-library environment all simultaneously faked.
- **Lines 441, 555, 578** — Additional isolated platform/glob patches in distinct test methods.
- **Line 1379** — `patch("z3.Solver", side_effect=RuntimeError("z3 unavailable"))` — second Z3 mock site in this file.
- **Line 1446** — `patch("tempfile.mkstemp", side_effect=OSError("disk full"))` — disk I/O faked via OSError injection.
- **Lines 281–301** — `sys.modules["cohere"] = _FakeCohereModule()` replacing the real Cohere SDK with a locally-defined fake module.

#### `tests/unit/test_platform_check.py`
- **Line 25** — `patch("glob.glob", return_value=[])` — empty musl-detection result.
- **Line 40** — `patch("glob.glob", return_value=["/lib/ld-musl-x86_64.so.1"])` — musl-present result.
- **Lines 50–103** — 7 additional `patch("glob.glob", ...)` combinations across Linux/Windows/macOS permutations; filesystem state entirely scripted.

#### `tests/unit/test_doctor_cli.py`
- **Line 269** — `patch("redis.from_url", return_value=_PingFailRedisClient())` — Redis connectivity replaced with a local class that always throws on `ping()`.
- **Line 286** — `patch("redis.from_url", return_value=PingOkRedisClient())` — Redis connectivity replaced with a local class that always returns True on `ping()`.

#### `tests/unit/test_hardening.py`
- **Line 268** — `patch("multiprocessing.current_process", return_value=fake_proc)` — process identity faked; tests calling `current_process().name` receive a scripted name.

#### `tests/unit/test_coverage_final_push.py`
- **Line 397** — `patch.dict(sys.modules, {"mistralai.client": None, "mistralai": fake_mistralai_mod})` — Mistral SDK entirely replaced with a hand-rolled fake module.
- **Lines 416, 1077, 1134** — `patch.dict(sys.modules, {"tenacity": None})` — three separate tenacity-absent scenarios.
- **Line 979** — `patch.dict(sys.modules, {"redis": None})` — Redis package nulled.
- **Line 1032** — `patch.dict(sys.modules, {"pydantic": mock_pydantic})` — Pydantic replaced with a hand-rolled mock module.
- **Line 1201** — `t._single_call = _fake_single_call  # type: ignore[method-assign]` — direct private-method replacement on a live object; the real `_single_call` never runs.

#### `tests/unit/test_guard_dark_paths.py`
- **Lines 703–721** — `_FakeTranslator` class defined inline + `monkeypatch.setattr(_redundant, "create_translator", _fake_create_translator)` + `monkeypatch.setattr(_redundant, "extract_with_consensus", _fake_extract_with_consensus)` — both the translator factory and the consensus extraction function replaced; no LLM call, no consensus logic.

#### `tests/unit/test_translator.py`
- **Line 983** — `pytest.skip("APIStatusError path cannot be triggered via the VS Code proxy")` — VS Code dev proxy blocks real HTTP error simulation; entire code path permanently skipped.
- **Line 988** — `pytest.skip("Streaming API always returns text; empty-content path is pragma: no cover")` — combined pragma + skip doubles down on hiding the empty-response path.
- **Lines 281–395** — Multiple inline `FakeTranslator`, `FakeA`, `FakeB`, `FakeBadA`, `FakeGoodB` classes replacing real translators for consensus-path tests; all network I/O is elided.

#### `tests/unit/test_coverage_gaps.py`
- **Line 964** — `patch.dict(sys.modules, {"orjson": None})` + `importlib.reload(pramanix.decision)` — module reloaded with orjson absent; stateful reload is order-dependent and can leak state to subsequent tests.
- **Lines 999–1218** — boto3, azure-identity, azure-keyvault-secrets, cryptography, redis.exceptions all nulled via `sys.modules[...] = None` in rapid succession — 8+ individual null assignments without isolation guarantees.
- **Lines 1371, 1390** — `sys.modules["anthropic"] = None`, `sys.modules["tenacity"] = None` — bare assignment, not `patch.dict`; no auto-restore on test failure.
- **Line 1570** — `sys.modules["opentelemetry"] = None` — bare assignment.
- **Line 1459** — `_GeminiGenaiModuleStub()` injected into `sys.modules["google.generativeai"]`.

#### `tests/unit/test_extra_coverage.py`
- **Lines 321–358** — `_pai_stub = types.ModuleType("pydantic_ai")` injected via `monkeypatch.setitem(sys.modules, ...)` — pydantic_ai replaced with an empty module.
- **Lines 401–416** — `_lc_stub`, `_lc_tools_stub` built inline with manually assigned `BaseTool` and injected into `sys.modules["langchain_core"]` and `sys.modules["langchain_core.tools"]`.

#### `tests/unit/test_integrations_lazy.py`
- **Lines 56–99** — `_stub_module()` helper builds empty `types.ModuleType` objects then injects them for crewai, dspy, haystack, haystack.components, semantic_kernel, and semantic_kernel.functions — 6 real packages replaced with structurally empty stubs to test lazy-load paths only.

#### `tests/unit/test_compliance_full_coverage.py`
- **Lines 99–111** — `_FakeFPDFModule` injected into `sys.modules["fpdf"]`; PDF generation code receives a fake FPDF class that tracks `add_page`/`cell` calls but never renders PDF bytes.

#### `tests/unit/test_misc_coverage_gaps.py`
- **Lines 399–410** — `_FakeSecretsClient` injected as `boto3.client()` return value to test AWS KMS provider.
- **Lines 440–452** — `_FakeSecretClient` and `_FakeSecret` injected for Azure Key Vault provider.
- **Lines 492–503** — `_FakeSecretManagerClient`, `_FakePayload`, `_FakeResponse` for GCP Secret Manager.
- **Lines 622–630** — `_FakeHvacClient`, `_FakeHvacModule` for HashiCorp Vault provider.

#### `tests/unit/test_pragma_free_paths.py`
- **Lines 304, 321** — Inline `_FakeModel` classes replacing `llama_cpp.Llama`; no binary model file loaded, no inference occurs.

#### `tests/unit/test_llm_backends_real.py`
- **Lines 449–493** — Three inline `_FakeLlama` classes (success path, completion error, generation error) replacing `llama_cpp.Llama` binary inference engine.

#### `tests/integration/test_cohere_translator.py`
- **Line 219** — `with patch.dict(sys.modules, {"cohere": None})` — integration test simulates Cohere SDK absence.

#### `tests/integration/test_gemini_translator.py`
- **Line 95** — `with _patch.dict(sys.modules, {"google.generativeai": None})` — integration test simulates google-generativeai absence.

---

### 1.2 MagicMock & Dynamic Proxies

The `tests/helpers/real_protocols.py` file explicitly replaced all MagicMock usages with real duck-typed implementations (cleared debt). However, MagicMock-adjacent patterns still appear in the following locations:

#### Remaining isolated MagicMock-adjacent usages (not covered by real_protocols.py)
- **`tests/unit/test_circuit_breaker_and_guard_paths.py` lines 285–333, 501–521, 1121–1129** — `prometheus_client` metric objects replaced with `MagicMock()` instances inside the patch blocks; `inc()`, `observe()`, `labels()` all become auto-spec'd no-ops.
- **`tests/unit/test_coverage_final_push.py` line 1032** — `mock_pydantic` is a `types.ModuleType` with attributes set to `MagicMock()` proxies; Pydantic validation calls vanish silently.
- **`tests/unit/test_circuit_breaker_half_open.py` line 270** — `_FakeBackend` inner class replaces `DistributedCircuitBreaker`'s Redis backend; uses hardcoded state variables, not `MagicMock`, but is not backed by `real_protocols.py` either.

---

### 1.3 Hardcoded Return Values

Locations where test doubles return fixed scalars, bypassing real computation:

- **`tests/helpers/real_protocols.py` line 479** — `_MistralClientStub`: all async calls return a hardcoded `_mistral_ok()` payload; no actual HTTP call.
- **`tests/helpers/real_protocols.py` line 1225** — `_CohereChatV5Stub`: returns hardcoded Cohere V5 response structure.
- **`tests/helpers/real_protocols.py` lines 1385, 1397** — `_ExecutorStub` and `_NoProcessesExecutorStub`: `submit()` returns futures that immediately resolve; no process pool scheduling.
- **`tests/unit/test_translator.py` lines 296–395** — All inline `FakeA`/`FakeB`/`FakeOk` translator classes return `"ALLOW"` or `"BLOCK"` as hardcoded strings.
- **`tests/unit/test_guard_dark_paths.py` line 703** — `_FakeTranslator.translate()` returns a fixed `TranslationResult` with hardcoded fields.
- **`tests/unit/test_llm_backends_real.py` respx blocks** — Lines 76, 90, 112, 128, 140, 188, 211, 252, 270, 282, 320, 332, 350, 369, 382, 400 — `respx.post(...).respond(...)` returns static JSON payloads as Mistral/Cohere API responses. (Note: `respx` is legitimate HTTP-level stubbing, but each fixed response body represents a hardcoded state that excludes variant real-world payloads.)
- **`tests/unit/test_enterprise_audit_sinks.py` lines 167, 187** — `respx.mock(base_url="http://splunk:8088")` with static HTTP 200 responses; Splunk HEC endpoint is fully simulated.
- **`tests/unit/test_translator_and_interceptor_paths.py` line 950** — `respx.mock(base_url="http://splunk:8088")` — same pattern.

---

## 2. Fakes, Simulations & Artificial Environments

### 2.1 Fake Integrations

Locations where a real external library is replaced by a locally-defined impostor:

#### Production source — inline stub base classes
- **`src/pramanix/k8s/webhook.py` line 51** — `class FastAPI:  # type: ignore[no-redef]` — if `fastapi` is absent, a 1-line empty class named `FastAPI` is used as the base; any code path that calls FastAPI's real request handling silently fails with no error.
- **`src/pramanix/integrations/langchain.py` line 33** — `class BaseTool:  # type: ignore[no-redef]` — fallback stub base class; a consumer doing `from pramanix.integrations.langchain import BaseTool` without LangChain installed receives a class that raises only on first method call.
- **`src/pramanix/integrations/llamaindex.py` lines 58, 67** — `class ToolMetadata:  # type: ignore[no-redef]` and `class ToolOutput:  # type: ignore[no-redef]` — two stub classes silently exported; a downstream importer gets structurally incorrect objects with no type error at import time.
- **`src/pramanix/integrations/crewai.py` line 82** — `class PramanixCrewAITool(_CrewAIBase):  # type: ignore[misc]` — inherits from either the real crewai base or a fallback stub; type checker cannot distinguish.
- **`src/pramanix/integrations/dspy.py` line 79** — `class PramanixGuardedModule(_ModuleBase):  # type: ignore[misc]` — same pattern.
- **`src/pramanix/interceptors/grpc.py` line 55** — `class PramanixGrpcInterceptor(_InterceptorBase):  # type: ignore[misc]` — inherits from either real gRPC interceptor base or a fallback.
- **`src/pramanix/translator/mistral.py` line 58** — `from mistralai import Mistral as _Mistral  # type: ignore[no-redef]` — inner import guarded by version try-except; if v1 SDK is absent the outer `_Mistral` fallback is a structurally-incompatible class.

#### Test — inline fake modules
- **`tests/unit/test_translator_and_interceptor_paths.py` line 301** — `sys.modules["cohere"] = _FakeCohereModule()` — real Cohere SDK replaced with a hand-built class hierarchy (`_FakeErrors`, `_FakeApiError`, `_FakeCore`, `_FakeCohereModule`).
- **`tests/unit/test_coverage_final_push.py` line 397** — `patch.dict(sys.modules, {"mistralai.client": None, "mistralai": fake_mistralai_mod})` — Mistral replaced with a fake module object.
- **`tests/helpers/real_protocols.py` lines 1721–1830** — 9 module-stub classes (`_Boto3ModuleStub`, `_AzureModuleStub`, `_AzureIdentityModuleStub`, `_AzureKVModuleStub`, `_AzureKVSecretsModuleStub`, `_GcpModuleStub`, `_GcpCloudModuleStub`, `_GcpSecretManagerModuleStub`, `_GeminiGenaiModuleStub`) — these are **partially** cleared (they have real method logic), but they still replace real cloud SDKs and cannot reproduce real transport errors, authentication challenges, or quota limits.
- **`tests/helpers/real_protocols.py` line 1821** — `_HvacModuleStub` — HashiCorp Vault client replaced with a stub that stores secrets in a dict.

#### re2 fallback (duplicated across two files)
- **`src/pramanix/nlp/validators.py` lines 36–39** — `import re2 as _re_engine  # type: ignore[import-not-found]` falls back to `_re_engine = re  # type: ignore[assignment]`; stdlib `re` and Google's `re2` have different catastrophic-backtracking behaviours; a policy that passes `re2` may exhibit ReDoS vulnerability under `re`.
- **`src/pramanix/translator/injection_filter.py` lines 54–57** — identical `re2` → `re` fallback; same ReDoS risk for injection pattern matching.

### 2.2 Fake Containers & Ephemeral Environments

Docker containers that stand in for real infrastructure — these are legitimate but every skip guard means real-infra paths are never tested in CI without Docker:

- **`tests/unit/conftest.py` lines 42–43** — `pytest.importorskip("testcontainers")` + `from testcontainers.redis import RedisContainer` — entire Redis testcontainer fixture is skipped silently if `testcontainers` is not installed; all tests guarded by `redis_url` fixture also skip.
- **`tests/unit/conftest.py` line 31, scope="session"** — `redis_url` is session-scoped; if the container fails to start mid-session, all downstream tests in the same session may use a stale or `None` URL.
- **`tests/integration/conftest.py` lines 53–203** — 6 session-scoped testcontainer fixtures (Kafka, Postgres, Redis, Vault via DockerContainer, LocalStack, a second Redis) — all guarded by `pytest.importorskip`; absent Docker or missing images cause silent skip cascades of entire integration suites.
- **`tests/unit/test_circuit_breaker_half_open.py` line 318** — `sys.modules["redis.asyncio"] = None` — async Redis module nulled to test the no-Redis code path; this does not exercise a testcontainer, it eliminates the dependency entirely.

### 2.3 Deterministic Simulation Overrides

Locations where time, filesystem, OS, or process state is replaced by deterministic values:

- **`tests/unit/test_platform_check.py` lines 25–103** — 9 `patch("glob.glob", ...)` calls simulate musl library presence/absence across Linux, Windows, macOS permutations; real filesystem never queried.
- **`tests/unit/test_translator_and_interceptor_paths.py` lines 57–83** — `patch("sys.platform", "win32"/"linux")` + `patch("glob.glob")` + `patch("ctypes.CDLL")` — OS identity, filesystem, and native-library loading all replaced simultaneously.
- **`tests/unit/test_hardening.py` line 268** — `patch("multiprocessing.current_process", return_value=fake_proc)` — process identity deterministically faked.
- **`tests/unit/test_translator_and_interceptor_paths.py` line 1446** — `patch("tempfile.mkstemp", side_effect=OSError("disk full"))` — disk-full condition scripted deterministically.
- **`src/pramanix/transpiler.py` line 605** — `z3.IntVal(int(_time.time()), ctx)` embeds wall-clock time into Z3 integer values; no time-injection mechanism exists in tests, so time-dependent constraint results are non-deterministic across test runs.
- **`src/pramanix/execution_token.py` lines 150, 245, 325, 559, 706, 715, 872, 1107, 1125** — 9 separate `time.time()` call sites without abstraction; no injectable clock interface; TTL expiry tests must use real wall-clock delays or `monkeypatch.setattr(time, "time", ...)`.
- **`tests/unit/test_audit_sink_full_coverage.py` lines 152, 196, 276** — `sys.modules["confluent_kafka"] = None`, `sys.modules["boto3"] = None`, `sys.modules["datadog_api_client"] = None` — three bare `sys.modules` assignments (not `patch.dict`); no automatic restore on test failure.

---

## 3. Pragma Directives, Suppressions & Silence Rules

### 3.1 Inline Pragmas & Linter Disables (`# noqa`)

**`src/pramanix/cli.py` line 1137** — `s.add(z3.Bool("x") == True)  # noqa: E712` — E712 "comparison to True" silenced; the `z3.Bool` comparison to Python `True` is intentional but the silence hides the semantic oddity.

**`src/pramanix/cli.py` line 1195** — `Ed25519PrivateKey,  # noqa: F401` — unused import suppressed; key type is imported for side-effects only but the suppression hides a dead import path.

**`src/pramanix/k8s/webhook.py` line 103** — `body: dict[str, Any] = _fastapi.Body(...),  # noqa: B008` — B008 "do not use mutable data structures as default values" silenced; the `Body(...)` sentinel is a FastAPI convention but the suppression hides a linting concern for non-FastAPI consumers.

**`src/pramanix/natural_policy/compiler.py` line 655** — `from pydantic import BaseModel as _BaseModel  # noqa: E402` — late import after module-level try-except blocks; suppression hides a structural design issue (conditional-import anti-pattern at module scope).

**`src/pramanix/translator/injection_scorer.py` line 361** — `import sklearn  # noqa: F401` — sklearn imported for its side-effect of registering the backend; suppression hides the implicit coupling to sklearn's global state.

**`src/pramanix/translator/gemini.py` line 97** — `import google.generativeai  # noqa: F401` — same pattern; import for side-effects only, linting concern suppressed.

**`pyproject.toml` lines 345–365** — `filterwarnings` block in `[tool.pytest.ini_options]` silences:
- `pydantic.warnings.PydanticDeprecatedSince20` — Cohere SDK V1 API deprecation swallowed; operators will not receive advance notice of upcoming breakage.
- `(?s).*google.generativeai.*:FutureWarning` — Google SDK self-deprecation warning swallowed globally.
- `coroutine 'AsyncClient.aclose' was never awaited:RuntimeWarning` — leaked async client coroutines from Cohere/Mistral SDKs silenced; potential resource leak masked.
- `InMemoryExecutionTokenVerifier:UserWarning` — production-safety warning silenced for tests that exercise this path.
- `GuardConfig:UserWarning` — `PRAMANIX_ENV=production` advisory silenced for tests that set it.
- `urllib3.*doesn't match a supported version` — version mismatch swallowed.

**`src/pramanix/translator/gemini.py` lines 41–42** — `_w.filterwarnings("ignore", ..., category=FutureWarning)` and `_w.filterwarnings("ignore", ..., category=DeprecationWarning)` — applied at module import time, affecting all code in the process that imports this module; silences upstream Google SDK deprecations globally, not locally.

---

### 3.2 Type-Checking Bypasses (`# type: ignore`)

Every `# type: ignore` in production source that hides a real type contract violation:

#### `src/pramanix/compiler.py`
- **Line 510** — `# type: ignore[truthy-bool]` — `if not rhs_val:` on a Z3 expression; truthy-bool on a Z3 node is semantically undefined.
- **Line 1400** — `# type: ignore[arg-type]` — `int(scalar)` where `scalar` is a union type; wrong branch may produce `TypeError` at runtime.
- **Line 1444** — `# type: ignore[operator]` — `lhs_node > rhs`; operator overload return type not statically verified.
- **Line 1446** — `# type: ignore[operator]` — `lhs_node < rhs`; same.
- **Line 1448** — `# type: ignore[operator]` — `lhs_node >= rhs`; same.
- **Line 1450** — `# type: ignore[operator]` — `lhs_node <= rhs`; same.
- **Line 1675** — `# type: ignore[name-defined]` — `_BoolOp` referenced before its conditional definition; structural gap in type narrowing.

#### `src/pramanix/expressions.py`
- **Line 559** — `def __pow__(self, exp: Any) -> ExpressionNode:  # type: ignore[override,unused-ignore]` — `__pow__` overrides a parent whose return type is `Any`; override contract broken.
- **Line 587** — `def __rpow__(self, o: Any) -> ExpressionNode:  # type: ignore[override,unused-ignore]` — same for reverse-power.
- **Line 851** — `def __eq__(self, o: Any) -> ConstraintExpr:  # type: ignore[override]` — `__eq__` returns `ConstraintExpr` instead of `bool`; violates Python data model; `if expr == other:` in user code is silently reinterpreted.
- **Line 854** — `def __ne__(self, o: Any) -> ConstraintExpr:  # type: ignore[override]` — same for `__ne__`; `!=` returns a constraint object, not a boolean.

#### `src/pramanix/integrations/__init__.py`
- **Lines 76, 80, 84, 88, 92, 96, 100, 104** — 8× `# type: ignore[no-redef]` on dynamic lazy-load reassignment of `_m`; the variable is successively rebound to different module objects; static analysis cannot track which binding is live.

#### `src/pramanix/k8s/webhook.py`
- **Line 51** — `class FastAPI:  # type: ignore[no-redef]` — stub class silently redefines the name imported from fastapi.

#### `src/pramanix/integrations/langchain.py`
- **Line 33** — `class BaseTool:  # type: ignore[no-redef]` — stub base class redefines the imported name.
- **Line 59** — `from starlette.responses import JSONResponse, Response  # type: ignore[assignment]` (FastAPI integration).

#### `src/pramanix/integrations/fastapi.py`
- **Line 59** — `# type: ignore[assignment]` on starlette import.
- **Line 73** — `class PramanixMiddleware(_BaseHTTPMiddleware):  # type: ignore[misc]` — misc override suppression.

#### `src/pramanix/integrations/llamaindex.py`
- **Line 58** — `class ToolMetadata:  # type: ignore[no-redef]`
- **Line 67** — `class ToolOutput:  # type: ignore[no-redef]`

#### `src/pramanix/integrations/crewai.py`
- **Line 82** — `class PramanixCrewAITool(_CrewAIBase):  # type: ignore[misc]`

#### `src/pramanix/integrations/dspy.py`
- **Line 79** — `class PramanixGuardedModule(_ModuleBase):  # type: ignore[misc]`

#### `src/pramanix/integrations/haystack.py`
- **Line 46** — `# type: ignore[import-untyped]` on haystack component import.

#### `src/pramanix/interceptors/grpc.py`
- **Line 55** — `class PramanixGrpcInterceptor(_InterceptorBase):  # type: ignore[misc]`

#### `src/pramanix/policy.py`
- **Line 230** — `@classmethod  # type: ignore[misc]`
- **Line 293** — `cls.invariants = _merged  # type: ignore[method-assign, assignment]`
- **Line 549** — `@classmethod  # type: ignore[misc]`

#### `src/pramanix/crypto.py`
- **Line 92** — (from context; union-attr suppression on optional cryptography object)
- **Line 499** — `load_pem_private_key(raw, password=None)  # type: ignore[arg-type]` — password argument typed as `bytes | None` but passed as `None` with no explicit cast.
- **Line 698** — same pattern; second PEM key load site.

#### `src/pramanix/natural_policy/compiler.py`
- **Line 198** — `# type: ignore[arg-type]` on Z3TypeEnum.value passed as Z3Type.
- **Line 395** — `return left == right  # type: ignore[return-value]` — Z3 equality returns `BoolRef`, not `bool`.
- **Line 397** — `return left != right  # type: ignore[return-value]` — same for inequality.
- **Line 669** — `def model_json_schema(cls, **kwargs: Any) -> dict[str, Any]:  # type: ignore[override]`

#### `src/pramanix/nlp/validators.py`
- **Line 36** — `# type: ignore[import-not-found]` on re2.
- **Line 39** — `# type: ignore[assignment]` on `_re_engine = re`.
- **Line 55** — `# type: ignore[import-not-found]` on detoxify.
- **Line 71** — `# type: ignore[import-not-found]` on sentence_transformers.

#### `src/pramanix/translator/injection_filter.py`
- **Line 54** — `# type: ignore[import-not-found]` on re2.
- **Line 57** — `# type: ignore[assignment]` on `_re_engine = re`.

#### `src/pramanix/translator/mistral.py`
- **Line 58** — `# type: ignore[no-redef]` on Mistral SDK v1 re-import.

#### `src/pramanix/execution_token.py`
- **Line 92** — `import asyncpg as _asyncpg  # type: ignore[import-untyped]`

#### `src/pramanix/cli.py`
- **Line 1245** — `# type: ignore[arg-type]` on `_log_status["level"]` passed to a logging function.

#### `tests/unit/conftest.py`
- **Line 32** — `def redis_url() -> str:  # type: ignore[return]` — the function is declared to return `str` but carries a type-ignore suppressing the return-type check; the actual return expression may be `None` in failure paths (see Section 4.1).

---

### 3.3 Ignored & Skipped Tests

Every `pytest.skip`, `pytest.mark.skipif`, `pytest.importorskip`, and `pytest.mark.xfail` instance across the test suite.

#### Hard `pytest.skip()` calls (tests that never run in any configuration)
- **`tests/unit/test_translator.py` line 983** — `pytest.skip("APIStatusError path cannot be triggered via the VS Code proxy")` — VS Code dev proxy permanently prevents this path; it is **never run in any CI or local environment**.
- **`tests/unit/test_translator.py` line 988** — `pytest.skip("Streaming API always returns text; empty-content path is pragma: no cover")` — compounded with pragma; coverage AND test both disabled.

#### `pytest.mark.skipif` conditional skips
- **`tests/unit/conftest.py` line 28** — `requires_docker = pytest.mark.skipif(not _DOCKER_AVAILABLE, reason="Docker not available")` — entire Docker-backed test battery skipped when Docker is absent; 84 tests reported as skipped in the baseline run.

#### `pytest.importorskip` skips (dependencies absent = silent skip)
- **`tests/unit/conftest.py` line 42** — `pytest.importorskip("testcontainers")`
- **`tests/integration/test_zero_trust_identity.py` line 32** — `pytest.importorskip("testcontainers", ...)`
- **`tests/integration/conftest.py`** — each of the 6 container fixtures calls `pytest.importorskip` for its library; any absent package silently drops the entire integration suite.
- **All 37 optional-dependency extras** — each `pytest.importorskip` in tests guarding e.g. `asyncpg`, `confluent_kafka`, `cohere`, `anthropic`, `google-generativeai`, `mistralai`, `hvac`, `boto3`, `azure-keyvault-secrets`, `sentence-transformers`, `detoxify`, `re2`, `redis`, `prometheus_client`, `opentelemetry` etc. results in silent test elision; the CI matrix does not enumerate all combinations.

#### `hypothesis` deadline/health suppression
- **`tests/unit/test_sanitise_properties.py` lines 96, 126, 157, 241, 253, 265, 277** — 7× `suppress_health_check=[HealthCheck.too_slow]` — Hypothesis's "this strategy is too slow" health check suppressed; slow strategies may indicate the code under test has unacceptable latency that is being hidden.
- **`tests/unit/test_decision_hash.py` line 120** — `database=None` — Hypothesis shrink database disabled; reproducibility of found failures is reduced.
- **All 43 `deadline=None` instances across `tests/property/`** — Hypothesis's deadline check disabled; performance regressions in Z3 constraint solving and NLP validators will not surface as test failures.

---

## 4. Hidden Architecture Flaws & Technical Debt

### 4.1 Critical Bug: `conftest.redis_url()` Return-Type Lie

**File**: `tests/unit/conftest.py` **Line 32**
```python
@pytest.fixture(scope="session")
def redis_url() -> str:  # type: ignore[return]
```
The `# type: ignore[return]` on the function signature means mypy/pyright detected that this function can return something other than `str`. A session-scoped fixture that silently returns `None` would pass that `None` as the `url` argument to `redis.asyncio.from_url(None)`, which raises `TypeError` only at connection time — deep inside test teardown or on first Redis command. Because the fixture is session-scoped, all tests in the session that depend on `redis_url` silently get a poisoned URL if the container fails to start. The skip guard (`requires_docker`) fires on the fixture body *only after* `redis_url` itself has already resolved. The actual return value in the failure branch is never explicitly surfaced.

**Risk**: Silent `NoneType` URL passed to Redis clients; confusing `TypeError` deep in async connection path; intermittent test suite corruption.

### 4.2 Z3 State Leakage and Trust Boundary Violation via Direct Patching

**Files**: `tests/unit/test_circuit_breaker_and_guard_paths.py` lines 1067, 1418–1419; `tests/unit/test_fail_safe_invariant.py` (15 setattr calls); `tests/unit/test_translator_and_interceptor_paths.py` line 1379

Z3 is Pramanix's security kernel — the SMT solver whose `sat`/`unsat`/`unknown` verdict is the authoritative enforcement decision. Patching `pramanix.guard.solve`, `z3.Solver`, or the pipeline helpers (`validate_intent`, `validate_state`, `flatten_model`) breaks the Z3 trust boundary:

1. **Tests that patch `z3.Solver`** never exercise the C-library binding. A regression in Z3 v4.x → v5.x that causes incorrect constraint evaluation would pass these tests.
2. **Tests that patch `pramanix.guard.solve`** bypass the entire transpiler → solver pipeline. These tests prove that the *guard shell* calls *something* on solver failure, but not that the solver pipeline itself is correct.
3. **`solver.py` uses `threading.local()` (`_tl_ctx`)** for per-thread Z3 contexts. `transpiler.py` documents that `ctx=None` falls back to Z3's global context which is "incompatible with the per-call z3.Context() used by solver.py". No test exercises a cross-thread Z3 global context collision; the test suite always runs Z3 in a single-thread-per-test arrangement.

**Risk**: Security-kernel regressions invisible to mock-patched tests; potential TOCTOU on global Z3 context under async workloads.

### 4.3 VS Code Dev Proxy Masking Real HTTP Error Path

**File**: `tests/unit/test_translator.py` **Lines 983, 988**

The VS Code dev proxy intercepts outgoing HTTP requests and always returns text, preventing the translator's `APIStatusError` and empty-content paths from being exercised. Both paths are permanently `pytest.skip()`-ped and additionally marked `pragma: no cover`. This means:

1. The `APIStatusError` handler in `MistralTranslator`/`CohereTranslator` has **zero test coverage**.
2. The empty-content path that falls through to a default is also **zero test coverage**.
3. In production, a real Mistral or Cohere API returning 4xx or 5xx will hit untested code paths.

**Risk**: Unverified error-handling in LLM translators; policy decisions under degraded API conditions are unproven.

### 4.4 `sys.modules` Bare Assignment Without `patch.dict` (No Auto-Restore)

**Files**: `tests/unit/test_audit_sink_full_coverage.py` lines 152, 196, 276; `tests/unit/test_coverage_gaps.py` lines 1371, 1390, 1570

Bare `sys.modules["some_package"] = None` assignments are **not** wrapped in `patch.dict`/`monkeypatch.setitem`. If the test throws before the cleanup code runs (e.g., assertion failure, `KeyboardInterrupt`), the module stays `None` in `sys.modules` for the rest of the process. All subsequent tests that try to import that package will receive `ModuleNotFoundError`. Test ordering becomes load-bearing.

Specific instances:
- `tests/unit/test_audit_sink_full_coverage.py:152` — `sys.modules["confluent_kafka"] = None`
- `tests/unit/test_audit_sink_full_coverage.py:196` — `sys.modules["boto3"] = None`
- `tests/unit/test_audit_sink_full_coverage.py:276` — `sys.modules["datadog_api_client"] = None`
- `tests/unit/test_coverage_gaps.py:1371` — `sys.modules["anthropic"] = None`
- `tests/unit/test_coverage_gaps.py:1390` — `sys.modules["tenacity"] = None`
- `tests/unit/test_coverage_gaps.py:1570` — `sys.modules["opentelemetry"] = None`

Note: The three `test_coverage_gaps.py` entries (lines 1371, 1390, 1570) use a try/finally sentinel pattern that restores the original module entry on normal completion, reducing the risk of test pollution compared to the `test_audit_sink_full_coverage.py` entries which have no corresponding restoration block. The `test_audit_sink_full_coverage.py` entries are the higher-risk instances. Nevertheless, try/finally restoration is NOT equivalent to `patch.dict` — if the finally block itself raises (e.g., another `KeyboardInterrupt` arrives mid-finally), the module entry is still corrupted for the rest of the process.

**Risk**: Invisible test-order dependency; test pollution across files; false green in parallel runs with `pytest-xdist`.

### 4.5 `InMemoryExecutionTokenVerifier` Exported as Production Symbol

**File**: `src/pramanix/execution_token.py` lines 427, 466–487; `src/pramanix/__init__.py` line 126

`InMemoryExecutionTokenVerifier` is exported in the top-level `pramanix` namespace (line 126 of `__init__.py` and line 312 of the `__all__` list). It emits three `warnings.warn(UserWarning)` calls at instantiation (not-safe-for-multi-worker, not-safe-for-production, tokens-are-in-process), but:

1. `pyproject.toml:348` globally suppresses `InMemoryExecutionTokenVerifier:UserWarning` in the test suite — every test that uses it gets no visible warning.
2. Operators scanning the top-level API surface see it as a first-class verifier alongside Redis and Postgres variants; nothing in the class name or docs clearly marks it as "testing only".

**Risk**: Production deployments using in-memory verifier silently bypass replay-attack protection; multi-worker deployments have no cross-worker token invalidation.

### 4.6 `__eq__`/`__ne__` Return Type Contract Broken in `expressions.py`

**File**: `src/pramanix/expressions.py` lines 851, 854

`ExpressionNode.__eq__` returns `ConstraintExpr` instead of `bool`. Python's data model specifies that `__eq__` must return `bool` (or `NotImplemented`). Any user code that writes:
```python
if some_node == other_node:
```
will always evaluate as truthy (non-None object). The `# type: ignore[override]` suppresses the warning. This is documented intentional DSL behaviour but:

1. `hash()` is undefined for `ExpressionNode` — if `__eq__` is overridden without `__hash__`, Python sets `__hash__` to `None`, making expression nodes unhashable. Using them as dict keys or in sets raises `TypeError`.
2. No test verifies that `ExpressionNode` instances cannot be accidentally used in boolean guard conditions inside policy `invariants()` methods.

**Risk**: Silent policy mis-evaluation if a developer writes `if field == value` inside an `invariants()` body; unhashable-type crash if nodes are used in sets.

### 4.7 Global Warning Suppression in `translator/gemini.py` at Import Time

**File**: `src/pramanix/translator/gemini.py` lines 41–42**

```python
_w.filterwarnings("ignore", message=r"(?s).*google\.generativeai.*", category=FutureWarning)
_w.filterwarnings("ignore", message=r"(?s).*google\.generativeai.*", category=DeprecationWarning)
```

These `filterwarnings` calls are executed at **module import time**, affecting the entire process. Any code that imports `pramanix.translator.gemini` (directly or transitively) will silently drop Google SDK deprecation warnings for the rest of the process lifetime — including user application code that has nothing to do with Pramanix's Gemini translator.

**Risk**: Operators' own Google SDK deprecation signals silenced by a library import; unexpected breakage when Google SDK removes deprecated APIs.

### 4.8 re2/stdlib re Silent Fallback Creates Security Inconsistency

**Files**: `src/pramanix/nlp/validators.py` lines 36–39; `src/pramanix/translator/injection_filter.py` lines 54–57

When `google-re2` is absent, both files fall back to Python's `re` module. The `re` module is vulnerable to ReDoS (Regular Expression Denial of Service) for patterns that use catastrophic backtracking. `re2` guarantees linear-time matching. Since the injection-filter patterns are evaluated against untrusted user input:

1. A production deployment with `re2` passes security review.
2. A deployment where `re2` failed to install (or is unavailable on the target platform) silently uses `re`, changing the security posture without any runtime warning or error.
3. No test verifies that the fallback does not introduce ReDoS-susceptible patterns.

**Risk**: Silent security-posture downgrade; ReDoS attack vector on injection filtering when `re2` is absent.

### 4.9 Circuit Breaker asyncio.Lock Created Fresh on Every Property Access — **[FIXED]**

**File**: `src/pramanix/circuit_breaker.py` lines 180–182, 540–542, 1052–1054
**Status**: **FIXED** — Applied in a prior hardening session. All three `@property def _lock(self) -> asyncio.Lock: return asyncio.Lock()` methods were changed to `@functools.cached_property`, which creates the lock once and caches it on the instance. Verified by reading current source.

*Original bug*: Each call to `self._lock` created a **new** `asyncio.Lock` object. Two coroutines entering `async with self._lock:` simultaneously each received their own lock and proceeded concurrently — providing zero mutual exclusion. The docstring claimed "always binds to the current event loop" but the real behaviour was "provides no locking at all". State (open/closed/half-open) could be simultaneously mutated by multiple coroutines.

*Residual gap*: A concurrent-mutation integration test does not yet exist. The fix is correct, but no test verifies linearizability of state transitions under concurrent async load. See §5 item 30 for the action item.

### 4.10 Broad `except Exception: pass` Swallowing in Production Source

Silent `except Exception: pass` or functionally-equivalent silently-absorbing patterns. All entries below are **verified by direct source inspection**; false positives from the prior version have been removed (see "Entries removed" subsection).

#### Confirmed silent swallows with security or operational consequence

- **`src/pramanix/guard.py` line 186** — `_emit_translator_metric()`: outer `except Exception: pass` swallows **all** Prometheus Counter errors. If `prometheus_client` raises during `.labels(model=...).inc()` (label-cardinality explosion, registry thread-race, duplicate registration), the failure is discarded with no log entry at any level. Consequence: `pramanix_extraction_failure_total` and `pramanix_consensus_failure_total` counters silently stop incrementing; operators have no Prometheus signal that LLM extraction or multi-model consensus is degraded.

- **`src/pramanix/guard.py` line 144** — `_is_picklable()`: `except Exception: return False` converts **all** non-pickling exceptions — including `MemoryError`, `RecursionError`, `SystemError` — silently to `False` ("not picklable") without logging the exception type or message. Callers receive `False` with no indication that a low-level failure (not a pickling incompatibility) occurred. Consequence: memory-pressure–induced `MemoryError` during policy state serialization presents identically to a legitimate "this object is not serializable" case; runbook cannot distinguish the two.

- **`src/pramanix/circuit_breaker.py` line 692** — bare `except Exception: pass` in a circuit-breaker cleanup path; no log, no metric, no re-raise. Consequence: cleanup errors are fully invisible to operators and monitoring.

- **`src/pramanix/circuit_breaker.py` lines 1144, 1172, 1202, 1205, 1213, 1238** — 6× bare `except Exception: pass` in the distributed-circuit-breaker Redis state-replication path (`_sync_state_to_redis`, `_load_state_from_redis`, and the transition callbacks). Redis write errors during state transitions (open→closed, closed→open, half-open→open) are silently swallowed. Consequence: a circuit-breaker instance that cannot sync state to Redis silently operates in split-brain; each replica independently decides to open or close without consensus. High-traffic distributed deployments will have divergent circuit states with no alerting.

- **`src/pramanix/fast_path.py` lines 88, 106, 141, 168** — 4× `except Exception: return None` in individual fast-path rule functions (`negative_amount`, `zero_or_negative_balance`, `exceeds_hard_cap`, `amount_exceeds_balance`). When `Decimal(str(val))` raises on an attacker-crafted value (e.g. `"NaN"`, `"Infinity"`, excessively long numeric string, special float), the rule silently returns `None` (no block) and the request falls through to Z3. No WARNING is emitted at the rule-function level. Consequence: fast-path pre-screening is silently bypassed for malformed numeric inputs; the sole defence is the Z3 solver. Full analysis in §4.13.

- **`src/pramanix/worker.py` lines 331, 441** — 2× `except Exception: pass` around Prometheus counter `.inc()` calls in the worker subsystem:
  - Line 331: `_WORKER_WATCHDOG_ERROR_COUNTER.inc()` in the watchdog path — on Prometheus error, the watchdog-error metric silently stops counting; watchdog failure rate in Grafana shows 0 rather than the real value.
  - Line 441: `_WORKER_WARMUP_FAILURE_COUNTER.inc()` in worker warm-up — on Prometheus error, warm-up failures become invisible to monitoring.

- **`src/pramanix/worker.py` lines 721, 725** — 2× `except Exception: pass` inside `WorkerPool.__del__()` GC finalizer (the `_log.warning()` call and the `executor.shutdown(wait=False)` call). These are in the last-resort GC-path and are architecturally acceptable since the event loop may already be torn down. However, no metric counts forced-close failures, and the dual-swallow means even the attempt to log the shutdown failure is itself swallowed.

- **`src/pramanix/crypto.py` lines 96, 98** — Two sequential bare `except` clauses in `_inc_signing_failure()`:
  - Line 96: `except ImportError: pass` — if `prometheus_client` is absent, the counter increment is skipped silently (acceptable; the import was optional).
  - Line 98: `except Exception: pass` — if `prometheus_client` IS present but `.inc()` raises (label conflict, registry corruption, threading race), the failure is silently discarded with no log. Consequence: the `pramanix_signing_failure_total` counter can stop incrementing without any operator alert; signing failures (missing key, Ed25519 library crash, RS256/ES256 error) appear as 0 in Prometheus dashboards.

- **`src/pramanix/crypto.py` lines 400, 429, 612, 627, 817, 832** — 6× `except Exception: return False` in `.verify()` methods of `PramanixSigner`, `RS256Verifier`, and `ES256Verifier`. The documented contract is "never raises; returns False for any failure". This converts infrastructure errors (corrupted key object, unexpected cryptography-library state, `MemoryError`, `OverflowError`) into the same `False` return as a valid-but-non-matching signature. Consequence: a verifier with a broken key silently reports "signature invalid" rather than "verifier is broken"; callers cannot distinguish "wrong signature" from "verification subsystem failure".

- **`src/pramanix/audit/signer.py`** — `DecisionSigner.__init__` sets `self._key = None` silently when the signing key is absent or too short (no `ConfigurationError` raised at init time). Downstream `.sign()` calls return `None` silently. Signed decisions with `token=None` pass signature-presence checks unless the caller explicitly handles `None`. Consequence: an audit trail can be generated with missing digital signatures if the key was misconfigured; no exception is raised at the point of misconfiguration.

- **`src/pramanix/guard_pipeline.py` lines 93, 109, 133, 137, 159, 163, 178, 193** — 8× `except Exception as _exc: _log.debug("... check skipped — non-numeric value", exc_info=_exc)` in `_semantic_post_consensus_check()`. Full analysis in §4.12. Summary: financial balance, daily-transfer-limit, healthcare-dosage, and infra-replica/CPU/memory safety checks are silently bypassed at DEBUG log level when `state_values` contains non-numeric data (e.g. `"CORRUPTED"` string injected via a compromised data store). No `SemanticPolicyViolation` is raised for malformed state; the request proceeds as if the check was satisfied.

- **`src/pramanix/interceptors/kafka.py` line 120** — `except Exception: pass` in Kafka consumer GC finalizer (after a `_log.warning(...)` that itself attempts string formatting). Acceptable GC-path location; the Kafka connection may already be dead. But no metric counts forced-close failures.

- **`src/pramanix/integrations/llamaindex.py` line 143** — `except Exception: pass` in `PramanixFunctionTool._shutdown_executor()`, a `weakref.finalize` callback for GC-path executor shutdown. Acceptable because `ThreadPoolExecutor.shutdown(wait=False)` may fail after interpreter teardown. No log on failure.

- **`src/pramanix/execution_token.py` line 905** — `except Exception: return 0` in `RedisExecutionTokenVerifier.count()`. When Redis is unreachable during `SCAN`, the method silently returns `0` (no tokens consumed). Consequence: quota checks or rate-limit checks based on `count()` receive a falsely-low value when Redis is degraded; callers may incorrectly permit requests that should be blocked.

- **`src/pramanix/nlp/validators.py` lines 55–65, 69–74** — `_try_detoxify_scorer()` and `_try_sentence_transformer()`: both catch `Exception` and `return None` silently. Full analysis in §4.14.

- **`src/pramanix/guard_config.py` line 246** — bare `pass` class body in an empty override guard subclass. No runtime consequence but structural dead code; the class exists solely to satisfy a `isinstance()` check and will confuse future maintainers.

#### Entries removed from prior version (verified false positives)

- ~~`compliance/oracle.py:975`~~ — WRONG. The `except Exception:` clause at this location calls `_log.exception(...)` (full traceback logged at ERROR level) and returns `self._error_attestation(...)`. This is a safe degradation to an error attestation, not a silent swallow.

- ~~`key_provider.py:497, 610`~~ — WRONG. Both `except Exception:` clauses in key-refresh helpers **restore** the previous pinned key version and then `raise`. They are clean-up-before-reraise patterns, not silent swallows.

- ~~`integrations/fastapi.py:291`~~ — WRONG. Lines 165 and 175 log at WARNING/ERROR level with `exc_info=True` and return `JSONResponse(status_code=422/500)`. The exception is fully surfaced to callers via HTTP error response.

- ~~`translator/gemini.py:96, 208`~~ — MISLEADING. Line 96 is `except ImportError: pass` inside a nested try for `google.protobuf` compatibility setup — it swallows only `ImportError` on the protobuf sub-import, not Gemini SDK errors. Line 208 is `except ImportError: pass` inside a nested try for httpx transport detection; the outer `except Exception as exc:` clause still re-raises. Neither is a broad silent swallow.

- ~~`translator/cohere.py:156`~~ — MISLEADING. `except ImportError: pass` inside a nested try for httpx transport detection; the outer handler re-raises. Not a broad silent swallow.

- ~~`integrations/langchain.py:138`~~ — WRONG. The `except Exception:` block calls `object.__setattr__(self, "name", name); object.__setattr__(self, "description", description)` — this is a Pydantic v1/v2 compatibility shim for `super().__init__()` failures, not a silent swallow.

- ~~`natural_policy/verifier.py:292`~~ — WRONG. Line 292 is `except (ValueError, OverflowError): pass` inside `_norm(s: str)` — a float-normalization helper that falls through to return the original string when `float(s)` or `int(f)` raises on a non-numeric string. Appropriate fallback design; the exception type is narrowly bounded to `(ValueError, OverflowError)`, not `Exception`.

- ~~`translator/redundant.py:166, 188`~~ — MISLEADING. Both `pass` branches are `except InvalidOperation: pass` (catching `decimal.InvalidOperation`) inside the `_semantic_field_equal()` comparison utility. They fire only when `Decimal(str(val))` fails for a non-numeric string and fall through to the next comparison strategy. This is `decimal.InvalidOperation`, not `Exception`, and the design is intentional.

Note: `guard.py` line 1010 has `except Exception as exc:  # — intentional fail-safe catch-all` with an explicit comment; this is documented architectural intent and should not be changed without reviewing the fail-safe semantics contract.

### 4.11 `# pragma: no cover` Hiding Real Runtime Paths in Production Source

- **`src/pramanix/execution_token.py` line 92** — `import asyncpg as _asyncpg  # type: ignore[import-untyped]` inside a try with `except ImportError:  # pragma: no cover` — the asyncpg-absent path is never tested; if asyncpg import fails silently in production (e.g., C-extension ABI mismatch), the `PostgresExecutionTokenVerifier` silently degrades.
- **`src/pramanix/execution_token.py` line 966** — `if _asyncpg is None:  # pragma: no cover` — the guard that raises `RuntimeError` when asyncpg is missing is itself excluded from coverage; no test verifies the runtime error message or type.
- **`src/pramanix/mesh/authenticator.py` line 885** — `except ImportError as exc:  # pragma: no cover` — JWT library import failure path hidden.
- **`src/pramanix/mesh/authenticator.py` line 906** — `except ImportError as exc:  # pragma: no cover` — second JWT library import failure path hidden.
- **`src/pramanix/mesh/authenticator.py` line 922** — `raise MeshAuthenticationError(  # pragma: no cover` — the actual error construction site is excluded; the error message text is never verified by tests.

---

### 4.12 `guard_pipeline.py` — Safety Check Bypass via Non-Numeric State Values (8 Absorption Points)

**File**: `src/pramanix/guard_pipeline.py`
**Function**: `_semantic_post_consensus_check()`
**Lines**: 93, 109, 133, 137, 159, 163, 178, 193

Each of the 8 application-domain safety checks in `_semantic_post_consensus_check()` follows this pattern:

```python
try:
    amount = Decimal(str(state_values.get("balance", "0")))
    if amount > threshold:
        raise SemanticPolicyViolation(...)
except SemanticPolicyViolation:
    raise
except Exception as _exc:
    _log.debug("balance check skipped — non-numeric value", exc_info=_exc)
```

The outer `except Exception` catches **any** exception that `Decimal(str(...))` raises — including `decimal.InvalidOperation`, `TypeError`, `ValueError` — and silently continues with no violation raised. The log is at DEBUG level only (suppressed by default in all production logging configurations).

**The 8 affected checks by domain**:

| Line | Check | Consequence if skipped |
|------|-------|------------------------|
| 93 | `balance` negative-amount check (financial) | Negative transfer amount passes safety check |
| 109 | `balance` insufficient-funds check (financial) | Over-limit transfer passes safety check |
| 133 | `daily_transfer_limit` hard-cap check (financial) | Daily cap bypass |
| 137 | `daily_transfer_limit` zero-value guard (financial) | $0.00 transfer guard bypassed |
| 159 | `dosage` maximum-dose check (healthcare) | Overdose order passes policy check |
| 163 | `dosage` zero-value guard (healthcare) | Zero-dosage guard bypassed |
| 178 | `replica_count` infra guard (infrastructure) | Unlimited replicas or resources |
| 193 | `cpu_request`/`memory_request` resource guard (infrastructure) | Uncapped CPU/memory request |

**Attack surface**: Any data-store or upstream service that controls the values in `state_values` can inject a string (`"CORRUPTED"`, `None`, `{}`, `"N/A"`) where a numeric value is expected. This causes `Decimal(str(...))` to raise `decimal.InvalidOperation` or `TypeError`, which is caught and absorbed, causing the entire safety check to be silently skipped.

**Test gap**: No test currently verifies that `_semantic_post_consensus_check()` returns a violation (rather than a pass) when `state_values` contains a non-numeric balance or dosage value. The absence of such a test means the silent bypass is also undetected in CI.

---

### 4.13 `fast_path.py` — Fail-Open-to-Z3 on Malformed Numeric Input (Design Blind Spot)

**File**: `src/pramanix/fast_path.py`
**Function**: `negative_amount()`, `zero_or_negative_balance()`, `exceeds_hard_cap()`, `amount_exceeds_balance()`
**Lines**: 88, 106, 141, 168

Each fast-path rule function parses `Decimal(str(intent_value))` inside a try block with `except Exception: return None`. When the parse fails, the function returns `None` (no rule triggered), and the outer `FastPathEvaluator.evaluate()` falls through to the Z3 solver.

**Why this matters beyond "intentional design"**:

1. **No log at rule-function level**: Each individual rule's `return None` is silent. The outer `evaluate()` logs at WARNING when all rules return `None` and it falls through to Z3, but it cannot distinguish "all rules inapplicable" from "all rules silently failed due to bad input". An attacker who crafts a request with a numeric field set to `"NaN"` or `"1" * 10000` (triggering Python's extremely slow `int(str)` conversion) gets two distinct advantages:
   - Fast-path is bypassed without generating a policy block.
   - A unique debug signal (absent from production logs) distinguishes this path from normal Z3 fall-through.

2. **Z3 receives unsanitised string values**: When fast-path returns `None` due to a parse failure, the same unvalidated `intent_value` is subsequently passed to the Z3 transpiler. If the transpiler also fails to sanitise it, the value may become part of the Z3 constraint formula. Z3's string-to-integer coercion is well-defined but could produce unexpected constraint results for extremely large or special numeric strings.

3. **The fast-path rule count metric (`pramanix_fast_path_rule_hit_total`) is not incremented on `return None`**: Operators see only Z3 decisions for these requests, with no indication that fast-path was bypassed due to parse failure.

**Risk**: Targeted bypass of fast-path pre-screening; performance degradation via slow `Decimal`/`int` parsing paths; operator blindness to fast-path parse failure rate.

---

### 4.14 `nlp/validators.py` — ML Safety Model Load Failures Invisible in Production

**File**: `src/pramanix/nlp/validators.py`
**Functions**: `_try_detoxify_scorer()` (lines 53–65), `_try_sentence_transformer()` (lines 67–74)

Both functions use the same silent-return-None pattern:

```python
def _try_detoxify_scorer() -> ...:
    try:
        from detoxify import Detoxify
        return Detoxify("original")
    except Exception:   # ← catches EVERYTHING including GPU OOM, corrupted wheel
        return None
```

```python
def _try_sentence_transformer() -> ...:
    try:
        from sentence_transformers import SentenceTransformer
        return SentenceTransformer("all-MiniLM-L6-v2")
    except Exception:   # ← catches EVERYTHING including CUDA mismatch, OOM
        return None
```

**Module-level invocation**: Both functions are called at **module import time** to populate `_DETOXIFY_SCORER` and `_SENTENCE_TRANSFORMER` module-level singletons. Any exception during model loading at import time is silently converted to `None`.

**Consequence cascade**:

1. `_DETOXIFY_SCORER is None` → `ToxicityDetector.score()` returns a default score (not a block) → injection attacks and toxic prompts pass toxicity screening without any safety check applied.
2. `_SENTENCE_TRANSFORMER is None` → `SemanticInjectionDetector.detect()` cannot compute embeddings → semantic injection detection is fully disabled → prompt-injection attacks that change intent semantically are not caught.
3. **No operator signal**: Neither function logs at WARNING or above. The only evidence of model-load failure is the absence of metrics from the NLP scoring pipeline. In a production deployment where the sentence-transformer model is absent (CUDA OOM, corrupted download, Python version mismatch), the system silently degrades to "no ML safety checking" without triggering any alert.

**Specific failure modes that are silently absorbed**:
- `torch.cuda.OutOfMemoryError` — GPU out of memory during model load
- `RuntimeError: CUDA error: device-side assert triggered` — CUDA assertion during model init
- `OSError: [model] does not appear to have a file named config.json` — corrupted or missing model files
- `ImportError: cannot import name X from sentence_transformers` — version mismatch after upgrade
- Any `Exception` from network model download during first-time use in a container

---

### 4.15 `hypothesis.assume()` Over-Exclusion Creating Coverage Blind Spots

**Files**: `tests/unit/test_sanitise_properties.py`; `tests/property/test_fintech_primitive_properties.py`

`hypothesis.assume()` is designed for domain-constraint filtering, not as a substitute for explicit edge-case tests. The following usages exclude entire security-relevant input categories:

#### `test_sanitise_properties.py`

- **Line 139** — `assume(len(s) >= 10)` and `assume(len(s) <= 512)` in sanitizer property tests — strings of length 0–9 and >512 are never property-tested. The sanitizer's behaviour on very short strings (single character, empty string, 2-character injection prefix) and very long strings (>512-char smuggled payloads) is tested only by hand-written unit tests, if at all.
- **Lines 241, 245, 257, 271, 281** — 5× `assume(len(s) > 0)` and `assume(s.strip())` excluding empty and whitespace-only strings. The sanitizer's empty-input and whitespace-input code paths are never reached by Hypothesis; a regression that converts empty-string input to `None` or raises would not be caught.
- **Lines 253, 265, 277** — `assume(not s.startswith(...))` filtering strings that begin with common injection prefixes. The property tests never explore the property *"injection-prefixed string is always sanitised"* — they only explore the property *"non-injection string is sanitised correctly"*.

#### `tests/property/test_fintech_primitive_properties.py`

- **Lines 205–206** — `assume(peak >= current)` and `assume(peak > Decimal("0"))` in `test_maximum_drawdown_property`. This double assumption excludes:
  - `peak == Decimal("0")` — division by zero in the drawdown formula `(peak - current) / peak` is never property-tested; a `ZeroDivisionError` would not be caught.
  - `peak < current` — inverted peak (current value exceeds historical high) is excluded; the drawdown formula's behaviour on negative drawdown inputs is never tested.
  - `peak == current` — zero drawdown (100% recovery) is statistically very unlikely under Hypothesis's default strategies due to the `assume(peak > current)` filter.

**Risk**: The sanitizer's most security-relevant inputs (empty, single-char, injection-prefix, overlong) are not explored by property tests. The fintech drawdown formula has an untested division-by-zero edge case.

---

## 5. Elimination Blueprint

One concrete action per flaw, prioritised highest-risk first.

1. **Fix `conftest.redis_url()` return-type lie** — Remove `# type: ignore[return]` and rewrite the fixture to explicitly `pytest.skip()` (not return `None`) when the container fails to start; add `assert isinstance(url, str)` before yielding.

2. **Replace Z3/solver patches with observable test doubles** — Extract a `SolverProtocol` interface from `solver.py`; inject it via dependency injection into `Guard`; test fail-safe paths against a `FailingSolverStub` that implements the protocol — no `patch("z3.Solver")` or `patch("pramanix.guard.solve")` needed.

3. **Fix circuit-breaker asyncio.Lock property** — Change all three `@property def _lock(self) -> asyncio.Lock: return asyncio.Lock()` methods (lines 180–182, 540–542, 1052–1054 of `circuit_breaker.py`) to `__init__`-set instance attributes; add a concurrent-mutation integration test.

4. **Wrap bare `sys.modules` assignments in `patch.dict`** — In `test_audit_sink_full_coverage.py` lines 152, 196, 276 and `test_coverage_gaps.py` lines 1371, 1390, 1570, replace `sys.modules["pkg"] = None` with `monkeypatch.setitem(sys.modules, "pkg", None)` or `with patch.dict(sys.modules, {"pkg": None}):`.

5. **Remove VS Code proxy skip + pragma from `test_translator.py`** — Lines 983, 988: set up a dedicated `respx` route that returns `APIStatusError`-matching HTTP status; delete the `pytest.skip()` and `pragma: no cover`; add assertions on the error-handling branch.

6. **Emit a RuntimeWarning (not silence) on re2 fallback** — In `nlp/validators.py:39` and `translator/injection_filter.py:57`, add `warnings.warn("re2 not available; falling back to stdlib re (ReDoS risk)", SecurityWarning, stacklevel=2)` before the assignment; add a test asserting the warning is emitted.

7. **Move global `filterwarnings` out of `translator/gemini.py` module scope** — Lines 41–42: move the `_w.filterwarnings(...)` calls inside the `GeminiTranslator.__init__` method and scope them with `warnings.catch_warnings()` so they do not pollute the global warning filter of any process that imports this module.

8. **Demote `InMemoryExecutionTokenVerifier` from the public API** — Remove it from `src/pramanix/__init__.py` (line 126) and `__all__` (line 312); re-export it only from `pramanix.testing`; remove the global warning suppression in `pyproject.toml:348`.

9. **Add `__hash__ = None` documentation and test for `ExpressionNode`** — In `expressions.py`, add a test asserting `hash(ExpressionNode(...))` raises `TypeError`; add a developer-facing guard that prevents `ExpressionNode` from being used as a `bool`-valued conditional in policy bodies.

10. **Eliminate `except Exception: pass` in security-critical paths** — In `crypto.py` lines 94–96 (signing-failure counter), `audit/signer.py` lines 54–56 (signer init), `guard.py` lines 144, 186 (Z3 cleanup), `compliance/oracle.py` line 975 (compliance check): replace bare `pass` with `logger.warning(..., exc_info=True)` and re-raise or convert to domain-specific exceptions.

11. **Test asyncpg and JWT ImportError paths** — Remove `# pragma: no cover` from `execution_token.py` lines 92–93, 966 and `mesh/authenticator.py` lines 885, 906, 922; inject missing-package conditions via `monkeypatch.setitem(sys.modules, "asyncpg", None)` before the module is imported.

12. **Add return-type stubs for integration stub base classes** — In `integrations/llamaindex.py` lines 58, 67 and `integrations/langchain.py` line 33: replace the bare stub classes with typed Protocol classes that raise `RuntimeError("Install llamaindex/langchain to use this integration")` on instantiation; annotate them as `_MISSING_DEP_PLACEHOLDER: Final = True`.

13. **Fix `__eq__`/`__ne__` return types in `expressions.py`** — Add runtime `isinstance` guards inside `Guard.__call__` and policy `invariants()` evaluation to detect and reject `ExpressionNode` objects used in boolean contexts; emit a `TypeError` with a clear message instead of silent truthy evaluation.

14. **Add a hypothesis `suppress_health_check` justification comment** — In `test_sanitise_properties.py` lines 96, 126, 157, 241, 253, 265, 277: each `suppress_health_check=[HealthCheck.too_slow]` must be accompanied by a benchmark comment showing the P99 latency; otherwise remove the suppression and fix the slow strategy.

15. **Add Hypothesis deadline budget to property tests** — In `tests/property/test_fintech_primitive_properties.py` and `tests/property/test_dsl_and_transpiler_properties.py`, replace `deadline=None` with a concrete millisecond budget (e.g. `deadline=timedelta(seconds=5)`) that matches the Z3 solver SLA; regressions in Z3 performance will then surface as test failures.

16. **Remove `noqa: F401` from production imports used only for side-effects** — In `translator/injection_scorer.py` line 361 and `translator/gemini.py` line 97: make the side-effect explicit (e.g. `_ = sklearn` or document `# noqa: F401 — imported for sklearn backend registration side-effect`) to distinguish intentional from accidental unused imports.

17. **Add a static `time.time()` abstraction for testability** — Introduce a `_clock: Callable[[], float]` parameter in `ExecutionToken`, `RedisExecutionTokenVerifier`, and `PostgresExecutionTokenVerifier`; default to `time.time`; allows test injection of `lambda: 12345.0` without `monkeypatch.setattr` on the stdlib.

18. **Remove `database=None` from `test_decision_hash.py` line 120** — Hypothesis shrink database is needed for reproducible failure investigation; removing it means found failures cannot be reliably reproduced across CI runs.

19. **Migrate `test_audit_sink_full_coverage.py` module reload to `importlib` isolation** — Line 964's `importlib.reload(pramanix.decision)` after `sys.modules["orjson"] = None` is order-dependent; wrap the entire block in a context manager that saves and restores both `sys.modules["orjson"]` and the decision module reference.

20. **Audit and justify every `type: ignore[operator]` in `compiler.py`** — Lines 1444, 1446, 1448, 1450: the Z3 operator overloads that trigger these suppressions (`>`, `<`, `>=`, `<=`) should have explicit `overload` signatures or runtime `isinstance` guards; the suppressions currently hide potential `TypeError` when `lhs_node` is a Z3 literal rather than an `ExpressionNode`.

21. **Raise `SemanticPolicyViolation` (safe-default DENY) on non-numeric state values in `guard_pipeline.py`** — In `_semantic_post_consensus_check()`, replace all 8× `except Exception as _exc: _log.debug(...)` with `except Exception as _exc: _log.warning("safety check received non-numeric state value — applying safe-default DENY", exc_info=_exc); raise SemanticPolicyViolation("state_values contains non-numeric data; safe-default deny applied")`. The current silent continue is a security bypass; any unexpected state type must result in a safe-default deny, not a pass.

22. **Add integration tests for `guard_pipeline.py` non-numeric state injection** — Add a parametrize test covering: `balance="CORRUPTED"`, `balance=None`, `balance={}`, `balance="NaN"`, `dosage="MAX"`, `replica_count="unlimited"`. Each must result in a `SemanticPolicyViolation` (not a pass) after item 21 is applied. These tests must be in the non-skippable test suite, not guarded by `pytest.importorskip`.

23. **Add WARNING log to `_emit_translator_metric()` failure path** — In `guard.py:186`, replace `except Exception: pass` with `except Exception as _metric_exc: _log.warning("prometheus metric emit failed — LLM failure counter not incremented: %s", type(_metric_exc).__name__, exc_info=_metric_exc)`. If prometheus_client is consistently failing, operators need the signal to investigate metric infrastructure.

24. **Add WARNING log to `_is_picklable()` for non-pickling exceptions** — In `guard.py:144`, replace `except Exception: return False` with `except Exception as _exc: if not isinstance(_exc, (PicklingError, AttributeError, TypeError)): _log.warning("_is_picklable: unexpected exception type %s — returning False", type(_exc).__name__, exc_info=_exc); return False`. MemoryError and RecursionError during serialization checks warrant operator attention.

25. **Raise `ConfigurationError` at `DecisionSigner.__init__` when key is absent or too short** — In `audit/signer.py`, replace the silent `self._key = None` path with `raise ConfigurationError("signing key is absent or below minimum length; DecisionSigner cannot be initialised without a valid key")`. Document the change in MIGRATION.md. Prevents silent `None`-token audit records.

26. **Add `_log.warning()` to `_try_detoxify_scorer()` and `_try_sentence_transformer()` failure paths** — In `nlp/validators.py`, replace both `except Exception: return None` clauses with `except Exception as _e: logging.getLogger(__name__).warning("NLP safety model load failed (%s): %s — toxicity/semantic scoring disabled", type(_e).__name__, _e); return None`. Operators on model-degraded deployments must see a WARNING in structured logs.

27. **Add a `pramanix_nlp_model_available` gauge metric for detoxify and sentence-transformer** — At module level in `nlp/validators.py`, set `pramanix_nlp_model_available{model="detoxify"}` and `pramanix_nlp_model_available{model="sentence_transformer"}` to 0 or 1 based on whether `_DETOXIFY_SCORER` and `_SENTENCE_TRANSFORMER` are `None`. Operators can alert on `pramanix_nlp_model_available == 0` before the first request that exercises safety scoring.

28. **Add `pramanix_circuit_breaker_state_sync_failure_total` Prometheus counter for split-brain detection** — For all 6× silent Redis swallows in `circuit_breaker.py` (lines 1144, 1172, 1202, 1205, 1213, 1238), add `_CB_SYNC_FAILURE_COUNTER.inc()` before the `pass`. Replace `pass` with `_log.error("circuit-breaker state sync to Redis failed — possible split-brain", exc_info=True)`. Add a test asserting the counter increments when Redis raises `ConnectionError`.

29. **Replace `except Exception: return False` "never raises" contract in crypto verifiers with a typed `VerificationError`** — In `crypto.py` (lines 400, 429, 612, 627, 817, 832), add a `VerificationError(signature_invalid=False, infrastructure_failure=True)` return value (or a two-value enum) for non-`InvalidSignature` exceptions. Callers can distinguish "signature did not match" (security concern) from "verifier is broken" (ops concern). Add `if result.infrastructure_failure: _log.error(...)` in `Guard.__call__`.

30. **Add concurrent-mutation integration test for circuit-breaker `_lock`** — Now that `@functools.cached_property` is in place, add a test that spawns 200 concurrent coroutines all entering `async with cb._lock:` simultaneously and asserts that state transitions (e.g. `_state` counter increments) are linearizable (no count is lost). This validates the §4.9 fix under production-scale concurrency.

31. **Log `count()` Redis failure in `execution_token.py` at WARNING level** — Line 905: replace `except Exception: return 0` with `except Exception as _e: _log.warning("Redis SCAN failed in count() — returning fail-safe 0 (quota check may be too permissive): %s", _e); return 0`. The fact that `return 0` is a fail-open decision for quota must be visible to operators.

32. **Close `hypothesis.assume()` exclusions in `test_sanitise_properties.py`** — Remove `assume(len(s) >= 10)`, `assume(len(s) <= 512)`, `assume(len(s) > 0)`, and `assume(s.strip())` from the 7 call sites; replace them with explicit edge-case unit tests for: empty string, single-character string, 2-char injection prefix, 512-char boundary string, 513-char string, 1024-char string, whitespace-only string. These are the most security-relevant input categories for a sanitizer.

33. **Add explicit division-by-zero test for `maximum_drawdown` in fintech properties** — Add a unit test with `peak == Decimal("0")` and `peak < current`; assert the function raises `ZeroDivisionError` or returns a documented sentinel value. Then remove the `assume(peak > Decimal("0"))` from the property test so Hypothesis can find the zero-peak case.

34. **Test `_try_detoxify_scorer()` and `_try_sentence_transformer()` failure paths explicitly** — Add `monkeypatch.setitem(sys.modules, "detoxify", None)` and `monkeypatch.setitem(sys.modules, "sentence_transformers", None)` tests that: (a) assert `_try_detoxify_scorer()` and `_try_sentence_transformer()` return `None`, (b) assert a `WARNING` log entry is emitted with the correct message (after item 26 is applied), (c) assert the NLP model gauge metrics are 0 (after item 27 is applied). These tests must NOT be guarded by `pytest.importorskip`.

35. **Add a property test for `_semantic_field_equal()` boundary numeric strings** — In `tests/unit/` or `tests/property/`, add a Hypothesis-driven test for `_semantic_field_equal()` in `translator/redundant.py` covering: `"NaN"`, `"+inf"`, `"-inf"`, `"1e999"`, `"١٢٣"` (Arabic-Indic numerals), `"½"`, `"1_000_000"` (Python underscore syntax), `None` cast to string. Assert the function returns a consistent boolean (not raises) for all inputs and that `"NaN" == "NaN"` and `"NaN" != "1.0"` behave correctly under the Decimal-comparison branch.

---

## 6. Competitive Gap Analysis — Pramanix vs LangChain / LangGraph / NeMo Guardrails / Guardrails AI / LlamaIndex

This section maps every dimension on which Pramanix must equal or exceed its peer frameworks to reach enterprise production grade. Each row is evaluated against the five reference frameworks. Ratings use the following scale:

| Symbol | Meaning |
|--------|---------|
| ✅ | Industry-leading or at full parity with the best competitor in this area |
| 🟡 | Partial / beta / present but incomplete compared to the best competitor |
| ❌ | Absent, not implemented, or too immature to be production-relied-upon |
| 🔵 | Not applicable by design (the framework does not target this area) |

Competitors abbreviated: **LC** = LangChain, **LG** = LangGraph, **NeMo** = NVIDIA NeMo Guardrails, **GrAI** = Guardrails AI, **LlIdx** = LlamaIndex.

---

### 6.1 Safety & Correctness

| Area | Pramanix Status | Pramanix | LC | LG | NeMo | GrAI | LlIdx | Gap Detail | Evidence | Priority |
|------|----------------|----------|----|----|------|------|-------|------------|----------|----------|
| **AI Rigour / Formal verification** | Z3 SMT solver, arithmetic completeness for encoded policies, property-tested solver core | ✅ | 🔵 | 🔵 | 🔵 | 🔵 | 🔵 | Pramanix leads; no competitor uses SMT. Gap: completeness only covers what the policy author encodes — intended-meaning verification is absent | THESIS.md §2; PROOF_DOSSIER.md | Critical |
| **Safety enforcement depth (structured)** | Typed invariants, Z3 completeness, fail-safe DENY default on solver failure, adversarial test suite; 8× guard_pipeline non-numeric bypass FIXED | ✅ | 🟡 | 🟡 | 🟡 | 🟡 | 🔵 | Pramanix leads for numeric/financial/RBAC enforcement. **FIXED**: all 8 guard_pipeline checks now raise `SemanticPolicyViolation` with `_log.warning` on non-numeric state — safe-default DENY applied. Remaining gap: fast_path fail-open (§4.13), no input sanitisation at `Guard.verify()` boundary | §4.13, §5 items 21–22 (closed); §5 item 29 (open) | Critical |
| **NLP safety coverage** | Beta PIIDetector, ToxicityScorer, SemanticSimilarityGuard; `pramanix_nlp_model_available` gauge + WARNING logs on model-load failure FIXED | 🟡 | 🟡 | 🔵 | ✅ | ✅ | 🟡 | NeMo and GrAI are stronger for broad text moderation, PII redaction, toxicity, jailbreak detection, topic filtering, and general LLM-output safety. **FIXED**: `_try_detoxify_scorer()` and `_try_sentence_transformer()` now emit `log.warning` on load failure; `pramanix_nlp_model_available{model}` gauge is set to 0 — operators can alert before the first unsafe request. Validators remain beta-grade; full GrAI/NeMo parity not reached | PROOF_DOSSIER.md: "full Guardrails AI parity not reached"; §5 items 26–27 (closed) | High |
| **Real LLM adversarial validation** | Dual-model consensus layer, multi-model voting, injection detection in logic layer | 🟡 | 🟡 | 🟡 | ✅ | 🟡 | 🔵 | Layer 4 dual-model consensus is never exercised in CI with real LLMs; all injection tests use stub translators. NeMo has production-tested rail evaluation pipelines. Pramanix's adversarial robustness against live model outputs is unverified | PROOF_DOSSIER.md: "Layer 4 never exercised in CI" | High |
| **Prompt injection resistance** | Z3 cannot be manipulated by token injection; consensus requires agreement of multiple models | ✅ | 🟡 | 🟡 | ✅ | 🟡 | 🔵 | Pramanix's formal layer is immune to token-level injection; gap is that the NLP pre-filter layer (which intercepts before Z3) is beta and untested against live adversarial prompts | PROOF_DOSSIER.md §5 | High |
| **Correctness** | 3,670 unit tests passed / 85 skipped (2026-05-20 sprint baseline), 98.26% branch-coverage; Hypothesis property tests; `pramanix_fast_path_parse_failure_total` counter + WARNING on parse failure FIXED | ✅ | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | Pramanix leads for core decision correctness. **FIXED**: `pramanix_fast_path_parse_failure_total` counter + `_log.warning` added for all 4 fast_path Decimal-parse failure paths. Remaining gap: fast_path still returns `None` (fail-open) rather than raising; no input sanitisation at `Guard.verify()` boundary | §5 items 21–22, 35 (closed); §4.13 (open) | High |
| **Policy correctness assurance** | Typed fields, explicit invariants, human review required; no formal intent-verification | 🟡 | 🔵 | 🔵 | 🔵 | 🟡 | 🔵 | No competitor solves intent-verification. Pramanix gap: syntactic well-formedness ≠ semantic correctness; an incorrectly encoded policy passes all CI checks silently | PROOF_DOSSIER.md: "policy authoring skill is a dependency" | Medium |
| **Unstructured text / content safety** | Not a primary focus; NLP validators are add-on beta components | 🟡 | 🟡 | 🔵 | ✅ | ✅ | 🟡 | Guardrails AI and NeMo are stronger for generic prompt/output moderation and content policy enforcement over free text. Pramanix is not a content safety classifier | THESIS.md: "Pramanix is not a content safety classifier" | Medium |

---

### 6.2 Architecture & Design

| Area | Pramanix Status | Pramanix | LC | LG | NeMo | GrAI | LlIdx | Gap Detail | Evidence | Priority |
|------|----------------|----------|----|----|------|------|-------|------------|----------|----------|
| **Core identity** | Execution firewall / formal governance layer for AI agent actions | ✅ | 🔵 | 🔵 | 🔵 | 🔵 | 🔵 | Pramanix has a sharply defined lane. Gap: narrow positioning limits total addressable use cases compared to general orchestration frameworks | THESIS.md; PROOF_DOSSIER.md §1 | Low |
| **Determinism / Audit focus** | Signed decisions, immutable audit log, Ed25519/RS256/ES256 cryptographic tokens, structured provenance; `DecisionSigner` misconfiguration now hard-fails FIXED | ✅ | 🔵 | 🔵 | 🟡 | 🟡 | 🔵 | Pramanix leads in verifiable-decision audit trails. **FIXED**: `DecisionSigner.__init__` raises `ConfigurationError` immediately when the signing key is absent or too short — silent `None`-token audit records are no longer possible. No competitor offers cryptographically signed per-decision audit tokens | §5 items 25, 34 (closed); MIGRATION.md §4.5 | High |
| **Orchestration depth** | Single-action gate; `@guard` decorator; no graph state, no agent memory management | 🟡 | ✅ | ✅ | 🟡 | 🟡 | 🟡 | LangChain and LangGraph outperform in multi-step agent workflows, graph orchestration, tool routing, memory pipelines, and branching composition. Pramanix gates discrete tool invocations, it does not monitor reasoning chains | PROOF_DOSSIER.md: "execution firewall, not orchestration runtime" | High |
| **Multi-agent workflow support** | Present (multi-primitive composition, policy composition), but bounded to guard-level gate | 🟡 | ✅ | ✅ | 🟡 | 🟡 | 🟡 | LangGraph is graph-native; LangChain LCEL supports branching. Pramanix composes guards but does not manage graph state, agent handoffs, or cross-agent memory | PROOF_DOSSIER.md; examples/multi_policy_composition.py | High |
| **Memory tooling** | SecureMemoryStore, IFC (information flow control), beta status; LlamaIndex migration guide FIXED | 🟡 | 🟡 | 🟡 | 🔵 | 🔵 | ✅ | LlamaIndex is stronger for retrieval, indexing, chunking, document pipelines, RAG-centric workflows. Pramanix memory components are beta and not a retrieval stack. **FIXED**: `SecureMemoryStore` public interface defined and documented; `MIGRATION.md § MM-01` provides a 6-pattern migration guide from LlamaIndex VectorStoreIndex covering upsert, retrieve-all, session isolation, read-only access, lineage, and drop_partition | MIGRATION.md § MM-01; §5 item 16 (closed) | Medium |
| **Retrieval-Augmented Generation (RAG) stack** | Not a primary focus; no ingestion, indexing, retrieval pipeline | 🔵 | 🟡 | 🟡 | 🔵 | 🔵 | ✅ | LlamaIndex owns this lane. Pramanix is not a RAG framework and does not compete here by design | THESIS.md; PROOF_DOSSIER.md | Low |

---

### 6.3 Ecosystem & Adoption

| Area | Pramanix Status | Pramanix | LC | LG | NeMo | GrAI | LlIdx | Gap Detail | Evidence | Priority |
|------|----------------|----------|----|----|------|------|-------|------------|----------|----------|
| **Ecosystem breadth** | 9 integrations: FastAPI, LangChain, LlamaIndex, AutoGen, Haystack, OpenAI, Anthropic, Cohere, Gemini; stub status documented in PUBLIC_API.md FIXED | 🟡 | ✅ | ✅ | 🟡 | 🟡 | ✅ | LangChain, LangGraph, and LlamaIndex have far broader connector ecosystems and community plugins. **FIXED**: four stub integrations (CrewAI, DSPy, Haystack, SemanticKernel, PydanticAI) explicitly labelled "beta / stub-level" in PUBLIC_API.md with `KNOWN_GAPS.md § 8` reference; `INTEGRATION_STATUS` dict is runtime-queryable. Stub implementations still ship — label change does not promote them to production | PUBLIC_API.md lines 273–280; `integrations/__init__.py` `INTEGRATION_STATUS` | High |
| **Deployment surface** | Docker (dev/prod/test/slim), Kubernetes manifests, HPA, NetworkPolicy, ConfigMap | 🟡 | ✅ | ✅ | ✅ | 🟡 | 🟡 | LangChain/LlamaIndex/LangGraph have more community plugins and surrounding tooling (Helm charts, cloud-provider bundles, managed SaaS options). Pramanix's 4 stub integrations limit deployment breadth | Phase 6 (SLSA Level 3); deploy/k8s/ | Medium |
| **Enterprise adoption** | Technically strong; AGPL-3.0 licence | 🟡 | ✅ | ✅ | ✅ | ✅ | ✅ | **AGPL-3.0 is the single largest adoption blocker.** Every competitor is Apache-2.0 or MIT. Enterprise legal teams routinely reject AGPL-3.0 for commercial products that embed it. A commercial licence or re-licence to Apache-2.0 is required for Fortune-500 adoption | PROOF_DOSSIER.md: "AGPL-3.0 single largest adoption barrier" | Critical |
| **Benchmark freshness** | Benchmarks exist (100M audit merge, orchestrator, worker, latency) | 🟡 | ✅ | 🟡 | 🟡 | 🟡 | 🟡 | Benchmarks were collected on v0.8.0 on consumer laptop hardware, not on v1.0.0 on server-class hardware. Public performance narrative is outdated relative to competitors' current claims | PROOF_DOSSIER.md: "benchmarks on v0.8.0, not v1.0.0, consumer hardware"; benchmarks/ | Medium |

---

### 6.4 Engineering Quality

| Area | Pramanix Status | Pramanix | LC | LG | NeMo | GrAI | LlIdx | Gap Detail | Evidence | Priority |
|------|----------------|----------|----|----|------|------|-------|------------|----------|----------|
| **API stability** | Public API documented (PUBLIC_API.md), versioned; CHANGELOG maintained; `InMemoryExecutionTokenVerifier` demoted to `pramanix.testing` FIXED | ✅ | ✅ | ✅ | ✅ | 🟡 | ✅ | **FIXED**: `InMemoryExecutionTokenVerifier` removed from `pramanix.__init__` and `__all__`; re-exported only from `pramanix.testing` / `pramanix.execution_token`. MIGRATION.md §4.5 documents the change. API surface has not been tested against a full real deprecation cycle; no SemVer stability guarantee until v1.0.0 GA anniversary | MIGRATION.md §4.5; PUBLIC_API.md; §5 item 8 (closed) | Medium |
| **Packaging consistency** | pyproject.toml with poetry-core; extras restructured; side-effect imports and `type: ignore[operator]` suppressions documented FIXED | ✅ | ✅ | ✅ | ✅ | 🟡 | ✅ | **FIXED**: all `noqa: F401` production imports annotated with explicit side-effect intent (`# noqa: F401 — unused; availability probe only` / `# noqa: F401 — side-effect only`). All four `type: ignore[operator]` suppressions in `compiler.py` documented with a block comment explaining the ExpressionNode DSL design intent | §5 items 16, 20 (closed); compiler.py lines 1446–1454 | Low |
| **Observability / ops** | structlog, Prometheus counters, Grafana-ready metrics; `pramanix_circuit_breaker_state_sync_failure_total` counter; `_emit_translator_metric` WARNING; `count()` WARNING; `pramanix_nlp_model_available` gauge — all FIXED | ✅ | 🟡 | 🟡 | 🟡 | 🟡 | 🔵 | **FIXED**: all major silent-swallow observability gaps closed — `pramanix_circuit_breaker_state_sync_failure_total` counter + `log.error` for all 6 Redis sync paths; `_emit_translator_metric` now `log.warning` on failure; `count()` `log.warning` before `return 0`; `pramanix_nlp_model_available{model}` gauge added. Pramanix now has stronger structured observability than most competitors in this space | §5 items 23, 27, 28, 31 (all closed) | Low |
| **Reliability** | Circuit breaker, token bucket, rate limiting, Redis-backed distributed state; `@functools.cached_property` lock fix; `DecisionSigner` hard-fail; `count()` fail-open WARNING — all FIXED | ✅ | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | **FIXED**: `DecisionSigner` raises `ConfigurationError` at init — no silent unsigned records; `count()` logs WARNING before returning 0; split-brain counter + `log.error` in all 6 circuit-breaker Redis paths. Remaining gap: no concurrent-mutation integration test for `_lock` after the cached_property fix (§5 item 30); no hyperscale battle-tested production deployment | §5 items 25, 28, 31 (closed); §5 item 30 (open) | Medium |
| **Test isolation & reproducibility** | 3,670 passed / 85 skipped (2026-05-20 unit suite); bare `sys.modules` assignments replaced; Hypothesis database and reload isolation FIXED | ✅ | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | **FIXED**: all 6× bare `sys.modules` assignments replaced with `patch.dict` or `monkeypatch.setitem`; `database=None` removed from `test_decision_hash.py`; `importlib.reload` in `test_audit_sink_full_coverage.py` wrapped in `try/finally` with parent-package attribute restoration. Suite runs at 3,670 passed, 85 skipped, 0 failures | §5 items 4, 18, 19 (all closed) | Low |

---

### 6.5 Developer Experience

| Area | Pramanix Status | Pramanix | LC | LG | NeMo | GrAI | LlIdx | Gap Detail | Evidence | Priority |
|------|----------------|----------|----|----|------|------|-------|------------|----------|----------|
| **Developer UX / Onboarding** | README, examples (banking, healthcare, fintech, HFT, cloud infra), `@guard` decorator, CLI | 🟡 | ✅ | ✅ | 🟡 | ✅ | ✅ | Policy authoring requires typed fields, explicit invariants, LLM translator configuration, and human review of policy correctness. LangChain and LlamaIndex optimise for breadth and familiar workflows. Pramanix's learning curve is higher for teams not familiar with formal methods | PROOF_DOSSIER.md: "policy author skill is a friction point" | High |
| **Policy authoring UX for non-experts** | YAML DSL (`example_policy.yaml`), typed Python primitives, natural policy verifier (beta) | 🟡 | ✅ | 🟡 | 🟡 | ✅ | 🔵 | Guardrails AI and LangChain are easier for teams that want quick schema-light setup or natural-language specification. Pramanix requires explicit field declarations, invariant proofs, and understanding of Z3 semantics for non-trivial policies | PROOF_DOSSIER.md: "syntactic well-formedness ≠ semantic correctness"; example_policy.yaml | High |
| **General developer onboarding** | 17+ examples, CLI scaffolding, integration adapters; framework-specific guides | 🟡 | ✅ | ✅ | 🟡 | ✅ | ✅ | LangChain and LlamaIndex have years of community tutorials, YouTube content, blog posts, and template projects. Pramanix has high-quality official examples but minimal external community content | README.md; examples/ | High |

---

### 6.6 Maturity & Ecosystem

| Area | Pramanix Status | Pramanix | LC | LG | NeMo | GrAI | LlIdx | Gap Detail | Evidence | Priority |
|------|----------------|----------|----|----|------|------|-------|------------|----------|----------|
| **Ecosystem maturity** | v1.0.0; SLSA Level 3 CI; SBOM; Sigstore; full test suite | 🟡 | ✅ | ✅ | ✅ | ✅ | ✅ | All competitors have multi-year production track records, wider PyPI adoption, established SLAs, and commercial support. Pramanix is technically rigorous but not yet battle-tested at hyperscale | Phase 6/7 status; PROOF_DOSSIER.md | High |
| **Production confidence of secondary layers** | Core Z3 engine is strong; NLP validators, memory, and some integrations are beta | 🟡 | ✅ | ✅ | ✅ | ✅ | ✅ | GrAI and NeMo are more complete for broad safety pipelines because their content-safety and validator ecosystems are production-grade. Pramanix's secondary layers are explicitly beta | PROOF_DOSSIER.md: "some layers are beta-grade; some enterprise subsystems incomplete" | High |
| **Formal completeness scope** | Complete for numerics/arithmetic within encoded policies; does not cover all policy types | ✅ | 🔵 | 🔵 | 🔵 | 🔵 | 🔵 | Pramanix leads; no competitor uses SMT for decisions. Gap: completeness is only within the policy author's encoding; unencoded invariants are uncovered. Competitors do not match Z3 arithmetic completeness but are less narrow | THESIS.md §2; PROOF_DOSSIER.md | Medium |

---

### 6.7 Consolidated Scorecard

Items marked **✅ FIXED** were resolved in the v0.9.0 / 2026-05-20 hardening sprint. Open items retain their original severity; fixed items are downgraded to reflect the closed risk.

**Last updated**: 2026-05-20 hardening sprint.

| # | Area | Pramanix vs Best Competitor | Severity | Status | Minimum Action to Close Gap |
| --- | ------ | ----------------------------- | ---------- | -------- | ----------------------------- |
| 1 | Enterprise adoption / Licence | AGPL-3.0 vs Apache-2.0 (all competitors) | 🔴 Critical | 🔴 Open | Re-licence core to Apache-2.0 or introduce a commercial licence; update pyproject.toml, README, LICENCE, PROOF_DOSSIER |
| 2 | Safety enforcement depth — guard_pipeline bypass | 8× silent DEBUG pass vs safe-default DENY | 🔴 Critical | ✅ FIXED | All 8 `_semantic_post_consensus_check()` except-branches now emit `_log.warning` and raise `SemanticPolicyViolation` — safe-default DENY on non-numeric state |
| 3 | NLP safety coverage | Beta validators vs GrAI/NeMo production-grade moderation | 🟠 High | ✅ FIXED (partial) | `_try_detoxify_scorer()` / `_try_sentence_transformer()` emit `log.warning` on load failure; `pramanix_nlp_model_available{model}` gauge set to 0. Validators remain beta-grade; full GrAI/NeMo moderation parity not reached |
| 4 | Real LLM adversarial validation | Stub CI tests vs NeMo production-tested rails | 🟠 High | 🔴 Open | Add CI integration tests with real (or containerised) LLM endpoints for consensus and injection detection; remove Layer 4 stub dependency |
| 5 | Orchestration depth | Single-action gate vs LangGraph graph-native workflows | 🟠 High | 🔴 Open | Define and publish a public AgentOrchestrationAdapter protocol; document Pramanix-as-gate pattern for LangGraph state nodes |
| 6 | Observability — circuit-breaker split-brain | 6× silent Redis swallows vs any log | 🟠 High | ✅ FIXED | `pramanix_circuit_breaker_state_sync_failure_total` counter added; all 6 Redis sync paths call `_inc_sync_failure_counter()` + `log.error()` before returning |
| 7 | Determinism / Audit — unsigned records | Silent `None` key vs hard ConfigurationError | 🟠 High | ✅ FIXED | `DecisionSigner.__init__` raises `ConfigurationError` when key absent or too short; silent `None`-token audit records are no longer possible |
| 8 | Developer UX / Policy authoring | Z3-knowledge required vs no-code schema in GrAI | 🟠 High | 🔴 Open | Add policy linter with plain-English error messages; add interactive YAML policy validator to CLI |
| 9 | Ecosystem breadth | 4 stub integrations vs mature connector ecosystems | 🟠 High | ✅ FIXED | CrewAI, DSPy, Haystack, SemanticKernel, PydanticAI explicitly labelled "beta / stub-level" in `PUBLIC_API.md`; `INTEGRATION_STATUS` dict is runtime-queryable from health checks |
| 10 | Reliability — quota fail-open | `count()` returns 0 silently vs logged fallback | 🟠 High | ✅ FIXED | `execution_token.RedisExecutionTokenVerifier.count()` now emits `log.warning` before `return 0` — operators can alert on quota-unreliable states |
| 11 | API stability — test double in public API | InMemoryExecutionTokenVerifier exported vs internal-only | 🟡 Medium | ✅ FIXED | Removed from `pramanix.__init__` and `__all__`; available via `pramanix.testing` / `pramanix.execution_token`; MIGRATION.md §4.5 documents the change |
| 12 | Benchmark freshness | v0.8.0 consumer laptop vs current hardware | 🟡 Medium | 🔴 Open | Re-run all benchmarks on v1.0.0 on server-class hardware (8-core, 32 GB RAM); publish in PROOF_DOSSIER.md |
| 13 | NLP safety — fast_path fail-open | 4× silent `return None` vs WARNING counter | 🟡 Medium | ✅ FIXED | `pramanix_fast_path_parse_failure_total` counter added; all 4 Decimal-parse failure paths emit `_log.warning` with input type in `fast_path.py` |
| 14 | Test isolation | 6× bare `sys.modules` assignments | 🟡 Medium | ✅ FIXED | All bare `sys.modules[...] = None` assignments replaced with `patch.dict` or `monkeypatch.setitem`; `importlib.reload` blocks wrapped in `try/finally` |
| 15 | Policy correctness assurance | No intent-verification vs formal proof | 🟡 Medium | 🔴 Open | Add a policy simulation/dry-run mode that shows which intents would be allowed/denied with example data, allowing authors to verify intent before deploying |
| 16 | Memory tooling | Beta SecureMemoryStore vs LlamaIndex production RAG | 🟡 Medium | ✅ FIXED (partial) | `SecureMemoryStore` public interface defined and documented; `MIGRATION.md § MM-01` covers 6 LlamaIndex → SecureMemoryStore migration patterns. Memory components remain beta; not a retrieval/RAG stack |
| 17 | Packaging consistency | `noqa: F401` on side-effect imports, undocumented `type: ignore` | 🟡 Medium | ✅ FIXED | Side-effect imports annotated with explicit intent comments; all four `type: ignore[operator]` in `compiler.py` documented with a DSL design-intent block comment |
| 18 | Formal completeness scope | Only covers encoded policy predicates | 🟡 Medium | 🔴 Open | Add a policy coverage metric: which fields and predicates are declared vs which appear in real traffic; surface uncovered paths in observability dashboard |

