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
- ~~**Lines 285–333, 501–521, 1121–1129**~~ — **✅ REMOVED** — `prometheus_client` MagicMock patch blocks eliminated; tests now hit real prometheus_client counters (or the real `_PROM_AVAILABLE` gate).

#### `tests/adversarial/test_fail_safe_invariant.py` (moved from `tests/unit/`)
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
- ~~**Lines 983, 988**~~ — **✅ REMOVED** — Both VS Code dev proxy `pytest.skip()` calls and their associated `pragma: no cover` have been deleted; `respx` routes now simulate `APIStatusError` HTTP responses directly.
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
- ~~`tests/unit/test_circuit_breaker_and_guard_paths.py` lines 285–333, 501–521, 1121–1129~~ — **✅ REMOVED** — prometheus_client MagicMock blocks eliminated.
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
- ~~`tests/unit/conftest.py` line 31~~  — **✅ FIXED** — `redis_url` fixture rewritten as `Generator[str, None, None]`; calls `pytest.skip()` explicitly when the container fails to start. `# type: ignore[return]` removed. No more silent `None` URL injection into session-scoped consumers.
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
- ~~`tests/unit/test_audit_sink_full_coverage.py` lines 152, 196, 276~~  — **✅ FIXED** — bare `sys.modules["confluent_kafka"] = None`, `sys.modules["boto3"] = None`, `sys.modules["datadog_api_client"] = None` replaced with `with patch.dict(sys.modules, {...}):` blocks using `try/finally`.

---

## 3. Pragma Directives, Suppressions & Silence Rules

### 3.1 Inline Pragmas & Linter Disables (`# noqa`)

**`src/pramanix/cli.py` line 1137** — `s.add(z3.Bool("x") == True)  # noqa: E712` — E712 "comparison to True" silenced; the `z3.Bool` comparison to Python `True` is intentional but the silence hides the semantic oddity.

**`src/pramanix/cli.py` line 1195** — `Ed25519PrivateKey,  # noqa: F401` — unused import suppressed; key type is imported for side-effects only but the suppression hides a dead import path.

**`src/pramanix/k8s/webhook.py` line 103** — `body: dict[str, Any] = _fastapi.Body(...),  # noqa: B008` — B008 "do not use mutable data structures as default values" silenced; the `Body(...)` sentinel is a FastAPI convention but the suppression hides a linting concern for non-FastAPI consumers.

**`src/pramanix/natural_policy/compiler.py` line 655** — `from pydantic import BaseModel as _BaseModel  # noqa: E402` — late import after module-level try-except blocks; suppression hides a structural design issue (conditional-import anti-pattern at module scope).

**`src/pramanix/translator/injection_scorer.py` line 361** — `import sklearn  # noqa: F401` — sklearn imported for its side-effect of registering the backend; suppression hides the implicit coupling to sklearn's global state.

**`src/pramanix/translator/gemini.py` line 97** — `import google.generativeai  # noqa: F401 — side-effect only` — annotated with explicit side-effect intent comment (✅ FIXED in §5 item 16).

**`pyproject.toml` lines 345–365** — `filterwarnings` block in `[tool.pytest.ini_options]` silences:
- `pydantic.warnings.PydanticDeprecatedSince20` — Cohere SDK V1 API deprecation swallowed; operators will not receive advance notice of upcoming breakage.
- `(?s).*google.generativeai.*:FutureWarning` — Google SDK self-deprecation warning swallowed globally.
- `coroutine 'AsyncClient.aclose' was never awaited:RuntimeWarning` — leaked async client coroutines from Cohere/Mistral SDKs silenced; potential resource leak masked.
- `InMemoryExecutionTokenVerifier:UserWarning` — production-safety warning silenced for tests that exercise this path.
- `GuardConfig:UserWarning` — `PRAMANIX_ENV=production` advisory silenced for tests that set it.
- `urllib3.*doesn't match a supported version` — version mismatch swallowed.

~~**`src/pramanix/translator/gemini.py` lines 41–42**~~ — **✅ FIXED** — `filterwarnings` calls moved inside `GeminiTranslator.__init__` and scoped with `with _warnings_mod.catch_warnings():`. No module-level filterwarnings remain; the process-global warning filter is no longer polluted.

---

### 3.2 ✅ FIXED: Type-Checking Bypasses (`# type: ignore`)

**Status**: **ALL ELIMINATED** — commit `1a0671c` (2026-05-21). `mypy --ignore-missing-imports` exits 0. `ruff check --select=PGH003` exits 0. `grep -rn '# type: ignore' src/pramanix/` returns 0 matches. 35 files changed, 317 insertions / 241 deletions. Every suppression replaced with a real structural fix.

**Structural fixes applied per suppression class:**

- **`no-redef` on fallback class definitions** (`k8s/webhook.py`, `integrations/langchain.py`, `integrations/llamaindex.py`, `integrations/crewai.py`, `integrations/dspy.py`, `integrations/fastapi.py`, `interceptors/grpc.py`, `interceptors/kafka.py`): All fallback stub-class definitions inside `except ImportError:` blocks converted to `if TYPE_CHECKING:` pattern. mypy only sees the real import; the `else:` branch (with `object` fallback or structurally-typed stub) is invisible to static analysis. Zero runtime behaviour change.

- **`misc` on dynamic base class inheritance** (all integration classes above): Removed because `if TYPE_CHECKING:` branch now provides the concrete real base type; mypy can resolve the inheritance chain without suppression.

- **`operator` on `ExpressionNode` DSL operators** (`compiler.py` lines 1444–1450, `natural_policy/compiler.py` lines 395/397): Replaced with `cast(ConstraintExpr, lhs_node == rhs)` / `cast(ConstraintExpr, left == right)` at each return site. `ConstraintExpr` moved out of `TYPE_CHECKING` block (TCH004) so `cast()` can use it at runtime. The `Any` returned by `__eq__`/`__ne__` now propagates through `cast()` rather than silently through the call chain.

- **`override` on `__eq__`/`__ne__`** (`expressions.py` lines 851/854): Same `cast(ConstraintExpr, ...)` fix. The override contract is maintained; mypy sees the return type as `ConstraintExpr` which is compatible with the `bool` supertype via `cast`.

- **`override,unused-ignore` on `__pow__`/`__rpow__`** (`expressions.py` lines 559/587): Removed by correcting the parent class return-type annotation; the override is no longer detected as a contract violation.

- **`method-assign, assignment` on `policy.py`** (`policy.py` lines 230, 293, 549): `cls.invariants = _merged` converted to `cast(Any, cls).invariants = _merged` (bypasses attribute-assignment check without suppression); `@classmethod` `[misc]` resolved by correcting the descriptor protocol.

- **`arg-type` and `return-value`** (`compiler.py`, `natural_policy/compiler.py`, `crypto.py`): Explicit `cast()` or narrowed type at each call site; no suppression needed.

- **`no-redef` on lazy-load `_m` rebinding** (`integrations/__init__.py` 8× sites): Refactored to use explicit typed `dict[str, ModuleType]` mapping; no successive rebinding of a single variable.

- **`import-not-found` / `import-untyped`** (`nlp/validators.py`, `translator/injection_filter.py`, `execution_token.py`, translators): All optional third-party imports guarded by `if TYPE_CHECKING:` pattern or annotated with `py.typed` stub markers; `--ignore-missing-imports` flag absorbs remaining third-party packages that have no stubs without requiring per-line suppressions.

- **`attr-defined` on Mistral v1 SDK** (`translator/mistral.py`): `cast(Any, _mistralai_pkg).Mistral` — standard pattern to bypass `[attr-defined]` on a dynamically-typed module object.

- **`type-arg` on gRPC interceptor** (`interceptors/grpc.py`): `grpc.ServerInterceptor[Any, Any]` in `TYPE_CHECKING` branch — provides the required generic parameters.

- **`override` on `model_json_schema`** (`natural_policy/compiler.py`): Added missing `union_format: Literal["any_of", "primitive_type_array"] = "any_of"` keyword-only parameter to match Pydantic v2's exact method signature.

- **`tests/unit/conftest.py` line 32**: ✅ Previously fixed (see §4.1) — `redis_url` fixture rewritten as `Generator[str, None, None]`; suppression removed.

**Additionally fixed during this commit** (Python 3.13 `NameError` — not a `# type: ignore`, but discovered in the same analysis pass):

- **`nlp/validators.py`** and **`translator/injection_filter.py`**: Both files had `if sys.version_info < (3, 12): class SecurityWarning(UserWarning): ...` — an incorrect assumption that `SecurityWarning` is a Python built-in in 3.12+. It is not a built-in in any Python version. On Python 3.13 the class was never defined, causing `NameError` at the `warnings.warn(..., SecurityWarning, ...)` call site in the `re2` import fallback. Fixed by defining `SecurityWarning` unconditionally (no version check). See §4.8 for full details.

**Residual scope**: `tests/unit/conftest.py` line 32 suppression was removed in the §4.1 fix sprint. The remaining `# type: ignore` entries in test files (noted in §1 and §1.2) are pre-existing and tracked separately; they do not appear in `src/pramanix/`.

---

### 3.3 Ignored & Skipped Tests

Every `pytest.skip`, `pytest.mark.skipif`, `pytest.importorskip`, and `pytest.mark.xfail` instance across the test suite.

#### Hard `pytest.skip()` calls (tests that never run in any configuration)
- ~~`tests/unit/test_translator.py` lines 983, 988~~  — **✅ FIXED** — Both VS Code proxy `pytest.skip()` calls and associated `pragma: no cover` removed; `respx` routes now cover `APIStatusError` HTTP responses.

#### `pytest.mark.skipif` conditional skips
- **`tests/unit/conftest.py` line 28** — `requires_docker = pytest.mark.skipif(not _DOCKER_AVAILABLE, reason="Docker not available")` — entire Docker-backed test battery skipped when Docker is absent; 84 tests reported as skipped in the baseline run.

#### `pytest.importorskip` skips (dependencies absent = silent skip)
- **`tests/unit/conftest.py` line 42** — `pytest.importorskip("testcontainers")`
- **`tests/integration/test_zero_trust_identity.py` line 32** — `pytest.importorskip("testcontainers", ...)`
- **`tests/integration/conftest.py`** — each of the 6 container fixtures calls `pytest.importorskip` for its library; any absent package silently drops the entire integration suite.
- **All 37 optional-dependency extras** — each `pytest.importorskip` in tests guarding e.g. `asyncpg`, `confluent_kafka`, `cohere`, `anthropic`, `google-generativeai`, `mistralai`, `hvac`, `boto3`, `azure-keyvault-secrets`, `sentence-transformers`, `detoxify`, `re2`, `redis`, `prometheus_client`, `opentelemetry` etc. results in silent test elision; the CI matrix does not enumerate all combinations.

#### `hypothesis` deadline/health suppression
- **`tests/unit/test_sanitise_properties.py` lines 96, 126, 157, 241, 253, 265, 277** — 7× `suppress_health_check=[HealthCheck.too_slow]` — Hypothesis's "this strategy is too slow" health check suppressed; slow strategies may indicate the code under test has unacceptable latency that is being hidden.
- ~~`tests/unit/test_decision_hash.py` line 120~~  — **✅ FIXED** — `database=None` removed; Hypothesis shrink database re-enabled for reproducible failure investigation.
- ~~All 43 `deadline=None` instances across `tests/property/`~~ — **✅ FIXED** — All `deadline=None` replaced with `deadline=timedelta(seconds=5)` in `test_fintech_primitive_properties.py` and across `tests/property/`; Z3 performance regressions now surface as test failures.

---

## 4. Hidden Architecture Flaws & Technical Debt

### 4.1 ✅ FIXED: `conftest.redis_url()` Return-Type Lie

**File**: `tests/unit/conftest.py` **Line 32** — **FIXED in 2026-05-20 sprint.**

`redis_url` fixture rewritten to return `Generator[str, None, None]`; calls `pytest.skip()` explicitly when Docker is unavailable rather than returning `None`. The `# type: ignore[return]` suppression has been removed. Session-scoped tests that depend on `redis_url` now correctly skip when the container fails to start, rather than receiving a `None` URL.

**Residual risk**: None — fixture now guarantees `str` yield or explicit skip.

### 4.2 Z3 State Leakage and Trust Boundary Violation via Direct Patching

**Files**: `tests/unit/test_circuit_breaker_and_guard_paths.py` lines 1067, 1418–1419; `tests/unit/test_fail_safe_invariant.py` (15 setattr calls); `tests/unit/test_translator_and_interceptor_paths.py` line 1379

Z3 is Pramanix's security kernel — the SMT solver whose `sat`/`unsat`/`unknown` verdict is the authoritative enforcement decision. Patching `pramanix.guard.solve`, `z3.Solver`, or the pipeline helpers (`validate_intent`, `validate_state`, `flatten_model`) breaks the Z3 trust boundary:

1. **Tests that patch `z3.Solver`** never exercise the C-library binding. A regression in Z3 v4.x → v5.x that causes incorrect constraint evaluation would pass these tests.
2. **Tests that patch `pramanix.guard.solve`** bypass the entire transpiler → solver pipeline. These tests prove that the *guard shell* calls *something* on solver failure, but not that the solver pipeline itself is correct.
3. **`solver.py` uses `threading.local()` (`_tl_ctx`)** for per-thread Z3 contexts. `transpiler.py` documents that `ctx=None` falls back to Z3's global context which is "incompatible with the per-call z3.Context() used by solver.py". No test exercises a cross-thread Z3 global context collision; the test suite always runs Z3 in a single-thread-per-test arrangement.

**Risk**: Security-kernel regressions invisible to mock-patched tests; potential TOCTOU on global Z3 context under async workloads.

### 4.3 ✅ FIXED: VS Code Dev Proxy Masking Real HTTP Error Path

**File**: `tests/unit/test_translator.py` **Lines 983, 988** — **FIXED in 2026-05-20 sprint.**

Both `pytest.skip()` calls and their `pragma: no cover` companions removed. `respx` routes now return `APIStatusError`-matching HTTP status codes, covering the error-handling branches in `MistralTranslator` and `CohereTranslator` without requiring a live LLM endpoint.

**Residual risk**: None for these paths — both previously skipped branches now have test coverage.

### 4.4 ✅ FIXED: `sys.modules` Bare Assignment Without `patch.dict` (No Auto-Restore)

**Files**: `tests/unit/test_audit_sink_full_coverage.py` lines 152, 196, 276; `tests/unit/test_coverage_gaps.py` lines 1371, 1390, 1570 — **FIXED in 2026-05-20 sprint.**

All six bare `sys.modules["pkg"] = None` assignments replaced:
- `test_audit_sink_full_coverage.py` lines 152, 196, 276 — converted to `with patch.dict(sys.modules, {...}):` with `try/finally`.
- `test_coverage_gaps.py` lines 1371, 1390 — converted to `with patch.dict(sys.modules, {"anthropic": None}):` and `with patch.dict(sys.modules, {"tenacity": None}):`.
- `test_coverage_gaps.py` line 1570 — converted to `monkeypatch.setitem`.

**Residual risk**: None — all six sites now auto-restore on test failure or `KeyboardInterrupt`.

### 4.5 ✅ FIXED: `InMemoryExecutionTokenVerifier` Exported as Production Symbol

**File**: `src/pramanix/execution_token.py`; `src/pramanix/__init__.py` — **FIXED in 2026-05-20 sprint.**

`InMemoryExecutionTokenVerifier` removed from `pramanix.__init__` and `__all__`. Re-exported only from `pramanix.testing` and `pramanix.execution_token`. `pyproject.toml` warning suppression entry removed. `MIGRATION.md §4.5` documents the change.

**Residual risk**: None — class is no longer a first-class public symbol.

### 4.6 ⚠️ PARTIALLY FIXED: `__eq__`/`__ne__` Return Type Contract Broken in `expressions.py`

**File**: `src/pramanix/expressions.py` lines 851, 854 — **Partially fixed in 2026-05-20 sprint.**

`ExpressionNode.__eq__` intentionally returns `ConstraintExpr` (documented DSL behaviour). Two fixes applied:

1. **`__bool__` trap** — `ExpressionNode.__bool__` now raises `TypeError("ExpressionNode cannot be used as a boolean — did you mean E(field) == value?")`. A developer writing `if field == value:` inside `invariants()` gets an immediate, clear error rather than silent truthy evaluation.
2. **`__hash__ = object.__hash__`** — Added at line 495 so nodes remain hashable by identity; can be used in sets and dicts without `TypeError`.

**Gap vs. blueprint item 9**: Blueprint specified `__hash__ = None` (unhashable). Actual implementation chose identity-based hashing instead — nodes are usable in sets, which is a deliberate engineering trade-off. `TestExpressionNodeHash` and `TestExpressionNodeBoolTrap` test classes confirm both behaviours.

**Residual risk**: A node accidentally placed in a set will not crash — it will be deduplicated by identity, which may silently allow duplicate constraint nodes in collections. The `__bool__` trap is the primary safety net for policy misuse.

### 4.7 ✅ FIXED: Global Warning Suppression in `translator/gemini.py` at Import Time

**File**: `src/pramanix/translator/gemini.py` — **FIXED in 2026-05-20 sprint.**

Both `_w.filterwarnings("ignore", ...)` calls moved inside `GeminiTranslator.__init__` and scoped with `with _warnings_mod.catch_warnings():`. No module-level `filterwarnings` calls remain. The process-global warning filter is no longer modified on import.

**Residual risk**: None — warning suppression is now instance-scoped and reverts on context-manager exit.

### 4.8 ⚠️ PARTIALLY FIXED: re2/stdlib re Silent Fallback Creates Security Inconsistency

**Files**: `src/pramanix/nlp/validators.py`; `src/pramanix/translator/injection_filter.py` — **Partially fixed in 2026-05-20 sprint; Python 3.13 NameError fully fixed in 2026-05-21 sprint (commit `1a0671c`).**

#### Fix 1 — SecurityWarning emission on re2 fallback (2026-05-20)

`SecurityWarning` is emitted at both fallback sites when `re2` is absent:

```python
warnings.warn("re2 not available; falling back to stdlib re (ReDoS risk)", SecurityWarning, stacklevel=2)
```

Operators can detect the security-posture downgrade via warning filters or log capture.

#### Fix 2 — Python 3.13 `NameError` on `SecurityWarning` (2026-05-21) ✅ FULLY FIXED

**Root cause**: Both files previously defined `SecurityWarning` conditionally:

```python
if sys.version_info < (3, 12):
    class SecurityWarning(UserWarning): ...
```

This rests on the false assumption that `SecurityWarning` is a Python built-in class in 3.12+. It is **not a built-in in any Python version**. On Python 3.13, the `if` branch was never taken, so `SecurityWarning` was never defined. The subsequent `warnings.warn(..., SecurityWarning, ...)` call in the `re2` import fallback raised `NameError: name 'SecurityWarning' is not defined`, propagating through `75+` test cases as `E NameError` failures.

**Fix**: Both files now define `SecurityWarning` unconditionally at module level:

```python
class SecurityWarning(UserWarning):
    """Security advisory (not a Python built-in — defined here for all versions)."""
```

The `import sys` import was removed as it became unused. Verified: `NameError` is gone on Python 3.13; `warnings.warn(..., SecurityWarning, ...)` works correctly in both files.

**Remaining gap**: The fallback to `stdlib re` still occurs — the system does not refuse to start or hard-fail when `re2` is absent. No test verifies that the fallback injection-filter patterns are ReDoS-free under `re`. The `SecurityWarning` is the only runtime signal.

**Risk**: ReDoS attack vector on injection filtering when `re2` is absent; `SecurityWarning` is emitted but the vulnerable path is still taken.

### 4.9 Circuit Breaker asyncio.Lock Created Fresh on Every Property Access — **[FIXED]**

**File**: `src/pramanix/circuit_breaker.py` lines 180–182, 540–542, 1052–1054
**Status**: **FIXED** — Applied in a prior hardening session. All three `@property def _lock(self) -> asyncio.Lock: return asyncio.Lock()` methods were changed to `@functools.cached_property`, which creates the lock once and caches it on the instance. Verified by reading current source.

*Original bug*: Each call to `self._lock` created a **new** `asyncio.Lock` object. Two coroutines entering `async with self._lock:` simultaneously each received their own lock and proceeded concurrently — providing zero mutual exclusion. The docstring claimed "always binds to the current event loop" but the real behaviour was "provides no locking at all". State (open/closed/half-open) could be simultaneously mutated by multiple coroutines.

*Residual gap*: A concurrent-mutation integration test does not yet exist. The fix is correct, but no test verifies linearizability of state transitions under concurrent async load. See §5 item 30 for the action item.

### 4.10 Broad `except Exception: pass` Swallowing in Production Source

Silent `except Exception: pass` or functionally-equivalent silently-absorbing patterns. All entries below are **verified by direct source inspection**; false positives from the prior version have been removed (see "Entries removed" subsection).

#### Confirmed silent swallows with security or operational consequence

- ✅ **FIXED** — **`src/pramanix/guard.py` line 186** — `_emit_translator_metric()`: `except Exception: pass` replaced with `except Exception as _metric_exc: _log.warning("prometheus metric emit failed ...", type(_metric_exc).__name__, exc_info=_metric_exc)`. Prometheus counter failures now surface in structured logs.

- ✅ **FIXED** — **`src/pramanix/guard.py` line 144** — `_is_picklable()`: unexpected exceptions (`MemoryError`, `RecursionError`, `SystemError`) now emit `_log.warning("_is_picklable: unexpected exception type %s ...", type(_exc).__name__, exc_info=_exc)` before returning `False`. Legitimate pickling failures vs infrastructure failures are now distinguishable in logs.

- **`src/pramanix/circuit_breaker.py` line 692** — bare `except Exception: pass` in a circuit-breaker cleanup path; no log, no metric, no re-raise. Consequence: cleanup errors are fully invisible to operators and monitoring. ❌ OPEN.

- ✅ **FIXED** — **`src/pramanix/circuit_breaker.py`** — All 3 Redis state-replication failure sites in `DistributedCircuitBreaker.verify_async()` now call `_inc_sync_failure_counter()` + `log.error("circuit-breaker state sync to Redis failed — possible split-brain", exc_info=True)`. The `pramanix_circuit_breaker_state_sync_failure_total` counter is incremented; Prometheus alerts can now fire on split-brain conditions.

- ✅ **FIXED** — **`src/pramanix/fast_path.py` lines 88, 106, 141, 168** — All 4 `except Exception: return None` paths now call `_inc_parse_failure(_rule_name)` (incrementing `pramanix_fast_path_parse_failure_total`) and emit `_log.warning("fast_path.X: could not parse %r as Decimal ...", val, ...)` before returning `None`. Full analysis in §4.13 (still fail-open by design).

- **`src/pramanix/worker.py` lines 331, 441** — 2× `except Exception: pass` around `_WORKER_WATCHDOG_ERROR_COUNTER.inc()` and `_WORKER_WARMUP_FAILURE_COUNTER.inc()`. Prometheus errors in the worker subsystem remain silently absorbed. ❌ OPEN.

- **`src/pramanix/worker.py` lines 721, 725** — 2× `except Exception: pass` inside `WorkerPool.__del__()` GC finalizer. Architecturally acceptable (event loop may be torn down), but the dual-swallow means even the attempt to log is swallowed. ❌ OPEN (acceptable GC-path design choice).

- ✅ **FIXED** — **`src/pramanix/crypto.py` line 98** — `_inc_signing_failure()`: `except Exception: pass` replaced with `except Exception as _exc: _log.warning("pramanix.audit.signer: unexpected error incrementing pramanix_signing_failures_total counter ...", _exc, exc_info=True)`. Counter failures are now visible in structured logs.

- ✅ **FIXED** — **`src/pramanix/crypto.py`** — All 6× `except Exception: return False` in `.verify()` methods (`PramanixSigner`, `RS256Verifier`, `ES256Verifier`) now distinguish `InvalidSignature`/`ValueError` (return `False`) from infrastructure exceptions (raise `VerificationError`). Callers can distinguish "wrong signature" from "verifier is broken".

- ✅ **FIXED** — **`src/pramanix/audit/signer.py`** — `DecisionSigner.__init__` now raises `ConfigurationError` immediately when the signing key is absent or shorter than 32 characters. Silent `None`-key construction is no longer possible. `DecisionSigner.optional()` provides the null-safe path. See §4.x (originally §audit/signer.py entry).

- ✅ **FIXED** — **`src/pramanix/guard_pipeline.py`** — All 8× `except Exception as _exc: _log.debug(...)` in `_semantic_post_consensus_check()` replaced with `except Exception as _exc: _log.warning("safety check received non-numeric value — applying safe-default DENY", exc_info=_exc); raise SemanticPolicyViolation(...)`. Non-numeric state now results in a hard DENY. Full analysis in §4.12.

- **`src/pramanix/interceptors/kafka.py` line 120** — `except Exception: pass` in Kafka consumer GC finalizer. Acceptable GC-path location. ❌ OPEN (acceptable design).

- **`src/pramanix/integrations/llamaindex.py` line 143** — `except Exception: pass` in `PramanixFunctionTool._shutdown_executor()` GC path. Acceptable. ❌ OPEN (acceptable design).

- ✅ **FIXED** — **`src/pramanix/execution_token.py` line 905** — `RedisExecutionTokenVerifier.count()`: `except Exception: return 0` now preceded by `_etlog.getLogger(__name__).warning("execution_token.RedisExecutionTokenVerifier.consumed_count(): Redis SCAN failed — returning 0 (fail-open for monitoring) ...")`. Quota-unreliable state is now visible to operators.

- ✅ **FIXED** — **`src/pramanix/nlp/validators.py`** — `_try_detoxify_scorer()` and `_try_sentence_transformer()`: both now emit `_log.warning("NLP safety model load failed (%s): %s — toxicity/semantic scoring disabled", ...)` before `return None`. `pramanix_nlp_model_available{model}` gauge set to 0. Full analysis in §4.14.

- **`src/pramanix/guard_config.py` line 246** — bare `pass` class body in an empty override guard subclass. Structural dead code; no runtime consequence. ❌ OPEN (cosmetic).

- 🆕 **NEW FINDING** — **`src/pramanix/guard.py` line 250** — `_emit_field_seen_metric()`: `except Exception: pass` silently swallows all Prometheus errors when incrementing the `pramanix_field_seen_total` field-coverage counter. If `prometheus_client` raises (label-cardinality explosion, registry collision), the field-coverage metric silently stops incrementing with no log entry. This is a **separate** gap from the `_emit_translator_metric()` fix at line 186. Consequence: field-coverage dashboards show 0 for all fields without any operator alert. See §4.16 and §5 item 36.

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

### 4.12 ✅ FIXED: `guard_pipeline.py` — Safety Check Bypass via Non-Numeric State Values (8 Absorption Points)

**File**: `src/pramanix/guard_pipeline.py` — **FIXED in 2026-05-20 sprint.**

All 8 `except Exception as _exc: _log.debug(...)` branches in `_semantic_post_consensus_check()` replaced with the fail-closed pattern:

```python
except SemanticPolicyViolation:
    raise
except Exception as _exc:
    _log.warning(
        "guard_pipeline: %s safety check received non-numeric value %r "
        "— applying safe-default DENY (fail-closed)",
        check_name, raw_value, exc_info=_exc,
    )
    raise SemanticPolicyViolation(
        f"{check_name} value {raw_value!r} is not a valid number; "
        "safe-default deny applied (state integrity cannot be confirmed)."
    ) from _exc
```

All 8 domain checks (financial balance, daily-transfer-limit, healthcare-dosage, infra-replica/CPU/memory) now emit WARNING and raise `SemanticPolicyViolation` on non-numeric state — rather than silently passing the request.

**Residual gap**: No integration test that exercises the non-numeric state injection path via a full `Guard.verify()` call. The unit-level tests confirm the exception propagation, but end-to-end injection tests (§5 item 22) are still open.

---

### 4.13 ⚠️ PARTIALLY FIXED: `fast_path.py` — Fail-Open-to-Z3 on Malformed Numeric Input

**File**: `src/pramanix/fast_path.py`
**Function**: `negative_amount()`, `zero_or_negative_balance()`, `exceeds_hard_cap()`, `amount_exceeds_balance()`
**Lines**: 88, 106, 141, 168 — **Partially fixed in 2026-05-20 sprint.**

**Fixed**: All 4 `except Exception: return None` paths now:
1. Call `_inc_parse_failure(_rule_name)` — increments `pramanix_fast_path_parse_failure_total{rule=...}` Prometheus counter.
2. Emit `_log.warning("fast_path.X: could not parse %r as Decimal — passing through to Z3/semantic check (%s: %s)", val, type(_exc).__name__, _exc)`.

Operators can now alert on a non-zero `pramanix_fast_path_parse_failure_total` rate and distinguish parse-failure Z3 fall-through from normal Z3 fall-through.

**Still open by design**: The function still returns `None` (fail-open to Z3) rather than raising a block decision on malformed input. This is the documented design intent — Z3 is the authoritative enforcement layer. The fast-path is an optional performance optimisation, not a security gate. The remaining risk:

- Z3 receives unvalidated `intent_value` strings; Z3's coercion is well-defined but could produce unexpected constraint results for extremely large numerics.
- No input sanitisation occurs at `Guard.verify()` boundary before fast-path or Z3 evaluation.

**Risk**: Reduced (observable via counter + WARNING) but not eliminated; fast-path bypassed for malformed input; Z3 is the sole remaining guard.

---

### 4.14 ✅ FIXED: `nlp/validators.py` — ML Safety Model Load Failures Invisible in Production

**File**: `src/pramanix/nlp/validators.py` — **FIXED in 2026-05-20 sprint.**

Both `_try_detoxify_scorer()` and `_try_sentence_transformer()` now emit a structured warning on failure:

```python
except Exception as _e:
    logging.getLogger(__name__).warning(
        "NLP safety model load failed (%s): %s — toxicity/semantic scoring disabled",
        type(_e).__name__, _e,
    )
    return None
```

Additionally, a `pramanix_nlp_model_available` Prometheus gauge is set to `1` on successful load and `0` on failure for both `model="detoxify"` and `model="sentence_transformer"` labels. Operators can alert on `pramanix_nlp_model_available == 0` before the first unsafe request reaches the system.

**Residual risk**: NLP validators remain beta-grade; the system degrades gracefully (with observable WARNING + gauge=0) rather than blocking requests when models are absent — this is by design for the optional NLP safety layer.

---

### 4.15 ⚠️ PARTIALLY FIXED: `hypothesis.assume()` Over-Exclusion Creating Coverage Blind Spots

**Files**: `tests/unit/test_sanitise_properties.py`; `tests/property/test_fintech_primitive_properties.py`

#### ✅ FIXED — `tests/property/test_fintech_primitive_properties.py`

- `assume(peak > Decimal("0"))` removed. `TestMaxDrawdownEdgeCases` class added with `test_peak_zero_with_positive_current_is_sat` deterministic test covering the `peak == Decimal("0")` case (division-by-zero guard confirmed).
- `assume(peak >= current)` kept with a justifying comment explaining why inverted-peak is an invalid domain input; the guard is now documented rather than implicit.
- `deadline=None` → `deadline=timedelta(seconds=5)` applied across all property tests (see §3.3).

#### ❌ OPEN — `tests/unit/test_sanitise_properties.py`

- **Line 139** — `assume(len(s) >= 10)` and `assume(len(s) <= 512)` remain. Sanitizer behaviour on length 0–9 and >512 strings is not property-tested.
- **Lines 241, 245, 257, 271, 281** — 5× `assume(len(s) > 0)` and `assume(s.strip())` remain. Empty and whitespace-only inputs are not explored by Hypothesis.
- **Lines 253, 265, 277** — `assume(not s.startswith(...))` filters on injection prefixes remain. Property tests never exercise the "injection-prefix string is always sanitised" property.
- **7× `suppress_health_check=[HealthCheck.too_slow]`** remain with no benchmark justification comment.

**Risk**: Sanitizer's most security-relevant inputs (empty, single-char, injection-prefix, overlong) are not property-tested. Regression on empty/whitespace handling would not be caught by Hypothesis.

---

### 4.16 🆕 NEW FINDING: `guard.py` — `_emit_field_seen_metric()` Silent Swallow

**File**: `src/pramanix/guard.py` **Line ~250** — **Identified in 2026-05-20 audit; not in original flaws.md.**

`_emit_field_seen_metric()` contains a separate `except Exception: pass` block for the `pramanix_field_seen_total` field-coverage counter:

```python
def _emit_field_seen_metric(field_name: str) -> None:
    try:
        _FIELD_SEEN_COUNTER.labels(field=field_name).inc()
    except Exception:
        pass
```

This is **distinct from the already-fixed `_emit_translator_metric()` at line 186**. If `prometheus_client` raises during field-coverage counter increment (label-cardinality explosion, registry collision after a hot-reload, threading race), the failure is silently discarded with no log entry at any level.

**Consequence**: `pramanix_field_seen_total` silently stops counting when Prometheus errors occur; field-coverage dashboards show 0 for all fields (or stale counts) without any operator alert. Field-coverage analysis becomes unreliable without any signal that the metric subsystem has failed.

**Action**: Apply the same fix as `_emit_translator_metric()` — replace `except Exception: pass` with `except Exception as _exc: _log.warning("pramanix field_seen metric emit failed: %s", type(_exc).__name__, exc_info=_exc)`. See §5 item 36.

---

## 5. Elimination Blueprint

One concrete action per flaw, prioritised highest-risk first.

1. ✅ **FIXED** — **Fix `conftest.redis_url()` return-type lie** — Fixture rewritten to return `Generator[str, None, None]`; calls `pytest.skip()` explicitly when Docker unavailable; `# type: ignore[return]` removed. See §4.1.

2. **Replace Z3/solver patches with observable test doubles** — Extract a `SolverProtocol` interface from `solver.py`; inject it via dependency injection into `Guard`; test fail-safe paths against a `FailingSolverStub` that implements the protocol — no `patch("z3.Solver")` or `patch("pramanix.guard.solve")` needed. ❌ OPEN.

3. ✅ **FIXED** — **Fix circuit-breaker asyncio.Lock property** — All three `@property def _lock(self) -> asyncio.Lock: return asyncio.Lock()` changed to `@functools.cached_property`; lock is created once and cached per instance. See §4.9. Concurrent-mutation test still open (item 30).

4. ✅ **FIXED** — **Wrap bare `sys.modules` assignments in `patch.dict`** — All 6 bare assignments in `test_audit_sink_full_coverage.py` and `test_coverage_gaps.py` replaced. See §4.4.

5. ✅ **FIXED** — **Remove VS Code proxy skip + pragma from `test_translator.py`** — Both `pytest.skip()` calls and `pragma: no cover` removed; `respx` routes cover `APIStatusError` paths. See §4.3.

6. ✅ **FIXED** — **Emit `SecurityWarning` on re2 fallback** — `SecurityWarning` emitted in `nlp/validators.py` and `translator/injection_filter.py` when falling back to stdlib `re`. Tests assert the warning is emitted. See §4.8. Fallback to `re` still occurs (partial fix).
   **Additionally fixed (2026-05-21)**: Python 3.13 `NameError: name 'SecurityWarning' is not defined` — the class was conditionally defined (`if sys.version_info < (3, 12)`) which skipped definition on Python 3.13. Both files now define `SecurityWarning` unconditionally; `import sys` removed. See §4.8 Fix 2.

7. ✅ **FIXED** — **Move global `filterwarnings` out of `translator/gemini.py` module scope** — Both `_w.filterwarnings(...)` calls moved inside `GeminiTranslator.__init__` and scoped with `with _warnings_mod.catch_warnings():`. See §4.7.

8. ✅ **FIXED** — **Demote `InMemoryExecutionTokenVerifier` from the public API** — Removed from `pramanix.__init__` and `__all__`; re-exported from `pramanix.testing`; `pyproject.toml` suppression removed; `MIGRATION.md §4.5` documents the change. See §4.5.

9. ⚠️ **PARTIAL** — **Add `__hash__` and bool-trap for `ExpressionNode`** — `__bool__` raises `TypeError` (fully fixed); `__hash__ = object.__hash__` chosen over `__hash__ = None` (blueprint specified unhashable — intentional deviation; identity hashing preferred). `TestExpressionNodeHash` and `TestExpressionNodeBoolTrap` tests added. See §4.6.

10. ✅ **FIXED** — **Eliminate `except Exception: pass` in `audit/signer.py`** — `_inc_signing_failure()` `except Exception: pass` replaced with `_log.warning(..., exc_info=True)`; test `test_unexpected_exception_from_inc_logs_warning` asserts WARNING is emitted.

11. **Test asyncpg and JWT ImportError paths** — Remove `# pragma: no cover` from `execution_token.py` lines 92–93, 966 and `mesh/authenticator.py` lines 885, 906, 922; inject missing-package conditions via `monkeypatch.setitem(sys.modules, "asyncpg", None)`. ❌ OPEN.

12. **Add Protocol stubs for integration stub base classes** — In `integrations/llamaindex.py` and `integrations/langchain.py`: replace bare stub classes with typed Protocol classes that raise `RuntimeError("Install X to use this integration")` on instantiation. ❌ OPEN.

13. ✅ **FIXED** — **Add `__bool__` trap to `ExpressionNode`** — `ExpressionNode.__bool__` now raises `TypeError("ExpressionNode cannot be used as a boolean ...")`. Silent policy mis-evaluation via `if field == value:` in invariants body is no longer possible. See §4.6 and item 9.

14. **Add `suppress_health_check` justification comments** — In `test_sanitise_properties.py` lines 96, 126, 157, 241, 253, 265, 277: each `suppress_health_check=[HealthCheck.too_slow]` needs a benchmark comment showing P99 latency; otherwise remove the suppression and fix the slow strategy. ❌ OPEN.

15. ✅ **FIXED** — **Add Hypothesis deadline budget to property tests** — All `deadline=None` replaced with `deadline=timedelta(seconds=5)` across `tests/property/`; Z3 performance regressions will now surface as test failures. See §3.3 and §4.15.

16. ✅ **FIXED** — **Annotate `noqa: F401` side-effect imports** — `translator/injection_scorer.py` and `translator/gemini.py` side-effect imports annotated with explicit intent comments. All four `type: ignore[operator]` in `compiler.py` documented with DSL design-intent block comment.

17. **Add injectable clock abstraction for `execution_token.py`** — Introduce `_clock: Callable[[], float]` parameter in `ExecutionToken`, `RedisExecutionTokenVerifier`, and `PostgresExecutionTokenVerifier`; default to `time.time`. Nine direct `time.time()` call sites remain without injection mechanism. ❌ OPEN.

18. ✅ **FIXED** — **Remove `database=None` from `test_decision_hash.py`** — Hypothesis shrink database re-enabled for reproducible failure investigation. See §3.3.

19. ✅ **FIXED** — **Wrap `importlib.reload` in `test_audit_sink_full_coverage.py`** — `importlib.reload(pramanix.decision)` block wrapped in `try/finally` with parent-package attribute restoration. See §2.3.

20. ✅ **FIXED** — **Audit `type: ignore[operator]` in `compiler.py`** — All four suppression sites (lines 1444, 1446, 1448, 1450) now have a block comment documenting the ExpressionNode DSL design intent; operators are explicit about the intentional departure from the default Python operator return type.

21. ✅ **FIXED** — **Raise `SemanticPolicyViolation` on non-numeric state values in `guard_pipeline.py`** — All 8× `except Exception: _log.debug(...)` replaced with `_log.warning(...); raise SemanticPolicyViolation(...)`. Safe-default DENY on non-numeric state. See §4.12.

22. **Add integration tests for non-numeric state injection in `guard_pipeline.py`** — Parametrised test covering `balance="CORRUPTED"`, `balance=None`, `balance={}`, `balance="NaN"`, `dosage="MAX"`, `replica_count="unlimited"` — each must result in `SemanticPolicyViolation` via a full `Guard.verify()` call (not mocked). ❌ OPEN.

23. ✅ **FIXED** — **Add WARNING log to `_emit_translator_metric()` failure path** — `guard.py:186`: `except Exception: pass` → `except Exception as _metric_exc: _log.warning(...)`. See §4.10.

24. ✅ **FIXED** — **Add WARNING log to `_is_picklable()` for non-pickling exceptions** — `guard.py:144`: unexpected exception types now emit `_log.warning(...)` before returning `False`. See §4.10.

25. ✅ **FIXED** — **Raise `ConfigurationError` at `DecisionSigner.__init__`** — Key-absent and key-too-short paths raise `ConfigurationError` immediately; `DecisionSigner.optional()` is the null-safe path. `MIGRATION.md §4.5` documents the change. See §4.10.

26. ✅ **FIXED** — **Add WARNING to `_try_detoxify_scorer()` and `_try_sentence_transformer()`** — Both failure paths now emit `_log.warning(...)` before `return None`. See §4.14.

27. ✅ **FIXED** — **Add `pramanix_nlp_model_available` gauge** — `pramanix_nlp_model_available{model="detoxify"/"sentence_transformer"}` gauge set to 0 or 1 at module import time. Operators can alert on gauge=0. See §4.14.

28. ✅ **FIXED** — **Add `pramanix_circuit_breaker_state_sync_failure_total` counter** — All 3 Redis sync failure sites in `DistributedCircuitBreaker.verify_async()` now call `_inc_sync_failure_counter()` and `log.error(...)`. Split-brain events are now observable. See §4.10.

29. ✅ **FIXED** — **Raise `VerificationError` in crypto verifiers for infrastructure failures** — All 6× `except Exception: return False` in `.verify()` methods now distinguish `InvalidSignature`/`ValueError` (return `False`) from other exceptions (raise `VerificationError`). See §4.10.

30. **Add concurrent-mutation integration test for circuit-breaker `_lock`** — Spawn 200 concurrent coroutines entering `async with cb._lock:` simultaneously; assert state-transition counter increments are linearizable. Validates §4.9 `@functools.cached_property` fix under concurrency. ❌ OPEN.

31. ✅ **FIXED** — **Log `count()` Redis failure at WARNING level** — `execution_token.py` line 905: WARNING emitted before `return 0`; fail-open decision now visible to operators. See §4.10.

32. **Close `hypothesis.assume()` exclusions in `test_sanitise_properties.py`** — Remove `assume(len(s) >= 10)`, `assume(len(s) <= 512)`, `assume(len(s) > 0)`, and `assume(s.strip())` from 7 sites; add explicit edge-case tests for empty, single-char, injection-prefix, boundary-length, and whitespace inputs. ❌ OPEN.

33. ✅ **FIXED** — **Add explicit division-by-zero test for `maximum_drawdown`** — `TestMaxDrawdownEdgeCases.test_peak_zero_with_positive_current_is_sat` added; `assume(peak > Decimal("0"))` removed. See §4.15.

34. ✅ **FIXED** — **Test `_try_detoxify_scorer()` and `_try_sentence_transformer()` failure paths** — `test_nlp_validators_main.py` added; tests inject `sys.modules["detoxify"] = None` and `sys.modules["sentence_transformers"] = None`; assert `None` return, WARNING log, and gauge=0. Not guarded by `pytest.importorskip`.

35. ✅ **FIXED** — **Add property test for `_semantic_field_equal()` boundary numeric strings** — `TestSemanticFieldEqualBoundaryStrings` (19 tests) and `TestSemanticFieldEqualProperties` (3 Hypothesis tests) added to `tests/unit/test_consensus_semantic.py`. Covers NaN, ±inf, 1e999, Arabic-Indic digits, ½, underscore syntax, `str(None)`. All 41 tests pass.

36. **Add WARNING log to `_emit_field_seen_metric()` failure path in `guard.py`** — Line ~250: replace `except Exception: pass` with `except Exception as _exc: _log.warning("pramanix field_seen metric emit failed: %s", type(_exc).__name__, exc_info=_exc)`. Matches the fix applied to `_emit_translator_metric()` at line 186. See §4.16. ❌ OPEN.

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
| **Correctness** | 4,494 passed / 0 failed / 165 skipped (4,659 collected, 2026-05-21 sprint); 0 `# type: ignore` in `src/pramanix/`; mypy exit 0; ruff exit 0; Hypothesis property tests; `pramanix_fast_path_parse_failure_total` counter + WARNING on parse failure FIXED | ✅ | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | Pramanix leads for core decision correctness. **FIXED (2026-05-21)**: all `# type: ignore` suppressions eliminated (35 files, structural fixes only — `if TYPE_CHECKING:`, `cast()`, corrected signatures); Python 3.13 `NameError` on `SecurityWarning` eliminated; warmup test bytecode-cache issue resolved. Remaining gap: fast_path still returns `None` (fail-open) rather than raising; no input sanitisation at `Guard.verify()` boundary | §3.2 (closed); §5 items 21–22, 35 (closed); §4.13 (open) | High |
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

