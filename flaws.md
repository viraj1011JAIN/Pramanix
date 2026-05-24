# Pramanix — Deep-Penetration Technical Audit

**Scope**: All source under `src/pramanix/` and `tests/`. Live codebase as of the current checkout.
**Purpose**: Exhaustive enumeration of every mock, stub, fake, pragma, suppression, and hidden flaw that remains open or is only partially addressed.
**Cleared debt** (do NOT count): `tests/helpers/real_protocols.py` (1,900-line duck-typed helper library; real implementations, zero MagicMock), `pytest.importorskip` for genuinely optional extras, `monkeypatch.setenv/delenv` for environment isolation, `respx` HTTP-level intercepts (deterministic network simulation, not MagicMock), testcontainers containers that back real protocol tests, `hypothesis.assume()` used for domain-constraint filtering in property tests.

---

## 1. Mocking & Stubbing Layer

### 1.1 Standard Mocks & Stubs (unittest.mock, patch)

Every `unittest.mock.patch` call that replaces a real collaborator with a scripted impostor.

#### `tests/unit/test_circuit_breaker_and_guard_paths.py`
- **Line 1067** — `patch("pramanix.guard.solve", side_effect=RuntimeError(...))` — replaces Z3 solve at the guard module boundary; test bypasses the solver entirely.
- **Lines 1418–1419** — `patch("z3.Solver", side_effect=RuntimeError("z3 down"))` — replaces the Z3 C-library binding with a scripted failure; no Z3 constraint resolution occurs.

#### `tests/adversarial/test_fail_safe_invariant.py`
- **15+ `monkeypatch.setattr` calls** replacing `pramanix.guard.validate_intent`, `pramanix.guard.validate_state`, `pramanix.guard.flatten_model`, `pramanix.guard.solve` — all four internal Z3 pipeline stages individually swapped; real constraint solving never runs.

#### `tests/unit/test_consensus_robustness.py`
- **Line 92** — `gem_mod.GeminiTranslator = _RecordingGeminiTranslator` — module-level class replacement; all GeminiTranslator instances after this line are recording fakes.
- **Line 114** — Same pattern for a second GeminiTranslator replacement in a different test method.

#### `tests/unit/test_translator_and_interceptor_paths.py`
- **Lines 57–83** — Triple-patch block: `patch("sys.platform", "win32")`, `patch("glob.glob", return_value=[...])`, `patch("ctypes.CDLL", return_value=MagicMock())` — OS, filesystem, and native-library environment all simultaneously faked.
- **Lines 441, 555, 578** — Additional isolated platform/glob patches.
- **Line 1379** — `patch("z3.Solver", side_effect=RuntimeError("z3 unavailable"))` — second Z3 mock site.
- **Line 1446** — `patch("tempfile.mkstemp", side_effect=OSError("disk full"))` — disk I/O faked.
- **Lines 281–301** — `sys.modules["cohere"] = _FakeCohereModule()` — real Cohere SDK replaced with a locally-defined fake module.

#### `tests/unit/test_platform_check.py`
- **Lines 25, 40, 50–103** — 9 `patch("glob.glob", ...)` calls simulate musl library presence/absence across Linux/Windows/macOS; real filesystem never queried.

#### `tests/unit/test_doctor_cli.py`
- **Line 269** — `patch("redis.from_url", return_value=_PingFailRedisClient())` — Redis always throws on `ping()`.
- **Line 286** — `patch("redis.from_url", return_value=PingOkRedisClient())` — Redis always returns True on `ping()`.

#### `tests/unit/test_hardening.py`
- **Line 268** — `patch("multiprocessing.current_process", return_value=fake_proc)` — process identity faked.

#### `tests/unit/test_coverage_final_push.py`
- **`TestMistralParseNonExtractionError`** — `t._single_call = _fake_single_call  # type: ignore[method-assign]` — direct private-method replacement on a live object; the real `_single_call` never runs. ❌ OPEN.

#### `tests/unit/test_guard_dark_paths.py`
- **Lines 703–721** — `_FakeTranslator` class + `monkeypatch.setattr(_redundant, "create_translator", ...)` + `monkeypatch.setattr(_redundant, "extract_with_consensus", ...)` — translator factory and consensus extraction both replaced; no LLM call, no consensus logic.

#### `tests/unit/test_translator.py`
- **Lines 281–395** — Multiple inline `FakeTranslator`, `FakeA`, `FakeB`, `FakeBadA`, `FakeGoodB` classes replacing real translators for consensus-path tests; all network I/O elided.

#### `tests/unit/test_coverage_gaps.py`
- **Line 964** — `patch.dict(sys.modules, {"orjson": None})` + `importlib.reload(pramanix.decision)` — module reloaded with orjson absent; stateful reload is order-dependent and can leak state to subsequent tests.
- **Lines 999–1218** — boto3, azure-identity, azure-keyvault-secrets, cryptography, redis.exceptions all nulled via `sys.modules[...] = None` in rapid succession — 8+ individual null assignments without isolation guarantees.
- **Lines 1371, 1390** — `sys.modules["anthropic"] = None`, `sys.modules["tenacity"] = None` — bare assignment, not `patch.dict`; no auto-restore on test failure.
- **Line 1570** — `sys.modules["opentelemetry"] = None` — bare assignment.
- **Line 1459** — `_GeminiGenaiModuleStub()` injected into `sys.modules["google.generativeai"]`.

#### `tests/unit/test_extra_coverage.py`
- **Lines 321–358** — `_pai_stub = types.ModuleType("pydantic_ai")` injected via `monkeypatch.setitem(sys.modules, ...)` — pydantic_ai replaced with an empty module.
- **Lines 401–416** — `_lc_stub`, `_lc_tools_stub` built inline and injected into `sys.modules["langchain_core"]` and `sys.modules["langchain_core.tools"]`.

#### `tests/unit/test_integrations_lazy.py`
- **Lines 56–99** — `_stub_module()` helper builds empty `types.ModuleType` objects injected for crewai, dspy, haystack, haystack.components, semantic_kernel, and semantic_kernel.functions — 6 real packages replaced with structurally empty stubs.

#### `tests/unit/test_misc_coverage_gaps.py`
- **Lines 399–410** — `_FakeSecretsClient` injected as `boto3.client()` return value for AWS KMS provider.
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
- **Line 95** — `with patch.dict(sys.modules, {"google.generativeai": None})` — integration test simulates google-generativeai absence.

---

### 1.2 MagicMock & Dynamic Proxies

The `tests/helpers/real_protocols.py` file explicitly replaced all MagicMock usages with real duck-typed implementations (cleared debt). Remaining MagicMock-adjacent usages:

- **`tests/unit/test_coverage_final_push.py` line 1032** — `mock_pydantic` is a `types.ModuleType` with attributes set to `MagicMock()` proxies; Pydantic validation calls vanish silently. ❌ OPEN.
- **`tests/unit/test_circuit_breaker_half_open.py` line 270** — `_FakeBackend` inner class replaces `DistributedCircuitBreaker`'s Redis backend; uses hardcoded state variables, not backed by `real_protocols.py`. ❌ OPEN.

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
- **`src/pramanix/integrations/langchain.py` line 33** — `class BaseTool:  # type: ignore[no-redef]` — fallback stub base class; a consumer without LangChain installed receives a class that raises only on first method call.
- **`src/pramanix/integrations/llamaindex.py` lines 58, 67** — `class ToolMetadata:` and `class ToolOutput:` — two stub classes silently exported; downstream importer gets structurally incorrect objects with no type error at import time.
- **`src/pramanix/integrations/crewai.py` line 82** — `class PramanixCrewAITool(_CrewAIBase):  # type: ignore[misc]` — inherits from either the real crewai base or a fallback stub.
- **`src/pramanix/integrations/dspy.py` line 79** — `class PramanixGuardedModule(_ModuleBase):  # type: ignore[misc]` — same pattern.
- **`src/pramanix/interceptors/grpc.py` line 55** — `class PramanixGrpcInterceptor(_InterceptorBase):  # type: ignore[misc]` — inherits from either real gRPC interceptor base or a fallback.
- **`src/pramanix/translator/mistral.py` line 58** — `from mistralai import Mistral as _Mistral  # type: ignore[no-redef]` — if v1 SDK is absent the outer `_Mistral` fallback is a structurally-incompatible class.

#### Test — inline fake modules
- **`tests/unit/test_translator_and_interceptor_paths.py` line 301** — `sys.modules["cohere"] = _FakeCohereModule()` — real Cohere SDK replaced with a hand-built class hierarchy.
- **`tests/helpers/real_protocols.py` lines 1721–1830** — 9 module-stub classes (`_Boto3ModuleStub`, `_AzureModuleStub`, `_AzureIdentityModuleStub`, `_AzureKVModuleStub`, `_AzureKVSecretsModuleStub`, `_GcpModuleStub`, `_GcpCloudModuleStub`, `_GcpSecretManagerModuleStub`, `_GeminiGenaiModuleStub`) — have real method logic but still replace real cloud SDKs; cannot reproduce real transport errors, authentication challenges, or quota limits. ⚠️ PARTIALLY CLEARED.
- **`tests/helpers/real_protocols.py` line 1821** — `_HvacModuleStub` — HashiCorp Vault client replaced with a stub that stores secrets in a dict.

#### re2 fallback — FULLY FIXED (2026-05-21)

Both files now raise `RuntimeError` at import when `google-re2` is absent — no stdlib `re` fallback occurs:
- **`src/pramanix/nlp/validators.py` lines 43–48** — `RuntimeError: "pramanix.nlp.validators: google-re2 is required but not installed. ReDoS via crafted PII patterns is a critical security risk without it."`
- **`src/pramanix/translator/injection_filter.py` lines 60–65** — identical hard-failure pattern; import refuses to complete.

The ReDoS-via-fallback risk is closed. Residual risk: `google-re2` must be present in the deployment environment (enforced via `pip install 'pramanix[security]'`).

### 2.2 Fake Containers & Ephemeral Environments

- **`tests/unit/conftest.py` lines 42–43** — `pytest.importorskip("testcontainers")` — entire Redis testcontainer fixture is skipped silently if `testcontainers` is not installed.
- **`tests/integration/conftest.py` lines 53–203** — 6 session-scoped testcontainer fixtures (Kafka, Postgres, Redis, Vault, LocalStack, second Redis) — all guarded by `pytest.importorskip`; absent Docker or missing images cause silent skip cascades.
- **`tests/unit/test_circuit_breaker_half_open.py` line 318** — `sys.modules["redis.asyncio"] = None` — async Redis module nulled to test the no-Redis code path; eliminates the dependency entirely.

### 2.3 Deterministic Simulation Overrides

- **`tests/unit/test_platform_check.py` lines 25–103** — 9 `patch("glob.glob", ...)` calls simulate musl library presence/absence; real filesystem never queried.
- **`tests/unit/test_translator_and_interceptor_paths.py` lines 57–83** — `patch("sys.platform", ...)` + `patch("glob.glob")` + `patch("ctypes.CDLL")` — OS identity, filesystem, and native-library loading all replaced simultaneously.
- **`tests/unit/test_hardening.py` line 268** — `patch("multiprocessing.current_process", return_value=fake_proc)` — process identity deterministically faked.
- **`tests/unit/test_translator_and_interceptor_paths.py` line 1446** — `patch("tempfile.mkstemp", side_effect=OSError("disk full"))` — disk-full condition scripted deterministically.
- **`src/pramanix/transpiler.py` line 605** — `z3.IntVal(int(_time.time()), ctx)` embeds wall-clock time into Z3 integer values; no time-injection mechanism exists, so time-dependent constraint results are non-deterministic across test runs.
- **`src/pramanix/execution_token.py` lines 150, 245, 325, 559, 706, 715, 872, 1107, 1125** — 9 separate `time.time()` call sites without abstraction; no injectable clock interface; TTL expiry tests must use real wall-clock delays or `monkeypatch.setattr(time, "time", ...)`.

---

## 3. Pragma Directives, Suppressions & Silence Rules

### 3.1 Inline Pragmas & Linter Disables (`# noqa`)

**`src/pramanix/cli.py` line 1137** — `s.add(z3.Bool("x") == True)  # noqa: E712` — E712 silenced; the `z3.Bool` comparison to Python `True` is intentional but the silence hides the semantic oddity.

**`src/pramanix/cli.py` line 1195** — `Ed25519PrivateKey,  # noqa: F401` — unused import suppressed; key type imported for side-effects only.

**`src/pramanix/k8s/webhook.py` line 103** — `body: dict[str, Any] = _fastapi.Body(...),  # noqa: B008` — B008 silenced; the `Body(...)` sentinel is a FastAPI convention but the suppression hides a linting concern for non-FastAPI consumers.

**`src/pramanix/natural_policy/compiler.py` line 655** — `from pydantic import BaseModel as _BaseModel  # noqa: E402` — late import after module-level try-except blocks; suppression hides a structural design issue.

**`src/pramanix/translator/injection_scorer.py` line 361** — `import sklearn  # noqa: F401` — sklearn imported for its side-effect of registering the backend; suppression hides implicit coupling to sklearn's global state.

**`pyproject.toml` lines 345–365** — `filterwarnings` block silences:
- `pydantic.warnings.PydanticDeprecatedSince20` — Cohere SDK V1 API deprecation swallowed.
- `(?s).*google.generativeai.*:FutureWarning` — Google SDK self-deprecation warning swallowed globally.
- `coroutine 'AsyncClient.aclose' was never awaited:RuntimeWarning` — leaked async client coroutines silenced; potential resource leak masked.
- `InMemoryExecutionTokenVerifier:UserWarning` — production-safety warning silenced for tests.
- `GuardConfig:UserWarning` — `PRAMANIX_ENV=production` advisory silenced for tests.
- `urllib3.*doesn't match a supported version` — version mismatch swallowed.

---

### 3.2 Ignored & Skipped Tests

#### `pytest.mark.skipif` conditional skips
- **`tests/unit/conftest.py` line 28** — `requires_docker = pytest.mark.skipif(not _DOCKER_AVAILABLE, ...)` — entire Docker-backed test battery skipped when Docker is absent; 84 tests reported as skipped in the baseline run.

#### `pytest.importorskip` skips (dependencies absent = silent skip)
- **`tests/unit/conftest.py` line 42** — `pytest.importorskip("testcontainers")`
- **`tests/integration/test_zero_trust_identity.py` line 32** — `pytest.importorskip("testcontainers", ...)`
- **`tests/integration/conftest.py`** — each of the 6 container fixtures calls `pytest.importorskip`; any absent package silently drops the entire integration suite.
- **All 37 optional-dependency extras** — each `pytest.importorskip` guarding `asyncpg`, `confluent_kafka`, `cohere`, `anthropic`, `google-generativeai`, `mistralai`, `hvac`, `boto3`, `azure-keyvault-secrets`, `sentence-transformers`, `detoxify`, `re2`, `redis`, `prometheus_client`, `opentelemetry` etc. results in silent test elision; the CI matrix does not enumerate all combinations.

#### `hypothesis` health suppression (⚠️ PARTIALLY OPEN)
- **`tests/unit/test_sanitise_properties.py` lines 96, 126, 157, 241, 253, 265, 277** — 7× `suppress_health_check=[HealthCheck.too_slow]` remain with no benchmark justification comment; slow strategies may indicate unacceptable latency being hidden.

---

## 4. Hidden Architecture Flaws & Technical Debt

### 4.1 Z3 State Leakage and Trust Boundary Violation via Direct Patching

**Files**: `tests/unit/test_circuit_breaker_and_guard_paths.py` lines 1067, 1418–1419; `tests/unit/test_fail_safe_invariant.py` (15 setattr calls); `tests/unit/test_translator_and_interceptor_paths.py` line 1379

Z3 is Pramanix's security kernel. Patching `pramanix.guard.solve`, `z3.Solver`, or the pipeline helpers (`validate_intent`, `validate_state`, `flatten_model`) breaks the Z3 trust boundary:

1. **Tests that patch `z3.Solver`** never exercise the C-library binding. A regression in Z3 v4.x → v5.x causing incorrect constraint evaluation would pass these tests.
2. **Tests that patch `pramanix.guard.solve`** bypass the entire transpiler → solver pipeline.
3. **`solver.py` uses `threading.local()` (`_tl_ctx`)** for per-thread Z3 contexts. `transpiler.py` documents that `ctx=None` falls back to Z3's global context — no test exercises a cross-thread Z3 global context collision.

**Risk**: Security-kernel regressions invisible to mock-patched tests; potential TOCTOU on global Z3 context under async workloads.

### 4.2 ⚠️ PARTIALLY FIXED: `sys.modules` Injection — Residual (5 Files)

All `patch.dict(sys.modules, ...)` and `monkeypatch.setitem(sys.modules, ...)` calls in the 16 Phase 3 target files were replaced (2026-05-22–23). Five files outside that scope still retain these calls:

- **`test_enterprise_audit_sinks.py:68, 115, 213, 300`** — `confluent_kafka`, `boto3`, `datadog`, fake boto3
- **`test_framework_adapters.py:36, 94, 152, 235, 249`** — `haystack`, `semantic_kernel`, `pydantic_ai`, `dspy`, `starlette`
- **`test_integrations_lazy.py:60–116`** — `crewai`, `dspy`, `haystack`, `semantic_kernel`, `pydantic_ai` stubs
- **`test_distributed_circuit_breaker.py:26–27`** — `redis`, `redis.asyncio`
- **`test_mistral_llamacpp.py:20–23, 80`** — `mistralai`, `llama_cpp`

These require dedicated tox environments before removal. ❌ OPEN.

### 4.3 ⚠️ PARTIALLY FIXED: `__eq__`/`__ne__` Return Type Contract in `expressions.py`

**File**: `src/pramanix/expressions.py` lines 851, 854

`ExpressionNode.__bool__` now raises `TypeError` (developer trap — ✅ done). `__hash__ = object.__hash__` added (identity-based hashing).

**Remaining gap**: Blueprint specified `__hash__ = None` (unhashable). Current implementation chose identity-based hashing — a deliberate deviation. A node accidentally placed in a set will not crash — it will be deduplicated by identity, which may silently allow duplicate constraint nodes in collections. Blueprint and implementation must be reconciled.

### 4.4 ✅ FULLY FIXED: re2 Hard Failure on Missing Dependency

**Files**: `src/pramanix/nlp/validators.py`; `src/pramanix/translator/injection_filter.py`

Both modules now raise `RuntimeError` at import time if `google-re2` is absent — no stdlib `re` fallback path exists. The `SecurityWarning` approach was superseded by a hard import-time failure (fixed 2026-05-21, verified 2026-05-23 via source read at `nlp/validators.py:43–48` and `translator/injection_filter.py:60–65`).

**Status**: ReDoS risk via fallback is fully closed. No open action required. Residual operational requirement: `google-re2` (C-extension) must be present in the deployment image — enforced by `pramanix[security]` extra.

### 4.5 Broad `except Exception: pass` Swallowing in Production Source — Open Items

The following locations remain unfixed (all fully-fixed locations have been removed from this list):

- **`src/pramanix/circuit_breaker.py` line 692** — bare `except Exception: pass` in a circuit-breaker cleanup path; no log, no metric, no re-raise. Cleanup errors are fully invisible to operators. ❌ OPEN.
- **`src/pramanix/worker.py` lines 331, 441** — ✅ FIXED (2026-05-20): both now log at ERROR with `exc_info=True` and increment a Prometheus counter via `contextlib.suppress`. Verified at `worker.py:327–334` and `worker.py:441–448`.
- **`src/pramanix/worker.py` lines 721, 725** — 2× `except Exception: pass` inside `WorkerPool.__del__()` GC finalizer. Architecturally acceptable but even the attempt to log is swallowed. ❌ OPEN (acceptable GC-path design choice).
- **`src/pramanix/interceptors/kafka.py` line 120** — `except Exception: pass` in Kafka consumer GC finalizer. ❌ OPEN (acceptable design).
- **`src/pramanix/integrations/llamaindex.py` line 143** — `except Exception: pass` in `PramanixFunctionTool._shutdown_executor()` GC path. ❌ OPEN (acceptable design).
- **`src/pramanix/guard_config.py` line 246** — bare `pass` class body in an empty override guard subclass. Structural dead code; no runtime consequence. ❌ OPEN (cosmetic).
- **`src/pramanix/guard.py` line 250** — ✅ FIXED (2026-05-20): `_emit_field_seen_metric()` now logs at DEBUG on exception (`log.debug("pramanix.guard: metrics increment failed: %s", _e)`). Verified at `guard.py:251–252`. See §4.9.

### 4.6 `# pragma: no cover` Hiding Real Runtime Paths in Production Source

- **`src/pramanix/execution_token.py` line 92** — `except ImportError:  # pragma: no cover` — asyncpg-absent path never tested; C-extension ABI mismatch silently degrades `PostgresExecutionTokenVerifier`.
- **`src/pramanix/execution_token.py` line 966** — `if _asyncpg is None:  # pragma: no cover` — the `RuntimeError` guard when asyncpg is missing is excluded from coverage.
- **`src/pramanix/mesh/authenticator.py` line 885** — `except ImportError as exc:  # pragma: no cover` — JWT library import failure path hidden.
- **`src/pramanix/mesh/authenticator.py` line 906** — `except ImportError as exc:  # pragma: no cover` — second JWT library import failure path hidden.
- **`src/pramanix/mesh/authenticator.py` line 922** — `raise MeshAuthenticationError(  # pragma: no cover` — error construction site excluded; error message text never verified by tests.

### 4.7 ⚠️ PARTIALLY FIXED: `fast_path.py` — Fail-Open-to-Z3 on Malformed Numeric Input

**File**: `src/pramanix/fast_path.py` lines 88, 106, 141, 168

All 4 `except Exception: return None` paths now call `_inc_parse_failure(_rule_name)` + `_log.warning(...)`. Operators can alert on a non-zero `pramanix_fast_path_parse_failure_total` rate.

**Still open by design**: Functions still return `None` (fail-open to Z3) rather than raising a block decision on malformed input. Z3 receives unvalidated `intent_value` strings. No input sanitisation at `Guard.verify()` boundary before fast-path or Z3 evaluation.

**Risk**: Reduced (observable via counter + WARNING) but not eliminated; Z3 is the sole remaining guard for malformed input.

### 4.8 ⚠️ PARTIALLY FIXED: `hypothesis.assume()` Over-Exclusion in `test_sanitise_properties.py`

**File**: `tests/unit/test_sanitise_properties.py`

- **Line 139** — `assume(len(s) >= 10)` and `assume(len(s) <= 512)` remain. Sanitizer behaviour on length 0–9 and >512 strings is not property-tested.
- **Lines 241, 245, 257, 271, 281** — 5× `assume(len(s) > 0)` and `assume(s.strip())` remain. Empty and whitespace-only inputs are not explored by Hypothesis.
- **Lines 253, 265, 277** — `assume(not s.startswith(...))` filters on injection prefixes remain. Property tests never exercise the "injection-prefix string is always sanitised" property.
- **7× `suppress_health_check=[HealthCheck.too_slow]`** remain with no benchmark justification comment.

**Risk**: Sanitizer's most security-relevant inputs (empty, single-char, injection-prefix, overlong) are not property-tested. Regression on empty/whitespace handling would not be caught by Hypothesis.

### 4.9 ✅ FIXED: `guard.py` — `_emit_field_seen_metric()` No Longer Silent

**File**: `src/pramanix/guard.py` **Lines 251–252** — Fixed 2026-05-20; verified 2026-05-23 via source read.

```python
except Exception as _e:
    log.debug("pramanix.guard: metrics increment failed: %s", _e)
```

The bare `pass` was replaced with a `DEBUG`-level log entry. If `prometheus_client` raises (label-cardinality explosion, registry collision, threading race), the failure is now recorded in the debug log.

**Remaining nuance**: Log level is DEBUG, not WARNING. A silent counter failure will not trigger an operator alert in default log configurations. An operator running at INFO+ will still not see this. If the intent is operator alertability, escalate to WARNING. Current state is a functional improvement but not fully observable in production log levels. ⚠️ LOW — acceptable as-is unless field-coverage dashboards are on-call critical.

---

## 5. Open Action Items

Concrete actions for all remaining flaws, prioritised highest-risk first.

1. **Replace Z3/solver patches with observable test doubles** — Extract a `SolverProtocol` interface from `solver.py`; inject it via dependency injection into `Guard`; test fail-safe paths against a `FailingSolverStub` that implements the protocol — no `patch("z3.Solver")` or `patch("pramanix.guard.solve")` needed. ❌ OPEN.

2. **Eradicate remaining `monkeypatch.setitem(sys.modules)` in 5 files** — `test_enterprise_audit_sinks.py`, `test_framework_adapters.py`, `test_integrations_lazy.py`, `test_mistral_llamacpp.py`, `test_distributed_circuit_breaker.py` — each requires a dedicated tox environment. ❌ OPEN.

3. **Resolve `ExpressionNode.__hash__` blueprint deviation** — Blueprint specifies `__hash__ = None` (unhashable). Current implementation uses identity hashing. Either update the blueprint to accept identity hashing or change to `__hash__ = None` and update all callers. ❌ OPEN.

4. **Test asyncpg and JWT ImportError paths** — Remove `# pragma: no cover` from `execution_token.py` lines 92–93, 966 and `mesh/authenticator.py` lines 885, 906, 922; inject missing-package conditions via `monkeypatch.setitem(sys.modules, "asyncpg", None)`. ❌ OPEN.

5. **Add Protocol stubs for integration stub base classes** — In `integrations/llamaindex.py` and `integrations/langchain.py`: replace bare stub classes with typed Protocol classes that raise `RuntimeError("Install X to use this integration")` on instantiation. ❌ OPEN.

6. **Add `suppress_health_check` justification comments** — In `test_sanitise_properties.py` lines 96, 126, 157, 241, 253, 265, 277: each `suppress_health_check=[HealthCheck.too_slow]` needs a benchmark comment showing P99 latency; otherwise remove the suppression and fix the slow strategy. ❌ OPEN.

7. **Add injectable clock abstraction for `execution_token.py`** — Introduce `_clock: Callable[[], float]` parameter in `ExecutionToken`, `RedisExecutionTokenVerifier`, and `PostgresExecutionTokenVerifier`; default to `time.time`. Nine direct `time.time()` call sites remain without injection mechanism. ❌ OPEN.

8. **Add integration tests for non-numeric state injection in `guard_pipeline.py`** — Parametrised test covering `balance="CORRUPTED"`, `balance=None`, `balance={}`, `balance="NaN"`, `dosage="MAX"`, `replica_count="unlimited"` — each must result in `SemanticPolicyViolation` via a full `Guard.verify()` call (not mocked). ❌ OPEN.

9. **Add concurrent-mutation integration test for circuit-breaker `_lock`** — Spawn 200 concurrent coroutines entering `async with cb._lock:` simultaneously; assert state-transition counter increments are linearizable. Validates the `@functools.cached_property` fix under concurrency. ❌ OPEN.

10. **Close `hypothesis.assume()` exclusions in `test_sanitise_properties.py`** — Remove `assume(len(s) >= 10)`, `assume(len(s) <= 512)`, `assume(len(s) > 0)`, and `assume(s.strip())` from 7 sites; add explicit edge-case tests for empty, single-char, injection-prefix, boundary-length, and whitespace inputs. ❌ OPEN.

11. **Escalate `_emit_field_seen_metric()` failure log level from DEBUG to WARNING in `guard.py`** — Line ~250: current fix logs at DEBUG; escalate to WARNING so prometheus failures surface at default log configurations. See §4.9. ⚠️ LOW (functional fix applied; observability improvement only).

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
| **Correctness** | ✅ | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | Remaining open: fast_path still returns `None` (fail-open) rather than raising; no input sanitisation at `Guard.verify()` boundary | High |
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
| **Reliability** | ✅ | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | Remaining gap: no concurrent-mutation integration test for `_lock` after the `cached_property` fix (§5 item 9); no hyperscale battle-tested production deployment | Medium |
| **Test isolation** | ✅ | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | 5 files outside Phase 3 scope retain `monkeypatch.setitem(sys.modules)` (see §4.2); require dedicated tox environments | Medium |

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

**Last updated**: 2026-05-23. Only rows with remaining open or partially-open gaps are listed.

| # | Area | Pramanix vs Best Competitor | Severity | Status | Minimum Action to Close Gap |
|---|------|-----------------------------|----------|--------|-----------------------------|
| 1 | Enterprise adoption / Licence | AGPL-3.0 vs Apache-2.0 (all competitors) | 🔴 Critical | 🔴 Open | Re-licence core to Apache-2.0 or introduce a commercial licence; update pyproject.toml, README, LICENCE, PROOF_DOSSIER |
| 2 | NLP safety coverage | Beta validators vs GrAI/NeMo production-grade moderation | 🟠 High | ⚠️ Partial | `pramanix_nlp_model_available` gauge and load-failure warnings added. Validators remain beta-grade; full GrAI/NeMo moderation parity not reached |
| 3 | Real LLM adversarial validation | Stub CI tests vs NeMo production-tested rails | 🟠 High | 🔴 Open | Add CI integration tests with real (or containerised) LLM endpoints for consensus and injection detection; remove Layer 4 stub dependency |
| 4 | Orchestration depth | Single-action gate vs LangGraph graph-native workflows | 🟠 High | 🔴 Open | Define and publish a public AgentOrchestrationAdapter protocol; document Pramanix-as-gate pattern for LangGraph state nodes |
| 5 | Developer UX / Policy authoring | Z3-knowledge required vs no-code schema in GrAI | 🟠 High | 🔴 Open | Add policy linter with plain-English error messages; add interactive YAML policy validator to CLI |
| 6 | Test isolation | 5 files still use `monkeypatch.setitem(sys.modules)` | 🟡 Medium | ⚠️ Partial | Eradicate remaining 5 out-of-scope files with dedicated tox environments (see §4.2) |
| 7 | Benchmark freshness | v0.8.0 consumer laptop vs current hardware | 🟡 Medium | 🔴 Open | Re-run all benchmarks on v1.0.0 on server-class hardware (8-core, 32 GB RAM); publish in PROOF_DOSSIER.md |
| 8 | fast_path fail-open | 4× `return None` to Z3 | 🟡 Medium | ⚠️ Partial | Counter and WARNING added; fast-path still returns `None` (fail-open by design). Either document as accepted risk or add malformed-input block decision at `Guard.verify()` boundary |
| 9 | Policy correctness assurance | No intent-verification vs formal proof | 🟡 Medium | 🔴 Open | Add a policy simulation/dry-run mode that shows which intents would be allowed/denied with example data |
| 10 | Memory tooling | Beta SecureMemoryStore vs LlamaIndex production RAG | 🟡 Medium | ⚠️ Partial | `SecureMemoryStore` public interface defined; `MIGRATION.md § MM-01` covers 6 LlamaIndex patterns. Memory components remain beta; not a retrieval/RAG stack |
| 11 | Formal completeness scope | Only covers encoded policy predicates | 🟡 Medium | 🔴 Open | Add a policy coverage metric: which fields and predicates are declared vs which appear in real traffic; surface uncovered paths in observability dashboard |
