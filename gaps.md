# Pramanix — Non-Real Integration Gaps Report (v6 — Open Items Only)

**Scope:** Every Python source file, test file, CI/CD workflow file, Dockerfile, and
configuration file in the repository was examined for: stubs, mocks, `MagicMock`,
`AsyncMock`, `monkeypatch`, `patch.dict(sys.modules, …)`, in-memory fakes, simulations,
duck-typed test doubles, `# pragma: no cover`, `# type: ignore`, `# noqa`, `continue-on-error`,
`filterwarnings` suppressions, skip decorators, `NotImplementedError` stubs, bare `pass`
exception handlers, placeholder text, hardcoded credentials, `PRAMANIX_TRANSLATOR_ENABLED=false`,
`PRAMANIX_ALLOW_NO_AUDIT_SINKS`, OTel/Prometheus no-op fallbacks, slur-list placeholders,
CI soft-fail gates, coverage exclusion rules, and any other place where the **real thing
is not used**.

**Note:** Fully-fixed items have been removed. This document contains only open (❌) and
partially-fixed (⚠️) gaps.
Cross-verified against: **4192 passed, 129 skipped, 50 warnings in 1310.03s** (2026-05-25).
Updated: 2026-05-30 — Section 3 all 4 remaining sys.modules files confirmed fixed (skipif +
real behaviour); Section 22 slur list confirmed populated; LlamaIndex stubs confirmed raise
ConfigurationError; GA-6 and GA-8 closed; doctor checks 19-23 added (metrics, tracing, NLP
backends, translator-enabled).

---

---

## 3. `patch.dict(sys.modules, …)` — Hidden / Simulated Import State

**✅ FULLY FIXED — 2026-05-30**

All 4 files previously listed have been converted to `pytest.mark.skipif(find_spec(...) is
not None, reason="run in tox:no-X")` with real `ConfigurationError` assertions. No
`patch.dict(sys.modules, …)` calls remain in any test file.

---

## 4. `monkeypatch.setattr` — Function / Method Replacement

### `tests/adversarial/test_fail_safe_invariant.py`

`pramanix.guard.solve` patches have been removed (fixed 2026-05-26) — Z3 solver failures
are now injected via `GuardConfig(solver_factory=…)` with `RaisingSolverStub` /
`TimeoutSolverStub` (real `SolverProtocol` implementations). The remaining patches replace
`validate_intent`, `validate_state`, and `flatten_model` to test those specific pipeline
handlers — these are acceptable `monkeypatch.setattr` calls, not Z3 trust-boundary
violations.

Lines still using `monkeypatch.setattr`: 164, 178, 220, 251, 277, 523.
Target functions: `validate_intent`, `validate_state`, `flatten_model` only. ⚠️ LOW.

### `tests/unit/test_audit.py`

| Line(s) | Effect |
|---------|--------|
| 113 | `monkeypatch.setattr(signer, "_canonicalize", _boom)` — internal method replaced |
| 406 | `monkeypatch.setattr(sys, "argv", […])` — CLI argv injected |
| 422 | `monkeypatch.setattr(sys, "stdin", io.StringIO(""))` — stdin replaced with in-memory buffer |

### `tests/unit/test_cli_simulate.py`

37+ calls using `monkeypatch.setattr(sys, "argv", […])`.

**Critical gap at line 537:** `monkeypatch.setattr(socket.socket, "connect", _no_connect)` —
Python's `socket.socket.connect()` is replaced globally for the duration of the test so that
any accidental real network I/O raises `AssertionError`. This correctly verifies that the
`simulate` command makes no network calls, but the mechanism is TCP-intercept-via-monkeypatch
rather than a real network-isolated sandbox.

### `tests/unit/test_doctor_cli.py`

| Line(s) | Effect |
|---------|--------|
| 222 | `monkeypatch.setattr(_sys, "version_info", fake_vi)` — Python version fabricated |
| 249 | `monkeypatch.setattr(builtins, "__import__", patched_import)` — import mechanism replaced |

### `tests/unit/test_guard_dark_paths.py`

| Line(s) | Effect |
|---------|--------|
| 746 | `monkeypatch.setattr(_redundant, "create_translator", _raise)` — translator factory replaced |
| 785, 786 | `monkeypatch.setattr(_redundant, "create_translator", _fake_create_translator)` + `extract_with_consensus` |

### `tests/unit/test_guard.py`

`TestGuardFailSafe` Z3 trust boundary violation fixed 2026-05-26 — `_patch_solve()` helper
removed; replaced with `_guard_raising()` using `GuardConfig(solver_factory=…)` and
`RaisingSolverStub`. Remaining patch:

| Line(s) | Effect |
|---------|--------|
| ~580 | `monkeypatch.setattr(_ExplodingPolicy, "invariants", classmethod(_boom))` — patches policy class method to test invariant-generation failure, not Z3. Acceptable. ⚠️ LOW |

### `tests/unit/test_misc_coverage_gaps.py:568`

`monkeypatch.setattr(_worker_mod._log, "warning", _warning_raises)` — structlog logger
replaced with a function that raises, to test error-swallowing in `_emergency_shutdown`.

### `tests/unit/test_oracle_coverage.py:199`

`monkeypatch.setattr(oracle, "_evaluate_impl", _boom)` — core oracle evaluation replaced.

### All other files using `monkeypatch.setattr` (46 total)

`test_calibrate_injection_cli.py`, `test_circuit_breaker_and_guard_paths.py`,
`test_cli_init.py`, `test_cli_coverage_gaps.py`, `test_compliance_reporter.py`,
`test_coverage_gaps.py`, `test_crypto.py`, `test_crypto_extended.py`,
`test_custom_injection_scorer.py`, `test_distributed_circuit_breaker.py`,
`test_enterprise_audit_sinks.py`, `test_execution_token_warnings.py`,
`test_framework_adapters.py`, `test_hardening.py`, `test_identity.py`,
`test_injection_calibration.py`, `test_input_too_long.py`, `test_intent_cache.py`,
`test_kms_provider.py`, `test_limitations_overrides.py`, `test_merkle_archiver.py`,
`test_mistral_llamacpp.py`, `test_nlp_validators_coverage.py`, `test_platform_check.py`,
`test_postgres_token_verifier.py`, `test_pragma_free_paths.py`,
`test_production_gaps_v2.py`, `test_provenance.py`, `test_rs256_es256.py`,
`test_translator.py`, `test_translator_and_interceptor_paths.py`,
`test_translator_anthropic.py`, `test_translator_ollama.py`, `test_verify_proof_cli.py`,
`test_worker_dark_paths.py`.

---

## 5. `monkeypatch.setenv` / `monkeypatch.delenv` — Simulated Environment Variables

| File | Variable(s) | Effect |
|------|-------------|--------|
| `tests/unit/test_audit.py:46, 52, 98, 410, 420–532` | `PRAMANIX_SIGNING_KEY` | Set/deleted to simulate key presence/absence |
| `tests/integration/test_fastapi_middleware.py:161, 178, 260, 384, 404` | `PRAMANIX_SIGNING_KEY` | Test hex string injected, not a real signing key |
| `tests/unit/test_circuit_breaker_and_guard_paths.py:591` | `DD_API_KEY` | Datadog API key injected |
| `tests/unit/test_cli_coverage_gaps.py:225–237, 699–732, 828–874` | `PRAMANIX_ENV`, `PRAMANIX_EXPECTED_POLICY_HASH`, `PRAMANIX_REDIS_URL`, `PRAMANIX_SIGNING_KEY`, `PRAMANIX_SCORER_HMAC_KEY_HEX` | Multiple env vars injected/deleted |
| `tests/unit/test_misc_coverage_gaps.py:143–156` | `PRAMANIX_ENV`, `PRAMANIX_ALLOW_NO_AUDIT_SINKS` | Production mode simulated via env flags |

---

## 6. `sys.platform` Fabrication

| File | Line(s) | Fabricated value |
|------|---------|-----------------|
| `tests/unit/test_translator_and_interceptor_paths.py` | 58 | `"win32"` |
| `tests/unit/test_translator_and_interceptor_paths.py` | 66, 76, 83, 87 | `"linux"` |

The real `sys.platform` is never the wrong value at runtime. These tests exercise
cross-platform musl/glibc detection branches without running on the actual target platform.

---

---

## 8. Integration Stubs in Production Source Code (`src/integrations/`)

### `src/pramanix/integrations/langchain.py` — `_BaseToolFallback` (lines 28–50)

Fallback class assigned to `BaseTool` when `langchain-core` is absent:
```python
BaseTool = _BaseToolFallback   # line 63
```
`_run` and `_arun` raise `ConfigurationError`; no `# pragma: no cover`. ✅ FIXED 2026-05-25.

**Gap (HIGH):** The real LangChain agent pipeline (real LLM → real tool call → real Guard →
real execution) is **never tested end-to-end** in any test.

### `src/pramanix/integrations/llamaindex.py` (lines 46–50)

Comment: *"Fallback stubs defined unconditionally so they can be used as assignments"*.
Stub types substituted when `llama_index` is absent.

**Gap:** Real LlamaIndex query or retriever pipeline never run against a real data source.

### `src/pramanix/integrations/dspy.py` (line 51)

Comment: *"Type stand-in for dspy.Module (no dspy stubs available)"*.

**Gap:** Real DSPy module execution against a real language model pipeline never tested.

### `src/pramanix/integrations/langgraph.py` (line 60)

Bare `pass` stub class body when LangGraph is absent. Real LangGraph `StateGraph` execution
never tested.

---

## 10. `# noqa` and `# type: ignore` Suppressions in `src/`

Confirmed by exhaustive grep — only 3 occurrences in production source (low risk):

| File | Line | Suppression | Reason |
|------|------|-------------|--------|
| `src/pramanix/cli.py` | 1547 | `# noqa: F401` | Unused import kept for re-export |
| `src/pramanix/compiler.py` | 108 | `# noqa: N814` | Pydantic `Field` naming convention |
| `src/pramanix/guard_config.py` | 196 | `# noqa: E402` | Late import after try/except block |

No `# type: ignore` in `src/` — clean.

---

## 11. `respx` HTTP Transport Mocking

`respx` intercepts HTTP at the transport layer. Real SDK code executes but **no packets
reach any server**.

### `tests/unit/test_llm_backends_real.py`

All Mistral and Cohere tests use `@respx.mock` / `respx.post(…).respond(…)`.
No real API key or endpoint used. Responses are fabricated JSON matching the SDK schema.
(File header: *"only the network transport is replaced by respx's mock transport"*.)

### `tests/unit/test_enterprise_audit_sinks.py` / `tests/unit/test_translator_and_interceptor_paths.py`

`respx` used for Splunk HEC and audit sink HTTP calls.

### `tests/integration/test_cohere_translator.py`

All non-live tests use `@respx.mock`. Real Cohere API is only hit when `COHERE_API_KEY`
is set. The file is named "integration" but most tests are network-intercepted.

---

## 12. Duck-Typed Test Doubles in `tests/helpers/real_protocols.py`

`real_protocols.py` (1948 lines) replaces `MagicMock` with real-class duck-types.
These have real method bodies but are **not the real implementations**.

| Class | Replaces | Real thing missing |
|-------|----------|--------------------|
| `_AsyncCloseClient` | `httpx.AsyncClient` | Real async HTTP client |
| `_ErrorCloseClient` | HTTP client with raising `close()` | Real error not induced |
| `_RaisingGuard` | `Guard` | Real Guard not used |
| `_ErrorCounter` | Prometheus counter | Real Prometheus metrics |
| `_ErrorPollProducer` | `confluent_kafka.Producer` (polling) | Real Kafka poll |
| `_ErrorFlushProducer` | `confluent_kafka.Producer` (flush) | Real Kafka flush |
| `_AsyncBreaker` | Circuit breaker | Real CB not used |
| `_MistralApiResponse` / `_MistralChoice` / `_MistralMessage` | Mistral SDK response | Real Mistral not called |
| `_ErrorRedisClient` | `redis.asyncio.Redis` | Real Redis not used |
| `_AsyncClosablePool` / `_PgPool` / `_PgConn` | `asyncpg` pool/connection | Real Postgres not used |
| `_ErrorS3Client` | `boto3` S3 client | Real S3 not used |
| `_CallTracker` | Callable / `MagicMock(return_value=…)` | Real callables replaced |
| `_DSPyModule` / `_DSPyForwardFn` | DSPy module | Real DSPy not called |
| `_GeminiRecordingGenaiModule` | `google.generativeai` | Real Gemini SDK not called |
| `_KafkaAuditProducer` / `_KafkaAuditModule` | `confluent_kafka` | Real Kafka not used |
| `_RaisingSubmitExecutor` | `ThreadPoolExecutor` | Real executor replaced |
| `_PingFailRedisClient` / `_PingOkRedisClient` | `redis.Redis` | Real Redis not used |
| `_FakeEntryPoint` | `importlib.metadata` entry point | Real entry-point not used |
| `_RecordingTranslator` | `Translator` protocol | Real LLM not called |
| `_FakeWorkerProcess` | `multiprocessing.Process` | Real process not used |
| `_TrackingPingRedisClient` | `redis.Redis` with ping counter | Real Redis not used |

### Additional inline duck-type classes in test files (not in `real_protocols.py`)

| File | Class(es) | Replaces |
|------|-----------|---------|
| `test_llm_backends_real.py:449–545` | `_FakeLlama`, `_BrokenLlama` (5 variants) | `llama_cpp.Llama` |
| `test_doctor_cli.py:284, 301` | `_PingFailRedisClient`, `_PingOkRedisClient` | `redis.Redis` |
| `test_coverage_gaps.py:1060, 1113` | `_Boto3ModuleStub`, `_HvacModuleStub` | `boto3`, `hvac` modules |
| `test_postgres_token_verifier.py:100` | `mock_pkg` (inline stub) | `asyncpg` module |
| `test_misc_coverage_gaps.py:401–627` | `_FakeSecretsClient`, `_FakeSecret`, `_FakeSecretClient`, `_FakePayload`, `_FakeResponse`, `_FakeSecretManagerClient`, `_FakeHvacClient`, `_FakeHvacModule` | AWS/Azure/GCP/Vault SDK clients |
| `test_circuit_breaker_half_open.py:270` | `_FakeBackend` | Distributed CB backend |
| `test_enterprise_audit_sinks.py:292` | `_FakeBoto3` | `boto3` module |
| `test_guard_dark_paths.py:768` | `_FakeTranslator` | `Translator` protocol |
| `test_translator.py:282–730` | `FakeA`, `FakeB`, `FakeBadA`, `FakeGoodB`, `FakeOk`, `FakeTranslator` | All LLM `Translator` instances |
| `test_translator_and_interceptor_paths.py:288–297` | `_FakeErrors`, `_FakeApiError`, `_FakeCore`, `_FakeCohereModule` | Cohere SDK internals |
| `test_coverage_final_push2.py:34` | `DummyPolicy` | Real `Policy` subclass |
| `test_coverage_gaps.py:321` | `FakePureLiteralInvariant` | Policy invariant object |
| `test_coverage_final_push.py:1011` | `MockSolver` | Z3 Solver |
| `test_interceptors_real.py:64–103` | `_FakeMessage`, `_FakeDLQProducer`, `_FakeConsumer` | Kafka consumer/producer |
| `tests/integration/test_dspy_adapter.py:70–90` | `_ForwardModule`, `_CallableModule` | Real DSPy module |
| `tests/integration/test_haystack_adapter.py:216, 231, 301, 319` | `_BrokenGuard` (4 variants) | Real Guard raising errors |
| `tests/integration/test_semantic_kernel_adapter.py:250, 268` | `_BrokenGuard` (2 variants) | Real Guard |

---

## 13. All LLM Translator Tests Use Fake Translators

`tests/unit/test_translator.py` (1140 lines) contains **zero real API calls**.
All `extract_with_consensus`, `RedundantTranslator`, and `create_translator` tests use
inline `FakeA` / `FakeB` / `FakeOk` classes whose `async def extract(…)` returns
hardcoded dicts.

**Untested real scenarios:**
- Real consensus disagreement (floating-point rounding, model ambiguity)
- Real rate-limit / authentication errors from LLM APIs
- Real network latency and streaming responses

---

---

## 15. White-Box State Mutation (Bypassing Real Interfaces)

Tests directly mutate private attributes to simulate conditions that the real system
would reach only through internal state transitions.

| File | Line | Mutation | Gap |
|------|------|----------|-----|
| `tests/unit/test_audit_sink_full_coverage.py` | 121 | `_sink_mod._OVERFLOW_COUNTER = None` | Module-level Prometheus counter forcibly set to `None` |
| `tests/unit/test_audit_sink_full_coverage.py` | 184 | `sink._queue_depth = 1` | Comment: *"white-box unit test: simulate full queue"* |
| `tests/unit/test_circuit_breaker_and_guard_paths.py` | 551 | `sink._queue_depth = 0` | Same pattern |
| `tests/unit/test_enterprise_audit_sinks.py` | 80 | `sink._queue_depth = 0` | Same pattern |
| `tests/unit/test_translator_and_interceptor_paths.py` | 872 | `sink._queue_depth = 0` | Same pattern |
| `tests/unit/test_coverage_final_push.py` | 73, 91, 109, etc. | `t._api_key = "key"` | Private translator attribute injected directly |
| `tests/integration/test_gemini_translator.py` | 46–50 | `GeminiTranslator.__new__()` + `t.model = "…"`, `t._api_key = "test-key"`, `t._client = None` | Constructor bypassed entirely; every private field manually injected |

The Gemini integration test case is the most severe: it constructs a `GeminiTranslator`
via `__new__()` and injects every private field, completely bypassing the constructor
that validates and initialises the real Gemini SDK client.

---

## 16. Fake / Placeholder API Keys

| File | Value | Context |
|------|-------|---------|
| `tests/integration/test_gemini_translator.py:47` | `"test-key"` | Gemini API key (no real call made) |
| `tests/integration/test_cohere_translator.py:77–196` | `"test-key"`, `"sk-real-key-test"` | Cohere API key (respx intercepts all calls) |
| `tests/unit/test_audit_sink_full_coverage.py:297` | `"unit-test-fake-key-xyzzy"` | Datadog API key; SDK called but swallows auth errors |
| `tests/unit/test_circuit_breaker_and_guard_paths.py:583, 1193, 1208, 1228` | `"dd-test-key"`, `"sk-test"` | Datadog / Anthropic keys |
| `tests/helpers/real_protocols.py:885, 922, 942` | `"FAKE_PEM"` | Default private-key value in duck-types; never parsed as real PEM |

The Datadog case (`"unit-test-fake-key-xyzzy"`) is notable: the real Datadog SDK is called
but the resulting authentication error is silently swallowed inside `emit()`. The test
verifies exception-swallowing semantics but **never verifies successful delivery**.

---

## 17. `pytest.importorskip` / Skip Decorators — Silently Skipped Tests

Entire test classes or modules are skipped when the runtime dependency is absent.
Any CI environment without Docker, Gemini API key, Cohere key, or GGUF model file
will silently skip real integration coverage.

| Decorator / guard | Condition | Skipped when |
|------------------|-----------|-------------|
| `@requires_docker` | `_DOCKER_AVAILABLE = False` | Docker daemon not running |
| `@requires_gemini` | `GOOGLE_API_KEY` not set | No Gemini API key |
| `@requires_azure` | `AZURE_*` vars not set | No Azure credentials |
| `requires_llamacpp` | `PRAMANIX_TEST_GGUF_PATH` not set | No GGUF model file |
| `pytestmark = pytest.mark.skipif(not os.environ.get("OPENAI_API_KEY"), …)` | No OpenAI key | All `test_llm_consensus.py` tests |
| `pytest.importorskip("confluent_kafka")` | Package absent | Kafka not installed |
| `pytest.importorskip("boto3")` | Package absent | boto3 not installed |
| `pytest.importorskip("datadog_api_client")` | Package absent | Datadog SDK absent |
| `@pytest.mark.skipif(not _DSPY_AVAILABLE, …)` | dspy not installed | `TestDSPyHierarchy` skipped |
| `@pytest.mark.skipif(not _CREWAI_AVAILABLE, …)` | crewai not installed | CrewAI hierarchy test skipped |
| `@pytest.mark.skipif(not _HAYSTACK_AVAILABLE, …)` | haystack not installed | Haystack real tests skipped |
| `_skip_without_pydantic_ai` | pydantic-ai not installed | PydanticAI tests skipped |
| `_skip_without_sk` | semantic-kernel not installed | SK tests skipped |
| `psutil_required` in `test_memory_stability.py` | psutil not installed | Memory stability tests skipped |

**None of these API keys or models are configured as GitHub Secrets** in `ci.yml` —
confirmed: only `SEMGREP_APP_TOKEN` and `CODECOV_TOKEN` are referenced in the CI workflow.
This means **live LLM consensus tests (`test_llm_consensus.py`), Gemini integration tests,
and LlamaCPP tests are always skipped in CI**.

---

## 18. Hardcoded Fake Credentials in Test Helpers

| File | Line(s) | Fake value | Context |
|------|---------|-----------|---------|
| `tests/helpers/real_protocols.py` | 885 | `secret_string: str = "FAKE_PEM"` | Default arg for AWS-Secrets-Manager duck-type |
| `tests/helpers/real_protocols.py` | 922 | `data: bytes = b"FAKE_PEM"` | `__init__` default for PEM-returning duck-type |
| `tests/helpers/real_protocols.py` | 942 | `value: str = "FAKE_PEM"` | Default for KMS-like duck-type |

These strings are intentionally fake but are **never validated against a real PEM format**.
Tests that consume these helpers exercise code that accepts a PEM but never parses it
with a real crypto library.

---

## 19. CI / CD Gaps

### `continue-on-error: true` — Soft-Fail Gates

| Line | Step | Gap |
|------|------|-----|
| 419 | *Upload Trivy SARIF report* | Trivy SARIF upload failure is acceptable by design; not a test gate |
| 800 | *`ollama-live` job* | `continue-on-error: true` intentional — Ollama live LLM tests are informational only; remove flag to make a strict gate |

### `PRAMANIX_TRANSLATOR_ENABLED=false` in Both Dockerfiles

Both `Dockerfile.dev` (line 116) and `Dockerfile.production` (line 134) bake in:
```
PRAMANIX_TRANSLATOR_ENABLED="false"
```

This means the LLM-based intent translation pathway is **disabled in every Docker-based
test run and in production containers by default**. Any test that relies on Docker-container
execution will never exercise the translator path with a real LLM connection.

### Live API Keys Not Configured as GitHub Secrets

No `OPENAI_API_KEY`, `GOOGLE_API_KEY`, `COHERE_API_KEY`, `AZURE_*`, or
`PRAMANIX_TEST_GGUF_PATH` are referenced as GitHub secrets in `ci.yml`. This means:
- `tests/integration/test_llm_consensus.py` — always skipped in CI
- `tests/integration/test_gemini_translator.py` live tests — always skipped in CI
- `tests/integration/test_llamacpp_translator.py` — always skipped in CI

### Secrets Scan Excludes `tests/` Entirely

`ci.yml` line 145–148:
```yaml
--exclude-dir=tests \
--exclude-dir=.venv \
--exclude-dir=.github \
```
The secrets scan deliberately skips the entire `tests/` directory, so hardcoded test keys
like `"unit-test-fake-key-xyzzy"`, `"test-key"`, `"FAKE_PEM"` are never detected by the
credential scanner.

---

## 21. `NotImplementedError` Stubs in Concrete Production Classes

| File | Line | Method | Risk |
|------|------|--------|------|
| `src/pramanix/policy.py` | 368 | `Policy.invariants()` | Intended abstract — subclasses must override |

**Note:** `rotate_key()` in `PemKeyProvider`, `FileKeyProvider`, and `AwsKmsKeyProvider` is
**fully implemented** as of the current codebase (`key_provider.py:145-164, 267-300, 407-415`).
Only `EnvKeyProvider.rotate_key()` raises `NotImplementedError`, which is correct as its
`supports_rotation` property returns `False`.

---

## 22. Production Source Placeholder / Incomplete Content

### `src/pramanix/nlp/validators.py` — Slur List

**✅ FIXED 2026-05-30** — `_DEFAULT_TOXIC_WORDS` now populated with threat/violence/slur
stems. Confirmed by grep. Comment updated: "Deliberately minimal — operators MUST tune
`threshold` and supply domain-specific `toxic_words`." No zero-stem fallback path remains.

### `src/pramanix/guard_config.py` — `worker_warmup` "dummy Z3 solve" (line 307)

The worker startup runs a Z3 warmup suite via `_warmup_worker()` in `worker.py`. While
this is real Z3, the warmup uses **hardcoded trivially-satisfied constraints** rather than
a representative sample from the actual deployed policy. A policy with large invariants
or non-linear arithmetic will still experience a JIT spike on the first real request.

**Note:** `PRAMANIX_ALLOW_NO_AUDIT_SINKS` has been **removed from the codebase** — grep
confirms no match anywhere in `src/pramanix/`. The audit-trail enforcement bypass
is closed.

---

## 23. OTel and Prometheus No-Op Fallbacks in Production

### OpenTelemetry (`src/pramanix/guard_config.py` lines 169–184)

```python
except ImportError:
    def _span(name: str) -> Any:
        """No-op span when opentelemetry is not installed."""
        return contextlib.nullcontext()
    _OTEL_AVAILABLE = False
```

Every `_span("…")` call is a no-op `nullcontext()`. All distributed traces are silently
discarded. No warning is emitted unless `GuardConfig(otel_enabled=True)` is set.

### Prometheus (`src/pramanix/guard_config.py` lines 187–251)

All four module-level metrics (`_decisions_total`, `_decision_latency`,
`_solver_timeouts_total`, `_validation_failures_total`) are `None` when
`prometheus_client` is absent. Every `_decisions_total.labels(…).inc()` call is guarded
by `if _decisions_total is not None`, which silently drops all metrics.

**Gap:** A production deployment that forgot to install `pramanix[metrics]` emits **no
metrics and no warning** unless `GuardConfig(metrics_enabled=True)` is explicitly set.

### ToxicityScorer — Detoxify Fallback

When `detoxify` is absent, `ToxicityScorer` degrades to keyword-density heuristic.
Warning is logged. **⚠️ PARTIALLY MITIGATED 2026-05-30**: `pramanix doctor` now
reports `nlp-toxicity-backend` as WARN/ERROR (production profile) when detoxify is
absent, surfacing the degradation before deployment. The `pramanix_nlp_degradation_total`
Prometheus counter increments on fallback. Core limitation remains: adversarial
synonym/obfuscation evasion is not caught without the ML model.

### SemanticSimilarityGuard — Jaccard Fallback

Without `sentence-transformers`, degrades to Jaccard word-overlap.
**⚠️ PARTIALLY MITIGATED 2026-05-30**: `pramanix doctor` now reports
`nlp-semantic-backend` as WARN (production profile) when sentence-transformers absent.
`pramanix_nlp_degradation_total` counter increments on fallback. Paraphrasing evasion
still possible without the embedding model.

---

## 24. Docker / Container Configuration — No Gaps Found

The integration test infrastructure uses **real containers** via `testcontainers`:

- **Redis 7-alpine** — `tests/unit/conftest.py`
- **Kafka (Redpanda)** — `tests/integration/conftest.py`
- **PostgreSQL 16-alpine** — `tests/integration/conftest.py`
- **HashiCorp Vault 1.16** — `tests/integration/conftest.py`
- **LocalStack 3.4 (AWS S3)** — `tests/integration/conftest.py`

These are real Docker containers with real network ports. No fakes found here.

---

## 25. Property-Based Tests — No Mock Gaps

`tests/property/` contains 3 files. No `MagicMock`, `patch`, `monkeypatch`, or `sys.modules`
injection found. Hypothesis generates real inputs against real production code. No gaps
in this directory.

---

## 26. Perf Tests — `psutil` Skip Decorator

`tests/perf/test_memory_stability.py` line 47:
```python
psutil_required = pytest.mark.skipif(
    not _PSUTIL_AVAILABLE, reason="psutil not installed"
)
```
Memory stability tests require `psutil` to measure RSS growth. If `psutil` is absent (it
is not in `pyproject.toml` dev dependencies), **all memory-stability assertions are skipped
silently**.

---

## Summary Table — Open Gaps Only

| # | Category | Count | Severity |
|---|----------|-------|---------|
| 3 | `patch.dict(sys.modules, …)` hiding real packages | ✅ 0 remaining (all fixed 2026-05-30) | — |
| 4 | `monkeypatch.setattr` replacing real functions | 80+ occurrences (46 files) | Medium |
| 5 | `sys.platform` fabricated via `monkeypatch` | 4 occurrences (1 file) | Medium |
| 6 | `monkeypatch.setenv` / `delenv` simulating environment | 30+ occurrences | Low–Medium |
| 8 | Integration stubs (LangChain, LlamaIndex fixed; DSPy, LangGraph real adapters added) | 2 remaining | Medium |
| 10 | `pyproject.toml` `exclude_lines` bare-ellipsis rule | 1 rule | Low |
| 11 | `# noqa` suppressions in `src/` | 3 lines | Low |
| 12 | `respx` HTTP transport mocking | All LLM backend + Cohere tests | Medium |
| 13 | Duck-typed test doubles in `real_protocols.py` | 22 classes | Low–Medium |
| 14 | Inline duck-types across test files | 37+ classes | Low–Medium |
| 15 | All LLM translator tests use fake translators | 1140-line file | Medium |
| 17 | White-box private state mutation | 7+ locations | Medium |
| 18 | Fake / placeholder API keys | 10+ occurrences | Low |
| 19 | `pytest.importorskip` / skip decorators silencing tests | 15 conditions | Medium |
| 20 | Live API keys absent from GitHub Secrets → CI always skips | 3 integration test files | **HIGH** |
| 21 | `continue-on-error: true` on `ollama-live` non-blocking gate (intentional) | 1 occurrence | Low |
| 22 | `PRAMANIX_TRANSLATOR_ENABLED=false` baked into both Dockerfiles | 2 Dockerfiles | Medium |
| 24 | Secrets scan excludes `tests/` entirely | 1 CI step | Medium |
| 27 | `NotImplementedError` stub: `Policy.invariants()` (intentional abstract method) | 1 stub | Low |
| 28 | Slur list placeholder | ✅ Fixed 2026-05-30 — `_DEFAULT_TOXIC_WORDS` populated | — |
| 29 | Worker warmup uses hardcoded Z3 patterns, not policy-sampled | 1 location | Low |
| 30 | OTel `nullcontext` no-op fallback — silent when `opentelemetry` absent | 1 module | Medium |
| 31 | Prometheus `None` metric no-op fallback — silent when `prometheus-client` absent | 4 metrics | Medium |
| 32 | ToxicityScorer → keyword-density fallback when `detoxify` absent (evasion risk) | 1 class | Medium |
| 33 | SemanticSimilarityGuard → Jaccard fallback when `sentence-transformers` absent | 1 class | Medium |
| 36 | `psutil` skip in memory stability perf tests | 1 decorator | Low |

---

## Highest-Priority Gaps (Ranked)

1. **LangChain, LlamaIndex, DSPy, LangGraph integrations** tested only with absent-package
   stubs or duck-types. No real end-to-end agent pipeline is exercised anywhere.

2. **Live LLM consensus tests, Gemini integration, and LlamaCPP tests are always skipped
   in CI** — required API keys and model files are not in GitHub Secrets. Only
   `SEMGREP_APP_TOKEN` and `CODECOV_TOKEN` are present.
