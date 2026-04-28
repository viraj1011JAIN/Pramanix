# Known Gaps

**Pramanix 1.0.0** — Honest list of what is unfinished, what has known limitations, and what to watch out for.

This document describes real gaps discovered from the code, not theoretical risks. If a gap is closed in a future version, it should be removed from here and recorded in DECISIONS.md.

---

## 1. ExecutionTokenVerifier consumed-set is in-memory only by default

**Severity:** High for high-security deployments that care about replay across restarts.

`InMemoryExecutionTokenVerifier` stores consumed token IDs in a `set` in process memory guarded by `threading.Lock`. A process restart clears this set. If a token was minted before the restart and has not yet expired, it can be consumed again after the restart.

**Who is affected:** Any deployment where:
- Tokens have a TTL longer than the typical restart gap, AND
- An attacker can intercept a token and delay consumption until after a restart.

**Current mitigations in code:**
- `InMemoryExecutionTokenVerifier.__init__` emits `UserWarning` unconditionally, describing the in-memory limitation and naming the durable alternatives.
- `InMemoryExecutionTokenVerifier.__init__` emits `RuntimeWarning` (elevated severity) when multi-worker environment variables (`WEB_CONCURRENCY`, `GUNICORN_CMD_ARGS`, `UVICORN_WORKERS`, `HYPERCORN_WORKERS`) are detected.
- `RedisExecutionTokenVerifier` closes this gap for Redis deployments.
- `SQLiteExecutionTokenVerifier` and `PostgresExecutionTokenVerifier` close it for SQL deployments.
- Default token TTL is 30 seconds — short enough that most planned restarts drain the window.

**What remains unaddressed:** `pramanix doctor` does not check whether the configured token verifier backend is durable. A deployment using `InMemoryExecutionTokenVerifier` in production will pass the doctor check without comment.

---

## 2. `_semantic_post_consensus_check` covers only 3 field patterns

**Severity:** Low — this is a defence-in-depth layer before Z3, not a primary enforcement mechanism.

`guard_pipeline._semantic_post_consensus_check` only checks:
1. `amount > 0`
2. `balance - amount >= minimum_reserve` (when `balance` is present in state)
3. `daily_spent + amount <= daily_limit` (when `daily_limit` and `daily_spent` are present in state)

Any policy domain that does not use these field names (e.g., healthcare PHI access control, infrastructure blast radius) gets no semantic pre-check. Z3 still enforces all invariants — the pre-check only reduces latency for obviously-invalid requests in the fintech domain.

**What to do:** If you have a high-traffic domain that would benefit from pre-Z3 screening, configure `GuardConfig.fast_path_rules` instead — that path is extensible and domain-agnostic.

---

## 3. Not published to PyPI

**Severity:** Medium — limits distribution.

Version 1.0.0 is complete and passes all CI gates, but no PyPI release exists. `pip install pramanix` will fail until a release is published. See RELEASE_CHECKLIST.md for the publish steps.

---

## 4. Enterprise audit sinks tested with mocked clients only

**Severity:** Medium for production deployments that rely on these sinks.

`KafkaAuditSink`, `S3AuditSink`, `SplunkHecAuditSink`, and `DatadogAuditSink` all have unit tests in `tests/unit/test_enterprise_audit_sinks.py`. However, those tests inject mock client objects via `__new__` bypass — they do not connect to real Kafka brokers, S3 buckets, Splunk HEC endpoints, or Datadog ingest APIs.

**What this means:** Message serialization, retry logic, and connection handling are tested. Whether the sink works with a real endpoint in a specific network configuration is not tested in CI.

**What to do:** Run a manual integration test against real endpoints before relying on these sinks in production. The sink protocol (`emit` must not raise) is tested; the transport layer is not.

---

## 5. Cloud KMS providers tested with mocked clients only

**Severity:** Medium — cloud providers are `stable` API but mock-only tested.

`AwsKmsKeyProvider`, `AzureKeyVaultKeyProvider`, `GcpKmsKeyProvider`, and `HashiCorpVaultKeyProvider` all accept an injected `_client` parameter. Unit tests use mock clients. No CI job runs against live AWS Secrets Manager, Azure Key Vault, GCP Secret Manager, or HashiCorp Vault.

**What this means:** Key retrieval, error handling, and rotation logic are unit-tested. IAM permissions, network policies, and secret name resolution in real cloud environments are not.

---

## 6. `interceptors/__init__.py` declares `__all__` without importing the names

**Severity:** Low — the implementation is in submodules.

`src/pramanix/interceptors/__init__.py` declares:
```python
__all__ = ["PramanixGrpcInterceptor", "PramanixKafkaConsumer"]
```
but does not import them. `from pramanix.interceptors import PramanixGrpcInterceptor` will raise `ImportError`. Users must import from the submodules directly:
```python
from pramanix.interceptors.grpc import PramanixGrpcInterceptor
from pramanix.interceptors.kafka import PramanixKafkaConsumer
```

---

## 7. Translator has no circuit breaker around LLM calls

**Severity:** Medium — LLM outages propagate to callers.

When `translator_enabled=True`, LLM call failures raise `ExtractionFailureError` or `LLMTimeoutError`. These propagate up through `Guard.verify()` and are caught by the fail-safe handler, returning `Decision.error(allowed=False)`. Guard itself does not open a circuit breaker on repeated LLM failures.

**What this means:** In a sustained LLM outage, every `Guard.verify()` call that requires the translator will timeout waiting for the LLM before falling through to `Decision.error()`. This adds `LLMTimeout` latency to every blocked request.

**Current mitigation:** `GuardConfig.translator_enabled=False` (the default). Only enable the translator if the LLM service has its own circuit breaker or rate limiter at the infrastructure level.

---

## 8. No rate limiting in Guard itself

**Severity:** Informational — by design.

`Guard.verify()` does not have built-in per-caller rate limiting. Rate limiting is not Guard's responsibility — it belongs at the API gateway or reverse proxy layer. However, this means a caller that calls `Guard.verify()` in a tight loop can exhaust the worker pool or the Z3 solver.

**Mitigations available in code:**
- `GuardConfig.solver_rlimit` caps Z3 resource usage per solve.
- `GuardConfig.solver_timeout_ms` caps per-solve wall time.
- `AdaptiveCircuitBreaker` opens under sustained solver pressure.
- Load shedding: `shed_latency_threshold_ms` and `shed_worker_pct` drop requests when the worker pool is overloaded.

---

## 9. `async-process` execution mode is not tested on Windows in CI

**Severity:** Low — CI is `ubuntu-latest` only.

`ProcessPoolExecutor(mp_context=spawn)` works on all platforms in principle. On Windows, `spawn` is the only available start method. However, CI does not include a Windows runner. Process-mode behavior on Windows is not verified in the test suite.

**Current dev machine:** Windows 11 (confirmed). The test suite passes in `sync` mode on Windows, but there is no CI coverage for `async-process` on Windows.

---

## 10. `Guard.verify()` has no async-native implementation

**Severity:** Informational — by design for now.

There is no `async def verify()`. Async execution modes (`async-thread`, `async-process`) submit work to a `concurrent.futures` pool and block on `executor.submit().result()` — which is not non-blocking from an asyncio perspective without wrapping in `asyncio.run_in_executor`.

**For FastAPI users:** The `integrations/fastapi.py` adapter wraps the Guard call in a thread using `run_in_executor`. This prevents blocking the asyncio event loop. However, it adds the executor overhead on top of the already async-ready `Guard`.

**Known limitation:** There is no way to `await guard.verify()` directly. The async adapter is the recommended path for FastAPI deployments.

---

## 11. `PolicyAuditor` coverage analysis is limited to specific expression node types

**Severity:** Low.

`PolicyAuditor.uncovered_fields()` walks the expression tree looking for `_FieldRef`, `_BinOp`, `_CmpOp`, `_BoolOp`, `_InOp`, and `_AbsOp` nodes. Custom expression subclasses that wrap fields in non-standard node types will not have their field references detected. The auditor will incorrectly report those fields as uncovered.

**When this matters:** Only when using custom `ConstraintExpr` subclasses. The built-in DSL (`E`, `Field`, `ForAll`, `Exists`) is fully covered.

---

## 12. `GuardConfig.expected_policy_hash` is opt-in with no enforcement default

**Severity:** Informational.

The policy fingerprint mismatch check (guard against silent policy drift in rolling deployments) only activates when `expected_policy_hash` is explicitly set in `GuardConfig`. Out of the box, two replicas running different policy versions will each silently accept different policy behavior with no error or warning.

**What to do:** In any multi-replica or rolling-deploy environment, set `expected_policy_hash` in each replica's `GuardConfig`. Get the hash by inspecting `guard._policy_hash` after construction on a reference build, then hardcode it.

---

## 13. PDF compliance reports are not layout-tested

**Severity:** Low.

`ComplianceReporter.to_pdf()` is tested to verify that the output starts with `b"%PDF"` (valid PDF header) and that the file size is non-zero. The visual layout, pagination, table formatting, and font rendering are not tested. Use `to_json()` for machine-readable output in automated pipelines.

---

## 14. `pramanix doctor` does not check for running audit sinks

**Severity:** Informational.

`pramanix doctor` runs 10 environment checks (Python version, Z3 availability, env vars, `PRAMANIX_ENV` production warnings, etc.). It does not verify that the configured `audit_sinks` are reachable at check time. A `KafkaAuditSink` pointing at an offline broker will pass the doctor check but fail silently when `Guard.verify()` tries to emit.

---

## 15. Structlog secrets-redaction only covers known key patterns

**Severity:** Informational.

The structlog secrets-redaction processor in `guard_config.py` redacts values for keys that match a known-sensitive pattern list (API keys, PEM data, HMAC secrets). User-defined field names that happen to contain sensitive values (e.g., a field named `user_token`) will not be redacted unless the redaction pattern list is extended.

This is not a Guard issue — Guard never logs field values by default. The redaction applies to structlog log records emitted by Guard internals (e.g., policy name, decision ID, latency). User-controlled field values are not logged.

---

## 16. `interceptors/__init__.py` declares names in `__all__` without importing them

**Severity:** Low — the implementation is in submodules.

`src/pramanix/interceptors/__init__.py` declares:

```python
__all__ = ["PramanixGrpcInterceptor", "PramanixKafkaConsumer"]
```

but does not import them. `from pramanix.interceptors import PramanixGrpcInterceptor` raises `ImportError`. Import directly from submodules:

```python
from pramanix.interceptors.grpc  import PramanixGrpcInterceptor
from pramanix.interceptors.kafka import PramanixKafkaConsumer
```

---

## 17. CrewAI, DSPy, Haystack, Pydantic AI, and Semantic Kernel adapters are stubs

**Severity:** Medium — these are listed as beta integrations but have minimal real test coverage.

The five adapters in `integrations/crewai.py`, `integrations/dspy.py`, `integrations/haystack.py`, `integrations/pydantic_ai.py`, and `integrations/semantic_kernel.py` are present and structurally correct. However, they have not been tested against real framework versions (i.e., actual `crewai`, `dspy-ai`, `haystack-ai`, `pydantic-ai`, or `semantic-kernel` library objects in an integration test). They may fail against specific framework API changes or version constraints.

**What is tested:** Unit-level tests that mock the framework objects.

**What is not tested:** Actual `crewai.Task` execution, DSPy `Module.forward()` pipeline, Haystack `Pipeline.run()`, Pydantic AI validator hooks, or Semantic Kernel plugin registration.

---

## 18. `pramanix doctor` does not check token verifier backend durability

**Severity:** Informational.

`pramanix doctor` checks 11 environment conditions but does not detect whether the application is using `InMemoryExecutionTokenVerifier` in a multi-process deployment. A deployment that uses the in-memory verifier with multiple workers (Gunicorn, Uvicorn `--workers N`) will pass the doctor check despite having broken replay protection.

The `InMemoryExecutionTokenVerifier.__init__` emits `RuntimeWarning` when multi-worker env vars are detected, but this only fires at object construction time — not at doctor check time.
