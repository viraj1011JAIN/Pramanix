# Known Gaps

**Pramanix 1.0.0** — An honest inventory of what is unfinished, untested, or constrained by deliberate design tradeoffs.

This document is maintained as code, not aspirations. If an item here is fixed in a release, it is moved to the CHANGELOG with a reference back to the gap number. If you discover a gap that is not listed, open an issue.

---

## § 1 — `InMemoryExecutionTokenVerifier` is not durable

**Impact:** Single-process deployments only.

`InMemoryExecutionTokenVerifier` stores consumed token IDs in a `threading.Lock`-guarded `set` in process memory. A process restart clears the set entirely. Any `ExecutionToken` minted before the restart and not yet consumed can be replayed after restart, as long as the token's `expires_at` has not passed.

**Workaround:** Use `RedisExecutionTokenVerifier` (requires `pip install 'pramanix[identity]'`) or `SQLiteExecutionTokenVerifier` for deployments that need replay protection across restarts or across multiple replicas.

**Not a bug:** The class is documented and exported with "not durable" in its `__doc__`. This is a deliberate design tradeoff — the in-memory variant has zero external dependencies and is correct for single-process, restart-tolerant deployments.

---

## § 2 — Not published to PyPI

**Impact:** Users must install from source.

`pip install pramanix` will fail with a package-not-found error until a PyPI release is published. See `docs/RELEASE_CHECKLIST.md` for the full pre-release gate list.

**Workaround:** `pip install git+https://github.com/viraj1011JAIN/Pramanix.git` or clone and `pip install -e '.[all]'`.

---

## § 3 — Enterprise audit sinks tested with stub transports only

**Impact:** Kafka, S3, Splunk, Datadog sinks are not tested against live endpoints in CI.

`KafkaAuditSink`, `S3AuditSink`, `SplunkHecAuditSink`, and `DatadogAuditSink` are tested with duck-typed stub clients in `tests/unit/`. Transport-layer correctness — broker connectivity, IAM permissions, network routing, partition assignment, S3 multipart upload — is not verified in CI.

**Risk:** A configuration error in a production audit sink will surface only at runtime. Since sink failures are caught and logged (never propagated), a misconfigured sink silently drops decisions.

**Workaround:** Run `pramanix doctor` after deploying a new sink configuration. Add sink-specific smoke tests in your deployment pipeline (e.g., `KafkaAuditSink.emit(Decision.error(...))` and verify the record appears in the topic before declaring the deployment healthy).

---

## § 4 — Cloud KMS key providers tested with stub clients only

**Impact:** `AwsKmsKeyProvider`, `AzureKeyVaultKeyProvider`, `GcpKmsKeyProvider`, `HashiCorpVaultKeyProvider` are not tested against live cloud endpoints in CI.

All cloud providers accept an injected `_client` parameter for testing. CI exercises only this path. IAM permissions, network policies, secret versions, key rotation behaviour, and regional failover are not verified.

**Risk:** A misconfigured cloud provider will raise at `Guard` construction time (fail-fast), not silently. The fail mode is safe, but it will break your deployment if misconfigured.

**Workaround:** Test your key provider configuration in a staging environment with real credentials before production. At a minimum, call `provider.public_key_pem()` and `provider.private_key_pem()` in a pre-deployment smoke test.

---

## § 5 — `async-process` mode not tested on Windows in CI

**Impact:** `execution_mode="async-process"` has no CI coverage on Windows.

The development machine is Windows 11. Unit tests pass in `sync` mode. `ProcessPoolExecutor` with `mp_context=spawn` on Windows uses a different codepath than Linux (no `fork`/`forkserver`). Worker startup, PPID watchdog behaviour, and IPC serialisation under Windows `spawn` semantics have not been exercised in a CI environment.

**Risk:** Silent correctness issues in `async-process` mode on Windows are possible. The `sync` and `async-thread` modes are safe to use on Windows.

**Workaround:** Use `execution_mode="async-thread"` on Windows until CI coverage is added.

---

## § 6 — `interceptors/__init__.py` declares `__all__` without importing the names

**Impact:** `from pramanix.interceptors import PramanixGrpcInterceptor` will fail.

`pramanix/interceptors/__init__.py` declares `__all__ = ["PramanixGrpcInterceptor", "PramanixKafkaConsumer"]` but does not import those names. The `__all__` declaration is aspirational, not functional.

**Workaround:** Import directly:
```python
from pramanix.interceptors.grpc  import PramanixGrpcInterceptor
from pramanix.interceptors.kafka import PramanixKafkaConsumer
```

**Fix:** Remove the `__all__` declaration from `interceptors/__init__.py` or add the corresponding imports. This is a one-line fix deferred to avoid breaking any code that already works around it.

---

## § 7 — Translator has no circuit breaker around LLM calls

**Impact:** Sustained LLM outages add full LLM timeout latency to every blocked request.

When `translator_enabled=True`, `Guard.verify()` calls the translator on every request before Z3 runs. If the LLM backend is down or rate-limiting, each request waits for the LLM timeout before the Z3 solve proceeds. With `execution_mode="async-thread"` or `"async-process"`, this blocks a worker slot for the duration of the timeout.

**Risk:** A sustained LLM outage degrades throughput proportional to `max_workers × LLM_timeout`. In the worst case, all workers are blocked on LLM calls and the Guard becomes unresponsive.

**Workaround:** Set a short timeout on your translator client (`httpx.AsyncClient(timeout=5.0)`). Use `AdaptiveCircuitBreaker` around the Guard to shed load when latency spikes. Consider running the translator outside the Guard verification path and passing structured intent directly.

---

## § 8 — DSPy, Haystack, Pydantic AI, Semantic Kernel integrations are stubs

**Impact:** Five integration adapters are present in source but have minimal test coverage and may not work against real framework versions.

`PramanixGuardedModule` (DSPy), `HaystackGuardedComponent`, `PramanixPydanticAIValidator`, `PramanixSemanticKernelPlugin` are class definitions that implement the framework's interface at a structural level. They have not been exercised against real framework instantiations in CI. API compatibility with current framework versions is not guaranteed.

`PramanixCrewAITool` has been fixed (§ H-04 in CHANGELOG) and is more complete, but also lacks end-to-end integration tests against a real CrewAI agent.

**Workaround:** Treat these as reference implementations. If you need one for production, review the adapter code, test against your target framework version, and open an issue or PR if you find incompatibilities.

---

## § 9 — `PolicyAuditor.uncovered_fields()` misses custom `ConstraintExpr` subclasses

**Impact:** Static field-coverage analysis reports false negatives for custom DSL extensions.

`PolicyAuditor.uncovered_fields()` walks the invariant list and extracts `_FieldRef` nodes from the AST. It recognises the built-in DSL nodes (`_BinOp`, `_CmpOp`, `_BoolOp`, `_ForAllOp`, etc.) but not subclasses of `ConstraintExpr` that wrap fields in non-standard node types.

If your policy uses a custom node type that references fields internally, `PolicyAuditor` will report those fields as uncovered even when they are constrained.

**Workaround:** For policies with custom nodes, supplement `PolicyAuditor` output with manual inspection. The auditor is a development-time tool, not a correctness gate.

---

## § 10 — `CalibratedScorer` depends on scikit-learn, which is not declared in any extra

**Impact:** `from pramanix.translator.injection_scorer import CalibratedScorer` raises `ImportError` unless scikit-learn is installed separately.

The `[translator]` extra does not include `scikit-learn`. The `CalibratedScorer` class and `pramanix calibrate-injection` CLI command both require `sklearn` at runtime but there is no `pramanix[sklearn]` extra defined in `pyproject.toml`.

**Workaround:** `pip install scikit-learn` manually before using `CalibratedScorer` or `pramanix calibrate-injection`.

**Fix:** Add `scikit-learn = {version = ">=1.3", optional = true}` and a `[sklearn]` extra to `pyproject.toml`. Include it in `[all]`.

---

## § 11 — `ComplianceReport.to_pdf()` layout is not tested

**Impact:** PDF output is generated but layout correctness is not verified in CI.

`ComplianceReport.to_pdf()` produces a valid PDF file (confirmed by `fpdf2`'s own internal checks). The header, title, and summary section render correctly. Multi-page layout, table wrapping, and Unicode character handling in regulatory citation text are not tested by any test in the suite.

**Risk:** Long `rationale` strings or regulatory citation tables with many rows may render incorrectly (truncated, overlapping, or missing content) without any runtime error.

**Workaround:** Visually inspect PDF output for your specific citation set before distributing compliance reports.

---

## § 12 — Kubernetes admission webhook has minimal test coverage

**Impact:** `pramanix.k8s.webhook.AdmissionWebhook` is tested at unit level only.

`AdmissionWebhook` handles the `/validate` and `/mutate` endpoints expected by the Kubernetes API server. Unit tests verify the handler logic against synthetic `AdmissionReview` payloads. End-to-end testing against a real cluster (via `kube-apiserver` admission webhook registration, TLS, and the actual webhook call flow) does not exist in CI.

**Risk:** TLS certificate configuration, webhook registration YAML, and the exact payload structure Kubernetes sends may differ from the unit test stubs.

**Workaround:** Test against a local Kind or Minikube cluster before deploying the webhook to production. See the `/deploy` directory for reference manifests.

---

## § 13 — IFC, Privilege, Oversight, Memory, Lifecycle, Provenance have no integration tests

**Impact:** Six beta subsystems are unit-tested in isolation but not tested in combination with Guard.

The six newer subsystems (`FlowEnforcer`, `ScopeEnforcer`, `InMemoryApprovalWorkflow`, `SecureMemoryStore`, `ShadowEvaluator`, `ProvenanceChain`) each have unit tests covering their own logic. None have tests that verify their interaction with `Guard.verify()` in a realistic multi-step agent scenario.

**Risk:** Integration-level bugs — e.g., a `FlowPolicy` that should block a `Guard.verify()` ALLOW, or a `ProvenanceChain` that drops entries under concurrent load — will not be caught by existing tests.

**Workaround:** Write scenario-level tests for your specific use of these subsystems before relying on them in production. They are `beta` stability for this reason.

---

## § 14 — `pramanix doctor` Redis check requires `PRAMANIX_REDIS_URL`

**Impact:** The Redis connectivity check in `pramanix doctor` is skipped unless `PRAMANIX_REDIS_URL` is set in the environment.

If you use `RedisExecutionTokenVerifier` or `RedisDistributedBackend` but don't set `PRAMANIX_REDIS_URL`, the doctor check passes (because the check is skipped, not because Redis is reachable).

**Workaround:** Set `PRAMANIX_REDIS_URL` in your deployment environment so that `pramanix doctor` actually verifies Redis connectivity. Add `--strict` to fail the health check on any `WARN`-level finding.
