# Changelog

All notable changes to Pramanix are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/).

---

## [Unreleased] — 1.0.0-dev

### Summary
First production-ready release. Deterministic neuro-symbolic guardrails for
autonomous AI agents using Z3 SMT formal verification.

### Added

**Core verification engine**
- `Guard` class with 8-phase verification pipeline (input size → resolver → Pydantic → version check → Z3 solve → governance gates → timing jitter → signing)
- `Policy` DSL with `E()` expressions, `Field` descriptors, `invariants` list
- `Transpiler` — DSL expression tree → Z3 AST (no `ast.parse`/`eval`/`exec`)
- `Solver` — Z3 wrapper with per-invariant timeouts, `assert_and_track`, unsat core attribution
- `Decision` — immutable result with proof/counterexample, 17-key wire format
- `fast_path.py` — O(1) pre-Z3 screening, always fail-closed
- `GuardConfig` — 32-field frozen dataclass; all fields env-var overridable

**Security hardening**
- `result_seal_key`: HMAC-SHA256 sealing for IPC results in async-process mode
- Nonce replay prevention in `verify_async`
- `allow_insecure_timing_leaks` production guard (requires explicit opt-in)
- `ForAll(empty_array)` no longer vacuously true (`allow_empty=False` default)
- `ControlMapping.control_id` validated per-framework (SOC2/HIPAA/NIST/ISO27001/PCI-DSS)
- `PRAMANIX_ENV=production` blocks all `InMemory*` sinks with `UserWarning`

**LLM translator layer**
- Translators: AnthropicTranslator, OpenAICompatTranslator, GeminiTranslator, CohereTranslator, MistralTranslator, OllamaTranslator, BedrockTranslator, VertexAITranslator, LlamaCppTranslator
- `RedundantTranslator` — dual-model consensus with semantic comparison
- Injection filter (google-re2 ReDoS-safe) + calibrated scorer (scikit-learn optional)
- `_sanitise.py` — Unicode normalization, size limits, explicit `InputTooLongError`

**Ecosystem integrations**
- FastAPI/ASGI middleware (`PramanixMiddleware`, `pramanix_route`)
- LangChain (`PramanixGuardedTool`, `wrap_tools`)
- LangGraph (`PramanixGuardNode`, `pramanix_node`, `GuardNodeAdapterProtocol`)
- LlamaIndex (`PramanixFunctionTool`, `PramanixQueryEngineTool`)
- AutoGen (`PramanixToolCallback`)
- CrewAI, DSPy, Haystack, Semantic Kernel, PydanticAI (beta)
- `AgentOrchestrationAdapter` Protocol for framework-agnostic wiring

**Governance**
- IFC (Information Flow Control) with lattice labels
- Privilege separation with `CapabilityManifest`
- Human oversight with `ApprovalWorkflow` (in-memory; DB-backed planned)
- Execution scope with `ExecutionScope`

**Audit**
- Merkle tamper-evident log (compression; encryption planned)
- Ed25519/RS256/ES256 signing via `DecisionSigner`
- `InMemoryAuditSink`, `StdoutAuditSink`, `DatadogAuditSink`, `SplunkHecAuditSink`, `S3AuditSink`, `KafkaAuditSink`

**Observability**
- Prometheus counters: `pramanix_guard_decisions_total`, `pramanix_solver_timeouts_total`, `pramanix_validation_failures_total`, `pramanix_audit_sink_emit_errors_total`, `pramanix_signing_failures_total`
- OpenTelemetry tracing throughout `Guard.verify()` and `Guard.parse_and_verify()`
- Structured JSON logging via structlog

**CLI (`pramanix`)**
- `pramanix doctor` — 23 environment checks across Z3, keys, observability, NLP
- `pramanix report` — governance compliance report (PDF/stdout)
- `pramanix calibrate-injection` — train `CalibratedScorer` from labelled examples
- `pramanix verify-proof` — verify a signed Decision against its audit record

**Key providers**
- `EnvKeyProvider`, `AwsKmsKeyProvider`, `AzureKeyVaultProvider`, `GcpSecretManagerProvider`, `HashiCorpVaultProvider`

**Primitives library**
- Finance: `NegativeAmountGuard`, `ExceedsHardCap`, `BalanceSufficiency`
- Fintech: `AntiStructuringGuard`, `CollateralHaircut`, `MaxDrawdown`, `MarginCallGuard`
- Healthcare: `HIPAAMinimumNecessary`, `EmergencyOverride`
- Infrastructure: `RateLimitGuard`, `RegionRestriction`
- RBAC: `RoleHierarchy`, `PrivilegeEscalationGuard`
- Time: `TimeWindowGuard`, `BusinessHoursGuard`

**NLP validators**
- `PIIDetector`, `ToxicityScorer`, `RegexClassifier`, `SemanticSimilarityGuard`
- `InformationExtractionValidator`, `SentimentGuard`

**Circuit breaker**
- Full state-machine with Redis distributed backend
- Adaptive load shedding

**Test suite**
- 5,687 tests across unit, adversarial, property, integration, perf, benchmarks
- Zero `MagicMock`/`AsyncMock`/`patch.object()` — all real dependencies
- Coverage gate: ≥ 98%

### Changed

- `Decision` wire format: 15 keys → 17 keys (added `error_domain`, `stack_trace_hash`)
- `GuardConfig`: 29 fields → 32 fields (added `result_seal_key`, `allow_insecure_timing_leaks`, `clock`)
- `pramanix.__all__`: 157 public exports (includes `ClockProtocol`)
- `cryptography` dependency bumped to `>=46.0.7` (CVE-2026-35/36 fix)

### Known Limitations (GA-release notes)

| ID | Limitation | Severity |
|----|------------|----------|
| GA-1 | ~~Apache-2.0 copyleft~~ — **RESOLVED: re-licensed to Apache-2.0** | ✅ Resolved |
| GA-2 | LLM consensus (`RedundantTranslator`) not tested in standard CI (no API keys) | High |
| GA-3 | Merkle archive encryption opt-in (AES-256-GCM exists via `PRAMANIX_MERKLE_ARCHIVE_KEY`) | Medium |
| GA-4 | `ApprovalWorkflow`: in-memory only, no DB durability | Medium |
| GA-5 | NLP ML models (`sklearn`/`sentence-transformers`): no real ML in standard CI | Low |

### Performance (dev machine, 2026-06-02)

| Metric | Value |
|--------|-------|
| Z3 mean (3-invariant policy) | 2.3 ms |
| Z3 p50 | 2.0 ms |
| Z3 p95 | 3.3 ms |
| Z3 p99 | 3.3 ms |
| Serial throughput | ~430 calls/sec |
| Cold start (first call) | < 3,000 ms |

---

[Unreleased]: https://github.com/pramanix-dev/pramanix/compare/HEAD
