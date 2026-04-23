# Public API

**Pramanix 1.0.0** — Stability contract for consumers, integrators, and tools.

The stability tiers below are what `pramanix.__stability__` actually contains. They are not aspirational — they reflect which surfaces have been hardened, tested, and committed to semver protection.

---

## Stability Tiers

| Tier | Meaning |
|---|---|
| **stable** | Public API. Semver-protected. No breaking changes without a major version bump. Deprecation notice required before removal. |
| **beta** | Available and usable in production. May change in minor versions with a deprecation notice. Expect occasional API shape adjustments. |
| **experimental** | Not available in 1.0.0. If added in future versions, will be labelled as such. |

```python
pramanix.__stability__ == {
    "core":            "stable",
    "audit":           "stable",
    "crypto":          "stable",
    "circuit_breaker": "stable",
    "execution_token": "stable",
    "key_provider":    "stable",
    "compliance":      "stable",
    "audit_sinks":     "stable",
    "worker":          "stable",
    "primitives":      "stable",
    "translator":      "beta",
    "integrations":    "beta",
    "fast_path":       "beta",
}
```

---

## Stable Public API

All names listed below are exported in `pramanix.__all__`.

### Core — Guard / Policy / Decision

| Name | Type | Notes |
|---|---|---|
| `Guard` | class | Main entrypoint. Instantiate once per Policy type. |
| `GuardConfig` | frozen dataclass | All configuration for a Guard instance. |
| `Policy` | class | Base class for all policies. Subclass to define invariants. |
| `invariant_mixin` | function | Combine invariants from multiple Policy mixin classes. |
| `model_dump_z3` | function | Pydantic model → dict for Z3-compatible field values. |
| `Field` | class | Schema field descriptor (name, Python type, Z3 sort). |
| `E` | class | Expression builder entry point. `E.field > E.value(100)`. |
| `ConstraintExpr` | class | DSL expression node (returned by `E`). |
| `ForAll` | class | Universal quantifier over array fields. |
| `Exists` | class | Existential quantifier over array fields. |
| `ArrayField` | class | Z3-mapped array field descriptor. |
| `DatetimeField` | class | Z3-mapped datetime field descriptor. |
| `NestedField` | class | Descriptor for nested Pydantic model fields. |
| `Decision` | frozen dataclass | Immutable result of `Guard.verify()`. |
| `SolverStatus` | enum | `SAFE`, `UNSAFE`, `TIMEOUT`, `ERROR`, `STALE_STATE`, `VALIDATION_FAILURE`. |
| `guard` | decorator | `@guard(policy=MyPolicy)` — wraps a function to enforce a policy. |

### Audit — Cryptographic signing and Merkle proofs

| Name | Type | Notes |
|---|---|---|
| `DecisionSigner` | class | Signs `Decision.decision_hash` with Ed25519. |
| `DecisionVerifier` | class | Verifies Ed25519 signature offline. |
| `MerkleAnchor` | class | In-memory Merkle tree. `add(decision_id)` → `root()` → `prove()`. |
| `PersistentMerkleAnchor` | class | `MerkleAnchor` + checkpoint callback every N additions. |
| `MerkleArchiver` | class | Bulk export and pruning of anchored batches. |

### Crypto — Ed25519 key management

| Name | Type | Notes |
|---|---|---|
| `PramanixSigner` | class | Ed25519 signer. `sign(decision) → hex_signature`. |
| `PramanixVerifier` | class | Ed25519 verifier. `verify(decision) → bool`. |

### Circuit Breaker — Adaptive fail-closed breaker

| Name | Type | Notes |
|---|---|---|
| `AdaptiveCircuitBreaker` | class | Adaptive CB. States: `CLOSED`, `OPEN`, `HALF_OPEN`, `ISOLATED`. |
| `CircuitBreakerConfig` | dataclass | Configuration for `AdaptiveCircuitBreaker`. |
| `DistributedCircuitBreaker` | class | Distributed CB backed by an `InMemoryDistributedBackend` or `RedisDistributedBackend`. |
| `InMemoryDistributedBackend` | class | In-process backend for `DistributedCircuitBreaker`. |
| `RedisDistributedBackend` | class | Redis-backed backend for `DistributedCircuitBreaker`. |

### Execution Token — TOCTOU gap closer

| Name | Type | Notes |
|---|---|---|
| `ExecutionToken` | dataclass | HMAC-SHA256 single-use token (30 s TTL by default). |
| `ExecutionTokenSigner` | class | Mints `ExecutionToken` instances. |
| `ExecutionTokenVerifier` | Protocol | Consume-and-validate interface. |
| `InMemoryExecutionTokenVerifier` | class | In-process consumed-set (thread-safe, not durable). |
| `SQLiteExecutionTokenVerifier` | class | SQLite-backed verifier. |
| `PostgresExecutionTokenVerifier` | class | PostgreSQL-backed verifier. |
| `RedisExecutionTokenVerifier` | class | Redis-backed verifier. |

### Key Provider — Key sourcing abstraction

| Name | Type | Notes |
|---|---|---|
| `KeyProvider` | Protocol | `private_key_pem() / public_key_pem() / key_version() / rotate_key()`. |
| `PemKeyProvider` | class | PEM string literal — for testing and simple deployments. |
| `EnvKeyProvider` | class | `PRAMANIX_SIGNING_KEY_PEM` environment variable. |
| `FileKeyProvider` | class | Reads PEM from a file path. |
| `AwsKmsKeyProvider` | class | AWS Secrets Manager. Requires `pip install 'pramanix[aws]'`. |
| `AzureKeyVaultKeyProvider` | class | Azure Key Vault. Requires `pip install 'pramanix[azure]'`. |
| `GcpKmsKeyProvider` | class | GCP Secret Manager. Requires `pip install 'pramanix[gcp]'`. |
| `HashiCorpVaultKeyProvider` | class | HashiCorp Vault KV v2. Requires `pip install 'pramanix[vault]'`. |

### Compliance — Regulatory citation reporter

| Name | Type | Notes |
|---|---|---|
| `ComplianceReporter` | class | Maps `violated_invariants` labels to regulatory citations. |
| `ComplianceReport` | dataclass | Structured report: verdict, severity, rationale, regulatory refs. |

### Audit Sinks — Durable decision emission

| Name | Type | Notes |
|---|---|---|
| `AuditSink` | Protocol | `emit(decision: Decision) -> None`. Must not raise. |
| `StdoutAuditSink` | class | Structured JSON to stdout. No extra deps. |
| `InMemoryAuditSink` | class | Appends to a list. For testing. No extra deps. |
| `KafkaAuditSink` | class | Requires `pip install 'pramanix[kafka]'`. |
| `S3AuditSink` | class | Requires `pip install 'pramanix[s3]'`. |
| `SplunkHecAuditSink` | class | Requires `pip install 'pramanix[splunk]'`. |
| `DatadogAuditSink` | class | Requires `pip install 'pramanix[datadog]'`. |

### Primitives — Pre-built policy mixins

All primitive mixin classes are in the `pramanix.primitives.*` submodules and are re-exported for direct import. They are `stable` but not individually listed in the top-level `__all__`. Import directly:

```python
from pramanix.primitives.fintech import HFTWashTradePolicy
from pramanix.primitives.healthcare import HIPAAPolicy
from pramanix.primitives.rbac import RBACPolicy
```

### Exceptions

All exception classes are stable. They are all subclasses of `PramanixError`.

| Name | When |
|---|---|
| `PramanixError` | Base class. |
| `ConfigurationError` | Invalid `GuardConfig`, musl detection, policy fingerprint mismatch. |
| `PolicyError` | Empty invariants list. |
| `InvariantLabelError` | Missing or duplicate invariant label. |
| `PolicyCompilationError` | DSL expression cannot be lowered to Z3 AST. |
| `TranspileError` | Z3 AST construction failure inside transpiler. |
| `SolverError` | Z3 internal error (not timeout). |
| `SolverTimeoutError` | Z3 exceeded `solver_timeout_ms`. |
| `ValidationError` | Pydantic strict-mode rejection of caller data. |
| `StateValidationError` | Policy state model missing `state_version` field. |
| `GuardError` | Internal Guard error (wraps unexpected exceptions). |
| `GuardViolationError` | Raised by `@guard` decorator on BLOCK decisions. |
| `FieldTypeError` | Unsupported Python type in a `Field` descriptor. |
| `WorkerError` | Worker pool internal error. |
| `ExtractionFailureError` | LLM extraction failed (translator). |
| `ExtractionMismatchError` | Dual-model consensus disagreement (translator). |
| `InjectionBlockedError` | Injection score ≥ threshold blocked the request. |
| `InputTooLongError` | Input exceeded `max_input_chars`. |
| `LLMTimeoutError` | LLM call timed out (translator). |
| `SemanticPolicyViolation` | Semantic post-consensus check failed. |

### Miscellaneous stable exports

| Name | Type | Notes |
|---|---|---|
| `ResolverRegistry` | class | Per-request ContextVar-scoped field resolution cache. |
| `PolicyMigration` | dataclass | Declarative schema migration between semver versions. |
| `PolicyAuditor` | class | Static invariant-coverage analysis. |
| `StringEnumField` | class | String → integer enum helper for Z3 fields. |
| `JWTIdentityLinker` | class | Links JWT identity claims to intent fields. |

---

## Beta Public API

Beta surfaces are available in 1.0.0 and usable in production, but their API shape may change in a minor version release. A deprecation notice will precede any breaking change.

### Translator — LLM intent extraction

```python
from pramanix.translator.redundant import extract_with_consensus, ConsensusStrictness
from pramanix.translator.injection_scorer import InjectionScorer, BuiltinScorer, CalibratedScorer
```

| Name | Notes |
|---|---|
| `extract_with_consensus` | Calls two translators concurrently. Raises `ExtractionMismatchError` on disagreement. |
| `ConsensusStrictness` | Enum: `"semantic"` (Decimal-normalised, case-insensitive) or `"strict"` (exact `!=`). |
| `InjectionScorer` | Protocol: `score(text: str) -> float`. |
| `BuiltinScorer` | Heuristic scorer. No extra deps. |
| `CalibratedScorer` | sklearn `TfidfVectorizer + LogisticRegression`. Requires `pip install 'pramanix[sklearn]'`. |
| `InvariantASTCache` | Pre-compiled expression tree metadata. Created by `compile_policy`. |

### Integrations — Framework adapters

```python
from pramanix.integrations.fastapi import PramanixMiddleware
from pramanix.integrations.langchain import PramanixGuardTool
from pramanix.integrations.llamaindex import PramanixQueryEngine
from pramanix.integrations.autogen import PramanixAutoGenHook
```

Adapters for CrewAI, DSPy, Haystack, Pydantic AI, Semantic Kernel are file-present but mostly stubs. See KNOWN_GAPS.md.

### Fast Path — O(1) Python pre-screen

Configured via `GuardConfig.fast_path_enabled` and `GuardConfig.fast_path_rules`. API shape for fast path rules:

```python
FastPathRule = Callable[[intent_dict, state_dict], str | None]
# Returns None → pass through to Z3
# Returns str  → block immediately with that string as the reason
```

---

## Internal / Not Public

The following modules are **not part of the public API**. They have `__all__ = []` or are prefixed with `_`. Do not import them directly.

| Module | Notes |
|---|---|
| `pramanix.solver` | Z3 invocation. Called only by Guard. |
| `pramanix.transpiler` | DSL AST → Z3 AST. Called only by Guard and solver. |
| `pramanix.guard_pipeline` | Semantic checks, fingerprinting. Called only by Guard. |
| `pramanix._platform` | musl detection. Runs at import time of `pramanix.guard`. |
| `pramanix.validator` | Pydantic strict-mode wrappers. Called only by Guard. |
| `pramanix.guard_config` | Private Prometheus/OTel helpers. `GuardConfig` itself is public. |
| `pramanix.helpers.serialization` | Internal dict flattening utilities. |
| `pramanix.translator.*` (individual files) | Use `extract_with_consensus` and scorer classes instead. |

---

## Optional Extras

```bash
pip install 'pramanix[translator]'   # httpx, LLM extraction
pip install 'pramanix[otel]'         # OpenTelemetry tracing
pip install 'pramanix[fastapi]'      # Starlette/FastAPI middleware
pip install 'pramanix[langchain]'    # LangChain adapter
pip install 'pramanix[llamaindex]'   # LlamaIndex adapter
pip install 'pramanix[autogen]'      # AutoGen adapter
pip install 'pramanix[identity]'     # PyJWT identity linker
pip install 'pramanix[audit]'        # cryptography (Ed25519 audit signing)
pip install 'pramanix[crypto]'       # cryptography (PramanixSigner/Verifier)
pip install 'pramanix[aws]'          # boto3 (AWS KMS + S3 sink)
pip install 'pramanix[azure]'        # azure-keyvault-secrets
pip install 'pramanix[gcp]'          # google-cloud-secret-manager
pip install 'pramanix[vault]'        # hvac (HashiCorp Vault)
pip install 'pramanix[kafka]'        # confluent-kafka audit sink
pip install 'pramanix[s3]'           # boto3 S3 audit sink
pip install 'pramanix[datadog]'      # datadog audit sink
pip install 'pramanix[splunk]'       # requests Splunk HEC sink
pip install 'pramanix[pdf]'          # fpdf2 compliance PDF export
pip install 'pramanix[sklearn]'      # scikit-learn CalibratedScorer
pip install 'pramanix[all]'          # everything above
```
