# Public API

**Pramanix 1.0.0** — Stability contract for consumers, integrators, and tools.

The stability tiers below are what `pramanix.__stability__` actually contains. They reflect which surfaces have been hardened, tested, and committed to semver protection.

---

## Stability Tiers

| Tier | Meaning |
|---|---|
| **stable** | Semver-protected. No breaking changes without a major version bump. Deprecation notice required before removal. |
| **beta** | Available and usable in production. May change in minor versions with a deprecation notice. Expect occasional API shape adjustments. |
| **experimental** | Not present in 1.0.0. |

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

All names below are exported in `pramanix.__all__` and reachable via `from pramanix import X`.

### Core — Guard / Policy / Decision

| Name | Type | Notes |
|---|---|---|
| `Guard` | class | Main entrypoint. Instantiate once per Policy type. Thread-safe after construction. |
| `GuardConfig` | frozen dataclass | All configuration. Validated at construction time. |
| `Policy` | class | Base class for all policies. Subclass to define invariants. |
| `invariant_mixin` | decorator | Compose invariants from multiple Policy subclasses at compile time. |
| `model_dump_z3` | function | Pydantic model → dict for Z3-compatible field values. |
| `Field` | class | Schema field descriptor: `Field(name, python_type, z3_sort)`. |
| `E` | class | Expression builder entry point. `E(cls.field) > E.value(100)`. |
| `ConstraintExpr` | class | DSL expression node. `&`, `\|`, `~`, `.named(label)`, `.is_in(list)`. |
| `ArrayField` | class | Descriptor for list-typed fields. Used with `ForAll` / `Exists`. |
| `DatetimeField` | class | Descriptor for datetime fields. Backed by Z3 `Int` (Unix timestamp). |
| `NestedField` | class | Descriptor for nested Pydantic model fields. Path notation: `"address.city"`. |
| `ForAll` | class | Universal quantifier over array fields. |
| `Exists` | class | Existential quantifier over array fields. |
| `Decision` | frozen dataclass | Immutable result. `allowed`, `status`, `violated_invariants`, `decision_hash`. |
| `SolverStatus` | StrEnum | `SAFE`, `UNSAFE`, `TIMEOUT`, `ERROR`, `STALE_STATE`, `VALIDATION_FAILURE`, `CONSENSUS_FAILURE`, `EXTRACTION_FAILURE`, `RATE_LIMITED`. |
| `guard` | decorator | `@guard(policy=MyPolicy, on_block="raise"\|"return")` — wraps any sync or async function. |

**`Decision` fields (13 total, schema is locked in v1.0.0):**

| Field | Type | Notes |
|---|---|---|
| `allowed` | `bool` | `True` iff `status == SAFE`. Enforced in `__post_init__`. |
| `status` | `SolverStatus` | Wire value is the `str` representation. |
| `violated_invariants` | `list[str]` | Empty on ALLOW. Invariant labels on BLOCK. |
| `explanation` | `str` | Z3 counterexample text. Empty string on ALLOW. |
| `decision_id` | `str` | UUID4. Not included in `decision_hash`. |
| `decision_hash` | `str` | SHA-256 hex over canonical fields. Deterministic. |
| `policy` | `str` | Policy class name. |
| `solver_time_ms` | `float` | Wall time for Z3 solve (0.0 for non-Z3 outcomes). |
| `metadata` | `dict` | Caller-supplied or Guard-populated context. |
| `intent_dump` | `dict \| None` | Captured intent values at verify() time. |
| `state_dump` | `dict \| None` | Captured state values at verify() time. |
| `signature` | `str \| None` | Ed25519 hex signature if `GuardConfig.signer` was set. |
| `public_key_id` | `str \| None` | SHA-256[:16] of the signing public key. |

### Audit — Cryptographic signing and Merkle proofs

| Name | Type | Notes |
|---|---|---|
| `DecisionSigner` | class | Signs `Decision.decision_hash` with Ed25519. Factory: `DecisionSigner.from_provider(kp)`. |
| `DecisionVerifier` | class | Verifies Ed25519 signatures offline. Returns `VerificationResult`. |
| `MerkleAnchor` | class | In-memory Merkle tree. `add(id)` → `root()` → `prove(id)` → `proof.verify(root)`. |
| `PersistentMerkleAnchor` | class | `MerkleAnchor` + `checkpoint_callback` every N additions. |
| `MerkleArchiver` | class | Segment-based bulk archival. Writes `.merkle.archive.YYYYMMDD` files. `verify_archive(path)` for offline checks. |

`VerificationResult` fields: `valid: bool`, `policy_hash: str`, `issued_at: int` (always `0` — see DECISIONS.md § 16).

### Crypto — Ed25519 key management

| Name | Type | Notes |
|---|---|---|
| `PramanixSigner` | class | `sign(decision) → hex`. `generate()` creates ephemeral keypair. |
| `PramanixVerifier` | class | `verify(decision) → bool`. Never raises; returns `False` on any failure. |

### Circuit Breaker

| Name | Type | Notes |
|---|---|---|
| `AdaptiveCircuitBreaker` | class | States: `CLOSED → OPEN → HALF_OPEN → CLOSED`. 3 consecutive OPEN episodes → `ISOLATED`. |
| `CircuitBreakerConfig` | dataclass | `pressure_threshold_ms`, `open_duration_s`, `probe_count`, `sync_mode`. |
| `DistributedCircuitBreaker` | class | Shares circuit state across replicas via pluggable backend. |
| `InMemoryDistributedBackend` | class | In-process backend. Useful for testing. |
| `RedisDistributedBackend` | class | Redis sorted-sets + pubsub backend. Requires `redis` installed. |

### Execution Token — TOCTOU gap closure

| Name | Type | Notes |
|---|---|---|
| `ExecutionToken` | dataclass | HMAC-SHA256 single-use token. Fields: `token_id`, `decision_id`, `policy_hash`, `expires_at`, `signature`. |
| `ExecutionTokenSigner` | class | `mint(decision, ttl_seconds=30) → ExecutionToken`. |
| `ExecutionTokenVerifier` | Protocol | `consume(token, expected_state_version) → bool`. Must be called at execution time. |
| `InMemoryExecutionTokenVerifier` | class | In-process consumed-set. Not durable — restart clears it. See KNOWN_GAPS.md § 1. |
| `SQLiteExecutionTokenVerifier` | class | WAL-mode SQLite. Survives restarts. Single-host only. |
| `PostgresExecutionTokenVerifier` | class | Advisory-lock based. Multi-server safe. Requires `asyncpg`. |
| `RedisExecutionTokenVerifier` | class | SETNX-based. Multi-server safe. Requires `redis`. |

### Key Provider — Key sourcing abstraction

| Name | Type | Notes |
|---|---|---|
| `KeyProvider` | Protocol | `private_key_pem()`, `public_key_pem()`, `key_version()`, `rotate_key()`. |
| `PemKeyProvider` | class | PEM string literal. For testing and simple deployments. |
| `EnvKeyProvider` | class | Reads from `PRAMANIX_SIGNING_KEY_PEM` env var. |
| `FileKeyProvider` | class | Reads PEM from a file path. |
| `AwsKmsKeyProvider` | class | AWS Secrets Manager. Requires `pip install 'pramanix[aws]'`. Mock-only tested in CI. |
| `AzureKeyVaultKeyProvider` | class | Azure Key Vault. Requires `pip install 'pramanix[azure]'`. Mock-only tested in CI. |
| `GcpKmsKeyProvider` | class | GCP Secret Manager. Requires `pip install 'pramanix[gcp]'`. Mock-only tested in CI. |
| `HashiCorpVaultKeyProvider` | class | HashiCorp Vault KV v2. Requires `pip install 'pramanix[vault]'`. Mock-only tested in CI. |

### Compliance — Regulatory citation reporter

| Name | Type | Notes |
|---|---|---|
| `ComplianceReporter` | class | Maps `violated_invariants` labels to regulatory citations. |
| `ComplianceReport` | dataclass | `verdict`, `severity`, `rationale`, `regulatory_refs`. |

`to_json()` produces audit-ready JSON. `to_pdf()` produces a valid PDF (header tested; layout not tested). See KNOWN_GAPS.md § 13.

### Audit Sinks — Durable decision emission

| Name | Type | Notes |
|---|---|---|
| `AuditSink` | Protocol | `emit(decision: Decision) -> None`. Must not raise. |
| `StdoutAuditSink` | class | Structured JSON to stdout. No extra deps. |
| `InMemoryAuditSink` | class | Appends to a list. For testing. |
| `KafkaAuditSink` | class | Requires `pip install 'pramanix[kafka]'`. Mock-only tested in CI. |
| `S3AuditSink` | class | Requires `pip install 'pramanix[s3]'` or `'pramanix[aws]'`. Mock-only tested in CI. |
| `SplunkHecAuditSink` | class | Requires `pip install 'pramanix[splunk]'`. Mock-only tested in CI. |
| `DatadogAuditSink` | class | Requires `pip install 'pramanix[datadog]'`. Mock-only tested in CI. |

Sink failures are caught by Guard and logged. They never propagate to the caller or affect the returned Decision.

### Primitives — Pre-built policy mixins

Primitives are `stable` but are not individually listed in `__all__`. Import directly from submodules:

```python
from pramanix.primitives.finance  import NonNegativeBalance, UnderDailyLimit, UnderSingleTxLimit
from pramanix.primitives.fintech  import HFTWashTradePolicy
from pramanix.primitives.healthcare import HIPAAPolicy
from pramanix.primitives.rbac     import RBACPolicy, RoleMustBeIn
from pramanix.primitives.time     import WithinTimeWindow, NotExpired
from pramanix.primitives.infra    import MinReplicas, WithinCPUBudget
from pramanix.primitives.common   import NotSuspended
```

`fintech.py` and `healthcare.py` carry legal disclaimers. These are correctly implemented constraint patterns, not compliance advice.

### Exceptions

All exception classes are stable subclasses of `PramanixError`.

| Name | When raised |
|---|---|
| `PramanixError` | Base class. |
| `ConfigurationError` | Invalid `GuardConfig`, musl detection, policy fingerprint mismatch. |
| `PolicyError` | Empty invariants list. |
| `InvariantLabelError` | Missing or duplicate invariant label. |
| `PolicyCompilationError` | DSL expression cannot be lowered to Z3 AST. Accidental `and`/`or` on `ConstraintExpr`. |
| `TranspileError` | Z3 AST construction failure inside transpiler. |
| `SolverError` | Z3 internal error (not timeout). |
| `SolverTimeoutError` | Z3 exceeded `solver_timeout_ms`. |
| `ValidationError` | Pydantic strict-mode rejection. |
| `StateValidationError` | Policy state model missing `state_version` field. |
| `FieldTypeError` | Unsupported Python type in a `Field` descriptor. |
| `GuardError` | Internal Guard error (wraps unexpected exceptions). |
| `GuardViolationError` | Raised by `@guard` decorator on BLOCK decisions. |
| `WorkerError` | Worker pool internal error. |
| `ExtractionFailureError` | LLM extraction failed (translator). |
| `ExtractionMismatchError` | Dual-model consensus disagreement (translator). |
| `InjectionBlockedError` | Injection score ≥ threshold. |
| `InputTooLongError` | Input exceeded `max_input_chars`. |
| `LLMTimeoutError` | LLM call timed out (translator). |
| `SemanticPolicyViolation` | Semantic post-consensus check failed. |

### Miscellaneous stable exports

| Name | Type | Notes |
|---|---|---|
| `ResolverRegistry` | class | Per-request ContextVar-scoped field resolution cache. |
| `PolicyMigration` | dataclass | `migrate(state)`, `can_migrate(state)`. Declarative schema migration between semver versions. |
| `PolicyAuditor` | class | Static invariant-coverage analysis. `uncovered_fields()` misses custom `ConstraintExpr` subclasses — see KNOWN_GAPS.md § 11. |
| `StringEnumField` | class | String → integer enum helper for Z3 fields. |
| `JWTIdentityLinker` | class | Links JWT `sub` claim to intent fields. Verifies signature before decoding any claim. |
| `InvariantASTCache` | class | Pre-compiled expression tree metadata created by `compile_policy()`. |

---

## Beta Public API

Beta surfaces are available in 1.0.0 and usable in production. API shape may change in a minor version with a deprecation notice.

### Translator — LLM intent extraction

```python
from pramanix.translator.redundant       import extract_with_consensus, ConsensusStrictness
from pramanix.translator.injection_scorer import InjectionScorer, BuiltinScorer, CalibratedScorer
```

| Name | Notes |
|---|---|
| `extract_with_consensus` | Calls two translators concurrently. Raises `ExtractionMismatchError` on disagreement. Wrapped by `Guard.parse_and_verify()`. |
| `ConsensusStrictness` | `"semantic"` (Decimal-normalised, case-insensitive) or `"strict"` (exact string equality). |
| `InjectionScorer` | Protocol: `score(text: str) -> float`. |
| `BuiltinScorer` | Heuristic scorer. 30+ OWASP injection patterns. No extra deps. |
| `CalibratedScorer` | sklearn `TfidfVectorizer + LogisticRegression`. Requires `pip install 'pramanix[sklearn]'`. Train with `pramanix calibrate-injection`. |

### Integrations — Framework adapters

Adapters call `Guard.verify()` or `Guard.parse_and_verify()`. They contain no policy logic.

**Tested integrations** (real library objects used in tests, not mocks):

```python
from pramanix.integrations.fastapi   import PramanixMiddleware
from pramanix.integrations.langchain  import PramanixGuardedTool
from pramanix.integrations.llamaindex import PramanixFunctionTool, PramanixQueryEngineTool
from pramanix.integrations.autogen   import PramanixToolCallback
```

**Present but stub-level** (class present, minimal test coverage, may not work against real framework versions):

```python
from pramanix.integrations.crewai          import PramanixCrewAITool
from pramanix.integrations.dspy            import PramanixGuardedModule
from pramanix.integrations.haystack        import HaystackGuardedComponent
from pramanix.integrations.pydantic_ai     import PramanixPydanticAIValidator
from pramanix.integrations.semantic_kernel import PramanixSemanticKernelPlugin
```

**Transport interceptors** (direct submodule import required — `interceptors/__init__.py` does not re-export):

```python
from pramanix.interceptors.grpc  import PramanixGrpcInterceptor
from pramanix.interceptors.kafka import PramanixKafkaConsumer
```

**Kubernetes admission webhook:**

```python
from pramanix.k8s.webhook import AdmissionWebhook
```

### Fast Path — O(1) Python pre-screen

```python
from pramanix import FastPathRule, SemanticFastPath
```

```python
FastPathRule = Callable[[intent_dict, state_dict], str | None]
# str  → block with that string as the reason
# None → pass through to Z3
# Exceptions → logged, treated as None (safe degradation)
```

Configured via `GuardConfig(fast_path_enabled=True, fast_path_rules=[...])`.

Built-in factory rules in `pramanix.fast_path`:
`negative_amount`, `zero_or_negative_balance`, `account_frozen`, `exceeds_hard_cap`, `amount_exceeds_balance`.

---

## Advanced Identity

```python
from pramanix.identity.linker       import JWTIdentityLinker, IdentityClaims, StateLoader
from pramanix.identity.redis_loader import RedisStateLoader
```

Zero-trust constraint: `JWTIdentityLinker` verifies the JWT signature before decoding any claims. Caller-provided request body state is always ignored; state is loaded exclusively via the verified `sub` claim.

---

## IFC, Privilege, Oversight, Memory, Lifecycle, Provenance

These six subsystems ship in 1.0.0 and are beta stability.

```python
from pramanix.ifc.enforcer    import FlowEnforcer
from pramanix.ifc.flow_policy import FlowPolicy, FlowRule, FlowDecision, TrustLabel, ClassifiedData
from pramanix.privilege.scope import ExecutionScope, ExecutionContext, ScopeEnforcer
from pramanix.oversight.workflow import InMemoryApprovalWorkflow, ApprovalRequest, ApprovalDecision
from pramanix.memory.store    import SecureMemoryStore, ScopedMemoryPartition
from pramanix.lifecycle.diff  import PolicyDiff, ShadowEvaluator
from pramanix.provenance      import ProvenanceRecord, ProvenanceChain
```

---

## Internal — Not public API

Do not import these directly. They have no stability guarantees.

| Module | Notes |
|---|---|
| `pramanix.solver` | Z3 invocation. Called only by Guard. |
| `pramanix.transpiler` | DSL AST → Z3 AST. Called only by Guard and solver. |
| `pramanix.guard_pipeline` | Semantic checks, fingerprinting. Called only by Guard. |
| `pramanix._platform` | musl detection. Runs at import time of `pramanix.guard`. |
| `pramanix.validator` | Pydantic strict-mode wrappers. Called only by Guard. |
| `pramanix.guard_config` | Private Prometheus/OTel helpers. `GuardConfig` itself is public. |
| `pramanix.helpers.serialization` | Internal dict flattening utilities. |
| `pramanix.translator.*` (individual files) | Use `extract_with_consensus` and scorer classes. |
| `pramanix.translator._sanitise` | Unicode normalisation internals. |
| `pramanix.translator._prompt` | Pydantic schema → system prompt templating. |
| `pramanix.translator._json` | Robust JSON extraction from LLM outputs. |

---

## Optional Extras

```bash
pip install 'pramanix[translator]'       # httpx, openai, anthropic, tenacity
pip install 'pramanix[otel]'             # opentelemetry-sdk, otlp-exporter
pip install 'pramanix[fastapi]'          # fastapi, starlette, httpx
pip install 'pramanix[langchain]'        # langchain-core
pip install 'pramanix[llamaindex]'       # llama-index-core
pip install 'pramanix[autogen]'          # pyautogen
pip install 'pramanix[identity]'         # redis (JWT identity + state loader)
pip install 'pramanix[audit]'            # fpdf2 (PDF compliance report)
pip install 'pramanix[crypto]'           # cryptography (Ed25519 signing)
pip install 'pramanix[aws]'              # boto3 (AWS KMS + S3 sink)
pip install 'pramanix[azure]'            # azure-keyvault-secrets, azure-identity
pip install 'pramanix[gcp]'              # google-cloud-secret-manager
pip install 'pramanix[vault]'            # hvac (HashiCorp Vault)
pip install 'pramanix[kafka]'            # confluent-kafka
pip install 'pramanix[s3]'              # boto3 (S3 audit sink only)
pip install 'pramanix[datadog]'          # datadog-api-client
pip install 'pramanix[splunk]'           # httpx (Splunk HEC)
pip install 'pramanix[postgres]'         # asyncpg
pip install 'pramanix[cohere]'           # cohere
pip install 'pramanix[gemini]'           # google-generativeai
pip install 'pramanix[mistral]'          # mistralai
pip install 'pramanix[llamacpp]'         # llama-cpp-python
pip install 'pramanix[crewai]'           # crewai
pip install 'pramanix[dspy]'             # dspy-ai
pip install 'pramanix[pydantic-ai]'      # pydantic-ai
pip install 'pramanix[semantic-kernel]'  # semantic-kernel
pip install 'pramanix[haystack]'         # haystack-ai
pip install 'pramanix[all]'              # everything above
```


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
