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
    "core":            "stable",   # Guard, Policy, Decision, DSL, exceptions
    "audit":           "stable",   # DecisionSigner/Verifier, MerkleAnchor
    "crypto":          "stable",   # PramanixSigner/Verifier
    "circuit_breaker": "stable",   # AdaptiveCircuitBreaker, DistributedCircuitBreaker
    "execution_token": "stable",   # ExecutionToken, all verifier backends
    "key_provider":    "stable",   # KeyProvider protocol + all implementations
    "compliance":      "stable",   # ComplianceReporter, ComplianceReport
    "audit_sinks":     "stable",   # AuditSink protocol + all implementations
    "worker":          "stable",   # WorkerPool, execution modes
    "primitives":      "stable",   # All primitive mixins
    "translator":      "beta",     # LLM extraction, injection scoring
    "integrations":    "beta",     # Framework adapters
    "fast_path":       "beta",     # FastPathRule, SemanticFastPath
    "ifc":             "beta",     # FlowEnforcer, FlowPolicy, TrustLabel
    "privilege":       "beta",     # ExecutionScope, ScopeEnforcer, CapabilityManifest
    "oversight":       "beta",     # InMemoryApprovalWorkflow, EscalationQueue
    "memory":          "beta",     # SecureMemoryStore, ScopedMemoryPartition
    "lifecycle":       "beta",     # PolicyDiff, ShadowEvaluator
    "provenance":      "beta",     # ProvenanceRecord, ProvenanceChain
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

### DSL string operations

`E(field)` exposes the following methods for `String`-sorted fields. These are the exact method names — they differ from Python builtins:

| Method | Signature | Notes |
|---|---|---|
| `.starts_with(prefix)` | `str → ConstraintExpr` | Equivalent to Z3 `PrefixOf`. |
| `.ends_with(suffix)` | `str → ConstraintExpr` | Equivalent to Z3 `SuffixOf`. |
| `.contains(substring)` | `str → ConstraintExpr` | Equivalent to Z3 `Contains`. |
| `.matches_re(pattern)` | `str → ConstraintExpr` | Z3 regex match; pattern is a Python `re`-syntax string. |
| `.length_between(lo, hi)` | `int, int → ConstraintExpr` | Length in `[lo, hi]` inclusive. |
| `.is_in(values)` | `Iterable → ConstraintExpr` | Membership test over any iterable of comparable values. |

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
| `InMemoryExecutionTokenVerifier` | class | In-process consumed-set. Not durable — restart clears it. See `KNOWN_GAPS.md § 1`. |
| `SQLiteExecutionTokenVerifier` | class | WAL-mode SQLite. Survives restarts. Single-host only. |
| `PostgresExecutionTokenVerifier` | class | Multi-server safe. Requires `pip install 'pramanix[postgres]'`. |
| `RedisExecutionTokenVerifier` | class | SETNX-based. Multi-server safe. Requires `pip install 'pramanix[identity]'`. |

### Key Provider — Key sourcing abstraction

Built-in providers are exported from `pramanix` directly. Cloud providers must be imported from `pramanix.key_provider` — they are not re-exported at the top level.

| Name | Import | Notes |
|---|---|---|
| `KeyProvider` | `from pramanix import KeyProvider` | Protocol: `private_key_pem()`, `public_key_pem()`, `key_version()`, `rotate_key()`. |
| `PemKeyProvider` | `from pramanix import PemKeyProvider` | PEM string literal. For testing and simple deployments. |
| `EnvKeyProvider` | `from pramanix import EnvKeyProvider` | Reads from `PRAMANIX_SIGNING_KEY_PEM` env var. |
| `FileKeyProvider` | `from pramanix import FileKeyProvider` | Reads PEM from a file path. |
| `AwsKmsKeyProvider` | `from pramanix.key_provider import ...` | AWS Secrets Manager. Requires `pip install 'pramanix[aws]'`. Mock-only tested in CI. |
| `AzureKeyVaultKeyProvider` | `from pramanix.key_provider import ...` | Azure Key Vault. Requires `pip install 'pramanix[azure]'`. Mock-only tested in CI. |
| `GcpKmsKeyProvider` | `from pramanix.key_provider import ...` | GCP Secret Manager. Requires `pip install 'pramanix[gcp]'`. Mock-only tested in CI. |
| `HashiCorpVaultKeyProvider` | `from pramanix.key_provider import ...` | HashiCorp Vault KV v2. Requires `pip install 'pramanix[vault]'`. Mock-only tested in CI. |

### Compliance — Regulatory citation reporter

| Name | Type | Notes |
|---|---|---|
| `ComplianceReporter` | class | Maps `violated_invariants` labels to regulatory citations. |
| `ComplianceReport` | dataclass | `verdict`, `severity`, `rationale`, `regulatory_refs`. |

`to_json()` produces audit-ready JSON. `to_pdf()` produces a valid PDF (header tested; multi-page layout not tested — see `KNOWN_GAPS.md § 11`).

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

Sink failures are caught by Guard and logged. They never propagate to the caller or affect the returned `Decision`.

### Primitives — Pre-built policy mixins

Primitives are `stable` but are not individually listed in `__all__`. Import directly from submodules:

```python
from pramanix.primitives.finance    import NonNegativeBalance, UnderDailyLimit, UnderSingleTxLimit
from pramanix.primitives.fintech    import HFTWashTradePolicy
from pramanix.primitives.healthcare import HIPAAPolicy
from pramanix.primitives.rbac       import RBACPolicy, RoleMustBeIn
from pramanix.primitives.time       import WithinTimeWindow, NotExpired
from pramanix.primitives.infra      import MinReplicas, WithinCPUBudget
from pramanix.primitives.common     import NotSuspended
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
| `FlowViolationError` | IFC flow policy violation. |
| `PrivilegeEscalationError` | Privilege scope boundary crossed. |
| `MemoryViolationError` | Secure memory access violation. |
| `OversightRequiredError` | Action requires human approval before execution. |
| `ProvenanceError` | Chain-of-custody record error. |
| `MigrationError` | Schema migration failure. |
| `ResolverConflictError` | Duplicate resolver registration. |

### Miscellaneous stable exports

| Name | Type | Notes |
|---|---|---|
| `ResolverRegistry` | class | Per-request ContextVar-scoped field resolution cache. |
| `PolicyMigration` | dataclass | `migrate(state)`, `can_migrate(state)`. Declarative schema migration between semver versions. |
| `PolicyAuditor` | class | Static invariant-coverage analysis. `uncovered_fields()` misses custom `ConstraintExpr` subclasses — see `KNOWN_GAPS.md § 9`. |
| `StringEnumField` | class | String → integer enum helper for Z3 fields. |
| `JWTIdentityLinker` | class | Links JWT `sub` claim to intent fields. Verifies signature before decoding any claim. |
| `InvariantASTCache` | class | Pre-compiled expression tree metadata created by `compile_policy()`. |

---

## Beta Public API

Beta surfaces are available in 1.0.0 and usable in production. API shape may change in a minor version with a deprecation notice.

### Translator — LLM intent extraction

```python
from pramanix.translator.redundant        import extract_with_consensus, ConsensusStrictness
from pramanix.translator.injection_scorer import InjectionScorer, BuiltinScorer, CalibratedScorer
```

| Name | Notes |
|---|---|
| `extract_with_consensus` | Calls two translators concurrently. Raises `ExtractionMismatchError` on disagreement. Wrapped by `Guard.parse_and_verify()`. |
| `ConsensusStrictness` | `"semantic"` (Decimal-normalised, case-insensitive) or `"strict"` (exact string equality). |
| `InjectionScorer` | Protocol: `score(text: str) -> float`. |
| `BuiltinScorer` | Heuristic scorer. 30+ OWASP injection patterns. No extra deps. |
| `CalibratedScorer` | sklearn `TfidfVectorizer + LogisticRegression`. Requires `scikit-learn`. Train with `pramanix calibrate-injection`. See `KNOWN_GAPS.md § 10`. |

### Integrations — Framework adapters

Adapters call `Guard.verify()` or `Guard.parse_and_verify()`. They contain no policy logic.

**Tested integrations** (real library objects used in tests, not mocks):

```python
from pramanix.integrations.fastapi    import PramanixMiddleware
from pramanix.integrations.langchain  import PramanixGuardedTool
from pramanix.integrations.llamaindex import PramanixFunctionTool, PramanixQueryEngineTool
from pramanix.integrations.autogen    import PramanixToolCallback
```

**Present but stub-level** (class present, minimal test coverage, may not work against real framework versions — see `KNOWN_GAPS.md § 8`):

```python
from pramanix.integrations.crewai          import PramanixCrewAITool
from pramanix.integrations.dspy            import PramanixGuardedModule
from pramanix.integrations.haystack        import HaystackGuardedComponent
from pramanix.integrations.pydantic_ai     import PramanixPydanticAIValidator
from pramanix.integrations.semantic_kernel import PramanixSemanticKernelPlugin
```

**Transport interceptors** (direct submodule import required — `interceptors/__init__.py` `__all__` is declared but not functional — see `KNOWN_GAPS.md § 6`):

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

`FastPathRule = Callable[[intent_dict, state_dict], str | None]`

- `str` return → block immediately with that string as the reason
- `None` return → pass through to Z3
- Exceptions → logged, treated as `None` (safe degradation)

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

These six subsystems ship in 1.0.0 at `beta` stability. No integration tests against Guard exist yet — see `KNOWN_GAPS.md § 13`.

```python
from pramanix.ifc.enforcer       import FlowEnforcer
from pramanix.ifc.flow_policy    import FlowPolicy, FlowRule, FlowDecision, TrustLabel, ClassifiedData
from pramanix.privilege.scope    import ExecutionScope, ExecutionContext, ScopeEnforcer
from pramanix.oversight.workflow import InMemoryApprovalWorkflow, ApprovalRequest, ApprovalDecision
from pramanix.memory.store       import SecureMemoryStore, ScopedMemoryPartition
from pramanix.lifecycle.diff     import PolicyDiff, ShadowEvaluator
from pramanix.provenance         import ProvenanceRecord, ProvenanceChain
```

All six are also re-exported from `pramanix` top-level (see `__init__.py`).

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
