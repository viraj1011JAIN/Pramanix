# Pramanix

**Deterministic Neuro-Symbolic Guardrails for Autonomous AI Agents**

Version: `1.0.0` | License: `AGPL-3.0-only` (Community) / Commercial (Enterprise)  
Language: Python ≥3.11 | Status: Beta → GA-in-progress  
Repository: `src/pramanix/` | Tests: `tests/` | CI: `.github/workflows/ci.yml`

---

## Table of Contents

1. [What This Is (And What It Is Not)](#1-what-this-is-and-what-it-is-not)
2. [Architecture Overview](#2-architecture-overview)
3. [Core Execution Pipeline](#3-core-execution-pipeline)
4. [Policy DSL — Implementation Map](#4-policy-dsl--implementation-map)
5. [Z3 SMT Solver Integration](#5-z3-smt-solver-integration)
6. [Translator Stack — Neuro-Symbolic Bridge](#6-translator-stack--neuro-symbolic-bridge)
7. [Worker Pool and Concurrency Model](#7-worker-pool-and-concurrency-model)
8. [Security Subsystems](#8-security-subsystems)
9. [Cryptographic Audit Layer](#9-cryptographic-audit-layer)
10. [Governance Gates](#10-governance-gates)
11. [Observability and Telemetry](#11-observability-and-telemetry)
12. [Framework Integrations](#12-framework-integrations)
13. [Primitives Library](#13-primitives-library)
14. [Operational Tooling](#14-operational-tooling)
15. [Test Suite Architecture](#15-test-suite-architecture)
16. [CI Pipeline](#16-ci-pipeline)
17. [Known Gaps, Flaws, and Limitations](#17-known-gaps-flaws-and-limitations)
18. [Dependency Map and Extras](#18-dependency-map-and-extras)
19. [Installation](#19-installation)
20. [Quickstart](#20-quickstart)
21. [Competitive Analysis](#21-competitive-analysis)
22. [Development Status by Component](#22-development-status-by-component)
23. [Roadmap](#23-roadmap)

---

## 1. What This Is (And What It Is Not)

Pramanix (from Sanskrit *Pramāṇa* — "proof" or "valid knowledge") is a Python SDK that places a deterministic, formally verified safety layer between an AI agent's stated intent and real-world action execution.

**What it does:**

- Accepts a structured intent dict (from an LLM or any caller) and a current-state dict
- Transpiles a Python-native policy DSL into Z3 SMT formulas
- Runs Z3 to prove safety or compute a counterexample
- Returns an immutable `Decision` object: `allowed=True` iff formal proof of safety exists, `allowed=False` with attribution in every other case
- All errors collapse to `allowed=False` — the fail-safe is unconditional

**What it does not do:**

- It is not an LLM guardrail in the "pattern-matching content filter" sense
- It cannot make probabilistic safety claims — only formal ones
- It does not replace application-level authorization (RBAC) for human users
- It does not guarantee LLM outputs are semantically meaningful, only that the extracted numeric/categorical fields satisfy declared invariants
- The NLP layer (`pramanix[translator]`) is optional and adds probabilistic preprocessing, but the formal guarantees come only from Z3 phase

**Name origin:** Pramāṇa + Unix. The "proof of valid knowledge" combined with UNIX composability philosophy.

---

## 2. Architecture Overview

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                              PRAMANIX SYSTEM BOUNDARY                            │
│                                                                                  │
│  ┌─────────────┐    ┌──────────────────────────────────────────────────────────┐ │
│  │  AI Agent   │    │                    GUARD (guard.py)                      │ │
│  │  / LLM /    │───▶│                                                          │ │
│  │  External   │    │  Step 1: Input size pre-check (max_input_bytes)          │ │
│  │  Caller     │    │  Step 2: Injection score (BuiltinScorer / CalibratedS.)  │ │
│  └─────────────┘    │  Step 3: LLM extraction (optional, via Translator)       │ │
│                     │  Step 4: Dual-model consensus check (optional)           │ │
│                     │  Step 5: Semantic post-consensus fast check              │ │
│                     │  Step 6: MESH authentication (optional)                  │ │
│                     │  Step 7: Governance gates (IFC/Privilege/Oversight)      │ │
│                     │  Step 8: Z3 SMT solving (transpile + solve)              │ │
│                     │  Step 9: Execution token issuance                        │ │
│                     │  Step 10: Audit sink + Merkle anchoring                  │ │
│                     │                                                          │ │
│                     └──────────────────────────┬───────────────────────────────┘ │
│                                                │                                  │
│                                    ┌───────────▼───────────┐                     │
│                                    │   Decision (frozen)   │                     │
│                                    │  allowed: bool        │                     │
│                                    │  status: SolverStatus │                     │
│                                    │  violated_invariants  │                     │
│                                    │  explanation: str     │                     │
│                                    │  proof / counterexamp │                     │
│                                    │  signature: Ed25519   │                     │
│                                    │  policy_hash: SHA-256 │                     │
│                                    └───────────────────────┘                     │
└──────────────────────────────────────────────────────────────────────────────────┘
```

### Package Structure

```
src/pramanix/
├── guard.py              # SDK entry point — Guard class, verify() pipeline
├── policy.py             # Policy base class, DSL field declarations
├── expressions.py        # Field, E(), ConstraintExpr, ArrayField, ForAll/Exists
├── transpiler.py         # DSL expression tree → Z3 AST lowering
├── solver.py             # Z3 wrapper, thread-local contexts, fast/attribution paths
├── compiler.py           # PolicyIR — serializable IR between Policy and Z3
├── decision.py           # Decision frozen dataclass, SolverStatus StrEnum
├── fast_path.py          # O(1) pre-Z3 Python screening rules
├── guard_config.py       # GuardConfig frozen dataclass, all knobs
├── guard_pipeline.py     # Layer-2.5 semantic post-consensus checks
├── worker.py             # ThreadPoolExecutor / ProcessPoolExecutor("spawn")
├── exceptions.py         # Full exception hierarchy (20 exception types)
│
├── translator/           # Neuro-symbolic bridge (LLM → structured intent)
│   ├── anthropic.py      # AnthropicTranslator (claude-*), tenacity retry
│   ├── openai_compat.py  # OpenAI-compat (GPT, Mistral, local)
│   ├── cohere.py         # CohereTranslator
│   ├── gemini.py         # GeminiTranslator (google-generativeai)
│   ├── bedrock.py        # BedrockTranslator (boto3, Claude/Titan/Llama/Converse)
│   ├── vertexai.py       # VertexAITranslator (google-cloud-aiplatform)
│   ├── llamacpp.py       # LlamaCppTranslator (local GGUF)
│   ├── mistral.py        # MistralTranslator
│   ├── ollama.py         # OllamaTranslator (local REST)
│   ├── redundant.py      # Dual-model consensus (strict_keys/lenient/unanimous)
│   ├── injection_scorer.py # BuiltinScorer + CalibratedScorer (sklearn, no-pickle)
│   ├── injection_filter.py # Pre-call injection filter
│   ├── _sanitise.py      # Input sanitisation + injection_confidence_score()
│   ├── _injection_patterns.py # Injection pattern library
│   ├── _json.py          # LLM JSON response parser
│   ├── _prompt.py        # System prompt builder from Pydantic schema
│   ├── _cache.py         # Intent LRU cache
│   └── base.py           # TranslatorContext, Translator Protocol
│
├── audit/                # Cryptographic audit layer
│   ├── signer.py         # DecisionSigner (HMAC-SHA256 JWS, orjson optional)
│   ├── verifier.py       # DecisionVerifier (standalone, stdlib-only)
│   ├── merkle.py         # MerkleAnchor, PersistentMerkleAnchor, MerkleProof
│   └── archiver.py       # MerkleArchiver (pruning + S3 export)
│
├── crypto.py             # PramanixSigner (Ed25519), RS256, ES256
├── audit_sink.py         # AuditSink Protocol + all sink implementations
├── execution_token.py    # HMAC-SHA256 single-use execution tokens, TOCTOU gap
├── circuit_breaker.py    # AdaptiveCircuitBreaker, DistributedCircuitBreaker
├── key_provider.py       # KeyProvider Protocol + AWS/Azure/GCP/Vault providers
│
├── nlp/                  # NLP validators
│   └── validators.py     # PIIDetector, ToxicityScorer, RegexClassifier, 7 more
│
├── mesh/                 # Zero-Trust Agent Mesh
│   └── authenticator.py  # MeshAuthenticator (SPIFFE JWT-SVID, RS256/ES256)
│
├── ifc/                  # Information Flow Control
│   ├── enforcer.py       # FlowEnforcer, gate() — raises FlowViolationError
│   ├── flow_policy.py    # FlowPolicy, FlowRule
│   └── labels.py         # TrustLabel lattice
│
├── privilege/            # Privilege Separation
│   └── scope.py          # ExecutionScope, ScopeEnforcer, CapabilityManifest
│
├── oversight/            # Human-in-the-Loop
│   └── workflow.py       # EscalationQueue, ApprovalWorkflow
│
├── compliance/           # Compliance Oracle (post-hoc, NOT hot path)
│   └── oracle.py         # ComplianceOracle: SOC2/GDPR/HIPAA/NIST/ISO42001
│
├── primitives/           # Reusable constraint factories
│   ├── fintech.py        # AntiStructuring, WashSale, Sanctions, Velocity...
│   ├── finance.py        # General finance constraints
│   ├── healthcare.py     # HIPAA/clinical constraints
│   ├── rbac.py           # Role-based access control
│   ├── infra.py          # Infrastructure safety (rate limits, resource caps)
│   ├── time.py           # Time-window constraints
│   └── roles.py          # Role definitions
│
├── integrations/         # Framework adapters (all optional)
│   ├── langchain.py      # PramanixGuardedTool (extends BaseTool)
│   ├── langgraph.py      # @pramanix_node decorator
│   ├── llamaindex.py     # PramanixFunctionTool, PramanixQueryEngineTool
│   ├── autogen.py        # PramanixToolCallback
│   ├── crewai.py         # PramanixCrewAITool
│   ├── dspy.py           # PramanixGuardedModule
│   ├── haystack.py       # HaystackGuardedComponent
│   ├── pydantic_ai.py    # PramanixPydanticAIValidator
│   ├── semantic_kernel.py # PramanixSemanticKernelPlugin
│   ├── fastapi.py        # PramanixMiddleware (ASGI) + pramanix_route decorator
│   └── agent_orchestration.py # AgentOrchestrationAdapter Protocol
│
├── natural_policy/       # Declarative YAML/TOML policy DSL
│   ├── yaml_loader.py    # load_policy_file, load_policy_yaml (safe AST)
│   ├── compiler.py       # YAML→Policy class compiler
│   ├── schemas.py        # YAML schema definitions
│   └── verifier.py       # Policy file validator
│
├── lifecycle/            # Policy lifecycle management
│   └── diff.py           # PolicyDiff, ShadowEvaluator
│
├── interceptors/         # Protocol interceptors
│   ├── grpc.py           # gRPC interceptor
│   └── kafka.py          # Kafka consumer interceptor
│
├── k8s/
│   └── webhook.py        # Kubernetes ValidatingWebhook (FastAPI)
│
├── identity/             # JWT identity + Redis state loading
│   ├── linker.py         # JWTIdentityLinker
│   └── redis_loader.py   # RedisStateLoader
│
├── memory/               # Secure scoped memory
│   └── store.py          # SecureMemoryStore, ScopedMemoryPartition
│
├── helpers/              # Internal utilities
│   ├── compliance.py     # ComplianceReport, ComplianceReporter (PDF via fpdf2)
│   ├── policy_auditor.py # PolicyAuditor — static coverage analysis
│   ├── type_mapping.py   # Python type → Z3 sort mapping
│   ├── string_enum.py    # StringEnumField coercions
│   └── serialization.py  # Serialization helpers
│
├── migration.py          # PolicyMigration — field rename across schema versions
├── provenance.py         # ProvenanceRecord + ProvenanceChain (HMAC-linked)
├── dry_run.py            # PolicyDryRun — side-effect-free batch simulation
├── decorator.py          # @guard synchronous function decorator
├── validator.py          # Standalone intent validator
├── resolvers.py          # ResolverRegistry (dynamic state field resolution)
├── logging_helpers.py    # Structlog helpers
├── governance_config.py  # GovernanceConfig dataclass
├── _platform.py          # Platform detection helpers
└── testing.py            # Test-only InMemoryExecutionTokenVerifier (not public API)
```

---

## 3. Core Execution Pipeline

### `Guard.verify()` — Six-Phase Execution

Source: [src/pramanix/guard.py](src/pramanix/guard.py)

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Guard.verify(intent, state)                                            │
│                                                                         │
│  Phase 0 — Input size guard                                             │
│    • Checks len(json(intent)) ≤ GuardConfig.max_input_bytes             │
│    • Raises InputTooLongError → Decision.error() if exceeded            │
│                                                                         │
│  Phase 1 — Resolver cache population                                    │
│    • Runs registered resolver functions to populate state fields        │
│    • Cleared in finally block (C-01: multi-tenant data bleed guard)     │
│                                                                         │
│  Phase 2 — Injection pre-screening (optional)                           │
│    • Calls InjectionScorer.score(raw_text)                              │
│    • score ≥ injection_threshold → InjectionBlockedError → BLOCK        │
│                                                                         │
│  Phase 3 — LLM extraction (optional, if translator configured)          │
│    • Translator.extract(text, intent_schema) → dict                     │
│    • Dual-model consensus via extract_with_consensus() if enabled       │
│    • Semantic post-consensus checks (_semantic_post_consensus_check)    │
│                                                                         │
│  Phase 4 — Pydantic validation                                          │
│    • IntentModel(**intent) — raises ValidationError → BLOCK             │
│    • StateModel(**state)  — raises StateValidationError → BLOCK         │
│                                                                         │
│  Phase 5 — Governance gates (_apply_governance_gates)                   │
│    • MESH authentication (MeshAuthenticator.authenticate if configured)  │
│    • IFC gate (FlowEnforcer.gate if configured)                         │
│    • Privilege scope check (ScopeEnforcer.check if configured)          │
│    • Human oversight check (ApprovalWorkflow.check if configured)       │
│                                                                         │
│  Phase 6 — Z3 SMT solving                                              │
│    • model_dump_z3() flattens Pydantic models to primitive dicts        │
│    • Transpiler lowers DSL expressions to Z3 formula AST               │
│    • solver.solve() — fast_check() then attribute_violations()          │
│    • Returns Decision.safe() or Decision.unsafe()                       │
│                                                                         │
│  Phase 7 — Timing jitter                                                │
│    • min_response_ms pad (default 0) prevents timing side-channel       │
│                                                                         │
│  Phase 8 — Execution token issuance                                     │
│    • ExecutionTokenSigner.sign(decision_id) if token_signer configured  │
│                                                                         │
│  Phase 9 — Audit                                                        │
│    • DecisionSigner.sign(decision) if signer configured                 │
│    • AuditSink.log(decision) for each configured sink                   │
│    • MerkleAnchor.append(decision) if anchor configured                 │
│                                                                         │
│  FAIL-SAFE: any exception at ANY phase → Decision.error() (BLOCK)       │
└─────────────────────────────────────────────────────────────────────────┘
```

**Critical invariant** (enforced in `Decision.__post_init__`):
```
allowed=True  ↔  status=SAFE
allowed=False ↔  status ≠ SAFE
```

This is a hard assertion, not a soft check. A `Decision` object with `allowed=True` and `status=UNSAFE` cannot be constructed.

### Three Execution Modes

| Mode | Mechanism | Use case |
|---|---|---|
| `sync` | Direct call on calling thread | Tests, scripts, single-process |
| `async-thread` | ThreadPoolExecutor | FastAPI, async frameworks |
| `async-process` | ProcessPoolExecutor("spawn") | CPU isolation, memory isolation |

For `async-process`, Pydantic models are serialized via `model_dump()` **before** `submit()` — Pydantic models are not pickle-safe. Source: `worker.py`.

---

## 4. Policy DSL — Implementation Map

Source: [src/pramanix/expressions.py](src/pramanix/expressions.py), [src/pramanix/policy.py](src/pramanix/policy.py)

### Field Types

```python
# [IMPLEMENTED] — expressions.py
Field(name, z3_type, source)   # "Real" | "Int" | "Bool" | "String"
ArrayField(name, element_type) # Array quantifiers — ForAll/Exists unrolled
DatetimeField(name)            # Stored as Int (Unix epoch milliseconds)
NestedField(parent, child)     # Chained field reference (B-1)
StringEnumField                # String field with coercion to Int for Z3
```

### Expression Operators

```python
# [IMPLEMENTED] — expressions.py
E(field)                       # Wrap a Field into an ExpressionNode
E(f) + E(g)                    # Arithmetic: BinOp (add, sub, mul, div)
E(f) == value                  # Comparison: CmpOp (eq, ne, gt, lt, gte, lte)
E(f).in_([...])                # Membership: InOp
E(f).matches(r"regex")         # Regex match: RegexMatchOp (backed by Z3 String)
E(f).contains("substr")        # String contains: ContainsOp
E(f).starts_with("prefix")     # String prefix: StartsWithOp
E(f).ends_with("suffix")       # String suffix: EndsWithOp
E(f).length_between(lo, hi)    # String length range: LengthBetweenOp
E(f) % N                       # Modulo: ModOp
E(f) ** N                      # Power: PowOp
abs(E(f))                      # Absolute value: AbsOp
ForAll(arr, lambda x: ...)     # Universal quantifier (unrolled)
Exists(arr, lambda x: ...)     # Existential quantifier (unrolled)
```

**Note on Z3 String sort:** `z3.Const(name, z3.StringSort(ctx))` is used instead of `z3.String(name)` to respect the per-thread Z3 context. Source: `transpiler.py`.

### Policy Class Structure

```python
class MyPolicy(Policy):
    class Meta:
        version = "1.0.0"         # Semver, validated against state_version field
        intent_model = IntentModel # Pydantic model for intent
        state_model = StateModel   # Pydantic model for state

    # Field declarations
    amount: Field = Field("amount", "Real", "intent")
    balance: Field = Field("balance", "Real", "state")

    @classmethod
    def invariants(cls) -> list[ConstraintExpr]:
        return [
            (E(cls.amount) > 0).named("positive_amount"),
            (E(cls.amount) <= E(cls.balance)).named("sufficient_funds"),
        ]
```

Every `ConstraintExpr` **must** carry a unique label via `.named()`. Missing labels raise `InvariantLabelError` at compile time (not runtime).

### YAML/TOML Policy DSL

Source: [src/pramanix/natural_policy/yaml_loader.py](src/pramanix/natural_policy/yaml_loader.py)

```yaml
# [IMPLEMENTED] — natural_policy/yaml_loader.py
policy:
  name: PaymentPolicy
  version: "1.0.0"
  fields:
    amount: {z3_type: Real, source: intent}
    balance: {z3_type: Real, source: state}
  invariants:
    - label: positive_amount
      expr: "amount > 0"
    - label: sufficient_funds
      expr: "amount <= balance"
```

The YAML loader uses a **safe AST visitor** — no `eval()`, no `exec()`. It walks the Python `ast` module node tree and whitelists specific node types only. Unknown nodes raise `PolicySyntaxError`. Source verified: `yaml_loader.py` uses `ast.parse()` + custom `_SafeExprVisitor`.

---

## 5. Z3 SMT Solver Integration

Source: [src/pramanix/solver.py](src/pramanix/solver.py), [src/pramanix/transpiler.py](src/pramanix/transpiler.py)

### Two-Phase Solving Algorithm

```
Phase 1 — Fast Check (_fast_check):
  • Single Z3 Solver instance
  • Assert ALL invariants simultaneously
  • If UNSAT → safe (all invariants hold)
  • If SAT → model is a counterexample → proceed to Phase 2

Phase 2 — Attribution (_attribute_violations):
  • For EACH invariant that failed:
    - Create a FRESH Z3 Solver instance (prevents cross-invariant contamination)
    - Assert ONLY that invariant's negation
    - Run to get unambiguous unsat_core
  • Result: per-invariant attribution with zero ambiguity

CRITICAL: Using unsat_core() on a shared solver returns only the MINIMAL
subset, not ALL violated invariants. Per-invariant solver instances are
required for correct attribution. This was a known design decision.
```

### Thread-Local Z3 Context

```python
# solver.py — actual implementation
_tl_ctx: threading.local()
_Z3_CTX_CREATE_LOCK: threading.Lock()  # Serializes Z3 context creation

def _thread_ctx() -> z3.Context:
    if not hasattr(_tl_ctx, "ctx"):
        with _Z3_CTX_CREATE_LOCK:
            _tl_ctx.ctx = z3.Context()
    return _tl_ctx.ctx
```

Z3 contexts are **not thread-safe**. Every worker thread gets its own context. The creation lock prevents two threads from simultaneously creating new contexts (Z3 global state mutation).

### Exact Arithmetic

```python
# transpiler.py — z3_val() for Decimal
if isinstance(value, Decimal):
    n, d = value.as_integer_ratio()
    return z3.RatVal(n, d, ctx=ctx)  # Exact rational — no float rounding
```

All financial arithmetic uses `Decimal` → exact `RatVal`, not `float`. This eliminates floating-point representation errors in safety proofs.

### String→Int Promotion Optimization

Source: `transpiler.py`, `analyze_string_promotions()`

When a `Field(z3_type="String")` is detected to be used only in equality/membership comparisons against a finite set of string literals, the transpiler automatically promotes it to a `z3.Int` enum representation. This yields 5–10x P50 latency improvement for String fields because Z3's theory of strings is exponentially harder than linear arithmetic.

### Benchmarks

Source: [benchmarks/latency_benchmark.py](benchmarks/latency_benchmark.py)

Published targets (not measured actuals):
- P50 < 5ms
- P95 < 10ms  
- P99 < 15ms

**No published actual measured numbers exist in the codebase.** The benchmark script (`BenchmarkPolicy`, 5 fields, 5 invariants, N=1000, warmup=10, sync mode) runs nightly at 02:00 UTC in CI. Results are not committed to the repository.

---

## 6. Translator Stack — Neuro-Symbolic Bridge

Source: [src/pramanix/translator/](src/pramanix/translator/)

This is **Phase 1** of the two-phase model. It is entirely optional. Without a translator, callers must provide pre-structured intent dicts.

### Supported Backends

| Translator | File | Extra | Status |
|---|---|---|---|
| Anthropic (Claude) | `anthropic.py` | `pramanix[translator]` | IMPLEMENTED |
| OpenAI compatible | `openai_compat.py` | `pramanix[translator]` | IMPLEMENTED |
| Cohere | `cohere.py` | `pramanix[cohere]` | IMPLEMENTED |
| Google Gemini | `gemini.py` | `pramanix[gemini]` | IMPLEMENTED |
| AWS Bedrock | `bedrock.py` | `pramanix[bedrock]` | IMPLEMENTED |
| Google Vertex AI | `vertexai.py` | `pramanix[vertexai]` | IMPLEMENTED |
| Mistral | `mistral.py` | `pramanix[mistral]` | IMPLEMENTED |
| Ollama (local REST) | `ollama.py` | none | IMPLEMENTED |
| llama.cpp (local) | `llamacpp.py` | `pramanix[llamacpp]` | IMPLEMENTED |

All translators implement the same `Translator` Protocol (`base.py`): `async def extract(text, intent_schema, context) -> dict`.

### Retry Strategy

All network-backed translators use `tenacity` exponential backoff:
- Retry on: `APITimeoutError`, `APIConnectionError`
- Wait: 1s → 2s → 4s (multiplier=1, min=1, max=10)
- Max attempts: 3
- Reraise: True (then mapped to `LLMTimeoutError`)

### Dual-Model Consensus

Source: [src/pramanix/translator/redundant.py](src/pramanix/translator/redundant.py)

```
ConsensusStrictness.strict_keys:  All fields must match exactly
ConsensusStrictness.lenient:       Only critical_fields list must match
ConsensusStrictness.unanimous:     Bitwise equality on canonical JSON
```

Any disagreement → `ExtractionMismatchError` → `Decision.error()` (BLOCK). Two different models seeing the same input and disagreeing is treated as a signal that the request is adversarial or ambiguous.

### Injection Detection

Source: [src/pramanix/translator/injection_scorer.py](src/pramanix/translator/injection_scorer.py)

**`BuiltinScorer`** — Heuristic scorer, no external deps. Wraps `injection_confidence_score()` from `_sanitise.py`.

**`CalibratedScorer`** — sklearn `TfidfVectorizer` + `LogisticRegression` pipeline:
- Requires minimum 200 labeled training examples
- Serializes to `.npz` (no pickle — `allow_pickle=False` at load time)
- Mandatory HMAC-SHA256 sidecar for every saved file
- No "skip verification" mode exists

### Input Sanitization

Source: [src/pramanix/translator/_sanitise.py](src/pramanix/translator/_sanitise.py)

- NFKC Unicode normalization (handles fullwidth chars like ５, Ａ)
- `google-re2` for ReDoS-safe regex matching (mandatory dependency)
- Truncation at `max_input_chars` raises `InputTooLongError` (not silent)

---

## 7. Worker Pool and Concurrency Model

Source: [src/pramanix/worker.py](src/pramanix/worker.py)

### Thread vs Process

```
async-thread mode:
  • ThreadPoolExecutor
  • Workers share memory with coordinator
  • Z3 isolation via thread-local contexts (threading.local())
  • Suitable for I/O-bound workloads and most production deployments

async-process mode:
  • ProcessPoolExecutor(method="spawn")
  • Full memory isolation per worker
  • Prevents Z3 memory accumulation across requests
  • HMAC-sealed IPC: results are signed with _RESULT_SEAL_KEY
  • Pydantic models serialized via model_dump() BEFORE submit() — not pickle-safe
  • Requires process_safe() check at Guard initialization
```

### Worker Warmup

Each worker performs a dummy Z3 solve during initialization to eliminate the cold-start JIT spike. Source: `worker.py`. The dummy solve runs against a trivial `1 > 0` formula.

### Adaptive Concurrency Shedding

Dual condition for load shedding activation:
1. `active_workers ≥ shedding_threshold` AND
2. p99 latency > `p99_latency_threshold_ms`

Both conditions must be true simultaneously. This prevents unnecessary shedding during brief latency spikes without concurrent load.

### Memory Management

`max_decisions_per_worker=10_000` default: workers are recycled after 10,000 decisions to prevent Z3 memory accumulation. This is a memory-vs-cold-start tradeoff. Cold start (worker warmup) is ~50ms; Z3 long-running memory growth can otherwise be unbounded.

---

## 8. Security Subsystems

### 8.1 Zero-Trust Agent Mesh (SPIFFE)

Source: [src/pramanix/mesh/authenticator.py](src/pramanix/mesh/authenticator.py)

- JWT-SVID validation: RS256 and ES256 only
- `"none"` algorithm: unconditionally rejected **before** any crypto work
- `HS256`: unconditionally rejected
- Order of checks: signature → exp/nbf/aud → SPIFFE URI format
- Intent poisoning prevention: rejects requests where `_mesh_principal` key already exists in intent dict (prevents principal spoofing)

### 8.2 Information Flow Control

Source: [src/pramanix/ifc/](src/pramanix/ifc/)

Trust label lattice:
```
PUBLIC < INTERNAL < CONFIDENTIAL < SECRET < TOP_SECRET
```

`FlowEnforcer.gate()` raises `FlowViolationError` if a data flow violates the active `FlowPolicy`. Backed by in-memory circular audit log. Thread-safe via `threading.Lock`.

### 8.3 Execution Token (TOCTOU Gap)

Source: [src/pramanix/execution_token.py](src/pramanix/execution_token.py)

Problem: The time between `Guard.verify() → allowed=True` and the actual execution of the action is a TOCTOU window. A second request could modify state between the two events.

Solution: `ExecutionToken` — HMAC-SHA256 signed, single-use, TTL-bounded (30s default).

Backends:
- `InMemoryExecutionTokenVerifier` — per-process only (test-only in production)
- `SQLiteExecutionTokenVerifier` — single-process production
- `PostgresExecutionTokenVerifier` — distributed (asyncpg + UNIQUE constraint)
- `RedisExecutionTokenVerifier` — distributed (SETNX atomic)

**Known limitation**: In multi-replica deployments, `InMemoryExecutionTokenVerifier` allows token replay across replicas. Use `RedisExecutionTokenVerifier` or `PostgresExecutionTokenVerifier` in distributed deployments.

### 8.4 Input Size Guard

Source: `guard.py`, `guard_config.py`

`GuardConfig.max_input_bytes` (default: not set → no limit in base config; set explicitly):
- Pre-validates `len(json.dumps(intent))` before any processing
- Raised as `InputTooLongError` → mapped to `Decision.error()` (BLOCK)
- Labeled H-01 in internal audit

### 8.5 Timing Side-Channel Mitigation

`GuardConfig.min_response_ms` pads BLOCK response times to prevent distinguishing rejection causes via latency. Default: 0 (disabled). Set to e.g. 50ms in production to prevent timing-based oracle attacks.

### 8.6 Secret Redaction

Source: `guard_config.py`, `_SECRET_KEY_RE`

`GuardConfig.__repr__` and logging recursively redacts dict keys matching `_SECRET_KEY_RE` pattern. Cited as §14.2 in internal docs.

### 8.7 Privilege Separation

Source: [src/pramanix/privilege/scope.py](src/pramanix/privilege/scope.py)

- `CapabilityManifest`: declares tool names and required scopes
- `ExecutionScope`: current granted scopes for an execution context
- `ScopeEnforcer.check()`: raises `PrivilegeEscalationError` if required scope not in granted scopes

### 8.8 Human Oversight

Source: [src/pramanix/oversight/workflow.py](src/pramanix/oversight/workflow.py)

- `EscalationQueue`: queues actions requiring human approval
- `ApprovalWorkflow`: manages dual-control approval process
- `OversightRequiredError`: raised when action requires approval not yet granted

---

## 9. Cryptographic Audit Layer

Source: [src/pramanix/audit/](src/pramanix/audit/), [src/pramanix/crypto.py](src/pramanix/crypto.py)

### Signing Algorithms

| Class | Algorithm | Key source | Use case |
|---|---|---|---|
| `PramanixSigner` | Ed25519 | PEM env var / ephemeral | Decision signing |
| `DecisionSigner` | HMAC-SHA256 JWS | 32+ char secret | Audit trail |
| `RS256Signer/Verifier` | RS256 | PEM key | JWT-compatible |
| `ES256Signer/Verifier` | ES256 | PEM key | JWT-compatible |

### Merkle Anchoring

Source: [src/pramanix/audit/merkle.py](src/pramanix/audit/merkle.py)

```
Leaf node:   SHA-256(decision_id_bytes)
Internal:    SHA-256(b'\x01' + left_hash + right_hash)
```

The `\x01` prefix for internal nodes prevents second-preimage attacks (H-07). This is the same technique used in certificate transparency logs.

`PersistentMerkleAnchor` accepts a `checkpoint_callback` for periodic root export. `MerkleArchiver` handles pruning and S3 export.

### Verification

`DecisionVerifier` is entirely stdlib — no external dependencies. Can be deployed in environments where `cryptography` package is unavailable. Uses `hmac.compare_digest()` for constant-time comparison.

### Audit Sinks

Source: [src/pramanix/audit_sink.py](src/pramanix/audit_sink.py)

| Sink | Backend | Notes |
|---|---|---|
| `StdoutAuditSink` | stdout JSON-lines | Always available |
| `InMemoryAuditSink` | in-process list | TEST-ONLY: warns/errors in production |
| `KafkaAuditSink` | confluent-kafka | Bounded queue 10k, 100ms background poll |
| `S3AuditSink` | boto3 | Batch upload |
| `SplunkHecAuditSink` | HEC HTTP | httpx |
| `DatadogAuditSink` | datadog-api-client | Background worker thread |

`InMemoryAuditSink` raises `ConfigurationError` when `PRAMANIX_ENV=production`. In all other environments it emits `UserWarning`. This prevents accidental use in production.

---

## 10. Governance Gates

Source: `guard.py`, `_apply_governance_gates()`, [src/pramanix/governance_config.py](src/pramanix/governance_config.py)

All governance gates are optional. Each is activated only when the corresponding config field is set in `GovernanceConfig`. Gates run in this fixed order within Phase 5:

```
1. MeshAuthenticator.authenticate(token)     → MeshAuthenticationError on failure
2. FlowEnforcer.gate(source, sink)           → FlowViolationError on violation
3. ScopeEnforcer.check(tool, manifest)       → PrivilegeEscalationError on escalation
4. ApprovalWorkflow.check(action, context)   → OversightRequiredError if unapproved
```

All gate failures are fail-closed: they raise exceptions that are caught by the outer try/except in `verify()` and collapse to `Decision.error()` (BLOCK).

### Compliance Oracle

Source: [src/pramanix/compliance/oracle.py](src/pramanix/compliance/oracle.py)

**This is NOT in the verification hot path.** It runs post-hoc against `ProvenanceRecord`s.

Supported frameworks:
- SOC 2 (Type II controls)
- EU AI Act (Article 9, 10, 13, 14)
- HIPAA (§164.308, §164.312)
- NIST AI RMF (Govern, Map, Measure, Manage)
- ISO 42001 (AI management system)
- GDPR (Article 5, 22, 25)

`ComplianceOracle` maps invariant labels to regulatory controls via `ControlMapping`. SPIFFE principal matching uses `fnmatch`. Each `ComplianceAttestation` carries a HMAC-SHA256 tag for proof of derivation.

---

## 11. Observability and Telemetry

Source: `guard_config.py`, `worker.py`, `fast_path.py`, `circuit_breaker.py`

### Prometheus Metrics

All metrics are optional (require `prometheus-client` extra):

| Metric | Type | Source |
|---|---|---|
| `pramanix_decisions_total` | Counter | `guard.py` — by status |
| `pramanix_solver_latency_ms` | Histogram | `solver.py` |
| `pramanix_fast_path_parse_failure_total` | Counter | `fast_path.py` |
| `pramanix_node_latency_ms` | Histogram | `integrations/langgraph.py` |
| `pramanix_node_verdict_total` | Counter | `integrations/langgraph.py` |
| `pramanix_circuit_breaker_state_sync_failure_total` | Counter | `circuit_breaker.py` |
| Warmup failure counters | Counter | `worker.py` |
| Watchdog error counters | Counter | `worker.py` |

### OpenTelemetry

Source: `guard_config.py`

Span context manager wraps each `verify()` call with OTel spans when `opentelemetry-sdk` is installed. No-op when absent. Span attributes include: policy name, decision status, solver latency, injection score.

### Structured Logging

`structlog` is a mandatory dependency. All logs are JSON-structured. `guard_config.py` configures structlog processors including `_SECRET_KEY_RE` redaction in log context.

---

## 12. Framework Integrations

Source: [src/pramanix/integrations/](src/pramanix/integrations/)

All integrations are **beta stability** per `__stability__` in `__init__.py`. All have graceful fallbacks when the host framework is absent.

### LangChain

Source: [src/pramanix/integrations/langchain.py](src/pramanix/integrations/langchain.py)

`PramanixGuardedTool` extends `langchain_core.tools.BaseTool`. Override of `_run()` calls `guard.verify()` before the tool body. `wrap_tools(tools, guard)` wraps a list of existing tools. Falls back to `_BaseToolFallback` stub if `langchain-core` is absent.

### LangGraph

Source: [src/pramanix/integrations/langgraph.py](src/pramanix/integrations/langgraph.py)

`@pramanix_node` decorator and `PramanixGuardNode` class. Records `pramanix_node_latency_ms` histogram and `pramanix_node_verdict_total` counter per node execution.

### FastAPI

Source: [src/pramanix/integrations/fastapi.py](src/pramanix/integrations/fastapi.py)

`PramanixMiddleware` (ASGI-compatible):
- `max_body_bytes` cap prevents OOM on large request bodies
- Content-type enforcement (rejects non-JSON by default)
- Timing pad for BLOCK responses (same latency as ALLOW, prevents timing oracle)

`pramanix_route` decorator for per-route guard injection.

### PydanticAI

Source: [src/pramanix/integrations/pydantic_ai.py](src/pramanix/integrations/pydantic_ai.py)

`PramanixPydanticAIValidator` with three usage patterns:
1. Direct `check()` / `check_async()` calls
2. `@guard_tool` decorator for async tool functions
3. `RunContext` hook registration

### AgentOrchestrationAdapter

Source: [src/pramanix/integrations/agent_orchestration.py](src/pramanix/integrations/agent_orchestration.py)

Framework-agnostic `@runtime_checkable` Protocol with three methods:
- `on_node_enter(node_name, intent, state) -> Decision`
- `on_node_exit(node_name, decision)`
- `should_block(decision) -> bool`

### Other Integrations

| Integration | Class | Status |
|---|---|---|
| LlamaIndex | `PramanixFunctionTool`, `PramanixQueryEngineTool` | IMPLEMENTED |
| AutoGen | `PramanixToolCallback` | IMPLEMENTED |
| CrewAI | `PramanixCrewAITool` | IMPLEMENTED |
| DSPy | `PramanixGuardedModule` | IMPLEMENTED |
| Haystack | `HaystackGuardedComponent` | IMPLEMENTED |
| Semantic Kernel | `PramanixSemanticKernelPlugin` | IMPLEMENTED |
| gRPC | gRPC interceptor | IMPLEMENTED |
| Kafka | Kafka consumer interceptor | IMPLEMENTED |
| Kubernetes | `ValidatingWebhook` via FastAPI | IMPLEMENTED |

---

## 13. Primitives Library

Source: [src/pramanix/primitives/](src/pramanix/primitives/)

Reusable `ConstraintExpr` factories. **Stable API.**

### Fintech (`fintech.py`)

Legal/regulatory disclaimer included in source file.

| Factory | Regulation | Description |
|---|---|---|
| `AntiStructuring` | 31 CFR §1020.320 | Structuring detection (smurfing) |
| `WashSaleDetection` | IRC §1091 | Wash sale rule |
| `SanctionsScreen` | OFAC | Sanctioned entity check |
| `VelocityCheck` | PSD2/Reg.E | Transaction velocity limits |
| `MarginRequirement` | Reg.T | Margin call threshold |
| `CollateralHaircut` | Basel III | Collateral valuation |
| `MaxDrawdown` | AIFMD | Maximum drawdown limit |
| `KYCTierCheck` | FATF | KYC compliance tier |
| `TradingWindowCheck` | SEC Rule 10b5-1 | Insider trading window |
| `SufficientBalance` | — | Balance sufficiency |

### Healthcare (`healthcare.py`)

HIPAA/clinical data handling constraints.

### Finance (`finance.py`)

General financial safety constraints (not fintech-specific).

### RBAC (`rbac.py`, `roles.py`)

Role-based access control constraint factories.

### Infrastructure (`infra.py`)

Rate limits, resource caps, infrastructure safety constraints.

### Time (`time.py`)

Time-window constraints, business hours, embargo periods.

---

## 14. Operational Tooling

### CLI

Source: [src/pramanix/cli.py](src/pramanix/cli.py)

```
pramanix compile-policy <policy_file>    # Compile YAML/TOML policy to IR
pramanix lint-policy <policy_file>       # E001-E004, W001-W005 codes
pramanix simulate <policy> <examples>   # Run dry-run simulation
pramanix verify-proof <decision_file>   # Verify Decision signature
pramanix audit <...>                    # Audit log operations
pramanix schema-export <policy>         # Export JSON Schema Draft-07
pramanix calibrate-injection <data>     # Train CalibratedScorer
pramanix doctor                         # Environment health check
```

`lint-policy` flags:
- `E001`: Missing invariant label (`.named()`)
- `E002`: Duplicate invariant label
- `E003`: No invariants declared
- `E004`: Field type mismatch
- `W001`–`W005`: Structural warnings

Flags: `--json` (machine-readable output), `--strict` (warnings as errors), `--policy-var` (dynamic policy loading).

### Policy Dry Run

Source: [src/pramanix/dry_run.py](src/pramanix/dry_run.py)

`PolicyDryRun` — batch simulation with zero side effects:
- No audit sinks
- No execution tokens
- No timing jitter (`min_response_ms=0`)
- `assert_all_allowed()` / `assert_all_blocked()` convenience methods for CI

### Policy Lifecycle

Source: [src/pramanix/lifecycle/diff.py](src/pramanix/lifecycle/diff.py)

`PolicyDiff` — structural diff between two `Policy` subclasses:
- Detects added/removed fields
- Detects changed invariants
- Returns typed `FieldChange` / `InvariantChange` objects

`ShadowEvaluator` — non-blocking parallel evaluation:
- Runs candidate policy alongside live policy
- Records divergence (where candidate and live disagree)
- Thread-safe
- No eval/exec

### Policy Migration

Source: [src/pramanix/migration.py](src/pramanix/migration.py)

`PolicyMigration` handles state schema migrations between policy versions:
- `field_renames`: rename state keys across versions
- `strict=True` raises `MigrationError` on missing keys
- `from_version` / `to_version` for traceability

### Policy Auditor

Source: [src/pramanix/helpers/policy_auditor.py](src/pramanix/helpers/policy_auditor.py)

Static analysis of policy coverage — identifies fields declared but not used in any invariant.

### Compliance Reporter

Source: [src/pramanix/helpers/compliance.py](src/pramanix/helpers/compliance.py)

`ComplianceReporter` generates `ComplianceReport` objects. PDF export via `fpdf2` (requires `pramanix[pdf]` extra).

---

## 15. Test Suite Architecture

Source: [tests/](tests/)

### Test Organization

```
tests/
├── unit/        # 100+ unit tests — no external services required
├── integration/ # Integration tests — testcontainers (Redis/Kafka/Postgres)
├── adversarial/ # Security tests — injection, overflow, HMAC, Z3 isolation
├── property/    # Hypothesis-based property tests
└── perf/        # Performance/memory tests (excluded from default run via addopts)
```

### Key Test Files

| File | What it tests |
|---|---|
| `adversarial/test_prompt_injection.py` | OWASP-labeled injection vectors (A-Z categories) |
| `adversarial/test_z3_context_isolation.py` | Thread-local Z3 context isolation |
| `adversarial/test_hmac_ipc_integrity.py` | HMAC-sealed IPC in process mode |
| `adversarial/test_toctou_awareness.py` | TOCTOU gap in execution token flow |
| `adversarial/test_worker_crash_isolation.py` | Worker crash containment |
| `property/test_dsl_and_transpiler_properties.py` | Hypothesis: transpiler properties |
| `property/test_fintech_primitive_properties.py` | Hypothesis: fintech constraint correctness |
| `integration/test_redis_circuit_breaker.py` | Real Redis (testcontainers) |
| `integration/test_postgres_token.py` | Real Postgres (testcontainers) |
| `integration/test_fastapi_middleware.py` | Real FastAPI ASGI |

### Testing Philosophy

Per project memory: **no mocks for external dependencies**. Integration tests use:
- `fakeredis` (in-memory Redis) for unit-level Redis tests
- `testcontainers` for real Redis/Kafka/Postgres/Vault in integration tests
- `InMemorySpanExporter` (real OTel, not mocked)
- `_CountingGuard` decorator for behavioral verification
- `_record_solve` injection for circuit breaker pressure testing

The `solver_factory` dependency injection point is the correct way to inject Z3 solver behavior in tests — patching `pramanix.guard.solve` or `z3.Solver` directly violates the thread-local context design.

### Coverage

`fail_under = 98` in `pyproject.toml`. Branch coverage enabled. Excludes: `TYPE_CHECKING` blocks, `__main__`, `@overload` stubs. This is enforced in CI — any PR reducing coverage below 98% fails.

---

## 16. CI Pipeline

Source: [.github/workflows/ci.yml](.github/workflows/ci.yml)

### Job Chain

```
sast
  └─▶ alpine-ban (reject Alpine base images — Z3 requires glibc)
        └─▶ lint-typecheck (ruff + mypy strict)
              └─▶ test (pytest, Python 3.13)
                    ├─▶ coverage (fail_under=98)
                    ├─▶ integration (parallel, testcontainers)
                    └─▶ wheel-smoke
                          └─▶ extras-smoke
                                └─▶ trivy (container scan)
                                      └─▶ license-scan
```

**Nightly:** latency benchmark at 02:00 UTC (results not committed to repo).

### Python Version Discrepancy

`pyproject.toml` declares `python = ">=3.11,<4.0"` and lists 3.11, 3.12, 3.13 classifiers. However, the CI matrix tests **only Python 3.13**. This means:

- 3.11 and 3.12 compatibility is **claimed but not CI-verified**
- Code may use features or behavior specific to 3.13
- mypy target is `python_version = "3.11"` (stricter — may catch issues)

### Secret Scanning

Banned patterns in CI (hardcoded secret detection):
- `PRAMANIX_HMAC_SECRET`
- `openai_api_key`
- Any base64-encoded-looking secrets

### License Allowlist

CI enforces an allowlist of approved open-source licenses. AGPL-3.0 dependencies are prohibited in extras that would force AGPL on users who only install `pramanix[translator]` or other non-core extras.

### Alpine Ban

Job `alpine-ban` explicitly rejects any Dockerfile using `alpine` as base image. Z3 requires glibc. Alpine uses musl libc and Z3 does not compile cleanly against it. Dockerfile uses `python:3.13-slim-bookworm` (Debian-based).

---

## 17. Known Gaps, Flaws, and Limitations

This section is a source-verified audit of weaknesses. Every item has a corresponding reference in the codebase.

### CRITICAL

**GA-1 — License Ambiguity (ENTERPRISE BLOCKER)**  
AGPL-3.0-only forces GPL-compatible licensing on any service that uses Pramanix over a network. The commercial license URL references `pramanix.dev/enterprise` but no enterprise license text exists in the repository (`LICENSE-COMMERCIAL` is referenced in `pyproject.toml` but not present in the repo). This is a hard blocker for any commercial adoption without explicit licensing.

**GA-1b — Per-Process Token Verifier**  
`InMemoryExecutionTokenVerifier` (`execution_token.py`) is per-process only. In a multi-replica deployment, tokens issued by replica A can be replayed against replica B. The fix exists (`RedisExecutionTokenVerifier`, `PostgresExecutionTokenVerifier`) but requires explicit configuration. The default is the broken implementation.

**GA-1c — Provenance Key Per-Process Risk**  
`ProvenanceRecord` HMAC uses `PRAMANIX_PROVENANCE_KEY` env var. If not set, it falls back to a per-process random key. In multi-replica deployments, provenance chains from different replicas are not cross-verifiable. Documentation states this but the code does not prevent it or warn loudly.

### HIGH

**Python Version Testing Gap**  
CI tests only Python 3.13. Declared 3.11 and 3.12 compatibility is untested. Any code using 3.13-specific behavior is latent breakage.

**In-Memory Merkle Anchor**  
`MerkleAnchor` is in-process only. Process restart loses the tree. `PersistentMerkleAnchor` with `checkpoint_callback` allows periodic persistence, but requires explicit configuration. The default `MerkleAnchor` provides tamper-evidence only within a single process lifetime.

**Benchmark Numbers Not Published**  
`benchmarks/latency_benchmark.py` defines targets (P50 < 5ms) but actual measured numbers from CI runs are not committed. No SLO document exists in the repository.

**No Distributed Trace Correlation**  
OTel spans are created per-`verify()` call but there is no correlation with the calling agent's trace context unless explicitly passed. Agents that call multiple Guard instances in a workflow do not get a unified trace.

**Compliance Oracle Is Post-Hoc Only**  
`ComplianceOracle` maps ProvenanceRecords to regulatory controls after the fact. It does not enforce compliance during verification. "HIPAA-compliant" and "SOC 2-compliant" in marketing context would be misleading — the oracle can generate attestations but cannot guarantee that the underlying system configuration meets audit requirements.

### MEDIUM

**ToxicityScorer Is Keyword-Based**  
`nlp/validators.py` `ToxicityScorer` is a keyword list, not an ML model. It will miss paraphrased toxicity, multilingual toxicity, and adversarial rephrasing. The name "ToxicityScorer" implies ML inference — it does not perform inference.

**Z3 String Theory Performance**  
Z3's string theory is significantly slower than linear arithmetic. The `analyze_string_promotions()` optimization helps for enum-like fields, but policies with many free-form string comparisons (regex, contains) can have P99 latencies well above targets. No published characterization of string-heavy policy performance exists.

**YAML DSL Coverage**  
The YAML/TOML DSL (`natural_policy/`) supports a subset of the Python DSL. Complex expressions using `ForAll`, `Exists`, `abs()`, `pow()`, `DatetimeField`, `NestedField`, and `ArrayField` quantifiers are not guaranteed to round-trip through the YAML loader. The safe AST visitor may reject valid Python that it cannot parse.

**No gRPC/Kafka TLS Configuration**  
`interceptors/grpc.py` and `interceptors/kafka.py` exist but TLS/mTLS configuration is not documented or tested in CI. Integration tests for these interceptors are minimal.

**Shadow Evaluator No Persistence**  
`ShadowEvaluator` records divergence in memory only. There is no built-in export of shadow evaluation results to audit sinks or external storage. Long-running shadow evaluations will accumulate results indefinitely.

**process_safe() Check Coverage**  
`async-process` mode requires that intent/state models are pickle-serializable. The `process_safe()` check exists but tests for the common failure cases (Pydantic v2 model with custom validators) are limited.

### LOW / INFORMATIONAL

**@invariant_mixin Ordering**  
`@invariant_mixin` appends invariants from multiple mixins in decoration order. If two mixins declare invariants with the same label, `InvariantLabelError` is raised at compile time, which is correct. However, the error message does not identify which mixin contributed the duplicate — debugging requires manual inspection.

**PolicyDiff Shallow Comparison**  
`PolicyDiff` compares field names and z3_types but does not compare invariant semantics — two invariants with different labels but logically equivalent Z3 formulas are reported as different. No semantic equivalence check exists.

**Resolver Cache Not Scoped Per-Request in Thread Mode**  
In `async-thread` mode with concurrent requests, resolver cache clearing in `finally` blocks prevents cross-request contamination for a given request. However, the implementation relies on the resolver being cleared on the same thread that called it. If a resolver is called from a different coroutine on the same thread (via `asyncio.to_thread`), the clearing semantics may not hold. Source: C-01 comment in `guard.py`.

**`PRAMANIX_ENV=production` Warning Threshold**  
`InMemoryAuditSink` raises `ConfigurationError` only when `PRAMANIX_ENV=production`. Other environments get `UserWarning` only. Staging environments that don't set this var will silently use in-memory audit — which means no durable audit trail.

---

## 18. Dependency Map and Extras

### Mandatory Dependencies

| Package | Version | Purpose |
|---|---|---|
| `pydantic` | `^2.5` | Intent/state model validation |
| `z3-solver` | `^4.12` | SMT solving (core, no optional) |
| `structlog` | `^23.2` | Structured logging |
| `google-re2` | `>=1.0` | ReDoS-safe regex in NLP layer |

`google-re2` is listed as mandatory in `pyproject.toml` but actual import-time behavior is lazy in `nlp/validators.py` — it raises `ConfigurationError` only when `PIIDetector` is instantiated without re2 present. The `injection_filter.py` also uses lazy import. If `google-re2` is not installed, basic guard operations still work but PII detection fails.

### Optional Extras

```
pramanix[translator]        openai, anthropic, httpx, tenacity
pramanix[otel]              opentelemetry-sdk, otlp exporter
pramanix[fastapi]           fastapi, starlette, httpx
pramanix[langchain]         langchain-core
pramanix[llamaindex]        llama-index-core
pramanix[autogen]           pyautogen
pramanix[redis]             redis>=5.0
pramanix[circuit-breaker]   redis>=5.0
pramanix[crypto]            cryptography>=41.0
pramanix[aws]               boto3>=1.34
pramanix[azure]             azure-keyvault-secrets, azure-identity
pramanix[gcp]               google-cloud-secret-manager
pramanix[vault]             hvac>=2.0
pramanix[kafka]             confluent-kafka>=2.3
pramanix[datadog]           datadog-api-client>=2.20
pramanix[cohere]            cohere>=5.0
pramanix[mistral]           mistralai>=1.0
pramanix[gemini]            google-generativeai>=0.7
pramanix[llamacpp]          llama-cpp-python>=0.2
pramanix[postgres]          asyncpg>=0.29
pramanix[dspy]              dspy-ai>=2.4
pramanix[crewai]            crewai>=0.55
pramanix[pydantic-ai]       pydantic-ai>=0.0.9
pramanix[semantic-kernel]   semantic-kernel>=1.0
pramanix[haystack]          haystack-ai>=2.0
pramanix[sklearn]           scikit-learn>=1.3
pramanix[bedrock]           boto3>=1.34
pramanix[vertexai]          google-cloud-aiplatform>=1.50
pramanix[metrics]           prometheus-client>=0.19
pramanix[performance]       orjson>=3.9
pramanix[pdf]               fpdf2>=2.7
pramanix[all]               everything above
```

### Docker

Source: `Dockerfile.production`

- Base: `python:3.13-slim-bookworm` (Debian-based, digest-pinned)
- Builder stage: `--require-hashes` pip install (supply chain integrity)
- Runner: UID 10001 (non-root)
- Health check: included
- `PRAMANIX_EXECUTION_MODE=async-thread` (default)
- Alpine: explicitly banned (Z3 requires glibc)

---

## 19. Installation

```bash
# Core only (Z3 + Pydantic + structlog + google-re2)
pip install pramanix

# With LLM translation support
pip install 'pramanix[translator]'

# With LangChain integration
pip install 'pramanix[langchain]'

# With Redis circuit breaker + distributed tokens
pip install 'pramanix[redis,circuit-breaker]'

# Full install (all extras)
pip install 'pramanix[all]'

# Development
pip install 'pramanix[all]'
pip install pytest pytest-asyncio pytest-cov hypothesis mypy ruff
```

**Python requirement:** 3.11+ (CI-verified: 3.13 only — see §17)

---

## 20. Quickstart

### Basic Usage — Pre-structured Intent

```python
from decimal import Decimal
from pydantic import BaseModel
from pramanix import Guard, Policy, Field, E, GuardConfig

class IntentModel(BaseModel):
    amount: Decimal
    recipient: str

class StateModel(BaseModel):
    balance: Decimal
    daily_sent: Decimal
    daily_limit: Decimal

class PaymentPolicy(Policy):
    class Meta:
        version = "1.0.0"
        intent_model = IntentModel
        state_model = StateModel

    amount: Field = Field("amount", "Real", "intent")
    balance: Field = Field("balance", "Real", "state")
    daily_sent: Field = Field("daily_sent", "Real", "state")
    daily_limit: Field = Field("daily_limit", "Real", "state")

    @classmethod
    def invariants(cls):
        return [
            (E(cls.amount) > 0).named("positive_amount"),
            (E(cls.amount) <= E(cls.balance)).named("sufficient_balance"),
            (E(cls.daily_sent) + E(cls.amount) <= E(cls.daily_limit)).named("daily_limit"),
        ]

guard = Guard(PaymentPolicy)

decision = guard.verify(
    intent={"amount": Decimal("500.00"), "recipient": "alice"},
    state={"balance": Decimal("1000.00"), "daily_sent": Decimal("0.00"), "daily_limit": Decimal("2000.00")},
)

print(decision.allowed)          # True
print(decision.status)           # SolverStatus.SAFE
print(decision.policy_hash)      # SHA-256 of policy bytecode
```

### With LLM Translation

```python
from pramanix import Guard, GuardConfig
from pramanix.translator.anthropic import AnthropicTranslator

translator = AnthropicTranslator(model="claude-opus-4-7")

guard = Guard(PaymentPolicy, config=GuardConfig(execution_mode="async-thread"))

# Raw natural language → structured intent → Z3 verification
decision = await guard.parse_and_verify(
    text="Send five hundred dollars to Alice",
    translator=translator,
)
```

### With Audit Trail

```python
from pramanix import Guard, GuardConfig
from pramanix import StdoutAuditSink, MerkleAnchor, DecisionSigner
import secrets

signer = DecisionSigner(secret_key=secrets.token_hex(32))
anchor = MerkleAnchor()

guard = Guard(
    PaymentPolicy,
    config=GuardConfig(
        audit_sinks=[StdoutAuditSink()],
        decision_signer=signer,
        merkle_anchor=anchor,
        execution_mode="sync",
    )
)
```

### Policy Dry Run

```python
from pramanix.dry_run import PolicyDryRun

runner = PolicyDryRun(
    PaymentPolicy,
    examples=[
        ({"amount": 100, "recipient": "alice"}, {"balance": 500, "daily_sent": 0, "daily_limit": 1000}),
        ({"amount": 2000, "recipient": "alice"}, {"balance": 500, "daily_sent": 0, "daily_limit": 1000}),
    ]
)

runner.assert_all_blocked()   # Raises AssertionError if any example is allowed
results = runner.simulate()   # Returns list[DryRunResult]
```

### @guard Decorator

```python
from pramanix import guard, Guard

g = Guard(PaymentPolicy)

@guard(g)
def process_payment(intent, state):
    # Only reached if decision.allowed == True
    return execute_transfer(intent, state)
```

---

## 21. Competitive Analysis

This comparison is based on publicly available source code and documentation as of May 2026. Every claim is source-verifiable.

### Summary Table

| Dimension | Pramanix | NeMo Guardrails | Guardrails AI | LangChain | LangGraph |
|---|---|---|---|---|---|
| **Formal verification** | Z3 SMT — mathematical proof | None — LLM-based | None — regex/validators | None | None |
| **Determinism** | Deterministic (Z3) | Non-deterministic (LLM) | Partially (regex paths) | Non-deterministic | Non-deterministic |
| **Failure mode** | Fail-closed (any error → BLOCK) | Non-deterministic | Depends on validator | Caller-dependent | Caller-dependent |
| **Policy language** | Python DSL + YAML/TOML | Colang (custom DSL) | Python validators | Python (no policy) | Python (no policy) |
| **Invariant attribution** | Per-invariant Z3 unsat cores | Not applicable | Per-validator | Not applicable | Not applicable |
| **LLM dependency** | Optional (Phase 1) | Required (core) | Optional | Core usage | Core usage |
| **Audit trail** | Merkle + Ed25519 + HMAC-JWS | Basic logging | Basic logging | Basic logging | Basic logging |
| **TOCTOU mitigation** | HMAC single-use execution tokens | None | None | None | None |
| **IFC** | FlowEnforcer + TrustLabel lattice | None | None | None | None |
| **Circuit breaker** | AdaptiveCircuitBreaker + Redis | None | None | None | None |
| **Compliance oracle** | SOC2/GDPR/HIPAA/NIST/ISO42001 | None | None | None | None |
| **Injection detection** | BuiltinScorer + CalibratedScorer | LLM-based rails | Rule-based | None | None |
| **Worker isolation** | Thread-local Z3 / ProcessPool | Shared | Shared | Shared | Shared |
| **License** | AGPL-3.0 / Commercial | Apache-2.0 | Apache-2.0 | MIT | MIT |
| **Python version** | 3.11+ (CI: 3.13 only) | 3.8+ | 3.8+ | 3.9+ | 3.9+ |
| **Test approach** | Real backends, adversarial suite | Moderate | Moderate | High | High |
| **Maturity** | Beta (GA-in-progress) | Stable (v0.10+) | Stable (v0.5+) | Stable | Stable |

### Detailed Comparison

#### Pramanix vs NeMo Guardrails

**NeMo Guardrails** (NVIDIA, Apache-2.0) uses a Colang DSL to define conversation flows and safety rails. Its safety checks are primarily LLM-based — it calls a "self-check" LLM to determine if a response is safe. This means:

- Safety decisions are probabilistic, not formal
- Two calls with identical inputs can produce different results
- No counterexample is produced when blocked — only "this is unsafe" without proof
- Rails can be bypassed by adversarial prompting of the LLM judge itself
- No execution token or TOCTOU mitigation
- No formal invariant attribution — "why was this blocked" is an LLM explanation, not a proof

NeMo excels at: conversational flow control, dialog management, topic-based safety filtering, and integrating with the NVIDIA ecosystem.

Pramanix is not a replacement for NeMo's conversational flow control. NeMo has no equivalent of Pramanix's Z3-based invariant verification for structured financial/healthcare/infrastructure operations.

**Honest assessment**: For chatbot safety (conversational topic filtering, response quality), NeMo is more mature and purpose-built. For structured operation safety (transfer $X to Y, deploy resource Z), Pramanix provides stronger formal guarantees.

#### Pramanix vs Guardrails AI

**Guardrails AI** (Apache-2.0, `pip install guardrails-ai`) validates LLM outputs against a library of "validators" — Python functions that check format, content, and structure. Key differences:

- Validators are functions, not formal proofs. A validator that checks `amount > 0` is a Python assertion, not a Z3 theorem.
- No formal counterexample on failure — just a failed validation
- The validator hub contains community validators of varying quality
- No two-phase verification — validators run sequentially, not as a joint constraint system
- No TOCTOU mitigation
- No IFC, no circuit breaker, no compliance oracle

Guardrails AI excels at: output format validation, PII redaction, JSON structure checking, string content filtering.

**Honest assessment**: Guardrails AI is better for LLM output validation. Pramanix is better for pre-action safety verification where you need formal proof, not heuristic checking. They are complementary, not competing.

#### Pramanix vs LangChain

LangChain is a framework for building LLM applications — chains, agents, tool calling, retrieval. It is not a safety framework. It provides no:

- Formal verification of tool inputs
- Policy-based blocking
- Audit trail with cryptographic integrity
- Execution token or TOCTOU protection

The comparison is largely a category error. LangChain's `PramanixGuardedTool` integration wraps LangChain tools with Pramanix safety checks — they are designed to be used together, not instead of each other.

**What LangChain has that Pramanix doesn't**: Agent orchestration, retrieval, prompt management, chain composition, streaming, memory management, a large ecosystem.

**What Pramanix has that LangChain doesn't**: Formal safety verification, policy DSL, cryptographic audit, TOCTOU protection.

#### Pramanix vs LangGraph

LangGraph adds graph-based state machine orchestration on top of LangChain. The `@pramanix_node` decorator in `integrations/langgraph.py` integrates at the node level. LangGraph has no built-in safety verification — it delegates to node implementations.

**What LangGraph has that Pramanix doesn't**: Stateful multi-agent workflows, human-in-the-loop checkpointing, graph visualization, streaming node outputs, persistence backends.

**What Pramanix has that LangGraph doesn't**: Formal safety at each node boundary, provenance chain, policy versioning and diff, shadow evaluation.

#### Pramanix vs LlamaIndex

LlamaIndex focuses on data ingestion, indexing, and retrieval for LLM applications. The comparison is similarly a category error. `PramanixFunctionTool` and `PramanixQueryEngineTool` in `integrations/llamaindex.py` wrap LlamaIndex tools with Pramanix verification.

LlamaIndex has no built-in formal safety, audit, or policy layer.

### Where Pramanix Is Currently Weaker

**Honest, source-verified weaknesses:**

1. **No production deployments tracked**: The repository has no case studies, public deployments, or user reports. All performance claims are targets, not measurements.

2. **AGPL-3.0 license**: Apache-2.0 (NeMo, Guardrails AI) and MIT (LangChain, LangGraph) are more permissive. AGPL-3.0 forces license compatibility for network services. Without the commercial license being publicly available, adoption in commercial settings is legally complex.

3. **Z3 startup overhead**: Cold-starting Z3 takes ~50ms per worker. NeMo and Guardrails AI have no equivalent startup cost (LLM API calls are I/O, not compute on the host).

4. **String theory performance**: Z3's theory of strings is EXPSPACE-complete in general. Policies with free-form string matching can have unbounded latency. NeMo's string safety is O(1) regex.

5. **LLM ecosystem integration maturity**: NeMo has deeper NVIDIA ecosystem integration. LangChain/LangGraph have thousands of community integrations. Pramanix's integrations (while implemented) have not been tested against real production agent deployments.

6. **Documentation**: This README is the primary documentation. NeMo, Guardrails AI, LangChain, and LlamaIndex all have dedicated documentation sites with tutorials, API references, and cookbook examples.

7. **Community**: NeMo, LangChain, and LlamaIndex have active communities, GitHub Discussions, Discord servers. Pramanix has none of these.

8. **CI Python version gap**: Only 3.13 tested. NeMo and Guardrails AI test across 3.8–3.12.

---

## 22. Development Status by Component

| Component | File | Status | Notes |
|---|---|---|---|
| Guard | `guard.py` | IMPLEMENTED | Core verify() pipeline complete |
| Policy DSL | `policy.py`, `expressions.py` | IMPLEMENTED | Full operator set implemented |
| Transpiler | `transpiler.py` | IMPLEMENTED | DSL→Z3 lowering, string promotion |
| Solver | `solver.py` | IMPLEMENTED | Thread-local contexts, attribution |
| Compiler/IR | `compiler.py` | IMPLEMENTED | PolicyIR, Decompiler |
| Decision | `decision.py` | IMPLEMENTED | All status codes, hash, signature |
| Fast Path | `fast_path.py` | IMPLEMENTED (beta) | Fail-closed, Prometheus counter |
| Worker Pool | `worker.py` | IMPLEMENTED | Thread+Process, HMAC IPC |
| Circuit Breaker | `circuit_breaker.py` | IMPLEMENTED | CLOSED/OPEN/HALF_OPEN/ISOLATED |
| Distributed CB | `circuit_breaker.py` | IMPLEMENTED | Redis backend |
| Execution Token | `execution_token.py` | IMPLEMENTED | SQLite/Postgres/Redis backends |
| Crypto | `crypto.py` | IMPLEMENTED | Ed25519, RS256, ES256 |
| Merkle | `audit/merkle.py` | IMPLEMENTED | Second-preimage resistant |
| Persistent Merkle | `audit/merkle.py` | IMPLEMENTED | checkpoint_callback |
| Decision Signer | `audit/signer.py` | IMPLEMENTED | HMAC-SHA256 JWS |
| Decision Verifier | `audit/verifier.py` | IMPLEMENTED | Stdlib-only |
| Audit Sinks | `audit_sink.py` | IMPLEMENTED | Kafka/S3/Splunk/Datadog/Stdout |
| YAML/TOML DSL | `natural_policy/` | IMPLEMENTED | Safe AST, subset of Python DSL |
| YAML DSL (full) | `natural_policy/` | PARTIALLY IMPLEMENTED | ForAll/Exists/complex ops: unverified |
| NLP Validators | `nlp/validators.py` | IMPLEMENTED | 11 validators total |
| ToxicityScorer | `nlp/validators.py` | IMPLEMENTED (keyword-only) | Not ML-based |
| PIIDetector | `nlp/validators.py` | IMPLEMENTED | Requires google-re2 |
| BuiltinScorer | `translator/injection_scorer.py` | IMPLEMENTED | Heuristic |
| CalibratedScorer | `translator/injection_scorer.py` | IMPLEMENTED | sklearn, no-pickle |
| AnthropicTranslator | `translator/anthropic.py` | IMPLEMENTED | tenacity retry |
| OpenAI Translator | `translator/openai_compat.py` | IMPLEMENTED | |
| BedrockTranslator | `translator/bedrock.py` | IMPLEMENTED | Claude/Titan/Llama |
| VertexAITranslator | `translator/vertexai.py` | IMPLEMENTED | Gemini/PaLM2 |
| GeminiTranslator | `translator/gemini.py` | IMPLEMENTED | |
| OllamaTranslator | `translator/ollama.py` | IMPLEMENTED | |
| LlamaCppTranslator | `translator/llamacpp.py` | IMPLEMENTED | |
| MistralTranslator | `translator/mistral.py` | IMPLEMENTED | |
| CohereTranslator | `translator/cohere.py` | IMPLEMENTED | |
| Dual-Model Consensus | `translator/redundant.py` | IMPLEMENTED | strict/lenient/unanimous |
| SPIFFE Mesh | `mesh/authenticator.py` | IMPLEMENTED | RS256/ES256 only |
| IFC | `ifc/` | IMPLEMENTED (beta) | In-memory audit only |
| Privilege Separation | `privilege/scope.py` | IMPLEMENTED (beta) | |
| Human Oversight | `oversight/workflow.py` | IMPLEMENTED (beta) | |
| Compliance Oracle | `compliance/oracle.py` | IMPLEMENTED (beta) | Post-hoc only |
| Compliance PDF | `helpers/compliance.py` | IMPLEMENTED | Requires fpdf2 |
| PolicyDiff | `lifecycle/diff.py` | IMPLEMENTED | Structural diff only |
| ShadowEvaluator | `lifecycle/diff.py` | IMPLEMENTED | In-memory results only |
| PolicyDryRun | `dry_run.py` | IMPLEMENTED | |
| PolicyMigration | `migration.py` | IMPLEMENTED | |
| PolicyAuditor | `helpers/policy_auditor.py` | IMPLEMENTED | Static analysis |
| Key Providers | `key_provider.py` | IMPLEMENTED | AWS/Azure/GCP/Vault |
| SecureMemory | `memory/store.py` | IMPLEMENTED (beta) | |
| ProvenanceChain | `provenance.py` | IMPLEMENTED | Per-process key risk |
| LangChain | `integrations/langchain.py` | IMPLEMENTED (beta) | |
| LangGraph | `integrations/langgraph.py` | IMPLEMENTED (beta) | |
| LlamaIndex | `integrations/llamaindex.py` | IMPLEMENTED (beta) | |
| PydanticAI | `integrations/pydantic_ai.py` | IMPLEMENTED (beta) | |
| FastAPI | `integrations/fastapi.py` | IMPLEMENTED (beta) | |
| AutoGen | `integrations/autogen.py` | IMPLEMENTED (beta) | |
| CrewAI | `integrations/crewai.py` | IMPLEMENTED (beta) | |
| DSPy | `integrations/dspy.py` | IMPLEMENTED (beta) | |
| Haystack | `integrations/haystack.py` | IMPLEMENTED (beta) | |
| Semantic Kernel | `integrations/semantic_kernel.py` | IMPLEMENTED (beta) | |
| gRPC Interceptor | `interceptors/grpc.py` | IMPLEMENTED | Limited test coverage |
| Kafka Interceptor | `interceptors/kafka.py` | IMPLEMENTED | Limited test coverage |
| K8s Webhook | `k8s/webhook.py` | IMPLEMENTED | Requires fastapi extra |
| CLI | `cli.py` | IMPLEMENTED | Full subcommand set |
| Fintech Primitives | `primitives/fintech.py` | IMPLEMENTED | 10 factory functions |
| Finance Primitives | `primitives/finance.py` | IMPLEMENTED | |
| Healthcare Primitives | `primitives/healthcare.py` | IMPLEMENTED | |
| RBAC Primitives | `primitives/rbac.py` | IMPLEMENTED | |
| Infra Primitives | `primitives/infra.py` | IMPLEMENTED | |
| Time Primitives | `primitives/time.py` | IMPLEMENTED | |
| Benchmark (targets) | `benchmarks/` | PROPOSED | Targets defined, actuals unmeasured |
| Commercial License | LICENSE-COMMERCIAL | MISSING | Referenced in pyproject.toml, not in repo |
| Documentation site | — | MISSING | No dedicated docs site |
| Migration guides | — | MISSING | No upgrade path docs |
| Changelog | CHANGELOG.md | MISSING | Referenced in pyproject.toml, not in repo |

---

## 23. Roadmap

Items below are derived from `docs/` references, internal gap analysis, and the `__stability__` tiers in `__init__.py`.

### v1.0.0 GA Requirements (Blocking)

- [ ] **GA-1**: Publish `LICENSE-COMMERCIAL` to resolve AGPL-3.0 enterprise blocker
- [ ] **GA-1**: Create `CHANGELOG.md` (referenced in `pyproject.toml`, absent)
- [ ] **CI**: Add Python 3.11 and 3.12 to test matrix (declared compat, not tested)
- [ ] **GA-benchmark**: Publish actual P50/P95/P99 numbers from nightly CI benchmark runs
- [ ] **Docs**: Minimum viable documentation site (API reference, tutorials)

### v1.1.0 (Planned — Beta Graduation)

- [ ] Promote `translator` to stable (remove beta tag from `__stability__`)
- [ ] Promote `integrations` to stable (requires production validation)
- [ ] Persistent shadow evaluator results via audit sink
- [ ] YAML DSL full parity with Python DSL (ForAll, Exists, complex operators)
- [ ] Distributed Merkle anchor (beyond per-process)

### Future (No Committed Date)

- [ ] ONNX/TensorRT toxicity model to replace keyword-based `ToxicityScorer`
- [ ] Z3 string theory performance: evaluate `z3.SequenceSort` alternatives
- [ ] Multi-replica provenance key management (auto-derive from shared secret)
- [ ] Graph-level policy (across multiple Guard calls in a workflow)
- [ ] Policy marketplace / registry
- [ ] Python 3.14 compatibility validation
- [ ] WASM compilation target for edge deployment (Z3 WASM port exploration)

---

## Appendix A — Exception Hierarchy

```
PramanixError
├── InputTooLongError
├── PolicyError
│   ├── PolicyCompilationError
│   ├── InvariantLabelError
│   ├── FieldTypeError
│   ├── TranspileError
│   └── PolicySyntaxError       # YAML/TOML policy syntax violations
├── GuardError
│   ├── ValidationError
│   ├── StateValidationError
│   ├── SolverTimeoutError
│   ├── SolverError
│   ├── WorkerError
│   ├── ExtractionFailureError
│   ├── ExtractionMismatchError
│   ├── LLMTimeoutError
│   ├── SemanticPolicyViolation
│   ├── InjectionBlockedError
│   ├── MeshAuthenticationError
│   ├── VerificationError
│   └── GuardViolationError     # raised by @guard decorator only
├── ConfigurationError
├── IntegrityError
├── ResolverConflictError
├── MigrationError
├── FlowViolationError
├── PrivilegeEscalationError
├── OversightRequiredError
├── MemoryViolationError
└── ProvenanceError
```

Source: [src/pramanix/exceptions.py](src/pramanix/exceptions.py)

---

## Appendix B — Decision Status Codes

```python
class SolverStatus(StrEnum):
    SAFE              = "safe"               # Z3 proved all invariants hold
    UNSAFE            = "unsafe"             # Z3 found counterexample
    TIMEOUT           = "timeout"            # Z3 exceeded timeout_ms
    ERROR             = "error"              # Unexpected internal error
    STALE_STATE       = "stale_state"        # state_version mismatch
    VALIDATION_FAILURE = "validation_failure" # Pydantic validation failed
    RATE_LIMITED      = "rate_limited"       # Concurrency limit reached
    CONSENSUS_FAILURE = "consensus_failure"  # Dual-model consensus failed
    CACHE_HIT         = "cache_hit"          # Served from intent cache
    GOVERNANCE_BLOCKED = "governance_blocked" # Gate rejected (IFC/privilege/oversight)
```

Only `SAFE` maps to `allowed=True`. All other statuses map to `allowed=False`. Enforced via `__post_init__` assertion in `Decision`. Source: [src/pramanix/decision.py](src/pramanix/decision.py)

---

## Appendix C — SolverStatus to HTTP Response Mapping

For deployments using `PramanixMiddleware` (FastAPI):

| Status | HTTP | Body |
|---|---|---|
| `SAFE` | 200 | Decision JSON |
| `UNSAFE` | 403 | Decision JSON with violated_invariants |
| `VALIDATION_FAILURE` | 422 | Decision JSON |
| `TIMEOUT` | 503 | Decision JSON |
| `RATE_LIMITED` | 429 | Decision JSON |
| `GOVERNANCE_BLOCKED` | 403 | Decision JSON |
| `ERROR` | 500 | Decision JSON |

---

## Appendix D — Key Configuration Knobs

Source: [src/pramanix/guard_config.py](src/pramanix/guard_config.py)

| Field | Type | Default | Effect |
|---|---|---|---|
| `execution_mode` | str | `"sync"` | `sync`, `async-thread`, `async-process` |
| `max_workers` | int | 4 | Worker pool size |
| `solver_timeout_ms` | int | 5000 | Per-invariant Z3 timeout |
| `max_input_bytes` | int | None | Input size limit (H-01) |
| `injection_threshold` | float | 0.5 | BuiltinScorer block threshold |
| `min_response_ms` | float | 0.0 | Timing side-channel pad |
| `audit_sinks` | list | `[]` | Audit sink instances |
| `fast_path_enabled` | bool | False | O(1) pre-screening |
| `max_decisions_per_worker` | int | 10000 | Worker recycle threshold |

---

## License

Community edition: [GNU Affero General Public License v3.0 (AGPL-3.0-only)](LICENSE)

Commercial/enterprise license: contact `viraj@pramanix.dev` (note: `LICENSE-COMMERCIAL` file is not yet present in this repository — see [Known Gaps §17](#17-known-gaps-flaws-and-limitations))

Copyright (C) 2026 Viraj Jain
