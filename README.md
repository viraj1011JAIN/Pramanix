# Pramanix

**Deterministic neuro-symbolic guardrails for autonomous AI agents.**

`pip install pramanix` — Python ≥ 3.13 — AGPL-3.0

---

## What it is

Pramanix is an execution firewall that sits between an AI agent's declared intent and the real-world action it would take. Before the action runs, Pramanix gives you a **binary, deterministic, formally-proved answer**: ALLOW or BLOCK.

The proof mechanism is [Z3](https://github.com/Z3Prover/z3), an industrial SMT solver from Microsoft Research. ALLOW decisions carry a satisfying assignment. BLOCK decisions carry a counterexample that names every violated invariant. Neither outcome is probabilistic; neither depends on a model's confidence score.

---

## What it is not

- It is not a content filter, a prompt classifier, or a safety classifier.
- It is not a rate limiter, a firewall rule, or an API gateway.
- It does not read or evaluate the agent's internal reasoning.
- It does not replace unit tests, type checking, or input validation.

Pramanix verifies **declared intent against formal policy**. If an agent lies about its intent, the guarantee does not hold. Intent extraction from natural language (the translator subsystem) is a separate, probabilistic layer that sits upstream; it is opt-in and explicitly marked `beta`.

---

## Core guarantee

```python
from pramanix import Guard, GuardConfig

guard = Guard(TransferPolicy)
decision = guard.verify(intent, state)
```

`guard.verify()` **never raises**. It always returns a `Decision`. `Decision.allowed` is `True` if and only if Z3 proved all invariants hold given the supplied intent and state. Every other outcome — timeout, validation failure, internal error, policy violation — produces `allowed=False`. There is no code path that returns `allowed=True` from an error handler.

This is the only property that matters. Everything else in the codebase exists to make this property useful in production.

---

## Quick start

```python
from decimal import Decimal
from pramanix import Guard, Policy, Field, E, Decision

class TransferPolicy(Policy):
    amount    = Field("amount",    Decimal, "Real")
    balance   = Field("balance",  Decimal, "Real")
    daily_spent = Field("daily_spent", Decimal, "Real")

    @classmethod
    def invariants(cls):
        return [
            (E(cls.amount) > 0).named("amount_positive"),
            (E(cls.amount) <= E(cls.balance)).named("no_overdraft"),
            (E(cls.daily_spent) + E(cls.amount) <= 10_000).named("daily_limit"),
        ]

guard = Guard(TransferPolicy)

decision = guard.verify(
    intent={"amount": Decimal("500.00")},
    state={"balance": Decimal("1200.00"), "daily_spent": Decimal("0.00")},
)

assert decision.allowed is True
assert decision.status.value == "SAFE"
```

BLOCK path:

```python
decision = guard.verify(
    intent={"amount": Decimal("1500.00")},
    state={"balance": Decimal("800.00"), "daily_spent": Decimal("0.00")},
)

assert decision.allowed is False
assert "no_overdraft" in decision.violated_invariants
# decision.explanation contains Z3's counterexample
```

---

## Installation

Core (always required):

```bash
pip install pramanix
```

Core requires: `pydantic ^2.5`, `z3-solver ^4.12`, `structlog ^23.2`, `prometheus-client ^0.19`, `orjson >=3.9`.

Optional extras:

```bash
pip install 'pramanix[translator]'       # LLM intent extraction (httpx, openai, anthropic)
pip install 'pramanix[otel]'             # OpenTelemetry tracing
pip install 'pramanix[fastapi]'          # FastAPI/Starlette middleware
pip install 'pramanix[langchain]'        # LangChain tool adapter
pip install 'pramanix[llamaindex]'       # LlamaIndex tool adapter
pip install 'pramanix[autogen]'          # AutoGen callback adapter
pip install 'pramanix[crypto]'           # Ed25519 signing (cryptography lib)
pip install 'pramanix[audit]'            # fpdf2 compliance PDF export
pip install 'pramanix[identity]'         # JWT identity linker (redis)
pip install 'pramanix[aws]'              # AWS Secrets Manager + S3 sink (boto3)
pip install 'pramanix[azure]'            # Azure Key Vault
pip install 'pramanix[gcp]'              # GCP Secret Manager
pip install 'pramanix[vault]'            # HashiCorp Vault
pip install 'pramanix[kafka]'            # Confluent Kafka audit sink
pip install 'pramanix[postgres]'         # PostgreSQL token verifier (asyncpg)
pip install 'pramanix[cohere]'           # Cohere translator backend
pip install 'pramanix[gemini]'           # Google Gemini translator backend
pip install 'pramanix[mistral]'          # Mistral translator backend
pip install 'pramanix[crewai]'           # CrewAI tool adapter
pip install 'pramanix[dspy]'             # DSPy module adapter
pip install 'pramanix[haystack]'         # Haystack component adapter
pip install 'pramanix[pydantic-ai]'      # Pydantic AI validator adapter
pip install 'pramanix[semantic-kernel]'  # Semantic Kernel plugin adapter
pip install 'pramanix[all]'              # Everything
```

**Alpine Linux is not supported.** Z3 ships glibc-compiled wheels. On musl libc, Z3 segfaults or runs 3–10× slower. `import pramanix.guard` raises `ConfigurationError` on Alpine unless `PRAMANIX_SKIP_MUSL_CHECK=1` is set — if you do that, Z3 stability is your problem.

---

## Architecture

Two-phase verification model:

```
User code
  │
  ├── [optional] Translator  ← NLP prompt → structured intent dict
  │     ├── Input sanitisation (NFKC, length cap, control chars)
  │     ├── Injection pattern detection (regex, 30+ OWASP patterns)
  │     ├── Dual-model consensus (two LLMs must agree before proceeding)
  │     └── CalibratedScorer (sklearn TF-IDF + LR, trainable per domain)
  │
  └── Guard.verify()
        ├── Pydantic strict-mode validation (intent + state)
        ├── Fast path O(1) pre-screen (configurable Python rules, BLOCK only)
        ├── Transpiler: DSL expression tree → Z3 AST (no eval/exec/ast.parse)
        ├── Solver: Phase 1 (shared solver, all invariants, fast SAT/UNSAT)
        │          Phase 2 (per-invariant solvers, UNSAT attribution)
        ├── Decision construction (immutable, SHA-256 hash, deterministic)
        ├── Ed25519 signing (optional, fail-closed)
        ├── Audit sink emit (Kafka / S3 / Splunk / Datadog, never blocks caller)
        └── OTel span + Prometheus metrics (optional, no-op if not installed)
```

Phase 1 uses a shared Z3 solver for overall SAT/UNSAT — this is the common (ALLOW) case and is fast. Phase 2 uses separate per-invariant Z3 solver instances so `unsat_core()` returns exactly `{label}` for each violated constraint. This sidesteps Z3's minimum-core behaviour, which would otherwise silently drop violated invariants from BLOCK responses.

No Z3 objects cross process boundaries. Workers receive `(policy_cls, values_dict)` and reconstruct the formula tree in-process.

---

## Execution modes

```python
GuardConfig(execution_mode="sync")           # default; Z3 in caller thread
GuardConfig(execution_mode="async-thread")   # ThreadPoolExecutor; Z3 in background thread
GuardConfig(execution_mode="async-process")  # ProcessPoolExecutor; Z3 in subprocess
```

`async-process` gives the strongest isolation. HMAC-sealed IPC prevents a compromised worker from forging `allowed=True` across the process boundary. Workers self-terminate via PPID watchdog if the parent process dies.

Worker pool recycling: after `max_decisions_per_worker=10,000` decisions (default), the executor is replaced. This caps Z3 heap accumulation. Old executors are handed off to a daemon thread for drain-and-shutdown; the event loop is never blocked.

---

## Policy DSL

Policies are plain Python classes. The DSL uses operator overloading; it never calls `eval`, `exec`, or `ast.parse`.

```python
from pramanix import Policy, Field, E, ConstraintExpr, ForAll
from decimal import Decimal

class TradePolicy(Policy):
    # Fields declare name, Python type, Z3 sort
    amount   = Field("amount",   Decimal, "Real")
    side     = Field("side",     str,     "String")
    quantity = Field("quantity", int,     "Int")
    prices   = Field("prices",   list,    "Array")

    @classmethod
    def invariants(cls) -> list[ConstraintExpr]:
        return [
            (E(cls.amount) > 0).named("positive_amount"),
            E(cls.side).is_in(["BUY", "SELL"]).named("valid_side"),
            (E(cls.quantity) >= 1).named("min_quantity"),
            ForAll(cls.prices, lambda p: p > 0).named("all_prices_positive"),
        ]
```

Supported operations: arithmetic (`+`, `-`, `*`, `/`, `**`, `%`, `abs`), comparisons, boolean composition (`&`, `|`, `~`), set membership (`.is_in()`), string operations (`.startswith()`, `.endswith()`, `.contains()`, `.matches(regex)`, `.length()`), array quantifiers (`ForAll`, `Exists`), datetime arithmetic (`DatetimeField`), nested model fields (`NestedField`).

`ConstraintExpr.__bool__` raises `PolicyCompilationError` if you accidentally use `and`/`or` instead of `&`/`|`. This catches a class of silent policy bug at compile time.

---

## GuardConfig

All fields are validated at construction time. Invalid values raise `ConfigurationError` immediately — not at first `verify()` call.

| Field | Default | Env var |
|---|---|---|
| `execution_mode` | `"sync"` | `PRAMANIX_EXECUTION_MODE` |
| `solver_timeout_ms` | `5000` | `PRAMANIX_SOLVER_TIMEOUT_MS` |
| `solver_rlimit` | `10_000_000` | `PRAMANIX_SOLVER_RLIMIT` |
| `max_workers` | `4` | `PRAMANIX_MAX_WORKERS` |
| `max_decisions_per_worker` | `10_000` | `PRAMANIX_MAX_DECISIONS_PER_WORKER` |
| `max_input_bytes` | `65_536` | `PRAMANIX_MAX_INPUT_BYTES` |
| `max_input_chars` | `512` | `PRAMANIX_MAX_INPUT_CHARS` |
| `min_response_ms` | `0.0` | — |
| `redact_violations` | `False` | — |
| `expected_policy_hash` | `None` | `PRAMANIX_EXPECTED_POLICY_HASH` |
| `metrics_enabled` | `True` | `PRAMANIX_METRICS_ENABLED` |
| `otel_enabled` | `False` | `PRAMANIX_OTEL_ENABLED` |
| `fast_path_enabled` | `False` | `PRAMANIX_FAST_PATH_ENABLED` |
| `signer` | `None` | — |
| `audit_sinks` | `[]` | — |
| `injection_threshold` | `0.5` | `PRAMANIX_INJECTION_THRESHOLD` |

`PRAMANIX_ENV=production` triggers `UserWarning` (not an exception) when:
- `execution_mode` is `sync` or `async-thread`
- `signer` is `None`
- `audit_sinks` is empty
- `solver_rlimit` is `0`
- `max_input_bytes` is `0`
- `expected_policy_hash` is `None`

These are not enforced. They are warnings. You decide what production means for your deployment.

---

## Decision

```python
@dataclass(frozen=True)
class Decision:
    allowed:             bool
    status:              SolverStatus      # SAFE | UNSAFE | TIMEOUT | ERROR | STALE_STATE | VALIDATION_FAILURE
    violated_invariants: list[str]         # empty on ALLOW; invariant labels on BLOCK
    explanation:         str               # Z3 counterexample text on BLOCK
    decision_id:         str               # UUID4
    decision_hash:       str               # SHA-256 over canonical fields
    policy:              str               # Policy class name
    solver_time_ms:      float
    metadata:            dict
    intent_dump:         dict | None       # captured at verify() time
    state_dump:          dict | None       # captured at verify() time
    signature:           str | None        # Ed25519 hex signature if signer configured
    public_key_id:       str | None        # SHA-256[:16] of signing public key
```

`allowed=True` and `status != SAFE` is a hard invariant violation — `__post_init__` raises `ValueError` immediately. This invariant cannot be bypassed without modifying the dataclass itself.

Factory methods: `Decision.safe()`, `Decision.unsafe()`, `Decision.timeout()`, `Decision.error()`, `Decision.stale_state()`, `Decision.validation_failure()`, `Decision.consensus_failure()`. All non-safe factories enforce `allowed=False`.

---

## Audit trail

Every `Decision` carries a deterministic SHA-256 hash over its content fields. This hash is the basis for Ed25519 signing and Merkle anchoring.

```python
from pramanix import Guard, GuardConfig, PramanixSigner, DecisionSigner
from pramanix import MerkleAnchor, InMemoryAuditSink

signer = PramanixSigner.generate()  # or load from KeyProvider
config = GuardConfig(
    signer=DecisionSigner(signer),
    audit_sinks=[InMemoryAuditSink()],
)
guard = Guard(TransferPolicy, config=config)

decision = guard.verify(intent, state)
# decision.signature is set; decision is in audit_sink.decisions
```

Merkle anchoring lets you prove any single decision was part of an unaltered batch without replaying all decisions:

```python
anchor = MerkleAnchor()
for d in decisions:
    anchor.add(d.decision_id)

proof = anchor.prove(decisions[42].decision_id)
assert proof.verify(anchor.root())
```

For production deployments with many decisions, `MerkleArchiver` handles segment-based flushing at configurable `max_active_entries`, writing `.merkle.archive.YYYYMMDD` files with chain-binding checkpoint leaves.

---

## TOCTOU gap closure

A `Decision(allowed=True)` can be replayed. Without single-use enforcement, an attacker who intercepts an ALLOW decision can trigger the guarded action again without a fresh verification.

`ExecutionToken` closes this gap:

```python
from pramanix import ExecutionTokenSigner, RedisExecutionTokenVerifier

token_signer = ExecutionTokenSigner(secret_key=os.environ["TOKEN_KEY"])
verifier = RedisExecutionTokenVerifier(redis_url=os.environ["REDIS_URL"])

# After verify() returns ALLOW:
token = token_signer.mint(decision)

# At execution time:
if verifier.consume(token, expected_state_version=current_version):
    # execute the action — token is now consumed, cannot be replayed
    pass
```

The in-memory verifier (`InMemoryExecutionTokenVerifier`) is sufficient for single-process deployments. For multi-process or multi-replica deployments, use `RedisExecutionTokenVerifier` or `SQLiteExecutionTokenVerifier`. A process restart clears the in-memory consumed set — tokens minted before restart can be replayed if their TTL has not expired. See `docs/KNOWN_GAPS.md § 1`.

---

## Circuit breaker

Under sustained Z3 solver pressure, use `AdaptiveCircuitBreaker` to shed load while keeping the system responsive:

```python
from pramanix import AdaptiveCircuitBreaker, CircuitBreakerConfig

cb = AdaptiveCircuitBreaker(guard, config=CircuitBreakerConfig(
    pressure_threshold_ms=200,
    open_duration_s=30,
    probe_count=3,
))

decision = await cb.verify_async(intent, state)
# Returns Decision.error(allowed=False) in OPEN/ISOLATED state
```

State machine: `CLOSED → OPEN → HALF_OPEN → CLOSED`. Three consecutive OPEN episodes → `ISOLATED` (requires manual `cb.reset()`). The breaker never returns `allowed=True` from a shed decision.

For distributed deployments (multiple replicas), `DistributedCircuitBreaker` shares state across instances via `RedisDistributedBackend`.

---

## Policy fingerprinting

In rolling deployments, replicas may run different policy versions simultaneously. Pin the expected policy hash in `GuardConfig` to detect drift at startup:

```python
# One-time: get the hash from a reference build
guard = Guard(TransferPolicy)
print(guard.policy_hash)  # "sha256:a1b2c3d4..."

# In production config:
config = GuardConfig(
    expected_policy_hash=os.environ["PRAMANIX_EXPECTED_POLICY_HASH"],
)
# Guard construction raises ConfigurationError immediately if hash mismatches
guard = Guard(TransferPolicy, config=config)
```

---

## FastAPI integration

```python
from fastapi import FastAPI
from pramanix.integrations.fastapi import PramanixMiddleware

app = FastAPI()
app.add_middleware(
    PramanixMiddleware,
    guard=guard,
    intent_extractor=lambda req: ...,  # dict from request
    state_loader=lambda req: ...,      # dict from request
)
```

The middleware applies `timing_budget_ms` to both ALLOW and BLOCK responses unconditionally. Asymmetric timing between ALLOW and BLOCK leaks an oracle that distinguishes allowed from blocked intents.

---

## LangChain integration

```python
from pramanix.integrations.langchain import PramanixGuardedTool

async def execute_transfer(intent: dict) -> str:
    await payment_gateway.transfer(**intent)
    return "ok"

tool = PramanixGuardedTool(
    name="transfer_funds",
    description="Transfer funds between accounts",
    policy=TransferPolicy,
    intent_model=TransferIntent,
    execute_fn=execute_transfer,  # required — no default
)
```

`execute_fn=None` emits `UserWarning` at construction time and raises `NotImplementedError` on `_arun()`. This changed in v1.0.0 — the previous silent default (`lambda i: "OK"`) was a correctness failure.

---

## @guard decorator

```python
from pramanix import guard as guard_decorator

@guard_decorator(policy=TransferPolicy, on_block="raise")
async def transfer_funds(amount: Decimal, balance: Decimal, **kwargs):
    ...

# Raises GuardViolationError on BLOCK; kwargs must contain all policy field names
```

`on_block="return"` returns the `Decision` directly instead of raising.

---

## Primitives

Pre-built policy mixin classes for common domains. Use `invariant_mixin` to compose them into your own policy:

```python
from pramanix import Policy, invariant_mixin
from pramanix.primitives.finance import NonNegativeBalance, UnderDailyLimit
from pramanix.primitives.rbac import RoleMustBeIn

@invariant_mixin(NonNegativeBalance, UnderDailyLimit, RoleMustBeIn)
class MyPolicy(Policy):
    ...
```

Available modules: `finance`, `fintech`, `healthcare`, `rbac`, `time`, `infra`, `common`.

`fintech.py` and `healthcare.py` carry legal disclaimers. The constraint patterns are implemented correctly; they are not compliance advice and do not substitute for qualified legal or clinical review.

---

## Observability

**Prometheus** (when `prometheus-client` installed and `metrics_enabled=True`):

| Metric | Type |
|---|---|
| `pramanix_decisions_total` | Counter (labels: `policy`, `status`) |
| `pramanix_decision_latency_seconds` | Histogram |
| `pramanix_solver_timeouts_total` | Counter |
| `pramanix_validation_failures_total` | Counter |
| `pramanix_circuit_state` | Gauge |
| `pramanix_circuit_pressure_events_total` | Counter |

**OpenTelemetry** (when `opentelemetry-sdk` installed and `otel_enabled=True`):

Span: `pramanix.guard.verify` with attributes `policy`, `allowed`, `status`, `latency_ms`.

**Structured logging** (always active via `structlog`):

```python
from pramanix.logging_helpers import configure_production_logging
configure_production_logging(level="WARNING", fmt="json")
```

Secrets redaction runs before any renderer. Keys matching `secret`, `api_key`, `token`, `hmac`, `password`, `credential` are replaced with `<redacted>` in all log records.

---

## CLI

```bash
# Check environment and configuration
pramanix doctor
pramanix doctor --strict          # exit 1 on warnings
pramanix doctor --json            # machine-readable

# Policy tools
pramanix simulate --intent intent.json --policy myapp.policies:TransferPolicy
pramanix schema export --policy myapp.policies:TransferPolicy
pramanix policy migrate --migration myapp.migrations:v1_to_v2 --state state.json

# Audit tools
pramanix verify-proof --key public.pem < signed_decision.json
pramanix audit verify audit.jsonl --fail-fast

# Injection scorer calibration
pramanix calibrate-injection --dataset labelled.jsonl --output scorer.pkl
```

`pramanix doctor` checks: Z3 installation, Pydantic version, policy hash binding, logging handlers, `PRAMANIX_ENV` warnings, Redis connectivity (if `PRAMANIX_REDIS_URL` set), and 4 others. Exit 0 = clean. Exit 1 = any failure. Exit 2 = usage error.

---

## Key management

For production Ed25519 signing, use a `KeyProvider` instead of inline PEM:

```python
from pramanix import AwsKmsKeyProvider, DecisionSigner, GuardConfig

key_provider = AwsKmsKeyProvider(
    secret_name="pramanix/signing-key",
    region_name="us-east-1",
)
config = GuardConfig(signer=DecisionSigner.from_provider(key_provider))
```

Available providers: `PemKeyProvider`, `EnvKeyProvider`, `FileKeyProvider`, `AwsKmsKeyProvider`, `AzureKeyVaultKeyProvider`, `GcpKmsKeyProvider`, `HashiCorpVaultKeyProvider`.

All cloud providers accept an injected `_client` parameter for testing without real credentials. None of them have been tested against live cloud endpoints in CI — see `docs/KNOWN_GAPS.md § 5`.

---

## Version stability

`pramanix.__stability__` is the authoritative stability contract:

```python
{
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
}
```

**stable** — semver-protected. No breaking changes without a major version bump. Deprecation notice required before removal.

**beta** — usable in production. May change in minor versions with a deprecation notice.

See `docs/PUBLIC_API.md` for the full export list with types and notes.

---

## Known limitations

Selected items from `docs/KNOWN_GAPS.md`:

- **`InMemoryExecutionTokenVerifier` is not durable.** Process restart clears the consumed set. Use `Redis-` or `SQLite-` backed verifier for replay protection across restarts.
- **Not published to PyPI.** `pip install pramanix` will fail until a release is published. See `docs/RELEASE_CHECKLIST.md`.
- **Enterprise audit sinks (`KafkaAuditSink`, `S3AuditSink`, `SplunkHecAuditSink`, `DatadogAuditSink`) are tested with mock clients only.** Transport-layer integration against real endpoints is not in CI.
- **Cloud KMS providers are tested with mock clients only.** IAM permissions and network policies in real cloud environments are not verified in CI.
- **`async-process` mode is not tested on Windows in CI.** The dev machine is Windows 11 and unit tests pass in `sync` mode, but `ProcessPoolExecutor` with spawn start method on Windows has no CI coverage.
- **`interceptors/__init__.py` declares `__all__` without importing the names.** Import directly from `pramanix.interceptors.grpc` and `pramanix.interceptors.kafka`.
- **Translator has no circuit breaker around LLM calls.** Sustained LLM outages add LLM timeout latency to every blocked request.
- **`PolicyAuditor.uncovered_fields()` misses custom `ConstraintExpr` subclasses** that wrap fields in non-standard node types.

Full list: `docs/KNOWN_GAPS.md`.

---

## Development setup

```bash
git clone https://github.com/viraj1011JAIN/Pramanix
cd Pramanix
python -m venv .venv && source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -e '.[all]'
pip install pytest pytest-asyncio pytest-cov hypothesis
pytest tests/unit/ -q
```

Integration tests require Docker for Kafka, PostgreSQL, and Redis containers (via testcontainers):

```bash
pytest tests/integration/ -q
```

Adversarial and property tests:

```bash
pytest tests/adversarial/ tests/property/ -q
```

Coverage gate is 98% branch coverage. Run with:

```bash
pytest --cov=pramanix --cov-branch --cov-fail-under=98
```

---

## License

AGPL-3.0-only. If you distribute a modified version or run it as a network service, the source of your modifications must be made available under the same license.

Commercial licensing for proprietary deployments: contact viraj@pramanix.dev.

---

## docs/

| Document | Contents |
|---|---|
| `docs/ARCHITECTURE_NOTES.md` | Subsystem boundaries, failure models, cross-cutting invariants |
| `docs/PUBLIC_API.md` | Full export list with stability tiers |
| `docs/CHANGELOG.md` | Version history (v0.0.0 → v1.0.0) |
| `docs/MIGRATION.md` | Breaking change guide with before/after code |
| `docs/KNOWN_GAPS.md` | Honest list of unfinished work and known limitations |
| `docs/DECISIONS.md` | Architecture decision records |
| `docs/HANDOVER.md` | Implementation notes, testing strategy, deployment guidance |
| `docs/RELEASE_CHECKLIST.md` | Pre-release verification steps |
| `docs/Blueprint.md` | Original design document |
