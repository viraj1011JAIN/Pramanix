# Pramanix

**Deterministic Neuro-Symbolic Guardrails for Autonomous AI Agents**

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://python.org)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.7.0-orange.svg)](src/pramanix/__init__.py)
[![Tests](https://img.shields.io/badge/tests-1601%20passed-brightgreen.svg)](#benchmarks--coverage)
[![Coverage](https://img.shields.io/badge/coverage-98%25%20line-brightgreen.svg)](#benchmarks--coverage)
[![RSS](https://img.shields.io/badge/RSS-13--56%20MB-brightgreen.svg)](#benchmarks--coverage)

Pramanix sits between an AI agent's intent and the real-world action it takes. Before any action executes, Z3 formally decides whether the submitted values satisfy all declared constraints. Every ALLOW is satisfiable under Z3; every BLOCK names the violated invariant with a concrete counterexample, not a probabilistic guess.

> **Scope note:** Z3 is an SMT solver — it decides constraint satisfiability within a bounded first-order theory. This is *constraint satisfaction verification*, not full formal verification in the sense of interactive theorem provers (Coq, Isabelle) or temporal model checkers (TLA+, SPIN). Z3 cannot reason about liveness or temporal properties, and cannot verify that your Z3 encoding is correct. What it *can* guarantee: if Z3 returns SAT, the submitted values satisfy every declared arithmetic, boolean, and membership constraint exhaustively.

---

## Why Pramanix

AI agents now initiate bank transfers, delete database records, and deploy infrastructure. LLM-based guardrails can be jailbroken; regex rules are bypassed with rephrasing; human review does not scale.

Pramanix applies **constraint satisfaction verification**: the Z3 solver evaluates the *mathematical structure* of your constraints against the actual submitted values. There is no natural language to manipulate. Either the values satisfy the constraints (ALLOW + proof of satisfiability) or they do not (BLOCK + concrete counterexample).

---

## Install

```bash
pip install pramanix
```

---

## Quick Start

```python
from decimal import Decimal
from pramanix import Guard, GuardConfig, Policy, Field, E

class BankingPolicy(Policy):
    class Meta:
        version = "1.0"

    amount      = Field("amount",      Decimal, "Real")
    balance     = Field("balance",     Decimal, "Real")
    daily_limit = Field("daily_limit", Decimal, "Real")
    is_frozen   = Field("is_frozen",   bool,    "Bool")

    @classmethod
    def invariants(cls):
        return [
            (E(cls.balance) - E(cls.amount) >= 0)
                .named("sufficient_balance")
                .explain("Insufficient balance: {balance} < {amount}"),

            (E(cls.amount) <= E(cls.daily_limit))
                .named("within_daily_limit")
                .explain("Amount {amount} exceeds daily limit {daily_limit}"),

            (~E(cls.is_frozen))           # idiomatic boolean NOT — prefer this form
                .named("account_not_frozen")
                .explain("Account is frozen"),
        ]

guard = Guard(BankingPolicy, GuardConfig(execution_mode="sync"))

decision = guard.verify(
    intent={"amount": Decimal("500.00")},
    state={
        "balance":     Decimal("1000.00"),
        "daily_limit": Decimal("5000.00"),
        "is_frozen":   False,
        "state_version": "1.0",
    },
)

if decision.allowed:
    execute_transfer()               # Z3-satisfiable: all invariants hold
else:
    raise PolicyViolation(decision.explanation)
```

> **DSL note:** `~E(cls.is_frozen)` is the idiomatic way to negate a boolean field.
> `E(field) == False` also compiles correctly — the `__eq__` overload returns a
> `ConstraintExpr` for Z3, not a Python bool — but requires `# noqa: E712` to
> suppress the linter. Prefer `~` in production policies.

### Neuro-Symbolic Mode (Natural Language → Verified Action)

```python
decision = await guard.parse_and_verify(
    "please move five hundred dollars to alice",
    TransferIntent,                              # Pydantic model for expected fields
    state=account_state,
    models=("gpt-4o", "claude-opus-4-5"),        # dual-model consensus required
)
# LLM disagreement → Decision.consensus_failure(status=CONSENSUS_FAILURE)
# LLM agreement does not skip Phase 2 — Z3 always verifies
```

---

## Core Concept: The Two-Phase Model

```
Free-form text → [Phase 1: Dual-LLM extraction] → [Phase 2: Z3 verification] → Decision
Structured dict →                                   [Phase 2: Z3 verification] → Decision
```

**Phase 1** (optional): Two LLMs extract structured intent from free-form text and must agree. Disagreement returns `Decision.consensus_failure()` (`status=CONSENSUS_FAILURE`) — this is an *expected policy outcome*, not an error. Agreement does not skip Phase 2.

**Phase 2** (required): Z3 checks every policy invariant against submitted values. SAT → `Decision.safe()`. UNSAT → `Decision.unsafe()` with `violated_invariants` and `explanation`.

**Fail-safe contract:** `guard.verify()` never raises. Every error — Z3 timeout, validation failure, unexpected exception — returns `Decision(allowed=False)`. `allowed=True` is unreachable from any error path.

---

## Policy DSL

```python
# Fields: declare the bridge between your data model and Z3 sorts
amount    = Field("amount",    Decimal, "Real")   # "Real" | "Int" | "Bool" | "String"
count     = Field("count",     int,     "Int")
is_active = Field("is_active", bool,    "Bool")
status    = Field("status",    str,     "String")

# Expressions: Python operators compile to Z3 AST nodes — no eval/exec/ast.parse
E(balance) - E(amount) >= 0
E(amount)  <= E(daily_limit)
~E(is_frozen)                           # boolean NOT
(E(amount) > 0) & (E(balance) > 0)     # AND
(E(frozen) == False) | (E(admin))       # OR (== False also valid; see DSL note)
E(status).is_in(["pending", "active"]) # membership

# Invariants: named constraints with interpolated explanations
(E(cls.balance) - E(cls.amount) >= 0)
    .named("sufficient_balance")
    .explain("Balance {balance} too low for transfer {amount}")
```

### Decision Object

```python
decision.allowed              # bool — True iff all invariants satisfied
decision.status               # SolverStatus enum
decision.violated_invariants  # tuple[str, ...] — labels of failed invariants
decision.explanation          # human-readable violation message
decision.decision_id          # UUID4 string for distributed tracing
decision.solver_time_ms       # float — Z3 wall-clock time
decision.to_dict()            # JSON-serialisable dict

# SolverStatus values (all except SAFE produce allowed=False):
# SAFE               → allowed=True
# UNSAFE             → Z3 found a counterexample
# CONSENSUS_FAILURE  → dual-LLM extraction disagreed (Phase 1)
# TIMEOUT            → Z3 exceeded solver_timeout_ms
# ERROR              → unexpected internal error
# STALE_STATE        → state_version mismatch
# VALIDATION_FAILURE → Pydantic validation failed
# RATE_LIMITED       → load shedding active
```

### `@guard` Decorator

```python
from pramanix import guard

@guard(BankingPolicy, config=GuardConfig(execution_mode="sync"))
def execute_transfer(amount: Decimal, balance: Decimal, daily_limit: Decimal, is_frozen: bool):
    # Function body runs only if all invariants are satisfied
    ...
```

- **Argument mapping:** All keyword arguments are passed as the combined intent+state dict. Argument names must match `Field` names declared in the policy.
- **On BLOCK:** raises `PolicyViolationError(decision)`. Access `e.decision.explanation` and `e.decision.violated_invariants` in the handler.
- **Async state:** For async-mode guards, pre-resolve all dynamic state before calling the decorated function. Use `async-thread` mode and an `async def` wrapper for async callsites.
- **Introspection:** `execute_transfer.__guard__` exposes the underlying `Guard` instance.

---

## Configuration

```python
guard = Guard(
    BankingPolicy,
    GuardConfig(
        execution_mode           = "async-process",  # "sync" | "async-thread" | "async-process"
        solver_timeout_ms        = 100,              # align with your P99 SLA — see warning below
        max_workers              = 8,                # match CPU core count
        max_decisions_per_worker = 10_000,           # recycle workers to prevent Z3 memory accumulation
        worker_warmup            = True,             # dummy solve on startup eliminates cold-start
        fast_path_enabled        = True,
        fast_path_rules          = (
            SemanticFastPath.negative_amount("amount"),
            SemanticFastPath.account_frozen("is_frozen"),
            SemanticFastPath.zero_or_negative_balance("balance"),
        ),
        metrics_enabled          = True,
        otel_enabled             = True,
        shed_worker_pct          = 90.0,
        shed_latency_threshold_ms= 200.0,
        log_level                = "INFO",
    ),
)
```

> **`solver_timeout_ms` warning:** This is a hard stall budget. If Z3 reaches the timeout, the request blocks for exactly `solver_timeout_ms` milliseconds before returning `Decision(allowed=False, status=TIMEOUT)`. The default is `5_000` (5 seconds). **Never use the default in production.** For a P99 target of 15ms, set this to `100`–`150`. A value of `5_000` will cascade stalls into your load shedder's P99 calculation and trip the circuit breaker under adversarial inputs.

All `GuardConfig` fields are overridable via `PRAMANIX_<FIELD_NAME_UPPER>` environment variables.

---

## Production Deployment

### Docker

```dockerfile
# Alpine is BANNED — z3-solver has musl compatibility issues
FROM python:3.11-slim

WORKDIR /app
COPY pyproject.toml .
RUN pip install --no-cache-dir .     # wheel install — never use pip install -e . in production

COPY src/ src/
CMD ["uvicorn", "myapp:app", "--host", "0.0.0.0", "--port", "8000"]
```

> **Why not `pip install -e .`:** Editable installs work by writing a `.pth` file that points back to the source tree. In a Docker image the source tree is `/app/src/` — correct locally, but the path reference breaks when the image is re-layered or copied. Always use a wheel install in production containers.

### Cryptographic Audit Trail

```python
from pramanix import DecisionSigner, DecisionVerifier, MerkleAnchor

signer   = DecisionSigner(key=your_hmac_key)
token    = signer.sign(decision)          # HMAC-SHA256 JWS token, individually verifiable

anchor   = MerkleAnchor()
anchor.append(decision)
root_hash = anchor.root()                 # sequential ordering proof; tampering invalidates chain

# CLI audit verification
# pramanix verify-proof <token>           exits 0 (VALID) or 1 (INVALID)
# pramanix verify-proof <token> --json    JSON output for scripting
```

> **Known limitation — Merkle persistence:** `MerkleAnchor` is process-scoped. The chain resets on process restart. For durable, cross-restart audit trails, export `root_hash` to an append-only store (Redis stream, database, or write-once log) at every checkpoint. Individual `DecisionSigner` HMAC tokens remain independently verifiable without the chain; the chain provides sequential *ordering* proof, not individual decision integrity.

### Adaptive Circuit Breaker

```python
from pramanix import AdaptiveCircuitBreaker, CircuitBreakerConfig

breaker = AdaptiveCircuitBreaker(CircuitBreakerConfig(
    failure_threshold  = 5,    # OPEN after 5 consecutive failures
    recovery_timeout_s = 30,   # attempt HALF_OPEN after 30s
    half_open_max_calls= 3,    # 3 probe calls before CLOSED
))

# State machine: CLOSED → OPEN → HALF_OPEN → CLOSED
# 3 consecutive OPEN cycles → ISOLATED (manual reset required)
# To reset an ISOLATED breaker: breaker.reset()
with breaker:
    decision = guard.verify(intent, state)
```

### Prometheus Metrics

```
pramanix_decisions_total{policy, status}          counter
pramanix_decision_latency_seconds{policy}         histogram
pramanix_solver_timeouts_total{policy}            counter
pramanix_validation_failures_total{policy}        counter
```

### Graceful Shutdown

```python
await guard.shutdown()   # release worker pool — always call on application exit
```

---

## Known Limitations

**TOCTOU:** Pramanix verifies state at the moment `verify()` is called, not at execution time. In concurrent systems, two requests can both pass verification and then both execute against a shared resource. Compose with optimistic locking or transactional commit protocols at the execution layer.

**Z3 encoding scope:** Z3 verifies that submitted values satisfy your declared constraints. It does not verify that state was accurately fetched, that the intent dict matches what the executor will actually do, or that your invariants fully capture your safety requirements. Invariants should be reviewed by domain experts.

**Phase 1 injection:** When `parse_and_verify()` is used, the LLM extraction layer processes untrusted text through a 6-layer injection hardening pipeline (NFKC normalize → parallel LLM extraction → partial-failure gate → Pydantic validate → consensus → injection confidence scoring). The injection confidence scorer computes a signal-weighted score in `[0, 1]`; scores ≥ 0.5 raise `InjectionBlockedError` before consensus is evaluated. This threshold is currently hardcoded — it is not a `GuardConfig` parameter. Phase 2 (Z3) is the binding safety guarantee regardless of what Phase 1 produces.

**Z3 native crashes (sync mode):** Python's `except Exception` cannot catch a Z3 C++ segfault (SIGABRT/SIGSEGV). In `async-process` mode, worker process death surfaces correctly as a fail-safe BLOCK. Use `async-process` mode in production for process-level isolation.

**Z3 string theory:** The `String` sort uses sequence theory, which is decidable but slower than arithmetic sorts. For string-heavy policies, prefer `is_in()` membership checks and tune `solver_timeout_ms` accordingly.

**Merkle persistence:** Documented above in [Cryptographic Audit Trail](#cryptographic-audit-trail).

---

## Benchmarks & Coverage

Measured on: Windows 11 / Python 3.11 / single-process sync mode.
Policy: `BankingPolicy` (5 invariants), n=500 decisions post-warmup.

> **Lower-bound benchmark:** 5 invariants is a minimal policy. Phase B (per-invariant solver instances on UNSAT paths) scales linearly with invariant count. A production RBAC or AML policy with 20–50 invariants will have materially higher P99 on BLOCK decisions. Benchmark *your* policy before committing to SLAs. Run `python benchmarks/latency_benchmark.py` to reproduce locally.

| Metric | Target | Measured |
|--------|--------|---------|
| P50 latency (sync) | < 6 ms  | 5.38 ms ✅ |
| P95 latency (sync) | < 10 ms | 6.01 ms ✅ |
| P99 latency (sync) | < 15 ms | 6.40 ms ✅ — CI-enforced nightly |
| Fast-path average  | < 1 ms  | < 1 ms  ✅ |
| 1M decisions RSS growth | < 20 MiB | ~13 MiB ✅ |

> P99 < 15 ms is enforced by a nightly CI benchmark job. A z3-solver patch causing P99 regression fails the build automatically.

**Memory — measured over ~2 hours continuous operation (Windows 11, WorkingSet64 sampling every 60s):**

| Condition | RSS |
|-----------|-----|
| Z3 JIT warm-up (first 8 min) | 107–123 MB |
| Idle / low-activity floor    |  13–29 MB  |
| Active decision processing   |  30–56 MB  |

No upward drift detected across 2 hours. The sawtooth oscillation (e.g., 48→32→48 MB) is normal Python GC behavior. Linux production RSS will be lower — shared library pages are not counted in VmRSS the same way as Windows WorkingSet64.

**Tests & coverage:**

```
Tests:    1601 passed · 0 failed · 2 skipped (Docker/Redis not available in CI)
Coverage: 98% line · 96% statement · 93% branch   (threshold: 95%)
```

| Suite | Count | What it covers |
|-------|-------|----------------|
| Unit | ~800 | All modules, every public method, every edge case |
| Integration | ~500 | Guard + Policy end-to-end, all 3 execution modes, integration adapters with mocked runtimes |
| Performance | ~50 | Latency targets, fast-path speed, 1M-decision memory stability |
| Dark-path | ~180 | Adversarial inputs, injection attacks, malformed data, Z3 timeout, all error paths |

---

## Comparison

| Capability | Pramanix | LangChain Guards | Guardrails AI | LLM-as-Judge | OpenPolicy Agent |
|-----------|:--------:|:----------------:|:-------------:|:------------:|:----------------:|
| Constraint satisfaction proof | ✅ | ❌ | ❌ | ❌ | ✅ (Rego logic) |
| Counterexample on violation | ✅ | ❌ | ❌ | ❌ | Partial |
| Fail-safe: errors = BLOCK | ✅ | ❌ | ❌ | ❌ | ✅ |
| Natural language input | ✅ | ✅ | ✅ | ✅ | ❌ |
| No LLM required for verification | ✅ | ❌ | ❌ | ❌ | ✅ |
| Cryptographic audit trail | ✅ | ❌ | ❌ | ❌ | ❌ |
| Circuit breaker + load shedding | ✅ | ❌ | ❌ | ❌ | ❌ |
| Async worker pools | ✅ | ❌ | ❌ | ❌ | ✅ |
| Python policy DSL | ✅ | ❌ | ✅ | ❌ | ❌ (Rego) |
| Per-invariant violation attribution | ✅ | ❌ | ❌ | ❌ | Partial |
| Memory stable at 1M decisions | ✅ (30–56 MB active) | Unknown | Unknown | N/A | ✅ |

> When `parse_and_verify()` is active (neuro-symbolic mode), the LLM extraction layer processes untrusted text and is susceptible to adversarial manipulation. Phase 2 (Z3) is the binding safety guarantee in all modes.

---

## Supply Chain

Every PyPI release ships with GitHub-attested provenance (Sigstore OIDC), SBOM, and Sigstore signatures. Verify:

```bash
gh attestation verify --owner virajjain dist/pramanix-*.whl
```

> **Provenance level:** The current release pipeline satisfies SLSA Level 2 requirements (hosted build platform, signed provenance). SLSA Level 3 (hermetic/reproducible build, out-of-band build definition) is on the roadmap for v1.0 GA.

---

## Ecosystem Integrations

```python
# FastAPI
from pramanix.integrations.fastapi import PramanixMiddleware, pramanix_route
app.add_middleware(PramanixMiddleware, policy=BankingPolicy)

# LangChain
from pramanix.integrations.langchain import wrap_tools
safe_tools = wrap_tools(agent_tools, BankingPolicy, config=GuardConfig(execution_mode="sync"))

# AutoGen
from pramanix.integrations.autogen import PramanixToolCallback
callback = PramanixToolCallback.wrap(BankingPolicy)

# LlamaIndex
from pramanix.integrations.llamaindex import PramanixFunctionTool
guarded_tool = PramanixFunctionTool(fn=execute_transfer, policy=BankingPolicy, fn_schema=TransferSchema)
```

---

## Project Status

**v0.7.0** — Core SDK complete: Policy DSL, Z3 solver, async worker pools, dual-LLM translator, CI/CD (SLSA), 25 domain primitives, FastAPI/LangChain/LlamaIndex/AutoGen integrations, Prometheus + OpenTelemetry, adversarial test suite.

**v0.8.0** (in progress): Redis-backed audit trail, Ed25519 signing, compliance reporter, audit CLI.

| Milestone | Status |
|-----------|--------|
| v0.1 Core SDK (Policy DSL, Z3, sync verify) | ✅ |
| v0.2 Async modes (thread/process pools, worker recycling) | ✅ |
| v0.3 Hardening (ContextVar isolation, HMAC IPC, OTel, Hypothesis) | ✅ |
| v0.4 Translator (dual-LLM consensus, 6-layer injection defense) | ✅ |
| v0.5 CI/CD (SLSA provenance, Sigstore, SBOM, hardened Docker, K8s) | ✅ |
| v0.6 Primitives (25 domain primitives with CFR/HIPAA citations) | ✅ |
| v0.7 Performance (expression cache, load shedding, benchmarks) | ✅ |
| v0.8 Audit (Ed25519 signing, compliance reporter, audit CLI) | 🔄 |
| v0.9 Docs site, policy registry, extended benchmark suite | 📋 |
| v1.0 GA (chaos testing, RC deployment, API contract lock) | 📋 |

---

## License

- **Community:** [AGPL-3.0](LICENSE) — free to use and modify; changes must be open-sourced
- **Enterprise:** Commercial license for closed-source deployments, SLA support, and compliance packages

---

*Built by Viraj Jain. Pramāṇa (प्रमाण) — "valid source of knowledge" or "proof."*
