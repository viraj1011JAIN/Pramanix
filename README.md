<p align="center">
  <br />
  <strong style="font-size: 2em;">PRAMANIX</strong>
  <br />
  <em>Deterministic Neuro-Symbolic Guardrails for Autonomous AI Agents</em>
  <br /><br />
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue?logo=python&logoColor=white" alt="Python 3.11 | 3.12 | 3.13"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-green" alt="License: AGPL-3.0"></a>
  <a href="https://github.com/viraj1011JAIN/Pramanix/actions/workflows/ci.yml"><img src="https://github.com/viraj1011JAIN/Pramanix/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
  <a href="https://codecov.io/gh/viraj1011JAIN/Pramanix"><img src="https://codecov.io/gh/viraj1011JAIN/Pramanix/branch/main/graph/badge.svg" alt="Coverage"></a>
  <a href="https://pypi.org/project/pramanix/"><img src="https://img.shields.io/pypi/v/pramanix?logo=pypi&logoColor=white&color=orange" alt="PyPI"></a>
  <a href="https://pypi.org/project/pramanix/"><img src="https://img.shields.io/pypi/dm/pramanix?logo=pypi&logoColor=white" alt="Downloads"></a>
  <a href="https://slsa.dev/"><img src="https://slsa.dev/images/gh-badge-level3.svg" alt="SLSA Level 3"></a>
  <br /><br />
</p>

> *Pramāṇa (Sanskrit: "proof / valid knowledge") + Unix (composable systems philosophy)*

**Pramanix** is a production-grade Python SDK that places a **mathematically verified execution firewall** between AI agent intent and real-world consequences. Every action it approves carries a formal Z3 SMT proof. Every action it blocks carries an exact counterexample with attributed invariant violations. No ambiguity. No exceptions.

```
AI Agent: "Transfer $5,000 to account X"
                    │
              [ PRAMANIX ]
                    │
        Z3 SMT Solver verifies ALL invariants:
          ✓  balance − amount ≥ 0          … SAT
          ✓  account_not_frozen            … SAT
          ✓  amount ≤ daily_limit          … SAT
          ✓  risk_score ≤ 0.8             … SAT
                    │
             ALLOW  (with cryptographic proof token)
```

---

## Table of Contents

- [Why Pramanix](#why-pramanix)
- [Key Features](#key-features)
- [How It Works](#how-it-works)
- [Installation](#installation)
- [Quick Start](#quick-start)
  - [Structured Mode](#structured-mode)
  - [Neuro-Symbolic Mode](#neuro-symbolic-mode)
  - [Decorator API](#decorator-api)
- [Core Concepts](#core-concepts)
  - [Policy DSL](#policy-dsl)
  - [The Decision Object](#the-decision-object)
  - [Execution Modes](#execution-modes)
- [Domain Examples](#domain-examples)
  - [Banking — Transfer Verification](#banking--transfer-verification)
  - [Healthcare — PHI Access Control](#healthcare--phi-access-control)
  - [Cloud Infrastructure — Replica Scaling](#cloud-infrastructure--replica-scaling)
- [Architecture](#architecture)
  - [Module Reference](#module-reference)
- [Advanced Features](#advanced-features)
  - [Primitives Library](#primitives-library)
  - [Semantic Fast-Path](#semantic-fast-path)
  - [Adaptive Load Shedding](#adaptive-load-shedding)
  - [Adaptive Circuit Breaker](#adaptive-circuit-breaker)
  - [Cryptographic Audit Trail](#cryptographic-audit-trail)
  - [Zero-Trust Identity (JWT)](#zero-trust-identity-jwt)
  - [Intent Cache](#intent-cache)
- [Ecosystem Integrations](#ecosystem-integrations)
  - [FastAPI](#fastapi)
  - [LangChain](#langchain)
  - [LlamaIndex](#llamaindex)
  - [AutoGen](#autogen)
- [Pramanix vs. Alternatives](#pramanix-vs-alternatives)
- [Configuration Reference](#configuration-reference)
- [Security Model](#security-model)
- [Performance](#performance)
- [Deployment](#deployment)
- [CLI](#cli)
- [Contributing](#contributing)
- [License](#license)

---

## Why Pramanix

LLMs are **probabilistic token samplers**. They do not reason — they pattern-match. In regulated, high-stakes domains, this is the difference between a deployable system and a liability.

| Domain | Risk Without Formal Verification |
|---|---|
| **FinTech** | Unauthorized transfers, balance overdraws, fraud bypass |
| **Healthcare** | Unauthorized PHI access, consent violations, dosage errors |
| **Cloud / Infra** | Destructive deletions, scaling beyond quotas, IAM escalation |
| **Legal / Compliance** | Unauthorized attestations, regulatory filing errors |

Current guardrail approaches are fundamentally broken:

| Approach | Why It Fails |
|---|---|
| **Rule-based (regex/if-then)** | Cannot reason about compound constraints. Breaks on edge cases. Unmaintainable at scale. |
| **LLM-as-Judge** | Uses the same probabilistic tool to judge itself. Adversarial prompts override the judge. |
| **OPA / Rego alone** | Handles authorization ("who can try") but not mathematical safety ("is this specific action safe given current state?"). |

**Pramanix replaces probabilistic judgment with formal satisfiability.** The Z3 SMT solver returns mathematically unambiguous SAT / UNSAT — not confidence scores.

---

## Key Features

| Feature | Description |
|---|---|
| **Z3 SMT Verification** | Every decision backed by a formal proof (SAT) or counterexample (UNSAT). Not a heuristic — a mathematical guarantee. |
| **Python-Native Policy DSL** | Write policies as Python class attributes + `invariants()` classmethod. Full IDE autocomplete, mypy strict compatible, zero YAML/Rego. |
| **Fail-Safe by Default** | Any error — LLM failure, timeout, type mismatch, IPC tampering — returns `BLOCK`. `ALLOW` requires positive Z3 proof. |
| **Exact Violation Attribution** | Every blocked decision identifies which invariants failed via Z3 unsat cores. Exact counterexample model values attached. |
| **Three Execution Modes** | `sync`, `async-thread`, `async-process` — match your server architecture. Worker pool with warmup and auto-recycling. |
| **Semantic Fast-Path** | Pure Python O(1) pre-screen blocks obvious violations before Z3 is invoked (`fast_path.py`). Never false-positive. |
| **Adaptive Load Shedding** | Dual-condition limiter: shed when `active_workers ≥ shed_worker_pct` AND `p99 > shed_latency_threshold_ms`. |
| **Adaptive Circuit Breaker** | CLOSED → OPEN → HALF_OPEN → CLOSED state machine protects against Z3 solver pressure cascades. |
| **Cryptographic Audit Trail** | HMAC-SHA256 JWS tokens per Decision. Merkle tree for tamper-evident immutable decision sequences. |
| **Zero-Trust Identity (JWT)** | Per-agent JWT-based policy binding. Redis-backed state loader with signed claims verification. |
| **HMAC IPC Integrity** | Worker results are sealed with an ephemeral HMAC key before crossing the thread/process boundary. Forgery → `Decision.error()`. |
| **Dual-Model LLM Consensus** | `strict_keys`, `lenient`, `unanimous` agreement modes. Both models must agree before Z3 is consulted. |
| **Composable Primitives** | Pre-built constraint factories for finance, fintech, RBAC, infra, healthcare, and time-based policies. |
| **Observability Built-In** | Prometheus counters/histograms, OpenTelemetry span hooks, structured JSON logs with secret redaction. |
| **SLSA Level 3 Supply Chain** | OIDC-authenticated PyPI publishing, Sigstore signing, automated SBOM. |

---

## How It Works

Pramanix operates on a **Two-Phase Execution Model**:

```
Phase 1: INTENT EXTRACTION                    Phase 2: FORMAL VERIFICATION
+---------------------------------+            +----------------------------------+
│                                 │            │                                  │
│  Structured     Neuro-Symbolic  │            │  Z3 SMT Solver (solver.py)       │
│  (typed dict)   (NLP → struct)  │            │                                  │
│       │              │          │            │  For each invariant:             │
│       │         [Translator]    │  ────────► │    assert_and_track(formula)     │
│       │         [dual-model]    │            │    solver.check()                │
│       │         [_sanitise.py]  │            │                                  │
│       └──────┬───────┘          │            │  SAT  → Decision.safe()          │
│              │                  │            │  UNSAT → Decision.unsafe()       │
│       [Pydantic v2 strict]      │            │           + unsat_core()         │
│       [Fast-Path Screen]        │            │           + counterexample       │
│       [Load Shedder]            │            │                                  │
│                                 │            │  LLM involvement: ZERO           │
+---------------------------------+            +----------------------------------+
```

**Critical invariant:** The LLM *never* decides safety policy. It only extracts structured fields from natural language. All verification is Z3 — deterministic, with mathematical guarantees.

---

## Installation

```bash
pip install pramanix
```

**Requirements:** Python 3.11+, z3-solver (auto-installed), pydantic v2, structlog, prometheus-client.

**Optional extras:**

```bash
# LLM translation (Neuro-Symbolic mode)
pip install 'pramanix[translator]'       # httpx + openai + anthropic + tenacity

# FastAPI/Starlette middleware + route decorator
pip install 'pramanix[fastapi]'

# LangChain tool integration (langchain-core >= 0.1)
pip install 'pramanix[langchain]'

# LlamaIndex function/query-engine tools (llama-index-core >= 0.10)
pip install 'pramanix[llamaindex]'

# AutoGen agent integration (pyautogen >= 0.2)
pip install 'pramanix[autogen]'

# All ecosystem integrations at once
pip install 'pramanix[integrations]'

# Zero-trust identity (Redis-backed JWT policy bindings)
pip install 'pramanix[identity]'

# OpenTelemetry tracing
pip install 'pramanix[otel]'

# Everything
pip install 'pramanix[all]'
```

> **Alpine Linux is NOT supported.** Z3's C++ runtime requires glibc. Use `python:3.11-slim` (Debian-based). Alpine musl causes segfaults and build failures with z3-solver.

---

## Quick Start

### Structured Mode

The primary integration pattern — your application provides typed intent and state directly.

```python
from decimal import Decimal
from typing import Literal

from pydantic import BaseModel, Field as PydanticField
from pramanix import Guard, GuardConfig, Policy, Field, E, Decision


# 1. Pydantic models for Pramanix strict validation
class TransferIntent(BaseModel):
    action: Literal["transfer"]
    amount: Decimal = PydanticField(gt=0, le=1_000_000)
    currency: str = PydanticField(pattern=r"^[A-Z]{3}$")

class AccountState(BaseModel):
    balance: Decimal
    is_frozen: bool
    daily_limit: Decimal
    risk_score: float = PydanticField(ge=0.0, le=1.0)
    state_version: str  # required — triggers STALE_STATE if mismatched


# 2. Define the policy using the Python DSL
class BankingPolicy(Policy):
    class Meta:
        version = "1.0"
        intent_model = TransferIntent
        state_model  = AccountState

    # Fields declared as class attributes — auto-discovered by fields()
    amount      = Field("amount",      Decimal, "Real")
    balance     = Field("balance",     Decimal, "Real")
    daily_limit = Field("daily_limit", Decimal, "Real")
    is_frozen   = Field("is_frozen",   bool,    "Bool")
    risk_score  = Field("risk_score",  float,   "Real")

    @classmethod
    def invariants(cls):
        return [
            # Access fields via cls.field_name inside invariants()
            (E(cls.balance) - E(cls.amount) >= 0)
                .named("non_negative_balance")
                .explain("Transfer blocked: amount {amount} exceeds balance {balance}."),

            (E(cls.is_frozen) == False)  # noqa: E712
                .named("account_not_frozen")
                .explain("Transfer blocked: account is currently frozen."),

            (E(cls.amount) <= E(cls.daily_limit))
                .named("within_daily_limit")
                .explain("Transfer blocked: {amount} exceeds daily limit {daily_limit}."),

            (E(cls.risk_score) <= 0.8)
                .named("acceptable_risk_score")
                .explain("Transfer blocked: risk score {risk_score} exceeds threshold 0.8."),
        ]


# 3. Create a Guard (validates policy at construction time)
guard = Guard(
    policy=BankingPolicy,
    config=GuardConfig(
        execution_mode="async-thread",
        solver_timeout_ms=100,
    ),
)


# 4. Verify — always returns a Decision, never raises
async def handle_transfer(amount: Decimal, balance: Decimal) -> None:
    decision: Decision = await guard.verify_async(
        intent={"action": "transfer", "amount": amount, "currency": "USD"},
        state={"balance": balance, "is_frozen": False, "daily_limit": Decimal("10000"),
               "risk_score": 0.3, "state_version": "1.0"},
    )

    if decision.allowed:
        # decision.status == SolverStatus.SAFE — Z3 proved all invariants hold
        print(f"Approved [{decision.decision_id}] in {decision.solver_time_ms:.1f}ms")
    else:
        # UNSAFE, TIMEOUT, ERROR, STALE_STATE, etc. — all blocked
        print(f"Blocked: {decision.explanation}")
        print(f"Violated: {decision.violated_invariants}")
```

### Neuro-Symbolic Mode

For natural language inputs, Pramanix uses a hardened dual-model translator pipeline before Z3 verification.

```python
from pramanix.translator.redundant import RedundantTranslator, create_translator
from pramanix.translator.anthropic import AnthropicTranslator
from pramanix.translator.ollama import OllamaTranslator

# Dual-model consensus — both must agree on critical fields
translator = RedundantTranslator(
    model_a=AnthropicTranslator(model="claude-haiku-4-5-20251001"),
    model_b=OllamaTranslator(model="llama3"),
    agreement_mode="lenient",           # only critical_fields must agree
    critical_fields=frozenset(["amount", "currency"]),
)

# OR use the factory shorthand
translator = create_translator(
    model_a_type="anthropic",
    model_b_type="ollama",
    agreement_mode="strict_keys",
)

decision = await guard.parse_and_verify(
    text="Send five thousand US dollars",
    state=account_state,
    translator=translator,
)
# Pipeline: sanitise → extract (parallel) → validate → consensus → Z3
```

**6-layer translator security pipeline** (`translator/redundant.py`, `translator/_sanitise.py`):

1. **Unicode NFKC normalisation** — collapses homoglyphs and full-width digits
2. **Parallel LLM extraction** — both models run concurrently via `asyncio.gather`
3. **Partial-failure gate** — if either model fails, the request is immediately blocked
4. **Pydantic schema validation** — both outputs must parse against `intent_schema`
5. **Consensus check** — agreement mode determines which fields must match
6. **Injection confidence gate** — heuristic score ≥ 0.5 raises `InjectionBlockedError`

### Decorator API

The `@guard` decorator gates an `async def` function — the body only runs if Z3 approves.

```python
from pramanix import guard, GuardConfig

@guard(policy=BankingPolicy, config=GuardConfig(execution_mode="async-thread"))
async def execute_transfer(intent: dict, state: dict) -> dict:
    # Only reached when Decision.allowed is True
    # On block: raises GuardViolationError with the full Decision attached
    return {"status": "transferred"}


# Soft mode — return the Decision instead of raising on block
@guard(policy=BankingPolicy, on_block="return")
async def execute_transfer_soft(intent: dict, state: dict) -> dict | Decision:
    return {"status": "transferred"}

# The Guard instance is accessible for introspection
execute_transfer.__guard__   # → Guard instance
```

> The `@guard` decorator validates the policy and creates the `Guard` instance **once at decoration time**, not per-call.

---

## Core Concepts

### Policy DSL

Policies are **Python classes** — no YAML, no Rego. Full IDE autocomplete, mypy strict compatible.

```python
from decimal import Decimal
from pramanix import Policy, Field, E

class MyPolicy(Policy):
    class Meta:
        version = "2.0"                    # optional: enables state_version check
        intent_model = MyIntentModel       # optional: Pydantic strict validation
        state_model  = MyStateModel        # optional: must have state_version field

    # Declare fields directly as class attributes
    balance = Field("balance", Decimal, "Real")   # (field_name, python_type, z3_sort)
    amount  = Field("amount",  Decimal, "Real")
    frozen  = Field("is_frozen", bool,  "Bool")
    role    = Field("role", str, "Int")            # strings projected to Int via is_in()

    @classmethod
    def invariants(cls):
        return [
            (E(cls.balance) - E(cls.amount) >= 0)
                .named("non_negative_balance")        # required — used in violation attribution
                .explain("Balance {balance} < amount {amount}."),

            (E(cls.frozen) == False)                  # noqa: E712
                .named("account_not_frozen")
                .explain("Account is frozen."),

            E(cls.role).is_in(["admin", "manager"])
                .named("authorized_role")
                .explain("Role '{role}' not permitted."),
        ]
```

**Field constructor:** `Field(name: str, python_type: type, z3_sort: Literal["Real", "Int", "Bool"])`

**Expression operators** (all compile to Z3 AST — zero `eval()`/`exec()`/`ast.parse()`):

| Operator | Syntax | Z3 output |
|---|---|---|
| Arithmetic | `E(a) + E(b)`, `- E(b)`, `* E(b)`, `/ E(b)` | `ArithRef` |
| Comparison | `>= <= > < == !=` | `BoolRef` |
| Boolean AND | `expr_a & expr_b` | `z3.And(a, b)` |
| Boolean OR | `expr_a \| expr_b` | `z3.Or(a, b)` |
| Boolean NOT | `~constraint_expr` | `z3.Not(a)` |
| Membership | `E(role).is_in(["admin", "dr"])` | `z3.Or(x==v1, x==v2, …)` |
| Label | `.named("label")` | `assert_and_track` label |
| Explanation | `.explain("template {field}")` | human-readable violation message |

> Use `&` / `|` operators, **not** Python `and` / `or` — those evaluate immediately and bypass the expression tree. Use `==` not `is` for boolean field comparisons.

### The Decision Object

Every `verify()` / `verify_async()` call returns an immutable frozen dataclass (`decision.py`).

```python
@dataclass(frozen=True)
class Decision:
    allowed: bool               # True IFF status == SolverStatus.SAFE
    status: SolverStatus        # SAFE | UNSAFE | TIMEOUT | ERROR | STALE_STATE | …
    violated_invariants: tuple[str, ...]    # labels of failed invariants
    explanation: str            # human-readable (filled by .explain() template)
    metadata: dict[str, Any]    # caller-supplied tracing data
    solver_time_ms: float       # wall-clock Z3 time in ms
    decision_id: str            # UUID4 — unique per verify() call
```

**Status codes:**

| Status | Meaning | `allowed` |
|---|---|---|
| `SAFE` | All invariants satisfied — Z3 returned SAT | `true` |
| `UNSAFE` | One or more invariants violated — Z3 UNSAT | `false` |
| `TIMEOUT` | Z3 exceeded `solver_timeout_ms` | `false` |
| `ERROR` | Internal error (fail-safe — never propagates) | `false` |
| `STALE_STATE` | `state_version` ≠ `Meta.version` | `false` |
| `VALIDATION_FAILURE` | Pydantic strict validation failed | `false` |
| `RATE_LIMITED` | Shed by adaptive load limiter | `false` |

**Factory methods:** `Decision.safe()`, `.unsafe()`, `.timeout()`, `.error()`, `.stale_state()`, `.validation_failure()`, `.rate_limited()`

**Serialisation:**
```python
d = decision.to_dict()
# {"decision_id": "…", "allowed": false, "status": "unsafe",
#  "violated_invariants": ["non_negative_balance"],
#  "explanation": "Transfer blocked: amount 5000 exceeds balance 100.",
#  "solver_time_ms": 7.3, "metadata": {}}
```

### Execution Modes

```
Is your server async (FastAPI, Starlette, AIOHTTP)?
│
├── YES → Heavy policies (15+ invariants / BitVec)?
│         ├── YES → execution_mode = "async-process"   (GIL-free, isolated Z3 context)
│         └── NO  → execution_mode = "async-thread"    (DEFAULT)
│
└── NO  → execution_mode = "sync"   (Django, Flask, Celery, scripts)
```

**Worker lifecycle:** Workers auto-recycle after `max_decisions_per_worker` verifications (default 10,000) to prevent Z3 C++ native memory accumulation. `worker_warmup=True` (default) runs a dummy Z3 solve on spawn to eliminate the JIT cold-start latency spike.

**HMAC IPC sealing:** In `async-process` mode, an ephemeral `_EphemeralKey` is generated per-Guard. Worker results are HMAC-SHA256 sealed before crossing the process boundary. The host verifies the seal before trusting the result — a compromised worker process cannot forge `Decision(allowed=True)`.

---

## Domain Examples

### Banking — Transfer Verification

```python
from pramanix.primitives.finance import NonNegativeBalance, UnderDailyLimit, SecureBalance

class BankingPolicy(Policy):
    balance         = Field("balance",         Decimal, "Real")
    amount          = Field("amount",          Decimal, "Real")
    daily_limit     = Field("daily_limit",     Decimal, "Real")
    minimum_reserve = Field("minimum_reserve", Decimal, "Real")
    is_frozen       = Field("is_frozen",       bool,    "Bool")

    @classmethod
    def invariants(cls):
        return [
            SecureBalance(cls.balance, cls.amount, cls.minimum_reserve),  # primitives
            UnderDailyLimit(cls.amount, cls.daily_limit),
            (E(cls.is_frozen) == False).named("not_frozen").explain("Account frozen."),  # noqa: E712
        ]

# Overdraft attempt → UNSAFE
decision = await guard.verify_async(
    intent={"amount": Decimal("5000"), "currency": "USD"},
    state={"balance": Decimal("100"), "daily_limit": Decimal("10000"),
           "minimum_reserve": Decimal("0.01"), "is_frozen": False, "state_version": "1.0"},
)
assert decision.allowed is False
assert "minimum_reserve_maintained" in decision.violated_invariants
```

### Healthcare — PHI Access Control

```python
from pramanix.primitives.rbac import RoleMustBeIn, ConsentRequired, DepartmentMustBeIn

class PHIAccessPolicy(Policy):
    role    = Field("user_role",         str,  "Int")
    consent = Field("patient_consent",   bool, "Bool")
    dept    = Field("department_match",  bool, "Bool")

    @classmethod
    def invariants(cls):
        return [
            RoleMustBeIn(cls.role, ["doctor", "nurse", "admin"]),
            ConsentRequired(cls.consent),
            DepartmentMustBeIn(cls.dept),
        ]
```

See `src/pramanix/primitives/healthcare.py` for PHI least-privilege, HIPAA consent, dosage gradient, break-glass auth, and pediatric dose bounds.

### Cloud Infrastructure — Replica Scaling

```python
from pramanix.primitives.infra import MinReplicas, MaxReplicas, ReplicaBudget

class ScalingPolicy(Policy):
    target  = Field("target_replicas",  int,  "Int")
    minimum = Field("minimum_replicas", int,  "Int")
    maximum = Field("maximum_replicas", int,  "Int")
    is_prod = Field("is_production",    bool, "Bool")

    @classmethod
    def invariants(cls):
        return [
            MinReplicas(cls.target, cls.minimum),
            MaxReplicas(cls.target, cls.maximum),
            # Production HA: prod deployments require ≥ 2 replicas
            (~E(cls.is_prod) | (E(cls.target) >= 2))
                .named("production_ha_minimum")
                .explain("Production requires ≥ 2 replicas."),
        ]
```

See `src/pramanix/primitives/infra.py` for CPU budget, memory budget, blast-radius, prod approval, and combined guards.

---

## Architecture

```
                              ┌══════════════┐
                              ║    CALLER    ║
                              ║ FastAPI /    ║
                              ║ LangChain /  ║
                              ║ AutoGen      ║
                              └──────┬───────┘
                                     │  guard.verify_async(intent, state)
                                     ▼
                   ┌────────────────────────────────────┐
                   │              GUARD  (guard.py)      │
                   │                                     │
                   │  ┌──────────────────────────────┐  │
                   │  │  Translator (optional)        │  │
                   │  │  • AnthropicTranslator        │  │
                   │  │  • OllamaTranslator           │  │
                   │  │  • OpenAICompatTranslator     │  │
                   │  │  • RedundantTranslator        │  │
                   │  │    (dual-model consensus)     │  │
                   │  └──────────────┬───────────────┘  │
                   │                 │                   │
                   │  ┌──────────────▼───────────────┐  │
                   │  │  Validator (validator.py)     │  │
                   │  │  Pydantic v2 strict mode      │  │
                   │  └──────────────┬───────────────┘  │
                   │                 │                   │
                   │  ┌──────────────▼───────────────┐  │
                   │  │  Semantic Fast-Path            │  │
                   │  │  (fast_path.py)               │  │
                   │  │  Pure Python O(1) pre-screen  │  │
                   │  │  Can only BLOCK, never ALLOW  │  │
                   │  └──────────────┬───────────────┘  │
                   │                 │                   │
                   │  ┌──────────────▼───────────────┐  │
                   │  │  Adaptive Load Shedder        │  │
                   │  │  (worker.py AdaptiveLimiter)  │  │
                   │  │  shed when ≥90% workers busy  │  │
                   │  │  AND p99 > 200ms              │  │
                   │  └──────────────┬───────────────┘  │
                   │                 │                   │
                   │  ┌──────────────▼───────────────┐  │
                   │  │  Resolver Registry            │  │
                   │  │  (resolvers.py)               │  │
                   │  │  ContextVar cache isolation   │  │
                   │  └──────────────┬───────────────┘  │
                   │                 │                   │
                   │    ┌────────────┴─────────────┐    │
                   │    │  Thread/Process Boundary  │    │
                   │    │  HMAC-SHA256 sealed IPC   │    │
                   │    └────────────┬─────────────┘    │
                   │                 │                   │
                   │  ┌──────────────▼───────────────┐  │
                   │  │  Worker (worker.py)           │  │
                   │  │  ┌──────────────────────┐    │  │
                   │  │  │  TRANSPILER          │    │  │
                   │  │  │  (transpiler.py)     │    │  │
                   │  │  │  DSL → Z3 AST        │    │  │
                   │  │  │  compile_policy()    │    │  │
                   │  │  └──────────┬───────────┘    │  │
                   │  │             │                 │  │
                   │  │  ┌──────────▼───────────┐    │  │
                   │  │  │  Z3 SOLVER           │    │  │
                   │  │  │  (solver.py)         │    │  │
                   │  │  │  assert_and_track()  │    │  │
                   │  │  │  unsat_core()        │    │  │
                   │  │  │  timeout enforced    │    │  │
                   │  │  └──────────┬───────────┘    │  │
                   │  └────────────┬┘                │  │
                   │               │  HMAC verify     │  │
                   │  ┌────────────▼─────────────┐   │  │
                   │  │  Decision Builder         │   │  │
                   │  │  (decision.py)            │   │  │
                   │  │  frozen dataclass         │   │  │
                   │  └────────────┬─────────────┘   │  │
                   │               │                  │  │
                   │  ┌────────────▼─────────────┐   │  │
                   │  │  Telemetry (telemetry.py) │   │  │
                   │  │  Prometheus + OTel spans  │   │  │
                   │  └────────────┬─────────────┘   │  │
                   └───────────────┼─────────────────┘
                                   │
                            Decision (returned)
                                   │
                   ┌───────────────▼─────────────────┐
                   │  Audit Trail (audit/)            │
                   │  DecisionSigner → JWS token      │
                   │  MerkleAnchor  → tamper-evident  │
                   └──────────────────────────────────┘
```

### Module Reference

| Module | Public API | Responsibility |
|---|---|---|
| `guard.py` | `Guard`, `GuardConfig` | SDK entrypoint — compile policy, manage worker pool, `verify()` / `verify_async()` / `parse_and_verify()` |
| `policy.py` | `Policy` | Base class — `fields()` auto-discovery, `invariants()` classmethod, `validate()`, `Meta` inner class |
| `expressions.py` | `E`, `Field`, `ConstraintExpr`, `ExpressionNode` | Lazy expression tree via operator overloading → AST nodes |
| `transpiler.py` | `compile_policy()`, `collect_fields()`, `InvariantMeta` | DSL AST → Z3 AST. Zero `ast.parse`/`eval`/`exec`. |
| `solver.py` | `solve()`, `_SolveResult` | Z3 context isolation, `assert_and_track`, unsat core, configurable timeouts |
| `worker.py` | `WorkerPool`, `AdaptiveConcurrencyLimiter`, `_EphemeralKey` | Worker spawn/warmup/recycle, HMAC IPC sealing, load shedding |
| `decision.py` | `Decision`, `SolverStatus` | Immutable frozen dataclass, factory methods, `to_dict()` |
| `validator.py` | `validate_intent()`, `validate_state()` | Pydantic v2 strict schema validation |
| `resolvers.py` | `ResolverRegistry` | Lazy field resolution with `ContextVar` per-request cache isolation |
| `fast_path.py` | `SemanticFastPath`, `FastPathEvaluator`, `FastPathResult` | Pure Python O(1) pre-screen rules before Z3 |
| `decorator.py` | `guard()` | `@guard(policy=…)` decorator factory for async functions |
| `exceptions.py` | 19 exception classes | Full hierarchy from `PramanixError` base |
| `telemetry.py` | Prometheus + OTel hooks | `pramanix_decisions_total`, `pramanix_decision_latency_seconds`, `pramanix_solver_timeouts_total` |
| `helpers/serialization.py` | `safe_dump()` | JSON-safe serialization helper |
| `helpers/type_mapping.py` | `python_type_to_z3_sort()` | Python type → Z3 sort mapping |
| **Translator** | | |
| `translator/base.py` | `Translator`, `TranslatorContext` | ABC for LLM translation backends |
| `translator/anthropic.py` | `AnthropicTranslator` | Claude (streaming + content block extraction) |
| `translator/ollama.py` | `OllamaTranslator` | Ollama local models (OpenAI-compatible JSON mode) |
| `translator/openai_compat.py` | `OpenAICompatTranslator` | OpenAI / compatible endpoints |
| `translator/redundant.py` | `RedundantTranslator`, `extract_with_consensus()`, `create_translator()` | Dual-model consensus, 6-layer security pipeline |
| `translator/_sanitise.py` | `sanitise_user_input()`, `injection_confidence_score()` | Unicode normalise, truncate, control-strip, injection-detect |
| `translator/_json.py` | `parse_llm_response()` | JSON extraction from LLM prose/markdown |
| `translator/_cache.py` | `IntentCache` | LRU + optional Redis intent result cache |
| `translator/_prompt.py` | `build_system_prompt()` | Extraction prompt template builder |
| **Audit** | | |
| `audit/signer.py` | `DecisionSigner`, `SignedDecision` | HMAC-SHA256 JWS token generation |
| `audit/verifier.py` | `DecisionVerifier`, `VerificationResult` | JWS token verification and payload extraction |
| `audit/merkle.py` | `MerkleAnchor`, `MerkleProof` | Append-only SHA-256 Merkle tree |
| **Identity** | | |
| `identity/linker.py` | `JWTIdentityLinker`, `IdentityClaims` | JWT-based per-agent policy binding |
| `identity/redis_loader.py` | `RedisStateLoader` | Redis-backed identity/state store |
| **Circuit Breaker** | | |
| `circuit_breaker.py` | `AdaptiveCircuitBreaker`, `CircuitBreakerConfig`, `CircuitState` | CLOSED/OPEN/HALF_OPEN/ISOLATED state machine |
| **Integrations** | | |
| `integrations/fastapi.py` | `PramanixMiddleware`, `pramanix_route()` | ASGI middleware + per-route decorator factory |
| `integrations/langchain.py` | `PramanixGuardedTool`, `wrap_tools()` | LangChain `BaseTool` subclass with Z3 gate |
| `integrations/llamaindex.py` | `PramanixFunctionTool`, `PramanixQueryEngineTool` | LlamaIndex tool wrappers with policy enforcement |
| `integrations/autogen.py` | `PramanixToolCallback` | AutoGen callable decorator (v0.2 + v0.4 compatible) |
| **Primitives** | | |
| `primitives/finance.py` | `NonNegativeBalance`, `UnderDailyLimit`, `UnderSingleTxLimit`, `RiskScoreBelow`, `SecureBalance`, `MinimumReserve` | Core financial constraints |
| `primitives/fintech.py` | `SufficientBalance`, `VelocityCheck`, `AntiStructuring`, `WashSaleDetection`, `CollateralHaircut`, `MaxDrawdown`, `SanctionsScreen`, `RiskScoreLimit`, `KYCTierCheck`, `TradingWindowCheck`, `MarginRequirement` | Advanced fintech / DeFi / trading constraints |
| `primitives/rbac.py` | `RoleMustBeIn`, `ConsentRequired`, `DepartmentMustBeIn` | Role-based access control |
| `primitives/infra.py` | `MinReplicas`, `MaxReplicas`, `WithinCPUBudget`, `WithinMemoryBudget`, `BlastRadiusCheck`, `CircuitBreakerState`, `ProdDeployApproval`, `ReplicaBudget`, `CPUMemoryGuard` | Kubernetes, Docker, cloud infrastructure |
| `primitives/healthcare.py` | `PHILeastPrivilege`, `ConsentActive`, `DosageGradientCheck`, `BreakGlassAuth`, `PediatricDoseBound` | PHI access, HIPAA, clinical safety |
| `primitives/time.py` | `WithinTimeWindow`, `After`, `Before`, `NotExpired` | Business hours, maintenance windows, cooldown periods |
| `primitives/common.py` | `NotSuspended`, `StatusMustBe`, `FieldMustEqual` | Cross-domain building blocks |
| **CLI** | | |
| `cli.py` | `main()` | `pramanix verify-proof` — cryptographic proof CLI |

---

## Advanced Features

### Primitives Library

Pre-built, composable constraint factories — pass your `Field` class attributes directly:

```python
from pramanix.primitives.finance import NonNegativeBalance, SecureBalance, UnderDailyLimit
from pramanix.primitives.fintech import AntiStructuring, VelocityCheck, KYCTierCheck
from pramanix.primitives.rbac import RoleMustBeIn, ConsentRequired
from pramanix.primitives.infra import MinReplicas, MaxReplicas, WithinCPUBudget
from pramanix.primitives.healthcare import PHILeastPrivilege, ConsentActive, BreakGlassAuth
from pramanix.primitives.time import WithinTimeWindow, NotExpired

class HighSecurityBankingPolicy(Policy):
    balance         = Field("balance",         Decimal, "Real")
    amount          = Field("amount",          Decimal, "Real")
    daily_limit     = Field("daily_limit",     Decimal, "Real")
    minimum_reserve = Field("minimum_reserve", Decimal, "Real")
    kyc_tier        = Field("kyc_tier",        int,     "Int")
    tx_count_24h    = Field("tx_count_24h",    int,     "Int")
    role            = Field("user_role",       str,     "Int")

    @classmethod
    def invariants(cls):
        return [
            SecureBalance(cls.balance, cls.amount, cls.minimum_reserve),
            UnderDailyLimit(cls.amount, cls.daily_limit),
            AntiStructuring(cls.amount, cls.tx_count_24h),   # AML structuring detection
            KYCTierCheck(cls.amount, cls.kyc_tier),           # KYC tier enforcement
            RoleMustBeIn(cls.role, ["teller", "manager"]),
        ]
```

### Semantic Fast-Path

Pre-screen obvious violations in O(1) pure Python before Z3. Architecture contract: **can only BLOCK, never ALLOW.**

```python
from pramanix.fast_path import SemanticFastPath

config = GuardConfig(
    fast_path_enabled=True,
    fast_path_rules=(
        SemanticFastPath.negative_amount("amount"),          # amount < 0
        SemanticFastPath.zero_or_negative_balance("balance"), # balance ≤ 0
        SemanticFastPath.account_frozen("is_frozen"),         # is_frozen == True
        SemanticFastPath.exceeds_hard_cap("amount", cap=1_000_000),  # absolute ceiling
        SemanticFastPath.amount_exceeds_balance("amount", "balance"), # obvious overdraft
    ),
)
# Fast-path runs AFTER Pydantic validation, BEFORE Z3
# A fast-path block saves the full Z3 solver round-trip (~5–30ms)
```

### Adaptive Load Shedding

Dual-condition shedder in `WorkerPool` returns `Decision.rate_limited()` when the system is under pressure:

```python
config = GuardConfig(
    shed_worker_pct=90,            # shed when ≥90% of workers are active (default)
    shed_latency_threshold_ms=200, # AND measured p99 latency > 200ms (default)
    max_workers=8,
)
# Both conditions must hold simultaneously — prevents false positives on transient spikes
```

Prometheus metric: `pramanix_decisions_total{status="rate_limited", policy="…"}`

### Adaptive Circuit Breaker

Wraps any `Guard` with a 4-state machine that protects against Z3 solver pressure cascades:

```python
from pramanix import AdaptiveCircuitBreaker, CircuitBreakerConfig

breaker = AdaptiveCircuitBreaker(
    guard=guard,
    config=CircuitBreakerConfig(
        pressure_threshold_ms=40.0,       # solver_time_ms > 40ms → "pressure" signal
        consecutive_pressure_count=5,     # 5 consecutive → OPEN
        recovery_seconds=30.0,            # wait 30s before HALF_OPEN probe
        isolation_threshold=3,            # 3 consecutive OPEN episodes → ISOLATED
        failsafe_mode="block_all",        # OPEN/ISOLATED always BLOCK
        namespace="banking",              # Prometheus label namespace
    )
)

# Transparent wrapper — same API as Guard
decision = await breaker.verify_async(intent=intent, state=state)

# State introspection
status = breaker.status  # CircuitBreakerStatus(state=CircuitState.CLOSED, …)

# Manual reset from ISOLATED (requires ops intervention)
breaker.reset()
```

**State transitions:**
```
CLOSED ──(5 slow solves)──► OPEN ──(30s)──► HALF_OPEN
                                               │  ├── probe success → CLOSED
                                               │  └── probe failure → OPEN
                            OPEN ──(×3)──► ISOLATED (manual reset required)
```

Prometheus: `pramanix_circuit_state{namespace="banking", state="closed|open|half_open|isolated"} 1`

### Cryptographic Audit Trail

Every `Decision` can be signed with HMAC-SHA256 JWS and anchored in a Merkle tree:

```python
from pramanix import DecisionSigner, DecisionVerifier, MerkleAnchor
import os

# At guard.verify() time — sign the decision
signer = DecisionSigner(signing_key=os.environ["PRAMANIX_SIGNING_KEY"])
signed = signer.sign(decision)
# signed.token  = "eyJhbGciOiJIUzI1NiIsInR5cCI6IlBSQU1BTklYLVBST09GIn0…"
# signed.decision_id = decision.decision_id
# signed.issued_at   = unix timestamp (ms)

if signed is None:
    # Key missing or too short (<32 chars) — signer silently returns None
    pass

# In audit / compliance tooling — verify proof token
verifier = DecisionVerifier(signing_key=os.environ["PRAMANIX_SIGNING_KEY"])
result = verifier.verify(signed.token)
assert result.valid
assert result.decision_id == decision.decision_id
assert result.allowed == decision.allowed
print(result.status, result.violated_invariants, result.explanation)

# Merkle tree for immutable decision sequencing
anchor = MerkleAnchor()
anchor.add(decision.decision_id)
anchor.add(decision2.decision_id)
proof = anchor.prove(decision.decision_id)
assert proof is not None
assert proof.verify()  # False after any tampering
```

**Generate a production signing key:**
```bash
python -c "import secrets; print(secrets.token_hex(64))"
```

Minimum key length: 32 characters. Recommended: 64+ hex chars (256-bit entropy).

### Zero-Trust Identity (JWT)

Per-agent JWT-based policy bindings backed by Redis:

```python
from pramanix import JWTIdentityLinker
from pramanix.identity.redis_loader import RedisStateLoader

# JWT claims define which policy this agent uses and what constraints apply
linker = JWTIdentityLinker(
    signing_key=os.environ["PRAMANIX_JWT_SECRET"],
    state_loader=RedisStateLoader(redis_url="redis://localhost:6379/0"),
)

claims = linker.verify_token(agent_jwt_token)
# IdentityClaims(agent_id="agent-abc", policy_name="BankingPolicy", …)
```

### Intent Cache

LRU + optional Redis cache for translated intent results (skip repeated LLM calls):

```python
from pramanix.translator._cache import IntentCache

# Auto-configures from PRAMANIX_REDIS_URL env var
cache = IntentCache.from_env(max_size=1024, ttl_seconds=300)

# Check stats
print(cache.stats())   # {"hits": 42, "misses": 8, "size": 50}
```

---

## Ecosystem Integrations

### FastAPI

```python
from fastapi import FastAPI, HTTPException
from pramanix.integrations.fastapi import PramanixMiddleware, pramanix_route

app = FastAPI()
guard = Guard(policy=BankingPolicy, config=GuardConfig())

# Option 1: ASGI middleware — intercepts every request before route handlers
app.add_middleware(
    PramanixMiddleware,
    guard=guard,
    state_loader=fetch_account_state,   # async callable: request → state dict
    timing_budget_ms=100,                # constant-time BLOCK to prevent timing oracles
    max_body_bytes=65_536,               # memory exhaustion protection
)

# Option 2: Per-route decorator
@app.post("/transfer")
@pramanix_route(guard=guard, state_loader=fetch_account_state)
async def transfer(intent: TransferIntent) -> dict[str, str]:
    await execute_transfer(intent)
    return {"status": "ok"}

@app.on_event("shutdown")
async def shutdown() -> None:
    await guard.shutdown()
```

Install: `pip install 'pramanix[fastapi]'`

### LangChain

```python
from pramanix.integrations.langchain import PramanixGuardedTool, wrap_tools

# Single guarded tool
tool = PramanixGuardedTool(
    name="transfer_funds",
    description="Transfer funds between accounts — guarded by Pramanix Z3 verification",
    guard=guard,
    intent_schema=TransferIntent,
    state_provider=lambda: get_account_state(),
)

# Wrap an existing list of BaseTool instances
guarded_tools = wrap_tools(
    tools=[existing_tool],
    guard=guard,
    intent_schema=TransferIntent,
    state_provider=state_provider,
)

# Use in any LangChain agent
from langchain.agents import initialize_agent, AgentType
agent = initialize_agent(tools=[tool], llm=llm, agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION)
```

Install: `pip install 'pramanix[langchain]'`

### LlamaIndex

```python
from pramanix.integrations.llamaindex import PramanixFunctionTool, PramanixQueryEngineTool

# Function tool — wraps any callable with policy enforcement
tool = PramanixFunctionTool(
    fn=execute_transfer,
    guard=guard,
    intent_schema=TransferIntent,
    state_provider=lambda: get_account_state(),
    name="transfer",
    description="Transfer funds — Z3 verified",
)

# Query engine tool — wraps an existing query engine
engine_tool = PramanixQueryEngineTool.from_function_tool(
    function_tool=tool,
    description="Verified financial query engine",
)

# tool.call(input) / await tool.acall(input)
output = await tool.acall({"amount": "5000", "currency": "USD"})
```

Install: `pip install 'pramanix[llamaindex]'`

### AutoGen

```python
from pramanix.integrations.autogen import PramanixToolCallback

# Works as a decorator for any async or sync tool function
callback = PramanixToolCallback(
    guard=guard,
    intent_schema=TransferIntent,
    state_provider=lambda: get_state(),
)

@assistant.register_for_execution()
@assistant.register_for_llm(description="Transfer funds")
@callback
async def transfer(amount: float, recipient: str) -> str:
    return f"Transferred {amount} to {recipient}"

# Class-method variant
guarded_fn = PramanixToolCallback.wrap(
    transfer,
    guard=guard,
    intent_schema=TransferIntent,
    state_provider=state_provider,
)
```

Policy violations return structured rejection strings (not exceptions) so the orchestrating LLM can adapt gracefully.

Install: `pip install 'pramanix[autogen]'`

---

## Pramanix vs. Alternatives

| | **Pramanix** | **OPA / Rego** | **LLM-as-Judge** | **Regex / Rules** | **LangChain Callbacks** |
|---|---|---|---|---|---|
| **Verification basis** | Z3 SMT (formal proof) | Datalog evaluation | Probabilistic | Pattern matching | LLM heuristic |
| **Guarantees** | Formal SAT / UNSAT | Policy evaluation result | None | Syntactic only | None |
| **Compound constraints** | Native (arith + bool + membership) | Limited arithmetic | Unreliable | Manual, brittle | None |
| **Counterexamples** | Exact Z3 model values | No | No | No | No |
| **Adversarial resistance** | Policy is compiled bytecode — LLM cannot reach it | Rego is interpretable | Vulnerable to jailbreak | Trivially bypassable | Vulnerable |
| **Audit trail** | HMAC-SHA256 JWS + Merkle tree | Evaluation log | Confidence score | Match log | Callback log |
| **LLM dependency** | Optional, firewalled, dual-model consensus | None | Required | None | Required |
| **Best for** | Mathematical safety of high-stakes actions | Authorization ("who can try") | Content filtering | Format validation | Observability hooks |

> **Recommended production architecture:** OPA handles authorization — "can this user/agent *attempt* this action?". Pramanix handles mathematical safety — "is this *specific instance* of the action safe given current state?". They are complementary.

---

## Configuration Reference

```python
from pramanix import GuardConfig

config = GuardConfig(
    # Execution backend
    execution_mode="async-thread",        # "sync" | "async-thread" | "async-process"

    # Z3 solver
    solver_timeout_ms=5_000,              # per-invariant timeout in ms (default: 5000)

    # Worker pool
    max_workers=4,                        # thread/process pool size (default: 4)
    max_decisions_per_worker=10_000,      # recycle threshold — bounds Z3 native memory
    worker_warmup=True,                   # dummy solve on spawn (eliminates JIT spike)

    # Semantic fast-path (default: disabled)
    fast_path_enabled=False,
    fast_path_rules=(),                   # tuple of SemanticFastPath rule callables

    # Adaptive load shedding (dual-condition)
    shed_worker_pct=90,                   # shed when ≥N% workers active (default: 90)
    shed_latency_threshold_ms=200,        # AND p99 > N ms (default: 200)

    # Observability (default: off)
    log_level="INFO",
    metrics_enabled=False,                # Prometheus counters/histograms
    otel_enabled=False,
    otel_endpoint=None,                   # e.g. "http://otel-collector:4317"

    # Translator (default: disabled)
    translator_enabled=False,
)
```

All fields can be set via `PRAMANIX_*` environment variables (read at construction time):

```bash
PRAMANIX_EXECUTION_MODE=async-thread
PRAMANIX_SOLVER_TIMEOUT_MS=5000
PRAMANIX_MAX_WORKERS=8
PRAMANIX_MAX_DECISIONS_PER_WORKER=10000
PRAMANIX_WORKER_WARMUP=true
PRAMANIX_FAST_PATH_ENABLED=false
PRAMANIX_SHED_WORKER_PCT=90
PRAMANIX_SHED_LATENCY_THRESHOLD_MS=200
PRAMANIX_LOG_LEVEL=INFO
PRAMANIX_METRICS_ENABLED=false
PRAMANIX_OTEL_ENABLED=false
PRAMANIX_OTEL_ENDPOINT=http://otel-collector:4317
PRAMANIX_TRANSLATOR_ENABLED=false
PRAMANIX_SIGNING_KEY=<hex-64-char-key>   # audit trail signing
```

**Environment variable precedence:** `PRAMANIX_*` env var overrides the coded default but is superseded by an explicit constructor argument.

---

## Security Model

### Threat Mitigations

| Threat | Mitigation |
|---|---|
| **Prompt injection** | Policy is compiled Python bytecode — inaccessible from user input. LLM is optional, isolated, and scanned by `_sanitise.py`. |
| **LLM hallucination** | LLM never invents IDs or decides safety. All LLM output must pass Pydantic strict validation + dual-model consensus. |
| **Unicode evasion** | NFKC normalisation collapses full-width digits, homoglyphs, and lookalike characters before any parsing. |
| **Sub-penny injection** | `injection_confidence_score()` flags anomalous micro-amounts (0 < amount < 0.10). Configurable threshold per currency/domain. |
| **Worker process compromise** | `_EphemeralKey` generates a random HMAC key per Guard. Worker results are sealed before IPC. Unsealing failure → `Decision.error()`. |
| **Numeric logic errors** | Z3 `RealSort` arithmetic is exact. Decimal values use `as_integer_ratio()` — no IEEE 754 approximation. |
| **TOCTOU / race conditions** | `state_version` binding. `Meta.version` mismatch returns `Decision.stale_state()`. Host must verify freshness before commit. |
| **Secret leakage in logs** | `_redact_secrets_processor` in structlog chain scrubs any event-dict key matching `secret|api_key|token|hmac|password|…` |
| **Memory exhaustion** | Input truncation (512 chars), body size cap (FastAPI middleware), worker recycling (Z3 native memory bounded). |
| **Opaque decisions** | Full unsat core with exact Z3 model counterexample in every BLOCK. Complete audit trail for regulators. |

### Fail-Safe Guarantee

```
decision(action, state) = ALLOW   ⟺   Z3.check(policy ∧ state) = SAT

decision(action, state) = BLOCK   in ALL other cases:
  UNSAT | TIMEOUT | UNKNOWN | EXCEPTION | TYPE_ERROR |
  NETWORK_FAILURE | CONFIG_ERROR | SERIALIZATION_ERROR |
  IPC_SEAL_FAILURE | PYDANTIC_VALIDATION_FAILURE |
  STALE_STATE | RATE_LIMITED | INJECTION_DETECTED
```

No action is approved by elimination. Every `ALLOW` requires **positive Z3 proof**. `Guard.verify()` and `Guard.verify_async()` **never raise** — every exception path returns `Decision.error()`.

---

## Performance

| Metric | Target | Conditions |
|---|---|---|
| **P50 latency** | < 5ms | Simple policy, 2–5 invariants, Real + Bool, async-thread |
| **P95 latency** | < 15ms | Including serialization and Pydantic validation |
| **P99 latency** | < 30ms | With worker warmup enabled |
| **Throughput** | > 100 RPS sustained | Per Guard instance, async-thread, simple policy |
| **Memory (1M decisions)** | RSS growth < 50MB | With worker recycling at 10K decisions/worker |
| **Fast-path latency** | < 0.1ms | Pure Python pre-screen, no Z3 |

**Solver timeout calibration:**

| Policy Complexity | Recommended `solver_timeout_ms` |
|---|---|
| Simple (2–5 invariants, Real + Bool only) | 50–200ms |
| Medium (5–15 invariants, mixed sorts) | 200–1000ms |
| Complex (15+ invariants, `is_in`, BitVec) | 1000–5000ms (default) |

**Prometheus metrics emitted by `telemetry.py`:**
```
pramanix_decisions_total{policy="…", status="safe|unsafe|timeout|error|…"}
pramanix_decision_latency_seconds{policy="…"}   (buckets: 1ms–2.5s)
pramanix_solver_timeouts_total{policy="…"}
pramanix_validation_failures_total{policy="…"}
pramanix_circuit_state{namespace="…", state="closed|open|half_open|isolated"}
```

---

## Deployment

### Docker

```dockerfile
# python:3.11-slim is REQUIRED — Alpine (musl) is NOT supported by z3-solver
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libz3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml poetry.lock ./
RUN pip install poetry && poetry install --only main --no-interaction

COPY src/ src/

# Non-root user
RUN useradd -m -u 1001 pramanix && chown -R pramanix:pramanix /app
USER pramanix

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
```

### Kubernetes

```yaml
env:
  - name: PRAMANIX_EXECUTION_MODE
    value: "async-thread"
  - name: PRAMANIX_MAX_WORKERS
    value: "8"
  - name: PRAMANIX_SOLVER_TIMEOUT_MS
    value: "5000"
  - name: PRAMANIX_METRICS_ENABLED
    value: "true"
  - name: PRAMANIX_OTEL_ENABLED
    value: "true"
  - name: PRAMANIX_OTEL_ENDPOINT
    value: "http://otel-collector:4317"
  - name: PRAMANIX_SIGNING_KEY
    valueFrom:
      secretKeyRef:
        name: pramanix-secrets
        key: signing-key
```

### FastAPI Complete Example

```python
from fastapi import FastAPI
from pramanix import Guard, GuardConfig, AdaptiveCircuitBreaker, CircuitBreakerConfig
from pramanix.integrations.fastapi import PramanixMiddleware

app = FastAPI()

guard = Guard(
    policy=BankingPolicy,
    config=GuardConfig(
        execution_mode="async-thread",
        solver_timeout_ms=200,
        max_workers=8,
        metrics_enabled=True,
        fast_path_enabled=True,
        fast_path_rules=(SemanticFastPath.negative_amount(),),
    ),
)

breaker = AdaptiveCircuitBreaker(
    guard=guard,
    config=CircuitBreakerConfig(namespace="banking"),
)

app.add_middleware(
    PramanixMiddleware,
    guard=breaker,           # wrap the circuit breaker, not the guard directly
    state_loader=fetch_state,
    timing_budget_ms=150,
    max_body_bytes=65_536,
)

@app.on_event("shutdown")
async def shutdown() -> None:
    await guard.shutdown()
```

---

## CLI

The `pramanix` CLI verifies cryptographic proof tokens from the audit trail:

```bash
# Verify a JWS proof token
PRAMANIX_SIGNING_KEY=<key> pramanix verify-proof eyJhbGciOiJIUzI1NiJ9...

# Output: VALID  decision_id=550e8400-...  issued_at=2026-03-15T12:00:00+00:00  status=safe

# Read token from stdin (pipe-friendly)
echo "eyJ..." | PRAMANIX_SIGNING_KEY=<key> pramanix verify-proof --stdin

# Machine-readable JSON output
PRAMANIX_SIGNING_KEY=<key> pramanix verify-proof eyJ... --json | jq .allowed

# Pass key inline (overrides env var)
pramanix verify-proof eyJ... --key <signing-key>
```

**Exit codes:** `0` = valid, `1` = invalid or verification error, `2` = usage error (missing token/key).

**Generate a production signing key:**
```bash
python -c "import secrets; print(secrets.token_hex(64))"
```

---

## Contributing

```bash
# Clone and install
git clone https://github.com/viraj1011JAIN/Pramanix.git
cd Pramanix
pip install -e ".[all]"           # install with all optional extras
pip install pytest pytest-asyncio pytest-cov hypothesis mypy ruff

# Run tests (skip API-key-dependent integration tests)
pytest tests/unit/ tests/adversarial/ tests/property/ tests/perf/ -q
pytest tests/integration/ -k "not (openai or anthropic or redis or zero_trust)" -q

# With coverage (must reach 95%)
pytest tests/unit/ tests/adversarial/ tests/property/ \
  --cov=src/pramanix --cov-report=term-missing --cov-fail-under=95

# Lint and type check (must be clean)
ruff check src/ tests/
mypy src/pramanix/ --strict
```

**Development rules:**
- Policy authoring errors must surface at `Guard.__init__()` time via `Policy.validate()` — never at first request
- Every error path must return `Decision(allowed=False)` — `verify()` / `verify_async()` never raise
- Use `assert_and_track` (not `solver.add`) for all invariants — unsat core attribution is mandatory
- Use `model_dump()` before crossing `ProcessPoolExecutor` — never pickle Pydantic models
- Use direct `isinstance()` checks in conditionals for mypy type narrowing — bool variable assignment doesn't narrow
- Alpine Docker images are banned — use `python:3.11-slim`

---

## License

Pramanix is licensed under **AGPL-3.0-only** for open-source use. A commercial license is available for proprietary deployments.

See [LICENSE](LICENSE) for details.

---

<p align="center">
  <strong>Pramanix</strong> — Because in high-stakes AI, <em>probabilistic safety is not safety. It is a liability.</em>
  <br /><br />
  Built by <a href="https://github.com/viraj1011JAIN">Viraj Jain</a>
</p>
