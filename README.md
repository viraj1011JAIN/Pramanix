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

**Pramanix** is a production-grade Python SDK that places a **mathematically verified execution firewall** between AI agent intent and real-world consequences. Every action it approves carries a formal SMT proof. Every action it blocks carries a counterexample with full attribution. No ambiguity. No exceptions.

```
AI Agent: "Transfer $5,000 to account X"
                    |
              [ PRAMANIX ]
                    |
        Z3 SMT Solver verifies ALL invariants:
          ✓  balance - amount >= 0      ... SAT
          ✓  account_not_frozen         ... SAT
          ✓  amount <= daily_limit      ... SAT
          ✓  risk_score <= 0.8          ... SAT
                    |
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
  - [Semantic Fast-Path](#semantic-fast-path)
  - [Adaptive Load Shedding](#adaptive-load-shedding)
  - [Adaptive Circuit Breaker](#adaptive-circuit-breaker)
  - [Cryptographic Audit Trail](#cryptographic-audit-trail)
  - [Zero-Trust Identity](#zero-trust-identity)
  - [Primitives Library](#primitives-library)
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

LLMs are **probabilistic token samplers**. They do not reason — they pattern-match. In regulated, high-stakes domains, this distinction is the difference between a deployable system and a liability.

| Domain | Risk Without Formal Verification |
|---|---|
| **FinTech** | Unauthorized transfers, balance overdraws, fraud bypass |
| **Healthcare** | Unauthorized PHI access, consent violations, dosage errors |
| **Cloud / Infra** | Destructive deletions, scaling beyond limits, IAM escalation |
| **Legal / Compliance** | Unauthorized attestations, regulatory filing errors |

Current guardrail approaches are fundamentally broken:

| Approach | Why It Fails |
|---|---|
| **Rule-based (regex/if-then)** | Cannot reason about compound constraints. Breaks on edge cases. Unmaintainable at scale. |
| **LLM-as-Judge** | Uses the same probabilistic tool to judge itself. Adversarial prompts override the judge. |
| **OPA / Rego alone** | Handles authorization ("who can try") but not mathematical safety ("is this specific transfer safe given current state?"). |

**Pramanix replaces probabilistic judgment with formal satisfiability.** The Z3 SMT solver provides mathematically unambiguous answers — not confidence scores.

---

## Key Features

| Feature | Description |
|---|---|
| **Z3 SMT Verification** | Every decision is backed by a formal proof (SAT) or counterexample (UNSAT). Not a confidence score — a mathematical guarantee. |
| **Python-Native Policy DSL** | Write policies as Python class methods with `E()` expression trees. Full IDE autocomplete, type checking, mypy strict compatible. |
| **Fail-Safe by Default** | Any error — LLM failure, timeout, type mismatch, config error — produces `BLOCK`, never `ALLOW`. Zero exceptions to this rule. |
| **Invariant Attribution** | Every blocked action identifies exactly which invariants were violated via Z3 unsat cores. Full counterexample model values attached. |
| **Dual Execution Modes** | **Structured Mode** for typed inputs. **Neuro-Symbolic Mode** for natural language with hardened dual-model LLM extraction. |
| **Async-First Architecture** | Three modes: `sync`, `async-thread`, `async-process`. Optimized for FastAPI, Django, Celery, and scripts. |
| **Worker Lifecycle Management** | Automatic worker recycling to bound Z3 native memory. Warmup solve eliminates cold-start JIT spikes. |
| **Semantic Fast-Path** | Pure Python O(1) pre-screen blocks obvious violations before Z3 is invoked. Configurable rules (negative amount, frozen account, etc.). |
| **Adaptive Load Shedding** | Dual-condition limiter (active workers % AND p99 latency) sheds excess load with `RATE_LIMITED` decisions before queue saturation. |
| **Adaptive Circuit Breaker** | CLOSED → OPEN → HALF_OPEN → CLOSED state machine protects against Z3 pressure cascades. |
| **Cryptographic Audit Trail** | Every `Decision` can be signed with HMAC-SHA256 JWS tokens. Merkle tree anchors immutable decision sequences. |
| **Zero-Trust Identity** | Per-agent policy bindings loaded from Redis. Identity-linked constraints applied at verification time. |
| **Ecosystem Integrations** | First-class FastAPI middleware, LangChain tool, LlamaIndex query engine, AutoGen agent wrappers. |
| **Composable Primitives** | Pre-built, tested constraint libraries for finance, fintech, RBAC, infrastructure, healthcare, and time-based policies. |
| **HMAC IPC Integrity** | Worker results are HMAC-sealed before crossing thread/process boundaries. Forgery attempts return `Decision.error()`. |
| **SLSA Level 3 Supply Chain** | OIDC-authenticated PyPI publishing, Sigstore artifact signing, automated SBOM generation. |

---

## How It Works

Pramanix operates on a **Two-Phase Execution Model**:

```
Phase 1: INTENT EXTRACTION                    Phase 2: FORMAL VERIFICATION
+---------------------------------+            +----------------------------------+
|                                 |            |                                  |
|  Structured     Neuro-Symbolic  |            |  Z3 SMT Solver                   |
|  (typed dict)   (NLP → struct)  |            |                                  |
|       |              |          |            |  For each invariant:             |
|       |         [Translator]    |   ------>  |    assert_and_track(formula)     |
|       |         [dual-model]    |            |    solver.check()                |
|       |              |          |            |                                  |
|       +------+-------+         |            |  SAT  → ALLOW (with proof)       |
|              |                  |            |  UNSAT → BLOCK (counterexample   |
|        [Pydantic v2]            |            |           + attributed labels)   |
|        strict validation        |            |                                  |
|              |                  |            |  LLM involvement: ZERO           |
|        [Fast-Path Screen]       |            +----------------------------------+
+---------------------------------+
```

**The critical architectural invariant:** the LLM *never* decides safety policy. It only translates natural language to structured fields. All safety verification is performed by Z3 — deterministically, with mathematical guarantees.

The fast-path screen (`fast_path.py`) runs pure Python checks before Z3 for common failure modes (negative amounts, frozen accounts). It can only BLOCK — never ALLOW.

---

## Installation

```bash
pip install pramanix
```

**Requirements:** Python 3.11+, z3-solver (installed automatically).

**Optional extras:**

```bash
# LLM translation (Neuro-Symbolic mode)
pip install 'pramanix[translator]'

# FastAPI/Starlette middleware + route decorator
pip install 'pramanix[fastapi]'

# LangChain tool integration
pip install 'pramanix[langchain]'

# LlamaIndex query engine integration
pip install 'pramanix[llamaindex]'

# AutoGen agent integration
pip install 'pramanix[autogen]'

# All ecosystem integrations
pip install 'pramanix[integrations]'

# Zero-trust identity (Redis-backed policy bindings)
pip install 'pramanix[identity]'

# OpenTelemetry tracing
pip install 'pramanix[otel]'

# Everything
pip install 'pramanix[all]'
```

> **Alpine Linux is NOT supported.** Z3's C++ runtime requires glibc. Use `python:3.11-slim` (Debian-based).

---

## Quick Start

### Structured Mode

The most common pattern — your application provides typed intent and state directly.

```python
from decimal import Decimal
from typing import Literal

from pydantic import BaseModel, Field as PydanticField
from pramanix import Guard, GuardConfig, Policy, Field, E, Decision


# 1. Define your intent and state models
class TransferIntent(BaseModel):
    action: Literal["transfer"]
    amount: Decimal = PydanticField(gt=0, le=1_000_000)
    currency: str = PydanticField(pattern=r"^[A-Z]{3}$")
    target_account_id: str

class AccountState(BaseModel):
    balance: Decimal
    is_frozen: bool
    daily_limit_remaining: Decimal
    risk_score: float = PydanticField(ge=0.0, le=1.0)
    state_version: str


# 2. Define your policy using the DSL
_balance    = Field("balance", Decimal, "Real")
_amount     = Field("amount", Decimal, "Real")
_frozen     = Field("is_frozen", bool, "Bool")
_daily_lim  = Field("daily_limit_remaining", Decimal, "Real")
_risk       = Field("risk_score", float, "Real")

class BankingPolicy(Policy):
    class Meta:
        name = "BankingPolicy"
        version = "1.0.0"

    @classmethod
    def fields(cls):
        return {
            "balance": _balance,
            "amount": _amount,
            "is_frozen": _frozen,
            "daily_limit_remaining": _daily_lim,
            "risk_score": _risk,
        }

    @classmethod
    def invariants(cls):
        return [
            (E(_balance) - E(_amount) >= 0)
                .named("non_negative_balance")
                .explain("Transfer blocked: amount {amount} exceeds balance {balance}."),

            (E(_frozen) == False)
                .named("account_not_frozen")
                .explain("Transfer blocked: account is currently frozen."),

            (E(_amount) <= E(_daily_lim))
                .named("within_daily_limit")
                .explain("Transfer blocked: {amount} exceeds daily limit {daily_limit_remaining}."),

            (E(_risk) <= 0.8)
                .named("acceptable_risk_score")
                .explain("Transfer blocked: risk score {risk_score} exceeds threshold 0.8."),
        ]


# 3. Create a Guard and verify
guard = Guard(policy=BankingPolicy, config=GuardConfig(
    execution_mode="async-thread",
    solver_timeout_ms=50,
))

async def handle_transfer():
    intent = TransferIntent(
        action="transfer",
        amount=Decimal("5000"),
        currency="USD",
        target_account_id="acc_abc123",
    )
    state = AccountState(
        balance=Decimal("10000"),
        is_frozen=False,
        daily_limit_remaining=Decimal("15000"),
        risk_score=0.3,
        state_version="2026-03-07T12:00:00Z",
    )

    decision: Decision = await guard.verify(intent=intent, state=state)

    if decision.allowed:
        # decision.status == SolverStatus.SAFE
        print("Transfer approved", decision.decision_id)
    else:
        print("Blocked:", decision.explanation)
        print("Violated:", decision.violated_invariants)
        print("Solver time:", decision.solver_time_ms, "ms")
```

### Neuro-Symbolic Mode

When your input is natural language, Pramanix uses a hardened dual-model LLM translator to extract structured intent before Z3 verification.

```python
from pramanix import Guard, GuardConfig
from pramanix.translator.redundant import RedundantTranslator
from pramanix.translator.anthropic import AnthropicTranslator
from pramanix.translator.ollama import OllamaTranslator

# Dual-model consensus: both models must agree on critical fields
translator = RedundantTranslator(
    model_a=AnthropicTranslator(model="claude-haiku-4-5-20251001"),
    model_b=OllamaTranslator(model="llama3"),
    agreement_mode="lenient",      # critical fields must agree
    critical_fields=["amount", "target_account_id"],
)

guard = Guard(
    policy=BankingPolicy,
    config=GuardConfig(translator_enabled=True),
    translator=translator,
)

decision = await guard.parse_and_verify(
    text="Transfer five thousand dollars to Alice's savings account",
    state=account_state,
)

# The LLM extracts structured fields → Pydantic validates → Z3 verifies
# LLM NEVER decides policy. LLM output is injection-screened before use.
```

**Translator hardening** (`translator/_sanitise.py`):
- Unicode NFKC normalization (collapses homoglyphs/full-width digits)
- Input truncation (512 chars max by default)
- Control character stripping
- Injection pattern detection (GPT/Claude/Llama jailbreak patterns)
- Confidence scoring with sub-penny amount anomaly detection

### Decorator API

Gate function execution directly — the function body only runs if Z3 approves.

```python
from pramanix.decorator import guarded

@guarded(policy=BankingPolicy, state_from="state")
async def execute_transfer(intent: TransferIntent, state: AccountState):
    # This body ONLY runs if all invariants pass.
    # Otherwise, GuardViolationError is raised with the full Decision attached.
    await actually_execute_transfer(intent)
```

---

## Core Concepts

### Policy DSL

Policies are **pure Python classmethods** — no YAML, no Rego, no string-based DSL. Full IDE autocomplete and mypy strict compatible.

```python
from pramanix import Policy, Field, E
from decimal import Decimal

# Declare fields as module-level constants
balance = Field("balance", Decimal, "Real")
amount  = Field("amount",  Decimal, "Real")
frozen  = Field("is_frozen", bool, "Bool")
role    = Field("role", str, "Int")   # String enums projected to Int via is_in()

class MyPolicy(Policy):
    class Meta:
        name = "MyPolicy"
        version = "1.0.0"

    @classmethod
    def fields(cls):
        return {"balance": balance, "amount": amount, "is_frozen": frozen, "role": role}

    @classmethod
    def invariants(cls):
        return [
            (E(balance) - E(amount) >= 0)
                .named("non_negative_balance")
                .explain("Insufficient balance: {amount} > {balance}"),

            (E(frozen) == False)
                .named("not_frozen")
                .explain("Account is frozen."),

            E(role).is_in(["admin", "manager"])
                .named("authorized_role")
                .explain("Role {role} is not authorized."),
        ]
```

**Expression operators** (all compile to Z3 AST — zero `eval()`/`exec()`):

| Operation | Syntax | Compiles To |
|---|---|---|
| Arithmetic | `E(a) + E(b)`, `- E(b)`, `* E(b)`, `/ E(b)` | Z3 `ArithRef` ops |
| Comparison | `>=`, `<=`, `>`, `<`, `==`, `!=` | Z3 `BoolRef` constraints |
| Boolean AND | `expr_a & expr_b` | `z3.And(a, b)` |
| Boolean OR | `expr_a \| expr_b` | `z3.Or(a, b)` |
| Boolean NOT | `~expr` (on `ConstraintExpr`) | `z3.Not(a)` |
| Membership | `E(role).is_in(["admin", "doctor"])` | `z3.Or(x == v1, x == v2, ...)` |
| Naming | `.named("invariant_name")` | Z3 `assert_and_track` label |
| Explanation | `.explain("template {field}")` | Human-readable violation message |

> **Important:** Use `&` / `|` operators, NOT Python `and` / `or`. Python keywords evaluate immediately and bypass the expression tree.

### The Decision Object

Every `verify()` call returns an immutable `Decision` frozen dataclass (`decision.py`):

```python
@dataclass(frozen=True)
class Decision:
    allowed: bool              # True IFF status == SAFE
    status: SolverStatus       # SAFE | UNSAFE | TIMEOUT | ERROR | STALE_STATE | ...
    violated_invariants: tuple[str, ...]
    explanation: str
    metadata: dict[str, Any]
    solver_time_ms: float
    decision_id: str           # UUID4 — unique per verification call
```

**Status codes:**

| Status | Meaning | `allowed` |
|---|---|---|
| `SAFE` | All invariants satisfied — Z3 returned SAT | `true` |
| `UNSAFE` | One or more invariants violated — Z3 returned UNSAT | `false` |
| `TIMEOUT` | Z3 exceeded `solver_timeout_ms` | `false` |
| `ERROR` | Unexpected internal error (fail-safe always blocks) | `false` |
| `STALE_STATE` | `state_version` mismatch | `false` |
| `VALIDATION_FAILURE` | Pydantic validation of intent or state failed | `false` |
| `RATE_LIMITED` | Request shed by adaptive load limiter | `false` |

Decisions serialize cleanly:

```python
d = decision.to_dict()
# {
#   "decision_id": "550e8400-...",
#   "allowed": false,
#   "status": "unsafe",
#   "violated_invariants": ["non_negative_balance"],
#   "explanation": "Transfer blocked: amount 5000 exceeds balance 100.",
#   "solver_time_ms": 7.3,
#   "metadata": {}
# }
```

### Execution Modes

Choose based on your server architecture:

```
Is your server async (FastAPI, Starlette)?
|
+-- YES --> Heavy policies (>50 constraints)?
|           +-- YES --> execution_mode = "async-process"   (GIL-free, separate Z3 context)
|           +-- NO  --> execution_mode = "async-thread"    (DEFAULT, shared memory)
|
+-- NO  --> execution_mode = "sync"   (Django, Flask, Celery, scripts)
```

**Worker lifecycle:** Workers auto-recycle after `max_decisions_per_worker` (default 10,000) to prevent Z3 native memory accumulation. `worker_warmup=True` (default) runs a dummy Z3 solve on spawn to eliminate the JIT cold-start latency spike.

---

## Domain Examples

### Banking — Transfer Verification

```python
decision = await guard.verify(
    intent=TransferIntent(action="transfer", amount=Decimal("5000"), currency="USD", target_account_id="acc_x"),
    state=AccountState(balance=Decimal("100"), is_frozen=False, daily_limit_remaining=Decimal("10000"), risk_score=0.3, state_version="v1"),
)

assert decision.allowed is False
assert decision.status.value == "unsafe"
assert "non_negative_balance" in decision.violated_invariants
# decision.explanation: "Transfer blocked: amount 5000 exceeds balance 100."
```

### Healthcare — PHI Access Control

```python
_role    = Field("user_role", str, "Int")
_consent = Field("patient_consent", bool, "Bool")
_dept    = Field("department_match", bool, "Bool")

class PHIAccessPolicy(Policy):
    class Meta:
        name = "PHIAccessPolicy"
        version = "1.0.0"

    @classmethod
    def fields(cls):
        return {"user_role": _role, "patient_consent": _consent, "department_match": _dept}

    @classmethod
    def invariants(cls):
        return [
            E(_role).is_in(["doctor", "nurse", "admin"])
                .named("authorized_role")
                .explain("PHI access blocked: role {user_role} is not authorized."),

            (E(_consent) == True)
                .named("patient_consent_required")
                .explain("PHI access blocked: patient has not provided consent."),

            (E(_dept) == True)
                .named("department_match_required")
                .explain("PHI access blocked: requester is not in patient department."),
        ]
```

See `src/pramanix/primitives/healthcare.py` for pre-built PHI, HIPAA, and clinical primitives.

### Cloud Infrastructure — Replica Scaling

```python
_target  = Field("target_replicas", int, "Int")
_min     = Field("minimum_replicas", int, "Int")
_max     = Field("maximum_replicas", int, "Int")
_is_prod = Field("is_production", bool, "Bool")

class ScalingPolicy(Policy):
    class Meta:
        name = "ScalingPolicy"
        version = "1.0.0"

    @classmethod
    def fields(cls):
        return {"target_replicas": _target, "minimum_replicas": _min, "maximum_replicas": _max, "is_production": _is_prod}

    @classmethod
    def invariants(cls):
        return [
            (E(_target) >= E(_min))
                .named("above_minimum")
                .explain("Scale blocked: {target_replicas} < minimum {minimum_replicas}."),

            (E(_target) <= E(_max))
                .named("below_maximum")
                .explain("Scale blocked: {target_replicas} > maximum {maximum_replicas}."),

            (~E(_is_prod) | (E(_target) >= 2))
                .named("production_ha_minimum")
                .explain("Scale blocked: production requires >= 2 replicas."),
        ]
```

See `src/pramanix/primitives/infra.py` for pre-built Kubernetes, Docker, IAM, and cloud scaling primitives.

---

## Architecture

```
                              +==============+
                              ||   CALLER   ||
                              || (FastAPI / ||
                              ||  LangChain ||
                              ||  AutoGen)  ||
                              +======+======+
                                     |  guard.verify(intent, state)
                                     v
                   +--------------------------------------------+
                   |                GUARD  (guard.py)           |
                   |  +-----------+   +-----------+             |
                   |  | Translator|   | Validator |             |
                   |  | (optional)|   | Pydantic  |             |
                   |  +-----+-----+   +-----+-----+             |
                   |        |               |                   |
                   |        +-------+-------+                   |
                   |                |                           |
                   |  +-------------v-----------+               |
                   |  |   Semantic Fast-Path     |               |
                   |  |   (fast_path.py)         |               |
                   |  |   O(1) pre-screen        |               |
                   |  +-------------+-----------+               |
                   |                |                           |
                   |  +-------------v-----------+               |
                   |  |  Adaptive Load Shedder   |               |
                   |  |  (worker.py)             |               |
                   |  +-------------+-----------+               |
                   |                |                           |
                   |  +-------------v-----------+               |
                   |  |  Resolver Registry       |               |
                   |  |  (resolvers.py)          |               |
                   |  |  runs on asyncio loop    |               |
                   |  +-------------+-----------+               |
                   |                |                           |
                   |  [Thread/Process Boundary — HMAC-sealed]   |
                   |                |                           |
                   |  +-------------v-----------+               |
                   |  |     Worker              |               |
                   |  |  +-----------------+   |               |
                   |  |  |   TRANSPILER    |   |               |
                   |  |  |   (transpiler.py)|  |               |
                   |  |  |   DSL → Z3 AST  |   |               |
                   |  |  +--------+--------+   |               |
                   |  |           |             |               |
                   |  |  +--------v--------+   |               |
                   |  |  |   Z3 SOLVER     |   |               |
                   |  |  |   (solver.py)   |   |               |
                   |  |  |  assert_and_    |   |               |
                   |  |  |  track / unsat  |   |               |
                   |  |  |  core / timeout |   |               |
                   |  |  +--------+--------+   |               |
                   |  +----------+-----------+  |               |
                   |             |               |               |
                   |  [HMAC verify on return]   |               |
                   |             |               |               |
                   |  +----------v-----------+   |               |
                   |  |   Decision Builder    |   |               |
                   |  |   (decision.py)       |   |               |
                   |  |   immutable frozenDC  |   |               |
                   |  +----------+-----------+   |               |
                   |             |               |               |
                   |  +----------v-----------+   |               |
                   |  |    Telemetry          |   |               |
                   |  |    (telemetry.py)     |   |               |
                   |  |    Prometheus + OTel  |   |               |
                   |  +----------+-----------+   |               |
                   +--------------------------------------------+
                                 |
                          Decision (returned)
                                 |
                   +-------------v-----------+
                   |  Audit Signer           |
                   |  (audit/signer.py)      |
                   |  HMAC-SHA256 JWS token  |
                   +-------------------------+
```

### Module Reference

| Module | Responsibility |
|---|---|
| `guard.py` | SDK entrypoint — policy compilation, worker pool, `verify()`, `parse_and_verify()` |
| `policy.py` | `Policy` base class — `fields()` / `invariants()` classmethods, `Meta` config, `validate()` |
| `expressions.py` | `E()` function, `Field`, `ExpressionNode`, `ConstraintExpr` — lazy expression tree via operator overloading |
| `transpiler.py` | DSL expression tree → Z3 AST. `compile_policy()` for pre-compilation metadata. Zero `ast.parse`/`eval`/`exec`. |
| `solver.py` | Z3 wrapper — context isolation, `assert_and_track`, unsat core attribution, configurable timeouts |
| `worker.py` | Worker spawn/warmup/recycle lifecycle, `AdaptiveConcurrencyLimiter`, HMAC IPC sealing |
| `decision.py` | Immutable `Decision` frozen dataclass, `SolverStatus` enum, factory class-methods |
| `validator.py` | Pydantic v2 strict schema validation layer |
| `resolvers.py` | Lazy field resolution with per-decision `ContextVar` cache isolation |
| `fast_path.py` | Semantic fast-path evaluator — pure Python O(1) pre-screen before Z3 |
| `telemetry.py` | Prometheus counters/histograms, OpenTelemetry span hooks, structured JSON logs |
| `decorator.py` | `@guarded` decorator — raises `GuardViolationError` with attached `Decision` on block |
| `exceptions.py` | All Pramanix exception types (`PolicyCompilationError`, `ExtractionFailureError`, etc.) |
| `helpers/` | Serialization utilities (`serialization.py`), Z3 type mappings (`type_mapping.py`) |
| **Translator** | | |
| `translator/base.py` | `BaseTranslator` ABC — `translate(text, schema)` interface |
| `translator/anthropic.py` | Anthropic Claude translator (streaming + block-level extraction) |
| `translator/ollama.py` | Ollama local-model translator (OpenAI-compatible JSON mode) |
| `translator/openai_compat.py` | OpenAI / OpenAI-compatible endpoint translator |
| `translator/redundant.py` | Dual-model consensus translator (`strict_keys`, `lenient`, `unanimous` agreement modes) |
| `translator/_sanitise.py` | Pre-LLM input sanitisation + injection confidence scoring |
| `translator/_json.py` | Robust JSON extraction (handles markdown fences, prose, nesting) |
| `translator/_cache.py` | LRU + optional Redis intent cache |
| `translator/_prompt.py` | Extraction prompt templates |
| **Audit** | | |
| `audit/signer.py` | `DecisionSigner` — HMAC-SHA256 JWS token generation |
| `audit/verifier.py` | `DecisionVerifier` — token verification and payload extraction |
| `audit/merkle.py` | `MerkleAnchor` — append-only Merkle tree for immutable decision sequences |
| **Identity** | | |
| `identity/linker.py` | `IdentityLinker` — per-agent policy binding resolution |
| `identity/redis_loader.py` | `RedisIdentityLoader` — Redis-backed identity store |
| **Circuit Breaker** | | |
| `circuit_breaker.py` | `AdaptiveCircuitBreaker` — CLOSED/OPEN/HALF_OPEN/ISOLATED state machine |
| **Integrations** | | |
| `integrations/fastapi.py` | `PramanixMiddleware` (ASGI) + `@pramanix_route` decorator factory |
| `integrations/langchain.py` | `PramanixGuardTool` — LangChain `BaseTool` with policy enforcement |
| `integrations/llamaindex.py` | `PramanixGuardEngine` — LlamaIndex `BaseQueryEngine` wrapper |
| `integrations/autogen.py` | `PramanixGuardAgent` — AutoGen `ConversableAgent` with action interception |
| **Primitives** | | |
| `primitives/finance.py` | Overdraft, daily limit, compliance (AML/KYC), multi-currency constraints |
| `primitives/fintech.py` | Cryptocurrency, DeFi, payment rails, liquidity constraints |
| `primitives/rbac.py` | Role-based access control, separation of duties, permission escalation |
| `primitives/infra.py` | Kubernetes scaling, Docker resource limits, IAM policies, cloud quotas |
| `primitives/healthcare.py` | PHI access, HIPAA, consent verification, clinical safety constraints |
| `primitives/time.py` | Business hours, maintenance windows, cooldown periods, rate windows |
| `primitives/common.py` | Shared building blocks used across domain primitives |
| **CLI** | | |
| `cli.py` | `pramanix verify-proof <token>` — CLI for cryptographic proof verification |

---

## Advanced Features

### Semantic Fast-Path

Pre-screen obvious violations in pure Python before Z3 is invoked. Runs < 0.1ms. Can only BLOCK — never ALLOW.

```python
from pramanix import Guard, GuardConfig
from pramanix.fast_path import SemanticFastPath

guard = Guard(
    policy=BankingPolicy,
    config=GuardConfig(
        fast_path_enabled=True,
        fast_path_rules=(
            SemanticFastPath.negative_amount("amount"),
            SemanticFastPath.zero_or_negative_balance("balance"),
            SemanticFastPath.frozen_account("is_frozen"),
        )
    )
)
```

### Adaptive Load Shedding

Dual-condition load shedder in `worker.py` prevents queue saturation:

```python
config = GuardConfig(
    shed_worker_pct=0.9,         # shed when ≥90% of workers are active
    shed_latency_threshold_ms=45, # AND p99 latency > 45ms
)
# Returns Decision.rate_limited() instead of queuing when both conditions hold.
```

### Adaptive Circuit Breaker

Wraps a `Guard` with CLOSED → OPEN → HALF_OPEN → CLOSED state machine:

```python
from pramanix.circuit_breaker import AdaptiveCircuitBreaker, CircuitBreakerConfig

breaker = AdaptiveCircuitBreaker(
    guard=guard,
    config=CircuitBreakerConfig(
        pressure_threshold_ms=40.0,
        failure_threshold=5,
        recovery_seconds=30.0,
        namespace="banking",
    )
)

# Use exactly like a Guard — transparent wrapper
decision = await breaker.verify_async(intent=intent, state=state)

# Prometheus: pramanix_circuit_state{namespace="banking", state="closed"} 1
```

After 3 consecutive OPEN episodes, transitions to `ISOLATED` state requiring manual `breaker.reset()`.

### Cryptographic Audit Trail

Every `Decision` can be signed with a HMAC-SHA256 JWS token. Merkle tree provides tamper-evident sequencing.

```python
from pramanix.audit.signer import DecisionSigner
from pramanix.audit.verifier import DecisionVerifier
from pramanix.audit.merkle import MerkleAnchor

# Signing (at guard.verify() time)
signer = DecisionSigner(signing_key=os.environ["PRAMANIX_SIGNING_KEY"])
signed = signer.sign(decision)
# signed.token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IlBSQU1BTklYLVBST09GIn0..."

# Verification (audit / compliance tooling)
verifier = DecisionVerifier(signing_key=os.environ["PRAMANIX_SIGNING_KEY"])
result = verifier.verify(signed.token)
assert result.valid
assert result.decision_id == decision.decision_id

# Merkle anchoring for immutable audit sequences
anchor = MerkleAnchor()
anchor.add(decision.decision_id)
proof = anchor.prove(decision.decision_id)
assert proof.verify()
```

Generate a production signing key:
```bash
python -c "import secrets; print(secrets.token_hex(64))"
```

### Zero-Trust Identity

Redis-backed per-agent policy bindings:

```python
from pramanix.identity.linker import IdentityLinker
from pramanix.identity.redis_loader import RedisIdentityLoader

loader = RedisIdentityLoader(redis_url="redis://localhost:6379/0")
linker = IdentityLinker(loader=loader)

# Resolve which policy applies to this agent
policy_cls = await linker.resolve(agent_id="agent-abc123")
guard = Guard(policy=policy_cls, config=GuardConfig())
```

### Primitives Library

Pre-built, composable constraint factories:

```python
from pramanix.primitives.finance import (
    overdraft_protection,
    daily_transfer_limit,
    aml_amount_threshold,
)
from pramanix.primitives.rbac import (
    role_in,
    requires_mfa,
    separation_of_duties,
)
from pramanix.primitives.time import (
    within_business_hours,
    not_in_maintenance_window,
)
```

---

## Ecosystem Integrations

### FastAPI

```python
from fastapi import FastAPI
from pramanix.integrations.fastapi import PramanixMiddleware, pramanix_route

app = FastAPI()

# Option 1: ASGI middleware — intercepts every request
app.add_middleware(
    PramanixMiddleware,
    guard=guard,
    state_loader=fetch_account_state,
    timing_budget_ms=100,       # constant-time BLOCK responses
    max_body_bytes=65536,        # memory exhaustion protection
)

# Option 2: Per-route decorator
@app.post("/transfer")
@pramanix_route(policy=BankingPolicy, state_from=fetch_account_state)
async def transfer(intent: TransferIntent):
    await execute_transfer(intent)  # only called if Z3 approves
```

Install: `pip install 'pramanix[fastapi]'`

### LangChain

```python
from pramanix.integrations.langchain import PramanixGuardTool

tool = PramanixGuardTool(
    guard=guard,
    name="transfer_guard",
    description="Verify financial transfer safety before execution",
)

# Use in any LangChain agent — tool.run() returns Decision JSON
agent = initialize_agent(tools=[tool], llm=llm, agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION)
```

Install: `pip install 'pramanix[langchain]'`

### LlamaIndex

```python
from pramanix.integrations.llamaindex import PramanixGuardEngine

engine = PramanixGuardEngine(
    guard=guard,
    base_engine=your_query_engine,
)

# All queries pass through Pramanix verification before reaching base_engine
response = await engine.aquery("Transfer $5000 to Alice")
```

Install: `pip install 'pramanix[llamaindex]'`

### AutoGen

```python
from pramanix.integrations.autogen import PramanixGuardAgent

agent = PramanixGuardAgent(
    name="FinanceAgent",
    guard=guard,
    system_message="You are a financial operations agent.",
)

# All agent actions are intercepted and verified by Pramanix before execution
```

Install: `pip install 'pramanix[autogen]'`

---

## Pramanix vs. Alternatives

| | **Pramanix** | **OPA / Rego** | **LLM-as-Judge** | **Regex / Rules** | **LangChain Callbacks** |
|---|---|---|---|---|---|
| **Verification basis** | Z3 SMT (mathematical proof) | Datalog evaluation | Probabilistic sampling | Pattern matching | LLM heuristic |
| **Guarantees** | Formal: SAT / UNSAT | Policy evaluation | None | Syntactic only | None |
| **Compound constraints** | Native (arithmetic, boolean, membership) | Limited arithmetic | Unreliable | Manual, brittle | None |
| **Counterexamples** | Exact model values from Z3 | No | No | No | No |
| **Adversarial resistance** | DSL compiled to bytecode — injection unreachable | Rego is interpretable | Vulnerable to jailbreak | Trivially bypassable | Vulnerable |
| **Audit trail** | Cryptographic JWS + Merkle tree | Evaluation log | Confidence score | Match/no-match | Callback log |
| **LLM dependency** | Optional, firewalled, dual-model consensus | None | Required | None | Required |
| **Python integration** | Native SDK | HTTP/gRPC sidecar | Library | Library | Library |
| **Best for** | Mathematical safety of high-stakes actions | Authorization (who can try) | Content filtering | Simple format checks | Observability hooks |

> **Recommended production architecture:** OPA handles authorization ("can this user attempt a transfer?"). Pramanix handles mathematical safety ("is this specific transfer safe given current state?"). They are complementary, not competing.

---

## Configuration Reference

```python
from pramanix import GuardConfig

config = GuardConfig(
    # Execution
    execution_mode="async-thread",        # "sync" | "async-thread" | "async-process"
    solver_timeout_ms=50,                 # 10–10,000ms (default: 50)
    max_workers=4,                        # 1–64 (default: 4)

    # Worker Lifecycle
    max_decisions_per_worker=10_000,      # Recycle to flush Z3 native memory (default: 10,000)
    worker_warmup=True,                   # Dummy solve on spawn (eliminates cold-start JIT spike)

    # Semantic Fast-Path (Phase 10)
    fast_path_enabled=False,              # Enable pure-Python pre-screen (default: False)
    fast_path_rules=(),                   # SemanticFastPath rules to apply

    # Adaptive Load Shedding
    shed_worker_pct=0.9,                  # Shed when ≥90% workers active (default: 0.9)
    shed_latency_threshold_ms=45.0,       # AND p99 > 45ms (default: 45.0)

    # Observability
    log_level="INFO",
    metrics_enabled=True,                 # Prometheus counters/histograms
    otel_enabled=False,
    otel_endpoint=None,                   # e.g. "http://otel-collector:4317"

    # Translator (disabled by default)
    translator_enabled=False,
)
```

**Environment variables:**

```bash
PRAMANIX_EXECUTION_MODE=async-thread
PRAMANIX_SOLVER_TIMEOUT_MS=50
PRAMANIX_MAX_WORKERS=8
PRAMANIX_MAX_DECISIONS_PER_WORKER=10000
PRAMANIX_WORKER_WARMUP=true
PRAMANIX_LOG_LEVEL=INFO
PRAMANIX_METRICS_ENABLED=true
PRAMANIX_OTEL_ENABLED=false
PRAMANIX_OTEL_ENDPOINT=http://otel-collector:4317
PRAMANIX_TRANSLATOR_ENABLED=false
PRAMANIX_SIGNING_KEY=<hex-64-char-key>   # Audit trail signing key
```

---

## Security Model

### Threat Mitigations

| Threat | Mitigation |
|---|---|
| **Prompt injection** | Policy is compiled Python bytecode — injection cannot reach it. The LLM is optional and isolated by `_sanitise.py` injection scanner. |
| **LLM hallucination** | LLM never invents IDs or decides policy. All LLM output passes strict Pydantic validation. Dual-model consensus required. |
| **Numeric logic errors** | Z3 `RealSort` arithmetic is exact. Decimal values use `as_integer_ratio()` — no IEEE 754 approximation. |
| **Race conditions (TOCTOU)** | `state_version` binding detected by `STALE_STATE`. Host must verify freshness before committing approved actions. |
| **Worker process compromise** | Worker results are HMAC-SHA256 sealed before crossing the IPC boundary. Tampered results return `Decision.error()`. |
| **Opaque decisions** | Full unsat core with exact Z3 model values in every BLOCK decision. Complete audit trail for regulators. |
| **Sub-penny injection** | `_sanitise.injection_confidence_score()` flags anomalous micro-amounts. Configurable threshold per currency. |
| **Unicode evasion** | NFKC normalization collapses full-width digits and homoglyphs before any parsing. |
| **Resource exhaustion** | Input truncation (512 chars default), body size cap (FastAPI middleware), adaptive load shedding. |

### Fail-Safe Guarantee

```
decision(action, state) = ALLOW   IFF   Z3.check(policy ∧ state) = SAT
decision(action, state) = BLOCK   in ALL other cases

"All other cases" includes:
  UNSAT | TIMEOUT | UNKNOWN | EXCEPTION | TYPE_ERROR |
  NETWORK_FAILURE | CONFIG_ERROR | SERIALIZATION_ERROR |
  IPC_SEAL_FAILURE | PYDANTIC_VALIDATION_ERROR
```

No action is approved by elimination. Every approval requires **positive proof**.

---

## Performance

| Metric | Target | Notes |
|---|---|---|
| **P50 latency** | < 5ms | Simple policies (2–5 invariants, Real + Bool) |
| **P95 latency** | < 15ms | Includes serialization overhead |
| **P99 latency** | < 30ms | With worker warmup enabled |
| **Throughput** | > 100 RPS sustained | Per Guard instance, async-thread mode |
| **Memory (1M decisions)** | RSS growth < 50MB | With worker recycling at 10K decisions |
| **Fast-path latency** | < 0.1ms | Pure Python pre-screen, no Z3 invocation |

**Solver timeout calibration:**

| Policy Complexity | Recommended Timeout |
|---|---|
| Simple (2–5 invariants, Real + Bool) | 10–20ms |
| Medium (5–15 invariants, mixed types) | 20–50ms (default) |
| Complex (15+ invariants, BitVec, `is_in` membership) | 100–500ms |

**Observability (Prometheus metrics emitted by `telemetry.py`):**

```
pramanix_decisions_total{status="safe|unsafe|timeout|error|...", policy="..."}
pramanix_decision_latency_seconds{policy="...", execution_mode="..."}
pramanix_solver_timeouts_total{policy="..."}
pramanix_circuit_state{namespace="...", state="closed|open|half_open|isolated"}
```

---

## Deployment

### Docker

```dockerfile
# python:3.11-slim is required — Alpine is NOT supported (Z3 requires glibc)
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libz3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml poetry.lock ./
RUN pip install poetry && poetry install --only main --no-interaction --no-ansi

COPY src/ src/

# Non-root user for security
RUN useradd -m -u 1001 pramanix && chown -R pramanix:pramanix /app
USER pramanix

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
    value: "50"
  - name: PRAMANIX_SIGNING_KEY
    valueFrom:
      secretKeyRef:
        name: pramanix-secrets
        key: signing-key
  - name: PRAMANIX_OTEL_ENDPOINT
    value: "http://otel-collector:4317"
```

### FastAPI Complete Example

```python
from fastapi import FastAPI
from pramanix import Guard, GuardConfig
from pramanix.integrations.fastapi import PramanixMiddleware

app = FastAPI()
guard = Guard(policy=BankingPolicy, config=GuardConfig(
    execution_mode="async-thread",
    solver_timeout_ms=50,
    metrics_enabled=True,
))

app.add_middleware(
    PramanixMiddleware,
    guard=guard,
    state_loader=fetch_account_state,
    timing_budget_ms=100,
)

@app.on_event("shutdown")
async def shutdown():
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
pramanix verify-proof eyJ... --json | jq .decision_id

# Exit codes: 0=valid, 1=invalid/error, 2=usage error
```

Generate a production signing key:
```bash
python -c "import secrets; print(secrets.token_hex(64))"
```

---

## Contributing

```bash
# Clone and setup
git clone https://github.com/viraj1011JAIN/Pramanix.git
cd Pramanix

# Install all dependencies
pip install -e ".[all]"
pip install -e ".[dev]"  # or: poetry install --with dev

# Run tests (skip API-dependent integration tests)
pytest tests/unit/ tests/adversarial/ tests/property/ tests/perf/ -q

# Run with coverage
pytest tests/unit/ tests/adversarial/ tests/property/ --cov=src/pramanix --cov-report=term-missing

# Lint + type check
ruff check src/ tests/
mypy src/pramanix/ --strict
```

**Development rules:**
- All policies must compile at `Guard.__init__()` time — no runtime surprises from bad invariants
- Every error path must produce `Decision(allowed=False)` — exceptions never propagate to callers
- Use `assert_and_track` (not `solver.add`) for all invariants — unsat core attribution is mandatory
- Never pickle Pydantic models — always `model_dump()` before crossing thread/process boundaries
- Alpine Docker images are banned — Z3 requires glibc; use `python:3.11-slim`
- Use direct `isinstance()` in conditionals for type narrowing — bool variables don't narrow in mypy strict

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
