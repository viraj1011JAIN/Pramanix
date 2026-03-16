# Pramanix

**Deterministic Neuro-Symbolic Guardrails for Autonomous AI Agents**

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://python.org)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.7.0-orange.svg)](src/pramanix/__init__.py)
[![Tests](https://img.shields.io/badge/tests-1601%20passed-brightgreen.svg)](#test-results)
[![Coverage](https://img.shields.io/badge/coverage-98%25-brightgreen.svg)](#test-results)
[![RSS](https://img.shields.io/badge/RSS-13--46%20MB-brightgreen.svg)](#memory-stability--measured-over-2-hours-continuous-operation)
[![SLSA Level 3](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev)

---

## Table of Contents

1. [What Is Pramanix?](#what-is-pramanix)
2. [The Problem It Solves](#the-problem-it-solves)
3. [Why Pramanix Exists](#why-pramanix-exists)
4. [Real-World Use Cases](#real-world-use-cases)
5. [Core Concept: The Two-Phase Model](#core-concept-the-two-phase-model)
6. [How It Works — Step by Step](#how-it-works--step-by-step)
7. [Key Features](#key-features)
8. [Pramanix vs Other Solutions](#pramanix-vs-other-solutions)
9. [Quick Start](#quick-start)
10. [Known Limitations](#known-limitations)
11. [The Policy DSL](#the-policy-dsl)
12. [Three Workflows](#three-workflows)
13. [Architecture Deep Dive](#architecture-deep-dive)
14. [File-by-File Reference](#file-by-file-reference)
15. [Ecosystem Integrations](#ecosystem-integrations)
16. [Production Deployment](#production-deployment)
17. [Test Results & Coverage](#test-results--coverage)
18. [Project Status](#project-status)
19. [Roadmap](#roadmap)
20. [License](#license)

---

## What Is Pramanix?

Pramanix (from Sanskrit *Pramāṇa* — "proof" or "valid knowledge" + Unix, meaning "composable") is an **execution firewall** that sits between an AI agent's *intent* and the real-world *action* it wants to take.

Before any action executes — a bank transfer, a database write, an API call, a cloud deployment — Pramanix intercepts it and runs **formal mathematical verification** using the Z3 SMT (Satisfiability Modulo Theories) solver. Every ALLOW comes with a **formal proof that the submitted values satisfy all declared constraints**. Every BLOCK identifies exactly which constraint was violated and why.

**In one sentence:** Pramanix formally verifies that the values submitted by an AI agent satisfy all declared safety constraints before any action executes — giving you a mathematical proof or a precise counterexample, not a probabilistic guess.

---

## The Problem It Solves

### AI Agents Are Taking Real Actions

AI agents are no longer just generating text. They are:
- Initiating bank transfers
- Deleting database records
- Deploying infrastructure
- Sending emails and Slack messages
- Managing user accounts and permissions

### Current Guardrails Are Not Enough

Most guardrails today rely on:
- **LLM-as-Judge**: Ask another LLM "is this safe?" — the judge can also hallucinate
- **Regex rules**: Pattern matching that attackers can bypass with rephrasing
- **Soft prompts**: "Please don't do X" in the system prompt — an LLM can be jailbroken
- **Human review**: Too slow for automated pipelines at scale

### The Fundamental Gap

None of these approaches give you **formal verification** — a mathematical proof that specific values satisfy specific constraints.

```
Traditional AI Pipeline:
  User Input → LLM → Action  ← No formal safety guarantee

Pramanix Pipeline:
  User Input → LLM → [PRAMANIX VERIFICATION WALL] → Action  ← Formally verified against declared constraints
```

---

## Why Pramanix Exists

- **AI agents execute real actions** — bank transfers, database writes, cloud deploys, permission changes. A hallucination isn't just wrong text; it's a wire transfer.
- **LLM judges hallucinate** — asking a model "is this safe?" gives you a probabilistic guess from something that can be jailbroken. Regex rules are bypassed with rephrasing.
- **You need mathematical proof, not probability** — the Z3 solver does not guess. It either proves all invariants hold or produces a concrete counterexample. No PhD required.

Pramanix applies the same formal verification technique used for aerospace software, cryptographic protocols, and CPU designs — exposed as a clean Python DSL any engineer can read and write.

---

## Real-World Use Cases

| Domain | What Could Go Wrong Without Pramanix | How Pramanix Prevents It |
|--------|--------------------------------------|--------------------------|
| **Banking / FinTech** | AI agent initiates transfer exceeding account balance | `balance - amount >= 0` invariant blocks the transfer mathematically |
| **Cloud Infrastructure** | AI agent scales down too aggressively, causes outage | `min_instances >= 2` invariant prevents unsafe scale-down |
| **Healthcare** | AI agent books appointment outside allowed hours | Time-window constraints reject out-of-hours bookings |
| **E-commerce** | AI agent applies a discount that results in negative revenue | `final_price >= cost` invariant blocks the action |
| **RBAC / Access Control** | AI agent grants a user higher privileges than it is allowed to grant | Role hierarchy invariants prevent privilege escalation |
| **AI Pipelines (LangChain, AutoGen, LlamaIndex)** | An autonomous agent loop takes an irreversible destructive action | Every tool call is intercepted and verified before execution |

---

## Core Concept: The Two-Phase Model

Pramanix operates in two phases. Neither phase can be skipped, and neither phase's decision can be overridden.

```
┌─────────────────────────────────────────────────────────────────────┐
│                     PRAMANIX EXECUTION FIREWALL                     │
│                                                                     │
│  ┌──────────────────────┐      ┌──────────────────────────────────┐ │
│  │  PHASE 1 (Optional)  │      │       PHASE 2 (Mandatory)        │ │
│  │  Intent Extraction   │      │    Formal Safety Verification    │ │
│  │                      │      │                                  │ │
│  │  Free-form text  ──► │ ───► │  Z3 SMT Solver                  │ │
│  │  Natural language    │      │  ┌─────────────────────────┐    │ │
│  │       ↓              │      │  │ For each invariant:      │    │ │
│  │  Dual LLM extraction │      │  │  ∀ values: constraint?   │    │ │
│  │  (consensus required)│      │  │  ├─ SAT  → ALLOW (proof) │    │ │
│  │       ↓              │      │  │  └─ UNSAT→ BLOCK (why)   │    │ │
│  │  Structured Intent   │      │  └─────────────────────────┘    │ │
│  └──────────────────────┘      └──────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
```

**Phase 1** is optional. Use it when your input is natural language ("transfer $500 to Alice") and needs to be converted to structured data. Two LLM models run concurrently and must agree — if they disagree, the action is blocked.

**Phase 2** is always required. The Z3 solver checks every constraint in your policy against the current system state and the proposed action. No exceptions, no shortcuts, no probabilistic guessing.

---

## How It Works — Step by Step

### The verify() Pipeline (6 Steps)

Every call to `guard.verify()` executes this exact pipeline:

```
Step 1: Intent Validation
         └─ Pydantic strict-mode validation of the intent dict
         └─ Fails fast with Decision.validation_failure() on bad input

Step 2: State Validation
         └─ Pydantic strict-mode validation of the state dict
         └─ state_version field required if Policy.Meta.version is set

Step 3: model_dump() → Plain Dicts
         └─ Validated Pydantic models converted to safe plain dicts
         └─ No Z3 objects or Pydantic models cross any process boundary

Step 4: Version Check
         └─ state["state_version"] must match Policy.Meta.version
         └─ Stale state → Decision.stale_state() (fail-safe)

Step 5: Z3 Solve (Two-Phase)
         Phase A: Shared solver — fast SAT/UNSAT determination
         Phase B: Per-invariant solvers — exact violation attribution
                  (only runs on UNSAT to find which invariants failed)

Step 6: Build Decision
         └─ Immutable Decision object with UUID, proof/counterexample, timing
         └─ NEVER raises — all exceptions become Decision.error()
```

### The Fail-Safe Contract

`guard.verify()` **never raises an exception**. This is not an aspiration — it is an enforced contract.

Every possible error — Z3 timeout, Pydantic validation failure, unexpected bug, memory error — is caught and returned as `Decision(allowed=False)`. The calling code is guaranteed to receive a `Decision` object. `allowed=True` is **mathematically impossible** from any error path.

```python
decision = guard.verify(intent=intent, state=state)
# Always a Decision. Never an exception. Always safe to check decision.allowed.
```

---

## Key Features

| # | Feature | Description |
|---|---------|-------------|
| 1 | **Formal Verification** | Z3 SMT solver proves every ALLOW. Formal constraint verification, not probability. |
| 2 | **Python Policy DSL** | Express safety rules in readable Python. No formal methods expertise required. |
| 3 | **Fail-Safe Architecture** | `verify()` never raises. Any error → BLOCK. The firewall cannot be crashed open. |
| 4 | **Semantic Fast-Path** | Pure Python O(1) pre-screener blocks obvious violations before Z3 runs. |
| 5 | **Expression Tree Pre-compilation** | Policy invariants compiled at `Guard` init — zero parsing overhead per request. |
| 6 | **Field Presence Pre-check** | Missing required fields detected in O(n) before Z3 is invoked. |
| 7 | **Async Worker Pools** | `async-thread` and `async-process` modes for high-throughput production use. |
| 8 | **Dual-Model Consensus Translator** | Two LLMs must agree on intent extraction. Disagreement → BLOCK. |
| 9 | **6-Layer Injection Security** | NFKC normalize → parallel LLM → partial-failure gate → Pydantic validate → consensus → injection confidence score. |
| 10 | **Adaptive Load Shedding** | Dual-condition (worker saturation AND high latency) sheds load before cascade failure. |
| 11 | **Adaptive Circuit Breaker** | 4-state FSM (CLOSED → OPEN → HALF_OPEN → CLOSED). 3 consecutive OPEN → ISOLATED. |
| 12 | **Cryptographic Audit Trail** | HMAC-SHA256 decision tokens. MerkleAnchor for tamper-evident sequential proof chaining. |
| 13 | **Authenticated Decision Context (Zero-Trust Pattern)** | JWT identity linking with Redis state loader. Every decision tied to a verified identity. |
| 14 | **HMAC IPC Sealing** | Worker results sealed with ephemeral per-Guard keys before crossing IPC boundary. Forgery → error. |
| 15 | **Structured Logging** | structlog JSON with automatic secret redaction. Secrets never reach disk. |
| 16 | **OpenTelemetry Tracing** | Optional distributed tracing. Each span carries `decision_id` for correlation. |
| 17 | **Prometheus Metrics** | 4 metrics: decisions_total, decision_latency_seconds, solver_timeouts_total, validation_failures_total. |
| 18 | **Ecosystem Integrations** | FastAPI, LangChain, LlamaIndex, AutoGen. One-line guard wrapping. |
| 19 | **Regulatory Primitives Library** | 25 domain primitives with exact regulatory citations: BSA/AML (31 CFR §1020.320), OFAC SDN (31 CFR §501.805), IRC §1091 wash-sale, HIPAA (45 CFR §164.502(b)), Reg. T margin (12 CFR §220), Basel III, and more. |
| 20 | **`@guard` Decorator** | Intercept any Python function call with policy verification. |
| 21 | **CLI Verification** | `pramanix verify-proof` command for audit token verification in CI/CD pipelines. |
| 22 | **Environment Variable Config** | All `GuardConfig` fields overridable via `PRAMANIX_*` env vars. |
| 23 | **SLSA Level 3 Supply Chain** | OIDC PyPI publish, Sigstore signing, SBOM. Verifiable provenance for every release. Verify with: `gh attestation verify --owner virajjain dist/pramanix-*.whl` |

---

## Pramanix vs Other Solutions

| Capability | Pramanix | LangChain Guardrails | Guardrails AI | LLM-as-Judge | OpenPolicy Agent | Regex Rules |
|-----------|:--------:|:-------------------:|:-------------:|:------------:|:----------------:|:-----------:|
| **Mathematical proof of safety** | ✅ | ❌ | ❌ | ❌ | ✅ (Rego logic) | ❌ |
| **Counterexample on violation** | ✅ | ❌ | ❌ | ❌ | Partial | ❌ |
| **Fail-safe: errors = BLOCK** | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ |
| **Works with natural language input** | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ |
| **Immune to jailbreaks / prompt injection** | Partial (Z3 only) | ❌ | ❌ | ❌ | ✅ | Partial |
| **No LLM needed for verification** | ✅ | ❌ | ❌ | ❌ | ✅ | ✅ |
| **Cryptographic audit trail** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Circuit breaker + load shedding** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Async worker pools** | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ |
| **Ecosystem integrations** | ✅ | Native | ✅ | N/A | ❌ | ❌ |
| **Python policy DSL** | ✅ | ❌ | ✅ | ❌ | ❌ (Rego) | ❌ |
| **Per-invariant violation attribution** | ✅ | ❌ | ❌ | ❌ | Partial | ❌ |
| **Zero eval/exec/ast.parse** | ✅ | N/A | N/A | N/A | N/A | N/A |
| **Memory stable at 1M decisions** | ✅ (measured: 13–29 MB steady-state RSS over 2-hour continuous run) | Unknown | Unknown | N/A | ✅ | ✅ |
| **Regulatory domain primitives (BSA/AML, OFAC, HIPAA)** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |

> **Note on "Immune to jailbreaks / prompt injection" (Partial):** When Phase 1 (LLM translator) is active via `parse_and_verify()`, the translator layer processes untrusted user input and is still vulnerable to adversarial extraction attempts. Only Phase 2 (Z3 verification) is fully immune — it evaluates mathematical structure and cannot be manipulated by natural language. If you use structured mode (`guard.verify()` directly), the full row applies without caveat.

### Why Pramanix Wins on the Critical Dimension

The single most important difference: **LLM-based guardrails can be lied to.** An adversarially crafted prompt can make an LLM judge say "safe" when it isn't. The Z3 solver cannot be lied to. It evaluates the *mathematical structure* of the constraints against the actual values — there is no natural language to manipulate.

---

## Quick Start

### Install

```bash
pip install pramanix
```

### Minimal Example (Structured Mode)

```python
from decimal import Decimal
from pramanix import Guard, GuardConfig, Policy, Field, E

# 1. Define your policy — what invariants must always hold?
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

            (E(cls.is_frozen) == False)  # noqa: E712  ← see DSL note below
                .named("account_not_frozen")
                .explain("Account is frozen"),
        ]

# 2. Create the guard once (at startup)
guard = Guard(BankingPolicy, GuardConfig(execution_mode="sync"))

# 3. Verify every action before it executes
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
    execute_transfer()                  # ← Z3-proven safe
else:
    raise PolicyViolation(decision.explanation)
    # "Insufficient balance: 200.00 < 500.00"
```

> **DSL design note:** `== False` is intentional here, not a style error.
> `E(field)` returns an `ExpressionNode` whose `__eq__` overloads to return
> a `ConstraintExpr` for Z3 compilation. Python's `is False` checks object
> identity and always returns `False` for non-singleton objects. The
> `# noqa: E712` suppresses the linter warning for this deliberate pattern.
> Use `~E(cls.is_frozen)` as an alternative if you prefer.

### Neuro-Symbolic Mode (Natural Language Input)

```python
# Parse free-form user text → verify → allow or block
decision = await guard.parse_and_verify(
    "please move five hundred dollars to alice",
    TransferIntent,   # Pydantic model defining expected fields
    state=account_state,
    models=("gpt-4o", "claude-opus-4-5"),  # dual-model consensus
)
# Two LLMs must agree on the extracted intent.
# Even if they agree, Z3 still verifies the constraints.
```

### Decorator Mode

```python
from pramanix import guard

@guard(BankingPolicy, config=GuardConfig(execution_mode="sync"))
def execute_transfer(amount: Decimal, balance: Decimal, ...):
    # This function body only runs if the policy verifies
    ...

# fn.__guard__ exposes the Guard instance for introspection
```

---

## Known Limitations

### Time-of-Check / Time-of-Use (TOCTOU)

Pramanix verifies the state at the moment `guard.verify()` is called. It does not guarantee that state remains unchanged between verification and execution. In concurrent systems, two requests could both pass verification and then both execute — consuming a shared resource beyond the allowed limit.

**Mitigation:** Compose Pramanix with optimistic locking, state version pinning, or transactional commit protocols at the execution layer. Pramanix is a pre-execution safety gate, not a distributed transaction coordinator.

### Model Accuracy

Z3 formally verifies that the *submitted values* satisfy your *declared constraints*. It does not verify that:
- The state values were accurately fetched from the real system
- The intent dict correctly represents what the executor will actually do
- Your invariants fully capture your safety requirements

**Mitigation:** Ensure state is fetched atomically and recently. Invariants should be reviewed by domain experts, not just engineers.

### Z3 String Theory Limitations

Z3's `String` sort uses sequence theory, which is decidable but slower and less expressive than arithmetic sorts. Complex string constraints (regex-like patterns, substring searches) may produce timeouts. For string-heavy policies, prefer `is_in()` membership checks over complex string expressions, and tune `solver_timeout_ms` accordingly.

### Phase 1 Translator Security

When `parse_and_verify()` is used (neuro-symbolic mode), the LLM extraction layer processes untrusted user input. The 6-layer injection hardening significantly reduces the attack surface, but a sufficiently sophisticated adversary who understands the extraction prompt design may still manipulate the structured output. Phase 2 (Z3) always runs and provides the binding safety guarantee regardless of what Phase 1 produces.

### Native Library Crashes (sync mode only)

`guard.verify()` catches all Python-level exceptions and returns `Decision(allowed=False)`. However, Z3 is a native C++ library. A Z3 segfault kills the worker process directly via a signal, which cannot be caught by Python's `except Exception`.

**In `async-process` mode:** worker process death is detected by the `ProcessPoolExecutor` and surfaces as a `BrokenProcessPool` exception, which the fail-safe catches correctly.

**In `sync` mode:** a Z3 segfault will crash the calling process. Use `async-process` mode for maximum isolation in production.

This scenario is rare — Z3 4.12+ is stable under normal arithmetic constraints — but operators should be aware of the distinction.

### Audit Trail Persistence

`MerkleAnchor` is process-scoped. The Merkle chain resets on process restart. For a durable audit trail across restarts, export `root_hash` to persistent storage (append-only log, database, or Redis stream) at each checkpoint. The `DecisionSigner` HMAC tokens are individually verifiable without the chain — the chain provides sequential ordering proof, not individual decision integrity.

---

## The Policy DSL

### Fields

Fields are the bridge between your system's data model and the Z3 solver.

```python
from decimal import Decimal
from pramanix import Field, E

# Field(name, python_type, z3_sort)
#   name:        key in the intent/state dict
#   python_type: Python type (Decimal, int, float, bool, str)
#   z3_sort:     Z3 type — "Real", "Int", "Bool", "String"

amount    = Field("amount",    Decimal, "Real")
count     = Field("count",     int,     "Int")
is_active = Field("is_active", bool,    "Bool")
username  = Field("username",  str,     "String")
```

### Expressions

`E(field)` wraps a Field into an expression that supports Python operators, which compile to Z3 AST nodes.

```python
from pramanix import E

# Arithmetic (Real/Int fields)
E(balance) - E(amount) >= 0
E(amount)  * 2 <= E(limit)
E(fee)     + E(amount) <= E(balance)

# Comparison
E(risk_score) <= 0.8
E(count)      >= 1
E(amount)     == E(limit)
E(amount)     != Decimal("0")

# Boolean (Bool fields)
E(is_frozen)  == False          # noqa: E712
E(is_active)  == True           # noqa: E712
~ConstraintExpr                 # NOT (on ConstraintExpr only)

# Logical combinators
(E(amount) > 0) & (E(balance) > 0)    # AND
(E(frozen) == False) | (E(admin))      # OR

# Membership
E(status).is_in(["pending", "active"])
```

### Invariants

Invariants are named constraints with optional human-readable explanations.

```python
@classmethod
def invariants(cls):
    return [
        (E(cls.balance) - E(cls.amount) >= 0)
            .named("sufficient_balance")          # machine-readable label
            .explain("Balance {balance} too low for transfer {amount}"),
                                                  # {field_name} interpolated on violation
    ]
```

### GuardConfig Reference

```python
GuardConfig(
    execution_mode           = "sync",       # "sync" | "async-thread" | "async-process"
    solver_timeout_ms        = 5_000,        # per-invariant Z3 timeout (ms)
    max_workers              = 4,            # worker pool size (async modes)
    max_decisions_per_worker = 10_000,       # worker restart threshold (memory hygiene)
    worker_warmup            = True,         # dummy Z3 solve on startup (eliminates cold-start)
    log_level                = "INFO",       # structured log level
    metrics_enabled          = False,        # Prometheus metrics
    otel_enabled             = False,        # OpenTelemetry traces
    translator_enabled       = False,        # LLM-based intent translation
    fast_path_enabled        = False,        # semantic fast-path pre-screener
    fast_path_rules          = (),           # tuple of callable rules
    shed_latency_threshold_ms= 200.0,        # load shedding: p99 latency threshold
    shed_worker_pct          = 90.0,         # load shedding: worker saturation %
)
# All fields overridable via PRAMANIX_<FIELD_NAME_UPPER> environment variables
```

### Decision Object Reference

```python
decision = guard.verify(intent=..., state=...)

decision.allowed              # bool — True iff action is permitted
decision.status               # SolverStatus enum value
decision.violated_invariants  # tuple[str, ...] — labels of failed invariants
decision.explanation          # human-readable violation message
decision.decision_id          # UUID4 string — for distributed tracing
decision.solver_time_ms       # float — Z3 wall-clock time

# SolverStatus values:
# SAFE              → allowed=True  (Z3 proved all invariants hold)
# UNSAFE            → allowed=False (Z3 found a counterexample)
# TIMEOUT           → allowed=False (Z3 exceeded time budget)
# ERROR             → allowed=False (unexpected internal error)
# STALE_STATE       → allowed=False (state_version mismatch)
# VALIDATION_FAILURE→ allowed=False (Pydantic validation failed)
# RATE_LIMITED      → allowed=False (load shedding)

decision.to_dict()   # JSON-serialisable dict for logging / audit
```

---

## Three Workflows

### Workflow 1: Structured Verification (No LLM)

Use when the agent's intent is already structured (API calls, SDK calls).

```
┌────────────────────────────────────────────────────────────────────┐
│                    STRUCTURED WORKFLOW                             │
│                                                                    │
│  Agent Code                                                        │
│      │                                                             │
│      ▼                                                             │
│  intent = {"amount": Decimal("500")}          ← structured dict   │
│  state  = {"balance": Decimal("1000"), ...}   ← current state     │
│      │                                                             │
│      ▼                                                             │
│  ┌─────────────────────────────────────────┐                      │
│  │  Guard.verify(intent, state)            │                      │
│  │                                         │                      │
│  │  1. Pydantic validation (strict mode)   │                      │
│  │  2. State version check                 │                      │
│  │  3. Fast-path pre-screen (O(1) Python)  │                      │
│  │  4. Z3 SMT solve                        │                      │
│  │     ├─ SAT  → Decision(allowed=True)    │                      │
│  │     └─ UNSAT→ Decision(allowed=False)   │                      │
│  └─────────────────────────────────────────┘                      │
│      │                                                             │
│      ▼                                                             │
│  if decision.allowed:  execute_action()                            │
│  else:                 block_and_log(decision.explanation)         │
└────────────────────────────────────────────────────────────────────┘
```

### Workflow 2: Neuro-Symbolic (Natural Language → Verified Action)

Use when users give free-form instructions to an AI agent.

```
┌────────────────────────────────────────────────────────────────────┐
│                   NEURO-SYMBOLIC WORKFLOW                          │
│                                                                    │
│  User: "Transfer five hundred dollars to my savings account"       │
│      │                                                             │
│      ▼                                                             │
│  ┌─────────────────────────────────────────┐                      │
│  │  Phase 1: Dual-LLM Consensus Extraction │                      │
│  │                                         │                      │
│  │  LLM-A (gpt-4o)   → {amount: 500.00}   │                      │
│  │  LLM-B (claude)   → {amount: 500.00}   │                      │
│  │                                         │                      │
│  │  Agreement? ✅ → Intent validated       │                      │
│  │  Disagreement? → Decision.error()       │                      │
│  │                                         │                      │
│  │  6-layer injection guard:               │                      │
│  │  NFKC normalize → parallel LLM →       │                      │
│  │  partial-failure gate → Pydantic →      │                      │
│  │  consensus → injection confidence       │                      │
│  └─────────────────────────────────────────┘                      │
│      │                                                             │
│      ▼                                                             │
│  ┌─────────────────────────────────────────┐                      │
│  │  Phase 2: Z3 Formal Verification        │                      │
│  │  (same as Structured Workflow above)    │                      │
│  └─────────────────────────────────────────┘                      │
└────────────────────────────────────────────────────────────────────┘
```

### Workflow 3: Decorator / Tool Interception

Use when you want transparent guardrails on any Python function or AI tool.

```python
# FastAPI route
from pramanix.integrations.fastapi import pramanix_route

@pramanix_route(BankingPolicy)
@app.post("/transfer")
async def transfer(body: TransferRequest, state: AccountState):
    # Only executes if policy verifies
    ...

# LangChain tool wrapping
from pramanix.integrations.langchain import wrap_tools

safe_tools = wrap_tools(agent_tools, BankingPolicy)
agent = initialize_agent(safe_tools, ...)
# Every tool call now passes through Z3 verification

# AutoGen agent wrapping
from pramanix.integrations.autogen import PramanixToolCallback

callback = PramanixToolCallback.wrap(BankingPolicy)
agent = AssistantAgent("banker", function_map=callback)
```

---

## Architecture Deep Dive

### System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         PRAMANIX SDK ARCHITECTURE                           │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                        PUBLIC API LAYER                              │  │
│  │  guard.verify() | guard.verify_async() | guard.parse_and_verify()   │  │
│  │  @guard decorator | Guard class | GuardConfig | Policy DSL           │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                   │                                         │
│  ┌────────────────┐  ┌────────────▼────────────┐  ┌─────────────────────┐ │
│  │   TRANSLATOR   │  │    VALIDATION LAYER      │  │   FAST-PATH LAYER   │ │
│  │                │  │                          │  │                     │ │
│  │ NL Text Input  │  │ Pydantic intent model    │  │ O(1) Python rules   │ │
│  │ LLM-A  LLM-B   │  │ Pydantic state model     │  │ negative_amount()   │ │
│  │ Consensus gate │  │ State version check      │  │ zero_balance()      │ │
│  │ Injection guard│  │ Field presence pre-check  │  │ account_frozen()    │ │
│  │ Pydantic valid │  │                          │  │ exceeds_hard_cap()  │ │
│  └────────────────┘  └──────────────────────────┘  └─────────────────────┘ │
│                                   │                                         │
│  ┌────────────────────────────────▼──────────────────────────────────────┐ │
│  │                     TRANSPILER LAYER                                  │ │
│  │                                                                       │ │
│  │  Policy DSL (Python) → Expression Tree → Z3 AST                      │ │
│  │  E(field).__ge__(0)  → GteNode(FieldRef, Literal) → z3.ArithRef      │ │
│  │  Zero eval / exec / ast.parse — pure structural traversal            │ │
│  │  compile_policy() at Guard init → InvariantMeta[] cached             │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                   │                                         │
│  ┌────────────────────────────────▼──────────────────────────────────────┐ │
│  │                      SOLVER LAYER                                     │ │
│  │                                                                       │ │
│  │  Phase A: Shared solver — fast SAT/UNSAT determination                │ │
│  │    assert_and_track all invariants → check() → SAT or UNSAT          │ │
│  │                                                                       │ │
│  │  Phase B: Per-invariant solvers (only on UNSAT)                       │ │
│  │    One solver per invariant → exactly one assert_and_track            │ │
│  │    → unsat_core() = exactly {label} when violated                    │ │
│  │    → precise attribution of every violated constraint                 │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                   │                                         │
│  ┌────────────────────────────────▼──────────────────────────────────────┐ │
│  │                     WORKER / ASYNC LAYER                              │ │
│  │                                                                       │ │
│  │  sync mode:          solve() runs on caller's thread                  │ │
│  │  async-thread mode:  ThreadPoolExecutor (Z3 in thread)               │ │
│  │  async-process mode: ProcessPoolExecutor (Z3 in subprocess)          │ │
│  │                                                                       │ │
│  │  AdaptiveConcurrencyLimiter:                                          │ │
│  │    Dual-condition: workers ≥ shed_pct% AND p99 > threshold_ms        │ │
│  │    → Decision.rate_limited() on shedding                             │ │
│  │                                                                       │ │
│  │  HMAC IPC Sealing:                                                    │ │
│  │    _EphemeralKey per Guard → seal result before crossing IPC          │ │
│  │    HMAC verification on receipt → forgery → Decision.error()          │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                   │                                         │
│  ┌────────────────────────────────▼──────────────────────────────────────┐ │
│  │                    SECURITY / OBSERVABILITY LAYER                     │ │
│  │                                                                       │ │
│  │  Audit: HMAC-SHA256 JWS decision tokens + MerkleAnchor chaining      │ │
│  │  Identity: JWTIdentityLinker + RedisStateLoader                       │ │
│  │  Circuit Breaker: CLOSED→OPEN→HALF_OPEN→CLOSED + ISOLATED             │ │
│  │  Logging: structlog JSON + secret redaction processor                 │ │
│  │  Metrics: Prometheus counters/histograms (optional)                   │ │
│  │  Tracing: OpenTelemetry spans per verify() call (optional)            │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Decision State Machine

```
Every verify() call produces exactly ONE Decision:

  Input arrives
      │
      ▼
  Pydantic validation ──FAIL──► Decision.validation_failure()
      │OK
      ▼
  State version check ──MISMATCH► Decision.stale_state()
      │OK
      ▼
  Fast-path pre-screen──BLOCKED► Decision.unsafe()  (fast, no Z3)
      │PASS
      ▼
  Z3 solve ──TIMEOUT──► Decision.timeout()
      │      ──ERROR───► Decision.error()
      │SAT
      ├──────────────► Decision.safe()   (allowed=True ✅)
      │UNSAT
      └──────────────► Decision.unsafe() (allowed=False ❌ + violated_invariants + explanation)
```

### Worker Lifecycle (Async Modes)

```
Guard.__init__()
      │
      ▼ (async-thread or async-process)
  WorkerPool.spawn()
      │
      ├── Worker 1: warmup solve (dummy Z3) → eliminates JIT cold-start
      ├── Worker 2: warmup solve
      ├── Worker N: warmup solve
      │
  Request arrives
      │
      ▼
  AdaptiveConcurrencyLimiter
      ├── workers ≥ 90% AND p99 > 200ms? → Decision.rate_limited()
      └── OK → submit to pool
                   │
                   ▼
             Worker executes solve()
                   │
                   ▼ (async-process mode only)
             HMAC seal result
                   │
             Cross IPC boundary
                   │
             HMAC verify → forgery check
                   │
                   ▼
             Decision returned

  After 10,000 decisions: worker recycled (prevents Z3 memory accumulation)
```

---

## File-by-File Reference

### Core SDK (`src/pramanix/`)

| File | Purpose | What It Contains | Why It Was Built |
|------|---------|-----------------|-----------------|
| `__init__.py` | Public API surface | All 44 exported names. The only stable contract. | Single stable import point. Internal modules may change. |
| `guard.py` | SDK entrypoint | `Guard`, `GuardConfig`, 6-step verify pipeline, structlog config, secret redaction, OTel spans, Prometheus metrics | Orchestrates all subsystems. The "main loop" of every verification. |
| `policy.py` | Policy base class | `Policy` ABC with `fields()` auto-discovery, `validate()`, `meta_version()`, `meta_intent_model()`, `meta_state_model()` | Provides the DSL base. Users subclass this. |
| `expressions.py` | DSL expression trees | `Field`, `E()`, `ConstraintExpr`, `ExpressionNode`, all operator overloads (`__ge__`, `__le__`, `__eq__`, `__and__`, `__or__`, `~`, `.is_in()`) | Converts Python expressions to abstract syntax tree nodes without eval(). |
| `transpiler.py` | AST → Z3 AST | `NodeKind` enum, `InvariantMeta` dataclass, `compile_policy()`, `collect_fields()`, `_tree_repr()`, `_tree_has_literal()`, `_collect_field_names()` | Translates expression trees to Z3 solver objects. Zero eval/exec/ast.parse. Policies compile once at Guard init. |
| `solver.py` | Z3 integration | `solve()`, `_SolveResult`, two-phase verification (shared SAT fast-path + per-invariant UNSAT attribution), `SolverTimeoutError` | Isolates all Z3 API calls. Phase A = speed. Phase B = precise violation attribution via `unsat_core()`. |
| `decision.py` | Result object | `Decision` frozen dataclass, `SolverStatus` enum, 7 factory methods (`safe()`, `unsafe()`, `timeout()`, `error()`, `stale_state()`, `validation_failure()`, `rate_limited()`), `to_dict()` | Immutable, JSON-serialisable result. The `allowed=True ↔ status=SAFE` invariant is enforced in `__post_init__`. |
| `fast_path.py` | Semantic pre-screener | `SemanticFastPath` (5 factory rules), `FastPathEvaluator`, `FastPathResult` | O(1) pure Python checks before Z3. Can only BLOCK, never ALLOW. |
| `worker.py` | Async worker pool | `WorkerPool`, `AdaptiveConcurrencyLimiter`, `_EphemeralKey`, `_worker_solve_sealed()`, `_unseal_decision()`, zombie-safe worker recycling | Isolates Z3 from the event loop. Dual-condition shedding prevents cascade failure. HMAC sealing prevents IPC forgery. |
| `validator.py` | Pydantic validation | `validate_intent()`, `validate_state()` — strict mode validation against Policy.Meta models | Catches bad input at the boundary, before any Z3 resources are allocated. |
| `resolvers.py` | Lazy field resolution | `ResolverRegistry` with thread-local cache, `clear_cache()` | Resolves dynamic state fields (e.g., from database) without data bleed between concurrent requests. |
| `decorator.py` | Function decorator | `@guard(policy, config, on_block)`, `fn.__guard__` introspection | Allows transparent guardrail injection on any callable. |
| `identity.py` | Authenticated Decision Context (Zero-Trust Pattern) | `JWTIdentityLinker`, `RedisStateLoader` | Ties every decision to a cryptographically verified identity. |
| `audit.py` | Cryptographic audit | `DecisionSigner`, `DecisionVerifier`, `MerkleAnchor` | HMAC-SHA256 JWS tokens + Merkle chaining for tamper-evident audit log. |
| `circuit_breaker.py` | Resilience FSM | `AdaptiveCircuitBreaker`, `CircuitBreakerConfig`, 4-state FSM | Prevents cascade failure when downstream system is degraded. |
| `cli.py` | Command-line tool | `pramanix verify-proof` command, JSON output, exit codes | Audit token verification for CI/CD pipelines and operator tooling. |
| `exceptions.py` | Exception hierarchy | 19 exception types under `PramanixError` | All internal errors are typed. Guard's fail-safe catches every subclass. |
| `helpers/serialization.py` | Safe serialization | `safe_dump()` — Pydantic model → plain dict, no Z3 objects | Ensures nothing unpicklable crosses IPC boundaries. |
| `telemetry.py` | Observability wiring | Prometheus metrics registration, OTel tracer setup | Isolated so telemetry setup does not pollute core logic. |

### Translator Subsystem (`src/pramanix/translator/`)

| File | Purpose | What It Contains |
|------|---------|-----------------|
| `base.py` | Translator ABC | `BaseTranslator`, `TranslatorContext`, abstract `extract()` method |
| `openai_compat.py` | OpenAI / Anthropic adapter | Routes `gpt-*`/`o?-*` to OpenAI, `claude-*` to Anthropic. Single adapter for both providers. |
| `ollama.py` | Local LLM adapter | Connects to Ollama for local/air-gapped deployments |
| `redundant.py` | 6-layer security pipeline | `create_translator()`, `extract_with_consensus()`, NFKC normalization, parallel extraction, partial-failure gate, Pydantic validation, consensus check, injection confidence scoring |

### Integrations (`src/pramanix/integrations/`)

| File | Integration | Key Classes | How It Works |
|------|------------|-------------|--------------|
| `fastapi.py` | FastAPI | `PramanixMiddleware`, `pramanix_route()` | Middleware intercepts requests. `@pramanix_route` wraps route handlers. |
| `langchain.py` | LangChain | `PramanixGuardedTool`, `wrap_tools()` | Wraps `BaseTool.run()`. `wrap_tools(tools, policy)` guards an entire tool list. |
| `autogen.py` | AutoGen | `PramanixToolCallback`, `.wrap()` | Hooks into AutoGen's function-call lifecycle. |
| `llamaindex.py` | LlamaIndex | `PramanixFunctionTool`, `PramanixQueryEngineTool` | Subclasses LlamaIndex tool base classes with guard interception. |

### Primitives Library (`src/pramanix/primitives/`)

| File | Domain | What's Included |
|------|--------|-----------------|
| `finance.py` | Financial | `NonNegativeBalance`, `SecureBalance`, `UnderDailyLimit`, `PositiveAmount`, `WithinRiskThreshold` |
| `rbac.py` | Access Control | Role hierarchy constraints, privilege escalation prevention |
| `infra.py` | Infrastructure | Min/max instance counts, resource quota enforcement |
| `time_window.py` | Scheduling | Business hours enforcement, maintenance window constraints |
| `common.py` | Shared utilities | Reusable building blocks for custom primitives |

### Tests (`tests/`)

| Directory | What It Tests | Count |
|-----------|--------------|-------|
| `tests/unit/` | Every module in isolation — expressions, transpiler, solver, decision, fast-path, circuit breaker, audit, identity, exceptions | ~800 tests |
| `tests/integration/` | Guard + Policy end-to-end, async modes, decorator, integrations, translator pipeline | ~500 tests |
| `tests/perf/` | P50 latency targets, fast-path sub-1ms, 1M decision memory stability (RSS < 50 MiB) | ~50 tests |
| `tests/dark_path/` | Edge cases: empty invariants, malformed fields, Z3 timeout, injection attacks, adversarial input | ~180 tests |

---

## Ecosystem Integrations

### FastAPI

```python
from fastapi import FastAPI
from pramanix.integrations.fastapi import PramanixMiddleware, pramanix_route

app = FastAPI()
app.add_middleware(PramanixMiddleware, policy=BankingPolicy)

@pramanix_route(BankingPolicy)
@app.post("/transfer")
async def transfer(body: TransferRequest):
    # Guard runs before your handler
    return {"status": "transferred"}
```

### LangChain

```python
from langchain.agents import initialize_agent
from pramanix.integrations.langchain import wrap_tools

# Wrap every tool in your agent with the guard
guarded_tools = wrap_tools(
    [transfer_tool, balance_tool, freeze_tool],
    BankingPolicy,
    config=GuardConfig(execution_mode="sync"),
)
agent = initialize_agent(guarded_tools, llm, ...)
# Every tool.run() now passes through Z3 verification
```

### AutoGen

```python
from autogen import AssistantAgent
from pramanix.integrations.autogen import PramanixToolCallback

callback = PramanixToolCallback.wrap(BankingPolicy)
agent = AssistantAgent(
    "banker",
    function_map=callback,
    llm_config={"functions": tool_schemas},
)
```

### LlamaIndex

```python
from pramanix.integrations.llamaindex import PramanixFunctionTool

guarded_tool = PramanixFunctionTool(
    fn=execute_transfer,
    policy=BankingPolicy,
    fn_schema=TransferSchema,
)
agent = ReActAgent.from_tools([guarded_tool])
```

---

## Production Deployment

### Recommended Configuration

```python
guard = Guard(
    BankingPolicy,
    GuardConfig(
        execution_mode="async-process",      # full CPU isolation for Z3
        solver_timeout_ms=5_000,             # 5s hard timeout per invariant
        max_workers=8,                        # match CPU cores
        max_decisions_per_worker=10_000,      # recycle to prevent Z3 memory accumulation
        worker_warmup=True,                   # eliminate cold-start JIT spike
        fast_path_enabled=True,               # fast O(1) pre-screen
        fast_path_rules=(
            SemanticFastPath.negative_amount("amount"),
            SemanticFastPath.account_frozen("is_frozen"),
            SemanticFastPath.zero_or_negative_balance("balance"),
        ),
        metrics_enabled=True,                 # Prometheus /metrics
        otel_enabled=True,                    # OpenTelemetry traces
        shed_worker_pct=90.0,                 # shed when 90%+ workers busy
        shed_latency_threshold_ms=200.0,      # AND p99 > 200ms
        log_level="INFO",
    ),
)
```

### Docker

```dockerfile
# Alpine is BANNED — z3-solver has musl compatibility issues
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ src/
RUN pip install -e .

CMD ["uvicorn", "myapp:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Environment Variables

```bash
# All GuardConfig fields can be set via environment
PRAMANIX_EXECUTION_MODE=async-process
PRAMANIX_SOLVER_TIMEOUT_MS=5000
PRAMANIX_MAX_WORKERS=8
PRAMANIX_METRICS_ENABLED=true
PRAMANIX_OTEL_ENABLED=true
PRAMANIX_LOG_LEVEL=INFO
PRAMANIX_FAST_PATH_ENABLED=true
PRAMANIX_SHED_WORKER_PCT=90
PRAMANIX_SHED_LATENCY_THRESHOLD_MS=200
```

### Prometheus Metrics

```
pramanix_decisions_total{policy="BankingPolicy", status="safe"}       counter
pramanix_decisions_total{policy="BankingPolicy", status="unsafe"}     counter
pramanix_decision_latency_seconds{policy="BankingPolicy"}             histogram
pramanix_solver_timeouts_total{policy="BankingPolicy"}                counter
pramanix_validation_failures_total{policy="BankingPolicy"}            counter
```

### Cryptographic Audit Trail

```python
from pramanix import DecisionSigner, DecisionVerifier, MerkleAnchor

# Sign decisions for tamper-evident audit log
signer = DecisionSigner(key=your_hmac_key)
token = signer.sign(decision)

# Verify a token (CLI or code)
verifier = DecisionVerifier(key=your_hmac_key)
verified = verifier.verify(token)

# Chain decisions into a Merkle sequence
anchor = MerkleAnchor()
anchor.append(decision)
root_hash = anchor.root()   # tampering invalidates the chain

# CLI verification
pramanix verify-proof <token>                  # exits 0 (VALID) or 1 (INVALID)
pramanix verify-proof <token> --json           # JSON output for scripting
pramanix verify-proof --stdin                  # read token from stdin
```

### Adaptive Circuit Breaker

```python
from pramanix import AdaptiveCircuitBreaker, CircuitBreakerConfig

breaker = AdaptiveCircuitBreaker(
    CircuitBreakerConfig(
        failure_threshold=5,          # OPEN after 5 consecutive failures
        recovery_timeout_s=30,        # try HALF_OPEN after 30s
        half_open_max_calls=3,        # 3 test calls in HALF_OPEN
    )
)

# States: CLOSED (normal) → OPEN (tripped) → HALF_OPEN (probing) → CLOSED
# 3 consecutive OPEN states → ISOLATED (manual reset required)
with breaker:
    decision = guard.verify(intent, state)
```

### Shutdown

```python
# Always shutdown gracefully to release worker pool resources
await guard.shutdown()
```

---

## Test Results & Coverage

```
┌─────────────────────────────────────────────────┐
│              Production Benchmarks              │
│  RSS:      13–46 MB steady-state (1M decisions) │
│  P99:       6.40 ms  (Windows 11 / Python 3.11) │
│  P95:       6.01 ms                             │
│  P50:       5.38 ms                             │
│  Tests:    1601 passed · 98% coverage           │
└─────────────────────────────────────────────────┘
```

### Full Test Suite Results

```
==================== test session info ====================
Platform:  Windows / Python 3.11
Test files: 28 files across 4 directories

===================== test summary ====================
PASSED  1601
SKIPPED    2  (testcontainers/Docker: Redis not running in CI)
FAILED     0
ERRORS     0

Coverage: 98%  (threshold: 95% ✅)
```

### Performance Benchmarks

Measured on: Windows 11 / Python 3.11 / single-process sync mode
Policy: BankingPolicy (5 invariants) / n=500 decisions post-warmup

| Benchmark | Target | Measured |
|-----------|--------|----------|
| P50 API latency (sync mode) | < 5ms | 5.38ms (Windows 11 / Python 3.11) |
| P95 API latency (sync mode) | < 10ms | 6.01ms |
| P99 API latency (sync mode) | < 15ms | 6.40ms — CI-enforced nightly |
| Fast-path average latency | < 1ms | ✅ Passing |
| 1M decisions RSS growth | < 20 MiB | ✅ Measured: ~13 MiB |
| Steady-state RSS | — | 13–29 MB (measured over 2 hours) |

> P99 < 15ms is enforced by a nightly CI benchmark job. A z3-solver patch that causes P99 regression fails the build automatically.
> Run `python benchmarks/latency_benchmark.py` to reproduce locally.

### Memory Stability — Measured Over ~2 Hours Continuous Operation

| Phase | RSS | Duration |
|-------|-----|----------|
| Z3 JIT warm-up | 107–123 MB | First 8 minutes |
| Post-GC collection | 73–86 MB | Minutes 8–12 |
| Stable operating band | 30–56 MB | Active decision processing |
| Low-activity floor | 13–29 MB | Extended operation |

**Trend: no upward drift detected across 2 hours of continuous decisions.**

The sawtooth oscillation (48→32→48 MB) is normal Python GC behavior — objects allocated during Z3 solving, collected, allocated again. The floor trends downward over time. There is no monotonic increase.

The 268–706 MB values sometimes seen in full test suite runs are from `pytest-cov` line instrumentation — the coverage profiler, not the SDK. Pramanix RSS never exceeds 123 MB during normal operation.

Platform: Windows 11 / Python 3.11 / WorkingSet64 sampling every 60s.
Linux RSS (production containers) will be lower — shared library pages are not counted in Linux VmRSS the same way.

### Test Categories

| Category | Tests | What's Covered |
|----------|-------|----------------|
| Unit tests | ~800 | All 28 source modules, every public method, every edge case |
| Integration tests | ~500 | Guard + Policy end-to-end, all 3 execution modes. Integration adapters tested with mocked runtimes; live service tests (require Docker) are excluded from CI coverage. |
| Performance tests | ~50 | Latency targets, fast-path speed, 1M decision memory stability |
| Dark-path tests | ~180 | Adversarial inputs, injection attacks, malformed data, Z3 timeout, all error paths |

---

## Project Status

**Version:** 0.7.0
**Release track:** v0.8.0 in active development

### Milestone Completion

| Milestone | Description | Status |
|-----------|-------------|--------|
| v0.1 | Core SDK: Policy DSL, Z3 solver, sync verify() | ✅ Complete |
| v0.2 | Async modes: thread pool, process pool, worker recycling | ✅ Complete |
| v0.3 | Hardening: ContextVar isolation, HMAC IPC, OTel, Hypothesis | ✅ Complete |
| v0.4 | Translator: dual-LLM consensus, 6-layer injection defense | ✅ Complete |
| v0.5 | CI/CD: SLSA Level 3, Sigstore, SBOM, hardened Docker, K8s | ✅ Complete |
| v0.5.x | Security: formal threat model T1–T7, adversarial test suite | ✅ Complete |
| v0.6 | Primitives: 25 domain primitives with CFR/HIPAA citations | ✅ Complete |
| v0.6.x | Integrations: FastAPI, LangChain, LlamaIndex, AutoGen | ✅ Complete |
| v0.7 | Performance: expression cache, load shedding, benchmarks | ✅ Complete |
| v0.8 | Audit: Ed25519 signing, compliance reporter, audit CLI | 🔄 In progress |
| v0.9 | Documentation site, policy registry, competitor benchmark | 📋 Planned |
| v1.0 GA | Chaos testing, RC deployment, API contract lock | 📋 Planned |

### What "Complete" Means at v0.7.0

- 1,601 tests passing (unit, integration, property, adversarial, perf)
- 98% coverage (96% statement, 93% branch)
- Memory stable: 13–29 MB steady-state RSS measured over 2 hours
- Core verification pipeline tested end-to-end across all execution modes. Integration adapters (FastAPI, LangChain, LlamaIndex, AutoGen) tested with mocked runtimes in CI. Live service integration tests require Docker and are excluded from the standard coverage measurement (`# pragma: no cover` on Starlette import blocks).
- Cryptographic audit trail verified
- SLSA Level 3 provenance on every PyPI release
- Formal threat model covering T1–T7 with CVSS scores and test references
- 25 domain primitives with exact regulatory citations

---

## Roadmap

| Milestone | Focus | Description |
|-----------|-------|-------------|
| v0.8.0 | Redis-backed state cache | Distributed state loader with TTL-bounded caching |
| v0.9.0 | Policy versioning & migration | Safe policy upgrades without decision gaps |
| v1.0.0 GA | Production hardening | Final security audit, SLA docs, enterprise packaging |
| v1.1.0 | Policy composition | Combine policies with `&` / `|` operators |
| v1.2.0 | gRPC transport | High-throughput inter-service guardrail calls |
| v2.0.0 | Distributed coordinator | Multi-node policy consensus for microservice meshes |

---

## License

Pramanix is dual-licensed:

- **Community Edition**: [AGPL-3.0](LICENSE) — free to use and modify, changes must be open-sourced
- **Enterprise Edition**: Commercial license available for closed-source deployments, SLA support, and compliance packages

---

*Built by Viraj Jain. Name from Sanskrit Pramāṇa (प्रमाण) — "valid source of knowledge" or "proof".*
