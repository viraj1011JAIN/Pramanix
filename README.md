<p align="center">
  <br />
  <strong style="font-size: 2em;">PRAMANIX</strong>
  <br />
  <em>Deterministic Neuro-Symbolic Guardrails for Autonomous AI Agents</em>
  <br /><br />
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.11%2B-blue?logo=python&logoColor=white" alt="Python 3.11+"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-green" alt="License: AGPL-3.0"></a>
  <a href="https://github.com/viraj1011JAIN/Pramanix/actions"><img src="https://img.shields.io/badge/build-passing-brightgreen?logo=githubactions&logoColor=white" alt="CI"></a>
  <a href="https://pypi.org/project/pramanix/"><img src="https://img.shields.io/badge/pypi-v0.1.0-orange?logo=pypi&logoColor=white" alt="PyPI"></a>
  <a href="https://pepy.tech/project/pramanix"><img src="https://img.shields.io/badge/downloads-0-lightgrey" alt="Downloads"></a>
  <br /><br />
</p>

> *Pramana (Sanskrit: "proof / valid knowledge") + Unix (composable systems philosophy)*

**Pramanix** is a production-grade Python SDK that places a **mathematically verified execution firewall** between AI agent intent and real-world consequences. Every action it approves carries a formal SMT proof. Every action it blocks carries a counterexample. No ambiguity. No exceptions.

```
AI Agent: "Transfer $5,000 to account X"
                    |
              [ PRAMANIX ]
                    |
        Z3 SMT Solver verifies ALL invariants:
          - balance - amount >= 0      ... SAT
          - account_not_frozen         ... SAT
          - amount <= daily_limit      ... SAT
          - risk_score <= 0.8          ... SAT
                    |
              ALLOW (with proof)
```

---

## Table of Contents

- [Why Pramanix](#why-pramanix)
- [Key Features](#key-features)
- [How It Works](#how-it-works)
- [Installation](#installation)
- [Quick Start](#quick-start)
  - [Structured Mode (Recommended)](#structured-mode-recommended)
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
- [Pramanix vs. Alternatives](#pramanix-vs-alternatives)
- [Configuration Reference](#configuration-reference)
- [Deployment](#deployment)
- [Performance](#performance)
- [Security Model](#security-model)
- [Roadmap](#roadmap)
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

**Pramanix replaces probabilistic judgment with formal satisfiability.** The Z3 SMT solver provides mathematically unambiguous answers — not confidence scores.

---

## Key Features

| Feature | Description |
|---|---|
| **Z3 SMT Verification** | Every decision is backed by a formal proof (SAT) or counterexample (UNSAT). Not a confidence score — a mathematical guarantee. |
| **Python-Native Policy DSL** | Write policies as Python expressions with full IDE autocomplete, type checking, and static analysis. No YAML, no Rego, no string-based DSL. |
| **Fail-Safe by Default** | Any error — LLM failure, timeout, type mismatch, config error — produces `BLOCK`, never `ALLOW`. |
| **Invariant Attribution** | Every blocked action identifies exactly which invariants were violated via Z3 unsat cores, with human-readable explanations. |
| **Dual Execution Modes** | **Structured Mode** for typed inputs. **Neuro-Symbolic Mode** for natural language with hardened LLM extraction. |
| **Async-First Architecture** | Three execution modes: `sync`, `async-thread`, `async-process` — optimized for FastAPI, Django, Celery, and scripts. |
| **Worker Lifecycle Management** | Automatic worker recycling to bound Z3 native memory, with warmup to eliminate cold-start latency spikes. |
| **Full Audit Trail** | Every `Decision` is immutable, serializable, and contains the complete proof or counterexample for regulatory compliance. |
| **Observability Built-In** | Prometheus metrics, OpenTelemetry traces, and structured JSON logging out of the box. |
| **Composable Primitives Library** | Pre-built, tested constraint primitives for finance, RBAC, infrastructure, and time-based policies. |

---

## How It Works

Pramanix operates on a **Two-Phase Execution Model**:

```
Phase 1: INTENT EXTRACTION                    Phase 2: FORMAL VERIFICATION
+---------------------------------+            +----------------------------------+
|                                 |            |                                  |
|  Structured     Neuro-Symbolic  |            |  Z3 SMT Solver                   |
|  (typed dict)   (NLP -> struct) |            |                                  |
|       |              |          |   ------>  |  For each invariant:             |
|       |         [Translator]    |            |    assert_and_track(formula)     |
|       |              |          |            |    solver.check()                |
|       +------+-------+         |            |                                  |
|              |                  |            |  SAT  -> ALLOW (with proof)      |
|        [Pydantic v2]            |            |  UNSAT -> BLOCK (with counter-   |
|        strict validation        |            |           example + attribution) |
|                                 |            |                                  |
|  LLM involvement: OPTIONAL     |            |  LLM involvement: ZERO           |
+---------------------------------+            +----------------------------------+
```

**The critical architectural invariant:** the LLM *never* decides safety policy. It only translates natural language to structured fields. All safety verification is performed by Z3 — deterministically, with mathematical guarantees.

---

## Installation

```bash
pip install pramanix
```

**Requirements:**
- Python 3.11+
- z3-solver (installed automatically)

**Optional dependencies:**

```bash
# For Neuro-Symbolic mode (LLM translation)
pip install pramanix[translator]

# For observability (Prometheus + OpenTelemetry)
pip install pramanix[observability]

# Everything
pip install pramanix[all]
```

> **Note:** Alpine Linux Docker images are **not supported** due to Z3 musl compatibility issues. Use `python:3.11-slim` or `python:3.11-bookworm`.

---

## Quick Start

### Structured Mode (Recommended)

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
class BankingPolicy(Policy):
    class Meta:
        name = "BankingPolicy"
        version = "1.0.0"

    balance    = Field("balance", Decimal, z3_type="Real")
    amount     = Field("amount", Decimal, z3_type="Real")
    is_frozen  = Field("is_frozen", bool, z3_type="Bool")
    daily_limit = Field("daily_limit_remaining", Decimal, z3_type="Real")
    risk_score = Field("risk_score", float, z3_type="Real")

    invariants = [
        (E(balance) - E(amount) >= 0)
            .named("non_negative_balance")
            .explain("Transfer blocked: amount {amount} exceeds balance {balance}."),

        (E(is_frozen) == False)
            .named("account_not_frozen")
            .explain("Transfer blocked: account is currently frozen."),

        (E(amount) <= E(daily_limit))
            .named("within_daily_limit")
            .explain("Transfer blocked: {amount} exceeds daily limit {daily_limit}."),

        (E(risk_score) <= 0.8)
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
        print("Transfer approved with proof:", decision.proof)
    else:
        print("Blocked:", decision.explanation)
        print("Violated:", decision.violated_invariants)
```

### Neuro-Symbolic Mode

When your input is natural language, Pramanix uses a hardened LLM translator to extract structured intent before verification.

```python
from pramanix import Guard, GuardConfig

guard = Guard(
    policy=BankingPolicy,
    config=GuardConfig(translator_enabled=True),
)

decision = await guard.verify(
    intent=TransferIntent,       # Pass the CLASS, not an instance
    state=account_state,
    translator_text="Transfer five thousand dollars to Alice's savings account",
)

# The LLM extracts structured fields -> Pydantic validates -> Z3 verifies
# LLM NEVER decides policy. It NEVER invents IDs.
```

### Decorator API

Gate function execution directly — the function body only runs if the policy passes.

```python
from pramanix import guard

@guard(policy=BankingPolicy, state_from="state")
async def execute_transfer(intent: TransferIntent, state: AccountState):
    # This body ONLY runs if all invariants pass
    # Otherwise, GuardViolationError is raised with full Decision attached
    await actually_execute_transfer(intent)
```

---

## Core Concepts

### Policy DSL

Policies are **pure Python** — no YAML, no Rego, no string-based DSL. Full IDE autocomplete and type checking.

```python
from pramanix import Policy, Field, E

class MyPolicy(Policy):
    class Meta:
        name = "MyPolicy"
        version = "1.0.0"

    # Declare fields with their Z3 types
    balance = Field("balance", Decimal, z3_type="Real")
    amount  = Field("amount", Decimal, z3_type="Real", source="intent")
    frozen  = Field("is_frozen", bool, z3_type="Bool")

    # Define invariants - each MUST be named
    invariants = [
        (E(balance) - E(amount) >= 0)
            .named("non_negative_balance")
            .explain("Insufficient balance: {amount} > {balance}"),

        (E(frozen) == False)
            .named("not_frozen")
            .explain("Account is frozen."),
    ]
```

**Expression operators:**

| Operation | Syntax | Compiles To |
|---|---|---|
| Arithmetic | `E(a) + E(b)`, `E(a) - E(b)`, `E(a) * E(b)`, `E(a) / E(b)` | Z3 `ArithRef` ops |
| Comparison | `>=`, `<=`, `>`, `<`, `==`, `!=` | Z3 `BoolRef` constraints |
| Boolean | `&` (AND), `\|` (OR), `~` (NOT) | `z3.And`, `z3.Or`, `z3.Not` |
| Membership | `E(role).is_in(["admin", "doctor"])` | `z3.Or(x == v1, x == v2, ...)` |
| Naming | `.named("invariant_name")` | Z3 `assert_and_track` label |
| Explanation | `.explain("template {field}")` | Human-readable violation message |

> **Important:** Use `&` / `|` operators, NOT Python `and` / `or` keywords. Python keywords evaluate immediately and cannot be overloaded.

### The Decision Object

Every `verify()` call returns an immutable `Decision`:

```json
{
  "allowed": false,
  "status": "UNSAFE",
  "violated_invariants": ["non_negative_balance", "within_daily_limit"],
  "explanation": "Transfer blocked: amount 5000 exceeds balance 100.",
  "proof": {
    "balance": "100.00",
    "amount": "5000.00",
    "is_frozen": false,
    "daily_limit_remaining": "10000.00",
    "risk_score": 0.3
  },
  "state_version": "2026-03-07T06:50:12.123Z",
  "metadata": {
    "decision_id": "550e8400-e29b-41d4-a716-446655440000",
    "policy_name": "BankingPolicy",
    "policy_version": "1.0.0",
    "solver_time_ms": 7,
    "total_time_ms": 12,
    "execution_mode": "async-thread",
    "timestamp_utc": "2026-03-07T06:50:12.135Z"
  }
}
```

**Status codes:**

| Status | Meaning | `allowed` |
|---|---|---|
| `SAFE` | All invariants satisfied (Z3 returned SAT) | `true` |
| `UNSAFE` | One or more invariants violated (Z3 returned UNSAT) | `false` |
| `TIMEOUT` | Z3 exceeded `solver_timeout_ms` | `false` |
| `UNKNOWN` | Z3 returned unknown (undecidable constraints) | `false` |
| `CONFIG_ERROR` | Missing fields, type errors, internal errors | `false` |

### Execution Modes

Choose based on your server architecture:

```
Is your server async (FastAPI, Starlette)?
|
+-- YES --> Heavy policies (>50 constraints)?
|           +-- YES --> execution_mode = "async-process"   (GIL-free)
|           +-- NO  --> execution_mode = "async-thread"    (DEFAULT)
|
+-- NO  --> execution_mode = "sync"   (Django, Flask, scripts)
```

---

## Domain Examples

### Banking — Transfer Verification

```python
decision = await guard.verify(
    intent=TransferIntent(action="transfer", amount=Decimal("5000"), ...),
    state=AccountState(balance=Decimal("100"), is_frozen=False, ...),
)

assert decision.allowed == False
assert "non_negative_balance" in decision.violated_invariants
# Explanation: "Transfer blocked: amount 5000 exceeds balance 100."
```

### Healthcare — PHI Access Control

```python
class PHIAccessPolicy(Policy):
    class Meta:
        name = "PHIAccessPolicy"
        version = "1.0.0"

    role       = Field("user_role", str, z3_type="Int")       # StringEnum projected
    consent    = Field("patient_consent", bool, z3_type="Bool")
    dept_match = Field("department_match", bool, z3_type="Bool")

    invariants = [
        E(role).is_in(["doctor", "nurse", "admin"])
            .named("authorized_role")
            .explain("PHI access blocked: role {user_role} is not authorized."),

        (E(consent) == True)
            .named("patient_consent_required")
            .explain("PHI access blocked: patient has not provided consent."),

        (E(dept_match) == True)
            .named("department_match_required")
            .explain("PHI access blocked: requester is not in patient department."),
    ]
```

### Cloud Infrastructure — Replica Scaling

```python
class ScalingPolicy(Policy):
    class Meta:
        name = "ScalingPolicy"
        version = "1.0.0"

    target  = Field("target_replicas", int, z3_type="Int", source="intent")
    minimum = Field("minimum_replicas", int, z3_type="Int")
    maximum = Field("maximum_replicas", int, z3_type="Int")
    is_prod = Field("is_production", bool, z3_type="Bool")

    invariants = [
        (E(target) >= E(minimum))
            .named("above_minimum")
            .explain("Scale blocked: {target_replicas} < minimum {minimum_replicas}."),

        (E(target) <= E(maximum))
            .named("below_maximum")
            .explain("Scale blocked: {target_replicas} > maximum {maximum_replicas}."),

        (~E(is_prod) | (E(target) >= 2))
            .named("production_ha_minimum")
            .explain("Scale blocked: production deployments require >= 2 replicas."),
    ]
```

---

## Architecture

```
                              +==============+
                              ||   CALLER   ||
                              || (FastAPI / ||
                              ||  Celery /  ||
                              ||  Script)   ||
                              +======+======+
                                     |  guard.verify(intent, state)
                                     v
                   +------------------------------------+
                   |            GUARD                   |
                   |  +----------+  +--------------+    |
                   |  |Translator|  |   Validator   |    |
                   |  |(optional)|  | (Pydantic v2) |    |
                   |  +-----+----+  +------+-------+    |
                   |        |              |             |
                   |  +-----v--------------v----------+  |
                   |  |      Resolver Registry         |  |
                   |  |   (runs on asyncio loop)       |  |
                   |  +---------------+----------------+  |
                   |                  |                   |
                   |  +---------------v----------------+  |
                   |  |   Executor (Thread / Process)   |  |
                   |  |  +-------------------------+    |  |
                   |  |  |       TRANSPILER         |    |  |
                   |  |  |    DSL -> Z3 AST         |    |  |
                   |  |  +-----------+-------------+    |  |
                   |  |              |                   |  |
                   |  |  +-----------v-------------+    |  |
                   |  |  |      Z3 SOLVER           |    |  |
                   |  |  |   assert_and_track       |    |  |
                   |  |  |   timeout enforced       |    |  |
                   |  |  |   unsat_core()           |    |  |
                   |  |  +-----------+-------------+    |  |
                   |  +---------------+----------------+  |
                   |                  |                   |
                   |  +---------------v----------------+  |
                   |  |       DECISION BUILDER          |  |
                   |  |   (immutable, serializable)     |  |
                   |  +---------------+----------------+  |
                   |                  |                   |
                   |  +---------------v----------------+  |
                   |  |         TELEMETRY               |  |
                   |  |   metrics + logs + spans        |  |
                   |  +--------------------------------+  |
                   +------------------------------------+
                                     |
                                     v
                              Decision (returned)
```

**Key modules:**

| Module | Responsibility |
|---|---|
| `guard.py` | SDK entrypoint — policy compilation, worker pool, `verify()` / `@guard` |
| `policy.py` | Policy base class, `Field` descriptor |
| `expressions.py` | `E()` DSL — expression tree via operator overloading |
| `transpiler.py` | DSL expression tree to Z3 AST (zero AST parsing) |
| `solver.py` | Z3 wrapper — contexts, timeouts, `assert_and_track`, unsat cores |
| `worker.py` | Worker spawn, warmup, recycling lifecycle |
| `decision.py` | Immutable `Decision` frozen dataclass |
| `validator.py` | Pydantic v2 strict validation layer |
| `resolvers.py` | Lazy field resolution with per-decision caching |
| `telemetry.py` | Prometheus, OpenTelemetry, structured JSON logs |
| `translator/` | Optional LLM integration (Ollama, OpenAI-compatible, dual-model agreement) |
| `primitives/` | Pre-built constraint libraries (finance, RBAC, infra, time) |

---

## Pramanix vs. Alternatives

| | **Pramanix** | **OPA / Rego** | **LLM-as-Judge** | **Regex / Rules** |
|---|---|---|---|---|
| **Verification** | Z3 SMT (mathematical proof) | Datalog evaluation | Probabilistic | Pattern matching |
| **Guarantees** | Formal: SAT / UNSAT | Policy evaluation | None | Syntactic only |
| **Compound constraints** | Native (arithmetic, boolean, membership) | Limited arithmetic | Unreliable | Manual, brittle |
| **Counterexamples** | Exact model values from Z3 | No | No | No |
| **Adversarial resistance** | Policy is compiled code — unreachable by injection | Rego is interpretable | Vulnerable | Bypassable |
| **Audit trail** | Every decision: proof + attribution | Evaluation log | Confidence score | Match / no-match |
| **Best for** | Mathematical safety of actions | Authorization (who can try) | Content filtering | Simple format checks |

> **Pramanix + OPA is the recommended production architecture.** OPA handles authorization ("can this user attempt a transfer?"). Pramanix handles mathematical safety ("is this specific transfer safe given current state?").

```python
# Gate 1: OPA — authorization
opa_result = await opa_client.check(policy="banking/transfer/allow", input={...})
if not opa_result.allowed:
    raise HTTPException(403, "Not authorized")

# Gate 2: Pramanix — mathematical safety
decision = await guard.verify(intent=intent, state=state)
if not decision.allowed:
    raise HTTPException(403, decision.explanation)

# Both gates passed — execute
await execute_transfer(intent)
```

---

## Configuration Reference

```python
from pramanix import GuardConfig

config = GuardConfig(
    # Execution
    execution_mode="async-thread",        # "sync" | "async-thread" | "async-process"
    solver_timeout_ms=50,                 # 10-10,000ms (default: 50)
    max_workers=4,                        # 1-64 (default: 4)

    # Worker Lifecycle
    max_decisions_per_worker=10_000,      # Recycle to flush Z3 native memory
    worker_warmup=True,                   # Dummy solve on spawn (eliminates cold-start)

    # Observability
    log_level="INFO",
    metrics_enabled=True,
    otel_enabled=False,
    otel_endpoint=None,

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
```

---

## Deployment

### Docker

```dockerfile
FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    libz3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml poetry.lock ./
RUN pip install poetry && poetry install --no-dev --no-interaction --no-ansi
COPY . .

RUN useradd -m -u 1001 pramanix && chown -R pramanix:pramanix /app
USER pramanix

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
```

> **Alpine Linux is NOT supported.** Z3's C++ runtime requires glibc. Alpine uses musl, which causes segfaults and build failures. Use `python:3.11-slim` (Debian-based).

### FastAPI Integration

```python
from fastapi import FastAPI, HTTPException
from pramanix import Guard, GuardConfig

app = FastAPI()
guard = Guard(policy=BankingPolicy, config=GuardConfig())

@app.post("/transfer")
async def transfer(req: TransferRequest):
    intent = TransferIntent(**req.intent)
    state = AccountState(**await fetch_account_state(req.account_id))

    decision = await guard.verify(intent=intent, state=state)

    if not decision.allowed:
        raise HTTPException(status_code=403, detail=decision.explanation)

    # Race condition guard: verify state freshness before commit
    if not await is_state_version_current(state.state_version):
        raise HTTPException(status_code=409, detail="State changed. Retry.")

    await execute_transfer(intent)
    return {"status": "ok", "decision_id": decision.metadata["decision_id"]}

@app.on_event("shutdown")
async def shutdown():
    await guard.shutdown()
```

---

## Performance

| Metric | Target | Notes |
|---|---|---|
| **P50 latency** | < 5ms | Simple policies (2-5 invariants) |
| **P95 latency** | < 15ms | Includes serialization overhead |
| **P99 latency** | < 30ms | With worker warmup enabled |
| **Throughput** | > 100 RPS sustained | Per Guard instance, async-thread mode |
| **Memory (1M decisions)** | RSS growth < 50MB | With worker recycling at 10K decisions |

**Solver timeout calibration:**

| Policy Complexity | Recommended Timeout |
|---|---|
| Simple (2-5 invariants, Real + Bool) | 10-20ms |
| Medium (5-15 invariants, mixed types) | 20-50ms (default) |
| Complex (15+ invariants, BitVec, quantifiers) | 100-500ms |

---

## Security Model

### Threat Mitigations

| Threat | Mitigation |
|---|---|
| **Prompt injection** | Policy is compiled Python DSL — injection cannot reach it. LLM is optional and firewalled. |
| **LLM hallucination** | LLM never invents IDs or decides policy. All LLM output passes strict Pydantic validation. |
| **Numeric logic errors** | Z3 `RealSort` arithmetic is exact. Decimals use `as_integer_ratio()` — no float approximation. |
| **Race conditions** | `state_version` binding. Host must verify freshness before committing approved actions. |
| **Opaque decisions** | Full unsat core with model values in every BLOCK. Complete audit trail for regulators. |

### Fail-Safe Guarantee

```
decision(action, state) = ALLOW   IFF   Z3.check(policy ^ state) = SAT
decision(action, state) = BLOCK   in ALL other cases

"All other cases" includes: UNSAT, TIMEOUT, UNKNOWN, EXCEPTION,
TYPE_ERROR, NETWORK_FAILURE, CONFIG_ERROR, SERIALIZATION_ERROR
```

No action is approved by elimination. Every approval requires **positive proof**.

---

## Roadmap

| Milestone | Description | Status |
|---|---|---|
| **M0** | Transpiler Spike — minimal `E()`, `Field`, Z3 integration proof | Planned |
| **M1** | Core SDK — Policy, Guard, Decision, sync mode | Planned |
| **M2** | Async modes, worker lifecycle, recycling, warmup | Planned |
| **M3** | Translator subsystem, primitives library | Planned |
| **M4** | Observability (Prometheus, OTel, structured logs) | Planned |
| **M5** | CI/CD, packaging, Docker, deployment guides | Planned |
| **v1.0 GA** | Production release | Planned |

---

## Contributing

Pramanix is in active development. Contributions are welcome.

```bash
# Clone and setup
git clone https://github.com/viraj1011JAIN/Pramanix.git
cd Pramanix

# Install dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/

# Run benchmarks
python -m benchmarks
```

**Development rules:**
- All policies must have compile-time validation — no runtime surprises
- Every error path must produce `Decision(allowed=False)` — never propagate exceptions
- Use `assert_and_track` (not `add`) for all invariants — unsat core attribution is mandatory
- Never pickle Pydantic models — always `model_dump()` before crossing process boundaries
- Alpine Docker images are banned — Z3 requires glibc

---

## License

Pramanix is licensed under **AGPL-3.0** for open-source use. A commercial license is available for proprietary deployments.

See [LICENSE](LICENSE) for details.

---

<p align="center">
  <strong>Pramanix</strong> — Because in high-stakes AI, <em>probabilistic safety is not safety. It is a liability.</em>
  <br /><br />
  Built by <a href="https://github.com/viraj1011JAIN">Viraj Jain</a>
</p>
