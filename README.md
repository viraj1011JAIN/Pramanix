# Pramanix

![PyPI](https://img.shields.io/badge/PyPI-not%20yet%20published-lightgrey)
![Python Version](https://img.shields.io/badge/python-3.13-blue)
![License AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-green)
![Version 0.9.0-beta](https://img.shields.io/badge/Version-0.9.0--beta-blue)
![Tests 1924 passed](https://img.shields.io/badge/Tests-1924%20passed-brightgreen)
![Coverage 97%](https://img.shields.io/badge/Coverage-97%25-brightgreen)
![SLSA Level 3 Ready](https://img.shields.io/badge/SLSA-Level%203%20Ready-blueviolet)

Safety guardrails for autonomous AI agents, backed by formal constraint verification.

Pramanix sits between an AI agent and the real world. Before any action executes — a bank transfer, a Kubernetes deployment, a database write — Pramanix checks whether that action is mathematically allowed by a policy you define. Every ALLOW comes with a proof. Every BLOCK comes with a counterexample showing exactly which constraint was violated.

The name comes from Sanskrit: *Pramana* (प्रमाण) means "valid source of knowledge" or "proof."

> **Status:** v0.9.0 beta. Not yet published to PyPI — install from source. The public API is stabilised and covered by an API contract test suite, but breaking changes may still occur before v1.0.

---

## The Problem This Solves

Most AI guardrail systems are probabilistic classifiers. They output a confidence score and compare it to a threshold. At scale, this creates a predictable failure rate:

- A 99.9% accurate classifier allows 1 in every 1,000 requests through incorrectly
- At 100 requests per second, that is 8,640 incorrect decisions per day
- An attacker can probe the threshold until they find inputs that score above it
- The failure rate is a mathematical property of the system, not an edge case

Pramanix does not use confidence scores. It evaluates whether specific values satisfy specific constraints:

- `balance - amount >= 0` either holds or it does not
- Z3 returns SAT (values satisfy all constraints) or UNSAT (they do not)
- The same inputs always produce the same result
- There is no threshold to probe, no probability involved, and no model to jailbreak

This approach trades the flexibility of a probabilistic classifier for the determinism of arithmetic. It is the right trade when the rule is clear and the consequences of failure are real.

The tradeoff: your policy must be expressible as arithmetic or boolean constraints over a typed dict. Fuzzy rules ("is this request suspicious?") do not fit this model.

---

## Install

```bash
# Not on PyPI. Install from source:
git clone https://github.com/viraj1011JAIN/Pramanix.git
cd Pramanix
pip install -e .

# With optional extras:
pip install -e '.[fastapi]'      # FastAPI/Starlette middleware and route decorator
pip install -e '.[langchain]'    # LangChain tool wrapping
pip install -e '.[llamaindex]'   # LlamaIndex query engine guard
pip install -e '.[autogen]'      # AutoGen agent wrapping
pip install -e '.[translator]'   # LLM intent extraction (Ollama, OpenAI, Anthropic)
pip install -e '.[audit]'        # Ed25519 signing and Merkle audit chain
pip install -e '.[crypto]'       # cryptography package (required by audit)
pip install -e '.[identity]'     # JWT + Redis zero-trust identity
pip install -e '.[otel]'         # OpenTelemetry tracing
pip install -e '.[all]'          # All of the above

# Requirements:
# Python 3.13+
# Alpine Linux is not supported — z3-solver is compiled against glibc.
# musl (Alpine) causes segfaults and 3-10x performance degradation.
# Use python:3.13-slim or ubuntu.
```

---

## Quick Start

```python
from decimal import Decimal
from pramanix import Guard, GuardConfig, Policy, Field, E

class BankingPolicy(Policy):
    class Meta:
        version = "1.0"

    amount          = Field("amount",          Decimal, "Real")
    balance         = Field("balance",         Decimal, "Real")
    daily_limit     = Field("daily_limit",     Decimal, "Real")
    minimum_reserve = Field("minimum_reserve", Decimal, "Real")
    is_frozen       = Field("is_frozen",       bool,    "Bool")

    @classmethod
    def invariants(cls):
        return [
            (E(cls.balance) - E(cls.amount) >= E(cls.minimum_reserve))
            .named("sufficient_funds")
            .explain("Insufficient balance: post-transfer balance would be "
                     "{balance} - {amount} = {post_balance}, minimum is {minimum_reserve}"),

            (E(cls.amount) <= E(cls.daily_limit))
            .named("daily_limit_check")
            .explain("Amount {amount} exceeds daily limit {daily_limit}"),

            (E(cls.is_frozen) == False)
            .named("account_not_frozen")
            .explain("Account is frozen. Contact support to unfreeze."),
        ]

guard = Guard(BankingPolicy, GuardConfig())

# ALLOW — all three constraints satisfied
decision = guard.verify(
    intent={"amount": Decimal("500")},
    state={
        "balance":         Decimal("1000"),
        "daily_limit":     Decimal("2000"),
        "minimum_reserve": Decimal("0.01"),
        "is_frozen":       False,
    }
)

print(decision.allowed)              # True
print(decision.status.value)         # "safe"

# BLOCK — overdraft attempt
decision = guard.verify(
    intent={"amount": Decimal("1500")},
    state={
        "balance":         Decimal("1000"),
        "daily_limit":     Decimal("2000"),
        "minimum_reserve": Decimal("0.01"),
        "is_frozen":       False,
    }
)

print(decision.allowed)              # False
print(decision.violated_invariants)  # ("sufficient_funds",)
print(decision.explanation)          # "Insufficient balance: post-transfer balance would be
                                     #  1000 - 1500 = -500, minimum is 0.01"
```

---

## Known Limitations

These are real constraints of the current design, not caveats added for legal cover. Each one has a concrete mitigation.

### TOCTOU (Time-of-Check vs Time-of-Use)

Pramanix verifies state at the moment `verify()` is called. In concurrent systems, two requests can both pass verification and then both execute against the same shared resource before either write completes.

*Mitigation:* Bind the state version to the `ExecutionToken` at verify time. If state changes before execution, `consume()` detects the mismatch and returns `False`:

```python
# At verify time — capture state version (ETag, DB row version, Redis version, etc.)
token = signer.mint(decision, state_version=account_row.etag)

# At execute time — re-fetch state and pass current version
if verifier.consume(token, expected_state_version=current_etag):
    execute_transfer()
# Returns False if the account was modified between verify() and execute()
```

The `state_version` is embedded in the HMAC body — stripping or modifying it invalidates the token. Use `RedisExecutionTokenVerifier` for enforcement across processes or servers.

### Z3 encoding scope
Z3 verifies that the submitted values satisfy your declared constraints. It does not verify that state was accurately fetched from your database, that the intent matches what the executor will actually do, or that your invariants fully capture your safety requirements.

*Mitigation:* Run `PolicyAuditor.audit()` at startup to catch fields declared on the policy but never referenced in any invariant — those fields silently accept any value:

```python
from pramanix import PolicyAuditor

PolicyAuditor.audit(BankingPolicy)
# UserWarning: 'BankingPolicy' declares fields not referenced in any invariant: ['currency_code'].
# These fields will never constrain a decision.

# Strict mode for CI:
PolicyAuditor.audit(BankingPolicy, raise_on_uncovered=True)

# Inspect only:
uncovered = PolicyAuditor.uncovered_fields(BankingPolicy)  # → ['currency_code']
```

Structural coverage catches unused fields. Correctness of the invariants themselves still requires domain-expert review before production deployment in regulated environments.

### Z3 native process crashes
Python's `except Exception` cannot catch a Z3 C++ segfault (SIGABRT/SIGSEGV). In `async-process` mode, a worker crash surfaces as a fail-safe BLOCK without killing the host process.

*Mitigation:* Use `execution_mode="async-process"` in production. Setting `PRAMANIX_ENV=production` with a non-process mode emits a `UserWarning` at construction time:

```python
# Triggers UserWarning when PRAMANIX_ENV=production:
GuardConfig(execution_mode="sync")          # not recommended for production
GuardConfig(execution_mode="async-thread")  # not recommended for production

# Recommended for production:
GuardConfig(execution_mode="async-process") # worker crash → fail-safe BLOCK
```

### Z3 string theory performance
Z3's `String` sort uses sequence theory, which is decidable but slower than linear-integer arithmetic.

*Mitigation:* Use `StringEnumField` to map fixed string enumerations to `Int`-backed fields. Authoring is identical; Z3 solves with linear-integer arithmetic instead of sequence theory:

```python
from pramanix import StringEnumField

_status = StringEnumField("status", ["CLEAR", "PENDING", "BLOCKED"])

class AccountPolicy(Policy):
    status = _status.field   # Int field — no sequence theory

    @classmethod
    def invariants(cls):
        return [
            _status.valid_values_constraint(cls.status),
            _status.is_allowed_constraint(cls.status, ["CLEAR"]),
        ]

# Encode at call time, decode for logging:
guard.verify(intent={"status": _status.encode("CLEAR")}, state=...)
_status.decode(0)  # → "CLEAR"
```

Benchmark on development hardware (Windows 11, Python 3.13, z3-solver 4.16.0): 5-invariant policy with one string field — ~12 ms P50 with `"String"` sort, ~5 ms P50 with `StringEnumField`.

### Merkle anchor persistence
`MerkleAnchor` is process-scoped and lost on restart.

*Fully mitigated:* Use `PersistentMerkleAnchor` with a checkpoint callback:

```python
anchor = PersistentMerkleAnchor(
    checkpoint_every=500,
    checkpoint_callback=lambda root, count: db.save_checkpoint(root, count),
)
# Call anchor.flush() on shutdown to persist any trailing decisions.
```

Individual Ed25519-signed decision records remain independently verifiable regardless of anchor state.

### Injection confidence threshold
*Configurable:* `GuardConfig(injection_threshold=0.5)` or `PRAMANIX_INJECTION_THRESHOLD` env var. Raise for high-security deployments (e.g. `0.3`); lower for domains with legitimately high-entropy inputs (e.g. crypto addresses, `0.7`). Phase 2 (Z3) is the binding safety guarantee regardless of Phase 1 outcome.

### LLM model minimum size
`llama3.2:1b` (1B parameters) cannot reliably perform structured intent extraction — it tends to echo the schema rather than fill it in. Use `llama3.2` (3B, Q4_K_M) or larger. `temperature=0.0` is set by default for deterministic extraction.

---

## How It Works

Pramanix runs in two phases:

### Phase 1 (Optional): Intent Extraction

- Accepts free-form text from the AI agent
- Two independent LLMs extract structured fields in parallel
- Both must agree on every field value (consensus check)
- Six-layer injection defense: NFKC normalization, parallel extraction, partial-failure gate, Pydantic strict validation, consensus check, injection confidence score
- If the models disagree or the injection score exceeds the threshold, the request is blocked before reaching Phase 2

### Phase 2 (Always runs): Z3 Formal Verification

- Receives a typed dict of field values (from Phase 1 or passed directly)
- Checks those values against every constraint in your policy
- Returns ALLOW with proof if all constraints are satisfied, or BLOCK with the violated constraints and their counterexamples
- This phase cannot be bypassed by anything in the input, because the policy is compiled to Z3 AST once at startup before any request arrives

---

## Architecture

```text
AI Agent
    │
    │  intent (structured dict OR free-form text)
    ▼
┌───────────────────────────────────────────────────────────────┐
│  Phase 1: Intent Extraction (optional)                        │
│                                                               │
│  Raw text ──► NFKC normalize ──► LLM-A  ──► Pydantic         │
│                                  LLM-B  ──► Pydantic         │
│                                    │                          │
│                              Consensus check                  │
│                              Injection score                  │
│                                    │                          │
│                   FAIL ◄──────────┤──────────► PASS          │
│               BLOCK (consensus     │            │             │
│                 / injection)       ▼            ▼             │
└──────────────────────────  typed intent dict ───┤─────────────┘
                                                  │
┌─────────────────────────────────────────────────▼─────────────┐
│  Phase 2: Z3 Formal Verification (always runs)                │
│                                                               │
│  policy.invariants() ──► Transpiler ──► Z3 AST               │
│  (compiled once at Guard.__init__)                            │
│                                                               │
│  intent dict + state ──► Solver (per-call Z3 Context)        │
│                                │                              │
│                    SAT?        │        UNSAT?                │
│                    ▼           │           ▼                  │
│              ALLOW + proof     │     BLOCK + counterexample   │
│                                │     + violated invariants    │
└────────────────────────────────│───────────────────────────────┘
                                 │
                          Decision object
                         (immutable, signed)
```

### Key design properties

- Phase 2 always runs regardless of Phase 1 outcome
- Policy compilation happens once at startup, not per-request
- Each Z3 solve uses an isolated `z3.Context()`, deleted after the call — no state bleeds between decisions
- Fail-safe: any exception in any code path returns `Decision(allowed=False)`
- `allowed=True` is unreachable from any error path

---

## Policy DSL

### Fields

```python
from decimal import Decimal
from pramanix import Field

# Field(name, python_type, z3_sort)
# Z3 sorts: "Real" (exact rational), "Int", "Bool", "String" (Z3 sequence theory)

amount    = Field("amount",    Decimal, "Real")   # Decimal → exact Z3 rational via as_integer_ratio()
balance   = Field("balance",   Decimal, "Real")   # No IEEE 754 floating-point ever reaches Z3
role      = Field("role",      int,     "Int")
active    = Field("active",    bool,    "Bool")
status    = Field("status",    str,     "String")  # Prefer StringEnumField for enumerations
```

### Expressions

```python
from pramanix import E

# Arithmetic (Real and Int sorts)
E(cls.balance) - E(cls.amount) >= Decimal("0")
E(cls.amount) * E(cls.quantity) <= E(cls.budget)
E(cls.price) / E(cls.quantity) > Decimal("0.01")

# Comparison
E(cls.risk_score) < Decimal("0.85")
E(cls.role) == 2
E(cls.amount) != Decimal("0")

# Boolean
E(cls.is_active) == True
~E(cls.is_frozen)

# Logical composition
(E(cls.amount) > 0) & (E(cls.amount) <= E(cls.limit))
(E(cls.role) == 1) | (E(cls.role) == 2)

# Membership (preferred for enumerations)
E(cls.status).is_in(["CLEAR", "VERIFIED"])
E(cls.role).is_in([1, 2, 3])
```

### Invariant Modifiers

```python
(E(cls.balance) - E(cls.amount) >= 0)
    .named("sufficient_funds")              # label in violated_invariants on BLOCK
    .explain("Balance {balance} insufficient for amount {amount}")  # template in decision
```

### Decision Object

```python
decision.allowed               # bool — True (ALLOW) or False (BLOCK)
decision.status                # SolverStatus enum
decision.violated_invariants   # tuple[str, ...] — named constraint labels (BLOCK path only)
decision.explanation           # str — human-readable reason, templates filled in
decision.decision_id           # UUID4 — unique per decision
decision.policy_hash           # SHA-256 of the compiled policy
decision.solver_time_ms        # float — Z3 solve time in milliseconds
decision.signature             # str | None — Ed25519 signature (if signer configured)
decision.decision_hash         # str — SHA-256 of canonical decision JSON

# Factory methods
Decision.safe(...)             # allowed=True, status=SAFE
Decision.unsafe(...)           # allowed=False, status=UNSAFE
Decision.timeout(...)          # Z3 exceeded solver_timeout_ms or solver_rlimit
Decision.rate_limited(...)     # Load shedder rejected the request
Decision.consensus_failure()   # Phase 1 dual-model disagreement
```

### SolverStatus Values

| Status | `allowed` | Meaning |
| -------- | ----------- | --------- |
| `SAFE` | `True` | All invariants satisfied. Z3 returned SAT. |
| `UNSAFE` | `False` | One or more invariants violated. Z3 returned UNSAT. |
| `TIMEOUT` | `False` | Z3 hit `solver_timeout_ms` or `solver_rlimit`. Request blocked. |
| `VALIDATION_FAILURE` | `False` | Input failed Pydantic validation before reaching Z3. |
| `RATE_LIMITED` | `False` | Load shedder rejected the request. |
| `CONSENSUS_FAILURE` | `False` | Phase 1: dual-model LLM disagreement on extracted values. |
| `ERROR` | `False` | Unexpected internal exception. Fail-safe path. |

### @guard Decorator

```python
from pramanix.decorator import guard

@guard(
    policy=BankingPolicy,
    config=GuardConfig(execution_mode="sync"),
    state_loader=lambda intent: fetch_account_state(intent["account_id"]),
)
def execute_transfer(intent: dict) -> dict:
    # Only runs if Guard.verify() returned ALLOW
    return transfer_service.execute(intent)

# Raises GuardViolationError on BLOCK
result = execute_transfer({"amount": Decimal("100"), "account_id": "acc-123"})
```

---

## Guard Configuration

```python
from pramanix import Guard, GuardConfig
from pramanix.crypto import PramanixSigner

guard = Guard(
    BankingPolicy,
    GuardConfig(
        # Execution model
        execution_mode           = "async-process",  # "sync" | "async-thread" | "async-process"
        max_workers              = 8,
        max_decisions_per_worker = 10_000,           # workers recycle after this many decisions

        # Z3 solver limits
        solver_timeout_ms        = 100,              # hard timeout per solve call (ms)
        solver_rlimit            = 10_000_000,       # Z3 elementary operation cap

        # Input hardening
        max_input_bytes          = 65_536,           # reject payloads over 64 KiB before Z3
        min_response_ms          = 50.0,             # pad BLOCK responses — prevents timing analysis
        redact_violations        = False,            # True for external-facing APIs

        # Policy drift detection
        expected_policy_hash     = fingerprint,      # raises ConfigurationError on mismatch

        # Cryptographic audit signing
        signer                   = PramanixSigner.from_pem(key_pem),

        # Load shedding
        shed_worker_pct          = 90.0,             # shed when worker pool utilisation > 90%
        shed_latency_threshold_ms= 200.0,            # shed when rolling P99 > 200 ms

        # Phase 1 injection defense
        injection_threshold      = 0.5,              # env: PRAMANIX_INJECTION_THRESHOLD

        # Observability
        metrics_enabled          = True,             # Prometheus counters and histograms
        otel_enabled             = True,             # OpenTelemetry spans
        log_level                = "INFO",

        # Phase 1 (optional)
        translator_enabled       = False,
    ),
)
```

### Configuration notes

- `solver_timeout_ms` defaults to 5,000 ms. In production this is too high — a stalled Z3 call cascades through the load shedder and trips the circuit breaker. 100–150 ms is a practical target for a P99 < 20 ms.
- `solver_rlimit` caps Z3 elementary operations regardless of wall time. Use both `solver_timeout_ms` and `solver_rlimit` together — one covers adversarial non-linear inputs, the other covers slow hardware.
- `min_response_ms` pads BLOCK responses to a minimum wall-clock time. Prevents an attacker from using response timing to determine whether a block was caused by fast-path evaluation or by Z3.
- `expected_policy_hash` pins the compiled policy fingerprint. If the policy changes after deployment, `Guard.__init__` raises `ConfigurationError` before the first request.
- `redact_violations` strips `violated_invariants` and `explanation` from BLOCK decisions returned to callers. The full fields are still in the signed `decision_hash` for server-side audit.
- All fields are overridable via `PRAMANIX_<FIELD_NAME_UPPER>` environment variables.

GuardConfig has 20 fields total. All have defaults; `GuardConfig()` with no arguments is valid.

---

## Execution Modes

### sync

Z3 runs in the calling thread. No worker pool. Suitable for scripts, tests, and single-threaded WSGI. A slow Z3 call blocks the entire thread. A Z3 C++ fault crashes the process.

### async-thread

Z3 runs in a `ThreadPoolExecutor`. The event loop is never blocked. Safe for concurrent async applications. Workers share memory — a Z3 C++ fault kills the entire process.

### async-process (recommended for production)

Z3 runs in isolated subprocess workers (`ProcessPoolExecutor`). Worker death surfaces as a fail-safe BLOCK without affecting the host process. Every result is HMAC-sealed before crossing the IPC boundary; the host verifies the seal before accepting any decision.

Worker lifecycle:

```text
spawn (not fork) → warmup (8-pattern Z3 solve) → serve decisions
                                                       │
                                       max_decisions_per_worker reached
                                                       │
                                           drain with grace period
                                                       │
                                           force-kill remaining processes
                                                       │
                                           spawn fresh worker
```

Workers are spawned, never forked — avoids inheriting parent process file descriptors and state. The warmup solve eliminates Z3 cold-start JIT latency before the first real request.

---

## Neuro-Symbolic Mode (Phase 1 + Phase 2)

Use `parse_and_verify()` when the AI agent provides free-form text instead of a structured dict.

```python
# Dual-model consensus (recommended)
decision = await guard.parse_and_verify(
    prompt="transfer 500 dollars to alice",
    intent_schema=TransferIntent,          # Pydantic model defining expected fields
    state=account_state,
    models=("gpt-4o", "claude-opus-4-6"),  # both must agree on every field value
)
```

### Phase 1 Injection Defense Pipeline

```text
Untrusted text
      │
      ▼
1. NFKC normalization       — collapses Unicode homoglyphs (Cyrillic "а" = Latin "a")
      │
      ▼
2. Parallel LLM extraction  — both models extract independently, no cross-contamination
      │
      ▼
3. Partial-failure gate     — if either model errors, result = CONSENSUS_FAILURE
      │
      ▼
4. Pydantic strict validate — extra fields rejected, types enforced, ranges checked
      │
      ▼
5. Consensus check          — field-by-field value agreement required across both models
      │
      ▼
6. Injection confidence     — signal-weighted additive score in [0, 1]
                               score >= threshold → InjectionBlockedError (BLOCK)
      │
      ▼
Phase 2 (Z3) — always runs
```

- If an attacker manipulates one LLM to extract `amount=999999999`, the other model extracts a different value. Consensus check fails. BLOCK.
- If both models are manipulated to agree on `amount=999999999`, Phase 2 still runs. Z3 checks `balance - 999999999 >= minimum_reserve`. UNSAT. BLOCK.

### Supported Translators

| Translator | Backend |
| ----------- | --------- |
| `OllamaTranslator` | Local Ollama server (tested: llama3.2 3B, temperature=0.0) |
| `OpenAICompatTranslator` | OpenAI API or any OpenAI-compatible endpoint |
| `AnthropicTranslator` | Anthropic Messages API |
| `RedundantTranslator` | Wraps any two translators for dual-model consensus |

```python
from pramanix.translator.ollama import OllamaTranslator
from pramanix.translator.anthropic import AnthropicTranslator
from pramanix.translator.redundant import RedundantTranslator

local = OllamaTranslator("llama3.2", base_url="http://localhost:11434")
cloud = AnthropicTranslator("claude-opus-4-6")

translator = RedundantTranslator(local, cloud)
```

### Intent Cache

```python
GuardConfig(
    translator_enabled=True,
    # PRAMANIX_INTENT_CACHE_REDIS_URL=redis://localhost:6379
    # PRAMANIX_INTENT_CACHE_TTL_SECONDS=3600
    # PRAMANIX_INTENT_CACHE_MAX_SIZE=1024
)
```

Repeated identical prompts hit the in-process LRU cache or Redis cache, bypassing LLM inference. Cache failures degrade gracefully — a miss always falls through to full extraction and Z3. The cache is best-effort and never blocks verification.

---

## Primitives Library

Pre-built constraint factories. Import directly into `invariants()`. All 38 primitives emit named labels that appear in `violated_invariants` on BLOCK.

### Finance (`pramanix.primitives.finance`)

| Primitive | Constraint |
| ----------- | ----------- |
| `NonNegativeBalance(balance, amount)` | `balance - amount >= 0` |
| `MinimumReserve(balance, amount, reserve)` | `balance - amount >= reserve` |
| `UnderDailyLimit(amount, daily_limit)` | `amount <= daily_limit` |
| `UnderSingleTxLimit(amount, single_tx_limit)` | `amount <= single_tx_limit` |
| `RiskScoreBelow(risk_score, threshold)` | `risk_score < threshold` |
| `SecureBalance(balance)` | `balance >= 0` |

### FinTech / AML (`pramanix.primitives.fintech`)

| Primitive | Constraint | Regulatory note |
| ----------- | ----------- | ----------------- |
| `SufficientBalance(balance, amount)` | `balance >= amount` | |
| `AntiStructuring(cumulative, threshold)` | `cumulative < threshold` | 31 CFR § 1020.320 CTR filing |
| `VelocityCheck(tx_count_24h, max_velocity)` | `tx_count_24h <= max_velocity` | PSD2 velocity cap |
| `KYCTierCheck(kyc_tier, required_tier)` | `kyc_tier >= required_tier` | FinCEN CDD rule |
| `SanctionsScreen(counterparty_status)` | `status not in ["SANCTIONED", "BLOCKED"]` | OFAC SDN |
| `MarginRequirement(collateral, requirement)` | `collateral >= requirement` | |
| `CollateralHaircut(collateral, haircut, exposure)` | `collateral * (1 - haircut) >= exposure` | |
| `MaxDrawdown(drawdown, max_pct)` | `drawdown <= max_pct` | |
| `WashSaleDetection(time_since_last_sale, window)` | `time_since_last_sale >= window` | |
| `TradingWindowCheck(timestamp, open, close)` | `open <= timestamp <= close` | |

### RBAC (`pramanix.primitives.rbac`)

| Primitive | Constraint |
| ----------- | ----------- |
| `RoleMustBeIn(role, allowed_roles)` | `role in allowed_roles` |
| `DepartmentMustBeIn(dept, allowed_depts)` | `dept in allowed_depts` |
| `ConsentRequired(consent_given)` | `consent_given == True` |

### Infrastructure (`pramanix.primitives.infra`)

| Primitive | Constraint |
| ----------- | ----------- |
| `MinReplicas(replicas, min_replicas)` | `replicas >= min_replicas` |
| `MaxReplicas(replicas, max_replicas)` | `replicas <= max_replicas` |
| `ReplicaBudget(replicas, min, max)` | `min <= replicas <= max` |
| `WithinCPUBudget(cpu_request, cpu_limit)` | `cpu_request <= cpu_limit` |
| `WithinMemoryBudget(mem_request, mem_limit)` | `mem_request <= mem_limit` |
| `CPUMemoryGuard(cpu_req, cpu_lim, mem_req, mem_lim)` | Combined CPU + memory |
| `ProdDeployApproval(approval_count, required)` | `approval_count >= required` |
| `CircuitBreakerState(circuit_state)` | `circuit_state != "open"` |
| `BlastRadiusCheck(affected, max_blast)` | `affected <= max_blast` |

### Healthcare (`pramanix.primitives.healthcare`)

| Primitive | Constraint | Regulatory note |
| ----------- | ----------- | ----------------- |
| `PHILeastPrivilege(role, allowed_roles)` | `role in allowed_roles` | HIPAA 45 CFR § 164.502(b) |
| `ConsentActive(status, expiry, current_epoch)` | `status == "ACTIVE" and now < expiry` | HIPAA § 164.508(b)(5) |
| `BreakGlassAuth(flag, auth_code_present)` | `not flag or auth_code_present` | HIPAA § 164.312(a)(2)(ii) |
| `PediatricDoseBound(dose, max_per_kg, weight)` | `dose <= max_per_kg * weight` | |
| `DosageGradientCheck(dose, previous, max_step)` | `abs(dose - previous) <= max_step` | |

### Time (`pramanix.primitives.time`)

| Primitive | Constraint |
| ----------- | ----------- |
| `Before(timestamp, deadline)` | `timestamp < deadline` |
| `After(timestamp, start)` | `timestamp > start` |
| `WithinTimeWindow(timestamp, start, end)` | `start <= timestamp <= end` |
| `NotExpired(now, expiry)` | `now < expiry` |

### Common (`pramanix.primitives.common`)

| Primitive | Constraint |
| ----------- | ----------- |
| `NonNegative(field)` | `field >= 0` |
| `Positive(field)` | `field > 0` |
| `InRange(field, low, high)` | `low <= field <= high` |

### Composition example

```python
from pramanix.primitives.finance import NonNegativeBalance, UnderDailyLimit
from pramanix.primitives.rbac import RoleMustBeIn
from pramanix.primitives.time import NotExpired

class TradingPolicy(Policy):
    class Meta:
        version = "2.1"

    amount       = Field("amount",       Decimal, "Real")
    balance      = Field("balance",      Decimal, "Real")
    daily_limit  = Field("daily_limit",  Decimal, "Real")
    role         = Field("role",         str,     "String")
    token_expiry = Field("token_expiry", int,     "Int")
    now          = Field("now",          int,     "Int")

    @classmethod
    def invariants(cls):
        return [
            NonNegativeBalance(cls.balance, cls.amount),
            UnderDailyLimit(cls.amount, cls.daily_limit),
            RoleMustBeIn(cls.role, ["trader", "desk_head"]),
            NotExpired(cls.now, cls.token_expiry),
        ]
```

---

## Integration Adapters

### FastAPI / Starlette

```python
from fastapi import FastAPI
from pramanix.integrations.fastapi import PramanixMiddleware, pramanix_route

app = FastAPI()

# Option 1: middleware — applies to all routes under the registered path
app.add_middleware(
    PramanixMiddleware,
    policy=BankingPolicy,
    intent_model=TransferIntent,
    state_loader=load_account_state,
    config=GuardConfig(execution_mode="async-thread"),
    max_body_bytes=65_536,
    timing_budget_ms=50.0,
)

# Option 2: per-route decorator
@app.post("/transfer")
@pramanix_route(
    policy=BankingPolicy,
    intent_model=TransferIntent,
    state_loader=lambda req: fetch_account(req.headers["X-Account-Id"]),
)
async def transfer_handler(request: Request):
    return {"status": "ok"}
```

Request pipeline:

1. Check `Content-Type: application/json` (415 if absent)
2. Read body, reject if over `max_body_bytes` (413)
3. Parse JSON, validate via `intent_model` (422 if invalid)
4. Load state via `state_loader`
5. Run `Guard.verify_async(intent, state)`
6. BLOCK: pad to `timing_budget_ms`, return 403 with decision JSON
7. ALLOW: forward to next ASGI handler

### LangChain

```python
from pramanix.integrations.langchain import PramanixGuardedTool, wrap_tools

guarded_transfer = PramanixGuardedTool(
    name="transfer_funds",
    description="Transfer money between accounts",
    policy=BankingPolicy,
    state_loader=get_account_state,
    tool_fn=execute_transfer,
)

# Or wrap existing tools in bulk
safe_tools = wrap_tools([some_tool, another_tool], policy=BankingPolicy, state_loader=get_state)
```

On BLOCK, the tool raises an exception — LangChain routes it back to the agent as a tool error.

### LlamaIndex

```python
from pramanix.integrations.llamaindex import PramanixGuardedQueryEngine

guarded_engine = PramanixGuardedQueryEngine(
    query_engine=base_engine,
    policy=PHIAccessPolicy,
    state_loader=lambda query: {
        "requestor_role": get_current_user_role(),
        "consent_active": check_consent(),
    },
)

# Guard runs BEFORE retrieval — PHI documents are never fetched for unauthorized requests
response = guarded_engine.query("What is the patient's diagnosis?")
```

### AutoGen

```python
from pramanix.integrations.autogen import PramanixGuardedAgent

guarded_agent = PramanixGuardedAgent(
    agent=base_agent,
    policy=InfraPolicy,
    state_loader=lambda: get_cluster_state(),
)

# Each agent has its own Guard instance. A compromised Agent A cannot
# make Agent B exceed its own policy limits.
```

---

## Zero-Trust Identity

```python
from pramanix.identity.linker import JWTIdentityLinker
from pramanix.identity.redis_loader import RedisStateLoader
import redis.asyncio as aioredis

client = aioredis.from_url("redis://localhost:6379")
loader = RedisStateLoader(redis_client=client)
linker = JWTIdentityLinker(
    state_loader=loader,
    jwt_secret="your-32-char-minimum-hmac-secret",
)

# State is loaded from Redis using only the verified JWT sub claim.
# State submitted in the request body is ignored.
claims, state = await linker.extract_and_load(request)

decision = await guard.verify_async(
    intent={"amount": Decimal(request.body["amount"])},
    state=state,  # from Redis, not from request body
)
```

- The caller cannot inject their own state. Even if the request body contains `{"balance": 999999}`, the system loads `balance` from Redis using the cryptographically verified JWT subject.
- JWT validation: HMAC-SHA256 signature (minimum 32-character secret), `exp` claim, tamper detection.
- Tested in `tests/integration/test_zero_trust_identity.py` against a real Redis instance (testcontainers).

---

## Execution Tokens

One-time-use HMAC-signed tokens that prove a specific ALLOW decision was issued and has not been used before.

```python
from pramanix.execution_token import ExecutionTokenSigner, ExecutionTokenVerifier

signer   = ExecutionTokenSigner(secret_key=b"32-byte-minimum-hmac-key-here!!!!")
verifier = ExecutionTokenVerifier(secret_key=b"32-byte-minimum-hmac-key-here!!!!")

# After an ALLOW decision — bind to state version for TOCTOU protection
token = signer.mint(decision, state_version=account_row.etag)

# Before executing the action
if verifier.consume(token, expected_state_version=current_etag):
    execute_transfer()
# Returns False on: replay, tampered token, state version mismatch, expired token

# For multi-process or multi-server deployments (replay-safe across restarts):
from pramanix.execution_token import RedisExecutionTokenVerifier
verifier = RedisExecutionTokenVerifier(
    secret_key=b"32-byte-minimum-hmac-key-here!!!!",
    redis_client=redis_client,
)
```

The token includes: `decision_id`, `allowed`, `intent_dump`, `policy_hash`, `state_version`, `expires_at`, a 16-byte random nonce, and an HMAC-SHA256 signature. The in-memory verifier uses a `threading.Lock` but the consumed-set is not shared across processes — use `RedisExecutionTokenVerifier` for multi-process deployments.

---

## Audit System

### Cryptographic Decision Signing

```python
from pramanix.crypto import PramanixSigner, PramanixVerifier

# Generate a keypair (save private key to secrets manager — never commit it)
signer = PramanixSigner.generate()

# Or load from PEM
signer = PramanixSigner.from_pem(os.environ["PRAMANIX_SIGNING_KEY_PEM"].encode())

# Pass to GuardConfig to sign every decision
config = GuardConfig(signer=signer)

# Verify offline with only the public key — no SDK, no network connection required
verifier = PramanixVerifier.from_public_pem(public_pem)
verifier.verify(decision)  # raises InvalidSignatureError if tampered
```

- Ed25519, 64-byte signature per decision
- `decision_hash`: SHA-256 over canonical JSON (sorted keys, orjson serialization)
- `key_id`: first 16 hex characters of SHA-256 of the public PEM — tracked per decision for key rotation

### Merkle Audit Chain

```python
from pramanix.audit.merkle import MerkleAnchor, PersistentMerkleAnchor

anchor = MerkleAnchor()
anchor.add(decision_1)
anchor.add(decision_2)

root_hash = anchor.root()   # SHA-256 Merkle root over all decisions
proof     = anchor.proof(1) # inclusion proof for decision at index 1

# Persistent across restarts
anchor = PersistentMerkleAnchor(
    checkpoint_every=500,
    checkpoint_callback=lambda root, count: db.save_checkpoint(root, count),
)
anchor.flush()  # call on shutdown
```

Any insertion, deletion, or modification of any decision breaks all subsequent chain hashes. The Merkle root can be published to an immutable store (S3 + Object Lock, Azure Blob + Immutable Storage) for external tamper evidence.

### Audit CLI

```bash
# Sign a decision
pramanix sign-decision <decision_json_file>

# Verify a signed token
pramanix verify-proof <token>          # exits 0 (VALID) or 1 (INVALID)
pramanix verify-proof <token> --json   # structured JSON output

# Verify a full decision log offline
pramanix audit verify decisions.jsonl --public-key public.pem
# Verified 10000 decisions. 0 tampered. 100 checkpoints.
# Final Merkle root: 09d082c0...
```

### Compliance Reporter

```python
from pramanix.helpers.compliance import classify_compliance_event

category = classify_compliance_event(
    violated_invariants=decision.violated_invariants,
    intent_dump=decision.intent_dump,
)
# Returns: "CRITICAL_PREVENTION" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL"
```

---

## Resilience

### Adaptive Circuit Breaker

```python
from pramanix import AdaptiveCircuitBreaker, CircuitBreakerConfig

breaker = AdaptiveCircuitBreaker(
    guard=guard,
    config=CircuitBreakerConfig(
        namespace                  = "banking_guard",
        pressure_threshold_ms      = 40.0,  # OPEN after solves > 40 ms
        consecutive_pressure_count = 5,     # 5 consecutive slow solves → OPEN
        recovery_seconds           = 30.0,  # attempt HALF_OPEN after 30 s
        isolation_threshold        = 3,     # 3 OPEN episodes → ISOLATED (manual reset)
    ),
)

# State machine:
# CLOSED → (5 consecutive pressure solves) → OPEN → (30 s) → HALF_OPEN → (probe ok) → CLOSED
# 3 total OPEN episodes → ISOLATED (manual reset required)

decision = await breaker.verify_async(intent=intent, state=state)
breaker.reset()  # reset from ISOLATED
```

### Fast-Path Evaluator

Pre-Z3 semantic rules that block obvious violations without invoking the solver. Average fast-path decision: under 0.1 ms (no Z3 context creation). Fast-path results are a performance optimization — they are not formal proofs.

```python
from pramanix.fast_path import SemanticFastPath

GuardConfig(
    fast_path_enabled = True,
    fast_path_rules   = (
        SemanticFastPath.negative_amount("amount"),
        SemanticFastPath.account_frozen("is_frozen"),
        SemanticFastPath.zero_or_negative_balance("balance"),
    ),
)
```

### Load Shedding

```python
GuardConfig(
    shed_worker_pct           = 90.0,   # shed when worker pool utilisation > 90%
    shed_latency_threshold_ms = 200.0,  # shed when rolling P99 > 200 ms
)
```

Shed decisions return `Decision.rate_limited()` with `allowed=False`.

---

## Observability

### Prometheus Metrics

```text
pramanix_decisions_total{policy, status}           counter   — decisions by outcome
pramanix_decision_latency_seconds{policy}          histogram — full verify() latency
pramanix_solver_timeouts_total{policy}             counter   — Z3 timeout events
pramanix_validation_failures_total{policy}         counter   — Pydantic rejection events
pramanix_circuit_breaker_state{namespace, state}   gauge     — breaker state
pramanix_circuit_breaker_pressure_total{namespace} counter   — pressure events
```

Enable: `GuardConfig(metrics_enabled=True)`, then expose `/metrics` via `prometheus_client.start_http_server(8001)`.

### OpenTelemetry

```python
GuardConfig(otel_enabled=True)
# Spans: pramanix.guard.decision, pramanix.z3_solve
# Compatible with OTLP collectors (Jaeger, Tempo, Honeycomb, Datadog)
```

### Structured JSON Logs

Every decision emits a structlog JSON line:

```json
{
  "decision_id": "02b9dd6d-48c7-4df0-bc71-28124f81a2e0",
  "policy": "BankingPolicy",
  "allowed": true,
  "status": "safe",
  "solver_time_ms": 5.47,
  "event": "pramanix.guard.decision",
  "level": "info",
  "timestamp": "2026-03-21T21:05:37.038412Z"
}
```

---

## Production Deployment

### Docker

```dockerfile
# Alpine is NOT supported — z3-solver requires glibc. Use python:3.13-slim.
FROM python:3.13-slim

WORKDIR /app
COPY pyproject.toml .
RUN pip install --no-cache-dir '.[fastapi,otel,identity,audit,crypto]'

COPY src/ src/
CMD ["uvicorn", "myapp:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
```

### Environment Variables

```bash
# Execution
PRAMANIX_EXECUTION_MODE=async-process
PRAMANIX_MAX_WORKERS=8
PRAMANIX_MAX_DECISIONS_PER_WORKER=10000

# Solver
PRAMANIX_SOLVER_TIMEOUT_MS=100
PRAMANIX_SOLVER_RLIMIT=10000000

# Input safety
PRAMANIX_MAX_INPUT_BYTES=65536
PRAMANIX_MIN_RESPONSE_MS=50.0
PRAMANIX_REDACT_VIOLATIONS=true
PRAMANIX_INJECTION_THRESHOLD=0.5

# Observability
PRAMANIX_METRICS_ENABLED=true
PRAMANIX_OTEL_ENABLED=true
PRAMANIX_LOG_LEVEL=INFO

# Identity
PRAMANIX_JWT_SECRET=your-32-char-minimum-secret
PRAMANIX_INTENT_CACHE_REDIS_URL=redis://redis:6379

# Audit signing
PRAMANIX_SIGNING_KEY_PEM=<contents of private key PEM>

# Crash guard — triggers UserWarning if execution_mode is sync or async-thread
PRAMANIX_ENV=production
```

### Graceful Shutdown

```python
await guard.shutdown()  # drains worker pool, releases pending work
```

---

## Benchmarks

All numbers measured on a single development machine: **Windows 11 / Python 3.13.7 / z3-solver 4.16.0**. Not a production server. Numbers will vary by hardware, OS, and Python version. Reproduce locally with the commands below before relying on them for capacity planning.

### Latency: 5-Invariant Policy (2,000 decisions, warm cache)

Policy: `BenchmarkPolicy` — 5 invariants covering balance, frozen flag, daily limit, risk score, positive amount.

```bash
python benchmarks/latency_benchmark.py --n 2000
```

| Metric | Target | Measured |
| -------- | -------- | ---------- |
| P50 latency | < 6 ms | **5.235 ms** |
| P95 latency | < 10 ms | **6.361 ms** |
| P99 latency | < 15 ms | **7.109 ms** |
| Mean latency | — | **5.336 ms** |

These numbers include structlog JSON serialization overhead (one JSON line per decision).

### Memory Stability: 1,000,000 Decisions (Single Thread)

```bash
python benchmarks/1m_decisions_full_audit.py
```

| Metric | Result |
| -------- | -------- |
| Total decisions | 1,000,000 |
| Total wall time | 12,298 s (~3.4 hours, single core) |
| Peak throughput (first 100K) | 152 decisions/sec |
| Sustained throughput (average) | 81 decisions/sec |
| Baseline RSS | 57.6 MiB |
| Final RSS | 60.4 MiB |
| Net memory growth | **+2.80 MiB** |
| GC gen0 cycles | 6 |
| GC gen1 / gen2 | 0 / 0 |
| Cumulative P50 | 11.283 ms |
| Cumulative P99 | 30.538 ms |

The +2.80 MiB net growth over 1M decisions confirms that per-call `del ctx` (destroying the Z3 Context after each solve) is working correctly at the C++ level. This is a single-threaded run to verify memory stability, not a throughput benchmark.

### Latency distribution (1,000,000 decisions)

| Percentile | Measured |
| :----------- | :--------- |
| Min | 4.454 ms |
| P50 | 11.283 ms |
| P95 | 20.145 ms |
| P99 | 30.538 ms |
| P99.9 | 153.848 ms |
| P99.99 | 270.578 ms |
| Max | 1,565.746 ms |
| Mean ± StdDev | 12.287 ms ± 10.033 ms |

P99.9 and P99.99 reflect Windows OS scheduler jitter across a 3.4-hour single-threaded run, not Z3 degradation.

### Memory Charts

#### RSS over time (1 Hz sampling, 3.4 hours)

![RSS Memory Timeline](public/1m_rss_timeline.png)

#### Latency percentiles at each 100K checkpoint

![Latency Percentiles](public/1m_latency_percentiles.png)

#### Throughput at each 100K checkpoint

![RPS Progression](public/1m_rps_progression.png)

#### Full latency distribution (log scale)

![Latency Distribution](public/1m_latency_distribution.png)

#### GC cycles before vs after 1M decisions

![GC Cycles](public/1m_gc_cycles.png)

### Multi-Worker Finance Benchmark (3 Workers)

```bash
python benchmarks/fast_benchmark_worker.py
```

| Metric | Result |
| -------- | -------- |
| Decisions | 1,002 |
| Workers | 3 |
| Elapsed | 4.1 s |
| Throughput | **247 RPS** |
| Allow / Block | 704 / 298 |
| Timeouts | 0 |
| Errors | 0 |
| Average P99 | 45.637 ms |
| Max worker RSS growth | +1.37 MiB |

### Reproduce Locally

```bash
python benchmarks/latency_benchmark.py --n 2000
python benchmarks/1m_decisions_full_audit.py  # ~3.4 hours
pytest tests/perf/test_memory_stability.py -v
pytest tests/unit/test_solver.py::TestSolveTimeout -v
```

---

## Test Suite

1,924 passed, 1 skipped, 0 failures. Coverage: 97% (threshold: 95%).

Measured with `pytest tests/unit/ tests/integration/`. The adversarial, property, and perf suites are run separately.

### Distribution

| Suite | Tests | Files | What it covers |
| ------- | ------- | ------- | ---------------- |
| Unit | 1,751 | 46 | All modules, every public method, edge cases, DSL correctness, HMAC IPC, CLI |
| Integration | 173 | 11 | Full verify() pipeline, all 3 execution modes, JWT + Redis zero-trust |
| Adversarial | 151 | 8 | Prompt injection, HMAC IPC tampering, field overflow, TOCTOU, Z3 context isolation |
| Property | 34 | 3 | Hypothesis-based DSL/transpiler round-trips, fintech invariant properties |
| Perf | 8 | 2 | Latency targets, 1M-decision memory stability, worker recycle RSS |
| **Total (badge)** | **1,924** | | **Unit + Integration; other suites run separately** |
| **Total (all suites)** | **2,117** | | |

### Coverage by Module

| Module | Coverage | Notes |
| -------- | ---------- | ------- |
| `solver.py` | 100% | Two-phase Z3 logic, rlimit, violation attribution |
| `expressions.py` | 100% | Full DSL operator coverage |
| `transpiler.py` | 100% | All Z3 sort conversions |
| `policy.py` | 100% | Validation, field registry |
| `decision.py` | 100% | All factory methods, JSON safety |
| `fast_path.py` | 100% | All semantic rule evaluators |
| `decorator.py` | 100% | @guard decorator |
| `identity/linker.py` | 100% | JWT verify, expiry, tamper detection |
| `translator/ollama.py` | 100% | Real TCP tests against live llama3.2 |
| `guard.py` | 97% | Async-process HMAC path partially covered |
| `worker.py` | 96% | Async-process submit path partially covered |
| `circuit_breaker.py` | 91% | ISOLATED state transitions |
| `cli.py` | ~95% | All subcommands, exit codes |

### No Mocks Policy

Tests use real resources wherever possible:

```python
# Real Z3 rlimit — not a monkeypatch
def test_rlimit_kills_solve(self) -> None:
    with pytest.raises(SolverTimeoutError):
        solve(INVARIANTS, _BASE, timeout_ms=5000, rlimit=1)

# Real TCP connection to localhost:11434
@_needs_ollama  # skips if Ollama is not running
async def test_extract_transfer_intent(self) -> None:
    t = OllamaTranslator()
    result = await t.extract("Transfer 250 dollars to account acc_789", _TransferIntent)
    assert "amount" in result and "recipient" in result

# Real Redis via testcontainers
async def test_caller_cannot_inject_own_state(self, redis_client):
    await redis_client.set("pramanix:state:alice", json.dumps({"balance": "100"}))
    claims, state = await linker.extract_and_load(_Request())
    assert str(state["balance"]) == "100"  # Redis value, not "999999" from request body
```

---

## Project Status

v0.9.0 — 58 source files, 3,182 statements, 97% coverage, 1,924 tests (unit + integration).

| Milestone | Status |
| ----------- | -------- |
| v0.1: Core SDK — Policy DSL, Z3 solver, sync verify() | Done |
| v0.2: Async modes — thread and process pools, worker recycling | Done |
| v0.3: Hardening — ContextVar isolation, HMAC IPC, OTel, Hypothesis | Done |
| v0.4: Translator — dual-LLM consensus, 6-layer injection defense | Done |
| v0.5: CI/CD — SLSA provenance pipeline, Sigstore, SBOM, hardened Docker | Done |
| v0.6: Primitives — 38 domain primitives (finance, AML, RBAC, infra, healthcare, time) | Done |
| v0.7: Performance — expression cache, load shedding, benchmarks | Done |
| v0.8: Audit — Ed25519 signing, Merkle chain, compliance reporter, audit CLI, zero-trust identity, execution tokens | Done |
| v0.9: Phase 12 hardening (H01-H15), docs suite, limitations mitigations (PolicyAuditor, StringEnumField, state_version TOCTOU), ruff/mypy clean sweep | Done |
| v1.0 GA: Chaos testing, PyPI publish, RC deployment, API contract lock | Planned |

---

## Supply Chain

The release pipeline (`release.yml`) is designed to satisfy **SLSA Level 3** when publishing to PyPI. This has not yet triggered because the package is not yet published.

| SLSA requirement | Pipeline design |
| --- | --- |
| Hosted build platform | GitHub Actions (ephemeral, isolated runners) |
| Signed provenance | `pypa/gh-action-pypi-publish` with `attestations: true` (OIDC) |
| Non-forgeable provenance | GitHub OIDC — no stored tokens, workflow identity bound to commit SHA |
| Artifact signing | Sigstore `gh-action-sigstore-python@v3` — `.sigstore.json` bundle per artifact |
| SBOM | CycloneDX JSON, attached to every GitHub Release |
| Post-release smoke test | Clean `pip install` from PyPI in an isolated venv, import verified |
| Version consistency gate | `pyproject.toml == git tag == __version__ == CHANGELOG entry` checked before build |

No `PYPI_API_TOKEN` is stored as a GitHub Secret. PyPI trusted publishing uses GitHub OIDC exclusively.

---

## Comparison

These comparisons reflect the state of each project as of April 2026. Feature sets change; verify against current documentation before making adoption decisions.

| Capability | Pramanix | LangChain Guards | Guardrails AI | LLM-as-Judge | OpenPolicy Agent |
| ------------ | :--------: | :----------------: | :-------------: | :------------: | :----------------: |
| Constraint satisfaction proof (SMT) | Yes | No | No | No | Yes (Rego) |
| Per-invariant counterexample | Yes | No | No | No | Partial |
| Complete violation attribution | Yes | No | No | No | Partial |
| Fail-safe: every error returns BLOCK | Yes | No | No | No | Yes |
| Natural language to verified action | Yes | Yes | Yes | Yes | No |
| LLM not required for verification | Yes | No | No | No | Yes |
| Cryptographic audit trail (Ed25519) | Yes | No | No | No | No |
| Adaptive circuit breaker | Yes | No | No | No | No |
| Process-level worker isolation | Yes | No | No | No | Yes |
| Zero-trust identity (JWT + Redis) | Yes | No | No | No | No |
| One-time execution tokens | Yes | No | No | No | No |
| Python policy DSL (no new language) | Yes | No | Yes | No | No (Rego) |
| RSS-stable at 1M decisions | +2.80 MiB | Unknown | Unknown | N/A | Yes |

Notes:

- OPA uses the Rego language. Pramanix uses Python. Both produce deterministic enforcement.
- LangChain Guards and Guardrails AI use classifiers or validators, not formal SMT proofs. They may produce ALLOW with non-zero false-positive rates by design.
- "LLM-as-Judge" refers to patterns where an LLM itself decides safety. Pramanix can use an LLM for intent extraction (Phase 1) but the safety decision is always Z3 (Phase 2).

---

## Documentation

Full documentation is in the [`docs/`](docs/) directory:

| File | Contents |
| ------ | ---------- |
| [`docs/architecture.md`](docs/architecture.md) | Pipeline internals, worker lifecycle, Z3 context isolation, TOCTOU/ExecutionToken flow |
| [`docs/security.md`](docs/security.md) | Threat model (T01-T07), Phase 12 hardening (H01-H15), cryptographic audit trail, key management |
| [`docs/performance.md`](docs/performance.md) | Benchmark methodology, per-stage latency budget, tuning guide |
| [`docs/policy_authoring.md`](docs/policy_authoring.md) | DSL operator reference, 30 production rules, multi-policy composition patterns |
| [`docs/primitives.md`](docs/primitives.md) | All 38 primitives with DSL formulas, SAT/UNSAT examples, regulatory citations |
| [`docs/integrations.md`](docs/integrations.md) | FastAPI, LangChain, LlamaIndex, AutoGen — full request pipeline for each |
| [`docs/compliance.md`](docs/compliance.md) | HIPAA, BSA/AML, OFAC, SOC 2, PCI DSS, GDPR patterns with policy code |
| [`docs/deployment.md`](docs/deployment.md) | Docker, Kubernetes, environment variables, health probes, upgrade runbook |
| [`docs/why_smt_wins.md`](docs/why_smt_wins.md) | Why formal verification outperforms probabilistic classifiers at scale |
| [`MIGRATION.md`](MIGRATION.md) | v0.7 → v0.8 → v0.9 → v1.0 migration guide — breaking changes, renamed fields |
| [`docs/incident_response.md`](docs/incident_response.md) | P0-P3 playbooks: false ALLOW, audit tampering, solver timeouts, ISOLATED state, key rotation |

---

## License

- **Community:** [AGPL-3.0](LICENSE) — free to use and modify. Changes to Pramanix source must be open-sourced under the same license.
- **Enterprise:** Commercial license available for closed-source deployments, SLA-backed support, and compliance packages.

---

*Built by Viraj Jain.*
*Pramana (प्रमाण) — "valid source of knowledge" or "proof" in Sanskrit.*
*z3-solver ^4.12 (tested on 4.16.0) · pydantic ^2.5 · Python 3.13+*
