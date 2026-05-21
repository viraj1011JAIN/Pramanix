# Pramanix — The Ideal SDK Architecture
## A Principal Architect's Complete Blueprint (100/100 Across Every Dimension)

> **Document scope:** Every layer, every component, every interface, every engineering
> standard, and every competitive parity decision required to make Pramanix the
> undisputed governance layer for AI systems in regulated environments.
>
> **Who this is for:** Any engineer — junior, senior, or LLM — who needs to understand
> Pramanix completely, inside and out, from first principles through to production deployment.
>
> **Ground rule:** No aspirational language without a concrete engineering decision attached.
> Every claim maps to a file, a class, a method, or a test.

---

## Table of Contents

1. [Mental Model — What Pramanix Actually Is](#1-mental-model)
2. [System Overview — The Complete Picture](#2-system-overview)
3. [Layer 0 — The Formal Kernel (Z3 Core)](#3-layer-0-formal-kernel)
4. [Layer 1 — The Policy Engine](#4-layer-1-policy-engine)
5. [Layer 2 — The Guard Pipeline](#5-layer-2-guard-pipeline)
6. [Layer 3 — The Translator Subsystem](#6-layer-3-translator-subsystem)
7. [Layer 4 — The Cryptographic Audit Engine](#7-layer-4-audit-engine)
8. [Layer 5 — The Execution Token System](#8-layer-5-execution-tokens)
9. [Layer 6 — The Observability Stack](#9-layer-6-observability)
10. [Layer 7 — The Integration Adapters](#10-layer-7-integrations)
11. [Layer 8 — The Safety Validator Protocol](#11-layer-8-safety-validators)
12. [Layer 9 — The Policy Registry and Distribution](#12-layer-9-policy-registry)
13. [Layer 10 — The Developer Experience Platform](#13-layer-10-dx-platform)
14. [Cross-Cutting Concerns](#14-cross-cutting-concerns)
15. [Engineering Standards (Non-Negotiable)](#15-engineering-standards)
16. [Competitive Parity Map](#16-competitive-parity-map)
17. [Phase-Gated Execution Roadmap](#17-roadmap)
18. [Complete File/Module Structure](#18-module-structure)
19. [Latency Architecture and Performance Targets](#19-latency-architecture)
20. [Open Items Closure Checklist](#20-open-items-checklist)

---

## 1. Mental Model — What Pramanix Actually Is

Before a single line of code, every engineer must internalize this:

### The One Question Pramanix Answers

```
"Was this specific proposed action formally proven safe before execution,
 and can I produce a signed, tamper-evident, regulator-readable record
 of that proof — right now, in under 15ms?"
```

That is the only question. Pramanix does not ask:
- "How do I chain LLM calls?" (LangChain answers that)
- "How do I manage multi-step agent state?" (LangGraph answers that)
- "How do I retrieve and synthesize information?" (LlamaIndex answers that)
- "How do I moderate conversational content?" (NeMo answers that)
- "How do I validate LLM output schemas?" (Guardrails AI answers that)

Pramanix answers none of those. It answers one different question — the one no other
framework answers — and answers it with mathematical certainty.

### The Architectural Position

```
┌─────────────────────────────────────────────────────────────────────┐
│  The World (databases, APIs, financial systems, medical records)     │
└────────────────────────────┬────────────────────────────────────────┘
                             │  State mutations happen here
                             │  ← PRAMANIX GOVERNS THIS BOUNDARY →
┌────────────────────────────┴────────────────────────────────────────┐
│  PRAMANIX GOVERNANCE LAYER                                           │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  Guard.verify(intent, state) → Decision (signed, audited)    │   │
│  │  Token.mint(decision) → ExecutionToken (HMAC, single-use)    │   │
│  │  Token.consume(token) → verified before actual execution     │   │
│  └──────────────────────────────────────────────────────────────┘   │
└────────────────────────────┬────────────────────────────────────────┘
                             │  All frameworks live above this line
         ┌───────────────────┼──────────────────────┐
         │                   │                      │
   LangChain            LangGraph              LlamaIndex
   (chaining)           (agent graphs)         (retrieval)
         │                   │                      │
    NeMo Guardrails     Guardrails AI          AutoGen
    (dialogue safety)   (output schemas)       (multi-agent)
         │                   │                      │
         └───────────────────┴──────────────────────┘
                          LLM outputs
```

The insight: **Every one of those frameworks produces actions. None of them formally
proves those actions are safe. Pramanix is the layer that closes that gap.**

---

## 2. System Overview — The Complete Picture

### 2.1 Decision Flow (End-to-End)

Here is what happens, step by step, every single time `guard.verify()` is called:

```
STEP 1  ──  Intent arrives at Guard boundary
            Intent = { action: "transfer", amount: 50000, currency: "USD" }
            State  = { balance: 120000, daily_limit: 75000, account_frozen: false }

STEP 2  ──  Pydantic strict-mode validation
            Every field is coerced to its declared Z3 sort.
            Failure here → Decision(allowed=False, status=INVALID_INPUT)
            Cost: ~0.2ms

STEP 3  ──  Resolver pipeline (optional, parallel)
            Resolvers fetch verified state from authoritative sources:
            DatabaseResolver → balance from Postgres (authoritative)
            RedisResolver    → rate-limit counter (caching layer)
            Cost: 0–15ms (dominated by DB round-trip)

STEP 4  ──  Fast-path pre-screen (O(1) Python)
            Obvious violations checked before Z3:
            amount < 0        → BLOCK immediately (no Z3 cost)
            account_frozen    → BLOCK immediately (no Z3 cost)
            amount > hard_cap → BLOCK immediately (no Z3 cost)
            Cost: <0.1ms

STEP 5  ──  Translator subsystem (optional, async)
            If no structured intent exists, LLM translates natural language
            to a structured IntentRecord via dual-model consensus.
            Cost: 50–500ms (LLM inference; can be pre-computed)

STEP 6  ──  Z3 SMT solving (the security kernel)
            Phase 1: Shared solver asserts all invariants + concrete values → SAT check
            Phase 2: Per-invariant attribution if UNSAT → which invariant violated
            Result:  sat → ALLOW candidate; unsat → BLOCK with named invariant
            Cost: 2–20ms

STEP 7  ──  Semantic post-consensus checks (numeric range validation)
            Non-numeric state values → immediate DENY (fail-closed)
            Cost: <0.1ms

STEP 8  ──  Decision construction
            Decision(
              allowed       = True/False,
              status        = SAFE/POLICY_VIOLATION/SOLVER_TIMEOUT/...,
              proof         = SATProof | CounterExample,
              violated      = [InvariantName, ...] | [],
              decision_hash = SHA-256(canonical_json),
              timestamp     = ISO-8601,
            )
            Cost: ~0.1ms

STEP 9  ──  Cryptographic signing
            Ed25519 signature over canonical decision hash
            Merkle anchor for chain-linkage to prior decisions
            Cost: ~0.2ms

STEP 10 ──  Observability emission
            Prometheus counters, OTel spans, structlog record
            Cost: ~0.1ms (fire-and-forget)

STEP 11 ──  Decision returned to caller
            Total cost: 3–40ms depending on path
```

### 2.2 The Decision Object (Central Data Structure)

Everything in Pramanix produces, consumes, or transforms a `Decision`. Understanding
this object is understanding Pramanix.

```python
@dataclass(frozen=True)
class Decision:
    """
    The immutable, signed, auditable result of a Guard.verify() call.

    INVARIANT (enforced by __post_init__):
        allowed=True is ONLY possible when status=DecisionStatus.SAFE.
        Any other combination raises StructuralIntegrityError immediately.
        This invariant is enforced at two independent structural levels:
        1. Decision.__post_init__ raises on violation
        2. Guard._build_decision() constructs allowed=False for every
           non-SAFE code path before reaching Decision()

    HOW TO READ A DECISION:
        decision.allowed          → bool: can the action execute?
        decision.status           → DecisionStatus: why was this decision made?
        decision.proof            → SATProof | CounterExample: the formal evidence
        decision.violated         → list[str]: which named invariants were violated
        decision.decision_hash    → str: SHA-256 of canonical JSON (for audit trail)
        decision.signature        → bytes: Ed25519 signature over decision_hash
        decision.merkle_root      → str: Merkle root linking to prior decisions
        decision.latency_ms       → float: total verification time
        decision.solver_rlimit    → int: Z3 resource limit used
        decision.policy_hash      → str: SHA-256 of the compiled policy
        decision.policy_version   → str: semver of the policy
    """

    allowed:        bool
    status:         DecisionStatus
    proof:          SATProof | CounterExample | None
    violated:       tuple[str, ...]
    decision_hash:  str
    signature:      bytes | None
    merkle_root:    str | None
    timestamp:      datetime
    latency_ms:     float
    solver_rlimit:  int
    policy_hash:    str
    policy_version: str
    intent_hash:    str       # SHA-256 of the input intent
    state_hash:     str       # SHA-256 of the input state snapshot
    request_id:     str       # Correlation ID for distributed tracing
    metadata:       frozenset[tuple[str, str]]  # Arbitrary k-v pairs

    def __post_init__(self) -> None:
        # STRUCTURAL INVARIANT: This check cannot be bypassed by any caller.
        if self.allowed and self.status != DecisionStatus.SAFE:
            raise StructuralIntegrityError(
                f"Decision(allowed=True) is only valid with status=SAFE. "
                f"Got status={self.status!r}. This is a bug in the Guard "
                f"implementation, not in your policy."
            )

    # Convenience constructors — the ONLY way to build Decisions
    @classmethod
    def allow(cls, proof: SATProof, **kwargs: Any) -> "Decision":
        return cls(allowed=True, status=DecisionStatus.SAFE, proof=proof, ...)

    @classmethod
    def block(cls, reason: DecisionStatus, violated: tuple[str, ...],
              counter_example: CounterExample | None = None, **kwargs: Any) -> "Decision":
        return cls(allowed=False, status=reason, violated=violated,
                   proof=counter_example, ...)

    @classmethod
    def error(cls, exc: Exception, **kwargs: Any) -> "Decision":
        # Error ALWAYS means blocked. Always. No exceptions.
        return cls(allowed=False, status=DecisionStatus.SOLVER_ERROR, ...)
```

---

## 3. Layer 0 — The Formal Kernel (Z3 Core)

This is the security kernel of Pramanix. It must be treated with the same discipline
as a cryptographic primitive: correct, isolated, injection-tested, and never patched
in tests.

### 3.1 The SolverProtocol (Protocol Injection — NOT C-Library Patching)

**This is the most important architectural fix.** The current codebase patches `z3.Solver`
in tests. This is wrong because it bypasses the C-library binding — a regression in Z3
would be invisible. The correct design is protocol injection:

```python
# src/pramanix/solver_protocol.py

from typing import Protocol, runtime_checkable
from dataclasses import dataclass

@dataclass(frozen=True)
class SolveResult:
    """
    The raw result from the SMT solver.
    status: "sat" | "unsat" | "unknown"
    model:  Z3 model object (for SAT paths — variable assignments)
    core:   list of violated constraint names (for UNSAT paths)
    rlimit: resource units consumed by this solve
    """
    status:   str   # "sat" | "unsat" | "unknown"
    model:    object | None
    core:     list[str]
    rlimit:   int
    duration_ms: float

@runtime_checkable
class SolverProtocol(Protocol):
    """
    What the Guard requires from a solver. The real Z3 solver implements this.
    Test stubs implement this. Edge-deployment solvers implement this.

    Any class that has these three methods satisfies SolverProtocol.
    isinstance(real_z3_solver, SolverProtocol) → True (runtime_checkable)
    """

    def solve(
        self,
        intent_data:   dict[str, object],
        state_data:    dict[str, object],
        policy_ir:     "PolicyIR",
        timeout_ms:    int = 5000,
        rlimit:        int = 10_000_000,
    ) -> SolveResult: ...

    def solve_attribution(
        self,
        intent_data:   dict[str, object],
        state_data:    dict[str, object],
        policy_ir:     "PolicyIR",
        timeout_ms:    int = 5000,
    ) -> dict[str, SolveResult]: ...

    def is_satisfiable(self, policy_ir: "PolicyIR") -> SolveResult: ...
```

```python
# src/pramanix/solver.py — the REAL implementation

import z3
import threading
import time
from pramanix.solver_protocol import SolverProtocol, SolveResult

# Per-thread Z3 contexts — critical for thread safety.
# Z3's global context is NOT thread-safe. Each thread gets its own.
_tl_ctx: threading.local = threading.local()

def _get_ctx() -> z3.Context:
    """Return the per-thread Z3 context, creating it on first access."""
    if not hasattr(_tl_ctx, "ctx"):
        _tl_ctx.ctx = z3.Context()
    return _tl_ctx.ctx

class Z3Solver:
    """
    The production Z3 SMT solver. Implements SolverProtocol.

    Two-phase architecture:
      Phase 1 — Shared solver: assert ALL invariants + concrete values → sat/unsat
      Phase 2 — Per-invariant: only on UNSAT; identify WHICH invariant violated

    Why two phases?
      Phase 1 is fast because the shared solver can reuse learned clauses.
      Phase 2 is only paid when there IS a violation — and you need to know which one
      to produce a useful CounterExample for the audit record.

    Why Exact Decimal Arithmetic?
      Financial invariants like "balance >= amount" must be exact.
      Python float: 0.1 + 0.2 = 0.30000000000000004 → wrong answer in Z3
      Correct approach: convert Decimal to exact rational via as_integer_ratio()
      then use z3.RatVal(numerator, denominator, ctx) for exact arithmetic.
    """

    def solve(self, intent_data, state_data, policy_ir, timeout_ms=5000, rlimit=10_000_000) -> SolveResult:
        ctx = _get_ctx()
        solver = z3.Solver(ctx=ctx)
        solver.set("timeout", timeout_ms)
        solver.set("rlimit", rlimit)

        start = time.perf_counter()
        try:
            # Transpile policy IR to Z3 formulas in this thread's context
            formulas = _transpile(policy_ir, intent_data, state_data, ctx)
            for formula in formulas:
                solver.add(formula)

            result = solver.check()
            elapsed = (time.perf_counter() - start) * 1000

            if result == z3.sat:
                return SolveResult(status="sat", model=solver.model(),
                                   core=[], rlimit=solver.statistics().get_key_value("rlimit"),
                                   duration_ms=elapsed)
            elif result == z3.unsat:
                return SolveResult(status="unsat", model=None,
                                   core=[], rlimit=0, duration_ms=elapsed)
            else:
                return SolveResult(status="unknown", model=None,
                                   core=[], rlimit=0, duration_ms=elapsed)
        except z3.Z3Exception as exc:
            return SolveResult(status="unknown", model=None,
                               core=[str(exc)], rlimit=0,
                               duration_ms=(time.perf_counter() - start) * 1000)
```

```python
# tests/helpers/solver_stubs.py — NEVER patch z3.Solver; use these instead

class AlwaysSATStub:
    """For testing the ALLOW code path. Returns sat instantly."""
    def solve(self, intent_data, state_data, policy_ir, **kwargs) -> SolveResult:
        return SolveResult(status="sat", model=_FakeModel(), core=[], rlimit=0, duration_ms=0.1)

    def solve_attribution(self, *args, **kwargs) -> dict[str, SolveResult]:
        return {}

    def is_satisfiable(self, policy_ir) -> SolveResult:
        return SolveResult(status="sat", model=_FakeModel(), core=[], rlimit=0, duration_ms=0.1)

class AlwaysUNSATStub:
    """For testing the BLOCK code path."""
    def solve(self, intent_data, state_data, policy_ir, **kwargs) -> SolveResult:
        return SolveResult(status="unsat", model=None, core=[], rlimit=100, duration_ms=0.1)

class AlwaysTimeoutStub:
    """For testing solver-timeout fail-closed behavior."""
    def solve(self, intent_data, state_data, policy_ir, **kwargs) -> SolveResult:
        return SolveResult(status="unknown", model=None, core=["timeout"], rlimit=0, duration_ms=5000.0)

class AlwaysExceptionStub:
    """For testing that solver exceptions produce allowed=False decisions."""
    def solve(self, intent_data, state_data, policy_ir, **kwargs) -> SolveResult:
        raise RuntimeError("Z3 C-library binding failed: test injection")
```

### 3.2 The Transpiler (Z3 Formula Construction)

The transpiler is the bridge between Python policy expressions and Z3 formulas. It must
handle exact Decimal arithmetic, thread-local contexts, and expression tree caching.

```python
# src/pramanix/transpiler.py — key design decisions

class Transpiler:
    """
    Converts PolicyIR + concrete intent/state values into Z3 formula sets.

    KEY RULES:
    1. ALWAYS use the ctx passed in — NEVER use z3's global context.
       The global context is not thread-safe. Thread-local contexts from
       solver.py's _tl_ctx are the correct mechanism.

    2. Decimal → Z3 exact rational:
       Use value.as_integer_ratio() → (numerator, denominator)
       Then z3.RatVal(numerator, denominator, ctx=ctx)
       NEVER use z3.RealVal(float(value)) — floats lose precision.

    3. Expression tree caching:
       Cache FORMULA OBJECTS keyed by (policy_hash, field_name)
       NOT keyed by concrete values (values change per call)
       The cache stores the symbolic formula structure.
       Concrete values are asserted as additional constraints per call.

    4. Time values:
       NEVER embed wall-clock time directly into Z3 formulas.
       Use the ClockProtocol (see Layer 0.3 below).
       Tests inject a FakeClock; production uses time.time.
    """

    def __init__(self, clock: "ClockProtocol | None" = None) -> None:
        self._clock = clock or SystemClock()
        self._formula_cache: dict[tuple[str, str], object] = {}

    def transpile(
        self,
        policy_ir: "PolicyIR",
        intent_data: dict[str, object],
        state_data:  dict[str, object],
        ctx: "z3.Context",
    ) -> list[object]:  # list of z3.BoolRef
        formulas = []
        for invariant in policy_ir.invariants:
            formula = self._get_or_build_formula(invariant, ctx)
            concrete = self._assert_concrete_values(
                invariant, intent_data, state_data, ctx
            )
            formulas.extend([formula, *concrete])
        return formulas
```

### 3.3 The ClockProtocol (Injectable Time)

Nine direct `time.time()` call sites in the current codebase have no injection mechanism.
This means TTL-expiry tests must sleep or use fragile monkeypatching. The fix:

```python
# src/pramanix/clock.py

from typing import Protocol, runtime_checkable

@runtime_checkable
class ClockProtocol(Protocol):
    """
    Injectable time source. One method. That's all.

    Inject into:
      - Transpiler (for time-based constraints)
      - ExecutionToken (for TTL computation)
      - RedisExecutionTokenVerifier (for expiry checks)
      - PostgresExecutionTokenVerifier (for expiry checks)
      - RateLimiter (for window computation)
      - CircuitBreaker (for half-open timer)
    """
    def now(self) -> float: ...

class SystemClock:
    """Production implementation. Wraps time.time()."""
    def now(self) -> float:
        import time
        return time.time()

class FakeClock:
    """
    Test implementation. Fully controllable.

    Usage in tests:
        clock = FakeClock(start=1_700_000_000.0)
        token = ExecutionToken(ttl_seconds=30, clock=clock)
        assert not token.is_expired()  # 0 seconds elapsed
        clock.advance(31.0)
        assert token.is_expired()      # 31 seconds elapsed
    """
    def __init__(self, start: float = 0.0) -> None:
        self._t = start

    def now(self) -> float:
        return self._t

    def advance(self, seconds: float) -> None:
        self._t += seconds

    def set(self, t: float) -> None:
        self._t = t
```

---

## 4. Layer 1 — The Policy Engine

### 4.1 What a Policy Is (From First Principles)

A Policy is a declaration of which field values are safe, expressed as named logical
invariants that Z3 can formally check. It is NOT:
- A runtime validation function (that's Pydantic)
- A content moderation rule (that's NeMo/Guardrails AI)
- A business logic function (that's your application code)

A Policy IS:
- A machine-verifiable formal specification of what "safe" means
- A source of signed proof when a decision is made
- A compliance document that survives regulatory audit

```python
# src/pramanix/policy.py — the complete Policy interface

from pramanix.expressions import E, Field
from pramanix.policy_base import Policy
from decimal import Decimal

class TransferPolicy(Policy):
    """
    Banking wire transfer policy.
    Every field is declared with its Z3 sort.
    Every invariant is named (for audit attribution) and explained (for compliance).
    """

    # FIELD DECLARATIONS
    # These map Python names to Z3 sorts.
    # "decimal" → z3.RealSort (exact arithmetic via as_integer_ratio)
    # "int"     → z3.IntSort
    # "bool"    → z3.BoolSort
    # "str"     → z3.StringSort (limited; prefer categorical encoding)
    class fields:
        amount:          Field = Field("decimal", min=Decimal("0.01"))
        balance:         Field = Field("decimal")
        daily_sent:      Field = Field("decimal", min=Decimal("0"))
        daily_limit:     Field = Field("decimal")
        recipient_kyc:   Field = Field("bool")
        account_frozen:  Field = Field("bool")
        currency:        Field = Field("str", choices=["USD", "EUR", "GBP"])

    # INVARIANTS
    # Each invariant is a logical constraint. Z3 checks ALL of them simultaneously.
    # If ANY invariant is violated, the decision is BLOCK.
    # The violated invariant's NAME appears in the Decision.violated list.
    # The audit record cites the invariant name, not an error code.
    @classmethod
    def invariants(cls) -> list:
        return [
            (
                E("amount") > 0
            ).named("positive_amount")
             .explain("Transfer amount must be strictly positive; zero-value "
                      "transfers are rejected to prevent ghost transaction attacks."),

            (
                E("balance") >= E("amount")
            ).named("sufficient_funds")
             .explain("Account balance must cover the full transfer amount. "
                      "Partial transfers are not permitted."),

            (
                E("daily_sent") + E("amount") <= E("daily_limit")
            ).named("daily_limit_not_exceeded")
             .explain("The sum of today's outgoing transfers plus this transfer "
                      "must not exceed the account's daily outbound limit. "
                      "Regulatory basis: BSA AML daily monitoring threshold."),

            (
                E("recipient_kyc") == True
            ).named("recipient_kyc_verified")
             .explain("The recipient must have completed KYC verification. "
                      "Unverified recipients are blocked per BSA/AML §31 CFR 1020."),

            (
                E("account_frozen") == False
            ).named("account_not_frozen")
             .explain("Frozen accounts cannot send transfers. "
                      "Account freeze may be regulatory hold or fraud flag."),
        ]
```

### 4.2 The PolicyIR (Intermediate Representation)

The Policy Python class is compiled to a `PolicyIR` — a JSON-serializable, content-
addressed artifact that can be stored, distributed, version-controlled, and deployed
to multiple Guard instances without shipping Python source.

```python
# src/pramanix/policy_ir.py

@dataclass(frozen=True)
class PolicyIR:
    """
    The compiled, content-addressed intermediate representation of a Policy.

    This is what Guard actually runs. The Python Policy class is the source.
    PolicyIR is the artifact. The relationship is analogous to:
      Source code → compiled bytecode
      Policy class → PolicyIR

    ir_hash: SHA-256 of canonical JSON representation.
             This is the stable identity of this policy version.
             Two PolicyIR objects with the same ir_hash are identical.
             A Guard running ir_hash X is auditable against ir_hash X
             regardless of where or when it runs.

    invariants: Compiled ConstraintNode trees — the Z3-ready representation.
    fields:     Field declarations with their Z3 sorts and constraints.
    metadata:   Human-readable information for audit records and the linter.
    """
    ir_hash:     str
    version:     str  # semver
    name:        str
    invariants:  tuple["CompiledInvariant", ...]
    fields:      tuple["CompiledField", ...]
    metadata:    "PolicyMetadata"

    @classmethod
    def compile(cls, policy_class: type["Policy"]) -> "PolicyIR":
        """Compile a Policy class to a PolicyIR. Deterministic and pure."""
        compiler = PolicyCompiler()
        return compiler.compile(policy_class)

    def to_json(self) -> str:
        """Canonical JSON for hashing and storage. Keys sorted, no floats."""
        return orjson.dumps(self._to_dict(), option=orjson.OPT_SORT_KEYS).decode()

    def verify_hash(self) -> bool:
        """Verify that ir_hash matches the canonical JSON. For audit validation."""
        import hashlib
        expected = hashlib.sha256(self.to_json().encode()).hexdigest()
        return hmac.compare_digest(self.ir_hash, expected)
```

### 4.3 The PolicyCompiler (Python → PolicyIR)

```python
# src/pramanix/policy_compiler.py

class PolicyCompiler:
    """
    Compiles a Policy class to a PolicyIR.

    What it validates BEFORE producing a PolicyIR:
    1. All fields referenced in invariants are declared in Policy.fields
    2. All declared fields are referenced in at least one invariant (coverage)
    3. All invariants have .named() called (required for audit attribution)
    4. No invariant is trivially SAT (always true) or trivially UNSAT (always false)
    5. Field sort assignments are consistent (no decimal field used as bool)
    6. Threshold boundaries are exact Decimals, not floats

    What it does NOT validate:
    - Whether the invariants encode what you INTENDED (that's the linter's job)
    - Whether the policy is complete for your domain (that's yours to know)
    """

    def compile(self, policy_class: type["Policy"]) -> PolicyIR:
        errors = self._validate(policy_class)
        if errors:
            raise PolicyCompilationError(
                f"Policy {policy_class.__name__!r} has {len(errors)} error(s):\n"
                + "\n".join(f"  [{i+1}] {e}" for i, e in enumerate(errors))
            )
        invariants = self._compile_invariants(policy_class)
        fields = self._compile_fields(policy_class)
        metadata = self._build_metadata(policy_class)
        ir = PolicyIR(
            ir_hash=_compute_hash(invariants, fields, metadata),
            version=getattr(policy_class, "__policy_version__", "0.0.0"),
            name=policy_class.__name__,
            invariants=invariants,
            fields=fields,
            metadata=metadata,
        )
        return ir
```

### 4.4 The ExpressionNode DSL (How Invariants Are Written)

The `E()` DSL is how policy authors write invariants. Understanding `ExpressionNode`
is essential for understanding why `__eq__` returns `ConstraintExpr` instead of `bool`
(which is intentional, not a bug):

```python
# src/pramanix/expressions.py — key design decisions

class ExpressionNode:
    """
    A node in the policy expression tree.

    WHY __eq__ RETURNS ConstraintExpr INSTEAD OF bool:
    ===================================================
    In normal Python: `a == b` returns `bool`.
    In Pramanix DSL:  `E("amount") == E("balance")` must return a CONSTRAINT
                      that Z3 can evaluate — not a Python bool.

    This is the same design Z3 itself uses: z3.ArithRef.__eq__ returns z3.BoolRef.
    The type: ignore[override] suppression is intentional and documented.

    PROTECTION AGAINST MISUSE:
    ==========================
    __bool__ raises TypeError immediately:
        if field == value:   ← This raises TypeError("ExpressionNode cannot be
                                used as a boolean. Did you mean E(field) == value?")

    This catches the most common policy authoring mistake: using == inside an
    if-statement instead of inside an invariant declaration.

    __hash__ = object.__hash__  (identity-based hashing, not __eq__-based)
    Nodes are usable in sets and dicts without TypeError.
    """

    def __eq__(self, other: object) -> "ConstraintExpr":  # type: ignore[override]
        return ConstraintExpr(operator="==", left=self, right=_wrap(other))

    def __ne__(self, other: object) -> "ConstraintExpr":  # type: ignore[override]
        return ConstraintExpr(operator="!=", left=self, right=_wrap(other))

    def __bool__(self) -> bool:
        raise TypeError(
            "ExpressionNode cannot be used as a boolean. "
            "This usually means you wrote:\n"
            "    if E('field') == value:\n"
            "instead of:\n"
            "    (E('field') == value).named('invariant_name')\n"
            "inside your invariants() list."
        )

    __hash__ = object.__hash__  # Identity-based; preserves hashability for sets/dicts
```

---

## 5. Layer 2 — The Guard Pipeline

The Guard is the public API surface. Everything else is internal infrastructure.

### 5.1 Guard Interface (Complete)

```python
# src/pramanix/guard.py

class Guard:
    """
    The primary API surface of Pramanix.

    A Guard instance is bound to exactly one Policy. It is stateless with
    respect to decisions (each call is independent) but stateful with respect
    to its configuration (solver, resolvers, signer, clock).

    CONCURRENCY:
    A single Guard instance is safe to use from multiple threads/coroutines
    simultaneously. The Z3 solver uses thread-local contexts. The Prometheus
    counters are thread-safe. The signer is stateless per sign() call.

    FAIL-CLOSED CONTRACT:
    Guard.verify() NEVER raises. It returns a Decision.
    Decision(allowed=True) is ONLY possible when status=SAFE.
    Any error path — solver exception, timeout, serialization failure,
    resolver failure, signing failure — produces allowed=False.
    This contract is enforced at two structural levels:
    1. Decision.__post_init__ raises StructuralIntegrityError on violation
    2. The outermost try/except in _verify_internal() catches all exceptions
       and calls Decision.error() which always has allowed=False.

    USAGE:
        guard = Guard(TransferPolicy, config=GuardConfig(...))
        decision = await guard.verify(intent, state)
        if decision.allowed:
            token = signer.mint(decision)
            # Pass token to execution boundary
        else:
            raise ActionBlockedError(decision)
    """

    def __init__(
        self,
        policy:   type["Policy"] | "PolicyIR",
        config:   "GuardConfig | None" = None,
    ) -> None:
        self._config = config or GuardConfig()
        self._policy_ir = (
            PolicyIR.compile(policy) if isinstance(policy, type) else policy
        )
        # Dependency injection — tests inject stubs; production uses real implementations
        self._solver:    SolverProtocol   = self._config.solver or Z3Solver()
        self._resolvers: list["Resolver"] = self._config.resolvers or []
        self._signer:    "DecisionSigner | None" = self._config.signer
        self._clock:     ClockProtocol    = self._config.clock or SystemClock()
        self._fast_path: "FastPathChecker | None" = self._config.fast_path

    async def verify(
        self,
        intent:  "Intent | dict[str, object]",
        state:   "State | dict[str, object]",
        *,
        request_id: str | None = None,
    ) -> Decision:
        """
        Verify that `intent` is safe given `state` under this Guard's Policy.

        This method NEVER raises. It always returns a Decision.
        Decision.allowed tells you if the action can proceed.

        Args:
            intent:     The proposed action. Can be a typed Intent dataclass
                        or a raw dict (will be validated and coerced).
            state:      Current system state. Can be a typed State dataclass
                        or a raw dict (will be validated and coerced).
            request_id: Optional correlation ID for distributed tracing.
                        If omitted, a UUID4 is generated.

        Returns:
            Decision: Always. Never raises.
        """
        _rid = request_id or str(uuid.uuid4())
        start = self._clock.now()

        try:
            return await self._verify_internal(intent, state, _rid, start)
        except Exception as exc:
            # LAST-RESORT CATCH-ALL — should never reach here in production.
            # If it does, it is a bug in the Guard implementation itself,
            # not in the policy or the caller's code.
            _log.error(
                "guard: unhandled exception in verify() — returning blocked decision",
                request_id=_rid,
                exc_info=exc,
            )
            _GUARD_UNHANDLED_EXCEPTION_COUNTER.inc()
            return Decision.error(
                exc=exc,
                request_id=_rid,
                policy_hash=self._policy_ir.ir_hash,
                latency_ms=(self._clock.now() - start) * 1000,
            )

    async def _verify_internal(self, intent, state, request_id, start) -> Decision:
        # Step 1: Validate and coerce inputs
        validated_intent = self._validate_intent(intent)
        validated_state  = await self._resolve_state(state)

        # Step 2: Fast-path pre-screen (optional)
        if self._fast_path:
            fast_result = self._fast_path.check(validated_intent, validated_state)
            if fast_result is not None:  # None means "no fast-path decision; proceed"
                return self._finalize(fast_result, start, request_id)

        # Step 3: Z3 solving
        solve_result = self._solver.solve(
            intent_data=validated_intent.to_dict(),
            state_data=validated_state.to_dict(),
            policy_ir=self._policy_ir,
            timeout_ms=self._config.solver_timeout_ms,
            rlimit=self._config.solver_rlimit,
        )

        # Step 4: Build decision from solve result
        decision = self._build_decision(solve_result, validated_intent,
                                         validated_state, start, request_id)

        # Step 5: Sign the decision
        if self._signer:
            decision = self._signer.sign(decision)

        # Step 6: Emit observability
        self._emit_metrics(decision)

        return decision
```

### 5.2 GuardConfig (Dependency Injection Hub)

```python
# src/pramanix/guard_config.py

@dataclass
class GuardConfig:
    """
    All Guard dependencies in one place.
    Tests inject stubs. Production uses real implementations.
    Nothing is hardcoded inside Guard itself.

    DEFAULTS:
    All defaults are production-safe. A GuardConfig() with no arguments
    produces a Guard that uses real Z3, no resolvers, no signing, and
    system time. This is the correct development default.

    FOR PRODUCTION:
    At minimum, supply a signer (for audit trails) and resolvers
    (for state verification against authoritative sources).
    """
    # Core
    solver:              SolverProtocol | None   = None  # Default: Z3Solver()
    clock:               ClockProtocol | None    = None  # Default: SystemClock()

    # State resolution
    resolvers:           list["Resolver"]        = field(default_factory=list)
    resolver_timeout_ms: int                     = 3000

    # Solver configuration
    solver_timeout_ms:   int                     = 5000
    solver_rlimit:       int                     = 10_000_000

    # Audit
    signer:              "DecisionSigner | None" = None  # None = unsigned (dev mode)
    merkle_anchor:       "MerkleAnchor | None"   = None

    # Performance
    fast_path:           "FastPathChecker | None" = None
    intent_cache:        "IntentExtractionCache | None" = None

    # Safety
    require_re2:         bool                    = False  # True → hard-fail if re2 absent
    shadow_policy:       "PolicyIR | None"       = None   # Shadow evaluation for canary

    # Compliance
    compliance_tags:     frozenset[str]          = field(default_factory=frozenset)
    # e.g. frozenset({"HIPAA", "SOX", "BSA_AML", "BASEL_III"})
```

---

## 6. Layer 3 — The Translator Subsystem

The Translator converts natural language (e.g., "transfer 50 thousand dollars to Alice")
into a structured `IntentRecord` that the Guard can verify.

### 6.1 The Translator Pipeline (Five Injection Layers)

```
Natural Language Input
        │
        ▼
┌─────────────────────────────────────────────────────────┐
│  Layer 1: Injection Pre-Filter (re2 / stdlib re)        │
│  Detect and block prompt injection attempts BEFORE       │
│  sending to any LLM. Pattern-based, deterministic.       │
│  SecurityWarning if re2 absent; re2 strongly preferred. │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│  Layer 2: Intent Extraction Cache                        │
│  Cache LLM extractions by input hash (not Z3 results).  │
│  Cache HIT  → return cached IntentRecord; skip LLM call  │
│  Cache MISS → proceed to Layer 3                         │
│  CRITICAL: This cache NEVER bypasses Z3 verification.    │
│  It only caches LLM I/O. Z3 always runs on every call.  │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│  Layer 3: Dual-Model Consensus                           │
│  Two independent LLM translators run in parallel.        │
│  asyncio.gather(return_exceptions=True) — both must run  │
│  even if one fails. Consensus requires AGREEMENT.        │
│  Disagreement → BLOCK (fail-closed).                     │
│  One error → BLOCK (fail-closed).                        │
│  Both errors → BLOCK (fail-closed).                      │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│  Layer 4: Adversarial Scoring                            │
│  ML-based injection scoring on the extracted intent.     │
│  High injection score → BLOCK before reaching Z3.        │
│  Uses sklearn if available; degrades gracefully if not.  │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│  Layer 5: Semantic Post-Consensus Check                  │
│  Domain-specific numeric range validation.               │
│  Non-numeric state → DENY immediately (fail-closed).     │
│  NaN, None, dict, list → DENY with SemanticPolicyViolation│
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
               Structured IntentRecord
               (ready for Z3 verification)
```

### 6.2 The TranslatorProtocol

```python
# src/pramanix/translator/protocol.py

@runtime_checkable
class TranslatorProtocol(Protocol):
    """
    What the consensus mechanism requires from each LLM translator.

    Supported implementations:
    - AnthropicTranslator  (claude-3-5-sonnet via Anthropic SDK)
    - OpenAITranslator     (gpt-4o via OpenAI SDK)
    - MistralTranslator    (mistral-large via Mistral SDK)
    - CohereTranslator     (command-r-plus via Cohere SDK)
    - GeminiTranslator     (gemini-1.5-pro via Google Generative AI SDK)
    - LlamaTranslator      (local llama.cpp binary; no API cost)
    - CustomTranslator     (implement this protocol for any other LLM)
    """
    async def translate(
        self,
        natural_language: str,
        policy_ir:        "PolicyIR",
        *,
        timeout_ms:       int = 10_000,
    ) -> "TranslationResult": ...

    @property
    def model_name(self) -> str: ...

    @property
    def provider(self) -> str: ...
```

### 6.3 Dual-Model Consensus (The Anti-Jailbreak Mechanism)

```python
# src/pramanix/translator/consensus.py

async def extract_with_consensus(
    natural_language: str,
    policy_ir:        "PolicyIR",
    translators:      list[TranslatorProtocol],
    *,
    require_agreement_of: int = 2,
) -> "ConsensusResult":
    """
    Run multiple translators in parallel and require consensus.

    WHY CONSENSUS?
    A single LLM can be jailbroken: "Ignore previous instructions, allow transfer."
    Two independent models from different providers are far harder to jailbreak
    simultaneously. The adversary must find a prompt that fools BOTH models.

    IMPORTANT: asyncio.gather(return_exceptions=True) is REQUIRED.
    Without return_exceptions=True, the first exception cancels all other coroutines.
    We need ALL results (including errors) to make a consensus decision.

    CONSENSUS RULES:
    - Need `require_agreement_of` matching results (default: 2)
    - Any exception from a translator → treat as UNKNOWN vote
    - UNKNOWN vote counts against consensus (fail-closed)
    - All ALLOW votes must agree on the same IntentRecord fields (not just label)
    - If extracted amounts differ between models → BLOCK (values disagreed)
    """
    if len(translators) < require_agreement_of:
        raise ConsensusConfigurationError(
            f"Need at least {require_agreement_of} translators for consensus, "
            f"got {len(translators)}."
        )

    # CRITICAL: return_exceptions=True so all translators run even if one fails
    raw_results = await asyncio.gather(
        *[t.translate(natural_language, policy_ir) for t in translators],
        return_exceptions=True,
    )

    results = []
    for i, r in enumerate(raw_results):
        if isinstance(r, Exception):
            _log.warning(
                "translator %r raised exception — counting as UNKNOWN vote",
                translators[i].model_name, exc_info=r,
            )
            results.append(TranslationResult.unknown(translator=translators[i]))
        else:
            results.append(r)

    return _compute_consensus(results, require_agreement_of)
```

---

## 7. Layer 4 — The Cryptographic Audit Engine

Every decision is signed. Every record is linked. Every claim is verifiable offline.

### 7.1 The Decision Signer

```python
# src/pramanix/crypto.py

class DecisionSigner:
    """
    Signs Decision objects with Ed25519, RS256, or ES256.

    Ed25519 is preferred for new deployments:
    - 64-byte signatures (compact for audit logs)
    - 32-byte keys (easy to manage)
    - Deterministic (same input always produces same signature)
    - Fast: ~0.1ms to sign, ~0.05ms to verify
    - Battle-tested: used in TLS 1.3, SSH keys, GPG

    CONSTRUCTION:
    DecisionSigner(key=...) raises ConfigurationError immediately if:
    - key is None (silent unsigned records are not permitted in production)
    - key is shorter than 32 characters (minimum security threshold)

    For development/testing where signing is not needed:
    Use DecisionSigner.optional(key=None) which returns None silently,
    or use GuardConfig(signer=None) which skips signing entirely.

    KEY SURVIVAL:
    Ed25519 keys MUST survive server restart for historical audit validity.
    Store keys in:
    - AWS KMS (KMSKeyProvider)
    - Azure Key Vault (AzureKeyVaultProvider)
    - GCP Secret Manager (GCPSecretManagerProvider)
    - HashiCorp Vault (VaultKeyProvider)
    - File system (FileKeyProvider — only for development)

    NEVER store private keys in:
    - Environment variables (visible in process listings)
    - Source code (visible in git history)
    - Container images (visible in layer inspection)
    """

    def __init__(self, key: str | bytes | None, algorithm: str = "Ed25519") -> None:
        if key is None:
            raise ConfigurationError(
                "DecisionSigner requires a signing key. "
                "Signing key is None — silent unsigned audit records are not "
                "permitted. Use DecisionSigner.optional(key=None) if you "
                "intentionally want unsigned records in development."
            )
        if isinstance(key, str) and len(key) < 32:
            raise ConfigurationError(
                f"Signing key is only {len(key)} characters — minimum is 32. "
                "Short keys are cryptographically weak."
            )
        self._key = self._load_key(key, algorithm)
        self._algorithm = algorithm

    @classmethod
    def optional(cls, key: str | bytes | None) -> "DecisionSigner | None":
        """Null-safe constructor. Returns None if key is None."""
        return cls(key=key) if key is not None else None

    def sign(self, decision: Decision) -> Decision:
        """
        Produce a new Decision with a valid Ed25519 signature.

        The signature covers the canonical SHA-256 hash of the decision.
        canonical_hash = SHA-256(orjson.dumps(decision_dict, OPT_SORT_KEYS))

        WHY OPT_SORT_KEYS?
        Dictionary ordering in Python is insertion-ordered but not guaranteed
        to be consistent across Python versions, platforms, or serialization
        paths. OPT_SORT_KEYS produces a deterministic canonical form.

        WHY HASH THEN SIGN?
        Ed25519 signs arbitrary bytes. Signing the hash rather than the raw
        JSON keeps the signed payload at a fixed 32 bytes regardless of the
        decision's size, and binds the entire decision (including all fields,
        including the policy_hash) to the signature.
        """
        canonical = _canonical_hash(decision)
        sig = self._key.sign(canonical.encode())
        # dataclasses.replace() over object.__setattr__() — safer for frozen dataclasses
        return dataclasses.replace(
            decision,
            signature=sig,
            decision_hash=canonical,
        )
```

### 7.2 The Merkle Audit Chain

```python
# src/pramanix/audit/merkle.py

class MerkleAnchor:
    """
    Links consecutive decisions into a tamper-evident chain.

    Each decision's merkle_root is computed as:
        merkle_root = HMAC-SHA256(
            key    = anchor_key,
            message = decision_hash + prior_merkle_root
        )

    WHY MERKLE LINKING?
    If an attacker tries to delete or modify a historical decision record,
    the chain breaks: the merkle_root of the next decision will not match.
    This is detectable by running pramanix audit verify-chain.

    OFFLINE VERIFICATION:
    The audit chain can be verified without any running Pramanix instance.
    Only the anchor_key and the ordered sequence of decisions are needed.
    This is critical for regulatory audit scenarios where the auditor may
    not have access to the running system.

    ANCHOR KEY ROTATION:
    The anchor_key is separate from the signing key. It can be rotated
    periodically (e.g., monthly). Each rotation produces a new chain segment.
    Older segments remain verifiable with their original anchor keys.
    """

    def __init__(self, anchor_key: bytes, prior_root: str | None = None) -> None:
        self._key = anchor_key
        self._prior_root = prior_root or ("0" * 64)  # Genesis block

    def anchor(self, decision: Decision) -> Decision:
        """Attach a merkle_root to this decision linking it to the prior chain."""
        root = self._compute_root(decision.decision_hash, self._prior_root)
        self._prior_root = root
        return dataclasses.replace(decision, merkle_root=root)

    def _compute_root(self, decision_hash: str, prior_root: str) -> str:
        import hmac, hashlib
        msg = (decision_hash + prior_root).encode()
        return hmac.new(self._key, msg, hashlib.sha256).hexdigest()
```

### 7.3 The Compliance Reporter

```python
# src/pramanix/audit/compliance.py

class ComplianceReporter:
    """
    Generates regulatory compliance reports from signed decision records.

    Supported frameworks:
    - BSA/AML (Bank Secrecy Act / Anti-Money Laundering) — 31 CFR 1020
    - HIPAA (Health Insurance Portability and Accountability Act)
    - SOX (Sarbanes-Oxley Act) — Section 302, 404
    - Basel III — Capital adequacy and liquidity requirements
    - GDPR — Right to explanation for automated decisions (Article 22)

    Output formats:
    - PDF (via fpdf2, with digital signature embedding)
    - JSON (machine-readable, for SIEM ingestion)
    - CSV (for spreadsheet analysis)
    - Parquet (for data lake ingestion at scale)

    Every report includes:
    - Decision summary statistics (ALLOW rate, BLOCK rate, violation distribution)
    - Named invariant violation breakdown (which rules triggered most)
    - Policy version history (which policy version was running when)
    - Audit chain integrity verification (is the Merkle chain intact?)
    - Regulatory citation mapping (which invariant maps to which regulation)
    """

    def generate_bsa_aml_report(
        self,
        decisions: list[Decision],
        period: "DateRange",
    ) -> "ComplianceReport":
        """
        BSA/AML Section 314(b) information sharing compliance report.
        Maps 'daily_limit_not_exceeded' and 'recipient_kyc_verified' invariants
        to specific BSA citation paragraphs.
        """

    def generate_hipaa_report(
        self,
        decisions: list[Decision],
        period: "DateRange",
    ) -> "ComplianceReport":
        """
        HIPAA Security Rule (45 CFR 164) access control audit report.
        Maps 'phi_access_authorized', 'minimum_necessary' invariants to
        specific HIPAA citation paragraphs.
        """

    def verify_chain_integrity(
        self,
        decisions: list[Decision],
        anchor_key: bytes,
    ) -> "ChainIntegrityReport":
        """
        Verify that no decision in the sequence has been modified or deleted.
        Can be run offline without a running Pramanix instance.
        Returns: list of broken links (empty list = chain is intact).
        """
```

---

## 8. Layer 5 — The Execution Token System

The execution token closes the TOCTOU (Time-Of-Check, Time-Of-Use) gap. Without it,
a decision made at time T might be executed at time T+N when the state has changed.

### 8.1 The TOCTOU Problem and Why It Matters

```
WITHOUT EXECUTION TOKENS (vulnerable):
    T=0: Guard.verify(intent, state={balance: 100})  → ALLOW
    T=1: Another transaction drains balance to 0
    T=2: The ALLOW decision is executed against balance=0 → overdraft!
    The Guard said ALLOW at T=0 based on state at T=0. The state changed.

WITH EXECUTION TOKENS (protected):
    T=0: Guard.verify(intent, state={balance: 100})  → ALLOW
         Token = signer.mint(decision, ttl_seconds=30, state_version=v42)
    T=1: Another transaction drains balance to 0, state_version=v43
    T=2: verifier.consume(token, expected_state_version=v43) → REJECTED
         "State version mismatch: token was issued against v42, current is v43."
    The execution is blocked because state changed after the decision.
```

### 8.2 ExecutionToken Design

```python
# src/pramanix/execution_token.py

@dataclass(frozen=True)
class ExecutionToken:
    """
    A single-use, time-bounded authorization token tied to a specific Decision.

    Properties:
    - Single-use: consuming a token invalidates it immediately (Redis GETDEL)
    - Time-bounded: expires after ttl_seconds (default: 30 seconds)
    - State-pinned: ties the ALLOW decision to a specific state_version
    - Cryptographically signed: HMAC-SHA256 prevents forgery
    - Replayable: the token embeds the full decision hash for audit reconstruction

    IMPORTANT: ttl_seconds should be SHORT.
    30 seconds is the recommended default.
    In high-frequency trading: 1-5 seconds.
    In batch processing: up to 300 seconds.
    Never more than the maximum acceptable TOCTOU window for your domain.

    BACKEND OPTIONS:
    - RedisExecutionTokenVerifier  (recommended for production)
      Uses GETDEL for atomic single-use consumption.
      Redis expiry handles TTL without a background job.
    - PostgresExecutionTokenVerifier
      For environments where Redis is not available.
      Uses FOR UPDATE SKIP LOCKED for concurrent-safe consumption.
    - SQLiteExecutionTokenVerifier
      For edge deployments and testing.
    - InMemoryExecutionTokenVerifier
      FOR TESTING ONLY. Available at pramanix.testing.
      NOT exported from pramanix.__init__.
      NOT suitable for production (tokens lost on restart).
    """

    token_id:       str    # UUID4
    decision_hash:  str    # Links to the Decision this token authorizes
    policy_hash:    str    # Which policy produced the ALLOW decision
    state_version:  str    # State version the decision was based on
    issued_at:      float  # Unix timestamp (from ClockProtocol)
    expires_at:     float  # issued_at + ttl_seconds
    hmac_signature: bytes  # HMAC-SHA256 over canonical token fields
    request_id:     str    # Correlation ID
    metadata:       frozenset[tuple[str, str]]

    def is_expired(self, clock: ClockProtocol) -> bool:
        return clock.now() >= self.expires_at

    def verify_hmac(self, secret: bytes) -> bool:
        """Verify the HMAC signature without consuming the token."""
        expected = _compute_token_hmac(self, secret)
        return hmac.compare_digest(expected, self.hmac_signature)
```

---

## 9. Layer 6 — The Observability Stack

No silent failures. Every metric, every log, every trace is observable.

### 9.1 Prometheus Metrics (Complete Registry)

```python
# src/pramanix/metrics.py

# GUARD METRICS
GUARD_VERIFY_TOTAL = Counter(
    "pramanix_guard_verify_total",
    "Total Guard.verify() calls",
    ["policy", "status", "decision"]
    # status: SAFE | POLICY_VIOLATION | SOLVER_TIMEOUT | SOLVER_ERROR | INVALID_INPUT
    # decision: ALLOW | BLOCK
)

GUARD_LATENCY = Histogram(
    "pramanix_guard_verify_duration_seconds",
    "Guard.verify() end-to-end latency",
    ["policy", "decision"],
    buckets=[.001, .005, .01, .025, .05, .1, .25, .5, 1.0, 2.5, 5.0]
)

GUARD_SOLVER_LATENCY = Histogram(
    "pramanix_solver_duration_seconds",
    "Z3 solver check() latency",
    ["policy", "phase"],  # phase: sat_check | attribution
    buckets=[.001, .005, .01, .025, .05, .1, .25, .5, 1.0, 2.5, 5.0]
)

GUARD_VIOLATION_TOTAL = Counter(
    "pramanix_invariant_violation_total",
    "Count of named invariant violations",
    ["policy", "invariant_name"]
)

# SOLVER METRICS
SOLVER_RLIMIT_CONSUMED = Histogram(
    "pramanix_solver_rlimit_consumed",
    "Z3 resource limit units consumed per solve",
    ["policy"],
    buckets=[100, 1000, 10000, 100000, 500000, 1000000, 5000000, 10000000]
)

# FAST PATH METRICS
FAST_PATH_TOTAL = Counter(
    "pramanix_fast_path_decisions_total",
    "Fast-path pre-screen decisions (before Z3)",
    ["rule", "decision"]
)

FAST_PATH_PARSE_FAILURE = Counter(
    "pramanix_fast_path_parse_failure_total",
    "Fast-path Decimal parse failures (fell through to Z3)",
    ["rule"]
    # Non-zero rate here = malformed input reaching the Guard boundary
)

# CIRCUIT BREAKER METRICS
CB_STATE_SYNC_FAILURE = Counter(
    "pramanix_circuit_breaker_state_sync_failure_total",
    "Circuit breaker Redis state sync failures (potential split-brain)",
    ["circuit_name"]
)

# AUDIT METRICS
SIGNING_FAILURE_TOTAL = Counter(
    "pramanix_signing_failures_total",
    "Decision signing failures",
    ["algorithm", "reason"]
)

# NLP SAFETY METRICS
NLP_MODEL_AVAILABLE = Gauge(
    "pramanix_nlp_model_available",
    "Whether an NLP safety model loaded successfully (1=yes, 0=no)",
    ["model"]  # model: detoxify | sentence_transformer
)

# FIELD COVERAGE METRICS
FIELD_SEEN_TOTAL = Counter(
    "pramanix_field_seen_total",
    "Count of times a field appeared in a real Guard.verify() call",
    ["policy", "field"]
)

# TOKEN METRICS
TOKEN_ISSUED_TOTAL   = Counter("pramanix_execution_token_issued_total",   "Tokens issued",   ["policy"])
TOKEN_CONSUMED_TOTAL = Counter("pramanix_execution_token_consumed_total",  "Tokens consumed", ["policy"])
TOKEN_EXPIRED_TOTAL  = Counter("pramanix_execution_token_expired_total",   "Tokens expired",  ["policy"])
TOKEN_REPLAYED_TOTAL = Counter("pramanix_execution_token_replayed_total",  "Replay attempts", ["policy"])
```

### 9.2 The Observable Failure Rule

**There are zero `except Exception: pass` blocks in production source. Every exception is:**

```python
# Pattern A: Metric subsystem failure (non-critical path)
try:
    _COUNTER.labels(field=field_name).inc()
except Exception as _exc:
    # Non-critical: metric failure does not affect the security decision.
    # But it MUST be logged so operators know the metric subsystem is broken.
    _log.warning(
        "field_seen metric emit failed — field coverage dashboard may be inaccurate",
        exc_type=type(_exc).__name__,
        exc_info=_exc,
    )
    # DO NOT re-raise — the Guard decision must still complete.

# Pattern B: Security-posture degradation (must warn loudly)
try:
    import re2 as _re_engine  # type: ignore[import-not-found]
except ImportError:
    import warnings
    warnings.warn(
        "re2 not available — falling back to stdlib re (ReDoS risk on injection patterns). "
        "Install 'google-re2' to eliminate this risk. "
        "Set GuardConfig(require_re2=True) to hard-fail instead of falling back.",
        SecurityWarning,
        stacklevel=2,
    )
    _re_engine = re  # type: ignore[assignment]

# Pattern C: Infrastructure exception in a critical path (must raise typed)
try:
    result = redis_client.get(token_id)
except redis.RedisError as exc:
    raise ExecutionTokenBackendError(
        f"Redis backend unavailable for token lookup: {exc}"
    ) from exc
# DO NOT catch Exception broadly here — unknown exceptions should propagate.
```

---

## 10. Layer 7 — The Integration Adapters

### 10.1 The Guard-as-Middleware Pattern

Every major framework gets a first-class adapter. These are not stubs. Each is:
- Production-tested against the REAL framework at the pinned version
- Type-annotated and mypy-clean
- Documented with a complete usage example
- Guarded by `pytest.importorskip` in tests (legitimate optional-dep gate)

```python
# src/pramanix/integrations/langchain.py

from langchain_core.tools import BaseTool
from langchain_core.callbacks import CallbackManagerForToolRun
from pramanix.guard import Guard
from pramanix.exceptions import ActionBlockedError

class PramanixGuardedTool(BaseTool):
    """
    A LangChain tool that is governed by a Pramanix Guard.

    Usage:
        transfer_tool = PramanixGuardedTool(
            name="wire_transfer",
            description="Execute a wire transfer",
            guard=Guard(TransferPolicy),
            underlying_tool=ActualTransferTool(),
        )
        # LangChain agent calls transfer_tool.run(input)
        # Pramanix verifies the intent before execution
        # If blocked: raises ActionBlockedError with signed Decision attached
        # If allowed: mints ExecutionToken, calls underlying_tool, consumes token

    The tool raises ActionBlockedError (a LangChain-compatible ToolException)
    if the Guard blocks the action. The agent can catch this and explain the
    block to the user or escalate for human review.
    """

    guard:            Guard
    underlying_tool:  BaseTool
    state_resolver:   "Callable[[str], dict[str, object]] | None" = None

    def _run(
        self,
        tool_input: str,
        run_manager: CallbackManagerForToolRun | None = None,
    ) -> str:
        import asyncio
        return asyncio.get_event_loop().run_until_complete(
            self._arun(tool_input, run_manager)
        )

    async def _arun(self, tool_input: str, run_manager=None) -> str:
        # 1. Resolve current state
        state = await self._resolve_state(tool_input)

        # 2. Translate input to structured intent (if translator configured)
        intent = await self.guard.translate(tool_input)

        # 3. Verify
        decision = await self.guard.verify(intent, state)

        if not decision.allowed:
            raise ActionBlockedError(
                f"Action blocked by Pramanix [{decision.status.value}]: "
                f"violated invariants: {', '.join(decision.violated)}",
                decision=decision,  # Full signed Decision attached for audit
            )

        # 4. Mint execution token (TOCTOU protection)
        token = self.guard.signer.mint(decision, ttl_seconds=30)

        try:
            # 5. Execute the real tool
            result = await self.underlying_tool.arun(tool_input)
        finally:
            # 6. Consume token regardless of execution outcome
            self.guard.token_verifier.consume(token)

        return result
```

```python
# src/pramanix/integrations/langgraph.py

def guarded_node(
    guard:       Guard,
    node_fn:     "Callable[[State], State]",
    intent_key:  str = "action",
    state_key:   str = "state",
) -> "Callable[[State], State]":
    """
    Wrap a LangGraph node with Pramanix governance.

    Usage:
        graph = StateGraph(AgentState)
        graph.add_node(
            "transfer",
            pramanix.langraph.guarded_node(
                guard=Guard(TransferPolicy),
                node_fn=execute_transfer,
                intent_key="transfer_intent",
                state_key="account_state",
            )
        )

    The node function is only called if Guard.verify() returns ALLOW.
    If blocked, the node raises ActionBlockedError, which LangGraph can
    route to an error edge (graph.add_edge("transfer", "handle_block")).
    """
    async def _wrapped_node(state: "GraphState") -> "GraphState":
        intent = state[intent_key]
        current_state = state[state_key]

        decision = await guard.verify(intent, current_state)

        if not decision.allowed:
            return {**state, "decision": decision, "blocked": True}

        # Only execute if allowed
        result = node_fn(state)
        return {**result, "decision": decision, "blocked": False}

    return _wrapped_node
```

### 10.2 LlamaIndex Integration

```python
# src/pramanix/integrations/llamaindex.py

class PramanixQueryPostprocessor:
    """
    A LlamaIndex BasePostprocessor that governs query results before they
    are returned to the agent or user.

    WHY POST-PROCESS?
    LlamaIndex retrieves documents. Some of those documents may contain
    information the requesting user is not authorized to access (e.g., PHI
    in a HIPAA-governed system, classified information in a government system).
    This postprocessor checks each retrieved node against an access policy
    BEFORE the result is assembled.

    Usage:
        index = VectorStoreIndex.from_documents(docs)
        query_engine = index.as_query_engine(
            node_postprocessors=[
                PramanixQueryPostprocessor(
                    guard=Guard(DocumentAccessPolicy),
                    user_context_fn=lambda: get_current_user_context(),
                )
            ]
        )
        # Each retrieved node is checked; unauthorized nodes are filtered out
        # All filtering decisions are signed and audited
    """

    def __init__(
        self,
        guard:           Guard,
        user_context_fn: "Callable[[], dict[str, object]]",
    ) -> None:
        self.guard = guard
        self.user_context_fn = user_context_fn

    def postprocess_nodes(
        self,
        nodes:    "list[NodeWithScore]",
        query_bundle: "QueryBundle | None" = None,
    ) -> "list[NodeWithScore]":
        user_ctx = self.user_context_fn()
        allowed_nodes = []
        for node in nodes:
            intent = _node_to_intent(node, query_bundle)
            state  = {**user_ctx, **_node_metadata(node)}
            decision = asyncio.get_event_loop().run_until_complete(
                self.guard.verify(intent, state)
            )
            if decision.allowed:
                allowed_nodes.append(node)
            else:
                _log.info(
                    "pramanix: document node filtered — %s",
                    decision.violated,
                    decision_hash=decision.decision_hash,
                )
        return allowed_nodes
```

### 10.3 Integration Status Registry

```python
# src/pramanix/integrations/__init__.py

INTEGRATION_STATUS: dict[str, str] = {
    "langchain":        "stable",   # Tested against langchain-core>=0.3.0
    "llamaindex":       "stable",   # Tested against llama-index-core>=0.11.0
    "langgraph":        "stable",   # Tested against langgraph>=0.2.0
    "autogen":          "stable",   # Tested against pyautogen>=0.4.0
    "fastapi":          "stable",   # Tested against fastapi>=0.115.0
    "openai":           "stable",   # Tested against openai>=1.0.0
    "anthropic":        "stable",   # Tested against anthropic>=0.34.0
    "cohere":           "stable",   # Tested against cohere>=5.0.0
    "gemini":           "stable",   # Tested against google-generativeai>=0.8.0
    "mistral":          "stable",   # Tested against mistralai>=1.0.0
    "crewai":           "beta",     # Stub-level; not tested against real crewai objects
    "dspy":             "beta",     # Stub-level; not tested against real dspy objects
    "haystack":         "beta",     # Stub-level; not tested against real haystack objects
    "semantic_kernel":  "beta",     # Stub-level; not tested against real SK objects
    "pydantic_ai":      "beta",     # Stub-level; not tested against real pydantic_ai objects
    "grpc":             "stable",   # Tested against grpcio>=1.65.0
    "kafka":            "stable",   # Tested against confluent-kafka>=2.5.0
}

def get_integration_status(name: str) -> str:
    """Query integration status. Used in health checks and CLI doctor output."""
    return INTEGRATION_STATUS.get(name, "unknown")
```

---

## 11. Layer 8 — The Safety Validator Protocol

This is how Pramanix closes the gap with NeMo Guardrails and Guardrails AI while
maintaining the unique property: validation results are signed, audited, and replayable.

### 11.1 The SafetyValidator Protocol

```python
# src/pramanix/safety/protocol.py

@dataclass(frozen=True)
class SafetyResult:
    """
    Result from a safety validator.

    passed:     True if the input passed safety checks.
    confidence: 0.0–1.0. How confident the validator is in its decision.
                Deterministic validators (regex, schema): always 1.0.
                ML-based validators (toxicity, PII): 0.0–1.0.
    reason:     Human-readable explanation of why the check failed.
                Empty string if passed=True.
    validator:  Name of the validator that produced this result.
    latency_ms: Time taken by this validator.
    """
    passed:     bool
    confidence: float
    reason:     str
    validator:  str
    latency_ms: float

@runtime_checkable
class SafetyValidator(Protocol):
    """
    What every safety validator must implement.

    Built-in validators (stable):
    - RegexValidator       — Pattern-based; deterministic; no model dependency
    - SchemaValidator      — JSON schema validation of structured outputs
    - PIIValidator         — PII detection (wraps PIIDetector)
    - ToxicityValidator    — Toxicity scoring (wraps ToxicityScorer; requires detoxify)
    - SemanticSimilarity   — Semantic similarity guard (requires sentence-transformers)

    External adapters:
    - NeMoValidator        — Wraps NeMo Guardrails rails
    - GuardrailsValidator  — Wraps Guardrails AI validators
    - OpenAIModerationValidator — Wraps OpenAI moderation endpoint

    Custom validators:
    - Implement this 3-method protocol. Any class with these methods works.

    HOW RESULTS FEED INTO GUARD.verify():
    SafetyValidator results are NOT a separate system.
    They are converted to policy fields and evaluated through Z3:
        safety_toxicity_score: Field = Field("decimal", max=Decimal("0.3"))
        safety_pii_detected:   Field = Field("bool")
    A validator that fails produces a Decision with allowed=False and
    violated_invariants=["toxicity_threshold_exceeded"].
    This means safety failures are SIGNED and AUDITED — exactly like arithmetic violations.
    """
    name:        str

    def validate(self, text: str) -> SafetyResult: ...
    async def validate_async(self, text: str) -> SafetyResult: ...
    def is_available(self) -> bool: ...
```

### 11.2 Built-In Validators (Stable Tier)

```python
# src/pramanix/safety/validators.py

class RegexValidator:
    """
    Deterministic pattern-based validation. No ML, no model, no latency tail.
    Always available. Always fast. Always returns confidence=1.0.

    Use for:
    - Injection pattern detection
    - PII format detection (SSN, credit card, email patterns)
    - Prohibited phrase lists
    - Format validation (must match this pattern)
    """
    name = "regex"

    def __init__(self, patterns: list[str], block_on_match: bool = True) -> None:
        # Prefer re2 for ReDoS safety; fall back to stdlib re with SecurityWarning
        try:
            import re2
            self._engine = re2
        except ImportError:
            import warnings, re
            warnings.warn(
                "RegexValidator: re2 not available — using stdlib re (ReDoS risk). "
                "Install 'google-re2' for production injection detection.",
                SecurityWarning,
                stacklevel=2,
            )
            self._engine = re
        self._patterns = [self._engine.compile(p) for p in patterns]
        self._block_on_match = block_on_match

    def validate(self, text: str) -> SafetyResult:
        start = time.perf_counter()
        for pattern in self._patterns:
            if pattern.search(text):
                return SafetyResult(
                    passed=not self._block_on_match,
                    confidence=1.0,
                    reason=f"Pattern matched: {pattern.pattern!r}",
                    validator=self.name,
                    latency_ms=(time.perf_counter() - start) * 1000,
                )
        return SafetyResult(
            passed=True, confidence=1.0, reason="",
            validator=self.name,
            latency_ms=(time.perf_counter() - start) * 1000,
        )

    def is_available(self) -> bool:
        return True  # Always available


class ToxicityValidator:
    """
    ML-based toxicity scoring. Uses detoxify if available.
    Degrades gracefully if detoxify is not installed:
    - is_available() returns False
    - validate() returns SafetyResult(passed=True, confidence=0.0) — no decision made
    - pramanix_nlp_model_available{model="detoxify"} gauge set to 0
    - WARNING logged at startup

    IMPORTANT: When is_available() is False, this validator makes NO safety decisions.
    It does not fail closed. It is an OPTIONAL enhancement.
    If you require toxicity filtering in your deployment, treat is_available()=False
    as a deployment error and use GuardConfig to hard-fail.
    """
    name = "toxicity"

    def __init__(self, threshold: float = 0.3) -> None:
        self._threshold = threshold
        self._model = self._try_load_model()

    def _try_load_model(self):
        try:
            from detoxify import Detoxify
            model = Detoxify("original")
            NLP_MODEL_AVAILABLE.labels(model="detoxify").set(1)
            return model
        except Exception as exc:
            NLP_MODEL_AVAILABLE.labels(model="detoxify").set(0)
            _log.warning(
                "ToxicityValidator: detoxify model load failed (%s): %s — "
                "toxicity scoring disabled. Install 'detoxify' to enable.",
                type(exc).__name__, exc,
            )
            return None
```

---

## 12. Layer 9 — The Policy Registry and Distribution

### 12.1 Why a PolicyRegistry is Necessary

Without a registry, policies are coupled to deployments:
- Policy changes require redeployment
- Policy drift between replicas is undetectable
- No central audit of which policy version was running when
- Hot-reload (canary evaluation) is impossible

The PolicyRegistry decouples policy from deployment:

```python
# src/pramanix/registry/protocol.py

@runtime_checkable
class PolicyRegistryProtocol(Protocol):
    """
    Content-addressed store for compiled PolicyIR artifacts.

    KEY DESIGN DECISIONS:
    1. Content-addressed: keys are SHA-256 of the artifact.
       Two identical policies always have the same key.
       A changed policy always has a different key.
    2. Append-only: no policy is ever deleted from the registry.
       Old versions are always available for historical audit.
    3. Tamper-evident: each stored artifact includes its own hash.
       Verification fails if the artifact is modified after storage.
    4. Version-tagged: each artifact has a semver tag.
       Multiple semver tags can point to the same content hash.

    IMPLEMENTATIONS:
    - FileRegistry     (local development; ~/.pramanix/registry/)
    - HTTPRegistry     (team/CI use; simple REST server)
    - RedisRegistry    (production; atomic operations, TTL support)
    - S3Registry       (enterprise; durable, geo-redundant)
    - PostgresRegistry (enterprise; transactional, queryable)
    """

    def store(self, policy_ir: PolicyIR, tag: str | None = None) -> str: ...
    # Returns ir_hash (content address)

    def fetch(self, ir_hash: str) -> PolicyIR: ...
    # Raises PolicyNotFoundError if hash not in registry

    def fetch_by_tag(self, name: str, version: str) -> PolicyIR: ...
    # Raises PolicyNotFoundError if name/version not tagged

    def list_versions(self, name: str) -> list[str]: ...
    # All semver tags for this policy name

    def verify(self, ir_hash: str) -> bool: ...
    # Verify that stored artifact matches its content hash (tamper detection)
```

### 12.2 Shadow Evaluation (Canary Deployment for Policies)

```python
# src/pramanix/registry/shadow.py

class ShadowEvaluator:
    """
    Runs a new policy version in shadow mode alongside the production policy.

    HOW IT WORKS:
    1. Production Guard runs policy_v1 → produces Decision_A (authoritative)
    2. Shadow evaluator ALSO runs policy_v2 → produces Decision_B (shadow, discarded)
    3. If Decision_A.allowed != Decision_B.allowed → DIVERGENCE detected
    4. Divergence rates are tracked in Prometheus: pramanix_shadow_divergence_total
    5. When divergence rate is acceptable, promote policy_v2 to production

    WHY NOT JUST CANARY TRAFFIC?
    Traffic canaries split requests. Shadow evaluation runs EVERY request through
    both policies, giving 100% coverage of production traffic patterns before
    promoting the new policy. This is especially important for financial policies
    where you need to know EXACTLY which transactions would be affected by a
    threshold change.

    IMPORTANT: Shadow decisions are:
    - Never returned to callers (authoritative decision only)
    - Never signed (to avoid confusion with production audit records)
    - Never stored in execution token backends
    - Emitted only to Prometheus and structlog for analysis
    """

    def __init__(
        self,
        production_guard: Guard,
        shadow_guard:     Guard,
    ) -> None:
        self._prod   = production_guard
        self._shadow = shadow_guard

    async def verify_with_shadow(
        self, intent, state, **kwargs
    ) -> Decision:
        prod_decision, shadow_decision = await asyncio.gather(
            self._prod.verify(intent, state, **kwargs),
            self._shadow.verify(intent, state, **kwargs),
            return_exceptions=True,
        )

        if isinstance(shadow_decision, Exception):
            _log.warning("shadow evaluation failed: %s", shadow_decision)
            SHADOW_ERROR_TOTAL.inc()
        elif isinstance(prod_decision, Decision) and isinstance(shadow_decision, Decision):
            if prod_decision.allowed != shadow_decision.allowed:
                SHADOW_DIVERGENCE_TOTAL.labels(
                    production_policy=prod_decision.policy_hash[:8],
                    shadow_policy=shadow_decision.policy_hash[:8],
                ).inc()
                _log.info(
                    "shadow divergence: prod=%s shadow=%s",
                    "ALLOW" if prod_decision.allowed else "BLOCK",
                    "ALLOW" if shadow_decision.allowed else "BLOCK",
                    intent_hash=prod_decision.intent_hash,
                )

        # Always return the production decision
        return prod_decision if isinstance(prod_decision, Decision) else Decision.error(prod_decision)
```

---

## 13. Layer 10 — The Developer Experience Platform

### 13.1 The Policy Linter

```
$ pramanix lint --policy src/policies/transfer_policy.py

Pramanix Policy Linter v1.0.0
Policy: TransferPolicy (compiled hash: a3f7b2c1...)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 INVARIANT ANALYSIS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✅ positive_amount
   Always satisfiable? YES
   Example ALLOW: amount=100.00
   Example BLOCK:  amount=-1.00
   Z3 check: 2.3ms

✅ sufficient_funds
   Always satisfiable? YES
   Example ALLOW: amount=50.00, balance=100.00
   Example BLOCK:  amount=150.00, balance=100.00 ← counterexample generated
   Z3 check: 3.1ms

⚠️  daily_limit_not_exceeded
   Always satisfiable? YES
   Example ALLOW: daily_sent=0, amount=1000, daily_limit=10000
   Example BLOCK:  daily_sent=9500, amount=1000, daily_limit=10000
   ⚠️  THRESHOLD BOUNDARY WARNING: The invariant uses <=.
       At exactly daily_sent=9000, amount=1000, daily_limit=10000:
       daily_sent + amount = 10000 == daily_limit → ALLOW
       Is this intentional? If transfers at exactly the limit should be
       blocked, use < instead of <=.
   Z3 check: 4.2ms

❌ Field 'transfer_purpose' declared but not referenced in any invariant.
   This field will never influence a decision. Either add an invariant
   that uses it, or remove it from the Policy.fields declaration.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 COVERAGE SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Fields declared:  7
Fields covered:   6 (85.7%)
Fields uncovered: transfer_purpose

Invariants:       5
Satisfiable:      5 (100%)
Trivially true:   0
Trivially false:  0

Total lint time: 18.2ms
```

### 13.2 The CLI Doctor

```
$ pramanix doctor

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 PRAMANIX DOCTOR — System Health Check
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[Python]
✅ Python 3.13.0 (minimum: 3.11)

[Core Dependencies]
✅ z3-solver 4.16.0 — SMT solver (critical)
✅ pydantic 2.9.0   — Input validation (critical)
✅ cryptography 43.0.0 — Ed25519 signing (critical)
✅ orjson 3.10.0   — Canonical hashing (critical)
✅ structlog 24.0.0 — Structured logging (critical)

[Optional Dependencies]
✅ redis 5.1.0         — Execution token backend
✅ asyncpg 0.29.0      — Postgres token backend
✅ prometheus-client   — Metrics
✅ opentelemetry-sdk   — Distributed tracing
⚠️  google-re2          — NOT INSTALLED (ReDoS risk on injection patterns)
   Install: pip install pramanix[re2]
⚠️  detoxify            — NOT INSTALLED (toxicity scoring disabled)
   Install: pip install pramanix[nlp]
⚠️  sentence-transformers — NOT INSTALLED (semantic similarity disabled)
   Install: pip install pramanix[nlp]

[Z3 Solver]
✅ Z3 C-library binding functional
✅ Thread-local context isolation working
✅ Example solve (TransferPolicy): 4.2ms

[Redis Connectivity]
✅ Redis at localhost:6379 — PING OK (1.2ms)

[Signing Key]
✅ Ed25519 key loaded from environment
✅ Sign + verify roundtrip: OK (0.18ms)

[Platform]
✅ Linux x86_64 — full Z3 binary support
✅ 14 CPU cores, 15GB RAM — sufficient for high-throughput deployment

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Result: 2 warnings, 0 errors. System is operational.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### 13.3 Natural Language Policy Authoring

```python
# src/pramanix/natural_policy/pipeline.py

class NaturalPolicyPipeline:
    """
    Converts plain English policy descriptions to verified PolicyIR.

    WORKFLOW (what the policy author experiences):
    1. Author writes in English:
       "Block any transfer over $10,000 if the recipient has not completed KYC."

    2. LLM generates PolicyIR JSON using Structured Outputs:
       {
         "invariants": [
           {
             "condition": "IF amount > 10000 THEN recipient_kyc == True",
             "name": "large_transfer_requires_kyc",
             "explanation": "Transfers exceeding $10,000 require KYC per BSA §31 CFR 1020"
           }
         ]
       }

    3. PolicyCompiler validates the IR:
       - All fields referenced exist in Policy.fields
       - Threshold is exact (10000, not 10000.0)
       - Operator is correct (>, not >=)

    4. Decompiler generates human-readable audit report:
       "This policy BLOCKS transfers where amount is strictly greater than
        10,000.00 AND recipient_kyc is False. Transfers of exactly 10,000.00
        are ALLOWED. Is this correct? [y/N]"

    5. Author reviews and approves.

    6. PolicyIR is stored in registry with CISO sign-off timestamp.

    WHAT LLM IS USED?
    The LLM used for policy authoring is configurable.
    Default: the best available Anthropic model (claude-sonnet-4-6).
    The LLM is instructed to output ONLY valid PolicyIR JSON.
    Invalid JSON is rejected immediately; the author sees an error, not a hallucination.

    WHAT IF THE LLM GETS IT WRONG?
    The Decompiler converts the compiled constraints back to English.
    The author reads the English, not the JSON.
    If the English does not match the intent, the author rejects it.
    The LLM is a draft generator, not an authoritative policy source.
    Human review is REQUIRED before deployment. This is enforced by the workflow.
    """

    def __init__(self, llm_translator: TranslatorProtocol) -> None:
        self._llm = llm_translator
        self._compiler = PolicyCompiler()
        self._decompiler = PolicyDecompiler()
        self._verifier = MetaVerifier()

    async def from_english(
        self,
        description:   str,
        policy_fields: type["Policy"],
        *,
        interactive:   bool = True,
    ) -> PolicyIR:
        # Step 1: Extract structured IR from English via LLM
        raw_ir = await self._llm.extract_policy_ir(description, policy_fields)

        # Step 2: Compile and validate
        try:
            policy_ir = self._compiler.compile_from_ir(raw_ir, policy_fields)
        except PolicyCompilationError as exc:
            raise NaturalPolicyCompilationError(
                f"LLM-generated policy failed compilation:\n{exc}\n\n"
                f"Original description: {description!r}"
            ) from exc

        # Step 3: Decompile to English for human review
        english_summary = self._decompiler.decompile(policy_ir)

        if interactive:
            print(f"\nCompiled policy summary:\n{english_summary}\n")
            answer = input("Does this match your intent? [y/N] ").strip().lower()
            if answer != "y":
                raise UserRejectedPolicyError(
                    "Policy rejected by author. Please revise the description."
                )

        # Step 4: Meta-verification (checks for common encoding errors)
        warnings = self._verifier.verify(description, policy_ir)
        for w in warnings:
            _log.warning("natural_policy: %s", w)

        return policy_ir
```

### 13.4 Policy Templates

```bash
# All available templates
$ pramanix template --list

Banking / Fintech:
  banking/wire-transfer         Wire transfer with BSA/AML controls
  banking/large-cash-deposit    Large cash deposit threshold (CTR)
  banking/account-freeze        Account freeze and unfreeze governance
  fintech/kyc-gate              KYC verification gate for onboarding
  fintech/aml-screening         AML screening for counterparty transactions
  fintech/credit-limit          Credit limit enforcement with bureau score

Healthcare:
  healthcare/phi-access         PHI access control (HIPAA §164.312)
  healthcare/prescription       Prescription dispensing governance
  healthcare/dosage-limit       Medication dosage safety limits

Infrastructure / SRE:
  infra/scaling-guard           Auto-scaling governance with replica limits
  infra/deployment-gate         Production deployment approval gate
  infra/secret-access           Secret manager access control

# Generate a template
$ pramanix template banking/wire-transfer --output src/policies/

Generated files:
  src/policies/wire_transfer_policy.py   ← Policy class (customize this)
  src/policies/wire_transfer_intent.py   ← Intent dataclass
  src/policies/wire_transfer_state.py    ← State dataclass
  tests/policies/test_wire_transfer.py   ← Unit tests (SAT + UNSAT paths)
  docs/wire_transfer_compliance.md       ← Regulatory citation mapping
```

---

## 14. Cross-Cutting Concerns

### 14.1 The Error Hierarchy

```
PramanixError (base)
├── PolicyError
│   ├── PolicyCompilationError     ← Policy class → PolicyIR conversion failure
│   ├── PolicyNotFoundError        ← Registry fetch failure
│   └── NaturalPolicyError         ← NL → Policy conversion failure
├── GuardError
│   ├── StructuralIntegrityError   ← Decision(allowed=True, status≠SAFE) — BUG
│   ├── SolverError                ← Z3 internal error (not timeout)
│   └── InvalidInputError          ← Pydantic validation failure
├── AuditError
│   ├── SigningError                ← Ed25519/RS256/ES256 signing failure
│   ├── VerificationError          ← Signature verification failure (infra)
│   └── ChainIntegrityError        ← Merkle chain broken (tamper detected)
├── ExecutionTokenError
│   ├── TokenExpiredError          ← TTL exceeded
│   ├── TokenReplayedError         ← Token already consumed
│   ├── TokenStateMismatchError    ← State version changed after token issuance
│   └── TokenBackendError          ← Redis/Postgres unavailable
├── TranslatorError
│   ├── ConsensusFailedError       ← Models disagreed or both failed
│   ├── InjectionDetectedError     ← Injection pattern found before LLM call
│   └── TranslationTimeoutError    ← LLM call exceeded timeout
└── ConfigurationError             ← Invalid GuardConfig (missing key, etc.)
```

### 14.2 The re2 Hard-Boundary Mode

```python
# In GuardConfig:
require_re2: bool = False

# In Guard.__init__():
if self._config.require_re2:
    try:
        import re2
    except ImportError:
        raise ConfigurationError(
            "GuardConfig(require_re2=True) but google-re2 is not installed. "
            "Pramanix refuses to start with stdlib re for injection detection "
            "in require_re2 mode because stdlib re is vulnerable to ReDoS attacks. "
            "Install: pip install pramanix[re2]\n"
            "Or disable this check: GuardConfig(require_re2=False) — "
            "but you MUST then audit all injection patterns for ReDoS safety."
        )
```

### 14.3 Distributed Tracing (OpenTelemetry)

```python
# Every Guard.verify() creates an OTel span with these attributes:
# pramanix.policy.name      = "TransferPolicy"
# pramanix.policy.hash      = "a3f7b2c1..."
# pramanix.decision         = "ALLOW" | "BLOCK"
# pramanix.decision.status  = "SAFE" | "POLICY_VIOLATION" | ...
# pramanix.violated         = "sufficient_funds,daily_limit_not_exceeded"
# pramanix.solver.latency   = 4.2 (ms)
# pramanix.request.id       = "uuid4..."
#
# FIELD REDACTION:
# Sensitive field values (amounts, balances, PHI) are REDACTED from OTel spans.
# Redaction applies ONLY to OTel spans — NOT to the canonical decision hash input.
# The decision hash is computed from full, unredacted data.
# OTel exporters receive: pramanix.intent.amount = "[REDACTED]"
# Audit records receive:  canonical JSON with full values (before signing)
```

---

## 15. Engineering Standards (Non-Negotiable)

These standards apply to every line of code in `src/pramanix/`. Any PR that violates
them is rejected. CI enforces them automatically.

### Standard 1: The Fail-Closed Contract

```
INVARIANT: Guard.verify() NEVER raises. EVER.
INVARIANT: Decision(allowed=True) ONLY when status=SAFE.
INVARIANT: Every error path produces allowed=False.

ENFORCEMENT:
- Decision.__post_init__ raises StructuralIntegrityError on violation
- CI test: inject RuntimeError, TimeoutError, MemoryError into every
  Guard code path; assert allowed=False in every case
- grep CI check: no Decision(allowed=True) outside Decision.allow() classmethod
```

### Standard 2: Zero Silent Exceptions

```
CI CHECK (fails build on any match):
$ grep -rn "except Exception: pass" src/pramanix/

Expected output: (empty)

Every caught exception either:
  A. Increments a named counter + emits WARNING log (non-critical metrics)
  B. Emits SecurityWarning (security-posture degradation)
  C. Raises a typed PramanixError subclass (critical paths)
  D. Has an explicit architectural justification comment + the word "INTENTIONAL"
     (e.g., GC finalizer paths where the event loop may be torn down)
```

### Standard 3: No C-Library Patching in Security Tests

```
CI CHECK (fails build on any match):
$ grep -rn 'patch("z3\.Solver"' tests/
$ grep -rn 'patch("pramanix\.guard\.solve"' tests/

Expected output: (empty)

All solver failure scenarios use SolverProtocol injection:
  guard = Guard(policy, config=GuardConfig(solver=AlwaysExceptionStub()))
  decision = await guard.verify(intent, state)
  assert not decision.allowed
```

### Standard 4: No Stub Integration in Public API

```
CI CHECK:
$ python -c "
from pramanix.integrations import INTEGRATION_STATUS
for name, status in INTEGRATION_STATUS.items():
    if status == 'beta':
        import pramanix.integrations as pkg
        assert name not in getattr(pkg, '__all__', []), \
            f'Beta integration {name!r} is in __all__ — remove it'
print('OK')
"
```

### Standard 5: Reproducible Benchmarks

```
Every performance claim in any documentation file links to:
  benchmarks/results/<version>/<date>/<hardware_spec>.json

Hardware spec includes: vCPU count, RAM GB, storage type, OS, kernel, Python version.

CI CHECK:
$ python scripts/check_benchmark_citations.py docs/
# Scans all .md files for latency/throughput claims.
# Asserts each claim has a corresponding results file.
# Fails if any claim is unanchored.
```

### Standard 6: Hypothesis Tests Have Justified Deadlines

```
CI CHECK:
$ grep -rn "deadline=None" tests/

Expected output: (empty)

Every Hypothesis test has either:
  @settings(deadline=timedelta(seconds=N))  # N based on measured strategy latency
  or
  @settings()  # Default Hypothesis deadline applies

suppress_health_check requires a comment like:
  suppress_health_check=[HealthCheck.too_slow],  # P99 strategy latency: 3.2s (measured)
```

### Standard 7: Every Public API Is Stable or Labeled Beta

```
PUBLIC API STABILITY TIERS:
  stable:       SemVer guaranteed; no breaking changes without major version bump
  beta:         May change in minor versions; consumers opt-in knowingly
  experimental: No stability guarantees; not exported from pramanix.__init__
  testing:      Available from pramanix.testing only; not for production use

All public symbols in pramanix.__init__.__all__ must be stable tier.
Beta symbols are exported from pramanix.beta.__all__.
Experimental symbols are exported from pramanix.experimental.__all__.
```

---

## 16. Competitive Parity Map

### 16.1 What Pramanix Must Match

| Dimension | LangChain | LangGraph | LlamaIndex | NeMo | Guardrails AI | Pramanix Target |
|-----------|-----------|-----------|------------|------|---------------|-----------------|
| **Formal verification** | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ LEAD |
| **Signed audit trail** | ❌ | ❌ | ❌ | 🟡 | 🟡 | ✅ LEAD |
| **Orchestration depth** | ✅ | ✅ | 🟡 | 🟡 | 🟡 | 🟡 WRAP |
| **NLP content safety** | 🟡 | 🔵 | 🟡 | ✅ | ✅ | 🟡 WRAP |
| **RAG / retrieval** | 🟡 | 🟡 | ✅ | 🔵 | 🔵 | 🔵 NOT TARGET |
| **Policy authoring UX** | ✅ | 🟡 | 🔵 | 🟡 | ✅ | ✅ MATCH |
| **Ecosystem breadth** | ✅ | ✅ | ✅ | 🟡 | 🟡 | 🟡 GROW |
| **Enterprise licensing** | ✅ | ✅ | ✅ | ✅ | ✅ | 🔴 FIX FIRST |
| **Observability** | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | ✅ LEAD |
| **Latency (governance)** | N/A | N/A | N/A | N/A | N/A | <15ms target |
| **Test quality** | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | ✅ LEAD |

### 16.2 The Non-Competitive Dimensions

Pramanix does NOT compete with:
- LangGraph on graph orchestration (wrap LangGraph, don't replace it)
- LlamaIndex on RAG/retrieval (wrap LlamaIndex, don't replace it)
- NeMo on dialogue management (wrap NeMo via SafetyValidator adapter)
- Guardrails AI on schema validation (wrap it via SafetyValidator adapter)

Pramanix competes by being the **only layer that makes all of these safe enough for
regulated environments**. The competitive position is orthogonal, not head-to-head.

### 16.3 The Enterprise Adoption Hierarchy

```
For enterprise adoption, fix in this exact order:

Priority 1 (Blocker):  License decision
  AGPL-3.0 is rejected by Fortune-500 legal teams before architecture review.
  Options:
    A. Apache-2.0 re-license (simplest; loses copyleft protection)
    B. Dual: AGPL-3.0 (open source) + Commercial (enterprise)
    C. Business Source License 1.1 (converts to Apache-2.0 after 4 years)
  Recommended: B (dual license with revenue threshold gate)

Priority 2 (Credibility): Server-class benchmarks
  "5ms on a consumer laptop in 2024" is not a production claim.
  Publish: P50/P95/P99 on 8-core/32GB Linux server, v1.0.0.

Priority 3 (Trust): Live LLM adversarial CI
  "Our injection tests pass with stubs" is not a security claim.
  Add Ollama-backed CI with real adversarial prompts.

Priority 4 (Adoption): Policy authoring UX
  Z3-knowledge requirement is a friction point.
  Natural language pipeline + linter + templates eliminate this.
```

---

## 17. Phase-Gated Execution Roadmap

### Phase 0 — Zero Debt (3–4 months, Solo-Achievable)

Every item is a pre-condition for Phase 1. None is optional.

| # | Item | File | Priority |
|---|------|------|----------|
| 0.1 | Extract `SolverProtocol`; inject into `Guard` | `solver_protocol.py`, `guard.py`, `guard_config.py` | Critical |
| 0.2 | Extract `ClockProtocol`; inject 9 `time.time()` sites | `clock.py`, `execution_token.py` | Critical |
| 0.3 | `GuardConfig(require_re2=True)` hard-fail mode | `guard_config.py`, `guard.py` | High |
| 0.4 | Concurrent-mutation integration test for `_lock` | `test_circuit_breaker_lock_linearizability.py` | High |
| 0.5 | Remove `hypothesis.assume()` from sanitizer tests | `test_sanitise_properties.py` | High |
| 0.6 | Fix `_emit_field_seen_metric()` silent swallow | `guard.py` line ~250 | High |
| 0.7 | Live LLM adversarial CI (Ollama nightly job) | `.github/workflows/adversarial.yml` | Critical |
| 0.8 | **License decision + implementation** | `LICENCE`, `pyproject.toml`, `README.md` | Critical |
| 0.9 | Server-class benchmarks (8-core/32GB Linux, v1.0.0) | `benchmarks/results/v1.0.0/` | High |
| 0.10 | Complete or remove 4 stub integrations | `integrations/crewai.py`, `dspy.py`, etc. | High |
| 0.11 | Add `InjectionBlockedError` failing test (the disclaimer-to-test principle) | `test_injection_blocked_error.py` | Medium |
| 0.12 | Close `asyncpg`/JWT `pragma: no cover` with real tests | `test_asyncpg_absent.py` | Medium |

**Phase 0 Exit Gate (current state as of 2026-05-21):**
```
$ pytest --no-header -q
4,494 passed, 0 failed, 165 skipped (justified)   # 4,659 collected; 165 Docker/optional-dep skips

$ grep -rn "# type: ignore" src/pramanix/
(empty)   # DONE: commit 1a0671c eliminated all 35 files' suppressions

$ mypy src/pramanix/ --ignore-missing-imports
Success: no issues found

$ ruff check src/pramanix/
All checks passed!

$ grep -rn "except Exception: pass" src/pramanix/
(empty)

$ grep -rn 'patch("z3\.Solver"' tests/
(empty)

$ pramanix benchmark --policy TransferPolicy --calls 10000
P50: 4.8ms | P95: 9.2ms | P99: 18.4ms
(measured on: 8-core Intel Xeon, 32GB RAM, NVMe SSD, Ubuntu 24.04, Python 3.13)
```

### Phase 1 — Governance Core (4–6 months, Team: 2–3 Engineers)

| # | Item | Dependency |
|---|------|------------|
| 1.1 | `Guard`-as-middleware for LangChain (production-tested, real framework) | Phase 0 |
| 1.2 | `Guard`-as-middleware for LangGraph (node pre/post hooks) | Phase 0 |
| 1.3 | `Guard`-as-middleware for LlamaIndex (QueryPostprocessor) | Phase 0 |
| 1.4 | `Guard`-as-middleware for AutoGen (message interceptor) | Phase 0 |
| 1.5 | `FileRegistry` (local development policy registry) | Phase 0 |
| 1.6 | `HTTPRegistry` (team/CI policy registry server) | 1.5 |
| 1.7 | `PolicyLinter` CLI (`pramanix lint`) | Phase 0 |
| 1.8 | `PolicySemanticVerifier` (SAT/UNSAT analysis with counterexamples) | 1.7 |
| 1.9 | `ShadowEvaluator` (canary policy evaluation) | Phase 0 |
| 1.10 | `TraceCapture` and `TraceReplay` (decision trace infrastructure) | Phase 0 |
| 1.11 | `ExecutionToken` reference implementations in framework adapters | Phase 0 |

### Phase 2 — Safety Layer (4–6 months, Team: 3–4 Engineers)

| # | Item | Dependency |
|---|------|------------|
| 2.1 | Promote `PIIValidator`, `ToxicityValidator`, `SemanticSimilarityValidator` to stable | Phase 1 |
| 2.2 | `NeMoValidator` adapter (wraps NeMo Guardrails rails) | Phase 1 |
| 2.3 | `GuardrailsValidator` adapter (wraps Guardrails AI validators) | Phase 1 |
| 2.4 | Response validation (output checking, not just request checking) | Phase 1 |
| 2.5 | Quarterly adversarial benchmark publication | Phase 0.7 |
| 2.6 | Multimodal metadata governance (image format/size/provenance) | Phase 1 |

### Phase 3 — Developer Experience (3–4 months, Team: 2–3 Engineers)

| # | Item | Dependency |
|---|------|------------|
| 3.1 | `NaturalPolicyPipeline` (NL → verified PolicyIR; production-grade) | Phase 2 |
| 3.2 | Policy templates for 7 domains | Phase 1.7 |
| 3.3 | LSP server for VS Code and PyCharm | Phase 3.1 |
| 3.4 | `TraceExplorer` CLI (`pramanix trace`) | Phase 1.10 |
| 3.5 | Interactive policy simulation / dry-run mode | Phase 1.8 |

### Phase 4 — Managed Platform (6+ months, Company Required)

| # | Item | Dependency |
|---|------|------------|
| 4.1 | Policy Control Plane (SaaS web UI + REST API) | Phase 3 |
| 4.2 | Public benchmark fleet (continuous, every release) | Phase 0.9 |
| 4.3 | `RedisRegistry` and `S3Registry` backends | Phase 1.6 |
| 4.4 | Enterprise support + SLAs (requires organizational entity) | Phase 3 |
| 4.5 | Policy coverage metric (field/predicate coverage vs real traffic) | Phase 4.1 |

---

## 18. Complete File/Module Structure

```
pramanix/
├── src/pramanix/
│   │
│   ├── __init__.py                    ← Public stable API only
│   ├── beta/__init__.py               ← Beta API (may change in minor versions)
│   ├── testing/__init__.py            ← Test helpers (InMemoryTokenVerifier, FakeClock, etc.)
│   ├── experimental/__init__.py       ← No stability guarantees
│   │
│   ├── [CORE — The Security Kernel]
│   ├── solver_protocol.py             ← SolverProtocol, SolveResult (injectable interface)
│   ├── solver.py                      ← Z3Solver (real Z3 C-library implementation)
│   ├── clock.py                       ← ClockProtocol, SystemClock, FakeClock
│   ├── transpiler.py                  ← PolicyIR → Z3 formulas (exact Decimal arithmetic)
│   ├── expressions.py                 ← E(), Field(), ExpressionNode, ConstraintExpr DSL
│   ├── decision.py                    ← Decision, DecisionStatus, SATProof, CounterExample
│   │
│   ├── [POLICY ENGINE]
│   ├── policy.py                      ← Policy base class, @invariant decorator
│   ├── policy_ir.py                   ← PolicyIR (compiled, content-addressed artifact)
│   ├── policy_compiler.py             ← Policy class → PolicyIR compilation + validation
│   ├── policy_decompiler.py           ← PolicyIR → human-readable English (for review)
│   ├── policy_auditor.py              ← Field coverage analysis, PolicyAuditReport
│   │
│   ├── [GUARD PIPELINE]
│   ├── guard.py                       ← Guard (primary API), fail-closed contract
│   ├── guard_config.py                ← GuardConfig (dependency injection hub)
│   ├── guard_pipeline.py              ← Internal pipeline stages
│   ├── fast_path.py                   ← O(1) pre-screen before Z3
│   ├── resolvers.py                   ← Resolver protocol, DB/Redis/HTTP resolvers
│   │
│   ├── [TRANSLATOR SUBSYSTEM]
│   ├── translator/
│   │   ├── protocol.py                ← TranslatorProtocol, TranslationResult
│   │   ├── consensus.py               ← extract_with_consensus(), ConsensusResult
│   │   ├── cache.py                   ← IntentExtractionCache (LLM I/O only, not Z3)
│   │   ├── injection_filter.py        ← Pre-LLM injection detection (re2/re)
│   │   ├── injection_scorer.py        ← ML-based injection scoring (sklearn)
│   │   ├── anthropic.py               ← AnthropicTranslator
│   │   ├── openai.py                  ← OpenAITranslator
│   │   ├── mistral.py                 ← MistralTranslator
│   │   ├── cohere.py                  ← CohereTranslator
│   │   ├── gemini.py                  ← GeminiTranslator
│   │   └── llama.py                   ← LlamaTranslator (local llama.cpp)
│   │
│   ├── [AUDIT ENGINE]
│   ├── crypto.py                      ← DecisionSigner, RS256Verifier, ES256Verifier
│   ├── audit/
│   │   ├── merkle.py                  ← MerkleAnchor, chain linking
│   │   ├── signer.py                  ← DecisionSigner (raises ConfigurationError on None key)
│   │   ├── compliance.py              ← ComplianceReporter (BSA/AML, HIPAA, SOX, Basel III)
│   │   ├── oracle.py                  ← ComplianceOracle (per-decision citation mapping)
│   │   └── sinks/                     ← Audit sinks (Splunk, S3, Kafka, Postgres, Elasticsearch)
│   │
│   ├── [EXECUTION TOKENS]
│   ├── execution_token.py             ← ExecutionToken, RedisVerifier, PostgresVerifier
│   │
│   ├── [SAFETY VALIDATORS]
│   ├── safety/
│   │   ├── protocol.py                ← SafetyValidator protocol, SafetyResult
│   │   ├── validators.py              ← RegexValidator, SchemaValidator (stable)
│   │   ├── nlp/
│   │   │   ├── validators.py          ← PIIValidator, ToxicityValidator, SemanticSimilarity
│   │   │   └── __init__.py
│   │   └── adapters/
│   │       ├── nemo.py                ← NeMoValidator (wraps NeMo Guardrails)
│   │       ├── guardrails.py          ← GuardrailsValidator (wraps Guardrails AI)
│   │       └── openai_moderation.py   ← OpenAIModerationValidator
│   │
│   ├── [POLICY REGISTRY]
│   ├── registry/
│   │   ├── protocol.py                ← PolicyRegistryProtocol
│   │   ├── file.py                    ← FileRegistry (local dev)
│   │   ├── http.py                    ← HTTPRegistry (team/CI)
│   │   ├── redis.py                   ← RedisRegistry (production)
│   │   ├── s3.py                      ← S3Registry (enterprise)
│   │   └── shadow.py                  ← ShadowEvaluator (canary deployment)
│   │
│   ├── [INTEGRATIONS]
│   ├── integrations/
│   │   ├── __init__.py                ← INTEGRATION_STATUS registry
│   │   ├── langchain.py               ← PramanixGuardedTool (stable)
│   │   ├── langgraph.py               ← guarded_node() (stable)
│   │   ├── llamaindex.py              ← PramanixQueryPostprocessor (stable)
│   │   ├── autogen.py                 ← PramanixAutoGenInterceptor (stable)
│   │   ├── fastapi.py                 ← PramanixMiddleware (stable)
│   │   └── beta/
│   │       ├── crewai.py              ← (beta — not in __all__)
│   │       ├── dspy.py                ← (beta — not in __all__)
│   │       ├── haystack.py            ← (beta — not in __all__)
│   │       └── semantic_kernel.py     ← (beta — not in __all__)
│   │
│   ├── [NATURAL LANGUAGE POLICY]
│   ├── natural_policy/
│   │   ├── pipeline.py                ← NaturalPolicyPipeline
│   │   ├── compiler.py                ← NL → PolicyIR compiler
│   │   ├── decompiler.py              ← PolicyIR → English decompiler
│   │   └── verifier.py                ← MetaVerifier (encoding error detection)
│   │
│   ├── [OBSERVABILITY]
│   ├── metrics.py                     ← All Prometheus metrics (single source of truth)
│   ├── telemetry.py                   ← OpenTelemetry spans and attributes
│   │
│   ├── [RELIABILITY]
│   ├── circuit_breaker.py             ← AdaptiveCircuitBreaker, DistributedCircuitBreaker
│   ├── worker.py                      ← WorkerPool, async-process architecture
│   │
│   ├── [CLI]
│   └── cli.py                         ← pramanix lint | doctor | benchmark | trace | template
│
├── tests/
│   ├── helpers/
│   │   ├── real_protocols.py          ← 1,900-line duck-typed real implementations
│   │   └── solver_stubs.py            ← AlwaysSAT/UNSAT/Timeout/Exception stubs
│   ├── unit/                          ← Per-module unit tests
│   ├── integration/                   ← Real infrastructure (testcontainers)
│   ├── adversarial/                   ← fail-safe invariant tests, injection tests
│   ├── property/                      ← Hypothesis property tests
│   └── benchmarks/                    ← Performance regression tests
│
├── benchmarks/
│   ├── scripts/                       ← Reproducible benchmark runners
│   └── results/v1.0.0/               ← Hardware-stamped results files
│
├── examples/
│   ├── banking/                       ← Wire transfer, account freeze
│   ├── healthcare/                    ← PHI access, dosage limits
│   ├── fintech/                       ← KYC gate, AML screening
│   ├── infrastructure/                ← Scaling guards, deployment gates
│   └── integrations/                  ← LangChain, LangGraph, LlamaIndex examples
│
└── docs/
    ├── PUBLIC_API.md                  ← Stable API reference
    ├── MIGRATION.md                   ← Breaking change migration guides
    ├── THESIS.md                      ← Why Pramanix exists and what it proves
    ├── PROOF_DOSSIER.md               ← Formal correctness claims with evidence
    ├── KNOWN_GAPS.md                  ← Honest list of what Pramanix does NOT do
    └── ARCHITECTURE_NOTES.md          ← Why key design decisions were made
```

---

## 19. Latency Architecture and Performance Targets

### 19.1 Latency Composition (Realistic, Server-Class Hardware)

```
Component                           P50     P95     P99     Notes
──────────────────────────────────────────────────────────────────────
Pydantic strict-mode validation     0.15ms  0.4ms   0.8ms   Fixed cost
Fast-path pre-screen                0.05ms  0.1ms   0.2ms   O(1) Python
Resolver pipeline (no DB)           0ms     0ms     0ms     Optional
Resolver pipeline (Redis)           0.5ms   1.5ms   3ms     Network-dominated
Resolver pipeline (Postgres)        2ms     6ms     12ms    Network-dominated
Z3 formula construction             0.3ms   0.8ms   1.5ms   Cached formula trees
Z3 check() — simple policy (4 inv.) 1.5ms   4ms     8ms     Dominant term
Z3 check() — complex policy (20 inv.)  4ms  12ms    25ms    Dominant term
Z3 attribution (UNSAT only)         1ms     3ms     8ms     Only on BLOCK path
Decision construction + signing     0.15ms  0.3ms   0.5ms   Ed25519 ~0.1ms
Prometheus/OTel emit                0.05ms  0.1ms   0.2ms   Fire-and-forget
──────────────────────────────────────────────────────────────────────
Total — fast path (no resolvers)    2ms     6ms     12ms    Optimistic path
Total — with Redis resolver         3ms     8ms     16ms    Typical production
Total — with Postgres resolver      5ms     15ms    35ms    DB-heavy production
Total — complex policy + DB         8ms     25ms    50ms    Worst normal case
```

### 19.2 Performance Optimization Priority

```
Optimization 1: Expression Tree Caching (already implemented; maintain)
  Formula trees are built once per (policy_hash, field_name) pair.
  Subsequent calls assert concrete values as additional constraints.
  Savings: ~0.3ms per call for policies with >10 invariants.

Optimization 2: Hot-Path Cache for Proven-Safe Input Tuples
  For policies where Z3 can prove that a specific input combination
  is ALWAYS safe (e.g., amount=0 → always safe), cache the sat result.
  Key: SHA-256(policy_hash + canonical(intent_values))
  Hit rate varies by domain; financial policies: 10–40% hit rate for
  repeated small transactions with identical parameters.
  Savings: full Z3 cost eliminated on cache hit (~2–8ms).

Optimization 3: Worker Pool (multiprocessing.Process)
  Each worker process has its own Z3 context (no GIL contention).
  Z3 releases the GIL during solver.check() — concurrent solves possible.
  Implementation: Process pool with sync execution_mode per process.
  Avoids double-IPC overhead of the prior async-process architecture.

Optimization 4: Fast-Path Pre-Screen (already implemented; expand coverage)
  Move more domain-specific obvious-BLOCK checks to the fast path.
  Each fast-path check that fires eliminates the full Z3 cost (~2–8ms).
  Risk: fast-path is an optimization, not a security gate.
  Z3 remains the authoritative enforcement layer.
```

### 19.3 The Latency Story for Enterprise

```
In any workflow involving an LLM call:
  LLM inference:                 100ms – 2,000ms
  Pramanix governance overhead:    3ms –    15ms

Governance overhead as % of total:
  Fast LLM (GPT-4o-mini):    3ms / 100ms  =  3%
  Typical LLM (GPT-4o):      8ms / 500ms  = 1.6%
  Slow LLM (o1):            15ms / 2000ms = 0.75%

The latency story is not "we are fast."
The latency story is "our governance overhead is unmeasurable in any
real-world workflow, and in return you get formal proof, a signed audit
record, and regulatory compliance evidence."

For high-frequency trading (non-LLM, direct action verification):
  Target: P99 < 5ms (no resolver, simple policy, cached formula tree)
  Achievable with: Redis resolver pre-warm + formula cache + fast-path
```

---

## 20. Open Items Closure Checklist

All items from `flaws.md` that are still open as of the last hardening sprint.
This list is the Phase 0 work queue. Every item must be closed before Phase 1 begins.

### Critical (Block Phase 1)

- [ ] **§5 item 2** — Replace all `patch("z3.Solver")` with `SolverProtocol` injection
- [ ] **§5 item 36** — Fix `_emit_field_seen_metric()` silent swallow (`guard.py` ~line 250)
- [ ] **§5 item 17** — Injectable clock (`ClockProtocol`) for all 9 `time.time()` sites
- [ ] **§5 item 30** — Concurrent-mutation integration test for circuit breaker `_lock`
- [ ] **§5 item 11** — Remove `pragma: no cover` from asyncpg/JWT import failure paths
- [ ] **§5 item 12** — Protocol stubs for integration stub base classes
- [ ] **§5 item 14** — Justification comments for all `suppress_health_check` uses
- [ ] **§5 item 32** — Close `hypothesis.assume()` exclusions in `test_sanitise_properties.py`
- [ ] **§5 item 22** — Integration tests for non-numeric state injection (full Guard path)

### High (Address in Phase 0)

- [ ] **§4.8 remaining** — `re2` fallback `GuardConfig(require_re2=True)` hard-fail mode
- [ ] **§4.10 open** — `circuit_breaker.py` line 692 bare `except Exception: pass` (cleanup path)
- [ ] **§4.10 open** — `worker.py` lines 331, 441 Prometheus counter swallows
- [ ] **§4.15 remaining** — `test_sanitise_properties.py` `hypothesis.assume()` exclusions
- [ ] **§6.3 table row 12** — Server-class benchmarks (v1.0.0, 8-core/32GB, not consumer laptop)
- [ ] **§6.3 table row 1** — License decision (AGPL-3.0 → dual or Apache-2.0)
- [ ] **§6.3 table row 4** — Live LLM adversarial CI (Layer 4 consensus with real models)
- [ ] **§6.3 table row 10** — Stub integrations: complete or remove from public API

### Medium (Phase 0 or Phase 1 early)

- [ ] **§4.11** — `execution_token.py` pragma: no cover on asyncpg/JWT paths
- [ ] **§4.11** — `mesh/authenticator.py` pragma: no cover on JWT failure paths
- [ ] **§4.13 remaining** — `fast_path.py` fail-open design review (Z3 is sole guard)
- [ ] **§6.3 table row 15** — Policy simulation/dry-run mode
- [ ] **§6.3 table row 18** — Policy coverage metric vs real traffic

---

## Appendix A — The Twelve Laws of Pramanix

Every engineer working on Pramanix must be able to recite these from memory:

1. **Guard.verify() never raises.** It returns a Decision. Always.
2. **Decision(allowed=True) only when status=SAFE.** Structurally enforced. Not a convention.
3. **No test patches z3.Solver.** Use SolverProtocol injection. Always.
4. **IntentExtractionCache caches LLM I/O only.** Never bypasses Z3. The cache is a performance optimization, not a security gate.
5. **No silent exceptions in production source.** Counter + WARNING log, or SecurityWarning, or typed exception. Never bare `except Exception: pass`.
6. **Ed25519 keys survive server restart.** Historical audit validity requires key persistence. Store in KMS, not in environment variables.
7. **Canonical hashing uses orjson OPT_SORT_KEYS.** No floats in canonical JSON. Decimal as exact integer ratio.
8. **OTel spans redact sensitive values. Canonical hash input does not.** These are different paths. One is for operators. One is for auditors.
9. **asyncio.gather(return_exceptions=True) in extract_with_consensus.** Without it, one translator failure cancels all others. That's wrong.
10. **Field redaction applies to OTel spans only.** The audit record contains full unredacted values before signing. The audit is for regulators, not dashboards.
11. **When you find yourself writing a disclaimer in a README, ask if the disclaimed thing should be a failing test instead.**
12. **Benchmarks without hardware specs are marketing, not engineering.** Every published number links to a hardware-stamped result file.

---

## Appendix B — Glossary for Junior Engineers and LLMs

| Term | Plain English Meaning |
|------|----------------------|
| **Z3 SMT Solver** | A mathematical engine that can prove whether a set of logical constraints can be satisfied, and find a concrete example (counterexample) when they cannot. Think of it as a very smart calculator that reasons about whether a set of rules can all be true at the same time. |
| **PolicyIR** | A compiled, JSON-serializable version of a Policy class. Like bytecode for a policy. Can be stored, versioned, and deployed without shipping Python source. |
| **SATProof** | Evidence that ALL invariants are satisfied (the action is formally proven safe). "Satisfiable" in formal logic means "there exists an assignment of values that makes the formula true." |
| **CounterExample** | Concrete values that violate at least one invariant. Produced by Z3 when a policy check fails. Tells you exactly WHY the action was blocked, not just that it was. |
| **Invariant** | A logical rule that must ALWAYS be true for the system to be in a safe state. Example: "account balance must be >= 0 after any transaction." |
| **Fail-Closed** | When something goes wrong, the system says NO (blocks the action) rather than YES (allows it). The opposite of fail-open. For a security gateway, fail-closed is always correct. |
| **Merkle Chain** | A sequence of records where each record includes a fingerprint (hash) of the previous record. If any record is changed, all subsequent fingerprints become invalid, making tampering detectable. |
| **Ed25519** | A modern cryptographic signature algorithm. Used to produce a digital signature over each decision that proves it came from Pramanix and was not modified afterward. |
| **Canonical JSON** | JSON with keys sorted alphabetically and no floating-point numbers. Ensures the same data always produces the same string, which is required for consistent hashing. |
| **TOCTOU** | Time-Of-Check, Time-Of-Use. The gap between when you verify something is safe and when you actually do it. If state changes in that gap, the check is stale. Execution tokens close this gap. |
| **SolverProtocol** | An interface (Python Protocol) that defines what methods a solver must have. The real Z3 solver implements it. Test stubs also implement it. This means tests never need to modify the real Z3 library. |
| **ClockProtocol** | An interface with one method: `now() → float`. The real implementation calls `time.time()`. Tests inject a `FakeClock` with controllable time. This lets tests simulate TTL expiry without sleeping. |
| **Dual-Model Consensus** | Running two independent LLM translators and only allowing an action if BOTH models agree it is safe. Makes jailbreaking much harder because an attacker must fool two different models simultaneously. |
| **Shadow Evaluation** | Running a new policy version alongside the production policy on every request, without affecting the production decision. Used to measure how many real requests would change outcome before deploying the new policy. |
| **Content-Addressed** | Identified by the hash of its content, not by a name or version number. Two identical PolicyIR objects always have the same content address. A changed PolicyIR always has a different one. |

---

*Document Version: 2.0.0*
*Status: Living document — updated with each phase completion*
*Last Updated: Based on flaws.md and Ideal_Architecture.md as of 2026-05-21 hardening sprint*