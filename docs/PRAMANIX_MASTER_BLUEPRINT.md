# PRAMANIX — MASTER BUILD BLUEPRINT
## From Zero to Ideal, and Beyond
### The Complete Engineering Manual · Author's Edition

> **What this document is:** A brick-by-brick construction manual for building Pramanix
> from an empty directory to a system that answers one question with mathematical certainty:
>
> *"Was this AI action formally proven safe — before execution — and can I produce a signed,
> tamper-evident, regulator-readable proof of that right now, in under 15 milliseconds?"*
>
> No competitor answers this. This document tells you exactly how to build the machine that does.

---

## Table of Contents

1. [The Mental Foundation — Before You Write One Line](#1-mental-foundation)
2. [Repository Skeleton — Day One Structure](#2-repository-skeleton)
3. [Phase 0 — The Mathematical Kernel (Z3 Core)](#3-phase-0-mathematical-kernel)
4. [Phase 1 — The Policy Engine](#4-phase-1-policy-engine)
5. [Phase 2 — The Guard Pipeline](#5-phase-2-guard-pipeline)
6. [Phase 3 — The Cryptographic Audit Engine](#6-phase-3-audit-engine)
7. [Phase 4 — The Execution Token System](#7-phase-4-execution-tokens)
8. [Phase 5 — The Translator Subsystem](#8-phase-5-translator)
9. [Phase 6 — The Observability Stack](#9-phase-6-observability)
10. [Phase 7 — The Worker Architecture](#10-phase-7-workers)
11. [Phase 8 — Integration Adapters](#11-phase-8-integrations)
12. [Phase 9 — Safety Validators](#12-phase-9-safety-validators)
13. [Phase 10 — The Policy Registry](#13-phase-10-registry)
14. [Phase 11 — The Key Provider System](#14-phase-11-key-providers)
15. [Phase 12 — The Reliability Layer](#15-phase-12-reliability)
16. [Phase 13 — Developer Experience Platform](#16-phase-13-dx)
17. [Phase 14 — CI/CD, SLSA, Release Engineering](#17-phase-14-cicd)
18. [Phase 15 — Kubernetes Production Deployment](#18-phase-15-kubernetes)
19. [The Testing Doctrine — How to Test a Security Kernel](#19-testing-doctrine)
20. [The Observability Contract — Every Metric, Every Alert](#20-observability-contract)
21. [The Beyond — What Lies Above the Ideal](#21-beyond-the-ideal)
22. [The Build Order — Day by Day, Week by Week](#22-build-order)
23. [Common Mistakes and How to Avoid Them](#23-common-mistakes)
24. [Glossary — Every Concept, From First Principles](#24-glossary)

---

## 1. Mental Foundation — Before You Write One Line

### 1.1 The One Insight That Drives Everything

Most AI safety systems answer: "Does this look safe?" (heuristic, probabilistic, pattern-matched).

Pramanix answers: "Is this provably safe, and can I prove it?" (formal, deterministic, mathematical).

The difference is architectural. You are not building a classifier. You are building an **execution firewall** backed by an SMT solver. The consequences of this choice ripple through every decision you make:

- Tests cannot mock the solver (you need to know the C library works)
- Performance targets are tighter (the solver must be warm and isolated)
- Audit records are cryptographically signed (non-negotiable from day one)
- Every exception path must fail closed, not open

### 1.2 The Architectural Position (Memorize This)

```
┌─────────────────────────────────────────────────────────────┐
│  THE REAL WORLD                                              │
│  (bank accounts, patient records, infrastructure)           │
└─────────────────────┬───────────────────────────────────────┘
                      │  State mutations
     ◄── PRAMANIX GOVERNS THIS BOUNDARY ──►
┌─────────────────────┴───────────────────────────────────────┐
│  PRAMANIX — Formal Proof + Signed Audit Trail               │
│  Guard.verify(intent, state) → Decision (proven, signed)    │
└─────────────────────┬───────────────────────────────────────┘
     LangChain    LangGraph    LlamaIndex    NeMo    AutoGen
```

Pramanix **wraps** everything above it. It does not replace any of it. It is the gate every agent action must pass through before touching real-world state.

### 1.3 The Twelve Laws — Internalize Before Building

These are not guidelines. They are architectural invariants enforced by CI gates.

**Law 1** — `Guard.verify()` never raises. Ever. Any exception returns `Decision.error()` with `allowed=False`.

**Law 2** — `Decision(allowed=True)` requires `status=SAFE`. Enforced structurally in `__post_init__`. No code path circumvents this.

**Law 3** — No test patches `z3.Solver`. Inject `SolverProtocol` via `GuardConfig`. The CI gate rejects any PR that adds a `patch("z3.Solver")` call.

**Law 4** — `IntentExtractionCache` caches LLM I/O only. Z3 runs on every call, always.

**Law 5** — No silent exceptions. Every `except` clause: counter + WARNING log, or `SecurityWarning`, or typed re-raise, or an explicit `# INTENTIONAL` comment for GC finalizers.

**Law 6** — Signing keys survive server restart. KMS/Vault always. Never env vars.

**Law 7** — Canonical hash uses `orjson OPT_SORT_KEYS`. No floats. Exact Decimal ratios.

**Law 8** — OTel spans redact sensitive values. Canonical hash input does not. Different audiences.

**Law 9** — `asyncio.gather(return_exceptions=True)` in consensus. Always. Without it, one failure cancels everything.

**Law 10** — `ClockProtocol` in every time-sensitive path. No raw `time.time()` in production code.

**Law 11** — When you write a README disclaimer, write a failing test instead.

**Law 12** — Benchmarks without hardware specs are marketing.

---

## 2. Repository Skeleton — Day One Structure

### 2.1 Directory Layout

Create this exact structure before writing any logic code. Structure reflects architecture.

```
pramanix/
├── src/
│   └── pramanix/
│       ├── __init__.py              # Stable public API — NOTHING else exports here
│       ├── testing/
│       │   └── __init__.py          # InMemory test doubles ONLY live here
│       ├── beta/
│       │   └── __init__.py          # Beta integrations — minor-version change OK
│       └── experimental/
│           └── __init__.py          # No stability guarantees
│
├── tests/
│   ├── helpers/
│   │   ├── real_protocols.py        # Duck-typed real implementations (no MagicMock)
│   │   └── solver_stubs.py          # AlwaysSAT/UNSAT/Timeout/Exception [CRITICAL]
│   ├── unit/                        # Fast, isolated, no real infrastructure
│   ├── integration/                 # Real containers via testcontainers
│   ├── adversarial/                 # Injection, jailbreak, fail-safe tests
│   ├── property/                    # Hypothesis-based property tests
│   └── benchmarks/                  # Performance regression detection
│
├── benchmarks/
│   ├── scripts/                     # Reproducible benchmark runners
│   └── results/                     # v{version}/{date}/{hardware}.json
│
├── examples/
│   ├── banking/
│   ├── healthcare/
│   ├── fintech/
│   └── infrastructure/
│
├── docs/
│   ├── PUBLIC_API.md
│   ├── MIGRATION.md
│   ├── THESIS.md
│   ├── PROOF_DOSSIER.md
│   ├── KNOWN_GAPS.md
│   └── LICENSING.md
│
├── deploy/
│   ├── k8s/
│   │   ├── deployment.yaml
│   │   ├── hpa.yaml
│   │   └── networkpolicy.yaml
│   └── monitoring/
│       └── alerts.yaml
│
├── pyproject.toml
├── Dockerfile.dev
├── Dockerfile.production
└── .github/
    └── workflows/
        ├── ci.yml
        ├── release.yml
        └── adversarial.yml
```

### 2.2 `pyproject.toml` — The Complete Configuration

```toml
[build-system]
requires = ["poetry-core>=1.0.0"]
build-backend = "poetry.core.masonry.api"

[tool.poetry]
name = "pramanix"
version = "0.1.0"
description = "Formal AI governance — Z3-proven decisions, cryptographically signed audit trail"
authors = ["Your Name <you@example.com>"]
license = "AGPL-3.0-or-later"
readme = "README.md"
packages = [{ include = "pramanix", from = "src" }]

[tool.poetry.dependencies]
python = ">=3.11,<3.14"
z3-solver = ">=4.13.0"
pydantic = ">=2.0.0"
structlog = ">=24.0.0"
orjson = ">=3.9.0"
cryptography = ">=42.0.0"
httpx = ">=0.27.0"

[tool.poetry.extras]
redis    = ["redis"]
postgres = ["asyncpg"]
kafka    = ["confluent-kafka"]
metrics  = ["prometheus-client"]
otel     = ["opentelemetry-sdk", "opentelemetry-api"]
re2      = ["google-re2"]
nlp      = ["detoxify", "sentence-transformers"]
aws      = ["boto3"]
azure    = ["azure-keyvault-secrets", "azure-identity"]
gcp      = ["google-cloud-secret-manager"]
vault    = ["hvac"]
langchain = ["langchain-core>=0.3.0"]
langgraph = ["langgraph>=0.2.0"]
llamaindex = ["llama-index-core>=0.11.0"]
all      = ["pramanix[redis,postgres,kafka,metrics,otel,re2,nlp,aws,langchain,langgraph,llamaindex]"]

[tool.poetry.group.dev.dependencies]
pytest = ">=8.0.0"
pytest-asyncio = ">=0.23.0"
pytest-cov = ">=5.0.0"
hypothesis = {version = ">=6.100.0", extras = ["cli"]}
respx = ">=0.21.0"
testcontainers = {version = ">=4.0.0", extras = ["redis", "kafka", "postgres"]}
mypy = ">=1.9.0"
ruff = ">=0.4.0"

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]
filterwarnings = [
    "error",   # ALL warnings are errors by default — intentional strictness
    "ignore::pramanix.exceptions.SecurityWarning",  # log it, don't fail CI
    "ignore::DeprecationWarning:google",
    "ignore::DeprecationWarning:cohere",
]

[tool.coverage.run]
source = ["pramanix"]
branch = true

[tool.coverage.report]
fail_under = 98
exclude_lines = [
    "if TYPE_CHECKING:",
    "if __name__ == .__main__.",
    "@overload",
    "# INTENTIONAL",  # Only GC-path bare-pass blocks
]

[tool.mypy]
strict = false
ignore_missing_imports = true
no_implicit_optional = true

[tool.ruff]
line-length = 100
select = ["E", "F", "W", "N", "B", "PGH003", "TCH"]
```

### 2.3 The First File — `src/pramanix/exceptions.py`

Write this first. Every other module imports from it. Having it first prevents circular imports.

```python
# src/pramanix/exceptions.py

from __future__ import annotations


class SecurityWarning(UserWarning):
    """
    Security-posture downgrade warning.

    NOT a Python built-in in any Python version.
    Defined unconditionally here. Import from this module everywhere.
    Never redefine conditionally (see: the NameError disaster on Python 3.13).
    """


class PramanixError(Exception):
    """Base for all Pramanix exceptions."""


# ── Policy Errors ─────────────────────────────────────────────────────────
class PolicyError(PramanixError): ...
class PolicyCompilationError(PolicyError): ...
class PolicyNotFoundError(PolicyError): ...
class NaturalPolicyCompilationError(PolicyError): ...
class UserRejectedPolicyError(PolicyError): ...


# ── Guard / Configuration Errors ──────────────────────────────────────────
class GuardError(PramanixError): ...
class StructuralIntegrityError(GuardError):
    """Decision(allowed=True, status≠SAFE) — always a bug in Guard internals."""
class InvalidInputError(GuardError): ...
class ResolverError(GuardError): ...
class ConfigurationError(GuardError): ...


# ── Action Blocking ────────────────────────────────────────────────────────
class ActionBlockedError(PramanixError):
    def __init__(self, message: str = "", decision=None) -> None:
        super().__init__(message)
        self.decision = decision


class InjectionDetectedError(ActionBlockedError):
    def __init__(self, decision, pattern_matched: str = "") -> None:
        super().__init__(
            f"Prompt injection detected. Pattern: {pattern_matched!r}",
            decision=decision,
        )
        self.pattern_matched = pattern_matched


# ── Audit Errors ──────────────────────────────────────────────────────────
class AuditError(PramanixError): ...
class SigningError(AuditError): ...
class VerificationError(AuditError): ...
class ChainIntegrityError(AuditError): ...


# ── Execution Token Errors ────────────────────────────────────────────────
class ExecutionTokenError(PramanixError): ...
class TokenExpiredError(ExecutionTokenError): ...
class TokenReplayedError(ExecutionTokenError): ...
class TokenStateMismatchError(ExecutionTokenError): ...
class TokenHMACInvalidError(ExecutionTokenError): ...
class TokenBackendError(ExecutionTokenError): ...


# ── Translator Errors ─────────────────────────────────────────────────────
class TranslatorError(PramanixError): ...
class ConsensusFailedError(TranslatorError): ...
class TranslationTimeoutError(TranslatorError): ...
```

---

## 3. Phase 0 — The Mathematical Kernel (Z3 Core)

This is the most critical phase. Get this wrong and nothing else matters.

### 3.1 The ClockProtocol — Build This Before Z3

You need injectable time before you build the solver. 9 locations in the system call `time.time()` and every one of them needs to be testable without `sleep()`.

```python
# src/pramanix/clock.py

from __future__ import annotations
import threading
import time
from typing import Protocol, runtime_checkable


@runtime_checkable
class ClockProtocol(Protocol):
    def now(self) -> float: ...


class SystemClock:
    """Production. Wraps time.time()."""
    def now(self) -> float:
        return time.time()


class MonotonicClock:
    """For duration measurement only. Never for TTL."""
    def now(self) -> float:
        return time.monotonic()


class FakeClock:
    """
    Fully controllable test clock.

    Usage:
        clock = FakeClock(start=1_700_000_000.0)
        clock.advance(31.0)   # Simulates 31 seconds instantly
        assert clock.now() == 1_700_000_031.0
    """
    def __init__(self, start: float = 0.0) -> None:
        self._t    = start
        self._lock = threading.Lock()

    def now(self) -> float:
        with self._lock:
            return self._t

    def advance(self, seconds: float) -> None:
        if seconds < 0:
            raise ValueError(f"FakeClock.advance(): delta must be >=0, got {seconds}")
        with self._lock:
            self._t += seconds

    def set(self, t: float) -> None:
        with self._lock:
            self._t = t

    def __repr__(self) -> str:
        return f"FakeClock(now={self._t})"
```

### 3.2 The SolverProtocol — The Most Important Abstraction

This single interface eliminates every `patch("z3.Solver")` call that has ever been written and ever will be. Build it before the real solver.

```python
# src/pramanix/solver_protocol.py

from __future__ import annotations
import dataclasses
from typing import Protocol, runtime_checkable


@dataclasses.dataclass(frozen=True)
class SolveResult:
    """
    Raw result from any SMT solver backend.

    status:      "sat" | "unsat" | "unknown"
    model:       Z3 model (witness) on sat. None otherwise.
    core:        Violated constraint labels on unsat. Empty otherwise.
    rlimit:      Z3 resource units consumed.
    duration_ms: Wall-clock time inside the solver.
    """
    status:      str
    model:       object | None
    core:        list[str]
    rlimit:      int
    duration_ms: float

    @property
    def is_sat(self) -> bool:    return self.status == "sat"
    @property
    def is_unsat(self) -> bool:  return self.status == "unsat"
    @property
    def timed_out(self) -> bool: return self.status == "unknown"


@runtime_checkable
class SolverProtocol(Protocol):
    """
    Interface between Guard and any SMT backend.

    PRODUCTION: Z3Solver (real C library)
    TESTS:      AlwaysSATStub, AlwaysUNSATStub, AlwaysTimeoutStub, AlwaysExceptionStub

    USAGE IN TESTS — NEVER patch z3.Solver directly:
        guard = Guard(MyPolicy, config=GuardConfig(solver=AlwaysSATStub()))
    """

    def solve(
        self,
        intent_data: dict[str, object],
        state_data:  dict[str, object],
        policy_ir:   object,
        timeout_ms:  int = 5_000,
        rlimit:      int = 10_000_000,
    ) -> SolveResult: ...

    def solve_attribution(
        self,
        intent_data: dict[str, object],
        state_data:  dict[str, object],
        policy_ir:   object,
        timeout_ms:  int = 5_000,
    ) -> dict[str, SolveResult]: ...

    def is_satisfiable(self, policy_ir: object) -> SolveResult: ...
```

### 3.3 The Solver Stubs — Write These Before the Real Solver

```python
# tests/helpers/solver_stubs.py

from __future__ import annotations
from pramanix.solver_protocol import SolveResult


class _FakeModel:
    """Placeholder for Z3 model objects in stubs."""
    pass


class AlwaysSATStub:
    """
    Tests the ALLOW code path.
    Inject via: GuardConfig(solver=AlwaysSATStub())
    """
    def solve(self, *a, **kw) -> SolveResult:
        return SolveResult("sat", _FakeModel(), [], 0, 0.1)

    def solve_attribution(self, *a, **kw) -> dict[str, SolveResult]:
        return {}

    def is_satisfiable(self, policy_ir) -> SolveResult:
        return SolveResult("sat", _FakeModel(), [], 0, 0.1)


class AlwaysUNSATStub:
    """
    Tests the BLOCK code path.
    Inject via: GuardConfig(solver=AlwaysUNSATStub(violates=["invariant_name"]))
    """
    def __init__(self, violates: list[str] | None = None) -> None:
        self._violates = violates or ["stub_invariant"]

    def solve(self, *a, **kw) -> SolveResult:
        return SolveResult("unsat", None, self._violates, 100, 0.1)

    def solve_attribution(self, *a, intent_data=None, state_data=None,
                          policy_ir=None, **kw) -> dict[str, SolveResult]:
        return {name: SolveResult("unsat", None, [], 0, 0.05)
                for name in self._violates}

    def is_satisfiable(self, policy_ir) -> SolveResult:
        return SolveResult("sat", _FakeModel(), [], 0, 0.1)


class AlwaysTimeoutStub:
    """
    Tests fail-closed on solver timeout.
    Inject via: GuardConfig(solver=AlwaysTimeoutStub())
    """
    def solve(self, *a, timeout_ms: int = 5000, **kw) -> SolveResult:
        return SolveResult("unknown", None, ["timeout"], 0, float(timeout_ms))

    def solve_attribution(self, *a, **kw) -> dict[str, SolveResult]:
        return {}

    def is_satisfiable(self, policy_ir) -> SolveResult:
        return SolveResult("unknown", None, ["timeout"], 0, 5000.0)


class AlwaysExceptionStub:
    """
    Tests fail-closed on Z3 C-library exception.
    Inject via: GuardConfig(solver=AlwaysExceptionStub())
    """
    def solve(self, *a, **kw) -> SolveResult:
        raise RuntimeError("Z3 C-library binding failed: test injection")

    def solve_attribution(self, *a, **kw) -> dict[str, SolveResult]:
        raise RuntimeError("Z3 C-library binding failed: test injection")

    def is_satisfiable(self, policy_ir) -> SolveResult:
        raise RuntimeError("Z3 C-library binding failed: test injection")
```

### 3.4 The Real Z3 Solver

Now build the real solver. Five non-negotiable rules:

**Rule 1** — Always pass `ctx=` explicitly. `z3.IntVal(5)` uses the global context (thread-unsafe). `z3.IntVal(5, ctx=ctx)` uses the per-thread context.

**Rule 2** — Exact Decimal arithmetic. Never `z3.RealVal(float(Decimal("0.1")))`. Use `as_integer_ratio()` and `z3.RatVal(n, d, ctx=ctx)`.

**Rule 3** — Thread-local Z3 contexts via `threading.local()`.

**Rule 4** — Separate Phase A (all invariants, shared solver) from Phase B (per-invariant attribution, only on UNSAT).

**Rule 5** — Cap per-invariant attribution timeouts. `min(timeout_ms, 2_000)` per invariant.

```python
# src/pramanix/solver.py

from __future__ import annotations
import threading
import time
from decimal import Decimal
from typing import Any

import z3

from pramanix.solver_protocol import SolverProtocol, SolveResult

# Thread-local Z3 contexts — NEVER use z3's global context under concurrency
_tl_ctx: threading.local = threading.local()


def _get_ctx() -> z3.Context:
    """Get or create the per-thread Z3 Context."""
    if not hasattr(_tl_ctx, "ctx"):
        _tl_ctx.ctx = z3.Context()
    return _tl_ctx.ctx


def decimal_to_z3_rational(value: Decimal, ctx: z3.Context) -> Any:
    """
    Convert Decimal to exact Z3 rational.
    NEVER use z3.RealVal(float(value)) — float() loses precision.
    0.1 in IEEE-754 is NOT exactly 0.1. For financial invariants, this matters.
    """
    n, d = value.as_integer_ratio()
    return z3.RatVal(n, d, ctx=ctx)


def _get_rlimit(solver: z3.Solver) -> int:
    try:
        return int(solver.statistics().get_key_value("rlimit"))
    except Exception:
        return 0


class Z3Solver:
    """
    Production Z3 SMT solver. Implements SolverProtocol.

    Phase A: One shared solver, ALL invariants → sat/unsat in one call.
    Phase B: N per-invariant solvers (attribution, only on BLOCK path).
    """

    def __init__(self, transpiler: Any | None = None) -> None:
        if transpiler is None:
            from pramanix.transpiler import Transpiler
            transpiler = Transpiler()
        self._transpiler = transpiler

    def solve(
        self,
        intent_data: dict[str, object],
        state_data:  dict[str, object],
        policy_ir:   Any,
        timeout_ms:  int = 5_000,
        rlimit:      int = 10_000_000,
    ) -> SolveResult:
        ctx = _get_ctx()
        s   = z3.Solver(ctx=ctx)
        s.set("timeout", timeout_ms)
        s.set("rlimit",  rlimit)
        t0  = time.perf_counter()

        try:
            for formula in self._transpiler.transpile(
                policy_ir, intent_data, state_data, ctx
            ):
                s.add(formula)
            check = s.check()
            ms    = (time.perf_counter() - t0) * 1000

            if check == z3.sat:
                return SolveResult("sat",     s.model(), [], _get_rlimit(s), ms)
            elif check == z3.unsat:
                return SolveResult("unsat",   None,      [], _get_rlimit(s), ms)
            else:
                return SolveResult("unknown", None, ["timeout_or_rlimit"], _get_rlimit(s), ms)

        except z3.Z3Exception as exc:
            ms = (time.perf_counter() - t0) * 1000
            return SolveResult("unknown", None, [f"z3_exception:{exc}"], 0, ms)

    def solve_attribution(
        self,
        intent_data: dict[str, object],
        state_data:  dict[str, object],
        policy_ir:   Any,
        timeout_ms:  int = 5_000,
        **_: Any,
    ) -> dict[str, SolveResult]:
        ctx     = _get_ctx()
        results: dict[str, SolveResult] = {}

        for inv in policy_ir.invariants:
            s = z3.Solver(ctx=ctx)
            s.set("timeout", min(timeout_ms, 2_000))  # cap per-invariant
            single_ir = policy_ir.with_only_invariant(inv.name)

            for formula in self._transpiler.transpile(
                single_ir, intent_data, state_data, ctx
            ):
                s.add(formula)

            t0    = time.perf_counter()
            check = s.check()
            ms    = (time.perf_counter() - t0) * 1000

            results[inv.name] = SolveResult(
                "sat"   if check == z3.sat   else
                "unsat" if check == z3.unsat else "unknown",
                s.model() if check == z3.sat else None,
                [], _get_rlimit(s), ms,
            )

        return results

    def is_satisfiable(self, policy_ir: Any) -> SolveResult:
        ctx = _get_ctx()
        s   = z3.Solver(ctx=ctx)
        s.set("timeout", 5_000)

        from pramanix.transpiler import Transpiler
        for formula in Transpiler().transpile_symbolic_only(policy_ir, ctx):
            s.add(formula)

        check = s.check()
        return SolveResult(
            "sat"   if check == z3.sat   else
            "unsat" if check == z3.unsat else "unknown",
            s.model() if check == z3.sat else None,
            [], _get_rlimit(s), 0.0,
        )
```

### 3.5 The Transpiler — Converting Policy Logic to Z3 Formulas

The transpiler bridges your policy DSL and the Z3 C library.

**Key decisions:**
- Cache formula structure by `(policy_hash, invariant_name)` — rebuilding the symbolic structure is expensive; concrete value assertions are added fresh each call
- Use categorical encoding (enum → int) for string fields — Z3's string theory is more restricted than arithmetic
- Wall-clock time comes through `ClockProtocol`, not `time.time()` directly

```python
# src/pramanix/transpiler.py  [abbreviated — full implementation below]

class Transpiler:
    """
    Converts PolicyIR + concrete values into Z3 formula lists.

    CACHING: Cache (policy_hash, invariant_name) → symbolic formula tree.
    The symbolic structure is built once per policy version.
    Concrete value assertions (value == X) are added fresh each call.
    """

    def __init__(self, clock: "ClockProtocol | None" = None) -> None:
        from pramanix.clock import SystemClock
        self._clock  = clock or SystemClock()
        self._cache: dict[tuple[str, str], object] = {}

    def transpile(self, policy_ir, intent_data, state_data, ctx):
        """Return list of z3.BoolRef formulas for the solver."""
        formulas = []
        merged   = {**intent_data, **state_data}

        for inv in policy_ir.invariants:
            cache_key = (policy_ir.ir_hash, inv.name)
            if cache_key not in self._cache:
                self._cache[cache_key] = self._build_symbolic_formula(inv, policy_ir, ctx)
            formulas.append(self._cache[cache_key])

            for field_name in inv.referenced_fields:
                field_decl = policy_ir.get_field(field_name)
                if field_name in merged:
                    z3_var = self._make_z3_var(field_name, field_decl.sort, ctx)
                    z3_val = self._value_to_z3(merged[field_name], field_decl.sort, ctx)
                    formulas.append(z3_var == z3_val)

        return formulas

    def transpile_symbolic_only(self, policy_ir, ctx):
        """For policy linter: build symbolic formulas only (no concrete values)."""
        return [
            self._build_symbolic_formula(inv, policy_ir, ctx)
            for inv in policy_ir.invariants
        ]

    def _value_to_z3(self, value, sort, ctx):
        """Convert Python value to Z3 value. Exact arithmetic for Decimal."""
        import z3
        if sort == "decimal" or sort == "real":
            if isinstance(value, Decimal):
                n, d = value.as_integer_ratio()
                return z3.RatVal(n, d, ctx=ctx)
            return z3.RatVal(int(value * 10**10), 10**10, ctx=ctx)
        elif sort == "int":
            return z3.IntVal(int(value), ctx=ctx)
        elif sort == "bool":
            return z3.BoolVal(bool(value), ctx=ctx)
        elif sort == "str":
            return z3.StringVal(str(value), ctx=ctx)
        raise ValueError(f"Unknown sort: {sort!r}")
```

### 3.6 Z3 Tests — The Foundation Test Suite

```python
# tests/unit/test_solver.py

import pytest
from decimal import Decimal
from pramanix.solver import Z3Solver, decimal_to_z3_rational, _get_ctx

def test_decimal_to_z3_rational_exact():
    """Verify that 0.1 is represented exactly, not as a float approximation."""
    import z3
    ctx = _get_ctx()
    val = decimal_to_z3_rational(Decimal("0.1"), ctx)
    # 0.1 + 0.1 + 0.1 == 0.3 exactly in rational arithmetic
    # This would FAIL with float representation
    s = z3.Solver(ctx=ctx)
    x = z3.Real("x", ctx=ctx)
    s.add(x == val + val + val)
    s.add(x == decimal_to_z3_rational(Decimal("0.3"), ctx))
    assert s.check() == z3.sat

def test_solver_thread_local_contexts():
    """Each thread gets its own Z3 context — no global state shared."""
    import threading
    contexts = []
    def capture_ctx():
        contexts.append(_get_ctx())
    t1 = threading.Thread(target=capture_ctx)
    t2 = threading.Thread(target=capture_ctx)
    t1.start(); t1.join()
    t2.start(); t2.join()
    assert contexts[0] is not contexts[1]

# Use stubs for Guard-level tests — never patch z3.Solver directly
from tests.helpers.solver_stubs import (
    AlwaysSATStub, AlwaysUNSATStub, AlwaysTimeoutStub, AlwaysExceptionStub
)

def test_stub_implements_protocol():
    from pramanix.solver_protocol import SolverProtocol
    assert isinstance(AlwaysSATStub(),       SolverProtocol)
    assert isinstance(AlwaysUNSATStub(),     SolverProtocol)
    assert isinstance(AlwaysTimeoutStub(),   SolverProtocol)
    assert isinstance(AlwaysExceptionStub(), SolverProtocol)
```

---

## 4. Phase 1 — The Policy Engine

### 4.1 The Expression DSL — The Policy Author's Interface

```python
# src/pramanix/expressions.py

from __future__ import annotations
from dataclasses import dataclass
from decimal import Decimal


def E(field_name: str) -> "FieldRef":
    """Entry point for the policy DSL. E('amount') > 0 → ConstraintExpr."""
    return FieldRef(field_name)


class ExpressionNode:
    """
    Base node in the policy expression tree.

    Critical design decisions:
    1. __eq__ returns ConstraintExpr, NOT bool (matches Z3's own design).
    2. __bool__ raises TypeError — prevents silent if E('x') == y: mistakes.
    3. __hash__ = object.__hash__ — identity-based; nodes usable in sets.
    """

    def __eq__(self, other: object) -> "ConstraintExpr":   # type: ignore[override]
        return ConstraintExpr("==", self, _wrap(other))

    def __ne__(self, other: object) -> "ConstraintExpr":   # type: ignore[override]
        return ConstraintExpr("!=", self, _wrap(other))

    def __lt__(self,  other: object) -> "ConstraintExpr":
        return ConstraintExpr("<",  self, _wrap(other))

    def __le__(self,  other: object) -> "ConstraintExpr":
        return ConstraintExpr("<=", self, _wrap(other))

    def __gt__(self,  other: object) -> "ConstraintExpr":
        return ConstraintExpr(">",  self, _wrap(other))

    def __ge__(self,  other: object) -> "ConstraintExpr":
        return ConstraintExpr(">=", self, _wrap(other))

    def __add__(self,  other: object) -> "ArithExpr":
        return ArithExpr("+", self, _wrap(other))

    def __radd__(self, other: object) -> "ArithExpr":
        return ArithExpr("+", _wrap(other), self)

    def __sub__(self,  other: object) -> "ArithExpr":
        return ArithExpr("-", self, _wrap(other))

    def __mul__(self,  other: object) -> "ArithExpr":
        return ArithExpr("*", self, _wrap(other))

    def __bool__(self) -> bool:
        raise TypeError(
            "\nExpressionNode cannot be used as a Python boolean.\n"
            "You probably wrote:\n"
            "    if E('field') == value:              ← WRONG\n"
            "    assert E('field') == value           ← WRONG\n"
            "Write inside invariants() list:\n"
            "    (E('field') == value).named('name')  ← CORRECT\n"
        )

    __hash__ = object.__hash__   # identity-based; preserves hashability


@dataclass
class FieldRef(ExpressionNode):
    field_name: str

    def __repr__(self) -> str:
        return f"E({self.field_name!r})"


@dataclass
class LiteralNode(ExpressionNode):
    value: int | float | Decimal | bool | str

    def __repr__(self) -> str:
        return repr(self.value)


@dataclass
class ArithExpr(ExpressionNode):
    operator: str
    left:     ExpressionNode
    right:    ExpressionNode


@dataclass
class ConstraintExpr:
    """A named logical constraint ready for the invariants() list."""
    operator: str
    left:     ExpressionNode
    right:    ExpressionNode
    _name:    str = ""
    _explain: str = ""
    _cite:    str = ""

    def named(self, name: str) -> "ConstraintExpr":
        return ConstraintExpr(self.operator, self.left, self.right,
                              name, self._explain, self._cite)

    def explain(self, text: str) -> "ConstraintExpr":
        return ConstraintExpr(self.operator, self.left, self.right,
                              self._name, text, self._cite)

    def cite(self, regulatory_ref: str) -> "ConstraintExpr":
        return ConstraintExpr(self.operator, self.left, self.right,
                              self._name, self._explain, regulatory_ref)

    @property
    def name(self) -> str:
        return self._name

    def __and__(self, other: "ConstraintExpr") -> "CompoundConstraint":
        return CompoundConstraint("and", [self, other])

    def __or__(self, other: "ConstraintExpr") -> "CompoundConstraint":
        return CompoundConstraint("or", [self, other])


@dataclass
class CompoundConstraint:
    operator: str  # "and" | "or" | "not"
    operands: list[ConstraintExpr | "CompoundConstraint"]


def _wrap(value: object) -> ExpressionNode:
    if isinstance(value, ExpressionNode):
        return value
    if isinstance(value, (int, float, Decimal, bool, str)):
        return LiteralNode(value)
    raise TypeError(f"Cannot convert {type(value).__name__!r} to ExpressionNode")
```

### 4.2 The Policy Base Class

```python
# src/pramanix/policy.py

from __future__ import annotations
from typing import ClassVar


class Field:
    """Declares a typed, constrained field in a policy."""
    def __init__(
        self,
        sort: str,           # "decimal" | "int" | "bool" | "str"
        *,
        min: object = None,
        max: object = None,
        choices: list[str] | None = None,
        description: str = "",
    ) -> None:
        self.sort        = sort
        self.min         = min
        self.max         = max
        self.choices     = choices
        self.description = description


class Policy:
    """
    Base class for all Pramanix governance policies.

    Subclasses MUST define:
      __policy_version__: str = "1.0.0"
      class fields:       # Declare all typed fields
      @classmethod
      def invariants(cls) -> list:  # Return list of ConstraintExpr

    VALIDATION: PolicyCompiler checks 14 rules before producing PolicyIR.
    COMPILATION: Call PolicyCompiler().compile(MyPolicy) to get a PolicyIR.
    """
    __policy_version__: ClassVar[str]   = "0.0.0"
    __compliance_tags__: ClassVar[frozenset[str]] = frozenset()

    @classmethod
    def invariants(cls) -> list:
        raise NotImplementedError(
            f"{cls.__name__}.invariants() must be overridden. "
            "Return a list of ConstraintExpr objects from the E() DSL."
        )
```

### 4.3 The PolicyIR — Compiled, Content-Addressed Form

```python
# src/pramanix/policy_ir.py

from __future__ import annotations
import dataclasses
import hashlib
from typing import Any

import orjson


@dataclasses.dataclass(frozen=True)
class CompiledField:
    name:        str
    sort:        str
    min_val:     str | None
    max_val:     str | None
    choices:     tuple[str, ...] | None
    description: str


@dataclasses.dataclass(frozen=True)
class CompiledInvariant:
    name:              str
    expression_tree:   dict[str, Any]
    explanation:       str
    regulatory_cite:   str | None
    referenced_fields: tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class PolicyIR:
    """
    Compiled, content-addressed PolicyIR.
    ir_hash = SHA-256 of canonical JSON. Changes when any invariant/field changes.
    Every Decision records ir_hash for full audit reconstruction.
    """
    ir_hash:     str
    name:        str
    version:     str
    invariants:  tuple[CompiledInvariant, ...]
    fields:      tuple[CompiledField, ...]
    tags:        frozenset[str]
    compiled_at: str

    def get_field(self, name: str) -> CompiledField:
        for f in self.fields:
            if f.name == name:
                return f
        raise KeyError(f"Field {name!r} not in policy {self.name!r}")

    def with_only_invariant(self, name: str) -> "PolicyIR":
        inv = next((i for i in self.invariants if i.name == name), None)
        if inv is None:
            raise KeyError(f"Invariant {name!r} not found in {self.name!r}")
        return dataclasses.replace(self, invariants=(inv,))

    def verify_hash(self) -> bool:
        import hmac as _hmac
        d = dataclasses.asdict(self)
        d.pop("ir_hash")
        computed = hashlib.sha256(
            orjson.dumps(d, option=orjson.OPT_SORT_KEYS)
        ).hexdigest()
        return _hmac.compare_digest(computed, self.ir_hash)
```

### 4.4 The PolicyCompiler — 14 Validation Rules

Write one test per validation rule. Each is a regression boundary.

```python
# src/pramanix/policy_compiler.py

from __future__ import annotations
import datetime
import hashlib
from typing import Any

import orjson

from pramanix.exceptions import PolicyCompilationError
from pramanix.policy import Policy, Field
from pramanix.policy_ir import PolicyIR, CompiledField, CompiledInvariant


class PolicyCompiler:
    """
    Compiles a Policy class → PolicyIR.
    Validates 14 rules. Any failure raises PolicyCompilationError.
    """

    def compile(self, policy_cls: type[Policy]) -> PolicyIR:
        self._validate(policy_cls)
        return self._build_ir(policy_cls)

    def _validate(self, cls: type[Policy]) -> None:
        fields     = self._get_fields(cls)
        invariants = cls.invariants()

        # Rule 1: __policy_version__ must be defined
        if cls.__policy_version__ == "0.0.0":
            raise PolicyCompilationError(
                f"{cls.__name__} must define __policy_version__."
            )

        # Rule 2: invariants() must return a non-empty list
        if not invariants:
            raise PolicyCompilationError(
                f"{cls.__name__}.invariants() returned empty list."
            )

        # Rule 3: All invariants must have .named() called
        for inv in invariants:
            if not inv.name:
                raise PolicyCompilationError(
                    f"{cls.__name__}: invariant without a name. Call .named('...')."
                )

        # Rule 4: No duplicate invariant names
        names = [inv.name for inv in invariants]
        if len(names) != len(set(names)):
            dupes = [n for n in names if names.count(n) > 1]
            raise PolicyCompilationError(
                f"{cls.__name__}: duplicate invariant names: {dupes}"
            )

        # Rule 5: All referenced fields are declared
        for inv in invariants:
            for fname in self._referenced_fields(inv):
                if fname not in fields:
                    raise PolicyCompilationError(
                        f"{cls.__name__}: invariant {inv.name!r} references "
                        f"undeclared field {fname!r}."
                    )

        # Rule 6: All declared fields are referenced in at least one invariant
        all_referenced = set()
        for inv in invariants:
            all_referenced.update(self._referenced_fields(inv))
        for fname in fields:
            if fname not in all_referenced:
                raise PolicyCompilationError(
                    f"{cls.__name__}: declared field {fname!r} is not referenced "
                    f"in any invariant. Remove it or add an invariant that uses it."
                )

        # Rules 7-14: threshold types, choices validity, explanations, etc.
        for inv in invariants:
            if not inv._explain:
                raise PolicyCompilationError(
                    f"{cls.__name__}: invariant {inv.name!r} has no .explain() text."
                )

        for fname, fdecl in fields.items():
            if fdecl.choices is not None and len(fdecl.choices) == 0:
                raise PolicyCompilationError(
                    f"{cls.__name__}: field {fname!r} has empty choices list."
                )

    def _get_fields(self, cls: type[Policy]) -> dict[str, Field]:
        fields_cls = getattr(cls, "fields", None)
        if fields_cls is None:
            raise PolicyCompilationError(f"{cls.__name__} has no inner 'fields' class.")
        return {
            name: val
            for name, val in vars(fields_cls).items()
            if isinstance(val, Field)
        }

    def _referenced_fields(self, inv) -> list[str]:
        """Extract field names from the expression tree of an invariant."""
        from pramanix.expressions import FieldRef, ArithExpr, ConstraintExpr, CompoundConstraint

        def _walk(node) -> list[str]:
            if isinstance(node, FieldRef):
                return [node.field_name]
            if isinstance(node, ArithExpr):
                return _walk(node.left) + _walk(node.right)
            if isinstance(node, ConstraintExpr):
                return _walk(node.left) + _walk(node.right)
            if isinstance(node, CompoundConstraint):
                result = []
                for op in node.operands:
                    result.extend(_walk(op))
                return result
            return []

        return _walk(inv)

    def _build_ir(self, cls: type[Policy]) -> PolicyIR:
        fields     = self._get_fields(cls)
        invariants = cls.invariants()
        compiled_fields = tuple(
            CompiledField(
                name=name,
                sort=fdecl.sort,
                min_val=str(fdecl.min) if fdecl.min is not None else None,
                max_val=str(fdecl.max) if fdecl.max is not None else None,
                choices=tuple(fdecl.choices) if fdecl.choices else None,
                description=fdecl.description,
            )
            for name, fdecl in fields.items()
        )
        compiled_invs = tuple(
            CompiledInvariant(
                name=inv.name,
                expression_tree={"op": inv.operator},
                explanation=inv._explain,
                regulatory_cite=inv._cite or None,
                referenced_fields=tuple(self._referenced_fields(inv)),
            )
            for inv in invariants
        )
        ir_dict = {
            "name":        cls.__name__,
            "version":     cls.__policy_version__,
            "invariants":  [ci.__dict__ for ci in compiled_invs],
            "fields":      [cf.__dict__ for cf in compiled_fields],
            "tags":        sorted(cls.__compliance_tags__),
            "compiled_at": datetime.datetime.utcnow().isoformat(),
        }
        ir_hash = hashlib.sha256(
            orjson.dumps(ir_dict, option=orjson.OPT_SORT_KEYS)
        ).hexdigest()
        return PolicyIR(
            ir_hash     = ir_hash,
            name        = cls.__name__,
            version     = cls.__policy_version__,
            invariants  = compiled_invs,
            fields      = compiled_fields,
            tags        = cls.__compliance_tags__,
            compiled_at = ir_dict["compiled_at"],
        )
```

### 4.5 A Complete Working Policy

Write this in `examples/banking/wire_transfer.py`. Run the linter against it as your first integration test.

```python
# examples/banking/wire_transfer.py

from decimal import Decimal
from pramanix.policy import Policy, Field
from pramanix.expressions import E


class WireTransferPolicy(Policy):
    """BSA/AML-aligned wire transfer governance."""

    __policy_version__   = "1.0.0"
    __compliance_tags__  = frozenset({"BSA_AML", "SOX"})

    class fields:
        amount:          Field = Field("decimal", min=Decimal("0.01"),
                                       description="Transfer amount in base currency")
        currency:        Field = Field("str",     choices=["USD", "EUR", "GBP", "JPY"])
        balance:         Field = Field("decimal", min=Decimal("0"))
        daily_sent:      Field = Field("decimal", min=Decimal("0"))
        daily_limit:     Field = Field("decimal", min=Decimal("0"))
        recipient_kyc:   Field = Field("bool")
        account_frozen:  Field = Field("bool")
        sanctions_clear: Field = Field("bool")

    @classmethod
    def invariants(cls) -> list:
        return [
            (E("amount") > Decimal("0"))
            .named("positive_amount")
            .explain("Transfer amount must be strictly positive.")
            .cite("BSA §31 CFR 1020.320"),

            (E("balance") >= E("amount"))
            .named("sufficient_funds")
            .explain("Account balance must cover the full transfer amount."),

            (E("daily_sent") + E("amount") <= E("daily_limit"))
            .named("daily_limit_not_exceeded")
            .explain("Sum of today's outbound transfers must not exceed daily limit.")
            .cite("BSA §31 CFR 1020.315"),

            (E("recipient_kyc") == True)
            .named("recipient_kyc_verified")
            .explain("Recipient must have completed KYC verification.")
            .cite("BSA §31 CFR 1020.220"),

            (E("account_frozen") == False)
            .named("account_not_frozen")
            .explain("Frozen accounts cannot initiate outbound transfers."),

            (E("sanctions_clear") == True)
            .named("sanctions_screening_passed")
            .explain("Transaction must have cleared OFAC sanctions screening.")
            .cite("31 CFR Part 501"),
        ]
```

---

## 5. Phase 2 — The Guard Pipeline

### 5.1 The Decision Object — Central Data Structure

```python
# src/pramanix/decision.py

from __future__ import annotations
import dataclasses
import hashlib
import uuid
from datetime import datetime
from enum import Enum
from typing import Any

import orjson

from pramanix.exceptions import StructuralIntegrityError


class DecisionStatus(str, Enum):
    SAFE               = "SAFE"
    POLICY_VIOLATION   = "POLICY_VIOLATION"
    INVALID_INPUT      = "INVALID_INPUT"
    SOLVER_TIMEOUT     = "SOLVER_TIMEOUT"
    SOLVER_ERROR       = "SOLVER_ERROR"
    FAST_PATH_BLOCK    = "FAST_PATH_BLOCK"
    INJECTION_DETECTED = "INJECTION_DETECTED"
    CONSENSUS_FAILED   = "CONSENSUS_FAILED"
    CONFIGURATION_ERROR = "CONFIGURATION_ERROR"


@dataclasses.dataclass(frozen=True)
class Decision:
    """
    Immutable, signed, auditable result of every Guard.verify() call.

    STRUCTURAL INVARIANT: allowed=True requires status=SAFE.
    __post_init__ enforces this. No code path can produce a false ALLOW.

    CONSTRUCTION: Use classmethods only. Never call Decision() directly.
    """
    allowed:         bool
    status:          DecisionStatus
    proof:           Any                   # SATProof | CounterExample | None
    violated:        tuple[str, ...]
    decision_hash:   str
    signature:       bytes | None
    merkle_root:     str | None
    timestamp:       datetime
    latency_ms:      float
    solver_rlimit:   int
    policy_hash:     str
    policy_version:  str
    intent_hash:     str
    state_hash:      str
    request_id:      str
    metadata:        frozenset[tuple[str, str]]

    def __post_init__(self) -> None:
        if self.allowed and self.status != DecisionStatus.SAFE:
            raise StructuralIntegrityError(
                f"Decision(allowed=True) requires status=SAFE. "
                f"Got status={self.status!r}. This is a bug in Guard internals."
            )

    @classmethod
    def allow(cls, proof: Any, **kw: Any) -> "Decision":
        return cls(
            allowed=True, status=DecisionStatus.SAFE,
            proof=proof, violated=(), **kw,
        )

    @classmethod
    def block(
        cls,
        reason: DecisionStatus,
        violated: tuple[str, ...],
        counter_example: Any = None,
        **kw: Any,
    ) -> "Decision":
        assert reason != DecisionStatus.SAFE
        return cls(
            allowed=False, status=reason,
            proof=counter_example, violated=violated, **kw,
        )

    @classmethod
    def error(cls, exc: Exception, **kw: Any) -> "Decision":
        return cls(
            allowed=False, status=DecisionStatus.SOLVER_ERROR,
            proof=None, violated=(),
            metadata=frozenset({
                ("error_type", type(exc).__name__),
                ("error_msg",  str(exc)[:256]),
            }),
            **kw,
        )

    def to_canonical_json(self) -> bytes:
        """Deterministic JSON for signing. OPT_SORT_KEYS. No floats."""
        d = dataclasses.asdict(self)
        d.pop("signature")   # not included in what gets signed
        return orjson.dumps(d, option=orjson.OPT_SORT_KEYS | orjson.OPT_NON_STR_KEYS)
```

### 5.2 The GuardConfig — Dependency Injection Hub

```python
# src/pramanix/guard_config.py

from __future__ import annotations
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pramanix.solver_protocol import SolverProtocol
    from pramanix.clock import ClockProtocol


@dataclass
class GuardConfig:
    """
    All Guard dependencies in one dataclass. Guard hardcodes nothing.

    TESTS:
        GuardConfig(solver=AlwaysSATStub())        # ALLOW paths
        GuardConfig(solver=AlwaysUNSATStub())       # BLOCK paths
        GuardConfig(solver=AlwaysTimeoutStub())     # timeout fail-closed
        GuardConfig(solver=AlwaysExceptionStub())   # exception fail-closed
        GuardConfig(clock=FakeClock(start=T))       # TTL without sleep
    """
    solver:              "SolverProtocol | None"   = None
    clock:               "ClockProtocol | None"    = None
    resolvers:           list[Any]                 = field(default_factory=list)
    resolver_timeout_ms: int                       = 3_000
    solver_timeout_ms:   int                       = 5_000
    solver_rlimit:       int                       = 10_000_000
    signer:              Any | None                = None   # DecisionSigner
    merkle_anchor:       Any | None                = None   # MerkleAnchor
    fast_path:           Any | None                = None   # FastPathChecker
    intent_cache:        Any | None                = None   # IntentExtractionCache
    require_re2:         bool                      = False
    safety_validators:   list[Any]                 = field(default_factory=list)
    shadow_policy:       Any | None                = None
    compliance_tags:     frozenset[str]            = field(default_factory=frozenset)
```

### 5.3 The Guard — Full Implementation

```python
# src/pramanix/guard.py

from __future__ import annotations
import asyncio
import hashlib
import uuid
from datetime import datetime
from typing import Any

import orjson
import structlog

from pramanix.decision import Decision, DecisionStatus
from pramanix.exceptions import ConfigurationError

_log = structlog.get_logger(__name__)


def _hash_obj(obj: Any) -> str:
    try:
        return hashlib.sha256(
            orjson.dumps(obj, option=orjson.OPT_SORT_KEYS)
        ).hexdigest()[:16]
    except Exception:
        return "unhashable"


class Guard:
    """
    Primary API surface of Pramanix.

    GUARANTEES:
      1. verify() NEVER raises. Always returns a Decision.
      2. Decision(allowed=True) ONLY when status=SAFE.
      3. Every error path produces Decision.error() → allowed=False.
      4. Safe for concurrent use from multiple threads/coroutines.
    """

    def __init__(
        self,
        policy: "type | Any",
        config: "Any | None" = None,
    ) -> None:
        from pramanix.guard_config import GuardConfig
        from pramanix.solver import Z3Solver
        from pramanix.clock import SystemClock

        cfg = config or GuardConfig()

        # Compile policy if class given, accept PolicyIR directly
        from pramanix.policy_ir import PolicyIR
        if isinstance(policy, type):
            from pramanix.policy_compiler import PolicyCompiler
            self._policy_ir: PolicyIR = PolicyCompiler().compile(policy)
        else:
            self._policy_ir = policy

        self._solver    = cfg.solver    or Z3Solver()
        self._clock     = cfg.clock     or SystemClock()
        self._resolvers = cfg.resolvers or []
        self._signer    = cfg.signer
        self._anchor    = cfg.merkle_anchor
        self._fast_path = cfg.fast_path
        self._config    = cfg

        if cfg.require_re2:
            self._validate_re2()

    def _validate_re2(self) -> None:
        try:
            import re2  # noqa: F401
        except ImportError:
            raise ConfigurationError(
                "GuardConfig(require_re2=True) requires google-re2.\n"
                "Install: pip install pramanix[re2]\n"
                "Pramanix refuses to start without re2 in require_re2 mode."
            )

    async def verify(
        self,
        intent:     Any,
        state:      Any,
        *,
        request_id: str | None = None,
    ) -> Decision:
        """
        Verify that intent is safe given state under this Policy.
        NEVER RAISES. ALWAYS returns a Decision.
        """
        _rid   = request_id or str(uuid.uuid4())
        _start = self._clock.now()

        try:
            return await self._verify_internal(intent, state, _rid, _start)
        except Exception as exc:
            _log.error(
                "guard.verify: unhandled exception — returning error decision",
                request_id=_rid, exc_type=type(exc).__name__, exc_info=exc,
            )
            return self._make_error_decision(exc, _rid, _start, intent, state)

    async def _verify_internal(self, intent, state, request_id, start) -> Decision:
        intent_dict = intent if isinstance(intent, dict) else dict(intent)
        state_dict  = state  if isinstance(state,  dict) else dict(state)

        # Fast-path pre-screen
        if self._fast_path:
            fast = self._fast_path.check(intent_dict, state_dict)
            if fast is not None:
                return self._finalize(fast, start, request_id, intent_dict, state_dict)

        # Z3 solve
        solve_result = self._solver.solve(
            intent_data = intent_dict,
            state_data  = state_dict,
            policy_ir   = self._policy_ir,
            timeout_ms  = self._config.solver_timeout_ms,
            rlimit      = self._config.solver_rlimit,
        )

        # Attribution (only on BLOCK path)
        violated: tuple[str, ...] = ()
        if solve_result.is_unsat:
            attr     = self._solver.solve_attribution(
                intent_data=intent_dict,
                state_data=state_dict,
                policy_ir=self._policy_ir,
            )
            violated = tuple(n for n, r in attr.items() if r.is_unsat)

        # Build decision
        decision = self._build_decision(
            solve_result, intent_dict, state_dict, violated, start, request_id
        )

        # Sign
        if self._signer:
            try:
                decision = self._signer.sign(decision)
            except Exception as exc:
                _log.warning("guard: signing failed — returning unsigned decision",
                             exc_info=exc)

        # Merkle
        if self._anchor:
            try:
                decision = self._anchor.anchor(decision)
            except Exception as exc:
                _log.warning("guard: merkle anchoring failed", exc_info=exc)

        return decision

    def _build_decision(
        self, solve_result, intent_dict, state_dict,
        violated, start, request_id,
    ) -> Decision:
        latency = (self._clock.now() - start) * 1000
        common  = dict(
            decision_hash  = "",
            signature      = None,
            merkle_root    = None,
            timestamp      = datetime.utcnow(),
            latency_ms     = latency,
            solver_rlimit  = solve_result.rlimit,
            policy_hash    = self._policy_ir.ir_hash,
            policy_version = self._policy_ir.version,
            intent_hash    = _hash_obj(intent_dict),
            state_hash     = _hash_obj(state_dict),
            request_id     = request_id,
            metadata       = frozenset(),
        )
        if solve_result.is_sat:
            return Decision.allow(proof=solve_result.model, **common)
        elif solve_result.is_unsat:
            return Decision.block(
                reason=DecisionStatus.POLICY_VIOLATION,
                violated=violated,
                **common,
            )
        else:
            status = (DecisionStatus.SOLVER_TIMEOUT
                      if "timeout" in str(solve_result.core)
                      else DecisionStatus.SOLVER_ERROR)
            return Decision.block(reason=status, violated=(), **common)

    def _finalize(self, raw_decision, start, request_id, intent_dict, state_dict) -> Decision:
        latency = (self._clock.now() - start) * 1000
        return dataclasses.replace(raw_decision,
            latency_ms=latency, request_id=request_id,
            intent_hash=_hash_obj(intent_dict), state_hash=_hash_obj(state_dict),
        ) if hasattr(raw_decision, "latency_ms") else raw_decision

    def _make_error_decision(self, exc, request_id, start, intent, state) -> Decision:
        return Decision.error(
            exc=exc,
            decision_hash="", signature=None, merkle_root=None,
            timestamp=datetime.utcnow(),
            latency_ms=(self._clock.now() - start) * 1000,
            solver_rlimit=0,
            policy_hash=self._policy_ir.ir_hash,
            policy_version=self._policy_ir.version,
            intent_hash=_hash_obj(intent),
            state_hash=_hash_obj(state),
            request_id=request_id,
            metadata=frozenset(),
            violated=(),
        )
```

### 5.4 The Mandatory Guard Tests

These tests are CI gates. They must pass before any other work continues.

```python
# tests/unit/test_guard_fail_closed.py

import pytest
from pramanix.guard import Guard
from pramanix.guard_config import GuardConfig
from pramanix.decision import DecisionStatus
from tests.helpers.solver_stubs import (
    AlwaysSATStub, AlwaysUNSATStub, AlwaysTimeoutStub, AlwaysExceptionStub
)
from examples.banking.wire_transfer import WireTransferPolicy

VALID_INTENT = {"amount": 100, "currency": "USD"}
VALID_STATE  = {
    "balance": 1000, "daily_sent": 0, "daily_limit": 5000,
    "recipient_kyc": True, "account_frozen": False, "sanctions_clear": True,
}

@pytest.mark.asyncio
async def test_guard_never_raises_on_z3_exception():
    guard = Guard(WireTransferPolicy, config=GuardConfig(solver=AlwaysExceptionStub()))
    try:
        decision = await guard.verify(VALID_INTENT, VALID_STATE)
    except Exception as e:
        pytest.fail(f"Guard.verify() raised {type(e).__name__}: {e}")
    assert decision is not None
    assert not decision.allowed

@pytest.mark.asyncio
@pytest.mark.parametrize("stub,expected", [
    (AlwaysExceptionStub(), DecisionStatus.SOLVER_ERROR),
    (AlwaysTimeoutStub(),   DecisionStatus.SOLVER_TIMEOUT),
])
async def test_guard_fail_closed_on_solver_failure(stub, expected):
    guard    = Guard(WireTransferPolicy, config=GuardConfig(solver=stub))
    decision = await guard.verify(VALID_INTENT, VALID_STATE)
    assert not decision.allowed
    assert decision.status == expected

@pytest.mark.asyncio
async def test_guard_allow_on_sat():
    guard    = Guard(WireTransferPolicy, config=GuardConfig(solver=AlwaysSATStub()))
    decision = await guard.verify(VALID_INTENT, VALID_STATE)
    assert decision.allowed
    assert decision.status == DecisionStatus.SAFE

@pytest.mark.asyncio
async def test_guard_block_on_unsat():
    guard    = Guard(WireTransferPolicy, config=GuardConfig(
        solver=AlwaysUNSATStub(violates=["sufficient_funds"])
    ))
    decision = await guard.verify(VALID_INTENT, VALID_STATE)
    assert not decision.allowed
    assert "sufficient_funds" in decision.violated

def test_decision_structural_integrity():
    """Decision(allowed=True, status≠SAFE) is structurally impossible."""
    import pytest
    from pramanix.decision import Decision
    from pramanix.exceptions import StructuralIntegrityError
    from datetime import datetime
    with pytest.raises(StructuralIntegrityError):
        Decision(
            allowed=True, status=DecisionStatus.SOLVER_ERROR,
            proof=None, violated=(), decision_hash="", signature=None,
            merkle_root=None, timestamp=datetime.utcnow(), latency_ms=0.0,
            solver_rlimit=0, policy_hash="", policy_version="", intent_hash="",
            state_hash="", request_id="", metadata=frozenset(),
        )
```

---

## 6. Phase 3 — The Cryptographic Audit Engine

### 6.1 The DecisionSigner

```python
# src/pramanix/audit/signer.py

from __future__ import annotations
import dataclasses
import hashlib
import structlog

from pramanix.exceptions import ConfigurationError, VerificationError

_log = structlog.get_logger(__name__)


class DecisionSigner:
    """
    Signs Decision objects with Ed25519 (default), RS256, or ES256.

    CONSTRUCTION CONTRACT:
      key=None  → raises ConfigurationError immediately.
      key short → raises ConfigurationError (len < 32).
      DecisionSigner.optional(None) → returns None (dev mode).

    VERIFY:
      returns False  → wrong signature (wrong key or tampered record)
      raises VerificationError → infrastructure failure (key load broken)
    """

    def __init__(
        self,
        key:       str | bytes,
        algorithm: str = "Ed25519",
    ) -> None:
        if key is None:
            raise ConfigurationError(
                "DecisionSigner: signing key is None. "
                "Use DecisionSigner.optional(None) for dev mode."
            )
        if isinstance(key, (str, bytes)) and len(key) < 32:
            raise ConfigurationError(
                f"DecisionSigner: key is only {len(key)} chars. Minimum 32."
            )
        self._raw_key  = key
        self._algorithm = algorithm
        self._private_key = self._load_key(key, algorithm)

    @classmethod
    def optional(cls, key: str | bytes | None) -> "DecisionSigner | None":
        """Null-safe factory. Returns None if key is None (unsigned dev mode)."""
        return cls(key=key) if key is not None else None

    def _load_key(self, key: str | bytes, algorithm: str):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        if algorithm == "Ed25519":
            raw = key.encode() if isinstance(key, str) else key
            # Generate from seed for deterministic keys
            return Ed25519PrivateKey.from_private_bytes(raw[:32])
        raise ConfigurationError(f"Unsupported algorithm: {algorithm!r}")

    def sign(self, decision: "Decision") -> "Decision":
        """Returns new Decision with signature. Logs WARNING on failure; never raises."""
        try:
            canonical = decision.to_canonical_json()
            dhash     = hashlib.sha256(canonical).hexdigest()
            sig       = self._private_key.sign(dhash.encode())
            return dataclasses.replace(decision, decision_hash=dhash, signature=sig)
        except Exception as exc:
            _log.warning(
                "decision signing failed — returning unsigned decision",
                exc_type=type(exc).__name__, exc_info=exc,
            )
            return decision

    def verify(self, decision: "Decision") -> bool:
        if decision.signature is None:
            return False
        try:
            from cryptography.exceptions import InvalidSignature
            self._private_key.public_key().verify(
                decision.signature, decision.decision_hash.encode()
            )
            return True
        except InvalidSignature:
            return False   # Wrong sig — not a bug
        except Exception as exc:
            raise VerificationError(
                f"Signature verification infrastructure failure: {exc}"
            ) from exc
```

### 6.2 The Merkle Audit Chain

```python
# src/pramanix/audit/merkle.py

from __future__ import annotations
import dataclasses
import hashlib
import hmac as _hmac

from pramanix.exceptions import ConfigurationError


class MerkleAnchor:
    """
    Links consecutive decisions into a tamper-evident chain.

    FORMULA:
      root[n] = HMAC-SHA256(key, decision_hash[n] + root[n-1])
      root[0] uses prior_root = "0" * 64

    Deleting or modifying any decision changes its hash,
    which invalidates all subsequent roots — detectable offline.
    """

    def __init__(self, anchor_key: bytes, prior_root: str | None = None) -> None:
        if len(anchor_key) < 32:
            raise ConfigurationError("MerkleAnchor key must be >=32 bytes.")
        self._key        = anchor_key
        self._prior_root = prior_root or ("0" * 64)

    def anchor(self, decision: "Decision") -> "Decision":
        root = _hmac.new(
            self._key,
            (decision.decision_hash + self._prior_root).encode(),
            hashlib.sha256,
        ).hexdigest()
        self._prior_root = root
        return dataclasses.replace(decision, merkle_root=root)

    @staticmethod
    def verify_chain(
        decisions:    list,
        anchor_key:   bytes,
        genesis_root: str = "0" * 64,
    ) -> dict:
        """Offline verification. Returns dict with intact: bool."""
        prior  = genesis_root
        broken: list[tuple[int, str]] = []
        for i, d in enumerate(decisions):
            expected = _hmac.new(
                anchor_key,
                (d.decision_hash + prior).encode(),
                hashlib.sha256,
            ).hexdigest()
            if not _hmac.compare_digest(expected, d.merkle_root or ""):
                broken.append((i, d.request_id))
            prior = d.merkle_root or ""
        return {
            "total":        len(decisions),
            "broken_links": broken,
            "intact":       len(broken) == 0,
        }
```

---

## 7. Phase 4 — The Execution Token System

The TOCTOU problem is why tokens exist. Verify at T=0. State mutates at T=0.1. Execute at T=0.2 against stale authorization. Tokens close that gap.

```python
# src/pramanix/execution_token.py

from __future__ import annotations
import dataclasses
import hashlib
import hmac as _hmac
import uuid

import orjson

from pramanix.exceptions import (
    TokenExpiredError, TokenReplayedError, TokenStateMismatchError,
    TokenHMACInvalidError, TokenBackendError,
)


@dataclasses.dataclass(frozen=True)
class ExecutionToken:
    """
    Single-use, time-bounded, HMAC-signed authorization token.

    Single-use:   Redis GETDEL (atomic get+delete)
    Time-bounded: TTL via Redis key expiry (no background job)
    State-pinned: state_version ties token to state at verify() time
    HMAC-signed:  Prevents forgery
    """
    token_id:       str
    decision_hash:  str
    policy_hash:    str
    state_version:  str
    issued_at:      float
    expires_at:     float
    hmac_signature: bytes
    request_id:     str
    metadata:       frozenset[tuple[str, str]]

    def is_expired(self, clock: "Any") -> bool:
        return clock.now() >= self.expires_at

    def verify_hmac(self, secret: bytes) -> bool:
        expected = _compute_hmac(self, secret)
        return _hmac.compare_digest(expected, self.hmac_signature)


def _compute_hmac(token: ExecutionToken, secret: bytes) -> bytes:
    payload = orjson.dumps({
        "token_id":      token.token_id,
        "decision_hash": token.decision_hash,
        "policy_hash":   token.policy_hash,
        "state_version": token.state_version,
        "issued_at":     token.issued_at,
        "expires_at":    token.expires_at,
    }, option=orjson.OPT_SORT_KEYS)
    return _hmac.new(secret, payload, hashlib.sha256).digest()


class RedisExecutionTokenVerifier:
    """
    Production token backend backed by Redis.

    ATOMIC CONSUME: GETDEL (not GET + DEL) — prevents race conditions.
    QUOTA COUNT: Redis SCAN — fail-open on failure with WARNING log.
    """

    def __init__(self, redis, secret: bytes, clock=None) -> None:
        from pramanix.clock import SystemClock
        self._redis  = redis
        self._secret = secret
        self._clock  = clock or SystemClock()

    def mint(
        self,
        decision:      "Decision",
        ttl_seconds:   int = 30,
        state_version: str = "",
    ) -> ExecutionToken:
        if not decision.allowed:
            raise ValueError("Cannot mint token from BLOCK decision.")
        now   = self._clock.now()
        token = ExecutionToken(
            token_id       = str(uuid.uuid4()),
            decision_hash  = decision.decision_hash,
            policy_hash    = decision.policy_hash,
            state_version  = state_version,
            issued_at      = now,
            expires_at     = now + ttl_seconds,
            hmac_signature = b"",    # computed below
            request_id     = decision.request_id,
            metadata       = decision.metadata,
        )
        signed = dataclasses.replace(
            token, hmac_signature=_compute_hmac(token, self._secret)
        )
        self._redis.setex(
            f"pramanix:token:{token.token_id}",
            ttl_seconds + 5,         # small grace period for clock skew
            orjson.dumps(dataclasses.asdict(signed)),
        )
        return signed

    def consume(self, token: ExecutionToken, current_state_version: str = "") -> None:
        if token.is_expired(self._clock):
            raise TokenExpiredError(f"Token {token.token_id} expired.")
        if not token.verify_hmac(self._secret):
            raise TokenHMACInvalidError(f"Token {token.token_id} HMAC invalid.")
        if (token.state_version and current_state_version
                and token.state_version != current_state_version):
            raise TokenStateMismatchError(
                f"State changed after issuance. "
                f"Token: {token.state_version!r} — Current: {current_state_version!r}"
            )
        try:
            stored = self._redis.getdel(f"pramanix:token:{token.token_id}")
        except Exception as exc:
            raise TokenBackendError(f"Redis unavailable: {exc}") from exc
        if stored is None:
            raise TokenReplayedError(f"Token {token.token_id} already consumed.")

    def count(self, policy_hash_prefix: str = "*") -> int:
        try:
            return sum(1 for _ in self._redis.scan_iter(
                f"pramanix:token:{policy_hash_prefix}*"
            ))
        except Exception as exc:
            import structlog
            structlog.get_logger(__name__).warning(
                "execution_token: Redis SCAN failed — returning 0 (fail-open). "
                "Alert on pramanix_execution_token_redis_scan_failure_total.",
                exc_type=type(exc).__name__, exc_info=exc,
            )
            return 0
```

---

## 8. Phase 5 — The Translator Subsystem

### 8.1 The Five-Layer Pipeline (In Order)

Build these layers in order. Each must be complete before adding the next.

**Layer 1 — Injection Pre-Filter:** re2 (or stdlib re + SecurityWarning)
**Layer 2 — Intent Extraction Cache:** SHA-256 keyed LLM I/O cache
**Layer 3 — Dual-Model Consensus:** asyncio.gather(return_exceptions=True)
**Layer 4 — Adversarial Scoring:** ML injection score on extracted intent
**Layer 5 — Semantic Post-Consensus:** Non-numeric state → DENY

### 8.2 The Injection Pre-Filter — Build This First

```python
# src/pramanix/translator/injection_filter.py

from __future__ import annotations
import re
import warnings

from pramanix.exceptions import SecurityWarning, InjectionDetectedError

# ALWAYS import SecurityWarning from pramanix.exceptions.
# NEVER define it conditionally. See: Python 3.13 NameError disaster.

try:
    import re2 as _re_engine  # type: ignore[import-not-found]
    _RE2_AVAILABLE = True
except ImportError:
    _re_engine = re  # type: ignore[assignment]
    _RE2_AVAILABLE = False
    warnings.warn(
        "re2 not available — falling back to stdlib re (ReDoS risk on injection patterns). "
        "Install: pip install pramanix[re2]",
        SecurityWarning,
        stacklevel=2,
    )

_INJECTION_PATTERNS: list[str] = [
    r"ignore\s+(all\s+)?previous\s+instructions?",
    r"you\s+are\s+now\s+(a|an)",
    r"forget\s+everything",
    r"(new\s+)?system\s+prompt",
    r"jailbreak",
    r"DAN\s+mode",
    r"developer\s+mode",
    r"pretend\s+(you|you're|you are)",
    r"act\s+as\s+(if\s+you\s+(are|were)|a)",
    r"disregard\s+(your\s+)?(previous\s+)?instructions?",
]

_COMPILED_PATTERNS = [
    _re_engine.compile(p, _re_engine.IGNORECASE)
    for p in _INJECTION_PATTERNS
]


def check_for_injection(text: str) -> str | None:
    """
    Check text for injection patterns.
    Returns the matched pattern string, or None if clean.
    """
    for pattern in _COMPILED_PATTERNS:
        match = pattern.search(text)
        if match:
            return match.group(0)
    return None


def assert_no_injection(text: str, decision=None) -> None:
    """Raise InjectionDetectedError if injection is detected."""
    matched = check_for_injection(text)
    if matched:
        raise InjectionDetectedError(decision=decision, pattern_matched=matched)
```

### 8.3 The TranslatorProtocol

```python
# src/pramanix/translator/protocol.py

from __future__ import annotations
from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class TranslationResult:
    label:    str             # "ALLOW" | "BLOCK" | "UNKNOWN"
    intent:   dict | None     # Extracted field values
    confidence: float         # 0.0 – 1.0
    model_name: str
    provider:   str
    raw_response: str         # Raw LLM output for debugging

    @classmethod
    def unknown(cls, translator=None) -> "TranslationResult":
        return cls(
            label="UNKNOWN", intent=None, confidence=0.0,
            model_name=getattr(translator, "model_name", "unknown"),
            provider=getattr(translator, "provider", "unknown"),
            raw_response="",
        )


@runtime_checkable
class TranslatorProtocol(Protocol):
    model_name: str
    provider:   str

    async def translate(
        self,
        text:      str,
        policy_ir: object,
    ) -> TranslationResult: ...
```

### 8.4 The Dual-Model Consensus — The Critical asyncio.gather Pattern

```python
# src/pramanix/translator/consensus.py

from __future__ import annotations
import asyncio
from typing import Sequence

import structlog

from pramanix.translator.protocol import TranslationResult, TranslatorProtocol

_log = structlog.get_logger(__name__)


async def extract_with_consensus(
    natural_language:     str,
    policy_ir:            object,
    translators:          Sequence[TranslatorProtocol],
    *,
    require_agreement_of: int = 2,
    request_id:           str = "",
) -> "ConsensusResult":
    """
    Run N translators in parallel, require M-of-N agreement.

    WHY return_exceptions=True IS NON-NEGOTIABLE:
      Without it: first exception cancels all other coroutines.
      → Guard sees 1 result when it needs 2 → always BLOCK.
      → Failure reason swallowed → impossible to debug.
      With it: all coroutines always complete (or all fail).
    """
    from pramanix.exceptions import ConsensusFailedError

    if len(translators) < require_agreement_of:
        raise ConsensusFailedError(
            f"Need ≥{require_agreement_of} translators, got {len(translators)}."
        )

    # CRITICAL: return_exceptions=True — do not remove this
    raw: list = await asyncio.gather(
        *[t.translate(natural_language, policy_ir) for t in translators],
        return_exceptions=True,
    )

    results: list[TranslationResult] = []
    for i, r in enumerate(raw):
        if isinstance(r, Exception):
            _log.warning(
                "consensus: translator raised — counting as UNKNOWN vote",
                translator=translators[i].model_name,
                provider=translators[i].provider,
                exc_type=type(r).__name__, exc_info=r,
                request_id=request_id,
            )
            results.append(TranslationResult.unknown(translators[i]))
        else:
            results.append(r)

    return _compute_consensus(results, require_agreement_of)


def _compute_consensus(results, require_agreement_of):
    allow   = [r for r in results if r.label == "ALLOW"]
    block   = [r for r in results if r.label == "BLOCK"]
    unknown = [r for r in results if r.label == "UNKNOWN"]

    if len(allow) < require_agreement_of:
        return _ConsensusResult(
            reached=False, label="BLOCK", intent=None,
            allow_count=len(allow), block_count=len(block),
            unknown_count=len(unknown),
            reason=f"Only {len(allow)} ALLOW votes, need {require_agreement_of}",
        )

    # All ALLOW votes must agree on field values
    reference = allow[0].intent or {}
    for other in allow[1:]:
        other_intent = other.intent or {}
        disagreements = [
            k for k, v in reference.items()
            if k in other_intent and not _values_agree(v, other_intent[k])
        ]
        if disagreements:
            return _ConsensusResult(
                reached=False, label="BLOCK", intent=None,
                allow_count=len(allow), block_count=len(block),
                unknown_count=len(unknown),
                reason=f"ALLOW votes disagree on fields: {disagreements}",
            )

    return _ConsensusResult(
        reached=True, label="ALLOW", intent=allow[0].intent,
        allow_count=len(allow), block_count=len(block),
        unknown_count=len(unknown), reason="",
    )


def _values_agree(a, b, epsilon=1e-9) -> bool:
    try:
        return abs(float(a) - float(b)) < epsilon
    except (TypeError, ValueError):
        return a == b


class _ConsensusResult:
    def __init__(self, *, reached, label, intent, allow_count,
                 block_count, unknown_count, reason):
        self.reached        = reached
        self.label          = label
        self.intent         = intent
        self.allow_count    = allow_count
        self.block_count    = block_count
        self.unknown_count  = unknown_count
        self.reason         = reason
```

---

## 9. Phase 6 — The Observability Stack

### 9.1 The Metrics Module — Single Source of Truth

Every Prometheus metric in one module. Never define metrics inline elsewhere.

```python
# src/pramanix/metrics.py

from __future__ import annotations
import structlog

_log = structlog.get_logger(__name__)

try:
    from prometheus_client import Counter, Histogram, Gauge
    _PROM_AVAILABLE = True
except ImportError:
    _PROM_AVAILABLE = False
    _log.warning("prometheus_client not installed — all metrics are no-ops. "
                 "Install: pip install pramanix[metrics]")


def _counter(name, doc, labels=()):
    if _PROM_AVAILABLE:
        return Counter(name, doc, list(labels))
    return _NoOpCounter()


def _histogram(name, doc, labels=(), buckets=None):
    if _PROM_AVAILABLE:
        kw = {"buckets": buckets} if buckets else {}
        return Histogram(name, doc, list(labels), **kw)
    return _NoOpHistogram()


def _gauge(name, doc, labels=()):
    if _PROM_AVAILABLE:
        return Gauge(name, doc, list(labels))
    return _NoOpGauge()


class _NoOpCounter:
    def labels(self, **_): return self
    def inc(self, _=1): pass


class _NoOpHistogram:
    def labels(self, **_): return self
    def observe(self, _): pass
    def time(self): return _NoOpCM()


class _NoOpGauge:
    def labels(self, **_): return self
    def set(self, _): pass


class _NoOpCM:
    def __enter__(self): return self
    def __exit__(self, *_): pass


# ── Guard ─────────────────────────────────────────────────────────────────
GUARD_VERIFY_TOTAL   = _counter("pramanix_guard_verify_total",
    "Total Guard.verify() calls", ["policy", "status", "decision"])
GUARD_VERIFY_LATENCY = _histogram("pramanix_guard_verify_duration_seconds",
    "Guard.verify() end-to-end latency", ["policy", "decision"],
    buckets=[.001,.005,.01,.025,.05,.1,.25,.5,1.,2.5,5.,10.])
GUARD_UNHANDLED_EXC  = _counter("pramanix_guard_unhandled_exception_total",
    "Last-resort catch-all triggered — always a bug indicator", ["policy"])

# ── Solver ────────────────────────────────────────────────────────────────
SOLVER_LATENCY = _histogram("pramanix_solver_duration_seconds",
    "Z3 solver check() duration", ["policy", "phase"],
    buckets=[.001,.005,.01,.025,.05,.1,.25,.5,1.,2.5,5.])
SOLVER_TIMEOUT = _counter("pramanix_solver_timeout_total",
    "Z3 solver timeouts", ["policy"])

# ── Invariant violations ──────────────────────────────────────────────────
INVARIANT_VIOLATION = _counter("pramanix_invariant_violation_total",
    "Named invariant violations", ["policy", "invariant_name"])

# ── Fast path ─────────────────────────────────────────────────────────────
FAST_PATH_TOTAL         = _counter("pramanix_fast_path_decisions_total",
    "Fast-path pre-screen decisions", ["rule", "decision"])
FAST_PATH_PARSE_FAILURE = _counter("pramanix_fast_path_parse_failure_total",
    "Fast-path Decimal parse failures — fell through to Z3", ["rule"])

# ── Field coverage ────────────────────────────────────────────────────────
FIELD_SEEN_TOTAL = _counter("pramanix_field_seen_total",
    "Times a field appeared in Guard.verify()", ["policy", "field"])

# ── Circuit breaker ───────────────────────────────────────────────────────
CB_SYNC_FAILURE = _counter("pramanix_circuit_breaker_state_sync_failure_total",
    "Circuit breaker Redis sync failures", ["circuit_name"])

# ── Audit ─────────────────────────────────────────────────────────────────
SIGNING_FAILURE = _counter("pramanix_signing_failures_total",
    "Decision signing failures", ["algorithm", "reason"])

# ── NLP safety ───────────────────────────────────────────────────────────
NLP_MODEL_AVAILABLE = _gauge("pramanix_nlp_model_available",
    "NLP safety model load status (1=loaded, 0=failed/absent)", ["model"])

# ── Execution tokens ──────────────────────────────────────────────────────
TOKEN_ISSUED        = _counter("pramanix_execution_token_issued_total",    "", ["policy"])
TOKEN_CONSUMED      = _counter("pramanix_execution_token_consumed_total",  "", ["policy"])
TOKEN_EXPIRED       = _counter("pramanix_execution_token_expired_total",   "", ["policy"])
TOKEN_REPLAYED      = _counter("pramanix_execution_token_replayed_total",  "", ["policy"])
TOKEN_SCAN_FAILURE  = _counter("pramanix_execution_token_redis_scan_failure_total", "", [])

# ── Shadow evaluation ─────────────────────────────────────────────────────
SHADOW_DIVERGENCE = _counter("pramanix_shadow_policy_divergence_total",
    "Production vs shadow policy divergences", ["production_policy", "shadow_policy"])
SHADOW_ERROR      = _counter("pramanix_shadow_policy_error_total",
    "Shadow policy evaluation errors", [])


def emit_field_seen(policy_name: str, field_name: str) -> None:
    """
    Emit field coverage counter. Non-critical path.
    Log WARNING on failure — NEVER re-raise.
    """
    try:
        FIELD_SEEN_TOTAL.labels(policy=policy_name, field=field_name).inc()
    except Exception as _exc:
        _log.warning(
            "pramanix: field_seen metric emit failed",
            policy=policy_name, field=field_name,
            exc_type=type(_exc).__name__, exc_info=_exc,
        )
```

### 9.2 The Observable Failure Rule — The Pattern Every except Must Follow

Every `except` clause in `src/pramanix/` must follow one of these four patterns:

```
PATTERN A — Non-critical observability path (metrics):
    except Exception as _exc:
        _log.warning("metric emit failed", exc_type=type(_exc).__name__, exc_info=_exc)
        # DO NOT re-raise

PATTERN B — Security-posture downgrade:
    except ImportError:
        warnings.warn("re2 absent — ReDoS risk", SecurityWarning, stacklevel=2)
        _re_engine = re

PATTERN C — Critical infrastructure failure:
    except redis.RedisError as exc:
        raise TokenBackendError(f"Redis unavailable: {exc}") from exc

PATTERN D — GC finalizer (must have # INTENTIONAL comment):
    def __del__(self):
        try:
            self._executor.shutdown(wait=False)
        except Exception:
            pass   # INTENTIONAL: GC finalizer; event loop may be torn down.
```

CI gate: `grep -rn "except Exception: pass" src/pramanix/ | grep -v INTENTIONAL` must return empty.

---

## 10. Phase 7 — The Worker Architecture

### 10.1 The IPC Problem — Understand This Before Building

```
WRONG DESIGN (double IPC — wastes ~3ms per call):
  Caller → [IPC serialize] → async worker → [IPC serialize] → Z3 process
                                         ← [IPC deserialize] ← Z3 process
         ← [IPC deserialize] ← async worker

CORRECT DESIGN (Z3 runs inside worker — one hop only):
  Caller → [submit to ProcessPoolExecutor] → Worker process
                                             Z3 runs HERE, no IPC for Z3
           ← [result via pool] ←

WHY PROCESS POOL (not thread pool)?
  Z3 releases the GIL. Threads work technically.
  Process pool gives better memory isolation and prevents Z3 memory leaks
  in long-lived processes. max_tasks_per_child=1000 recycles workers.
```

### 10.2 The WorkerPool + PPID Watchdog

```python
# src/pramanix/worker.py

from __future__ import annotations
import asyncio
import os
import threading
import time
from concurrent.futures import ProcessPoolExecutor
from typing import Any

import structlog

_log = structlog.get_logger(__name__)


def _worker_init() -> None:
    """
    Called ONCE per worker process at startup.
    Starts PPID watchdog. Pre-warms Z3.
    """
    ppid = os.getppid()

    def _watchdog() -> None:
        while True:
            time.sleep(5)
            try:
                os.kill(ppid, 0)   # signal 0 = check existence, not kill
            except ProcessLookupError:
                _log.warning("worker: parent gone — self-terminating (PPID watchdog)")
                os._exit(0)        # Hard exit — no cleanup, no exceptions
            except PermissionError:
                pass               # Parent alive, we lack signal permission

    t = threading.Thread(target=_watchdog, daemon=True, name="pramanix-ppid-watchdog")
    t.start()

    # Pre-warm Z3: first context creation costs ~10ms
    from pramanix.solver import _get_ctx
    _get_ctx()


def _solve_in_worker(intent_data, state_data, policy_ir, timeout_ms, rlimit):
    """Run INSIDE the worker process. Z3 is local — no IPC for the solver."""
    from pramanix.solver import Z3Solver
    return Z3Solver().solve(intent_data, state_data, policy_ir, timeout_ms, rlimit)


class WorkerPool:
    """
    Process pool for parallel Z3 solving.
    Three defenses against Ghost Solver hangs:
      1. Per-call rlimit
      2. PPID watchdog thread
      3. asyncio.wait_for timeout
    """

    def __init__(
        self,
        workers:              int | None = None,
        max_tasks_per_worker: int = 1_000,
    ) -> None:
        self._n    = workers or max(1, (os.cpu_count() or 2) // 2)
        self._max  = max_tasks_per_worker
        self._pool: ProcessPoolExecutor | None = None

    def start(self) -> None:
        self._pool = ProcessPoolExecutor(
            max_workers=self._n,
            max_tasks_per_child=self._max,
            initializer=_worker_init,
        )
        _log.info("worker_pool: started", workers=self._n)

    def stop(self, wait: bool = True) -> None:
        if self._pool:
            self._pool.shutdown(wait=wait, cancel_futures=not wait)
            self._pool = None

    async def solve(
        self,
        intent_data: dict,
        state_data:  dict,
        policy_ir:   Any,
        timeout_ms:  int = 5_000,
        rlimit:      int = 10_000_000,
    ) -> Any:
        loop   = asyncio.get_running_loop()
        future = loop.run_in_executor(
            self._pool, _solve_in_worker,
            intent_data, state_data, policy_ir, timeout_ms, rlimit,
        )
        try:
            return await asyncio.wait_for(future, timeout=timeout_ms / 1000 + 2.0)
        except asyncio.TimeoutError:
            from pramanix.solver_protocol import SolveResult
            _log.warning("worker_pool: asyncio timeout — returning unknown result")
            return SolveResult("unknown", None, ["worker_asyncio_timeout"],
                               0, float(timeout_ms))

    def __del__(self) -> None:
        try:
            self.stop(wait=False)
        except Exception:
            pass   # INTENTIONAL: GC finalizer; event loop may be torn down.
```

---

## 11. Phase 8 — Integration Adapters

### 11.1 The Integration Status Registry — Always Current

```python
# src/pramanix/integrations/__init__.py

INTEGRATION_STATUS: dict[str, str] = {
    # Stable: tested against REAL framework objects in CI
    "langchain":   "stable",
    "langgraph":   "stable",
    "llamaindex":  "stable",
    "autogen":     "stable",
    "fastapi":     "stable",
    "openai":      "stable",
    "anthropic":   "stable",
    "cohere":      "stable",
    "gemini":      "stable",
    "mistral":     "stable",
    "grpc":        "stable",
    "kafka":       "stable",
    # Beta: documented stub-level implementations
    "crewai":          "beta",
    "dspy":            "beta",
    "haystack":        "beta",
    "semantic_kernel": "beta",
    "pydantic_ai":     "beta",
}


def get_integration_status(name: str) -> str:
    return INTEGRATION_STATUS.get(name, "unknown")
```

### 11.2 The Critical Pattern for Integration Fallbacks

Wrong — defines a stub that silently fails later:
```python
# BAD
try:
    from langchain_core.tools import BaseTool
except ImportError:
    class BaseTool:   # type: ignore[no-redef]
        pass
```

Right — fails loudly at first use:
```python
# GOOD
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from langchain_core.tools import BaseTool

try:
    from langchain_core.tools import BaseTool as _BaseTool
    _LANGCHAIN_AVAILABLE = True
except ImportError:
    _LANGCHAIN_AVAILABLE = False

    class _LangChainNotInstalledBase:
        def __init__(self, *a, **kw):
            raise ImportError(
                "langchain-core is required for PramanixGuardedTool. "
                "Install: pip install pramanix[langchain]"
            )
    _BaseTool = _LangChainNotInstalledBase
```

### 11.3 The LangChain Adapter — Full Pattern

```python
# src/pramanix/integrations/langchain.py

from __future__ import annotations
import asyncio
from typing import Any

import structlog

from pramanix.exceptions import ActionBlockedError

_log = structlog.get_logger(__name__)

try:
    from langchain_core.tools import BaseTool
    from langchain_core.callbacks import CallbackManagerForToolRun
    _LANGCHAIN_AVAILABLE = True
except ImportError:
    _LANGCHAIN_AVAILABLE = False
    BaseTool = object
    CallbackManagerForToolRun = Any


class PramanixGuardedTool(BaseTool):  # type: ignore[misc]
    """
    A LangChain tool governed by a Pramanix Guard.
    Every invocation requires formal Z3 proof before execution.
    """
    guard:             Any
    underlying_tool:   Any
    state_resolver:    Any
    token_verifier:    Any | None = None
    token_ttl_seconds: int = 30

    def _run(self, tool_input: str, run_manager=None) -> str:
        return asyncio.get_event_loop().run_until_complete(
            self._arun(tool_input, run_manager)
        )

    async def _arun(self, tool_input: str, run_manager=None) -> str:
        state    = await _call_maybe_async(self.state_resolver, tool_input)
        decision = await self.guard.verify(tool_input, state)

        if not decision.allowed:
            _log.info("langchain: tool blocked", tool=self.name,
                      decision_hash=decision.decision_hash[:8],
                      violated=decision.violated)
            raise ActionBlockedError(
                f"'{self.name}' blocked [{decision.status.value}]. "
                f"Violated: {', '.join(decision.violated)}. "
                f"ID: {decision.decision_hash[:8]}",
                decision=decision,
            )

        token = None
        if self.token_verifier:
            token = self.token_verifier.mint(
                decision, ttl_seconds=self.token_ttl_seconds,
                state_version=str(state.get("version", "")),
            )

        try:
            result = await _call_maybe_async(self.underlying_tool._arun, tool_input)
            _log.info("langchain: tool executed", tool=self.name)
            return result
        finally:
            if token and self.token_verifier:
                try:
                    self.token_verifier.consume(token)
                except Exception as exc:
                    _log.error("langchain: token consume failed after execution",
                               token_id=token.token_id, exc_info=exc)


async def _call_maybe_async(fn, arg):
    import inspect
    result = fn(arg)
    if inspect.isawaitable(result):
        return await result
    return result
```

---

## 12. Phase 9 — Safety Validators

### 12.1 The SafetyValidator Protocol

Validators feed field values into Z3 — they do not make security decisions themselves.

```python
# src/pramanix/safety/protocol.py

from __future__ import annotations
import dataclasses
from typing import Protocol, runtime_checkable


@dataclasses.dataclass(frozen=True)
class SafetyResult:
    passed:     bool
    confidence: float   # 1.0 for deterministic; 0.0-1.0 for ML
    reason:     str     # empty if passed=True
    validator:  str
    latency_ms: float


@runtime_checkable
class SafetyValidator(Protocol):
    name: str
    def validate(self, text: str) -> SafetyResult: ...
    async def validate_async(self, text: str) -> SafetyResult: ...
    def is_available(self) -> bool: ...
```

### 12.2 The Degradation Contract — Always Log, Always Set Gauge

```python
# src/pramanix/safety/nlp/toxicity.py

from __future__ import annotations
import time
import structlog

from pramanix.safety.protocol import SafetyResult
from pramanix.metrics import NLP_MODEL_AVAILABLE

_log = structlog.get_logger(__name__)


class ToxicityValidator:
    name = "toxicity"

    def __init__(self, threshold: float = 0.3) -> None:
        self._threshold = threshold
        self._model     = self._try_load()

    def _try_load(self):
        try:
            from detoxify import Detoxify
            model = Detoxify("original")
            NLP_MODEL_AVAILABLE.labels(model="detoxify").set(1)
            _log.info("ToxicityValidator: detoxify loaded successfully")
            return model
        except Exception as exc:
            NLP_MODEL_AVAILABLE.labels(model="detoxify").set(0)
            _log.warning(
                "ToxicityValidator: detoxify load failed (%s): %s — disabled. "
                "Install pramanix[nlp] to enable.",
                type(exc).__name__, exc,
            )
            return None

    def is_available(self) -> bool:
        return self._model is not None

    def validate(self, text: str) -> SafetyResult:
        t0 = time.perf_counter()
        if self._model is None:
            return SafetyResult(
                passed=True, confidence=0.0,
                reason="detoxify not available",
                validator=self.name,
                latency_ms=0.0,
            )
        scores   = self._model.predict(text)
        toxicity = scores.get("toxicity", 0.0)
        passed   = toxicity <= self._threshold
        return SafetyResult(
            passed=passed, confidence=1.0,
            reason="" if passed else f"toxicity={toxicity:.3f} > {self._threshold}",
            validator=self.name,
            latency_ms=(time.perf_counter() - t0) * 1000,
        )

    async def validate_async(self, text: str) -> SafetyResult:
        import asyncio
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.validate, text)
```

---

## 13. Phase 10 — The Policy Registry

### 13.1 The Registry Protocol

```python
# src/pramanix/registry/protocol.py

from typing import Protocol, runtime_checkable


@runtime_checkable
class PolicyRegistryProtocol(Protocol):
    """
    Content-addressed store for compiled PolicyIR artifacts.
    Append-only. Tamper-evident. Version-tagged.

    BACKENDS:
      FileRegistry     → local dev
      HTTPRegistry     → team/CI
      RedisRegistry    → production (atomic, TTL)
      S3Registry       → enterprise (durable, geo-redundant)
      PostgresRegistry → enterprise (transactional, queryable)
    """
    def store(self, policy_ir, tag=None) -> str: ...
    def fetch(self, ir_hash: str): ...
    def fetch_by_tag(self, name: str, version: str): ...
    def list_versions(self, name: str) -> list[str]: ...
    def verify(self, ir_hash: str) -> bool: ...
```

### 13.2 The Shadow Evaluator

```python
# src/pramanix/registry/shadow.py

import asyncio
import structlog

from pramanix.metrics import SHADOW_DIVERGENCE, SHADOW_ERROR

_log = structlog.get_logger(__name__)


class ShadowEvaluator:
    """
    Runs new policy alongside production on EVERY request.
    Production decision returned to caller. Shadow only logged.
    100% coverage before promotion — essential for financial policies.
    """

    def __init__(self, production, shadow) -> None:
        self._prod   = production
        self._shadow = shadow

    async def verify_with_shadow(self, intent, state, **kw):
        prod_d, shadow_d = await asyncio.gather(
            self._prod.verify(intent, state, **kw),
            self._shadow.verify(intent, state, **kw),
            return_exceptions=True,
        )
        if isinstance(shadow_d, Exception):
            SHADOW_ERROR.inc()
            _log.warning("shadow: evaluation failed", exc_info=shadow_d)
        elif hasattr(prod_d, "allowed") and hasattr(shadow_d, "allowed"):
            if prod_d.allowed != shadow_d.allowed:
                SHADOW_DIVERGENCE.labels(
                    production_policy=prod_d.policy_hash[:8],
                    shadow_policy=shadow_d.policy_hash[:8],
                ).inc()
                _log.info("shadow: DIVERGENCE",
                          prod="ALLOW" if prod_d.allowed else "BLOCK",
                          shadow="ALLOW" if shadow_d.allowed else "BLOCK",
                          intent_hash=getattr(prod_d, "intent_hash", "?"))
        return prod_d
```

---

## 14. Phase 11 — The Key Provider System

### 14.1 The KeyProvider Protocol

```python
# src/pramanix/key_provider.py

from typing import Protocol, runtime_checkable
from pramanix.exceptions import ConfigurationError, SecurityWarning


@runtime_checkable
class KeyProvider(Protocol):
    def get_signing_key(self) -> str: ...
    def get_anchor_key(self) -> bytes: ...
    def rotate_signing_key(self) -> str: ...


class FileKeyProvider:
    """
    DEVELOPMENT ONLY. Emits SecurityWarning at construction.
    NEVER returns a default key. NEVER swallows read exceptions.
    """
    def __init__(self, key_path: str) -> None:
        import warnings
        warnings.warn(
            f"FileKeyProvider({key_path!r}) is for development only. "
            "Use AWSKMSKeyProvider, AzureKeyVaultProvider, or GCPSecretManagerProvider.",
            SecurityWarning, stacklevel=2,
        )
        self._key_path = key_path

    def get_signing_key(self) -> str:
        try:
            with open(self._key_path) as f:
                return f.read().strip()
        except Exception as exc:
            raise ConfigurationError(
                f"FileKeyProvider: cannot read from {self._key_path!r}: {exc}"
            ) from exc

    def get_anchor_key(self) -> bytes:
        return self.get_signing_key().encode()

    def rotate_signing_key(self) -> str:
        raise NotImplementedError(
            "FileKeyProvider does not support key rotation. "
            "Use a proper KMS for production key rotation."
        )
```

---

## 15. Phase 12 — The Reliability Layer

### 15.1 The Circuit Breaker — The Lock Fix (Non-Negotiable)

```python
# src/pramanix/circuit_breaker.py

import functools
import asyncio
import structlog

_log = structlog.get_logger(__name__)


class AdaptiveCircuitBreaker:
    """
    States: CLOSED → OPEN → HALF_OPEN → CLOSED

    THE LOCK FIX (critical — never regress this):
    -----------------------------------------------
    WRONG:  @property
            def _lock(self) -> asyncio.Lock:
                return asyncio.Lock()   ← NEW LOCK on EVERY access
            Two coroutines each get their own lock → zero mutual exclusion.

    CORRECT: @functools.cached_property
             def _lock(self) -> asyncio.Lock:
                 return asyncio.Lock()  ← Created ONCE, cached per instance.
    """

    @functools.cached_property
    def _lock(self) -> asyncio.Lock:
        return asyncio.Lock()

    def __init__(
        self,
        threshold: float = 0.5,
        window:    int   = 60,
        clock:     "Any | None" = None,
    ) -> None:
        from pramanix.clock import SystemClock
        self._threshold     = threshold
        self._window        = window
        self._state         = "CLOSED"
        self._failure_count = 0
        self._request_count = 0
        self._last_failure  = 0.0
        self._clock         = clock or SystemClock()


class DistributedCircuitBreaker(AdaptiveCircuitBreaker):
    """Redis-backed circuit breaker with split-brain detection."""

    def __init__(self, redis, circuit_name: str, **kwargs) -> None:
        super().__init__(**kwargs)
        self._redis = redis
        self._name  = circuit_name

    def _sync_to_redis(self, state_dict: dict) -> None:
        from pramanix.metrics import CB_SYNC_FAILURE
        try:
            self._redis.hset(f"pramanix:cb:{self._name}", mapping=state_dict)
        except Exception as exc:
            CB_SYNC_FAILURE.labels(circuit_name=self._name).inc()
            _log.error(
                "circuit-breaker: Redis state sync failed — possible split-brain.",
                circuit_name=self._name, exc_info=exc,
            )
```

### 15.2 The TokenBucket Rate Limiter — Clock-Injectable

```python
# src/pramanix/rate_limiter.py

import threading


class TokenBucketRateLimiter:
    """
    Token bucket with injectable clock for deterministic tests.

    With FakeClock: advance(1.0) refills tokens instantly — no sleep().
    """

    def __init__(self, rate: float, capacity: float, clock=None) -> None:
        from pramanix.clock import SystemClock
        self._rate     = rate
        self._capacity = capacity
        self._tokens   = capacity
        self._clock    = clock or SystemClock()
        self._last_t   = self._clock.now()
        self._lock     = threading.Lock()

    def acquire(self, tokens: float = 1.0) -> bool:
        with self._lock:
            now          = self._clock.now()
            elapsed      = now - self._last_t
            self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
            self._last_t = now
            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False
```

---

## 16. Phase 13 — Developer Experience Platform

### 16.1 The Policy Linter — 14 Rules, Human-Readable Output

```python
# src/pramanix/linter.py

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any


@dataclass
class LintResult:
    policy_name:   str
    ir_hash:       str
    warnings:      list[str]        = field(default_factory=list)
    errors:        list[str]        = field(default_factory=list)
    boundary_notes: list[str]       = field(default_factory=list)
    invariant_results: list[dict]   = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return len(self.errors) == 0


class PolicyLinter:
    """
    Validates PolicyIR beyond compilation.
    Runs Z3 to detect trivially-SAT or trivially-UNSAT invariants.
    Checks boundary conditions (< vs <=, >= vs >).
    Validates regulatory citations are present.
    """

    def lint(self, policy_ir: Any, solver=None) -> LintResult:
        from pramanix.solver import Z3Solver
        s = solver or Z3Solver()
        result = LintResult(
            policy_name=policy_ir.name,
            ir_hash=policy_ir.ir_hash,
        )

        for inv in policy_ir.invariants:
            # Check invariant is satisfiable at all
            sat_result = s.is_satisfiable(policy_ir.with_only_invariant(inv.name))
            if sat_result.is_unsat:
                result.errors.append(
                    f"Invariant '{inv.name}' is trivially UNSAT — "
                    f"blocks every action. This is a policy authoring error."
                )

            # Check regulatory citation
            if not inv.regulatory_cite:
                result.warnings.append(
                    f"Invariant '{inv.name}' has no regulatory citation. "
                    f"Add .cite('...') for compliance reporting."
                )

            # Detect boundary conditions
            if inv.expression_tree.get("op") == "<=":
                result.boundary_notes.append(
                    f"Invariant '{inv.name}' uses <=. "
                    f"At exactly the threshold value, the action is ALLOWED. "
                    f"Verify this matches regulatory intent."
                )

            result.invariant_results.append({
                "name": inv.name,
                "satisfiable": sat_result.status,
                "has_citation": bool(inv.regulatory_cite),
            })

        return result
```

### 16.2 The CLI — Complete Command Set

```python
# src/pramanix/cli.py
# Use click or typer. Every command maps to a documented behavior.

# pramanix lint       --policy <class_or_file> [--simulate] [--format text|json|sarif]
# pramanix doctor     Check Z3, Redis, signing key, re2, NLP models, integrations
# pramanix benchmark  --policy <class> --calls N --workers N
# pramanix template   --list | --domain banking | <name>
# pramanix simulate   --policy <class> --examples examples.json [--margins]
# pramanix trace      --request-id <uuid> | --policy <name> [--since 24h]
# pramanix audit      verify-chain | export | report bsa-aml | report hipaa
# pramanix registry   store | push | pull | list | verify
# pramanix coverage   analyze --policy <name> --days 30 --prometheus <url>
```

---

## 17. Phase 14 — CI/CD, SLSA, Release Engineering

### 17.1 The Complete CI Workflow

```yaml
# .github/workflows/ci.yml

name: Pramanix CI

on: [push, pull_request]

jobs:
  lint-and-type-check:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.13" }
      - run: pip install poetry && poetry install --extras "all"
      - run: ruff check src/ tests/
      - run: mypy src/pramanix/ --ignore-missing-imports

      # ── CI Gates ────────────────────────────────────────────────────────
      - name: Gate — no z3.Solver patches in tests
        run: |
          count=$(grep -rn 'patch.*z3\.Solver\|patch.*pramanix\.guard\.solve' tests/ | wc -l)
          if [ "$count" -gt 0 ]; then
            echo "ERROR: $count z3.Solver patch(es). Replace with GuardConfig(solver=Stub())"
            exit 1
          fi

      - name: Gate — no silent exceptions in src/
        run: |
          count=$(grep -rn "except Exception: pass" src/pramanix/ | grep -v "INTENTIONAL" | wc -l)
          if [ "$count" -gt 0 ]; then
            echo "ERROR: $count bare 'except Exception: pass' without INTENTIONAL marker"
            exit 1
          fi

      - name: Gate — no deadline=None in Hypothesis tests
        run: |
          if grep -rn "deadline=None" tests/; then
            echo "ERROR: Use deadline=timedelta(seconds=5) — not deadline=None"
            exit 1
          fi

      - name: Gate — no bare sys.modules assignments
        run: |
          if grep -rn 'sys\.modules\[.*\] = None' tests/ | grep -v 'patch\.dict\|monkeypatch'; then
            echo "ERROR: Wrap in 'with patch.dict(sys.modules, {\"pkg\": None}):'"
            exit 1
          fi

      - name: Gate — no type: ignore in src/
        run: |
          count=$(grep -rn '# type: ignore' src/pramanix/ | wc -l)
          if [ "$count" -gt 0 ]; then
            echo "ERROR: $count type: ignore suppression(s) in src/pramanix/"
            exit 1
          fi

      - name: Gate — coverage floor is 98%
        run: |
          # CI must use 98%, not the wrong 95% override that was once there
          grep "fail_under = 98" pyproject.toml || exit 1

  test-unit:
    runs-on: ubuntu-24.04
    strategy:
      matrix:
        python-version: ["3.11", "3.12", "3.13"]
    steps:
      - uses: actions/checkout@v4
      - run: poetry install --extras "all"
      - run: pytest tests/unit/ -x --tb=short -q
      - run: pytest --cov=pramanix --cov-fail-under=98

  test-property:
    runs-on: ubuntu-24.04
    steps:
      - run: pytest tests/property/ --hypothesis-seed=42 -x

  test-adversarial:
    runs-on: ubuntu-24.04
    steps:
      - run: pip install google-re2
      - env: { PRAMANIX_REQUIRE_RE2: "1" }
        run: pytest tests/adversarial/ -x -v
        # Any SecurityWarning during adversarial tests = failure

  test-integration:
    runs-on: ubuntu-24.04
    services:
      redis:    { image: "redis:7-alpine",    ports: ["6379:6379"] }
      postgres: { image: "postgres:16-alpine", ports: ["5432:5432"],
                  env: { POSTGRES_PASSWORD: test } }
    steps:
      - run: pytest tests/integration/ -x --tb=short

  coverage:
    needs: [test-unit]
    runs-on: ubuntu-24.04
    steps:
      - run: pytest --cov=pramanix --cov-report=xml
      - uses: codecov/codecov-action@v4

  integration-gate:
    # CRITICAL: this must gate the merge pipeline
    # The integration job not gating merge was the original flaw
    needs: [test-unit, test-integration, test-adversarial]
    runs-on: ubuntu-24.04
    steps:
      - run: echo "All integration gates passed"
```

### 17.2 SLSA Level 3 Release Pipeline

```yaml
# .github/workflows/release.yml

name: Release (SLSA Level 3)
on:
  push:
    tags: ["v*.*.*"]
permissions:
  contents: write
  id-token: write

jobs:
  build:
    runs-on: ubuntu-24.04
    outputs:
      hashes: ${{ steps.hash.outputs.hashes }}
    steps:
      - uses: actions/checkout@v4
      - run: poetry build
      - name: Generate SBOM
        run: |
          pip install cyclonedx-bom
          cyclonedx-py environment --output sbom.json
      - id: hash
        run: |
          sha256sum dist/* > hashes.txt
          echo "hashes=$(base64 -w0 hashes.txt)" >> $GITHUB_OUTPUT

  provenance:
    needs: build
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2
    with:
      base64-subjects: "${{ needs.build.outputs.hashes }}"
    permissions:
      actions: read
      contents: write
      id-token: write

  sign:
    needs: build
    runs-on: ubuntu-24.04
    steps:
      - uses: sigstore/cosign-installer@v3
      - run: cosign sign-blob dist/*.whl --output-signature dist/*.whl.sig

  publish:
    needs: [build, provenance, sign]
    environment: pypi
    runs-on: ubuntu-24.04
    steps:
      - uses: pypa/gh-action-pypi-publish@release/v1
        with: { attestations: true }
```

---

## 18. Phase 15 — Kubernetes Production Deployment

```yaml
# deploy/k8s/deployment.yaml

apiVersion: apps/v1
kind: Deployment
metadata:
  name: pramanix-guard
  namespace: pramanix-prod
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate: { maxSurge: 1, maxUnavailable: 0 }
  template:
    metadata:
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port:   "8080"
        prometheus.io/path:   "/metrics"
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser:    65534
      containers:
      - name: pramanix
        image: ghcr.io/your-org/pramanix:1.0.0
        ports:
          - containerPort: 8080   # HTTP + /metrics
          - containerPort: 9090   # gRPC
        env:
          - name: PRAMANIX_SIGNING_KEY
            valueFrom: { secretKeyRef: { name: pramanix-secrets, key: signing-key } }
          - name: PRAMANIX_ANCHOR_KEY
            valueFrom: { secretKeyRef: { name: pramanix-secrets, key: anchor-key } }
          - name: REDIS_URL
            valueFrom: { secretKeyRef: { name: pramanix-secrets, key: redis-url } }
          - name: PRAMANIX_REQUIRE_RE2
            value: "1"
          - name: PRAMANIX_WORKERS
            value: "4"
          # CRITICAL: Do NOT set PRAMANIX_TRANSLATOR_ENABLED=false in production
          # This was baked into both Dockerfiles — that is a serious flaw to avoid
        resources:
          requests: { cpu: "2", memory: "4Gi" }
          limits:   { cpu: "4", memory: "8Gi" }
        livenessProbe:
          httpGet: { path: /health/live, port: 8080 }
          initialDelaySeconds: 10
          periodSeconds: 10
        readinessProbe:
          httpGet: { path: /health/ready, port: 8080 }
          initialDelaySeconds: 5
          periodSeconds: 5

---
# deploy/monitoring/alerts.yaml

groups:
  - name: pramanix.critical
    rules:
      - alert: PramanixGuardUnhandledException
        expr:  rate(pramanix_guard_unhandled_exception_total[5m]) > 0
        for:   1m
        labels: { severity: critical }
        annotations:
          summary: "Guard last-resort catch-all triggered — this is a bug."

      - alert: PramanixSigningFailure
        expr:  rate(pramanix_signing_failures_total[5m]) > 0
        for:   1m
        labels: { severity: critical }
        annotations:
          summary: "Decision signing failures — audit records may be unsigned."

      - alert: PramanixCircuitBreakerSplitBrain
        expr:  rate(pramanix_circuit_breaker_state_sync_failure_total[5m]) > 0
        for:   1m
        labels: { severity: critical }
        annotations:
          summary: "Circuit breaker Redis sync failures — possible split-brain."

  - name: pramanix.high
    rules:
      - alert: PramanixSolverTimeoutHigh
        expr:  rate(pramanix_solver_timeout_total[5m]) > 0.1
        for:   2m
        labels: { severity: high }
        annotations:
          summary: "Z3 timeout rate >10%."

      - alert: PramanixNLPModelUnavailable
        expr:  pramanix_nlp_model_available == 0
        for:   5m
        labels: { severity: high }
        annotations:
          summary: "NLP model {{ $labels.model }} failed — scoring disabled."

      - alert: PramanixFieldCoverageMetricAbsent
        expr:  absent(pramanix_field_seen_total)
        for:   10m
        labels: { severity: high }
        annotations:
          summary: "Field coverage counter absent — Prometheus metric may be silently failing."
```

---

## 19. The Testing Doctrine — How to Test a Security Kernel

### 19.1 The Test Hierarchy

```
tests/
├── unit/            # Fast, isolated. No real infrastructure.
│                    # Inject stubs via GuardConfig(solver=Stub()).
│                    # Every unit test completes in <100ms.
│
├── integration/     # Real containers (testcontainers).
│                    # Real Redis, Postgres, Kafka, Vault, LocalStack.
│                    # Tests the full stack with real I/O.
│
├── adversarial/     # Injection attacks, jailbreak attempts, fail-safe invariants.
│                    # Uses REAL re2 (PRAMANIX_REQUIRE_RE2=1).
│                    # Uses REAL injection pre-filter (not stubs).
│
├── property/        # Hypothesis-based. deadline=timedelta(seconds=5) everywhere.
│                    # NEVER deadline=None. Deadline violations = Z3 regression.
│
└── benchmarks/      # Performance regression detection.
                     # Results saved to benchmarks/results/{version}/{date}/{hardware}.json
```

### 19.2 The Real Protocols Pattern

Tests need doubles for external dependencies (Redis, Kafka, S3). The pattern:

**Wrong:** MagicMock (auto-attributes — wrong return types, wrong behavior)

**Right:** Duck-typed real implementations with real method signatures

```python
# tests/helpers/real_protocols.py

class _PingOkRedisClient:
    """Duck-type for Redis client that always responds to ping."""
    def ping(self) -> bool: return True
    def get(self, key: str): return None
    def setex(self, key, ttl, value): pass
    def getdel(self, key): return None
    def scan_iter(self, pattern): return iter([])
    def hset(self, key, mapping): pass
    def close(self): pass


class _PingFailRedisClient:
    """Duck-type for Redis client that fails on ping."""
    def ping(self):
        raise ConnectionError("Redis unreachable — test injection")
    def close(self): pass
```

### 19.3 The Mandatory Test — Every Phase Gate

Phase 0 (Z3 Core) gate:
```python
# tests/unit/test_solver.py
# Must pass: decimal precision, thread safety, protocol conformance
```

Phase 1 (Policy Engine) gate:
```python
# tests/unit/test_policy_compiler.py
# Must pass: all 14 validation rules, each as a separate test
```

Phase 2 (Guard Pipeline) gate:
```python
# tests/unit/test_guard_fail_closed.py
# Must pass: never raises, fail-closed on exception/timeout, structural integrity
```

Phase 3 (Audit) gate:
```python
# tests/unit/test_signer.py
# Must pass: ConfigurationError on None key, HMAC correctness, verification semantics
```

Phase 4 (Tokens) gate:
```python
# tests/unit/test_execution_token.py
# Must pass: single-use, TTL expiry (with FakeClock!), state mismatch, HMAC tampering
```

Phase 5 (Translator) gate:
```python
# tests/unit/test_consensus.py
# Must pass: return_exceptions=True enforced, fail-closed on both translators failing,
# disagreement on field values → BLOCK
```

---

## 20. The Observability Contract — Every Metric, Every Alert

### 20.1 The Three Observability Questions

Every production issue must be diagnosable from metrics + logs alone. Design for this upfront.

**Question 1: Is the system healthy right now?**
Answered by: `pramanix_guard_verify_total`, `pramanix_solver_timeout_total`, `pramanix_guard_unhandled_exception_total`

**Question 2: Is the audit trail intact?**
Answered by: `pramanix_signing_failures_total`, `pramanix_circuit_breaker_state_sync_failure_total`

**Question 3: Is the security posture degraded?**
Answered by: `pramanix_nlp_model_available`, `pramanix_execution_token_redis_scan_failure_total`, `pramanix_field_seen_total` (absence alerts)

### 20.2 The Latency Architecture — What You Are Building Toward

```
Component                            P50     P95     P99
─────────────────────────────────────────────────────────
Pydantic strict validation          0.15ms  0.40ms  0.80ms
Fast-path pre-screen                0.05ms  0.10ms  0.20ms
Redis resolver (cached layer)       0.50ms  1.50ms  3.00ms
Z3 formula construction (cached)    0.30ms  0.80ms  1.50ms
Z3 check() — 4–6 invariants         1.50ms  4.00ms  8.00ms
Decision construction + signing     0.20ms  0.35ms  0.65ms
Prometheus + OTel emit              0.05ms  0.10ms  0.20ms
─────────────────────────────────────────────────────────
TOTAL — Z3, Redis, 4–6 invariants   4.0ms   9.0ms  18.0ms  ← TARGET
```

Every LLM workflow already spends 100–2000ms on inference. Pramanix adds ≤2%. That is the headline.

---

## 21. The Beyond — What Lies Above the Ideal

### 21.1 What the Ideal Architecture Does Not Yet Solve

The Ideal_Architecture.md document represents the best of what is currently specifiable. Here is what lies beyond it — problems not yet solved by any framework:

**Beyond 1 — Intent-Verification (the open problem)**
Pramanix verifies that the encoded policy is satisfied. It cannot verify that the policy author encoded their actual intent correctly. `E("amount") <= 10000` might mean "block above 10,000" or the author meant "10,000 is the exclusive limit." Both compile. Both pass the linter. Formal intent-verification requires bridging natural language semantics to Z3 semantics — an unsolved problem at the intersection of NLP and formal methods.

*The path forward:* Build a policy decompiler that translates PolicyIR back to plain English with worked examples, and require a human sign-off. Not perfect, but closes the gap by 80%.

**Beyond 2 — Adaptive Policies (policies that learn from traffic)**
Current policies are static. A wire transfer policy has fixed thresholds. But what if the optimal daily limit should adapt to a user's verified transaction history? A static policy cannot express this without external state injection.

*The path forward:* A `DynamicField` type that pulls its current value from a resolver at verify-time. The field declaration says "daily_limit comes from UserProfileResolver." The policy invariant remains static Z3 arithmetic.

**Beyond 3 — Multi-Step Reasoning Chains (not just single actions)**
Guard.verify() gates a single action. A multi-step agent plan (transfer $500 + buy stock + send email) can satisfy each invariant individually while violating a combined constraint. No framework currently governs compound action sequences formally.

*The path forward:* A `CompoundGuard` that takes a sequence of actions and verifies them as a unit, with Z3 encoding the sequential constraints: action[n].state_after == action[n+1].state_before.

**Beyond 4 — Formal Policy Equivalence (are two policies semantically identical?)**
Two teams write policies for the same regulatory requirement independently. Are they equivalent? You cannot answer this by reading them. Z3 can answer it in milliseconds: `∀x: policy1(x) ↔ policy2(x)`.

*The path forward:* A `PolicyEquivalenceChecker` that builds a single Z3 formula encoding both policies and asks Z3 whether any input produces different outcomes.

**Beyond 5 — Adversarial Policy Synthesis**
Given a policy, can you automatically generate the inputs that maximally stress each boundary condition? Z3 already generates counterexamples — extend this to generate a complete boundary test suite automatically.

*The path forward:* For each invariant, use Z3 to enumerate boundary cases: exact threshold values, one unit above/below, combinations of multiple invariants at their boundaries. This generates a test suite from the policy itself.

**Beyond 6 — Cross-Organization Policy Composition**
Organization A uses Pramanix. Organization B uses Pramanix. They form a joint operation. Can the combined policy (A's invariants AND B's invariants) be formally analyzed for inconsistency before deployment?

*The path forward:* PolicyIR is JSON. Two PolicyIRs can be merged into a combined IR. Z3 checks consistency of the union. A trivially-UNSAT combined policy (impossible to satisfy both) is detected immediately.

**Beyond 7 — Differential Privacy in Audit Records**
Audit records contain sensitive field values (balances, amounts). Regulators need to verify decisions but shouldn't see raw values. Differential privacy techniques can add calibrated noise to numeric values in audit exports while preserving statistical properties auditors care about.

*The path forward:* An `AuditExporter` with `--privacy-budget ε` that applies Laplace noise to numeric fields in exported records before handing to auditors.

**Beyond 8 — Hardware-Level Isolation for Z3**
For the most security-sensitive deployments (defense, critical infrastructure), running Z3 in a standard Linux process is insufficient. An adversary with code execution can modify Z3's memory. The path to hardware-level guarantee: run Z3 inside an Intel SGX enclave, where the solver result is cryptographically attested by the hardware itself.

*The path forward:* A `SGXSolver` that wraps Z3 running inside an SGX enclave. The solve result includes an attestation report that the computation occurred on genuine Intel hardware in a genuine enclave.

### 21.2 The Research Frontier

These require original research contributions, not just engineering:

- **Quantitative policy verification:** Not just SAT/UNSAT, but "how far is this action from violating an invariant?" (margin analysis as a first-class Z3 concept, not post-hoc arithmetic)
- **Compositional formal proofs:** Prove that if component A satisfies property P and component B satisfies property Q, then the composition satisfies property R — without re-verifying the composition from scratch
- **Probabilistic invariants:** "The probability that amount > balance, given the distribution of historical transactions" — probability theory meets formal methods
- **Temporal logic policies:** "This action is safe NOW but would violate an invariant if performed within 60 seconds of another action" — LTL/CTL meets the Guard

---

## 22. The Build Order — Day by Day, Week by Week

### Weeks 1–2: The Bedrock

1. Repository skeleton + `pyproject.toml` exactly as specified
2. `exceptions.py` (ALL exceptions, including `SecurityWarning` unconditionally defined)
3. `clock.py` (`ClockProtocol`, `SystemClock`, `MonotonicClock`, `FakeClock`)
4. `solver_protocol.py` (`SolveResult`, `SolverProtocol`)
5. `tests/helpers/solver_stubs.py` (all four stubs)
6. `solver.py` (Z3Solver — thread-local contexts, exact Decimal)
7. `tests/unit/test_solver.py` (precision, thread safety, protocol conformance)

**Gate:** `pytest tests/unit/test_solver.py` — 100% pass

### Weeks 3–4: The Policy Engine

8. `expressions.py` (E(), ExpressionNode, __bool__ trap, ConstraintExpr, .named(), .explain(), .cite())
9. `policy.py` (Policy base class, Field)
10. `policy_ir.py` (PolicyIR, CompiledInvariant, CompiledField)
11. `policy_compiler.py` (PolicyCompiler, 14 validation rules)
12. `transpiler.py` (Transpiler, formula caching, exact Decimal)
13. `examples/banking/wire_transfer.py` (WireTransferPolicy — your integration anchor)
14. `tests/unit/test_policy_compiler.py` (one test per validation rule)

**Gate:** `PolicyCompiler().compile(WireTransferPolicy)` produces a valid `PolicyIR`

### Weeks 5–6: The Guard Pipeline

15. `decision.py` (Decision, DecisionStatus, `__post_init__` enforcement)
16. `guard_config.py` (GuardConfig)
17. `guard.py` (Guard — full fail-closed contract)
18. `tests/unit/test_guard_fail_closed.py` (the mandatory test suite — never regress these)

**Gate:** All 5 guard fail-closed tests pass. CI gate for `patch("z3.Solver")` active.

### Weeks 7–8: The Audit Engine

19. `audit/signer.py` (DecisionSigner — hard fail on None key)
20. `audit/merkle.py` (MerkleAnchor + offline verify_chain)
21. `tests/unit/test_signer.py` + `tests/unit/test_merkle.py`
22. `audit/sinks/` (start with S3 and Kafka sinks)

**Gate:** Decision signed → hash verifiable → Merkle chain integrity check passes

### Weeks 9–10: Execution Tokens + Observability

23. `execution_token.py` (ExecutionToken, RedisExecutionTokenVerifier — GETDEL atomicity)
24. `metrics.py` (all Prometheus metrics — single source of truth)
25. `tests/unit/test_execution_token.py` (single-use, TTL with FakeClock, replay detection)

**Gate:** FakeClock advances 31 seconds — token expires. Zero `sleep()` calls in test.

### Weeks 11–13: The Translator

26. `translator/injection_filter.py` (re2 fallback with SecurityWarning)
27. `translator/protocol.py` (TranslatorProtocol, TranslationResult)
28. `translator/consensus.py` (extract_with_consensus — return_exceptions=True)
29. First real translator: `translator/anthropic.py`
30. `tests/unit/test_consensus.py` (both fail → BLOCK, disagreement → BLOCK)
31. `tests/adversarial/test_injection_blocked_error.py` (real re2, real patterns)

**Gate:** Injection payload raises `InjectionDetectedError` before any LLM call

### Weeks 14–16: Workers + Integrations + Safety

32. `worker.py` (WorkerPool, PPID watchdog, _solve_in_worker)
33. `integrations/langchain.py` (PramanixGuardedTool)
34. `integrations/langgraph.py` (guarded_node, PramanixAgentOrchestrationAdapter)
35. `safety/protocol.py` + `safety/nlp/toxicity.py` + `safety/nlp/pii.py`
36. `circuit_breaker.py` (cached_property lock — never regress this)
37. `rate_limiter.py` (ClockProtocol injection)

### Weeks 17–20: Registry, Key Providers, CLI, DX

38. `registry/` (FileRegistry, HTTPRegistry)
39. `key_provider.py` (FileKeyProvider with SecurityWarning, AWSKMSKeyProvider)
40. `linter.py` (PolicyLinter, 14 rules → human-readable output)
41. `simulate.py` (PolicySimulator with margin analysis)
42. `cli.py` (lint, doctor, benchmark, simulate, audit commands)

### Weeks 21–24: Production Infrastructure

43. Kubernetes manifests (deployment, HPA, NetworkPolicy)
44. Prometheus alerts (all 8 critical + high alerts)
45. SLSA Level 3 release pipeline
46. Server-class benchmarks (8-core/32GB Linux) → `benchmarks/results/v1.0.0/`
47. Complete documentation (THESIS.md, PROOF_DOSSIER.md, MIGRATION.md)

---

## 23. Common Mistakes and How to Avoid Them

### Mistake 1 — Patching z3.Solver in Tests

**What it looks like:** `with patch("z3.Solver") as mock_solver: mock_solver.return_value.check.return_value = z3.sat`

**Why it's wrong:** A Z3 version regression producing wrong answers would pass these tests silently.

**Correct approach:** `Guard(Policy, config=GuardConfig(solver=AlwaysSATStub()))`

### Mistake 2 — Bare sys.modules Assignments Without Context Manager

**What it looks like:** `sys.modules["redis"] = None  # at test level, not in a context manager`

**Why it's wrong:** Test failure or `KeyboardInterrupt` leaves `sys.modules` permanently polluted, causing cascading failures in subsequent tests that are impossible to debug.

**Correct approach:** `with patch.dict(sys.modules, {"redis": None}): ...`

### Mistake 3 — deadline=None in Hypothesis Tests

**What it looks like:** `@settings(deadline=None) def test_property(data): ...`

**Why it's wrong:** A Z3 performance regression is completely invisible. The test passes in 45 seconds. Nobody notices until production latency spikes.

**Correct approach:** `@settings(deadline=timedelta(seconds=5))` — regressions become failures.

### Mistake 4 — The asyncio.Lock Recreation Bug

**What it looks like:**
```python
@property
def _lock(self) -> asyncio.Lock:
    return asyncio.Lock()   # NEW lock every time!
```

**Why it's wrong:** Two coroutines entering `async with self._lock:` get different locks. Zero mutual exclusion. State corrupted silently under concurrency.

**Correct approach:** `@functools.cached_property` — the lock is created exactly once.

### Mistake 5 — Defining SecurityWarning Conditionally

**What it looks like:**
```python
if sys.version_info < (3, 12):
    class SecurityWarning(UserWarning): ...
```

**Why it's wrong:** `SecurityWarning` is not a Python built-in in any version. On Python 3.13, this condition is False, the class is never defined, and any `warnings.warn(..., SecurityWarning)` call raises `NameError` — failing 75+ tests.

**Correct approach:** Import from `pramanix.exceptions`. Define it once, unconditionally.

### Mistake 6 — InMemoryAuditSink in Production __all__

**What it looks like:** `__all__ = [..., "InMemoryAuditSink", ...]` in the main package init

**Why it's wrong:** Any developer who types `from pramanix import InMemoryAuditSink` in a production config silently loses all audit records on process restart with no error.

**Correct approach:** `InMemoryAuditSink` lives in `pramanix.testing`. Period. It is never exported from `pramanix.__init__`.

### Mistake 7 — PRAMANIX_TRANSLATOR_ENABLED=false Baked into Dockerfiles

**What it looks like:** `ENV PRAMANIX_TRANSLATOR_ENABLED="false"` in both Dockerfiles

**Why it's wrong:** The LLM translation pathway is never exercised in any Docker-based test run or production container. You ship a governance system with the AI integration disabled by default.

**Correct approach:** Default to enabled. Add a documented override for environments without LLM access. Never bake it into the image.

### Mistake 8 — Integration Job Not Gating the Merge Pipeline

**What it looks like:** `integration:` job with `needs: test` but not listed in any subsequent job's `needs:`

**Why it's wrong:** A broken integration test can be merged. The downstream `wheel-smoke`, `trivy`, `license-scan` gates run regardless of integration failure.

**Correct approach:** Integration must be in the `needs:` of the final merge gate. If integration fails, the PR cannot merge.

### Mistake 9 — pyproject.toml Says 98%, CI Says 95%

**What it looks like:** `fail_under = 98` in `pyproject.toml`, but `coverage report --fail-under=95` in `ci.yml`

**Why it's wrong:** The CI step explicitly overrides the config file. The enforced floor is 95%. Three percent of uncovered production code goes undetected across every PR.

**Correct approach:** Remove `--fail-under` from the CI command. Let the config file be authoritative. CI reads `pyproject.toml` automatically.

### Mistake 10 — Fake Credentials in Tests Excluded from Secrets Scan

**What it looks like:** `--exclude-dir=tests` in the secrets scanner CI step

**Why it's wrong:** `"unit-test-fake-key-xyzzy"`, `"test-key"`, `"FAKE_PEM"` all exist in committed test code and are never detected by the scanner. If a real key is accidentally committed to a test file, it goes undetected.

**Correct approach:** Run the secrets scanner on tests too. Use a known-false-positive suppression list for intentional test fixtures.

---

## 24. Glossary — Every Concept, From First Principles

**Z3 SMT Solver** — A mathematical program that decides whether a set of logical statements can all be true at once ("satisfiable") and produces a concrete counterexample when they cannot. Z3 is the security kernel of Pramanix. It is not a heuristic. It is a proof.

**SAT (Satisfiable)** — Z3 found values for all fields that make ALL invariants simultaneously true. In Pramanix: SAT → ALLOW. A Z3 model (witness) is attached to the Decision.

**UNSAT (Unsatisfiable)** — Z3 proved that no assignment of field values can make all invariants simultaneously true. In Pramanix: UNSAT → BLOCK. A counterexample (the violated invariant names) is attached.

**Unknown** — Z3 ran out of time (timeout) or resources (rlimit) before reaching a conclusion. In Pramanix: Unknown → BLOCK. Fail-closed. The system never says "I don't know, let it through."

**Thread-local Z3 Context** — Z3's global context is not thread-safe. Each thread gets its own `z3.Context()` object. Every Z3 variable, value, and solver must be created with `ctx=` pointing to the thread-local context.

**Exact Decimal arithmetic** — Financial invariants require `0.1 + 0.1 + 0.1 == 0.3` exactly. In IEEE-754 floating point, this is false. Pramanix converts `Decimal("0.1")` to `z3.RatVal(n, d)` where `(n, d) = Decimal("0.1").as_integer_ratio()` — exact rational representation.

**SolverProtocol** — A Python `Protocol` defining the interface between Guard and any SMT backend. The real `Z3Solver` implements it. Test stubs (`AlwaysSATStub`, etc.) also implement it. Guard accepts any conforming object. This eliminates `patch("z3.Solver")` permanently.

**ClockProtocol** — One-method interface: `now() -> float`. `SystemClock` wraps `time.time()`. `FakeClock` is fully controllable: `clock.advance(31.0)` simulates 31 seconds instantly, enabling TTL tests without `sleep()`.

**PolicyIR** — The compiled, content-addressed, JSON-serializable form of a Policy. Like bytecode. `ir_hash = SHA-256(canonical_json)`. Any change to any field or invariant produces a different hash. Every Decision records `ir_hash` — you can reconstruct exactly which policy ran on any historical decision.

**Decision** — The immutable, signed, auditable result of every `Guard.verify()` call. `allowed` is a bool. `status` is the machine-readable reason. `proof` is the Z3 evidence. `signature` is the Ed25519 bytes. `merkle_root` links to the prior decision. `latency_ms` is the wall-clock time.

**Fail-Closed** — On error or uncertainty, say NO. Guard.verify() is fail-closed in every error path. Solver exception → `allowed=False`. Timeout → `allowed=False`. Bug in Guard internals → `allowed=False`. Never "allow on uncertainty."

**TOCTOU (Time-Of-Check Time-Of-Use)** — The gap between verifying safety (T=0) and executing the action (T=N). State can change in that gap. A balance of $120,000 at T=0 might be $0 at T=30s if another process drains it. ExecutionTokens close this gap by binding the authorization to the state version at verify-time.

**ExecutionToken** — Single-use (Redis GETDEL), time-bounded (TTL), HMAC-signed authorization token. Minted from an ALLOW Decision. Consumed atomically at the execution boundary. Replaying returns `TokenReplayedError`. Expiry returns `TokenExpiredError`. State change returns `TokenStateMismatchError`.

**Dual-Model Consensus** — Two independent LLMs must both agree before accepting a natural language intent. Both must agree on the verdict AND all field values. Requiring two model providers to be simultaneously jailbroken raises the adversarial bar from "trick one model" to "trick two independent models at once."

**Merkle Chain** — A sequence where each record's fingerprint includes the prior record's fingerprint. `root[n] = HMAC(key, hash[n] + root[n-1])`. Deleting or modifying any record breaks all subsequent roots — tamper-evident by construction, verifiable offline without a running Pramanix instance.

**SLSA Level 3** — Supply-chain Levels for Software Artifacts. Level 3 requires: builds on a hardened isolated system; provenance is unforgeable (generated by the build system, not the developer); no human access to push artifacts directly.

**Shadow Evaluator** — Runs a new policy alongside production on every request. Production decision is returned to callers. Shadow decision is only logged. Divergences (prod ALLOW, shadow BLOCK) are counted in `pramanix_shadow_policy_divergence_total`. This gives 100% traffic coverage before policy promotion — not 10% canary.

**SolverProtocol.is_satisfiable()** — Used by the policy linter to check: "Is there any input at all that would be ALLOWED by this policy?" A policy that is trivially UNSAT (no input ever satisfies it) blocks every action — a policy authoring error detected at compile time.

**Ghost Solver** — A Z3 solver process that continues running after the parent process exits. Prevented by three independent defenses: per-call rlimit, PPID watchdog thread (kills self if parent dies), asyncio.wait_for timeout at the callsite.

**re2** — Google's RE2 library, which guarantees linear-time regex matching. Python's stdlib `re` can exhibit catastrophic backtracking (ReDoS) on adversarially crafted injection patterns. When re2 is absent, Pramanix falls back to stdlib `re` and emits `SecurityWarning`.

**SecurityWarning** — A `UserWarning` subclass emitted when Pramanix operates in a security-reduced mode (re2 absent, signing key missing in dev, etc.). Not a Python built-in in any version. Defined in `pramanix.exceptions` unconditionally.

---

*This blueprint is a living document. Every open item in §22 is a concrete engineering task.
Every law in §1.3 is a CI gate. Every phase gate is a binary: it either passes or it doesn't.*

*The system described here does not exist fully anywhere. That is why you are building it.*
