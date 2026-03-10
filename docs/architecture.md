# Pramanix — Architecture

> For the complete design specification see [Blueprint.md](Blueprint.md).

## Overview

Pramanix is a deterministic neuro-symbolic guardrail SDK that places a
mathematically verified execution firewall between AI agent intent and
real-world consequences.

## Two-Phase Execution Model

1. **Intent Extraction** — Map input to a typed, validated Pydantic model.
   LLM involvement is optional (Neuro-Symbolic mode only).
2. **Formal Safety Verification** — Z3 SMT solver proves all policy invariants
   are satisfied. Zero LLM involvement.

## Key Design Decisions

| Decision | Rationale | Reference |
|---|---|---|
| Z3 SMT for verification | Mathematical proof, not confidence score | Blueprint §1 |
| Fail-safe default | Any error → BLOCK, never ALLOW | Blueprint §2 |
| Python DSL (not YAML/Rego) | IDE autocomplete, type checking, static analysis | Blueprint §2 |
| `model_dump()` before process boundary | Pydantic models are not safely picklable | Blueprint §15 |
| Worker warmup with dummy Z3 solve | Eliminates cold-start JIT spike | Blueprint §15 |
| `assert_and_track` (not `add`) | Required for unsat core attribution | Blueprint §14 |
| Alpine Linux banned | Z3 requires glibc; musl causes segfaults | Blueprint §48 |

## Module Map

See Blueprint §9 for the complete directory structure and Blueprint §10–§20
for detailed module specifications.

---

## Phase 1 Findings — Transpiler Spike (`transpiler_spike.py`)

**Status:** Gate PASSED — 2026-03-09

### What was proved

The spike (`transpiler_spike.py`, 302 lines including reference invariants and
self-test block) proved every technical unknown targeted by Phase 1:

| Claim | Result |
|---|---|
| `E()` + `Field` build a lazy expression tree | **PROVED** — `ExpressionNode` wraps tree nodes; Python operators return new nodes, never Z3 expressions |
| Transpiler walks tree → correct Z3 AST | **PROVED** — all node types transpile correctly; verified with 53 unit tests |
| `Decimal` → `z3.RealVal` via `as_integer_ratio()` | **PROVED** — `Decimal('0.1')` maps to Z3 rational `1/10` exactly; `Decimal('100.01')` maps to `10001/100` |
| No floating-point drift | **PROVED** — floats are converted through `Decimal(str(v))` before `as_integer_ratio()`; Z3 model evaluations confirm exact fractions |
| `assert_and_track` + violation attribution | **PROVED** (with design revision — see below) |
| Solver timeout respected | **PROVED** — `solver.set('timeout', timeout_ms)` wired to all solver instances |

### Gate test results (5 mandatory scenarios)

```
SAT  normal tx                               -> SAT [OK]
UNSAT single  overdraft                      -> UNSAT core=['non_negative_balance']
UNSAT multi   overdraft+frozen               -> UNSAT core=['account_not_frozen', 'non_negative_balance']
SAT  boundary exact (0>=0)                   -> SAT [OK]
UNSAT boundary breach                        -> UNSAT core=['non_negative_balance']
```

All five pass. **Gate condition met.**

### Critical design finding — `unsat_core()` and minimal cores

The Blueprint called for a single shared solver with all invariants tracked via
`assert_and_track`, then reading `unsat_core()` to identify violated invariants.

**This approach is architecturally insufficient.** Z3's `unsat_core()` returns
a *minimal* unsatisfiable subset — the smallest set of tracked assertions that
jointly makes the system UNSAT. When multiple invariants are independently
violated (e.g., `non_negative_balance` AND `account_not_frozen`), Z3 only
needs one of them to prove UNSAT and may return only that one.

**Empirical confirmation (test_gate_3):**

```python
# balance=50, amount=1000, frozen=True
# Both non_negative_balance and account_not_frozen are violated.
# Shared-solver unsat_core() returns: ['non_negative_balance']  <-- INCOMPLETE
```

**The fix (implemented in the spike):** Check each invariant independently
with its own `z3.Solver` instance. With exactly one `assert_and_track` call per
solver, the core contains exactly that label when violated — no ambiguity. This
gives **exact, complete violation attribution** with no over- or under-reporting.

```python
for inv in invariants:
    s = z3.Solver()
    s.set("timeout", timeout_ms)
    for z3v, z3val in bindings:          # concrete values (untracked)
        s.add(z3v == z3val)
    s.assert_and_track(formula, z3.Bool(inv._label))  # one per solver
    if s.check() == z3.unsat:
        violated.append(inv)             # unsat_core() = {label} exactly
```

**Implication for Phase 2:** The `Guard` and `Policy` implementations must
use per-invariant solver instances for violation attribution, not a single
shared solver. The fast-path optimization (shared solver for the overall
SAT/UNSAT check) remains valid; individual checks are needed only when
computing the violation report for a BLOCK decision.

### Decimal arithmetic — exact rational throughout

Z3's `RealVal` accepts exact rationals. The spike converts every numeric value
through `as_integer_ratio()`:

```python
Decimal("100.01").as_integer_ratio()  # -> (10001, 100)
z3.RealVal(10001) / z3.RealVal(100)   # exact: 10001/100 in Z3
```

Floats are first passed through `Decimal(str(v))` to obtain the decimal
representation before `as_integer_ratio()`. This eliminates IEEE 754 drift
entirely. **No floating-point values are ever passed directly to Z3.**

### Files produced by Phase 1

| File | Purpose |
|---|---|
| `transpiler_spike.py` | Standalone spike — all Phase 1 logic |
| `tests/unit/test_transpiler_spike.py` | 53 unit tests (5 gate tests + 48 additional) |
| `docs/architecture.md` | This document |

### What is NOT proved by the spike

The spike intentionally excludes framework concerns deferred to later milestones:

- `Policy` class, `Guard` SDK entrypoint, `Decision` object (Phase 2 / M1)
- Async worker pool, `ThreadPoolExecutor` / `ProcessPoolExecutor` (M2)
- `Translator` subsystem — NLP → structured intent (M3)
- Observability: Prometheus metrics, OpenTelemetry spans (M4)
- Pydantic model integration and `model_dump()` boundary (M1)
