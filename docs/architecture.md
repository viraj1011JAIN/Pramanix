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

---

## Phase 4 — The Hardening Blueprint

**Status:** COMPLETE — 2026-03-13
**Test suite:** 705 passed, 10 skipped — 0 failures

Phase 4 hardened the full neuro-symbolic pipeline from LLM extraction through
Z3 verification, closing every attack surface identified during adversarial
review. The result is the Five-Layer Defence described below.

---

### Two-Phase Execution Model (Hardened)

```
 User Input
     │
     ▼
┌─────────────────────────────────────────────────────────────┐
│ PHASE 1 — LLM Extraction                                    │
│                                                             │
│  sanitise_user_input()          Unicode NFKC + C0 strip +  │
│       │                         injection pattern scan      │
│       ▼                                                     │
│  Dual-model extraction          GPT-4o  ┐ independent      │
│  (redundant.py)                 Claude  ┘ extraction        │
│       │                                                     │
│  validate_consensus()           Exact string-equality       │
│       │                         check on canonical JSON     │
│       ▼                                                     │
│  injection_confidence_score()   Additive risk: patterns,   │
│                                 sub-penny, dangerous chars, │
│                                 high-entropy tokens         │
│       │                                                     │
│  semantic_post_consensus_check()  Minimum-reserve, daily   │
│       │                           limit, full-drain gateway │
│       ▼                                                     │
│  TransactionIntent (Pydantic)   Strict field validators    │
└────────────────────────┬────────────────────────────────────┘
                         │ ALLOW (only if all checks pass)
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ PHASE 2 — Z3 Formal Verification                            │
│                                                             │
│  WorkerPool.submit_solve()      Dispatch to thread or       │
│       │                         spawn-isolated process      │
│       ▼                                                     │
│  _worker_solve_sealed()         Z3 solve inside child;      │
│       │                         HMAC-SHA256 signs result    │
│       ▼                                                     │
│  _unseal_decision()             Host verifies HMAC before   │
│                                 trusting the decision       │
│       ▼                                                     │
│  Decision (immutable)           .allowed / .reason /        │
│                                 .violated_invariants        │
└─────────────────────────────────────────────────────────────┘
```

Every box is a mandatory gate. Any exception at any gate → BLOCK. There is no
code path that converts an error into an ALLOW.

---

### Five-Layer Defence

#### Layer 1 — Input Sanitisation and Injection Scoring

**File:** `pramanix_llm_hardened.py`

Raw user text passes through `sanitise_user_input()` before it reaches any LLM:

1. **Unicode NFKC normalisation** — collapses homoglyphs, full-width variants,
   and bidirectional override characters that can make malicious strings look
   benign in logs.
2. **Hard length truncation** — input is capped at 512 characters to prevent
   token-budget exhaustion attacks.
3. **C0 control-character strip** — removes everything in `\x00–\x1f` and
   `\x7f` except `\n` and `\t`.
4. **Injection pattern scan** — 30 + regex patterns match role-escalation
   tokens (`ignore all previous instructions`, LLM special tokens `[INST]`,
   `<<sys>>`, code-execution markers, exfil probes, and semantic manipulation
   phrases). Matches are recorded as warnings; the text is **not** silently
   stripped (transparency).

After dual-model extraction, `injection_confidence_score()` runs an additive
risk model against the *extracted intent*, not the raw text:

| Signal | Weight | Notes |
|---|---|---|
| Injection regex matched | +0.60 | From warnings or fresh scan |
| Input suspiciously short | +0.20 | < 10 characters |
| Sub-penny amount | +0.30 | Per-currency threshold (JPY→1, KWD→0.001, BTC→0.0001, default 0.01) |
| Dangerous `recipient_id` chars | +0.30 | Blocklist: `;|()\\/'"` `` ` ``<>&$%#{}` + control chars; hyphens, dots, `+` are **permitted** |
| Unparseable `amount` | +0.40 | Cannot be cast to positive `Decimal` |
| High-entropy token | +0.20 | Long string with < 10 % separators (likely base64/hex payload) |

Score ≥ 0.5 → definitive BLOCK. The additive model is intentionally
conservative; no single weak signal can alone breach the threshold.

**Telemetry hook:** every evaluation calls
`get_telemetry().record_injection_score(score)`. Scores ≥ 0.5 increment the
`injection_spikes` rolling counter and fire all registered red-flag listeners.

---

#### Layer 2 — Dual-Model Consensus

**File:** `src/pramanix/translator/redundant.py`

The same user utterance is submitted to two independent LLM backends in
parallel. `validate_consensus()` performs a **canonical JSON equality check**:
both extractions are serialised with `sort_keys=True`; if the strings differ
by even one character, the pipeline blocks with `reason=extraction_mismatch`
at layer 1 before any Z3 work begins.

A rising consensus-mismatch rate in the telemetry window is a strong signal of
adversarial model-probing (attempting to find an input where one model can be
manipulated while the other stays clean, then replaying it).

---

#### Layer 2b — Semantic Post-Consensus Gateway

**File:** `pramanix_hardened.py → semantic_post_consensus_check()`

Fast pure-Python business rules evaluated *after* consensus, *before* Z3,
to avoid paying the Z3 overhead on obviously invalid transactions:

| Check | Policy |
|---|---|
| `balance − amount < minimum_reserve` | BLOCK — would leave account below reserve (closed boundary `≥`, not `>`) |
| `amount > daily_remaining` | BLOCK — exceeds remaining daily limit |
| `amount ≤ 0` | BLOCK — non-positive transfer |
| `amount == balance` (full drain) | BLOCK unless `_HUMAN_APPROVAL_GATEWAY.approve_or_raise()` succeeds |

**Fail-Closed Human Approval Gateway:**

The `_FailClosedApprovalGateway` singleton intercepts full-drain transfers. The
default singleton has `backend=None`, so full-drain is **always blocked** until
an operator explicitly wires a `HumanApprovalBackend` implementation. If the
backend raises any exception (network error, timeout, unexpected crash), the
gateway raises `HumanApprovalTimeout` — still a BLOCK. There is no code path
that converts a gateway error into an approval.

```python
# To enable human approval in production:
from pramanix_hardened import _HUMAN_APPROVAL_GATEWAY, HumanApprovalBackend

class MyBackend:
    def request_approval(self, *, amount, balance, timeout_s) -> bool:
        # Call your ticketing / 4-eyes system; return True only on explicit approval.
        ...

_HUMAN_APPROVAL_GATEWAY._backend = MyBackend()
```

---

#### Layer 3 — Z3 Formal Verification

**Files:** `src/pramanix/solver.py`, `src/pramanix/transpiler.py`

The Policy DSL compiles to a Z3 SMT problem. Every numeric value traverses
`Decimal → as_integer_ratio() → z3.RealVal(p) / z3.RealVal(q)`, eliminating
IEEE 754 drift entirely. No floating-point value ever reaches Z3.

The minimum-reserve invariant uses a **closed (`≥`) boundary**, not an open
(`>`) boundary:

```python
# Correct — closed boundary: balance after transfer must be ≥ reserve
(E(cls.balance) - E(cls.amount) >= E(cls.minimum_reserve))
.named("minimum_reserve_floor")

# WRONG — open boundary: balance of exactly reserve passes
(E(cls.balance) - E(cls.amount) > E(cls.minimum_reserve))  # ← vulnerability
```

See [policy_authoring.md](policy_authoring.md) for the full catalogue of
boundary-condition mistakes and how to avoid them.

---

#### Layer 4 — Spawn-Isolated Subprocess Vault

**File:** `src/pramanix/worker.py → WorkerPool`

In `execution_mode="async-process"`, Z3 runs inside a **spawned** (not forked)
subprocess. Spawn creates a fresh Python interpreter; forking can silently
share Z3's internal heap state, leading to non-deterministic corruption under
concurrent load.

Key properties:

- **No Z3 objects cross the process boundary.** `_worker_solve` receives only
  `(policy_cls, values_dict, timeout_ms)` — all plain Python types.
- **Timeout enforced.** If Z3 does not return within `solver_timeout_ms`, the
  subprocess is forcibly killed via `.kill()` and the result is BLOCK.
- **Z3 timeouts reported to telemetry.** Every timeout increments the
  `z3_timeouts` rolling counter (DoS-detection signal).
- **Worker recycling.** After `max_decisions_per_worker` calls the entire
  executor is replaced. This caps Z3 context heap growth and prevents RSS
  bloat from accumulating solver metadata across thousands of evaluations.

---

#### Layer 5 — HMAC Integrity Seal

**File:** `src/pramanix/worker.py → _worker_solve_sealed / _unseal_decision`

The Z3 subprocess cannot directly return a Python object to the host — IPC
deserialisation (pickle) is a code-execution vector. Instead:

1. The child calls `_worker_solve_sealed()`, which serialises the decision dict
   to canonical JSON (`sort_keys=True`) and computes `HMAC-SHA256(key, payload)`.
2. The sealed envelope `{"_p": payload, "_t": hmac_tag}` is returned via IPC.
3. The host calls `_unseal_decision()`, which recomputes the HMAC using
   `_RESULT_SEAL_KEY.bytes` and calls `hmac.compare_digest()` (constant-time
   comparison — no timing oracle). Any mismatch raises `ValueError` → BLOCK.

---

### `_EphemeralKey` Lifecycle

```
Process start
     │
     ▼
secrets.token_bytes(32)               ← OS CSPRNG, not Python random
     │
     ▼
_EphemeralKey(_RESULT_SEAL_KEY)
     │
     ├── repr() / str()  → "<EphemeralKey: redacted>"   (log-safe)
     │
     ├── __reduce__()    → raises TypeError              (pickle.dump BLOCKED)
     │                                                   (shelve, joblib, etc.)
     │
     ├── .bytes          → raw bytes (explicit IPC forwarding only)
     │
     └── HMAC operations use .bytes inline — key never stored in any dict,
         never logged, never written to disk.

Process end / restart
     │
     ▼
New secrets.token_bytes(32)           ← key auto-rotates
```

**Why this matters:** If a HMAC key leaks to persistent storage, an attacker
who compromises that store can forge `allowed=True` decisions for any future
transaction without Z3 involvement. The `_EphemeralKey` design makes the
Python object itself unable to reach persistent storage — the raw bytes can
only be forwarded explicitly via `.bytes`, which is only done at the moment of
subprocess construction.

---

### Telemetry — Three Red Flags

**File:** `pramanix_telemetry.py`

| Counter | Trigger | Operational meaning |
|---|---|---|
| `injection_spikes` | `injection_confidence_score ≥ 0.5` | Automated attack campaign in progress |
| `consensus_mismatches` | Dual-model extraction disagrees | Adversarial model-probing (crafted inputs to split models) |
| `z3_timeouts` | Z3 subprocess killed after timeout | Deliberate constraint-complexity DoS |

All counters use a 300-second rolling window. `window_rate` (events ÷ attempts
in the window) is the primary alert metric; `total_events` provides
long-running forensics context.

`StructuredLogEmitter` forwards every red-flag event as a newline-delimited
JSON record to any writable stream (default: `sys.stdout`). Pipe stdout to
Fluentd, Vector, or any log ship daemon to get data into Grafana or Datadog
within seconds. See [deployment.md](deployment.md) for the full integration
guide.

---

### Phase 4 Files

| File | Role |
|---|---|
| `pramanix_hardened.py` | Reference integration: all five layers, standalone |
| `pramanix_llm_hardened.py` | LLM hardening surface: sanitiser, scorer, consensus |
| `pramanix_telemetry.py` | Red-flag telemetry singleton and structured log emitter |
| `src/pramanix/worker.py` | Production worker pool with `_EphemeralKey` + HMAC seal |
| `tests/unit/test_integrity.py` | 13 integrity gate tests (13/13 pass) |
| `tests/unit/test_llm_hardening.py` | 16 LLM hardening unit tests (16/16 pass) |
| `radar_test.py` | Smoke-test: exercises all three red flags and prints snapshot |
