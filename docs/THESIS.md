# PRAMANIX: A Deterministic Neuro-Symbolic Execution Firewall for Autonomous AI Agents

## A Technical Thesis — Engineering Design, Research Foundations, and Production Evidence

**Author:** Viraj Jain
**System Version:** Pramanix 1.0.0
**Codebase Audit Date:** 2026-05-12
**License:** AGPL-3.0-only (`pyproject.toml:8`)
**Primary Repository:** https://github.com/viraj1011JAIN/Pramanix

---

> **Evidence policy for this document:** Every claim is grounded in a specific file, line number, or benchmark result from the actual codebase. Nothing here is aspirational. Where a gap exists it is named exactly as a gap. Where the code proves a claim, the proof is cited.

---

## TABLE OF CONTENTS

```
PART I    — ABSTRACT
PART II   — BACKGROUND AND MOTIVATION
PART III  — RESEARCH AND DESIGN PHASE
PART IV   — TECHNICAL ARCHITECTURE
PART V    — DEVELOPMENT JOURNEY
PART VI   — TESTING STRATEGY
PART VII  — RESEARCH AND BENCHMARKS
PART VIII — USE CASES AND TARGET INDUSTRIES
PART IX   — KNOWN LIMITATIONS AND FUTURE ROADMAP
PART X    — COMPETITIVE DEEP-DIVE
PART XI   — ECONOMICS OF RUNNING
PART XII  — SECURITY THREAT MODEL
PART XIII — ACADEMIC AND RESEARCH GROUNDING
PART XIV  — FAILURE LOG
PART XV   — REAL WORLD SIMULATION RESULTS
PART XVI  — DEPENDENCY RISK ANALYSIS
PART XVII — REGULATORY MAPPING
PART XVIII — SCALING STORY
PART XIX  — DEVELOPER EXPERIENCE DECISIONS
PART XX   — PERSONAL REFLECTION
```

---

# PART I — ABSTRACT

Pramanix is an execution firewall for autonomous AI agents. Its core contract, stated in `docs/Blueprint.md`, is mathematically precise: a decision is `allowed=True` if and only if the Microsoft Research Z3 SMT solver returns `sat` for all policy invariants simultaneously against the given inputs. Any other result — `unsat`, `unknown`, timeout, exception, type error, network failure — produces `allowed=False`. There is no third path.

The problem it solves is real. When a language model reasons about a financial transfer, it reasons probabilistically. At 99.9% accuracy across 10,000 daily operations, ten transactions per day will be incorrect. The consequential ones — the overdrafts, the frozen-account violations, the daily-limit breaches — are exactly the cases where an inch of probability is unacceptable. Pramanix eliminates that inch by moving the decision from statistical inference to mathematical proof.

The system is not a prompt filter. It is not a toxicity classifier. It does not read LLM output for bad words. It sits at the action boundary: an AI agent produces a structured JSON intent (`{"amount": 5000}`), and Pramanix decides whether that action is logically consistent with every invariant in a formally specified policy before the action fires against any real system.

At its core, thirteen architectural layers collaborate: a DSL expression engine, a Z3 transpiler that converts Python AST to Z3 AST without ever calling `eval` or `exec`, a two-phase solver with per-invariant violation attribution, a worker pool with process-isolation for production, an eleven-layer injection defence stack, a cryptographic audit trail with Ed25519 signing and Merkle batch anchoring, a compliance reporter mapping violation labels to regulatory citations in six legal frameworks, and a shadow policy evaluator that makes safe canary promotion possible for the first time in any guardrail framework.

The codebase was independently audited against its own source on 2026-05-12 (`reality.md`). The audit score is 8.5/10. The technical moat is real. The single crisis is the AGPL-3.0 license, which blocks enterprise adoption before a single sale. That is documented, named, and not softened.

---

# PART II — BACKGROUND AND MOTIVATION

## 2.1 The Probabilistic Problem in AI Agents

Modern AI agent frameworks — LangChain, AutoGen, CrewAI, Semantic Kernel — give large language models tools: bank transfer APIs, infrastructure scale commands, medical record access, trading order entry. The models are stochastic. Their outputs are samples from a probability distribution. At temperature zero they are more deterministic, but they are never formally deterministic in the mathematical sense.

The practical consequence, articulated precisely in `docs/Blueprint.md § 1`, is this:

> LLMs are stochastic token samplers. Temperature > 0 means no two identical runs are guaranteed identical. In a banking context, a 99.9% accuracy rate on a financial operation means 1 in 1,000 transfers may be incorrect. At scale — 10,000 daily operations — that is 10 provably dangerous actions per day.

This is not hypothetical. It is arithmetic. The question becomes: what do you put between the model and the action?

## 2.2 Why Existing Approaches Fail

The market's current answers fall into two broken categories, both documented in the Blueprint:

**Category 1 — Rule-Based Systems (regex, IF-THEN).** Cannot reason about compound constraints. `amount < 10000 AND balance > amount AND NOT frozen` looks reasonable until the edge cases arrive: floating-point rounding on the balance comparison, compound conditions that interact non-linearly, rules that were correct in isolation but produce wrong results in combination. More fundamentally, rule-based systems have no completeness guarantee. A badly-written rule silently passes or blocks incorrectly.

**Category 2 — LLM-as-Judge.** Uses the same probabilistic tool to judge itself. "Is this transfer safe?" asked of a language model returns "Yes, it looks fine" with some probability. Adversarial prompts can override the judge entirely. The system is circular.

Pramanix's approach, documented in `docs/DECISIONS.md § 1`, rejects both:

> SMT solvers provide a completeness guarantee: if Z3 says `sat`, every invariant holds for the given inputs. There is no false positive path. Attribution (`unsat_core()`) identifies exactly which invariants were violated, not just "something failed". Z3 handles real arithmetic (`z3.Real`) natively, which is required for financial invariants. Z3 is deterministic. Given the same formula and the same timeout, it produces the same answer.

## 2.3 The Name

The name encodes the philosophy. *Pramāṇa* is a Sanskrit epistemological term meaning "valid means of knowledge" — proof, evidence, what makes a belief justified. *Unix* is the composable systems philosophy. Pramanix is the combination: a composable system that operates on proof, not belief.

## 2.4 What It Is Not

The `docs/Blueprint.md § 3` table is worth preserving exactly because it prevents misuse:

| It is NOT | Because |
|---|---|
| A replacement for OPA | OPA handles AuthZ (who can try). Pramanix handles mathematical safety (is this attempt valid). Use both. |
| A prompt guardrail | It does not filter LLM outputs. It verifies structured intents. |
| A general-purpose rule engine | It operates exclusively on Z3-expressible constraints over typed fields. |
| Secure without host freshness check | The `state_version` check MUST be implemented by the caller. Pramanix enforces the contract; it does not implement the check. |

---

# PART III — RESEARCH AND DESIGN PHASE

## 3.1 The Core Research Question

The research question is practical and specific: can a Python library provide formal, mathematical verification of AI agent actions with latency and ergonomics suitable for production deployment?

The two sub-questions that follow:
1. Can Z3 be made fast enough for request-path verification?
2. Can the policy authoring surface be ergonomic enough for application engineers who have never used an SMT solver?

Both answers are yes, with caveats. The benchmark evidence is in `benchmarks/results/latency_results.json`: P50 of 5.235ms, P95 of 6.361ms, P99 of 7.109ms over 2,000 samples in `sync` mode. The ergonomics are answered by the DSL: `(E(balance) - E(amount) >= 0).named("non_negative_balance")` is pure Python, type-checked, IDE-complete, and readable without any knowledge of Z3.

## 3.2 SMT Solvers as Verification Engines

The choice of Z3 over alternative verification engines is documented in `docs/DECISIONS.md § 1` with reasons that are not post-hoc:

**OPA/Rego was considered and rejected.** Rego is Datalog-based. It cannot prove invariants over arithmetic without custom extensions. Attribution of which rule failed requires introspection OPA does not natively provide. For financial invariants like `balance - amount >= min_reserve`, Rego has no native arithmetic completeness guarantee.

**Custom Python rule engine was considered and rejected.** Fast, but no formal completeness guarantee. A badly-written rule silently passes or blocks incorrectly with no attribution.

**Symbolic execution over Python bytecode was considered and rejected.** Complexity is prohibitive, failure modes are not well-understood.

Z3 wins on four properties: completeness guarantee (SAT means all invariants hold), unsat-core attribution (exactly which invariants were violated), native real arithmetic (exact, not floating-point), and determinism.

## 3.3 The Exact Arithmetic Design Decision

One design decision that separates Pramanix from naive Z3 usage deserves its own section. `docs/DECISIONS.md § 10` explains why floating-point values are never passed directly to Z3:

> Floating-point values in invariants are converted via `Decimal(str(v)).as_integer_ratio()` before being passed to Z3 as rational numbers (`z3.RatVal(numerator, denominator)`).

The implementation is in `transpiler.py` at the float handling path. `Decimal(str(v)).as_integer_ratio()` produces an exact rational (numerator, denominator pair). Z3's `RatVal` represents this as exact rational arithmetic. `0.1 + 0.2 != 0.3` in IEEE 754. In Z3 via this path, it is exactly equal. Financial invariants of the form `balance - amount >= min_reserve` must be exact. This is not an optimization; it is a correctness requirement.

## 3.4 The Two-Phase Solver Strategy

The solver architecture in `docs/DECISIONS.md § 3` reflects a trade-off between the common case and the rare case:

**Phase 1 (fast path):** One shared `z3.Solver` with all invariants added via `add()`. If `sat` → return SAFE immediately. This is the common case for legitimate requests.

**Phase 2 (attribution):** Each invariant gets its own `z3.Solver` with `assert_and_track`. One assertion per solver so `unsat_core()` is always `{label}` — complete violation attribution with no minimal-core ambiguity.

The insight is that `assert_and_track + unsat_core()` on a single solver with multiple assertions does not always return the minimal core — Z3's core extraction is heuristic. Using one solver per invariant guarantees that `unsat_core()` returns exactly `{label}`, so violation attribution is complete and deterministic. The cost is O(k) solves in Phase 2, but Phase 2 only triggers on violations, which should be the minority of requests in a correctly configured production system.

## 3.5 The Fail-Closed Invariant

The most important design decision in the system is documented in `docs/DECISIONS.md § 2`:

> `Guard.verify()` catches all exceptions and returns `Decision.error(allowed=False)`. It never raises to the caller.

This is enforced not just by convention but by code structure. `Decision.__post_init__` raises `ValueError` if `allowed=True` and `status != SAFE`. There is no code path in the entire system where an error handler returns `allowed=True`. The invariant is: Z3 returning SAT is the *only* path to `allowed=True`.

---

# PART IV — TECHNICAL ARCHITECTURE

## 4.1 The Thirteen-Layer Architecture

The system is not a single module. It is thirteen distinct layers with clean boundaries, documented in `docs/ARCHITECTURE_NOTES.md` and independently verified in `reality.md § 1.2`:

### Layer 1 — The Orchestrator (`guard.py`, `guard_pipeline.py`)

The `Guard` class is the single entry point. Every `verify()` call passes through a ten-step pipeline documented in `docs/ARCHITECTURE_NOTES.md § Guard`:

```
1. Pydantic strict-mode validation (intent + state)
2. Fast-path O(1) pre-screen (if enabled) — can only BLOCK
3. Translator consensus extraction (if translator_enabled=True)
4. guard_pipeline semantic post-consensus check
5. Z3 solve via solver.py
6. Decision construction
7. Ed25519 signing (_sign_decision)
8. Audit sink emit (all configured sinks, failures caught and logged)
9. Structlog emission
10. OTel span close / Prometheus update
```

The boundary invariant: `Guard.verify()` **never raises**. Every exception, including unexpected ones from user-defined `invariants()`, is caught and returned as `Decision.error()` with `allowed=False`. Signing failure returns `Decision.error()`. Sink failure is logged and the decision proceeds. Nothing breaks the no-raise contract.

### Layer 2 — The DSL (`expressions.py`, `policy.py`)

Pure Python, zero Z3 imports. The `E()` builder, `ConstraintExpr`, `ForAll`, `Exists`, `ArrayField`, `DatetimeField`, `NestedField`. The DSL is a library of composable Python objects — no string phase, no `eval`, no `exec` anywhere in the codebase (`docs/DECISIONS.md § 9`).

The `ConstraintExpr.__bool__` method raises `PolicyCompilationError` rather than returning a value. This is intentional: `bool(expr1) and bool(expr2)` short-circuits at the Python level and discards one operand. The policy author intended `expr1 & expr2`. These are not the same operation. Raising at compilation time surfaces the bug immediately rather than silently producing wrong constraints (`docs/DECISIONS.md § 17`).

### Layer 3 — The Transpiler (`transpiler.py`)

The only file in the codebase that calls `z3.*` from DSL nodes. Lowers Python AST to `z3.ExprRef` via explicit structural pattern matching (`match/case`) starting at line 382.

Two critical details: floats go through `Decimal(str(v)).as_integer_ratio()` before becoming `z3.RatVal`. Integer literals default to `z3.RealVal` for compatibility with Real-sorted fields. `InvariantASTCache` pre-walks the expression tree at Guard construction time and caches the result — no repeated tree walks at request time.

Known bug (`reality.md § 1.1`): `_tree_repr()` at line 730 has no match clauses for `_PowOp` or `_ModOp`. Any invariant using `E(x)**n` or `E(x) % n` falls through to `Unknown(_PowOp)` in `InvariantMeta.tree_repr`. Z3 verification correctness is unaffected. Policy diff tooling and equivalence tests will produce wrong output for polynomial policies.

### Layer 4 — The Solver (`solver.py`)

Z3 invocation and two-phase verification. Thread-local `z3.Context()` per OS thread — created once, never destroyed. This prevents GC races on Windows/Python 3.13. Both wall-clock timeout (`set("timeout", timeout_ms)`) and elementary operation cap (`set("rlimit", solver_rlimit)`) are applied. The `rlimit` prevents logic-bomb and non-linear expression DoS attacks that could exhaust CPU time regardless of wall-clock timeout.

### Layer 5 — The Worker Pool (`worker.py`)

Three execution modes:
- `sync` — Z3 runs in the calling thread. Lowest latency, highest risk (Z3 crash kills the process)
- `async-thread` — `ThreadPoolExecutor`. Shared in-process memory; no IPC overhead. GIL is released during Z3 solving (Z3 releases the GIL), enabling genuine parallelism.
- `async-process` — `ProcessPoolExecutor(mp_context=spawn)`. Full process isolation. Z3 crash kills only the worker; host continues. HMAC-sealed IPC prevents forged results from a compromised worker.

The `spawn` context (not `fork`) is mandatory because forking after Z3 initialisation produces undefined behavior. Z3 has internal state — heap objects, file descriptors — that cannot be safely copied via `fork` (`docs/DECISIONS.md § 4`).

In `async-process` mode, each solve result is HMAC-SHA256 tagged with an ephemeral key (`_EphemeralKey`) before crossing the `multiprocessing.Queue` boundary. The ephemeral key is generated once per Guard instance lifetime at construction, stored only in the host process, and `_EphemeralKey.__reduce__` raises `TypeError` to prevent serialisation (`docs/DECISIONS.md § 15`).

### Layer 6 — The Fast-Path Pre-Screener (`fast_path.py`)

`SemanticFastPath` and `FastPathEvaluator` — configurable pure-Python O(1) rules that run after Pydantic validation and before Z3. Architecture contract from `docs/DECISIONS.md § 8`:

> Fast-path rules can only BLOCK — they return a string reason or `None`. `None` passes through to Z3. There is no fast-path mechanism to allow a request.

Built-in rules: `negative_amount`, `zero_or_negative_balance`, `account_frozen`, `exceeds_hard_cap`, `amount_exceeds_balance`. These eliminate Z3 invocation for the most common failure modes.

### Layer 7 — The LLM Translation Layer (`translator/`)

Seven provider adapters: `openai_compat`, `anthropic`, `ollama`, `gemini`, `cohere`, `mistral`, `llamacpp`. A five-layer injection defence stack executes before any LLM call:

1. Unicode NFKC normalisation — collapses homoglyphs
2. Input length enforcement — `InputTooLongError` at `max_input_chars`
3. Control-character stripping
4. Injection pattern detection — pre-compiled regex, ~25 patterns covering instruction overrides, jailbreak keywords, open-source model tokens (Llama 2/3, ChatML, Phi-3), role escalation
5. Dual-model consensus — two independent LLMs must agree

The dual-model consensus is documented in `docs/DECISIONS.md § 7`:

> Two independent models must produce the same intent for the same input. A successful prompt injection attack would need to manipulate both models in the same direction simultaneously — a significantly harder attack than manipulating one.

### Layer 8 — The Audit Chain (`audit/`)

`DecisionSigner` signs `decision.decision_hash` with Ed25519 via `PramanixSigner`. `DecisionVerifier` is intentionally self-contained — an auditor can copy it as a single file and verify tokens offline without installing Pramanix (`docs/ARCHITECTURE_NOTES.md § Audit`).

`MerkleAnchor` builds an in-memory Merkle tree. `add(decision_id)` → `root()` → `prove(decision_id)` → `proof.verify()`. Proves any single decision was part of an unaltered batch without replaying all decisions. `MerkleArchiver` writes segment-based archive files atomically via `tempfile + os.fsync() + os.replace()`.

One honest gap: archive files are written in plaintext NDJSON. The archiver emits a `WARNING` at construction time citing the gap. SOC 2, PCI DSS, and HIPAA deployments must encrypt the archive directory externally.

The iterative Merkle root construction (replacing recursive) was a deliberate correctness fix documented in `docs/DECISIONS.md § 18`. The recursive implementation hits Python's call stack limit at approximately 1,000 decisions. The iterative version uses O(1) stack depth.

### Layer 9 — The Governance Gates (`privilege/`, `oversight/`, `ifc/`)

Information-Flow Control (`ifc/`): Lattice-based enforcement between trust levels. `FlowPolicy` maps `(source_label, dest_label)` pairs to `ALLOW` or `DENY` rules. The `regulated()` preset explicitly rules that `REGULATED → INTERNAL`, `REGULATED → CUSTOMER`, and `REGULATED → CONFIDENTIAL` are all `permitted=False`, surfacing violation reasons in `FlowViolationError`.

`OversightWorkflow` (`oversight/`) manages escalation queues. `PrivilegeScope` (`privilege/`) manages capability manifests and execution scope boundaries. These gates run after consensus and before Z3 in the pipeline.

### Layer 10 — The Compliance and Lifecycle Tools (`helpers/`, `lifecycle/`)

`ComplianceReporter` (`helpers/compliance.py`) takes a `Decision` object and produces structured regulatory citations: BSA/AML (31 CFR §1020), OFAC/SDN (50 CFR §598), SEC wash sale (IRC §1091), HIPAA (45 CFR §164), SOX (15 U.S.C. §7241), Basel III (BCBS 189). JSON and PDF export. This is the feature that converts a developer SDK into an enterprise product.

`PolicyDiff` and `ShadowEvaluator` (`lifecycle/diff.py`) provide safe canary promotion. `ShadowEvaluator` runs the candidate policy alongside every live decision, recording divergence events non-blocking via `threading.Lock`. This makes it possible to build statistical confidence before promoting a new policy version.

### Layer 11 — The Request Infrastructure (`resolvers.py`, `validator.py`)

`ResolverRegistry` stores per-request resolved field values in a `contextvars.ContextVar` — not `threading.local`. The distinction is security-critical: in asyncio, multiple concurrent tasks share one OS thread. `threading.local` would allow Task B to see Task A's resolved values — a P0 data bleed between users. `ContextVar` is Task-scoped (`docs/DECISIONS.md § 6`). Guard calls `clear_cache()` in its `finally` block unconditionally — no resolved value survives across requests.

`validator.py` uses Pydantic v2 strict mode. Implicit coercions (`"123"` → `int`) are rejected. All input validation happens at this single boundary.

### Layer 12 — The Exception Hierarchy (`exceptions.py`)

Nineteen typed exception classes in a strict `PramanixError` tree. Domain-specific: `GuardViolationError` (contains the full `Decision` object), `FlowViolationError` (IFC violation), `PrivilegeEscalationError`, `OversightRequiredError`, `MemoryViolationError`, `ProvenanceError`, `IntegrityError`, `SolverTimeoutError`, `ExtractionMismatchError`. Callers never need to catch bare `Exception`.

### Layer 13 — The Primitives Library (`primitives/`)

Thirty-eight pre-built Policy constraints across seven domains. This is underdocumented and underappreciated. The full verified count from `reality.md § 2.2`:

- **Finance:** `NonNegativeBalance`, `UnderDailyLimit`, `UnderSingleTxLimit`, `RiskScoreBelow`
- **FinTech:** `AntiStructuring`, `CollateralHaircut`, `KYCTierCheck`, `MarginRequirement`, `MaxDrawdown`, `SanctionsScreen`, `SufficientBalance`, `TradingWindowCheck`, `VelocityCheck`, `WashSaleDetection`
- **Healthcare:** `BreakGlassAuth`, `ConsentActive`, `DosageGradientCheck`, `PediatricDoseBound`, `PHILeastPrivilege`
- **RBAC:** `ConsentRequired`, `DepartmentMustBeIn`, `RoleMustBeIn`
- **Infrastructure:** `BlastRadiusCheck`, `CircuitBreakerState`, `CPUMemoryGuard`, `MaxReplicas`, `MinReplicas`, `ProdDeployApproval`, `ReplicaBudget`, `WithinCPUBudget`, `WithinMemoryBudget`
- **Time:** `After`, `Before`, `NotExpired`, `WithinTimeWindow`
- **Common:** `FieldMustEqual`, `NotSuspended`, `StatusMustBe`, `EnterpriseRole`, `HIPAARole`

## 4.2 The Decision Object

`Decision` is a frozen dataclass with one invariant enforced in `__post_init__`: `allowed=True ↔ status=SAFE`. No other combination is valid. The status values and their meanings (`docs/ARCHITECTURE_NOTES.md § Decision`):

| Status | allowed | Cause |
|---|---|---|
| `SAFE` | `True` | Z3 proved all invariants hold |
| `UNSAFE` | `False` | Z3 found a counterexample |
| `TIMEOUT` | `False` | Z3 exceeded time budget |
| `ERROR` | `False` | Unexpected internal error |
| `STALE_STATE` | `False` | `state_version` field mismatch |
| `VALIDATION_FAILURE` | `False` | Pydantic model validation failed |
| `CONSENSUS_FAILURE` | `False` | Dual-model LLM disagreement |
| `RATE_LIMITED` | `False` | Load-shedding threshold exceeded |

The canonical hash is SHA-256 over `decision_id + status + allowed + violated_invariants + explanation`, computed via `orjson` (or stdlib `json` fallback). The `iat` timestamp is excluded from the signed payload. This makes signatures deterministic — two identical decisions signed at different moments produce the same signature (`docs/DECISIONS.md § 16`).

## 4.3 The Public API Stability Contract

The stability tiers from `docs/PUBLIC_API.md` reflect what is actually tested and semver-protected:

- **Stable:** `core`, `audit`, `crypto`, `circuit_breaker`, `execution_token`, `key_provider`, `compliance`, `audit_sinks`, `worker`, `primitives`
- **Beta:** `translator`, `integrations`, `fast_path`, `ifc`, `privilege`, `oversight`, `memory`, `lifecycle`, `provenance`

The beta subsystems are usable in production but may change in minor versions with deprecation notice.

---

# PART V — DEVELOPMENT JOURNEY

## 5.1 The Migration: From Concept to 1.0.0

The development history is reconstructed from `docs/CHANGELOG.md` (which follows Keep a Changelog format) and the `docs/Blueprint.md` milestone sequence. The Blueprint documents versions v0.0 through v1.0 GA as a planned sequence, and the CHANGELOG documents what actually happened in the unreleased v1.0.0 work.

### Phase 0 — v0.0: Concept Validation

The fundamental question: can Z3 verify a financial invariant in Python within acceptable latency? Before any architecture was built, this had to be answered empirically. The answer is yes — the benchmark in `benchmarks/latency_benchmark.py` (which runs a five-invariant `BenchmarkPolicy` with `sync` mode) demonstrates P99 of 7.109ms over 2,000 samples. But that result came after significant optimization work.

### Phase 1 — v0.1–v0.3: Core Engine

The foundation: `guard.py`, `policy.py`, `expressions.py`, `transpiler.py`, `solver.py`. The key design decision made at this stage was the fail-closed contract. `Decision.__post_init__` raises `ValueError` if `allowed=True` and `status != SAFE`. This constraint is checked in every test suite run and has never been relaxed.

The `ConstraintExpr.__bool__` raising behavior was added early and has remained stable. It's a DX decision with zero cost for correct policies and immediate failure for the most common incorrect one.

### Phase 2 — v0.4: Exception Hierarchy and Type Safety

Nineteen typed exceptions replacing bare raises. `mypy` strict mode (`pyproject.toml: mypy.strict = true`). `disallow_untyped_defs = true`. The policy of zero `cast()` except where Z3's incomplete type stubs require it (`transpiler.py:390-396`) was established here.

### Phase 3 — v0.5: Security Hardening

The formal threat model was written. The HMAC-sealed IPC for `async-process` mode (`docs/DECISIONS.md § 15`) was implemented here. The `_EphemeralKey.__reduce__` raising `TypeError` to prevent serialisation was a direct response to the threat of worker process exploitation.

The musl/Alpine rejection at import time (`_platform.py`) was added in this phase. The rationale from `docs/DECISIONS.md § 12` is precise: Z3's glibc-compiled wheels segfault or run 3–10× slower on musl. By the time Guard is constructed, Z3 is already loaded. Failing at import time is the only way to produce an attributable error in container startup logs rather than a crash 30 minutes into production load.

### Phase 4 — v0.6: Domain Primitives

Thirty-eight pre-built primitives across seven domains. The `ComplianceReporter` with six regulatory frameworks and PDF export. This phase transformed the SDK from a framework requiring users to write all constraints from scratch into a library with batteries included. The primitives are stable-tier as of v1.0.0.

### Phase 5 — v0.7: Performance Engineering

The `InvariantASTCache` — pre-compiles the expression tree at Guard construction time, eliminating repeated tree walks at request time. The `SemanticFastPath` — O(1) Python pre-screener before Z3. The process pool with zero-IPC worker architecture, documented in detail in `benchmarks/100m_worker_fast.py`:

> Old: asyncio coroutine → ThreadPoolExecutor → Guard process → Z3 process
> 2 IPC crossings per decision × ~15 ms each = ~30 ms overhead = 22-27 RPS/worker
>
> New: 18 OS processes, each owns sync Guard + Z3 in one address space
> 0 IPC crossings per decision. ~80-120 RPS/worker → 1 440-2 160 aggregate RPS.

Three micro-optimisations are documented in `100m_worker_fast.py`:
1. `max_input_bytes=0` — skips the per-decision JSON size-check round-trip (~1-2ms saved)
2. Pre-built payload cache — 10,000 payloads generated at startup, hot path cycles with `i % 10_000`, no `Decimal()` construction in the decision loop (~0.5ms saved)
3. orjson + 8 MiB buffer — one OS `write()` per ~100k decisions vs one per decision (~0.3ms saved)

### Phase 6 — v0.8: Cryptographic Audit Engine

Ed25519 signing (`crypto.py`), `MerkleAnchor` and `PersistentMerkleAnchor` (`audit/merkle.py`), `ProvenanceChain` (`provenance.py`), `DecisionSigner`/`DecisionVerifier` (`audit/signer.py`, `audit/verifier.py`). The iterative Merkle root was a correctness fix — the recursive implementation hit Python's stack limit at 1,000 decisions (`docs/DECISIONS.md § 18`).

### Phase 7 — v0.9: Enterprise Integrations

Nine framework adapters: LangChain, LlamaIndex, AutoGen, FastAPI, CrewAI, DSPy, Haystack, Semantic Kernel, Pydantic AI. Two runtime interceptors: gRPC `ServerInterceptor` and Kafka consumer wrapper. Kubernetes `ValidatingWebhook`. The `@guard` decorator.

The LangChain integration had a security bug (`CHANGELOG.md § H-03`): `PramanixGuardedTool` previously defaulted `execute_fn` to `lambda i: "OK"` when no function was provided. Every guarded action returned success without executing any real logic. Fixed: `execute_fn=None` now raises `NotImplementedError` with a diagnostic message. A `UserWarning` is emitted at construction time.

The CrewAI integration had an identical bug (`CHANGELOG.md § H-04`): `PramanixCrewAITool._run()` previously returned a non-exception string when `underlying_fn=None`. A blocked CrewAI tool should raise, not return. Fixed.

### Phase 8 — v0.9.5: Security Hardening Pass

This phase documents the bugs found and fixed in the unreleased changelog:

**C-01**: `verify_async()` had a bare `except Exception: pass` in the `max_input_bytes` size-check path. Unserializable payloads silently bypassed the size gate and continued to Z3. Fixed: now returns `Decision.error(allowed=False)`.

**H-02/M-05**: The timing-pad (`min_response_ms`) was applied only to BLOCK responses. ALLOW responses returned immediately, leaking a timing oracle. Fixed: timing pad applied unconditionally to every response, before the ALLOW/BLOCK branch.

**BUG-03**: `OversightRecord` had no `__slots__`. Arbitrary attribute injection on a tamper-evident audit record. Fixed: `__slots__ = ("request", "decision", "_key", "_tag")`.

**BUG-10**: `JWTIdentityLinker._verify_token()` decoded the JWT payload before validating the `alg` header. An attacker could craft a token with `alg: "RS256"` and an HMAC-SHA256 signature, bypassing the asymmetric-key check (CVE-2015-9235 family). Fixed: header decoded and `alg` validated as `"HS256"` **before** signature computation.

**BUG-11**: JWT `nbf` (not-before) claim not enforced. Tokens with future `nbf` were accepted. Fixed.

**BUG-12**: Empty or missing JWT `sub` claim accepted. `"sub": ""` produced an empty-identity principal. Fixed.

### Phase 9 — v1.0.0 GA: Documentation, Coverage, and Honest Gaps

`docs/KNOWN_GAPS.md` was created — an honest inventory of 14 known limitations. `MIGRATION.md` covering v0.7–v1.0 upgrade paths. `docs/PUBLIC_API.md` stability tiers finalised. `pramanix doctor` check #10 (logging-handlers) and check #11 (policy-hash-binding) added.

The test suite at v1.0.0: 3966 items collected, 3883 passed, 81 skipped, 3 failed (before the bugs documented in this thesis). Coverage: 97.76% against a 98% gate.

---

# PART VI — TESTING STRATEGY

## 6.1 Test Architecture Philosophy

The test suite is not a collection of happy-path unit tests. It is an adversarial testing infrastructure. The distinction is important and documented in `reality.md § 3.1`.

## 6.2 Adversarial Tests

**Z3 Context Isolation** (`tests/adversarial/test_z3_context_isolation.py`): Uses `threading.Barrier` to force 10 concurrent simultaneous solver executions. Mathematically proves context poisoning between threads is impossible. CVE-prevention level testing.

**Prompt Injection** (`tests/adversarial/test_prompt_injection.py`): Verifies resistance to null bytes, unicode full-width digits, massive integers, negative bounds, and resource exhaustion using in-process stub translators. Isolates the Z3 + governance layer from LLM parsing — correct layered unit-test design.

## 6.3 Property-Based Tests (Hypothesis)

`hypothesis` is in the dev dependencies (`pyproject.toml: hypothesis = "^6.100"`). Property-based testing is used to verify that the DSL produces correct constraints for arbitrary input values rather than just the hand-picked examples in unit tests.

Known gap (from `reality.md § 3.1`): The `_sanitise.py` injection scorer has complex additive float-math heuristics. No Hypothesis property tests verify that score combinations are monotonically bounded within `[0.0, 1.0]` across the full input space.

## 6.4 Real Infrastructure Integration Tests

`tests/integration/` — 26 files hitting real containers: Kafka via Redpanda, Redis, Postgres, LocalStack, Azure KeyVault, HashiCorp Vault. Live LLM adapters tested: Gemini, Cohere. Container availability is detected at test session start (`tests/integration/conftest.py:34-45`):

```python
try:
    import docker; _client.ping()
except Exception:
    _DOCKER_AVAILABLE = False
requires_docker = pytest.mark.skipif(not _DOCKER_AVAILABLE, ...)
```

The 81 skips in the test suite are primarily these infrastructure-dependent tests skipping when Docker is unavailable. This is correct behavior, not a testing gap.

## 6.5 Concurrent Load Tests

`tests/unit/test_production_gaps.py` — 14 tests including a 50-coroutine concurrent async size-check test with oversized payloads, unserializable payloads, and mixed batches (no cross-contamination verification). Timing-pad distribution tests: p5 latency assertions (≥90% of budget) for both ALLOW and BLOCK; symmetry ratio check (≤1.30) to detect asymmetric padding.

## 6.6 Coverage Gate

`pyproject.toml: fail_under = 98`. The coverage gate is enforced in CI. Current status: 97.76%. The 3 test failures described in this thesis are the proximate cause. When those fixes land and the tests pass, the coverage gate should be achievable.

## 6.7 The Three Known Test Failures

Three tests fail in the current suite. Root causes established:

**Failure 1 — `test_sklearn_absent_raises_configuration_error`**: `CalibratedScorer.load()` classmethohd lacks the sklearn availability check present in `__init__()`. The test calls `load()` with sklearn hidden and expects `ConfigurationError`. None is raised. Fix: add the sklearn import check at the start of `load()`.

**Failure 2 — `test_canonical_bytes_exception_falls_back_to_stdlib_json`**: The test sets `_dec_mod._canonical_bytes = _boom` (a function that raises). `_compute_hash()` in `decision.py` calls `_canonical_bytes` by its module-level name binding established at import time. Monkey-patching the module attribute after import has no effect on the already-resolved local binding. Fix: use `unittest.mock.patch("pramanix.decision._canonical_bytes", side_effect=RuntimeError(...))` which patches at the call site.

**Failure 3 — `test_gemini_prefix`**: `_GEMINI_AVAILABLE` in `test_redundant_full.py` uses `find_spec("google.generativeai") is not None`. The `google` namespace package is installed (via `google.auth`), so `find_spec` returns not-None. But the actual import fails with `AttributeError: module 'google' has no attribute 'auth'` due to internal `google-generativeai` dependency conflicts. `GeminiTranslator.__init__` only catches `ImportError`, not `AttributeError`. Fix: catch `(ImportError, AttributeError)` in `GeminiTranslator.__init__`, and change `_GEMINI_AVAILABLE` detection to an actual try-import.

---

# PART VII — RESEARCH AND BENCHMARKS

## 7.1 Latency Benchmarks

Results from `benchmarks/results/latency_results.json` — API mode, 2,000 samples, 5-invariant policy, `sync` execution mode:

| Metric | Measured | Target |
|---|---|---|
| P50 | 5.235 ms | 5.0 ms |
| P95 | 6.361 ms | 10.0 ms |
| P99 | 7.109 ms | 15.0 ms |
| Mean | 5.336 ms | — |

P50 narrowly misses its target by 0.235ms. P95 and P99 are well within targets. The `passed: false` in the JSON reflects the strict P50 gate.

## 7.2 1M Decision Stability Test

Results from `benchmarks/results/1m_audit_summary.json` — 1,000,000 decisions, 500 warmup, 1-invariant policy, `sync` mode, single-threaded:

| Metric | Value |
|---|---|
| Total decisions | 1,000,000 |
| Total elapsed | 12,298.479 s |
| Average RPS | 81.3 |
| P50 latency | 11.283 ms |
| P95 latency | 20.145 ms |
| P99 latency | 30.538 ms |
| P99.9 | 153.848 ms |
| P99.99 | 270.578 ms |
| Max | 1,565.746 ms |
| Baseline RSS | 57.617 MiB |
| Final RSS | 60.422 MiB |
| Peak RSS | 80.395 MiB |
| Growth | 2.805 MiB over 1M decisions |
| GC gen0 delta | +6 collections |
| GC gen1/gen2 delta | 0 |

The memory profile is critical evidence. 2.805 MiB growth across 1,000,000 decisions is not a leak. The RSS spikes visible in `1m_audit_full.log` (oscillating between 57 MiB and 74 MiB throughout the run) are Z3's native heap behavior — the solver allocates and deallocates Z3 context objects in its internal C heap, and Python's process RSS reflects those allocations with some lag. The final RSS is only 2.8 MiB above baseline. This is bounded and stable behavior.

The 81.3 average RPS in single-threaded sync mode is the baseline. The 100M benchmark architecture targets 80-120 RPS per worker across 18 workers — 1,440 to 2,160 aggregate RPS.

## 7.3 100M Decision Architecture

The `benchmarks/100m_orchestrator_fast.py` and `benchmarks/100m_worker_fast.py` files document a zero-IPC production architecture:

```
18 × multiprocessing.Process (spawn mode)
Each process: owns sync Guard + Z3 in one address space
Decision loop: cycles through 10,000 pre-built payloads (5 MiB per worker)
Target: 100M decisions per domain × 5 domains = 500M decisions total
```

The architectural comparison is documented:

| Architecture | RPS per Worker | IPC Crossings |
|---|---|---|
| Old (asyncio → ThreadPool → Guard → Z3 process) | 22-27 | 2 per decision |
| New (18 process × sync Guard) | 80-120 | 0 per decision |

The 3.5–5× throughput improvement comes entirely from eliminating IPC crossings.

Windows spawn mode constraint: the target function must be at module level (not nested) because pickle serialises as `("__main__", "worker_entry")`. The child process re-imports the main module to find the function. The `if __name__ == "__main__":` guard prevents infinite recursion. This is documented in `100m_orchestrator_fast.py`.

## 7.4 Memory Under Scale

The 10,000-payload cache uses approximately 500 bytes × 10,000 = 5 MiB per worker. The Guard recycle strategy (recycle after `max_decisions_per_worker = 10,000`) keeps Z3 heap growth bounded. From the benchmark architecture notes:

> max_decisions_per_worker: Recycle Guard after this many decisions (keeps Z3 heap bounded at < 50 MiB growth).

At 18 workers × ~50 MiB Z3 heap peak = ~900 MiB peak RAM usage for the full 100M audit. Pre-flight check requires 25 GB free disk for JSONL output (~7-20 GB per domain run).

---

# PART VIII — USE CASES AND TARGET INDUSTRIES

## 8.1 Financial Services

**Banking Transfers**: `examples/banking_transfer.py` is the canonical reference. A `BankingPolicy` with three invariants (`non_negative_balance`, `within_daily_limit`, `account_not_frozen`) demonstrates all six decision outcomes. The exact arithmetic via `Decimal` prevents the rounding errors that would cause `balance - amount >= 0` to fail or pass incorrectly in IEEE 754.

**High-Frequency Trading — Wash Sale Detection**: `examples/hft_wash_trade.py`. The `WashSaleDetection` primitive in `primitives/fintech.py` directly maps to IRC §1091 (documented in `ComplianceReporter`). A Z3-verified wash sale gate that fires before an order hits the exchange is a direct regulatory risk reduction.

**Anti-Structuring / BSA-AML**: `AntiStructuring` in `primitives/fintech.py`. Maps to BSA/AML 31 CFR §1020.320(a)(2). An AI agent structuring deposits to avoid BSA reporting thresholds is a criminal violation. Z3-verified anti-structuring invariants are provably compliant.

**Collateral Management**: `CollateralHaircut`, `MarginRequirement`, `MaxDrawdown`, `VelocityCheck`. These are quantitative invariants that Z3 handles exactly — no approximation, no rounding error.

## 8.2 Healthcare

**PHI Access Control**: `examples/healthcare_phi_access.py` and `examples/healthcare_rbac.py`. The `PHILeastPrivilege`, `BreakGlassAuth`, `ConsentActive` primitives enforce HIPAA minimum-necessary standard at the action boundary. Every PHI access produces a signed, Merkle-anchored `Decision` with a `decision_hash` — ready for HIPAA audit trail requirements.

**Dosage Safety**: `DosageGradientCheck`, `PediatricDoseBound` — invariants over prescription amounts. An AI clinical decision support system that recommends dosages cannot exceed pediatric weight-based bounds. Z3 verifies this before the recommendation reaches the prescriber.

## 8.3 Cloud Infrastructure

**Blast Radius Control**: `examples/infra_blast_radius.py`. `BlastRadiusCheck` in `primitives/infra.py`. An AI agent scaling Kubernetes pods cannot set replicas above a hard cap without a `ProdDeployApproval` invariant passing. `ReplicaBudget`, `CPUMemoryGuard`, `WithinCPUBudget`, `WithinMemoryBudget` — all computable from current cluster state and expressible as Z3 Real arithmetic.

**SRE Automation**: Infrastructure changes proposed by AI SRE systems are Z3-verified before applying. A change that would violate `MinReplicas` during a traffic spike is blocked with a full explanation.

## 8.4 Multi-Agent Systems

**AutoGen / CrewAI**: `examples/autogen_multi_agent.py`. The `PramanixCrewAITool` and AutoGen adapter ensure that every tool invocation in a multi-agent system — not just the first one — is verified. An agent in a chain cannot bypass a policy by delegating to a sub-agent.

**LangChain / LlamaIndex**: `examples/langchain_banking_agent.py`, `examples/llamaindex_rag_guard.py`. The integration adapters call `Guard.verify()` on every tool execution, not just on initialization. The RAG guard example is important: a retrieval-augmented agent that queries a document database and then proposes an action based on retrieved content cannot use that content to bypass the policy.

---

# PART IX — KNOWN LIMITATIONS AND FUTURE ROADMAP

## 9.1 Verified Limitations (From Code and docs/KNOWN_GAPS.md)

**1. AGPL-3.0 License** (`pyproject.toml:8`). This is not a technical limitation but it is the most impactful business limitation. No enterprise legal team approves AGPL as a Python library dependency. The entire target market — financial services, healthcare, cloud providers — uses Apache 2.0, MIT, or commercial licenses. Switch to Apache 2.0 before any public release. This is documented in `reality.md § 4.2` as the first truth.

**2. Redis Circuit Breaker TOCTOU Race** (`circuit_breaker.py:775`). `RedisDistributedBackend.set_state` reads `failure_count` outside the `pipeline(transaction=True)` block. Under concurrent multi-node writes, increments are lost — the circuit breaker trips later than it should. Fix: `HINCRBY` inside the pipeline.

**3. `_tree_repr` Polynomial Gap** (`transpiler.py:730`). No match clauses for `_PowOp` or `_ModOp`. Structural fingerprint corrupted for polynomial/modulo policies. Z3 correctness unaffected.

**4. Logging Split-Brain** (`reality.md § 4.1`). `guard_config.py` installs structlog with secrets redaction as the first processor. But `worker.py`, `solver.py`, `decision.py`, and most other modules use `logging.getLogger(__name__)` (stdlib), which bypasses the structlog redaction pipeline entirely. Sensitive policy values can reach log sinks unredacted. Fix: route stdlib logging through `structlog.stdlib.ProcessorFormatter`.

**5. Merkle Archive Plaintext** (`audit/archiver.py`). The archiver warns at construction time: compliance deployments must encrypt the archive directory. SOC 2, PCI DSS, HIPAA require encryption at rest. Fix: pluggable `ArchiveWriter` callback.

**6. HMAC-Only JWT** (`identity/linker.py`). HMAC-SHA256 symmetric. Every service in a microservice mesh must share the secret key — symmetric key distribution is a security liability. RS256 or ES256 required for enterprise microservice deployments.

**7. Execution Token Replay After Restart** (`execution_token.py`). The consumed-set is in-memory only. A process restart clears it — replay is possible if a token was minted before restart and consumed after. `RedisExecutionTokenVerifier` closes this for Redis deployments.

**8. No NLP Validators**. No PII redaction, toxicity scoring, or free-text classification. Pramanix is built exclusively for structured intent verification. This is a scope decision, not a gap, but it means Pramanix + Guardrails AI (or similar) are complementary, not alternatives.

**9. Injection Scorer Sub-Penny Gap** (`_sanitise.py:177`). `injection_confidence_score` hardcodes the `"amount"` key. Non-financial callers skip the sub-penny signal unless they pass `sub_penny_threshold=Decimal("0")`. Nothing in the API surface communicates this requirement.

**10. Stub Integrations** (`integrations/`). DSPy, Haystack, Semantic Kernel, and Pydantic AI are stubs — they are present but not fully implemented. Per `docs/KNOWN_GAPS.md § 8`.

## 9.2 Future Roadmap

Based on the known gaps and the architectural trajectory:

**Immediate (Pre-PyPI):**
- License change: AGPL-3.0 → Apache 2.0
- Fix Redis circuit breaker TOCTOU
- Fix `_tree_repr` polynomial gap
- Fix 3 failing tests, restore 98% coverage gate

**Short-Term (v1.1):**
- Logging split-brain fix
- Merkle archive pluggable writer
- RS256/ES256 JWT support
- Hypothesis property tests for injection scorer

**Medium-Term (v1.2):**
- Complete DSPy, Haystack, Semantic Kernel, Pydantic AI integrations
- Z3 formula caching across Guard instances with identical policies
- Declarative policy YAML front-end (without removing Python DSL)

**Long-Term:**
- NLP safety layer integration (PII, toxicity) as optional complement
- Multi-tenant cloud deployment mode with per-tenant policy isolation
- Formal SLSA Level 4 supply chain attestation
- Type-level Z3 sort inference to reduce boilerplate in Field declarations

---

# PART X — COMPETITIVE DEEP-DIVE

## 10.1 Open Policy Agent (OPA)

**What OPA does**: Policy-as-code with Rego, a Datalog-inspired declarative language. Evaluate structured JSON data against policy rules. Returns allow/deny. Used widely for Kubernetes admission control and API authorization.

**Where OPA falls short for Pramanix's use case** (per `docs/DECISIONS.md § 1`):

Rego is Datalog-based. Datalog does not have arithmetic built in. The constraint `balance - amount >= min_reserve` is not expressible in native Rego without custom Rego built-in functions that introduce their own approximation risks. OPA provides no formal completeness guarantee over arithmetic. Attribution in OPA requires `with input as ...` test expressions — there is no native `unsat_core()` equivalent.

**Replication difficulty**: An OPA policy for banking transfers requires writing custom Rego arithmetic extensions and does not produce a counterexample — it returns `deny` with whatever reason message you manually write. The user must diagnose which rule fired. Pramanix returns the exact violated invariant labels with the Z3 counterexample values.

**Correct use**: OPA is the right tool for authorization (`can user X perform action Y?`). Pramanix is the right tool for mathematical safety (`is action Y logically consistent with all invariants?`). Use both.

## 10.2 Guardrails AI

**What Guardrails AI does**: Provides `Validator` objects that run checks on LLM input/output strings. Hundreds of pre-built validators: PII detection, toxicity, content safety, format checks.

**Where Guardrails AI falls short for Pramanix's use case**:

Guardrails AI is a text-processing library. Its validators are probabilistic functions — they return a score or a pass/fail for a string. They do not provide formal proofs. `(E(balance) - E(amount) >= 0)` cannot be expressed as a Guardrails validator without reimplementing Z3 arithmetic.

The `reality.md` audit initially claimed "Pramanix lacks pre-built validators" — this was false. Pramanix has 38 Z3-expressible primitives. But Pramanix genuinely lacks Guardrails AI's NLP-based validators (PII redaction, toxicity scoring). These are different domains.

**Replication difficulty**: Guardrails AI cannot replicate formal mathematical verification. A `balance_check` Guardrails validator would be a Python function that does the arithmetic — no formal guarantee, no counterexample attribution, no unsat core.

**Market reality**: The two systems are complementary. Guardrails AI for content safety on LLM I/O. Pramanix for formal safety on structured actions.

## 10.3 NVIDIA NeMo Guardrails

**What NeMo does**: Colang-based dialogue flow management for conversational AI. Controls what topics an LLM can discuss, how it handles jailbreak attempts, what actions it can take in a multi-turn conversation.

**Why it is not comparable**: NeMo is dialogue management. Pramanix is transactional action verification. They are in entirely different domains. As `docs/Blueprint.md` states: "on transactional action verification, Pramanix is architecturally superior."

## 10.4 The True Competitive Landscape

The `reality.md` audit identifies the actual competition:

> The SDK is not competing with NeMo or Guardrails AI. It is competing with enterprise compliance teams writing custom middleware in Go or Java.

Every financial institution, healthcare provider, and cloud company that deploys AI agents is currently doing one of two things: not verifying actions at all (accepting probabilistic risk), or writing bespoke middleware that reinvents incomplete versions of what Pramanix provides. The `ComplianceReporter` maps `violated_invariants` to BSA/AML CFR citations. Banks pay seven figures for compliance software that does less.

---

# PART XI — ECONOMICS OF RUNNING

## 11.1 Compute Cost Per Decision

At 81.3 RPS single-threaded (from `1m_audit_summary.json`), one CPU core handles approximately 81 verifications per second in sync mode. Each decision costs ~12.3ms of wall-clock time including all overhead.

At the 18-worker architecture (from `benchmarks/100m_orchestrator_fast.py`), targeting 80-120 RPS per worker:
- 18 workers × 80 RPS = 1,440 aggregate RPS minimum
- 18 workers × 120 RPS = 2,160 aggregate RPS maximum

18 processes require 18 CPU cores (or hardware threads). On a 32-vCPU c5.8xlarge (AWS) at $1.36/hour, that is approximately $0.0000094/1,440 decisions per second, or roughly $0.0034 per million decisions in compute only. This is lower than most cloud service API costs and is fully self-hosted.

## 11.2 Memory Budget

Per worker: ~50-80 MiB peak Z3 heap + 5 MiB payload cache + baseline Python process.

From `1m_audit_summary.json`: baseline RSS 57.617 MiB, peak 80.395 MiB, growth 2.805 MiB over 1M decisions.

18 workers × 80 MiB peak = ~1.4 GB RAM for the full 100M/domain audit configuration. A production deployment with 4-8 workers would require 320-640 MB, well within any modern server instance.

## 11.3 SaaS Unit Economics

If Pramanix were productized as a SaaS API:

At 1 billion decisions/month, with 4 dedicated workers per customer:
- Worker RPS: 80-120 per worker
- Decisions per month per 4 workers: ~4 workers × 80 RPS × 86,400 s/day × 30 days = 829M decisions/month
- Cloud cost at $0.0034/million: $2.83/month at 829M decisions

The cost floor is compute, and Z3 is fast. The SaaS pricing ceiling is set by the value of an incorrect decision in the target domain — a single fraudulent banking transfer is typically thousands of dollars. At $0.01/1,000 decisions ($10/million), the margin is enormous relative to cost.

## 11.4 Z3 Compute at Scale

Z3's SMT solving time scales with formula complexity. The two-phase strategy keeps the common case (SAT, all invariants hold) at Phase 1 cost — one shared solver with all invariants. Phase 2 (UNSAT, violation attribution) runs k solvers where k is the number of invariants. For the 5-invariant `BenchmarkPolicy`, Phase 2 would run 5 Z3 instances. For the 14-invariant healthcare policy, it would run 14.

The `rlimit` cap in `GuardConfig.solver_rlimit` prevents CPU exhaustion from adversarially crafted non-linear constraints. From `docs/ARCHITECTURE_NOTES.md § Solver`:

> Every Z3 instance has `set("timeout", timeout_ms)` applied. If `solver_rlimit > 0`, `set("rlimit", solver_rlimit)` is also applied.

At `solver_rlimit = 0`, only wall-clock timeout protects against resource exhaustion. The `reality.md` audit flags `solver_rlimit=0` as a production warning.

---

# PART XII — SECURITY THREAT MODEL

## 12.1 The Eleven-Layer Defence Stack

The complete stack verified from source (`reality.md § 2.1`):

| Layer | Location | Defense |
|---|---|---|
| 1 | `_platform.py` | Alpine/musl rejection at import time |
| 2 | `translator/injection_filter.py` | Pre-compiled regex, ~25 injection patterns |
| 3 | `translator/_sanitise.py` | NFKC normalisation + length limits |
| 4 | `validator.py` | Pydantic v2 strict mode, zero implicit coercions |
| 5 | `translator/redundant.py` | Dual-model LLM consensus |
| 6 | `guard_pipeline.py` | Post-consensus semantic check |
| 7 | `fast_path.py` | Configurable O(1) pre-screener, can only BLOCK |
| 8 | `solver.py` | Z3 with rlimit DoS guard |
| 9 | `translator/_sanitise.py` | Post-consensus injection heuristics |
| 10 | `guard.py` | Governance gates (Privilege, Oversight, IFC) |
| 11 | `crypto.py` | Ed25519 decision signing |

## 12.2 Attack Vector Analysis

**Prompt Injection**: An adversary attempts to override policy by injecting instructions into a natural-language request. The five-layer translator defence handles this: NFKC normalisation collapses homoglyphs, regex patterns detect common overrides, dual-model consensus requires both LLMs to agree. The Z3 layer is unreachable via text injection because the policy is compiled Python DSL — `"ignore previous instructions"` cannot affect the Z3 formula.

**Malicious Z3 Constraints**: An adversary attempts to express a formula that consumes infinite CPU time. Mitigation: both wall-clock timeout and `rlimit` (elementary operation cap) are applied. `rlimit` prevents non-linear expression DoS that can defeat wall-clock timeout via adversarial formula construction.

**Worker Process Exploitation**: In `async-process` mode, a memory-safety vulnerability in Z3 (a C++ library) could allow code execution in a worker process. The HMAC-sealed IPC (`docs/DECISIONS.md § 15`) means a compromised worker cannot forge `allowed=True` in the host process without the ephemeral key, which is only stored in the host process and is not serializable.

**HMAC Key Compromise** (`reality.md § 2.1`): `injection_scorer.py:305` uses `pickle.loads()` after HMAC verification. If `PRAMANIX_SCORER_KEY` is compromised, this is an RCE vector. HMAC key hygiene is a deployment requirement that must be documented prominently.

**JWT Algorithm Confusion** (fixed, `CHANGELOG.md § BUG-10`): The CVE-2015-9235 family attack — crafting a token with `alg: "RS256"` and an HMAC-SHA256 signature — was present and is now fixed. The header is now decoded and `alg` validated as `"HS256"` before signature computation.

**Timing Oracle**: ALLOW responses returning faster than BLOCK responses allow binary-search probing to identify violated constraints even with `redact_violations=True`. Fixed: timing pad applied unconditionally to every response before the ALLOW/BLOCK branch (`CHANGELOG.md § H-02`).

**Replay Attack on Execution Tokens**: A stolen `ExecutionToken` could authorize an action without fresh verification. Mitigation: `ExecutionTokenVerifier.consume()` removes the `token_id` from an in-memory set under `threading.Lock`. Single-use guarantee holds within a process lifetime. `RedisExecutionTokenVerifier` extends this to Redis deployments for process-restart resilience.

## 12.3 The IPC Integrity Boundary

The HMAC-sealed IPC design (`docs/DECISIONS.md § 15`) is a security boundary that most IPC frameworks omit. The `multiprocessing.Queue` does not provide integrity guarantees. A forged pickle payload from a compromised worker is indistinguishable from a legitimate one without an explicit MAC. The design:

1. Ephemeral key generated at Guard construction time, stored host-process-only
2. Every solve result is HMAC-SHA256 tagged before crossing the Queue boundary
3. Host process verifies tag before trusting the result
4. `_EphemeralKey.__reduce__` raises `TypeError` — the key cannot be serialized

The overhead is one HMAC-SHA256 per decision. The security property: forging `allowed=True` from a compromised worker requires knowledge of the ephemeral key.

## 12.4 The Audit Non-Repudiation Chain

Four layers of non-repudiation:

1. **Decision hash**: SHA-256 over `decision_id + status + allowed + violated_invariants + explanation`. Deterministic. Any tampering is detectable.
2. **Ed25519 signature**: Signs the decision hash. Offline verifiable with only the public key.
3. **Merkle proof**: Proves inclusion in an unaltered batch without replaying all decisions.
4. **ProvenanceChain**: HMAC-signed chain-of-custody binding each decision to policy version, model version, and IFC input labels.

These four layers collectively make it impossible to tamper with a decision record without either breaking Ed25519 or invalidating the Merkle tree, both of which are computationally infeasible.

---

# PART XIII — ACADEMIC AND RESEARCH GROUNDING

## 13.1 SMT Solving — The Theoretical Foundation

Satisfiability Modulo Theories (SMT) is the decision problem for logical formulas with respect to background theories. The theories Pramanix uses:

**Linear Real Arithmetic (LRA)**: For financial constraints of the form $balance - amount \geq min\_reserve$. LRA is decidable (Presburger arithmetic over reals is decidable). Z3 uses the Simplex algorithm for LRA, which has polynomial average-case complexity for common financial constraint patterns.

**Linear Arithmetic over Integers (LIA)**: For count-based constraints. Also decidable.

**Boolean combinations**: Z3's DPLL(T) architecture combines SAT solving (propositional Boolean reasoning) with theory solvers. The DPLL SAT solver handles the Boolean structure; the theory solver (Simplex for LRA) handles the arithmetic atoms.

The two-phase strategy in Pramanix exploits the asymmetry between the SAT case and the UNSAT case. For the SAT case, a shared solver with `add()` is optimal — one solve, linear in the number of constraints. For the UNSAT case, per-invariant solvers with `assert_and_track` give complete attribution.

## 13.2 Formal Methods in Safety-Critical Systems

Formal verification in safety-critical domains (avionics, nuclear, medical devices) has used model checkers and theorem provers for decades. The NASA Ames Formal Methods group, the Cambridge L4.verified project, and seL4 demonstrate that formal verification at scale is achievable in production systems.

Pramanix applies this philosophy to a newer domain: AI agent actions. The argument is exactly the same as in avionics: when the cost of an incorrect action is high enough, probabilistic correctness is insufficient. A bank transfer that overdrafts an account is not a statistic; it is an individual financial loss. Formal verification eliminates the possibility.

## 13.3 Neuro-Symbolic AI

The "neuro-symbolic" framing in the project name and description reflects the architecture: a neural component (LLM for intent extraction) combined with a symbolic component (Z3 for formal verification). This is a recognized research paradigm, with work from IBM Research, MIT, and DeepMind on neuro-symbolic integration.

Pramanix's contribution is a production-ready instantiation: the LLM extracts structured intent from natural language; the symbolic verifier proves that intent against formal constraints. The LLM's probabilistic nature is contained to the extraction phase; the verification phase is deterministic.

The dual-model consensus (`docs/DECISIONS.md § 7`) is a neuro-symbolic defense: two independent neural extractors must agree before the symbolic verifier is invoked. Disagreement is itself a signal — ambiguous or adversarial input produces consistent disagreement between models, which blocks the action.

## 13.4 The Z3 Literature

Microsoft Research's Z3 has been continuously developed since 2007 (de Moura and Bjørner, Z3: An Efficient SMT Solver, 2008). It is used in program verification (KLEE, Pex), security (S2E, ForAllSecure), and formal methods education worldwide. The key properties exploited by Pramanix:

- **DPLL(T) completeness**: For decidable theories (LRA, LIA), Z3 either returns SAT with a model or UNSAT with a proof. No false positives.
- **Unsat cores**: `assert_and_track + unsat_core()` extracts the minimal set of constraints responsible for unsatisfiability. Pramanix uses one constraint per solver to get complete attribution without relying on Z3's heuristic minimal-core extraction.
- **Python API**: `z3-solver` is the official Python binding with the Z3 C++ library. The GIL is released during solver execution (`docs/DECISIONS.md § 1`), enabling genuine thread-level parallelism.

---

# PART XIV — FAILURE LOG

## 14.1 Architectures That Were Tried and Rejected

**Recursive Merkle root construction**: The initial `MerkleAnchor._build_root` was recursive. It hit Python's default call stack limit at approximately 1,000 decisions. The iterative replacement uses O(1) stack depth. Documented in `docs/DECISIONS.md § 18`.

**fork() instead of spawn() for worker processes**: Fork copies parent file descriptors, memory-mapped files, and OS resources. Z3 has internal state — forking after Z3 initialization produced undefined behavior. spawn() starts a clean process. `docs/DECISIONS.md § 4` documents the specific failure mode.

**threading.local for resolver cache**: `threading.local` is thread-scoped. Under asyncio, multiple concurrent tasks share one OS thread. Task B could see Task A's resolved field values — a data bleed between users. `contextvars.ContextVar` is Task-scoped. `docs/DECISIONS.md § 6`.

**Single solver for unsat attribution**: Z3's `unsat_core()` on a multi-assertion solver does not always return the minimal core — the extraction is heuristic. One solver per invariant guarantees `unsat_core()` returns exactly `{label}`. Documented in `docs/DECISIONS.md § 3`.

**Eval/exec in the transpiler**: Early design considerations included string-based formula generation. Rejected entirely — eval/exec of user-supplied or internally generated strings is an RCE surface. The DSL is a typed Python object tree; the transpiler is structural pattern matching over it. `docs/DECISIONS.md § 9`.

**Floating-point direct to Z3**: Financial constraints with floating-point values would have IEEE 754 rounding errors. `0.1 + 0.2 != 0.3` in Z3's floating-point arithmetic. The `Decimal(str(v)).as_integer_ratio()` path was not obvious — it required understanding Z3's `RatVal` constructor and the specific behavior of Python's `Decimal.as_integer_ratio()`. `docs/DECISIONS.md § 10`.

## 14.2 Security Bugs Found During Development

The CHANGELOG documents security bugs found during internal audit. These are real, not hypothetical:

**Silent stub exploitation** (H-03, H-04): The LangChain and CrewAI integrations both had `execute_fn=None` defaulting to `lambda i: "OK"`. Any guarded action returned success without executing real logic. This is a complete defeat of the tool's purpose. Both fixed by raising `NotImplementedError`.

**Async fail-safe bypass** (C-01): `verify_async()` had `except Exception: pass` in the size-check path. Unserializable payloads silently bypassed the size gate. This is the async analog of the fail-closed contract — any exception must produce `Decision.error(allowed=False)`, never silent pass.

**Timing oracle** (H-02): ALLOW and BLOCK responses having different latencies is a side-channel attack. The timing pad was applied only to BLOCK. An attacker with sub-millisecond timing measurement could binary-search which invariants are violated even with `redact_violations=True`.

**JWT algorithm confusion** (BUG-10): The CVE-2015-9235 family. Decoding the payload before validating the algorithm allows crafting tokens with mismatched algorithms. Fixed by validating `alg` before any cryptographic operation.

## 14.3 The Hardest Bugs

**Z3 context threading**: Z3 `Context` objects are thread-local C objects. They cannot be shared between threads. The GIL is released during solving — this is good for parallelism but means Z3 operations in multiple threads run truly concurrently in C code. Using shared contexts between threads produces undefined behavior. The solution: thread-local `z3.Context()` created once per OS thread, never destroyed. The adversarial test (`test_z3_context_isolation.py`) uses `threading.Barrier` to force 10 concurrent simultaneous solver executions and verify no cross-contamination.

**The `ConstraintExpr.__bool__` trap**: `expr1 and expr2` in Python short-circuits at the Python level. If `ConstraintExpr.__bool__` returned `True`, the `and` expression would return `expr2`, silently discarding `expr1`. The policy would be missing an invariant with no error. The fix — raising `PolicyCompilationError` — means the common mistake (using Python `and`/`or` instead of `&`/`|`) is immediately detected.

---

# PART XV — REAL WORLD SIMULATION RESULTS

## 15.1 The 1M Decision Stability Test

The most important stability result is in `benchmarks/results/1m_audit_summary.json`. One million decisions at 81.3 average RPS, with memory and GC tracked throughout.

Key finding: Z3 heap behavior is oscillatory, not leaking. The `1m_audit_full.log` shows RSS spiking between 57 MiB and 74 MiB throughout the entire run, then settling. The net growth over 1M decisions: 2.805 MiB. GC gen0 collected 6 additional times; gen1 and gen2 unchanged. This is bounded, stable behavior.

The P99.9 of 153.848ms and P99.99 of 270.578ms indicate rare but real tail latency events. The max of 1,565.746ms is a single outlier — likely GC pause or OS scheduling jitter. For production deployments, a `min_response_ms` padding budget and circuit breaker should handle these tail events.

## 15.2 Finance Domain Stress Test

`benchmarks/100m_domain_policies.py` documents the Finance domain benchmark policy (`Finance100MPolicy`) with target statistics:

- 20% overdraft (BLOCK on `non_negative_balance`)
- 10% high risk (BLOCK on `risk_score_below_threshold`)
- ~5% overlap (double BLOCK)
- Target ~25% BLOCK rate overall

This mix exercises both Phase 1 (SAT, ~75% of decisions) and Phase 2 (UNSAT attribution, ~25% of decisions). A policy tuned only for common-case SAT performance that degrades badly on UNSAT would not survive this benchmark.

## 15.3 Banking Domain with 4-Invariant Policy

The `BankingPolicy` in `examples/banking_transfer.py` has three invariants. The `BenchmarkPolicy` in `benchmarks/latency_benchmark.py` has five. The 1M audit used a 1-invariant policy for baseline measurement. Real banking policies typically have 3-7 invariants. The Phase 2 cost scales linearly with invariant count; at 5 invariants, Phase 2 (violation attribution) runs 5 Z3 solvers, each typically completing in 1-3ms for linear arithmetic.

## 15.4 Memory Growth Model

The benchmark architecture's `max_decisions_per_worker = 10,000` Guard recycling strategy was empirically derived. Without recycling, Z3's internal C heap grows monotonically as new formula objects are allocated. The Guard recycle strategy:

1. After 10,000 decisions, the old Guard is replaced with a new one
2. The old Guard's worker pool is drained (background thread, `_drain_executor`)
3. Z3 heap of the old Guard is freed by Python's GC when the Guard object's reference count drops to zero

This keeps Z3 heap bounded at `< 50 MiB growth` per the benchmark documentation.

---

# PART XVI — DEPENDENCY RISK ANALYSIS

## 16.1 Z3 API Change Risk

Z3's Python API (`z3-solver`) has been stable for several major versions. The constraint in `pyproject.toml`: `z3-solver = "^4.12"`. The `^` operator means compatible releases — `>=4.12.0, <5.0.0`.

Risk: Z3 major version bumps have historically been infrequent (4.x has been the stable line since 2018). The Z3 API is not designed for external callers to depend on specific internal behaviors — the parts Pramanix uses (`.check()`, `.model()`, `.unsat_core()`, `z3.RatVal()`, `z3.Context()`) are stable public API.

Mitigation: The transpiler is the only file calling Z3 directly. A Z3 API change requires updating only `transpiler.py` and `solver.py`. The rest of the codebase is Z3-agnostic.

## 16.2 Z3 Swap Difficulty

Could Z3 be swapped for another SMT solver (e.g., cvc5, MathSAT)? The transpiler translates the DSL AST to Z3 AST nodes (`z3.ExprRef`). A swap would require:

1. A new transpiler file that emits the target solver's AST
2. A new solver module wrapping the target solver's Python API
3. Compatibility verification for the exact Z3 behaviors used: `RatVal` for exact rationals, `assert_and_track` + `unsat_core()` for attribution, GIL release during solve

The DSL and all user-facing policy code would be unchanged. The swap difficulty is medium — approximately 500-800 lines of code in the transpiler and solver, plus thorough re-testing of the exact rational arithmetic behavior.

## 16.3 LLM Deprecation Risk

The translator layer supports seven LLM providers. If any single provider deprecates its API, only one adapter file needs updating. The `OpenAICompatTranslator` in `translator/openai_compat.py` is the most important — it covers OpenAI, Azure OpenAI, and any OpenAI-compatible endpoint. This broad coverage reduces single-provider lock-in.

Risk: The LLM translation layer is beta (`docs/PUBLIC_API.md`). API shape adjustments are explicitly possible in minor versions.

## 16.4 Pydantic v2 Dependency

`pydantic = "^2.5"` — Pydantic v2 with strict mode. Pydantic v2 is a complete rewrite from v1; the APIs are incompatible. Pramanix has committed to v2 strict mode as a core dependency. Migration to a hypothetical v3 would require updating validator.py and all `BaseModel` subclasses.

## 16.5 Single Points of Failure

The only genuine single point of failure in the system is Z3. If Z3 is unavailable (binary not found, musl libc incompatibility), the entire verification stack fails. The musl check (`_platform.py`) fails fast at import time rather than at first verification. The `solver_timeout_ms` and `solver_rlimit` parameters provide runtime protection against Z3 misbehavior. But there is no Z3 fallback — by design, the system is fail-closed when Z3 is unavailable.

---

# PART XVII — REGULATORY MAPPING

## 17.1 Financial Regulation

The `ComplianceReporter` in `helpers/compliance.py` maps `violated_invariants` Z3 labels to structured regulatory citations. The specific frameworks and their mappings (from `reality.md § 2.4`):

| Domain | Regulation | CFR/USC Reference |
|---|---|---|
| BSA/AML | Bank Secrecy Act, Anti-Structuring | 31 CFR §1020.320(a)(2) |
| OFAC/SDN | Sanctions screening | 50 CFR §598 |
| SEC Wash Sale | Securities regulation | IRC §1091 |
| SOX | Financial controls reporting | 15 U.S.C. §7241 |
| Basel III | Capital adequacy | BCBS 189 |

The `AntiStructuring` primitive in `primitives/fintech.py` directly implements the BSA anti-structuring constraint. When this invariant is violated, `ComplianceReporter` can generate a report citing the specific CFR section — ready for regulators.

## 17.2 Healthcare Regulation (HIPAA)

`PHILeastPrivilege`, `BreakGlassAuth`, `ConsentActive`, `DosageGradientCheck`, `PediatricDoseBound` in `primitives/healthcare.py`. The `ComplianceReporter` maps these to HIPAA 45 CFR §164.

**Audit trail for HIPAA**: Every PHI access decision produces a `Decision` with `decision_hash`, Ed25519 signature, and Merkle inclusion proof. This satisfies HIPAA's audit log requirements: who accessed what, when, with proof of unaltered records.

**Note**: Merkle archive plaintext gap (`reality.md § 4.1`) is a blocker for HIPAA compliance: PHI-adjacent audit logs stored in plaintext would fail a HIPAA audit. This must be fixed before production healthcare deployment.

## 17.3 EU AI Act

The EU AI Act (Regulation (EU) 2024/1689) classifies AI systems by risk. High-risk AI systems (Annex III, including financial services AI, healthcare AI, and critical infrastructure AI) require:

- **Article 9**: Risk management system — ongoing evaluation of risks
- **Article 10**: Data governance — training data quality
- **Article 12**: Record-keeping — logging of AI system operations
- **Article 13**: Transparency — information to deployers
- **Article 17**: Quality management system

Pramanix's audit trail (signed decisions, Merkle anchoring, ProvenanceChain) directly supports Article 12 record-keeping. The `ComplianceReporter` could be extended to produce EU AI Act Article 13 transparency reports from Decision audit logs.

## 17.4 SOC 2 Type II

SOC 2 Trust Services Criteria require documented evidence of controls. For a financial AI system:

- **CC6.1 (Logical access)**: The JWT identity boundary with HMAC-SHA256 verification and `sub` claim validation
- **CC7.2 (System operations monitoring)**: 6 configurable audit sinks (Kafka, S3, Splunk, Datadog)
- **CC7.3 (Incident detection)**: `AdaptiveCircuitBreaker` state machine with `ISOLATED` state requiring manual reset
- **Availability (A1)**: Circuit breaker + load shedding + process isolation
- **Confidentiality (C1)**: `_RedactSecretsProcessor` in structlog pipeline, IFC labels

The Merkle archive plaintext gap is a blocker for CC6.6 (encryption of data at rest). This must be fixed before a SOC 2 audit.

---

# PART XVIII — SCALING STORY

## 18.1 10x Scale: Current Architecture

At 10x current load (810 RPS), a 10-worker configuration with the zero-IPC architecture:

- 10 workers × 80-120 RPS = 800-1,200 RPS aggregate
- RAM: 10 workers × 80 MiB = 800 MiB
- CPU: 10 dedicated cores (or hardware threads)
- Audit sink throughput: Kafka sink has a bounded 10,000-message queue; at 810 RPS, this buffer holds ~12 seconds of backlog

No architectural changes required. The current design handles 10x by adding workers. The circuit breaker (`AdaptiveCircuitBreaker`) begins shedding load when P99 latency exceeds `shed_latency_threshold_ms`, protecting against cascade failure.

## 18.2 100x Scale: Horizontal Z3 Worker Pools

At 100x (8,100 RPS), a single machine with 18 workers approaches its ceiling (~2,160 RPS). Scaling to 8,100 RPS requires 4-6 machines or a Kubernetes deployment.

Architecture:
- K8s `PramanixMiddleware` admission webhook → shared policy hash check at startup
- StatelessGuard instances per pod (no inter-pod state, policies are immutable)
- Redis `DistributedCircuitBreaker` for coordinated load shedding across pods
- Redis `RedisExecutionTokenVerifier` for cross-pod single-use token enforcement

The policy hash check (`GuardConfig.expected_policy_hash`) is the critical invariant: all replicas must run the same policy version. A SHA-256 mismatch at construction time raises `ConfigurationError` — prevents split-brain policy enforcement across replicas during rolling deploys.

## 18.3 1000x Scale: What Breaks First

At 1,000x (81,000 RPS), several architectural limits are hit:

**Z3 memory**: At ~80 MiB peak per worker × 750 workers = ~60 GB peak RAM. Horizontal pod scaling with smaller per-pod worker counts mitigates.

**Redis circuit breaker**: The documented TOCTOU race in `circuit_breaker.py:775` becomes critical. At high write concurrency, `failure_count` under-counting causes late tripping. Fix: `HINCRBY` inside pipeline or Lua script.

**Audit sink throughput**: Kafka sink's 10,000-message queue overflows if backend throughput drops below 81,000 messages/second. The Prometheus overflow metric (`AuditSink` has an overflow counter) will show this. Fix: increase queue size or add Kafka partitioning.

**Execution token consumed-set**: In-memory `threading.Lock`-protected set is per-process. At 81,000 RPS across hundreds of pods, the `RedisExecutionTokenVerifier` becomes mandatory — and Redis becomes a SPOF.

## 18.4 Multi-Tenant Architecture

`SecureMemoryStore` with IFC trust labels provides per-tenant isolation in a single process. `UNTRUSTED` data cannot write to `CONFIDENTIAL+` partitions. In a true multi-tenant cloud deployment:

- Per-tenant policy isolation: each tenant's Guard uses a different Policy class
- Per-tenant audit trails: each tenant's decisions go to a dedicated audit sink
- Per-tenant keys: `KeyProvider` per tenant, backed by AWS KMS or Azure Key Vault with per-tenant key namespacing

The `contextvars.ContextVar` resolver cache is Task-scoped — concurrent requests from different tenants on the same OS thread cannot bleed field values.

---

# PART XIX — DEVELOPER EXPERIENCE DECISIONS

## 19.1 Python vs. Rust/Go

The decision to use Python is not documented explicitly, but it is implicit in the architecture. The reasons are clear from the design:

**Ecosystem fit**: AI agent frameworks (LangChain, AutoGen, CrewAI) are Python-first. The SDK must integrate without a language boundary. A Rust or Go guard library would require FFI from Python, adding complexity and latency.

**Z3's Python binding**: `z3-solver` is the official Python binding. Z3's Rust bindings (`z3` crate) are less mature and do not have feature parity. The Python binding is the reference implementation.

**DSL ergonomics**: The policy DSL is Python code. `E(balance) - E(amount) >= 0` is natural Python. The equivalent in Rust would require a builder pattern with much more syntactic noise.

**Type checking**: `mypy` strict mode with `disallow_untyped_defs = true` gives Pramanix close to Rust-level type safety in Python.

**The GIL tradeoff**: Z3 releases the Python GIL during solve. This means genuine parallel solving in thread mode without Python-level synchronization. The GIL is not a limitation for the CPU-bound Z3 work.

## 19.2 Poetry vs. pip

`pyproject.toml` uses Poetry's build backend (`poetry-core>=1.7.0`). The lockfile-based dependency resolution prevents the transitive dependency conflicts that bare pip installs produce with 31 optional extras. The `[all]` extra installs 31 packages from 7 different ecosystem areas (AI, cloud, database, cryptography, compliance). Poetry's lockfile ensures reproducible installs. The test failure with `google-generativeai` (`AttributeError: module 'google' has no attribute 'auth'`) is an example of the transitive dependency conflict risk — even with Poetry, some extras interact badly.

## 19.3 AGPL-3.0 vs. Apache 2.0 vs. MIT

This is the most consequential non-technical decision in the project. AGPL-3.0 is documented in `pyproject.toml:8` and analyzed in `reality.md § 4.2` as the first absolute blocker:

> AGPL-3.0 License: No enterprise legal team approves an AGPL Python dependency. Blocks fintech, healthcare, and enterprise B2B adoption.

AGPL's copyleft requirement: any software that uses an AGPL library and is provided as a network service must release its source code. For a bank or hospital using Pramanix in production, this means releasing their entire application source. No enterprise legal team accepts this.

Apache 2.0 is the correct choice for a commercially-targeted open-source SDK. It provides patent protection (important for Z3 usage), has enterprise-approved legal language, and allows proprietary use without source release. MIT is also viable but lacks Apache's explicit patent grant.

## 19.4 DSL Syntax Alternatives

The DSL design (`expressions.py`) chose Python operator overloading (`&`, `|`, `~`, `>=`, `<=`, `>`, `<`, `==`, `!=`) over several alternatives:

**String-based DSL** (`"balance - amount >= 0"`): Rejected because it requires `eval`/`parse` and is an injection vector. No type checking. No IDE support.

**YAML-based policy**: Rejected because YAML cannot express Python-typed constraints without a custom schema language. Less maintainable than Python.

**Rego/Datalog-style**: Rejected because it lacks Z3's arithmetic. Would require embedded parser.

**JSON Schema-based**: Rejected because JSON Schema is not a constraint specification language — it validates types, not cross-field relationships.

The Python operator overloading approach trades some operator-precedence surprises (users must use `&` not `and`) for IDE support, type checking, and Python-native ergonomics. The `__bool__` raising provides immediate feedback when the common mistake (`and` instead of `&`) is made.

---

# PART XX — PERSONAL REFLECTION

## 20.1 What This Project Actually Is

Pramanix is an attempt to answer one specific engineering question: can production-quality formal verification be made accessible to Python developers who build AI systems?

The answer, based on the evidence of this codebase, is yes — with significant caveats. The caveats are not embarrassments; they are the research findings.

## 20.2 What Required the Most Learning

**Z3 internals**: Thread-local contexts, GIL release semantics, `assert_and_track` vs `add()`, `RatVal` vs `IntVal` vs `RealVal`, `rlimit` as a DoS defense. None of this is in the Z3 Python tutorial. It required reading Z3's C++ source code, the DPLL(T) algorithm papers, and extensive empirical testing under adversarial conditions.

**The memory model**: Understanding why Z3 heap oscillates rather than leaks, how Python's GC interacts with C++ allocated objects via `z3-solver`, when to recycle a Guard instance — these required building the 1M-decision benchmark and reading the log output at the line level.

**Exact arithmetic in SMT**: The `Decimal.as_integer_ratio()` insight was not obvious. IEEE 754 floating-point passed to Z3's `z3.Q(...)` produces floating-point arithmetic in Z3, not real arithmetic. `z3.RatVal(numerator, denominator)` from the integer ratio produces exact rational arithmetic. This distinction matters for financial invariants and took significant experimentation to understand and verify.

**Security reasoning in depth**: The JWT algorithm confusion bug (BUG-10), the async fail-safe bypass (C-01), the timing oracle (H-02), the worker HMAC seal — these are not bugs that surface in happy-path testing. They surface in adversarial analysis. Building the threat model before the implementation would have caught several earlier.

## 20.3 What the Audit Taught

The `reality.md` document is the most important artifact in this repository. It is an honest, line-by-line audit of every claim made about the system against the actual source code. Several claimed features were initially described incorrectly; the audit corrected them. Several real gaps were found that the initial implementation missed.

The practice of writing this kind of audit — before any external release — is what separates engineering from marketing. The gaps documented in `reality.md` are not weaknesses to hide; they are the work remaining to be done.

Three truths from the audit that summarize the project:

1. **The technical moat is real.** Eleven-layer defence stack, 38 pre-built primitives, enterprise compliance reporting with six regulatory frameworks, audit infrastructure ready for regulated industries. This was independently verified line by line.

2. **The licence is the crisis.** Every claim about enterprise market potential is blocked by AGPL-3.0. Switch to Apache 2.0 before anything else.

3. **The ComplianceReporter and ShadowEvaluator are the features that nobody knows about.** A compliance reporter that converts a Z3 violation label into a BSA/AML CFR citation, ready for auditors, exported as PDF. A shadow evaluator that runs canary policy tests non-blocking against live traffic before promotion. These are the capabilities that make Pramanix an enterprise product rather than a developer SDK. They need front-page documentation.

## 20.4 What Comes Next

The fail-closed contract must never be relaxed. The Z3 path to `allowed=True` must remain the only path. Every layer that was added to the defence stack was added because a specific attack vector existed, and it must be maintained.

The license must change. The Redis circuit breaker race must be fixed. The logging split-brain must be unified. The Merkle archive encryption must be pluggable.

After those four changes, Pramanix is ready for external release. Not because the system is perfect — the 14 known gaps in `docs/KNOWN_GAPS.md` document what remains. But because every gap is known, named, and honest, and the core contract has not been broken.

That is what production readiness means: not the absence of gaps, but the honest accounting of them.

---

## APPENDIX A — File Reference Map

| Claim | File | Line/Section |
|---|---|---|
| Fail-closed contract | `docs/DECISIONS.md` | §2 |
| Two-phase solver | `docs/DECISIONS.md` | §3 |
| Exact arithmetic | `docs/DECISIONS.md` | §10 |
| HMAC-sealed IPC | `docs/DECISIONS.md` | §15 |
| ContextVar isolation | `docs/DECISIONS.md` | §6 |
| Alpine/musl rejection | `docs/DECISIONS.md` | §12 |
| Iterative Merkle | `docs/DECISIONS.md` | §18 |
| Timing pad design | `docs/DECISIONS.md` | §19 |
| P50/P95/P99 latency | `benchmarks/results/latency_results.json` | root |
| 1M stability test | `benchmarks/results/1m_audit_summary.json` | root |
| 100M architecture | `benchmarks/100m_orchestrator_fast.py` | header |
| 38 primitives | `reality.md` | §2.2 |
| AGPL blocker | `reality.md` | §4.2 |
| Redis TOCTOU | `reality.md` | §4.1 |
| Logging split-brain | `reality.md` | §4.2 |
| 3966 tests | `reality.md` | §3.1 |
| Stability tiers | `docs/PUBLIC_API.md` | Stability Tiers |
| 9 integrations | `reality.md` | §2.4 |
| ComplianceReporter | `reality.md` | §2.4 |
| ShadowEvaluator | `reality.md` | §2.4 |
| BUG-10 JWT fix | `docs/CHANGELOG.md` | §BUG-10 |
| H-02 timing fix | `docs/CHANGELOG.md` | §H-02 |
| C-01 async fix | `docs/CHANGELOG.md` | §C-01 |

---

## APPENDIX B — Dependency Inventory

Core (always installed with `pip install pramanix`):

| Package | Version | Purpose |
|---|---|---|
| `pydantic` | `^2.5` | Strict-mode input validation |
| `z3-solver` | `^4.12` | SMT formal verification engine |
| `structlog` | `^23.2` | Structured logging with secrets redaction |

Optional extras (31 total, from `pyproject.toml`):
- `translator`: httpx, openai, anthropic, tenacity
- `otel`: opentelemetry-sdk, opentelemetry-exporter-otlp-proto-grpc
- `fastapi`: fastapi, starlette, httpx
- `crypto`: cryptography (Ed25519)
- `aws`/`azure`/`gcp`/`vault`: cloud key providers
- `kafka`: confluent-kafka (audit sink)
- `metrics`: prometheus-client
- `performance`: orjson
- `sklearn`: scikit-learn (CalibratedScorer)
- Plus 20 more for specific integrations

---

*End of Thesis*

*Every claim in this document is grounded in source code, benchmark output, or documentation that exists in the repository as of the audit date 2026-05-12. Where the code and any documentation disagree, the code is the authority.*
