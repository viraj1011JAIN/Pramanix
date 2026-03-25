# Pramanix -- Architecture Reference

> **Version:** v0.8.0
> **For the complete design specification see** [Blueprint.md](Blueprint.md).
> **Audience:** Engineers integrating Pramanix, contributors, and reviewers doing a security evaluation.

---

## 1. What Pramanix Does

- Takes an AI agent's intended action (structured or natural language)
- Runs it through a mathematically proven policy check using Z3 SMT solver
- Returns a `Decision` that is either `allowed=True` (SAFE, mathematically proven) or `allowed=False` (BLOCK, with the exact reason)
- Never guesses, never uses a confidence score -- every ALLOW has a formal proof, every BLOCK has a counterexample

---

## 2. Two-Phase Execution Model

Every call to `Guard.verify()` goes through exactly two phases:

```
                    ┌──────────────────────────────────────────────┐
                    │  PHASE 1 -- Intent Extraction (optional)      │
                    │                                               │
  User Input        │  Raw text                                     │
  (NL string)  ───► │    ↓  sanitise_user_input()                   │
                    │  Cleaned text                                 │
                    │    ↓  dual-model LLM extraction               │
                    │  Two independent JSON extractions             │
                    │    ↓  validate_consensus()                    │
                    │  Canonical JSON (both models agreed)          │
                    │    ↓  injection_confidence_score()            │
                    │  Risk score check (≥0.5 → BLOCK)              │
                    │    ↓  Pydantic strict validation              │
                    │  Typed intent dict                            │
                    └──────────────────┬───────────────────────────┘
                                       │  ALLOW (only if all checks pass)
                                       ↓
  Structured        ┌──────────────────────────────────────────────┐
  Input        ───► │  PHASE 2 -- Z3 Formal Verification           │
  (dict)            │                                               │
                    │  values dict                                  │
                    │    ↓  max_input_bytes check (64 KiB cap)      │
                    │  size-validated payload                       │
                    │    ↓  Transpiler: DSL → Z3 AST               │
                    │  Z3 formula list                              │
                    │    ↓  shared solver: overall SAT/UNSAT        │
                    │  If UNSAT: per-invariant solvers              │
                    │    ↓  Decision factory                        │
                    │  Immutable Decision object                    │
                    │    ↓  Ed25519 sign (if signer configured)     │
                    │  Signed Decision                              │
                    │    ↓  timing pad (if min_response_ms set)     │
                    │  Decision returned to caller                  │
                    └──────────────────────────────────────────────┘
```

- **Phase 1 only runs when `translator_enabled=True`** (NLP mode). Structured API mode skips directly to Phase 2.
- **Phase 2 always runs.** There is no shortcut to ALLOW without Z3.
- **Any exception at any step returns `Decision.error(allowed=False)`.** Nothing can convert an error into ALLOW.

---

## 3. Full Data Flow -- NLP Mode

```
User text
  │
  ▼
sanitise_user_input()
  - Unicode NFKC normalisation
  - Hard truncation at 512 characters
  - C0 control character strip (except \n and \t)
  - 30+ injection pattern scan (records warnings, does not silently strip)
  │
  ▼
Dual-model extraction  (asyncio.gather)
  - GPT-4o  ──┐  independent calls
  - Claude   ──┘  same prompt, same input
  │
  ▼
validate_consensus()
  - Serialize both outputs: json.dumps(sort_keys=True)
  - Exact string equality check
  - Any mismatch → ExtractionMismatchError → Decision(allowed=False)
  │
  ▼
injection_confidence_score()
  - Additive risk: pattern match (+0.60), short input (+0.20),
    sub-penny amount (+0.30), dangerous recipient chars (+0.30),
    unparseable amount (+0.40), high-entropy token (+0.20)
  - Score ≥ 0.5 → InjectionBlockedError → Decision(allowed=False)
  │
  ▼
Pydantic strict validation  (intent_model.model_validate(strict=True))
  - Type coercion, range checks, string length limits
  - ValidationError → Decision(allowed=False)
  │
  ▼
Async field resolvers  (run on event loop BEFORE dispatching to worker)
  - Thread-local cache prevents cross-request contamination
  - ResolverNotFoundError → Decision(allowed=False)
  │
  ▼
WorkerPool.submit_solve()
  - Dispatch to thread or spawn-isolated subprocess
  - model_dump() before process boundary (never pickle Pydantic models)
  │
  ▼
Z3 Solve  (inside worker)
  - Transpile DSL expressions to Z3 AST
  - Shared solver: fast overall SAT/UNSAT check
  - If UNSAT: per-invariant solvers for exact violation attribution
  - HMAC-SHA256 seal on result (IPC tamper protection)
  │
  ▼
Decision object
  - allowed, status, violated_invariants, explanation
  - decision_hash: SHA-256 over canonical JSON
  - signature: Ed25519 (if PramanixSigner configured)
  │
  ▼
Audit log  (structlog JSON line)
  - decision_id, policy, status, latency_ms, timestamp
  - Merkle anchor updates (PersistentMerkleAnchor if configured)
```

---

## 4. Module Map

| Module | File | Responsibility |
|--------|------|---------------|
| Guard | `guard.py` | SDK entrypoint, config, fail-safe wrapper, Phase 12 hardening |
| GuardConfig | `guard.py` | Immutable config, all PRAMANIX_* env var bindings |
| Policy | `policy.py` | DSL base class, field discovery, compile-time validation |
| Field | `expressions.py` | Name + python_type + z3_type descriptor |
| E() | `expressions.py` | Expression builder, lazy AST nodes |
| ConstraintExpr | `expressions.py` | Boolean composition (AND, OR, NOT) with .named() and .explain() |
| Transpiler | `transpiler.py` | DSL expression tree to Z3 AST; InvariantMeta caching |
| Solver | `solver.py` | Z3 wrapper, two-phase verification, timeout enforcement |
| Decision | `decision.py` | Immutable result, SHA-256 hash, factory methods |
| WorkerPool | `worker.py` | Async/process execution, HMAC sealing, warmup, recycling |
| PramanixSigner | `crypto.py` | Ed25519 signing over decision_hash |
| PramanixVerifier | `crypto.py` | Ed25519 signature verification |
| ExecutionToken | `execution_token.py` | HMAC-SHA256 single-use token binding decision to action |
| Translator | `translator/` | LLM extraction (OpenAI, Anthropic, Ollama, Redundant) |
| Primitives | `primitives/` | Pre-built constraints for finance, fintech, healthcare, infra, rbac, time, common |
| ResolverRegistry | `resolvers.py` | Async field resolver cache with thread-local isolation |
| MerkleAnchor | `audit/` | SHA-256 rolling hash chain + checkpoint tree |
| CLI | `cli.py` | `pramanix audit verify` offline verification subcommand |
| CircuitBreaker | `circuit_breaker.py` | Adaptive load shedding, four-state FSM |
| FastPath | `fast_path.py` | O(1) pre-Z3 screening, up to 5 rules |
| Decorator | `decorator.py` | `@guard` function wrapper |

---

## 5. Worker Lifecycle

```
Guard.__init__()
  │
  ▼
WorkerPool.spawn()
  │
  ├── Create ThreadPoolExecutor (async-thread)
  │   or ProcessPoolExecutor with spawn start method (async-process)
  │
  └── worker_warmup=True (default):
        Submit one dummy Z3 solve per worker slot
        - Creates z3.Context() private to the warmup call
        - Adds z3.Real("__warmup_x") >= z3.RealVal(0)
        - Calls solver.check()
        - Loads libz3 into OS page cache
        - Eliminates first-request JIT spike (50-200 ms without warmup)

  ▼
Worker steady state:
  Per-call z3.Context() creation
    ↓
  Transpile DSL → Z3 AST
    ↓
  Shared solver: solver.check() → SAT or UNSAT or UNKNOWN
    ↓  (only on UNSAT path)
  Per-invariant solvers: exactly one assert_and_track() each
    ↓
  del solver after every decision (prevents Z3 memory accumulation)

  ▼
Worker recycle (after max_decisions_per_worker = 10,000 decisions):
  Old executor → background daemon thread for clean shutdown
  New executor created on the main thread
  worker_warmup fires on new executor immediately
  Clients are never blocked during recycle

  ▼
Zombie prevention (H02):
  PPID watchdog daemon thread
  Checks os.getppid() every 5 seconds
  Parent process dead → child calls os._exit(0) immediately
  Prevents Z3 subprocesses from running indefinitely after host crash
```

---

## 6. Z3 Context Isolation

**Problem:** Z3's global context is shared by default across all threads. Two concurrent solve calls using the same context produce non-deterministic results and can corrupt each other's expression tables.

**Solution:** Every solver call creates its own `z3.Context()` instance.

```python
# What Pramanix does for every single solve
ctx = z3.Context()
s = z3.Solver(ctx=ctx)
s.set("timeout", timeout_ms)
# ... add constraints using this context only ...
result = s.check()
del s, ctx  # release immediately after use
```

- **No Z3 Context objects are shared across decisions.**
- **No Z3 Context objects cross the process boundary.** Only plain Python dicts are passed to workers.
- **In `async-process` mode**, the subprocess was spawned (not forked). Each subprocess starts with a fresh Python heap. Fork would silently inherit Z3's internal state and cause non-deterministic corruption under load.

---

## 7. TOCTOU Prevention -- ExecutionToken

**The problem (TOCTOU = Time-of-Check to Time-of-Use):**

```
t=0  Guard.verify(intent, state) → Decision(allowed=True)
t=1  [state changes in the database]
t=2  Executor acts on the Decision from t=0  <-- acting on stale verification
```

Or:

```
t=0  Attacker intercepts Decision(allowed=True) JSON
t=1  Attacker replays it to the executor without calling Guard.verify()
```

**The solution -- ExecutionToken:**

```
Guard.verify()
  │  returns Decision(allowed=True)
  ▼
ExecutionTokenSigner.mint(decision)
  - Embeds: decision_id, intent_dump, policy_hash, expires_at (now + TTL), token_id (16-byte nonce)
  - Signs: HMAC-SHA256(secret_key, canonical_token_body)
  - Default TTL: 30 seconds
  │
  ▼
ExecutionToken passed to executor
  │
  ▼
ExecutionTokenVerifier.consume(token)
  - Recompute HMAC and compare (constant-time)
  - Check expires_at > now
  - Check token_id NOT in consumed_set (single-use)
  - Add token_id to consumed_set
  - Returns True ONLY if all three checks pass
  │
  ▼
Execute action only if consume() returns True
```

- **Single-use:** `consume()` adds token_id to an in-memory set. The same token returns False on a second call, even with a valid signature.
- **Time-bounded:** Default TTL is 30 seconds. Tokens minted but not consumed within the window are automatically rejected.
- **Multi-process deployments:** Each process has its own consumed-set. Use `RedisExecutionTokenVerifier` (backed by Redis SETNX) for distributed single-use enforcement across multiple instances.
- **Thread-safe:** `consume()` uses a `threading.Lock` around the consumed-set mutation.

---

## 8. Phase 12 Hardening Fields (GuardConfig)

Five new fields were added to `GuardConfig` in Phase 12. All have `PRAMANIX_*` env var equivalents.

| Field | Default | Env Var | What it does |
|-------|---------|---------|-------------|
| `solver_rlimit` | `10_000_000` | `PRAMANIX_SOLVER_RLIMIT` | Z3 elementary operation cap per solve call. Prevents non-linear logic bombs that stay within the wall-clock timeout but consume excessive CPU. `0` disables. |
| `max_input_bytes` | `65_536` (64 KiB) | `PRAMANIX_MAX_INPUT_BYTES` | Serialized byte size cap on the combined intent + state payload. Rejects oversized requests before reaching Z3 at all. `0` disables. |
| `min_response_ms` | `0.0` | (no env var) | Minimum wall-clock time before `verify()` returns. Short decisions are padded to this floor, making timing side-channels statistically infeasible. `0.0` disables. |
| `redact_violations` | `False` | (no env var) | When `True`, BLOCK decisions replace `explanation` and `violated_invariants` with a generic message before returning to callers. The `decision_hash` is computed over the real fields before redaction, so the server-side audit log remains verifiable. |
| `expected_policy_hash` | `None` | (no env var) | SHA-256 fingerprint of the compiled policy. If set, `Guard.__init__` raises `ConfigurationError` if the running policy's fingerprint does not match. Prevents silent policy drift in distributed deployments where multiple instances may be running different policy versions. |

---

## 9. Key Design Decisions

| Decision | Why |
|----------|-----|
| Z3 SMT solver for verification | Produces a mathematical proof (SAT) or counterexample (UNSAT), not a confidence score |
| Fail-safe default (error → BLOCK) | Any bug in Pramanix itself produces a BLOCK, never a false ALLOW |
| Python DSL, not YAML or Rego | IDE autocomplete, mypy type checking, no parser to attack |
| `assert_and_track` per-invariant solver instances | Z3's `unsat_core()` returns a minimal subset, not all violated invariants. Per-invariant solvers guarantee exact attribution. |
| `model_dump()` before process boundary | Pydantic models are not safely picklable across process boundaries |
| Worker warmup with Z3 dummy solve | Eliminates 50-200 ms cold-start JIT spike on first request |
| `del solver` after every decision | Prevents Z3 reference-counting accumulation (RSS growth) |
| Spawn, not fork, for subprocesses | Fork silently inherits Z3 heap state and causes non-determinism under concurrent load |
| Alpine Linux banned | Z3's `libz3.so` is compiled against glibc. musl (Alpine) causes segfaults and 3-10x performance degradation |
| `Decimal → as_integer_ratio() → z3.RealVal` | Exact rational arithmetic. No IEEE 754 floating-point values ever reach Z3 |
| HMAC-SHA256 on IPC result | Prevents a malicious subprocess from returning a forged `allowed=True` via the IPC channel |
| Ephemeral HMAC key (`secrets.token_bytes(32)`) | Key rotates on every process start. Cannot be pickled or logged -- `__reduce__` raises `TypeError`. |

---

## 10. Phase 1 Critical Finding -- `unsat_core()` and Minimal Cores

**Gate PASSED: 2026-03-09**

**The finding:** Z3's `unsat_core()` returns a *minimal* unsatisfiable subset, not all violated invariants. When multiple invariants are independently violated, Z3 only needs one to prove UNSAT and may omit the others.

**Empirical demonstration:**
```python
# balance=50, amount=1000, frozen=True
# Both non_negative_balance AND account_not_frozen are violated.
# Shared-solver unsat_core() returned: ['non_negative_balance']  <-- incomplete
```

**The fix:** Use one `z3.Solver` instance per invariant. Each solver has exactly one `assert_and_track()` call. When that solver returns UNSAT, `unsat_core()` contains exactly `{label}` -- no ambiguity.

```
Fast-path optimization:
  Shared solver: checks overall SAT/UNSAT  ← runs on every call
                                              (single check, fast)
  Per-invariant solvers: identify which    ← runs ONLY on UNSAT path
                          invariants failed   (O(n) individual checks)
```

**Decimal arithmetic:**
- `Decimal("100.01").as_integer_ratio()` returns `(10001, 100)`
- `z3.RealVal(10001) / z3.RealVal(100)` is exact in Z3 -- no floating-point drift
- Floats first pass through `Decimal(str(v))` before `as_integer_ratio()`
- No IEEE 754 values ever reach Z3

---

## 11. Five-Layer Defence (Phase 4)

Applies when `translator_enabled=True` (NLP mode):

```
Layer 1 -- Compiled DSL unreachable from input
  The Policy DSL compiles to Z3 AST at Guard.__init__() time.
  No user input can modify, inject, or override the compiled policy.

Layer 2 -- Extraction-only prompt design
  LLM system prompt explicitly prohibits following embedded instructions.
  Responds with JSON only -- no prose or reasoning.

Layer 3 -- Pydantic strict schema validation
  Every extracted value validated against developer-supplied model.
  Numeric ranges, string lengths, type coercion enforced by Pydantic.

Layer 4 -- Blind ID resolution
  LLM never sees real account identifiers (UUIDs, account numbers).
  Only human-readable labels are provided; host resolves labels to IDs.

Layer 5 -- Dual-model consensus
  Two independent LLM instances called concurrently (asyncio.gather).
  Canonical JSON equality check (json.dumps sort_keys=True).
  Any character-level difference → ExtractionMismatchError → BLOCK.
```

Each layer is independent. Bypassing one does not bypass the others.

**Note on consensus strictness:** The `json.dumps(sort_keys=True)` equality check is deliberately byte-level strict. If one model returns `{"amount": "500.0"}` and the other returns `{"amount": "500.00"}`, they will fail consensus despite being semantically equivalent. This is intentional: Pramanix cannot know whether two extracted values are semantically equivalent in your domain without domain knowledge you haven't encoded. The strictness trades away a small number of false CONSENSUS_FAILURE results (which are safe -- they result in BLOCK) in exchange for a guarantee that any discrepancy between models -- including subtle injection-driven differences -- is always caught.

---

## 12. What Pramanix Does Not Solve

Understanding these boundaries is important for correct deployment in regulated environments.

**TOCTOU (Time-of-Check vs Time-of-Use):**
- Pramanix verifies state at the moment `verify()` is called, not at execution time.
- In concurrent systems, two requests can both pass verification against the same shared state, and both execute.
- Mitigation: use `ExecutionToken` (one-time-use HMAC token) to bind the ALLOW decision to a single execution attempt. This reduces the TOCTOU window but does not eliminate it if execution is not atomic at the application layer.

**Z3 encoding scope:**
- Z3 verifies that the submitted values satisfy your declared constraints.
- It does not verify that state was accurately fetched from your database.
- It does not verify that the intent dict matches what the executor will actually do.
- It does not verify that your invariants fully capture your safety requirements.
- Invariants should be reviewed by domain experts before deployment in regulated environments.

**Liveness and temporal properties:**
- Pramanix is a point-in-time safety check, not a temporal model checker.
- It cannot verify properties like "this account has never exceeded the daily limit across its entire history."
- It verifies: "the value of `cumulative_daily_amount` satisfies `<= daily_limit` right now."
- The accuracy of `cumulative_daily_amount` depends on your state loading logic, not on Pramanix.

**State accuracy:**
- The security guarantee is only as strong as the state source.
- If both intent and state arrive in the same untrusted request body, an attacker can inject matching values to pass Z3 checks.
- For full protection, load state from a trusted source independent of the user request. The Zero-Trust Identity layer (`JWTIdentityLinker` + `RedisStateLoader`) provides this guarantee.

**Z3 native crashes in sync and async-thread modes:**
- Python's `except Exception` cannot catch a Z3 C++ segfault (SIGABRT/SIGSEGV).
- In `async-process` mode, a worker process crash surfaces as a fail-safe BLOCK; the host process is unaffected.
- Use `async-process` in production for full process-level isolation.

**Cross-references:** [security.md](security.md) § Threat Model, [why_smt_wins.md](why_smt_wins.md) § Section 4.
