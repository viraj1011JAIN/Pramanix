# Design Decisions

**Pramanix 1.0.0** — Major design choices, the context in which they were made, and why the alternatives were rejected.

Each entry records the decision, the alternatives that were considered, and the reasons the current approach was chosen. These are not post-hoc rationalizations — they are the engineering constraints that ruled alternatives out.

---

## 1. Z3 SMT Solver as the verification engine

**Decision:** Use Z3 (Microsoft Research) as the formal verification engine for all policy invariants.

**Alternatives considered:**
- Rule-based engine (custom Python): Fast, but no formal completeness guarantee. A badly-written rule can silently pass or block incorrectly with no attribution.
- Open Policy Agent (OPA / Rego): Rego is Datalog-based, not SMT. It cannot prove invariants over arithmetic (e.g. `balance - amount >= min_reserve`) without custom extensions. Attribution of which rule failed requires introspection that OPA does not natively provide.
- Symbolic execution over Python bytecode: Requires a full interpreter model. Complexity is prohibitive and the failure modes are not well-understood.

**Why Z3:**
- SMT solvers provide a **completeness guarantee**: if Z3 says `sat`, every invariant holds for the given inputs. There is no false positive path.
- Attribution (`unsat_core()`) identifies exactly which invariants were violated, not just "something failed".
- Z3 handles real arithmetic (`z3.Real`) natively, which is required for financial invariants (`balance - amount >= 0`).
- Z3 is deterministic. Given the same formula and the same timeout, it produces the same answer. There is no ML non-determinism.
- Z3 releases the Python GIL during solver execution, enabling genuine parallelism in thread mode.

**Accepted costs:**
- Z3 binaries are glibc-linked; Alpine/musl is not supported without a custom build.
- Z3 can return `unknown` (timeout) rather than a definitive answer; this is handled as a BLOCK decision, not an allow.
- Z3 startup time is non-trivial; Guard construction pre-compiles the policy to minimize per-request overhead.

---

## 2. Fail-closed: Guard.verify() never raises

**Decision:** `Guard.verify()` catches all exceptions and returns `Decision.error(allowed=False)`. It never raises to the caller.

**Alternatives considered:**
- Propagate exceptions to the caller. Caller can decide whether to allow on error.

**Why fail-closed:**
- If verification infrastructure fails, the correct behavior is to block, not to allow. The alternative — allowing on error — means a targeted attack on the verification infrastructure can grant access.
- Callers do not need to write `try/except` around `Guard.verify()` to be safe. The system is safe by default.
- Audit trail completeness: even error decisions are emitted to audit sinks and signed. The caller always receives a serialisable `Decision` regardless of what went wrong internally.

**Invariant enforced in code:** `Decision.__post_init__` raises `ValueError` if `allowed=True` and `status != SAFE`. No error handler anywhere in `guard.py` returns `allowed=True`.

---

## 3. Two-phase Z3 verification (fast-sat then per-invariant attribution)

**Decision:** Run Phase 1 with all invariants in a single `z3.Solver` using `add()`. On `sat`, return immediately. On `unsat`, run Phase 2 with one `z3.Solver` per invariant using `assert_and_track`.

**Why not always use Phase 2:**
- `assert_and_track` + `unsat_core()` is noticeably slower than `add()` for the common case (all invariants hold). The majority of legitimate requests are `sat`. The slow path only triggers on violations.

**Why not use a single Phase 2 path:**
- `unsat_core()` on a single solver with multiple tracked assertions does not always return the minimal core — Z3's core extraction is heuristic. Using one solver per invariant guarantees that `unsat_core()` returns exactly `{label}`, so violation attribution is complete.

**Why not use `minimize-core` or other Z3 options:**
- More expensive and still heuristic for non-trivial formulas. One-solver-per-invariant is O(k) solves at Phase 2 but produces deterministic complete attribution.

---

## 4. Process isolation (async-process) for production Z3 execution

**Decision:** Production deployments should use `execution_mode="async-process"`. Worker processes use `ProcessPoolExecutor(mp_context=spawn)`.

**Why spawn, not fork:**
- `fork()` copies all parent file descriptors, memory-mapped files, and OS resources. Z3 has internal state (heap objects, file descriptors for its own logging). Forking after Z3 has initialized produces undefined behavior.
- `spawn` starts a clean process and re-imports the module. Z3 is initialized fresh in each worker.
- Windows does not support `fork` at all; `spawn` works cross-platform.

**Why process mode at all:**
- A Z3 internal assertion failure (SIGSEGV, SIGABRT) in thread mode kills the entire host process. In process mode, the crash kills only the worker process; the host process receives a `Decision.error()` and continues serving other requests.

**Accepted cost:**
- Process startup overhead (mitigated by worker warmup on Guard construction).
- Only `(policy_cls, values_dict, timeout_ms)` can cross the process boundary. No Z3 objects, no open file handles. Policy classes must be importable by their fully-qualified name (i.e., defined at module level, not inside a function).

---

## 5. No Z3 objects cross process boundaries

**Decision:** Workers receive only `(policy_cls, values_dict, timeout_ms)`. The Z3 formula is reconstructed inside the worker.

**Why:**
- Z3 contexts are thread-local C objects. They cannot be pickled. Attempting to serialize them would crash.
- Sharing Z3 state across processes via shared memory would require a custom Z3 build.

**Consequence:** Policy classes must be picklable by import reference. Lambdas or closures capturing non-picklable objects cannot be used as policy invariants.

---

## 6. contextvars for resolver registry (per-request context isolation)

**Decision:** `ResolverRegistry` uses `contextvars.ContextVar` to store the resolved-values cache.

**Alternatives considered:**
- `threading.local`: Thread-scoped. In asyncio (FastAPI/Uvicorn), multiple concurrent requests share one OS thread. `threading.local` would allow Task B to see Task A's resolved field values — a P0 data-bleed.
- Passing the cache through the call stack: Correct, but requires threading the cache object through every function signature in the call chain.

**Why contextvars:**
- `ContextVar` is Task-scoped under asyncio (each `asyncio.Task` gets a copy-on-write context snapshot). Under threading, it degrades gracefully to thread-scope.
- Guard calls `clear_cache()` in its `finally` block unconditionally. No resolved value survives across requests even if an exception occurs.

---

## 7. Dual-model LLM consensus (translator)

**Decision:** `extract_with_consensus()` calls two independent LLM translators concurrently, validates both against the intent schema, and raises `ExtractionMismatchError` if the extracted intents disagree.

**Alternatives considered:**
- Single-model extraction: Faster, cheaper, but subject to single-model hallucination or injection.
- Majority vote with 3+ models: Higher cost; diminishing returns vs two-model mutual validation.

**Why two models:**
- Two independent models must produce the same intent for the same input. A successful prompt injection attack would need to manipulate both models in the same direction simultaneously — a significantly harder attack than manipulating one.
- Disagreement is itself a signal: if two models extract different amounts from the same text, the text is ambiguous or adversarial. Blocking on disagreement is the correct behavior.

**Note:** This is a beta feature. It requires two LLM API credentials and adds latency proportional to the slower of the two models.

---

## 8. Fast path can only BLOCK, never ALLOW

**Decision:** `FastPathRule` callables return `str | None`. A `str` return blocks the request. `None` passes through to Z3. There is no fast-path mechanism to allow a request.

**Why:**
- The fast path is user-defined Python code. User code may have bugs. If the fast path could return `allowed=True`, a buggy rule could bypass Z3 entirely.
- Removing `allowed=True` from the fast path as a possibility makes the invariant simple: Z3 is the only path to `allowed=True`. This invariant can be checked statically (and it is — there is no code path in `fast_path.py` that produces an `allowed=True` Decision).

---

## 9. No eval / exec / ast.parse in the transpiler

**Decision:** The DSL is a Python expression tree of `ConstraintExpr` objects. The transpiler walks this tree structurally and emits Z3 AST nodes. No string compilation, no `eval`, no `exec`.

**Why:**
- `eval` of user-supplied strings is a remote code execution vector. Even internal use of `eval` creates an auditable surface.
- The DSL is a library of composable Python objects. There is no string phase. If a user can construct a `ConstraintExpr`, it is because they have called library functions with typed arguments — not because they passed a string that the library compiled.
- The transpiler is the only site where Z3 AST is constructed. This makes it auditable: the only way to reach Z3 is through the typed DSL.

---

## 10. Exact Decimal arithmetic for numeric invariants

**Decision:** Floating-point values in invariants are converted via `Decimal(str(v)).as_integer_ratio()` before being passed to Z3 as rational numbers (`z3.RatVal(numerator, denominator)`).

**Alternatives considered:**
- Pass Python `float` directly to Z3: Z3 would represent these as IEEE 754 floating-point. `0.1 + 0.2 != 0.3` in floating-point arithmetic. Financial invariants such as `balance - amount >= min_reserve` would have rounding errors that could cause a legitimate transaction to be blocked or an illegitimate one to pass.

**Why Decimal:**
- `Decimal(str(v)).as_integer_ratio()` produces an exact rational (numerator, denominator pair). Z3's `RatVal` represents this as exact rational arithmetic.
- Financial thresholds must be exact. `100.00 - 99.99 >= 0.01` must be provably true, not a floating-point approximation.

---

## 11. HMAC-SHA256 for execution tokens (not Ed25519)

**Decision:** `ExecutionToken` uses HMAC-SHA256 (`hashlib.blake2b` family, then verified via `hmac.compare_digest`) rather than Ed25519.

**Why HMAC:**
- Execution tokens are consumed by the same process that minted them (or by a shared-secret backend). There is no need for asymmetric verification. HMAC with a shared secret is sufficient.
- HMAC is faster than asymmetric cryptography for high-frequency token validation.
- Decision signing (Ed25519) is for offline verifiability by a third party — the audit trail must be verifiable by regulators with only the public key. Execution tokens are a runtime control; they are consumed and discarded. Offline verifiability is not required.

---

## 12. Alpine / musl rejection at import time

**Decision:** `_platform.py` globs `/lib/ld-musl-*.so.1` at `import pramanix.guard` time and raises `ConfigurationError` if found.

**Why at import time, not at Guard construction:**
- Z3 imports happen as a side effect of module loading. By the time `Guard()` is constructed, Z3 is already loaded and potentially already misbehaving on musl.
- Fail early: a `ConfigurationError` at import time is visible in container startup logs. A segfault 30 minutes into production load is much harder to attribute.

**Why not warn instead of raise:**
- Z3 segfaults on musl libc are not recoverable. A warning that is ignored leads to a production crash. A `ConfigurationError` requires the operator to either use a glibc image or explicitly set `PRAMANIX_SKIP_MUSL_CHECK=1` (accepting the risk in writing).

---

## 13. Structlog for all internal logging

**Decision:** All internal logging uses `structlog` with a secrets-redaction processor.

**Why structlog over stdlib `logging`:**
- Structured key-value output can be consumed by log aggregators (Splunk, Datadog, Loki) without regex parsing.
- The secrets-redaction processor runs before any renderer. Keys matching known-sensitive patterns (API keys, PEM data, HMAC secrets) are redacted to `"[REDACTED]"` before the log record reaches any handler, including stdout.
- Stdlib `logging` does not provide a structured, processor-based pipeline without additional wrapping.

---

## 14. Policy fingerprinting at Guard construction time

**Decision:** Guard computes a SHA-256 fingerprint of the policy's compiled invariants at construction time. If `GuardConfig.expected_policy_hash` is set and does not match, `ConfigurationError` is raised.

**Why:**
- In rolling deployments, it is possible for two replicas to be running different versions of the same policy class (e.g., during a deploy). This produces split-brain policy enforcement.
- The fingerprint check forces operators to explicitly acknowledge a policy change (by updating `expected_policy_hash`) rather than silently running a different policy version.
- The `policy_hash` field on every `Decision` provides a record of which policy version produced each decision. This is required for audit trail reconstruction.

---

## 15. HMAC-sealed IPC for async-process worker results

**Decision:** In `async-process` mode, each solve result is HMAC-SHA256 tagged with an ephemeral key (`_EphemeralKey`) before crossing the `multiprocessing.Queue` boundary. The host process verifies the tag before trusting the result.

**Alternatives considered:**
- Trust the `Decision` dict returned from the subprocess directly: A compromised or exploited worker process (e.g., via a malformed Z3 formula triggering a UAF) could forge `allowed=True` across the process boundary. No other defense exists at the `Queue` level.

**Why HMAC seal:**
- The `multiprocessing.Queue` does not provide integrity guarantees. A forged pickle payload from a compromised worker is indistinguishable from a legitimate one without an explicit MAC.
- The ephemeral key is generated once per `Guard` instance lifetime at construction time, stored only in the host process, and never serialized to disk (`_EphemeralKey.__reduce__` raises `TypeError`).
- The overhead is one HMAC-SHA256 per decision (microseconds). The security property is that forging `allowed=True` from a compromised worker requires knowledge of the ephemeral key, which is only accessible in the host process.

---

## 16. `issued_at=0` in signed decision payloads

**Decision:** The `iat` (issued-at) timestamp is not embedded in the JWS body of a `DecisionSigner.sign()` payload. `VerificationResult.issued_at` is always `0`.

**Why:**
- Including wall-clock time in the signed payload means two identical decisions signed at different moments produce different signatures. This breaks signature determinism: given the same `(decision, key)` pair, `sign()` must produce the same output.
- Signature determinism matters for test reproducibility and for detecting accidental re-signing.
- The timestamp is preserved in `SignedDecision.issued_at` outside the HMAC boundary — available for display but not part of the integrity guarantee.

---

## 17. `ConstraintExpr.__bool__` raises instead of returning a value

**Decision:** `ConstraintExpr.__bool__` raises `PolicyCompilationError` with a message explaining that `and`/`or` must be replaced with `&`/`|`.

**Alternatives considered:**
- Return `True` unconditionally: Silently makes every Python `and`/`or` expression appear valid. The combined constraint silently behaves as the left operand only.
- Return `False` unconditionally: Same problem; even worse behavior in policy logic.

**Why raise:**
- `bool(expr1) and bool(expr2)` short-circuits at Python level and discards one operand. The policy author intended `expr1 & expr2` (Z3 conjunction). These are not the same operation.
- This is a policy correctness bug that is invisible at runtime — the wrong constraint is compiled and wrong decisions are produced silently. Raising at compilation time surfaces the bug immediately.
- The cost is zero for correct policies. The DSL operators that produce `ConstraintExpr` values return `ConstraintExpr`, not `bool`. Only accidental use of `and`/`or` triggers this path.

---

## 18. Iterative Merkle root construction (replacing recursive)

**Decision:** `MerkleAnchor._build_root` uses an iterative `while len(level) > 1:` loop, not recursion.

**Why:**
- The recursive implementation hits Python's default call stack limit at approximately 1,000 decisions (log₂ of 1,000 ≈ 10 recursion levels, but the full hash tree is built pair-wise and each recursion is one level). For production audit logs with tens of thousands of decisions per batch, the recursion limit causes a `RecursionError`.
- The iterative version uses O(1) stack depth regardless of batch size. There is no functional difference in the output.

---

## 19. Timing pad applied to both ALLOW and BLOCK responses

**Decision:** `GuardConfig.min_response_ms` padding is applied to every `Guard.verify()` return, unconditionally, before the `allowed` branch.

**Alternatives considered:**
- Apply padding only to BLOCK responses: A caller that can distinguish ALLOW latency from BLOCK latency can binary-search which invariants are violated. This leaks a timing oracle that identifies the violated constraint even with `redact_violations=True`.

**Why unconditional:**
- Timing side-channel attacks require a measurable latency difference between outcomes. Unconditional padding makes ALLOW and BLOCK responses statistically indistinguishable at the network level (given sufficient padding budget).
- The same principle applies to the FastAPI middleware: `timing_budget_ms` is applied before the ALLOW/BLOCK response branch, not after.

---

## 20. `max_input_bytes` failure returns `Decision.error()` not propagates exception

**Decision:** When `max_input_bytes` is exceeded (or when the payload cannot be serialized to check size), `verify_async()` returns `Decision.error(allowed=False)` rather than propagating the exception.

**Context:** Prior to v1.0.0 (C-01 fix), `verify_async()` had a bare `except Exception: pass` in the size-check path. Unserializable payloads (circular references, custom objects) silently bypassed the size gate and continued to the Z3 solver.

**Why return `Decision.error()` rather than propagate:**
- Fail-closed consistency: all failure paths return `Decision.error(allowed=False)`. Propagating an exception from `verify_async()` would break the no-raise contract and require callers to add exception handling to be safe.
- The serialization failure is itself a signal that the input is malformed. Blocking is the correct outcome.
