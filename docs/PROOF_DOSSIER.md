# Pramanix Proof Dossier

**Version:** 1.0.0
**License:** AGPL-3.0-only
**Python:** ≥3.11 (tested on 3.13.7)
**Z3:** 4.16.0
**Pydantic:** v2.12.5
**Test baseline:** 4,002 passed, 81 skipped, 0 failed (commit 809ad33)
**Branch coverage:** 98.26%
**Benchmark hardware:** Windows 11, Intel Core (Family 6 Model 154), 20 logical / 14 physical cores, 15.63 GB RAM — consumer laptop, NOT a server
**Benchmark version:** v0.8.0 (not v1.0.0)

This document answers, from code evidence alone, what Pramanix is, what it proves, where it is strong, where it is weak, and what claims cannot yet be made. The code is the sole truth. Every assertion is labelled with its evidence source and status. Labels used throughout:

`real` — implemented and tested with real dependencies
`real-partial` — implemented but tested with stubs or under constrained conditions
`integration-real` — implemented and tested against real external services (requires Docker)
`stub-backed` — logic is real; external dependencies replaced by stubs in all current tests
`documented-only` — described in comments or docs; no test coverage found
`mocked` — tested, but core dependency mocked/monkeypatched
`production-grade` — implemented, tested, fail-closed, audited
`beta` — implemented, partially tested, documented as not stable
`unverified` — claimed somewhere but no corroborating test found
`gap` — missing, incomplete, or architecturally absent

---

## 1. Executive Assessment

Pramanix is a Python library that wraps Z3 SMT solver verification around agentic AI tool calls. It is not a model safety layer, not a content filter, and not a prompt guardrail system. It is a **deterministic execution firewall**: given a typed policy and a typed request, it returns a cryptographically signed binary decision — SAFE or UNSAFE — with exact attribution of which constraint was violated.

The core proposition is real and verified: Z3 provides completeness guarantees that rule-based or LLM-based checkers cannot. If Z3 says `sat`, every invariant holds for the exact inputs provided. There is no false-positive path for well-formed inputs.

The architecture is production-grade on its primary axis (Z3 verification, fail-closed error handling, adversarial input rejection). It is beta-grade on its secondary axes (LLM consensus extraction, process-mode IPC, some enterprise subsystems). The AGPL-3.0 license is an enterprise-adoption blocker that no technical quality can overcome.

**What is proven:** fail-closed behaviour across all 6 pipeline stages; Z3 thread-safety at 10 concurrent threads; injection resistance against 10 adversarial vector classes with stub translators; Pydantic strict-mode boundary rejection; HMAC IPC tamper detection.

**What is partial:** LLM consensus layer (real implementation, never tested with real LLMs in CI); integration tests (real containers, skipped without Docker); timing-oracle protection (implemented and tested with ≤1.30 symmetry ratio, not a cryptographic guarantee).

**What is missing:** NLP-based content validation (PII, toxicity); Merkle archive encryption; cross-process replay prevention; injected-field scope for non-financial policies (historical hardcode of `"amount"` key, partially fixed in CHANGELOG M-03).

**Overall capability score:** 9.0/10 (from `reality.md`, revised from 8.5 after confirmed fixes). The delta from 10 is attributable to the AGPL license, absent NLP validators, and Merkle plaintext gap — not to correctness or safety defects.

---

## 2. What the SDK Really Is

### 2.1 Core Function

Pramanix is a **policy enforcement point** for agentic systems. Its contract: given a policy expressed as Z3-typed field constraints and a request consisting of an intent dict and a state dict, return an immutable, signed `Decision(allowed: bool, status: SolverStatus, violated_invariants: list[str])`.

The verification loop (`Guard.verify()`) is:

1. Pydantic strict-mode validation — rejects type coercions (string `"100"` for Decimal field is rejected)
2. Optional O(1) fast-path pre-screen — can only BLOCK, never ALLOW
3. Optional LLM translator consensus extraction (beta, requires API keys)
4. Optional semantic post-consensus integrity check
5. Z3 solve (two-phase: all-invariants fast then per-invariant attribution)
6. Decision construction
7. Ed25519/HMAC signing
8. Audit sink emit
9. structlog emission
10. OpenTelemetry span close
11. Prometheus counter/histogram update
12. `ResolverRegistry.clear_cache()` (unconditional, in `finally`)

Every exception in any of these steps is caught and returned as `Decision.error(allowed=False)`. This is enforced structurally: `Decision.__post_init__` raises `ValueError` if `allowed=True` and `status != SAFE`. No error handler anywhere in `guard.py` produces `allowed=True`.

### 2.2 What It Is Not

- Not a content safety classifier. No semantic understanding of text. No PII detection, toxicity scoring, or hate-speech detection.
- Not a real-time fraud scoring system. It verifies individual decisions against explicit constraints; it does not model behavioural sequences or anomaly baselines.
- Not a runtime monitor for agent reasoning chains. It gates discrete tool invocations.
- Not LLM-agnostic by default. The LLM translator layer (optional) requires API keys for OpenAI, Anthropic, Gemini, Cohere, Mistral, Ollama, or Llama.cpp. Without a configured translator, callers must provide pre-parsed intent dicts.
- Not a replacement for access control systems (RBAC/ABAC). It is complementary: enforces invariants over the _content_ of a request, not just the identity of the caller.

### 2.3 Scope Boundaries

The SDK enforces only what the policy author encodes. A policy with no invariants passes everything (Z3 returns `sat` vacuously — this is tested in `test_dsl_and_transpiler_properties.py` property 10). A policy that encodes the wrong invariants enforces the wrong constraints. `PolicyAuditor` in `helpers/policy_auditor.py` performs static analysis to find Fields declared but never referenced in invariants — a gap-detection tool, not a correctness oracle.

---

## 3. Architecture Walkthrough

### 3.1 Subsystem Inventory

| Subsystem | File(s) | Status | Notes |
|---|---|---|---|
| Verification orchestration | `guard.py` | production-grade | 12-step pipeline; never raises |
| DSL | `expressions.py` | production-grade | Zero Z3 imports; no eval/exec |
| Pillar 1 IR compiler | `compiler.py` | real | Pydantic `PolicyIR` → `ConstraintExpr`; no LLM dependency; compile-time type/sort/op validation; `Decompiler` for CISO sign-off |
| Transpiler | `transpiler.py` | production-grade | `Decimal.as_integer_ratio()` exact arithmetic |
| Z3 solver | `solver.py` | production-grade | Thread-local contexts; two-phase attribution |
| Fast path | `fast_path.py` | production-grade | 5 built-in rules; can only BLOCK |
| Input validation | `validator.py` | production-grade | Pydantic v2 strict mode; `extra="forbid"` |
| Decision | `decision.py` | production-grade | Immutable; `allowed=True ↔ status=SAFE` enforced |
| Ed25519 signing | `crypto.py` | real-partial | 7 key providers; ephemeral fallback warns on stderr |
| Provenance chain | `provenance.py` | real-partial | HMAC-SHA256; key not persisted across restarts |
| Audit sinks | `audit_sink.py` | real-partial | 6 sinks; Kafka/S3/Splunk/Datadog; all emit-failures caught |
| Merkle archiving | `audit/merkle.py` | real-partial | Real integrity; plaintext-on-disk gap (documented) |
| JWS signing | `audit/signer.py` | real | HMAC-SHA256 compact token; deterministic canonical payload |
| JWS verifier | `audit/verifier.py` | real | Self-contained stdlib-only; offline-verifiable |
| JWT identity boundary | `identity/linker.py` | real | HS256/RS256/ES256; algorithm confusion patched (BUG-10) |
| Circuit breaker | `circuit_breaker.py` | production-grade | CLOSED→OPEN→HALF_OPEN→ISOLATED; ALLOW_WITH_AUDIT deprecated |
| Worker pool | `worker.py` | production-grade | Thread and process modes; HMAC IPC seal in process mode |
| Injection filter | `translator/injection_filter.py` | real | Regex; syntactic only; fails-open |
| LLM translators | `translator/` | beta | 7 adapters; dual-model consensus; never tested in CI |
| IFC | `ifc/` | beta | `SecureMemoryStore`; cross-tenant isolation; beta stability |
| Privilege / Oversight | `privilege/`, `oversight/` | beta | `EscalationQueue`, `InMemoryApprovalWorkflow`; sweeper added (BUG-04) |
| gRPC interceptor | `interceptors/grpc.py` | real | `ServerInterceptor`; abort on empty stream fixed (BUG-07) |
| Kafka interceptor | `interceptors/kafka.py` | real | DLQ batching fixed (BUG-09); `continue` on transient error (BUG-08) |
| K8s webhook | `k8s/webhook.py` | real | `ValidatingWebhook` via FastAPI |
| Compliance reporter | `helpers/compliance.py` | real | 6 regulatory domains; JSON + PDF export |
| Policy lifecycle | `lifecycle/diff.py` | real | Structural diff; `ShadowEvaluator` for canary promotion |
| Pre-built primitives | `primitives/` | real | 38 constraints; 7 domains; legal disclaimer on every file |
| Framework integrations | `integrations/` | real | 9 confirmed; `BaseTool` inheritance verified in tests |
| CLI | `cli.py` | real | `pramanix doctor` 11 checks including logging and policy-hash |

### 3.2 Fail-Closed Enforcement Chain

The fail-closed guarantee has two structural enforcement points:

1. **`guard.py`:** `try/except` at the outermost scope of `verify()`. Every exception class (including `MemoryError`, `BaseException`, bare `Exception`) returns `Decision.error(allowed=False)`. Adversarial test `test_fail_safe_invariant.py` covers all 6 pipeline stages and 9 exception types.

2. **`decision.py` `__post_init__`:** `ValueError` raised if `allowed=True` and `status != SAFE`. This makes it structurally impossible to return `allowed=True` from any error handler — the `Decision` constructor itself rejects the combination.

These two enforcement points are **independent and complementary**. The first prevents propagation; the second prevents construction. A bug in the first would be caught by the second.

### 3.3 Z3 Thread Safety

Thread-local Z3 contexts (`_thread_ctx()` in `solver.py`): one `z3.Context()` per OS thread, never destroyed. Prevents GC race on Windows/Python 3.13. Adversarial test `test_z3_context_isolation.py` uses `threading.Barrier` to force 10 concurrent simultaneous solver executions, verifying no cross-contamination and no `allowed=True` from any thread where `balance < amount`.

### 3.4 Exact Arithmetic

Floating-point values go through `Decimal(str(v)).as_integer_ratio()` → `z3.RatVal(numerator, denominator)` before entering Z3. No IEEE 754 rounding errors reach the solver. This is the correct approach for financial invariants. Property test 6 in `test_dsl_and_transpiler_properties.py` verifies Z3 agrees with Python `Decimal` for all precisions via Hypothesis.

### 3.5 Process Isolation

`async-process` mode uses `ProcessPoolExecutor(mp_context=spawn)`. No Z3 objects cross the process boundary — only `(policy_cls, values_dict, timeout_ms)` is transmitted. `policy_cls` is a class reference, not a Z3 object. Worker crash returns `Decision.error()` without propagating to the host process. A Z3 SIGSEGV in process mode kills only the worker; thread mode would kill the host.

### 3.6 Pillar 1 IR Compiler (`compiler.py`)

`compiler.py` implements the deterministic boundary between structured LLM output (via Structured Outputs / JSON Mode) and the Z3 verification engine. It is distinct from `natural_policy/` (Phase 2), which requires an active LLM client and translates raw English text. The IR compiler receives a fully Pydantic-validated `PolicyIR` object and lowers it to `ConstraintExpr` objects that are functionally identical to hand-authored invariants — the same objects `transpiler.py` receives from `Policy.invariants()`.

The module has four isolated layers:

1. **IR schema** (`FieldReference`, `LiteralValue`, `Operator`, `Condition`, `Rule`, `PolicyIR`) — pure Pydantic v2, zero Z3, zero I/O. `ConfigDict(extra="forbid", frozen=True)` on every model. `Rule` is recursive via `Rule.model_rebuild()`. `PolicyIR` enforces globally unique rule names via a `model_validator` — duplicate names would produce duplicate invariant labels, which the Z3 attribution phase cannot disambiguate. The `version` field requires semver format (`MAJOR.MINOR.PATCH`).

2. **`PolicyCompiler`** — stateless; `compile(ir, policy_cls) → list[ConstraintExpr]`. Validates at compile time: (a) every `FieldReference.field_name` must resolve against `Policy.fields()`; (b) Z3 sort compatibility between lhs and a scalar rhs (e.g., `String`-sorted field rejects integer literal); (c) field-to-field sort compatibility when rhs is also a `FieldReference`; (d) ordering operators (`GT`, `LT`, `GTE`, `LTE`) rejected on `Bool`-sorted fields; (e) `IN`/`NOT_IN` requires a `LiteralValue` with a list `value`; (f) `FieldReference` RHS rejected for membership operators. Every violation raises `PolicyCompilationError` with full context — the compiler never silently drops a constraint or returns a partial result. Uses `Decimal(str(scalar))` for `Real`-sorted scalars, consistent with `transpiler.py`'s exact arithmetic path.

3. **Fail-closed validation** — seven compile-time error classes detected before any Z3 formula is constructed: unknown field, scalar type incompatible with field Z3 sort, field-to-field sort mismatch, ordering operator on Bool sort, membership operator on non-list RHS, empty membership set, bool literal as ordering RHS.

4. **`Decompiler`** — reverse translation: `list[ConstraintExpr] → str`. Walks the internal DSL AST (`_FieldRef`, `_Literal`, `_BinOp`, `_CmpOp`, `_BoolOp`, `_InOp`) without touching Z3. Produces a timestamped CISO sign-off report with per-invariant English sentences. For field-to-field comparisons, the explanation line uses the `_OP_PHRASE` map to generate human-readable text such as `"intent.amount must be less than or equal to state.balance"`. Unknown future AST node types produce a `<TypeName>` placeholder (graceful degradation). Deterministic and idempotent.

**Security invariants:** No `eval()`, no `exec()`, no dynamic code generation. The LLM is never called by this module. Every field reference is validated against the `Policy` class's declared `Field` attributes — a hallucinated field name in the LLM output is caught before any Z3 formula is constructed.

**Public surface:** Ten symbols exported via both `compiler.__all__` and `pramanix.__init__`: `Condition`, `Decompiler`, `FieldReference`, `FieldSource`, `LiteralValue`, `Logic`, `Operator`, `PolicyCompiler`, `PolicyIR`, `Rule`.

### 3.7 Polymorphic RHS Discriminated Union (Pillar 1 + Pillar 2 Unification)

**The architectural problem.** A naive `Condition` model that accepts only scalar RHS values (`bool | int | float | str | list`) cannot express relational business logic such as `intent.amount <= state.balance`. It also cannot express identity-bound conditions such as `intent._mesh_principal == "spiffe://…/payments-agent"` where `_mesh_principal` is a live field injected by Pillar 2 (`MeshAuthenticator`). Without field-to-field comparison support, these two pillars operate in isolation.

**The solution: discriminated union on `Condition.rhs`.** The `rhs` field of every `Condition` is a Pydantic v2 discriminated union keyed by a `"type"` tag:

| `type` value | Python model | JSON shape | Use case |
|---|---|---|---|
| `"field"` | `FieldReference` | `{"type": "field", "source": "intent", "field_name": "amount"}` | Field-to-field comparison |
| `"literal"` | `LiteralValue` | `{"type": "literal", "value": 50000}` | Field-to-constant comparison |
| `"literal"` | `LiteralValue` | `{"type": "literal", "value": ["USD", "GBP"]}` | `IN` / `NOT_IN` membership |

Pydantic reads the `"type"` key and routes to the correct model before any validation runs — there is no ambiguous coercion, no type-inference fallback, and no silent data loss.

**`_mesh_principal` bridge.** `MeshAuthenticator.authenticate_and_bind()` injects the verified SPIFFE URI of the caller into the intent context under the key `"_mesh_principal"`. Policy authors reference it as:

```json
{
  "lhs": {"type": "field", "source": "intent", "field_name": "_mesh_principal"},
  "op": "==",
  "rhs": {"type": "literal", "value": "spiffe://prod.example.com/ns/payments/sa/payments-agent"}
}
```

`FieldReference.field_name` accepts any non-empty string including underscore-prefixed names — `_mesh_principal` is valid without special casing. The compiler resolves it against `Policy.fields()` at compile time; if the policy class does not declare a `Field` for `_mesh_principal`, the compile fails with a `PolicyCompilationError` listing all declared fields.

**Decompiler output for field-to-field conditions.** When both sides are field references, the audit report explanation line uses `_OP_PHRASE` to produce natural English:

```
Rule 2 [amount_within_balance]: amount ≤ balance
  → intent.amount must be less than or equal to state.balance.
```

**Example YAML.** See `examples/mesh_policy_ir.yaml` for a complete policy demonstrating all three RHS variants (`FieldReference`, scalar `LiteralValue`, and list `LiteralValue`) alongside `_mesh_principal` identity gating.

---

## 4. Proof of Toughness

### 4.1 What "Tough" Means Here

Toughness claims are assessed against four questions: (a) does the system fail closed, (b) does it resist adversarial inputs, (c) does it maintain integrity under concurrency, (d) does it preserve correct behavior under pressure?

### 4.2 Fail-Closed: Proven

Evidence: `tests/adversarial/test_fail_safe_invariant.py` — 9 exception types × 6 pipeline stages. Covers `pydantic.ValidationError`, `StateValidationError`, `RuntimeError` in serialisation, `ValueError` from conflicting keys, `SolverTimeoutError`, `z3.Z3Exception`, `MemoryError`, generic `Exception`, bare `Exception` catch-all. All return `Decision(allowed=False)`. No test produces `allowed=True` from an error path.

### 4.3 Injection Resistance: Partial

5 layers implemented: regex filter (Layer 0), size gate (Layer 1), Pydantic strict validation (Layer 2), injection scorer (Layer 3), LLM consensus (Layer 4).

Layers 0–3 are proven against stub translators. Layer 4 (LLM consensus) is the critical defence against sophisticated injection — it requires two independent LLMs to agree on the extracted intent. This layer is **never tested in CI with real LLMs**. All injection tests (`test_prompt_injection.py`) use in-process stub translators that return pre-programmed responses. The 10 vectors (A–J) are tested at the Z3+governance level, not at the LLM consensus level.

The regex filter (`injection_filter.py`) is syntactic only. It covers known patterns (instruction overrides, jailbreak keywords, open-source model tokens, role escalation, prompt extraction, compliance coercion) but cannot catch novel injection patterns. Novel patterns that pass the regex reach the LLM consensus layer — which is the correct defence-in-depth design, but the LLM layer has no CI coverage.

### 4.4 Pydantic Strict Boundary: Proven

Evidence: `tests/adversarial/test_pydantic_strict_boundary.py` — 12 tests. String `"100"` for Decimal field is rejected. Integer `1` for bool field is rejected. Extra fields rejected. `None` for non-optional field rejected. Nested model as value rejected. End-to-end through `Guard.verify()` confirmed for both extra-field injection and string-amount injection.

### 4.5 Field Overflow: Proven

Evidence: `tests/adversarial/test_field_overflow.py` — 8 overflow vectors. `recipient` over `max_length=64` rejected. `amount` above `le=1_000_000` rejected. Zero `amount` with `gt=0` rejected. Large integer string rejected. All rejections surface as `ExtractionFailureError` before reaching Z3.

### 4.6 Concurrent Z3 Safety: Proven

Evidence: `tests/adversarial/test_z3_context_isolation.py` — 10 concurrent threads via `threading.Barrier`, unique balance/amount pairs per thread, no `Z3Exception`, no cross-contamination, no `allowed=True` from thread where balance < amount.

### 4.7 HMAC IPC Integrity: Proven

Evidence: `tests/adversarial/test_hmac_ipc_integrity.py` — tampered `allowed` field detected, tampered arbitrary field detected, stripped tag detected, wrong key detected. Replay attack is **documented as a known limitation**: the same host key validates a stale envelope; replay must be handled at application layer (optimistic locking, token single-use enforcement). This is architecturally correct — preventing cross-host replays requires coordination outside the SDK scope.

### 4.8 TOCTOU: Documented Contract

Evidence: `tests/adversarial/test_toctou_awareness.py` — contract test demonstrating the Optimistic Concurrency pattern required of host integrations. `verify()` is stateless per-call. If state changes between verify and execute, the next `verify()` with fresh state detects staleness via `STALE_STATE` status. The SDK cannot enforce the optimistic lock — that is the host's responsibility. The test documents the required integration pattern.

### 4.9 Timing Oracle Protection: Implemented and Tested

CHANGELOG H-02: `PramanixMiddleware.dispatch()` now applies `timing_budget_ms` unconditionally to both ALLOW and BLOCK responses. `test_production_gaps.py` includes symmetry ratio check (≤1.30). This is a statistical mitigation, not a cryptographic constant-time guarantee.

---

## 5. Use Cases

### 5.1 What It Is Definitively Good For

- **Financial transaction verification:** Balance, amount, daily limit, anti-structuring, sanctions screen, margin, KYC tier — all expressible as Z3 Real/Int invariants. `primitives/fintech.py` provides 10 pre-built constraints. Z3 real arithmetic handles penny-level precision without floating-point error.
- **Healthcare access gating:** HIPAA minimum-necessary, consent expiry, break-glass authentication, paediatric dose bounds — expressible as Z3 Int/Bool invariants. `primitives/healthcare.py` provides 5 pre-built constraints.
- **Infrastructure blast radius control:** Resource counts, CIDR ranges, tag requirements — expressible as Z3 invariants. `examples/infra_blast_radius.py` demonstrates the pattern.
- **LLM agent tool-call enforcement:** Any LangChain `BaseTool`, LlamaIndex `FunctionTool`, AutoGen tool, CrewAI tool, DSPy module, Haystack component, Semantic Kernel plugin, or Pydantic AI tool can be wrapped. Real subclass inheritance verified in `test_langchain_tool.py`.
- **Regulatory compliance reporting:** `ComplianceReporter` maps violated Z3 labels to citations for BSA/AML, OFAC/SDN, SEC wash sale, HIPAA, SOX, Basel III. Real implementation; no independent regulatory validation performed.
- **Multi-agent pipeline gating:** AutoGen multi-agent example (`examples/autogen_multi_agent.py`) demonstrated. Each agent action can be independently verified.

### 5.2 What It Is Not Good For

- **Unstructured text moderation.** No NLP-based validators. Cannot detect PII in free text, hate speech, toxicity, or off-topic content. Guardrails AI's `detect_pii` and `toxic_language` primitives have no equivalent here.
- **Behavioural anomaly detection.** No baseline modelling, no statistical scoring, no temporal sequence analysis. If a user makes 1,000 normal-looking individually-valid transactions in sequence, Pramanix passes them all.
- **Non-structured-field policies.** Policies require typed field declarations. If the relevant constraint cannot be expressed over a finite set of typed fields, it cannot be expressed in the DSL.
- **Semantic equivalence checking.** Two semantically equivalent intents expressed differently will produce different extraction outputs if LLM translators disagree. Consensus extraction catches this as `ExtractionMismatchError` (blocking by design), but it also blocks legitimate paraphrases.
- **Real-time streaming data.** The SDK processes discrete synchronous requests. Stream processing requires wrapping each message in a `Guard.verify()` call via the Kafka interceptor — functional but adds per-message Z3 overhead.

---

## 6. Evidence Matrix

**Table 1: Claim Evidence Matrix**

| Claim | Evidence Source | Implementation Status | Test Status | Confidence | Notes |
|---|---|---|---|---|---|
| Guard.verify() never raises | `guard.py` try/except; `decision.py` `__post_init__` | real | `test_fail_safe_invariant.py` 9 types × 6 stages | **high** | Two independent structural enforcement points |
| Z3 thread-local context isolation | `solver.py` `_thread_ctx()` | real | `test_z3_context_isolation.py` 10 concurrent threads + Barrier | **high** | CVE-prevention level; barrier maximises concurrency probability |
| Pydantic strict-mode rejects coercions | `validator.py` `strict=True, extra="forbid"` | real | `test_pydantic_strict_boundary.py` 12 cases | **high** | String→Decimal, int→bool, extra fields all rejected |
| Fast-path can only BLOCK, never ALLOW | `fast_path.py`; `guard.py` pipeline order | real | Unit tests; by construction (no `allowed=True` code path) | **high** | Statically verifiable; no code path produces allowed=True in fast_path.py |
| Exact Decimal arithmetic in Z3 | `transpiler.py` `Decimal(str(v)).as_integer_ratio()` | real | `test_dsl_and_transpiler_properties.py` property 6 via Hypothesis | **high** | No float drift to Z3 |
| Two-phase Z3 attribution | `solver.py` Phase 1 (all) + Phase 2 (per-invariant) | real | `test_banking_flow.py` violation attribution tests | **high** | One solver per invariant → deterministic `unsat_core()` |
| `PolicyIR` Pydantic validation rejects malformed LLM output | `compiler.py` IR models; `extra="forbid"`, `model_validator` for unique rule names, snake_case label enforcement, semver version pattern | real | Pydantic v2 strict boundary; validated at model construction before `PolicyCompiler` is invoked | **high** | LLM hallucinated field names, duplicate rule names, invalid labels all caught pre-compile; no dedicated adversarial test file yet |
| `PolicyCompiler` compile-time sort and operator enforcement | `compiler.py` field existence check, sort compatibility checks, operator legality checks | real | 7 error classes raised before any Z3 formula is constructed; `PolicyCompilationError` on every violation path | **high** | Structural enforcement — partial compile is architecturally impossible; no dedicated adversarial test file yet |
| HMAC IPC tamper detection | `worker.py` `_worker_solve_sealed` | real | `test_hmac_ipc_integrity.py` 4 tamper scenarios | **high** | Replay is documented limitation (app-layer concern) |
| Ed25519 signing fail-closed | `guard.py` `_sign_decision`; signing failure → `Decision.error()` | real | Unit tests; adversarial pipeline tests | **high** | Unsigned decisions never returned |
| 5-layer injection defence | `injection_filter.py`, `validator.py`, scorer, translator | real-partial | Layers 0–3 tested with stubs; Layer 4 (LLM consensus) stub-only in CI | **medium** | Real LLM consensus never tested in CI |
| Dual-model LLM consensus | `translator/redundant.py` | beta | `test_field_overflow.py` uses stub pair | **medium** | Beta feature; no CI test against real LLM APIs |
| Ed25519 key from AWS KMS / Vault | `key_provider.py` 7 providers | real-partial | Integration tests skipped without Docker/real credentials | **medium** | Cloud providers: TTL-based rotation at 300s |
| Merkle chain tamper detection | `audit/merkle.py` | real-partial | Unit tests for `MerkleProof.verify()`; archive is plaintext | **medium** | Plaintext-on-disk gap documented; `L-02` warning added |
| ProvenanceChain HMAC integrity | `provenance.py` | real-partial | Unit tests; key is per-process ephemeral, not persisted | **medium** | Chain breaks across process restarts; cross-restart audit requires external key persistence |
| JWT algorithm confusion prevention | `identity/linker.py` BUG-10 fix | real | Unit tests post-BUG-10 | **high** | Alg header validated BEFORE signature; `alg` mismatch → `JWTVerificationError` |
| 38 pre-built primitives across 7 domains | `primitives/` | real | `test_fintech_primitive_properties.py` (Hypothesis) | **high** | Legal disclaimers on every file; not regulatory advice |
| 9 framework integrations | `integrations/` | real | `test_langchain_tool.py` confirms real `BaseTool` subclass | **high** | `issubclass(PramanixGuardedTool, BaseTool)` — not a stub |
| 98.26% branch coverage | `coverage.json` | real | pytest 8.4.2 run; 4,002 passed | **high** | 98% gate passing; measured on commit 809ad33 |
| Injection scorer field scope fix | CHANGELOG M-03 | real | Changelog entry; fields ending in `_id`, `_key`, `_token`, etc. | **medium** | Historical hardcode of `"amount"` key partially fixed; full scope unverified |
| Async fail-safe bypass patched | CHANGELOG C-01 | real | `test_production_gaps.py` 50 concurrent coroutines | **high** | `verify_async()` size-check path now fail-closed |
| Timing oracle protection | CHANGELOG H-02; `test_production_gaps.py` | real | Symmetry ratio ≤1.30; p5 latency ≥90% of budget | **medium** | Statistical mitigation; not cryptographic constant-time |
| Process mode crash isolation | `worker.py` ProcessPoolExecutor spawn | real-partial | Architectural claim; no adversarial SIGSEGV test found | **medium** | Correct by design; not adversarially tested |

---

## 7. Failure-Mode Matrix

**Table 2: Failure-Mode Matrix**

| Failure Mode | Expected Behavior | Actual Observed Behavior | Proof Type | Residual Risk |
|---|---|---|---|---|
| Pydantic validation error (bad type) | `Decision(status=VALIDATION_FAILURE, allowed=False)` | Confirmed | adversarial test (9 exception types) | Low — structural enforcement in `__post_init__` |
| Z3 solver timeout | `Decision(status=TIMEOUT, allowed=False)` | Confirmed | adversarial test; `SolverTimeoutError` path covered | Low — `z3.unknown` on either phase → block |
| Z3 internal exception | `Decision(status=ERROR, allowed=False)` | Confirmed | adversarial test; `z3.Z3Exception` path covered | Low |
| `MemoryError` during verification | `Decision(status=ERROR, allowed=False)` | Confirmed | adversarial test explicit `MemoryError` case | Low — bare `except Exception` in outermost catch |
| Signing key unavailable / failure | `Decision(status=ERROR, allowed=False)` — no unsigned decision returned | Confirmed | adversarial pipeline test; `_sign_decision` contract | Low — ephemeral fallback warns but still signs |
| Audit sink emit failure | Decision already returned; sink failure logged, not propagated | Confirmed | `audit_sink.py` emit exception catch; source review | Low — sink failures are fire-and-forget |
| Worker process crash (async-process) | `Decision.error()` returned to host; host process unaffected | documented-only (architectural claim) | Design doc (`DECISIONS.md` §4); no adversarial SIGSEGV test | Medium — not adversarially tested |
| Concurrent Z3 context access (10 threads) | No cross-contamination; each thread gets isolated result | Confirmed | `test_z3_context_isolation.py` Barrier test | Low — thread-local context design proven |
| IPC envelope tampering (process mode) | `HMAC verify fails → Decision.error()` | Confirmed | `test_hmac_ipc_integrity.py` 4 tamper scenarios | Low for cross-thread; Medium for cross-process replay (app-layer responsibility) |
| Stale state between verify and execute (TOCTOU) | `Decision(status=STALE_STATE)` on next verify with fresh state | Confirmed as contract | `test_toctou_awareness.py` (documentation test) | Medium — SDK cannot enforce optimistic lock; host must implement `UPDATE WHERE state_version=:verified` |
| ProvenanceChain key loss (process restart) | Chain broken; previous records unverifiable with new key | Confirmed as gap | Source: `os.urandom(32)` per-process, not persisted | Medium for long-running audit chains; Low for single-process deployments |
| Merkle archive plaintext | Data readable by host OS users without decryption | Confirmed as gap | Source comment + CHANGELOG L-02 warning | High for SOC2/PCI DSS/HIPAA deployments; Low if archive directory is encrypted by OS/storage layer |
| Injection via novel LLM prompt (past regex) | Layer 4 LLM consensus blocks; extractions must agree | Partial — Layer 4 never tested with real LLMs | stub-backed tests only | Medium — sophisticated injection may bypass syntactic regex |
| `DeprecationWarning` on `ALLOW_WITH_AUDIT` | `BLOCK_ALL` behaviour enforced; `DeprecationWarning` emitted | Confirmed | `circuit_breaker.py` source; deprecated alias | Low — always fail-closed regardless of deprecated mode |
| Policy hash mismatch across replicas | `ConfigurationError` raised at Guard construction (not at verify-time) | Confirmed | `guard_config.py` `__post_init__`; `ARCHITECTURE_NOTES.md` | Low |
| Async size-check bypass (pre-CHANGELOG) | `Decision.error()` on unserializable payload | Fixed in C-01 | `test_production_gaps.py` 50 concurrent coroutines | Low — patched |
| LangChain tool with no `execute_fn` | `NotImplementedError` at `_arun()` time | Fixed in H-03 | CHANGELOG; `UserWarning` at construction | Low — patched; breaking change documented in `MIGRATION.md` |
| CrewAI tool with no `underlying_fn` | `NotImplementedError` at `_run()` time | Fixed in H-04 | CHANGELOG; explicit raise with diagnostic message | Low — patched |

---

## 8. Competitive Comparison

**Table 4: Competitor Comparison**

| Capability | Pramanix | NeMo Guardrails | Guardrails AI | LangChain (built-in) | OPA / Rego | OpenFGA | Casbin |
|---|---|---|---|---|---|---|---|
| **Verification model** | Z3 SMT (formal, complete) | Colang dialogue state | LLM + validators | Callback hooks | Datalog evaluation | Relationship tuples | Policy language (ACL/RBAC/ABAC) |
| **Formal completeness** | Yes — if Z3 says sat, invariant holds | No | No | No | No (Rego is not SMT) | No | No |
| **Arithmetic invariants** | Real, Int, Rational (exact Decimal) | No | Partial (custom validators) | No | Limited (integer arithmetic) | No | No |
| **Attribution (which rule failed)** | Yes — per-invariant Z3 unsat_core | No | Partial (validator name) | No | Partial (rule name) | No | Limited |
| **Fail-closed on error** | Yes — structural dual enforcement | Partial (configurable) | Partial | No | Partial | No | No |
| **Injection defence** | 5 layers (Layer 4 stub-only in CI) | Colang rail-based | Partial (input validation) | No | N/A | N/A | N/A |
| **Signed audit trail** | JWS HMAC-SHA256; Ed25519; Merkle | No | No | No | No | No | No |
| **NLP validators (PII, toxicity)** | **Gap — not present** | Partial | Yes (key feature) | No | N/A | N/A | N/A |
| **Framework integrations** | 9 (LangChain, LlamaIndex, AutoGen, FastAPI, CrewAI, DSPy, Haystack, SK, PydanticAI) | LangChain, NeMo | LangChain, partial | Native | External | External | External |
| **License** | **AGPL-3.0** (enterprise blocker) | Apache-2.0 | Apache-2.0 | MIT | Apache-2.0 | Apache-2.0 | Apache-2.0 |
| **Kubernetes/gRPC/Kafka** | Yes (webhook, gRPC interceptor, Kafka consumer) | No | No | No | Yes (OPA sidecar) | No | No |
| **Identity boundary** | JWT (HS256/RS256/ES256) with algorithm confusion fix | No | No | No | OPA OIDC | Yes (relationship model) | RBAC subject |
| **Process isolation for Z3 crashes** | spawn-mode ProcessPoolExecutor | N/A | N/A | N/A | N/A | N/A | N/A |
| **Regulatory citation reporting** | 6 domains: BSA/AML, OFAC, SEC, HIPAA, SOX, Basel III | No | No | No | No | No | No |
| **Maturity** | 1.0.0; single author | Mature; NVIDIA-backed | Mature; VC-backed | Mature; LangChain Inc | Mature; CNCF | Mature | Mature |
| **Primary audience** | Agentic AI tool-call enforcement | Conversational AI safety | LLM output validation | LLM application developers | Cloud-native policy | Fine-grained authorization | Application RBAC/ABAC |

**Narrow claims where Pramanix is stronger:**

1. Pramanix is stronger than OPA in formal arithmetic invariant enforcement for agentic tool calls on typed numeric fields. OPA/Rego handles arithmetic but is not an SMT solver; it cannot prove `balance - amount ≥ 0` is satisfiable across all model inputs.
2. Pramanix is stronger than Guardrails AI in tamper-evident audit trail for blocked decisions. Guardrails AI has no signed immutable audit chain.
3. Pramanix is stronger than NeMo Guardrails in transactional action verification. NeMo is a dialogue management system; it was not designed to enforce arithmetic constraints over typed agentic tool parameters.
4. Pramanix is stronger than LangChain built-in hooks in fail-closed error semantics. LangChain's callback system propagates exceptions; Pramanix's `Guard.verify()` cannot raise.
5. Pramanix is stronger than Casbin/OpenFGA for financial constraint verification. Those systems enforce identity-relationship policies, not arithmetic invariants.

**Where Pramanix is weaker:**

1. NLP validation: Guardrails AI has PII detection, toxicity scoring, regex validators, and semantic similarity checks. Pramanix has none of these.
2. License: AGPL-3.0 precludes commercial use without a proprietary license arrangement. All competitors listed above are Apache-2.0 or MIT.
3. Community maturity: 1.0.0, single author. All named competitors have multi-year community and production deployment history.
4. LLM consensus CI coverage: the key anti-injection defence is never tested in CI against real LLMs.

---

## 9. Strengths That Are Real

### 9.1 Structural Fail-Closed: Production-Grade

`Guard.verify()` has two independent, structural fail-closed enforcement mechanisms. This is not a convention or a documented promise — it is enforced by the type system (`Decision.__post_init__` raises `ValueError`). An error in any of the 12 pipeline steps always produces `allowed=False`. This is provably stronger than systems that rely on caller-side `try/except` for safety.

**Stronger than:** LangChain hooks (caller must catch), Guardrails AI validators (exceptions propagate), NeMo rails (configurable fail mode).

### 9.2 Formal Arithmetic Completeness: Production-Grade

Z3's completeness guarantee is real: if `solve()` returns `sat`, every invariant holds for the exact inputs. There is no false-positive path for well-typed inputs. Combined with exact Decimal arithmetic (no IEEE 754 drift), the arithmetic layer is correct for financial invariants.

This does not mean the policy is correct. A policy with wrong invariants enforces wrong constraints. Completeness is over the policy-as-written, not over the policy-as-intended.

### 9.3 Adversarial Test Quality: Production-Grade

8 adversarial test files covering: fail-safe across all pipeline stages, prompt injection (10 vectors), field overflow (8 vectors), HMAC IPC tamper detection, Z3 concurrent context isolation, Pydantic strict boundary, TOCTOU contract documentation, ID injection. This is unusually thorough for a 1.0.0 library. The `threading.Barrier` pattern in `test_z3_context_isolation.py` is specifically designed to maximise probability of revealing race conditions.

### 9.4 Attribution: Production-Grade

Per-invariant attribution is exact, not heuristic. Phase 2 uses one `z3.Solver` per invariant with `assert_and_track` — `unsat_core()` always returns `{label}`. No minimal-core ambiguity, no heuristic approximation. The violated invariant label is surfaced in `Decision.violated_invariants` and in the `ComplianceReporter` regulatory citation map.

### 9.5 Provenance and Audit Trail: Real (with limitations)

`ProvenanceChain` (HMAC-SHA256, SHA-256 of prev record's tag in `prev_hash`), Merkle anchoring (inclusion proofs), JWS compact tokens (stdlib-only, offline-verifiable), 6 audit sinks, Ed25519 signing with 7 key providers. Taken together, this is a complete chain-of-custody for agentic decisions — more than any named competitor provides. Limitations (ProvenanceChain key not persisted; Merkle archive plaintext) are documented.

### 9.6 Policy Lifecycle Tooling: Real

`PolicyAuditor` (static analysis), `PolicyDiff`, `ShadowEvaluator` (canary promotion), `PolicyMigration` (declarative schema migration), SHA-256 policy fingerprint with `expected_policy_hash` drift detection, `pramanix doctor` CLI with 11 checks. This is production operations tooling that most SDK-level competitors lack entirely.

### 9.7 Integration Coverage: Real and Wide

9 framework integrations with real subclass inheritance verified in tests. gRPC interceptor, Kafka consumer interceptor, K8s ValidatingWebhook. All 3 integration-layer bugs found in testing (BUG-07, BUG-08, BUG-09) were real bugs, not theoretical — they were fixed before 1.0.0.

### 9.8 Strict Neuro-Symbolic IR Boundary: Real

`compiler.py` provides the deterministic typed boundary between probabilistic LLM output and formal Z3 logic. The `PolicyIR` Pydantic schema acts as a strict contract: an LLM cannot reference a field that does not exist in the policy schema, cannot apply an ordering operator to a `Bool`-sorted field, and cannot produce a partial compilation result without raising `PolicyCompilationError`. Every violation is a loud attributed exception with the offending field name, operator, and sort information.

The `Decompiler` closes the loop: any policy compiled from an LLM-generated `PolicyIR` can be rendered back to structured English for CISO review before the policy is deployed. Zero `eval`, zero `exec`, zero dynamic code generation. The LLM is never invoked by the compiler — it operates on the already-validated `PolicyIR` object.

This is distinct from `natural_policy/` (Phase 2), which is an LLM pipeline. `compiler.py` is the standalone, deterministic lower half that any LLM pipeline — present or future — can target.

---

## 10. Weaknesses and Gaps

### 10.1 AGPL-3.0 License: Enterprise Blocker

AGPL-3.0 requires any software that _uses_ the library over a network to release its source code. This blocks adoption in most commercial and enterprise contexts without a proprietary license arrangement. All direct competitors are Apache-2.0 or MIT. This is the single largest adoption barrier regardless of technical quality. Noted in `reality.md` as a gap preventing score > 9.0.

### 10.2 No NLP Validators: Gap

No PII detection, toxicity scoring, hate-speech detection, semantic similarity, or regex-based text validators. Guardrails AI's core feature set is absent. Pramanix can enforce `amount > 0` but cannot detect that a user is asking an LLM to reveal SSNs in a text field. This gap is significant for any use case where the policy constraint is over text content rather than structured numeric/boolean fields.

### 10.3 LLM Consensus Layer Not Tested in CI: Gap

Layer 4 of the injection defence — dual-model LLM consensus — requires two real LLM API keys. It is never exercised in CI. All injection tests use stub translators. The strongest advertised anti-injection defence has zero CI coverage against real adversarial inputs. This is a significant evidence gap: the claim that "two independent models must agree" is correct as a design principle but unvalidated in practice.

### 10.4 ProvenanceChain Key Not Persisted: Gap

`_provenance_key()` generates `os.urandom(32)` per process. The key is not persisted. Cross-restart audit chain verification is impossible without external key storage. For long-running audit chains, this means the chain is effectively segmented by process lifetime.

### 10.5 Merkle Archive Plaintext: Gap

`MerkleArchiver` writes `.merkle.archive.YYYYMMDD` files to disk in plaintext. Deployments subject to SOC 2 Type II, PCI DSS, or HIPAA must encrypt the archive directory externally. The gap is documented in source comments and CHANGELOG L-02 adds a warning log, but the encryption responsibility is entirely on the operator.

### 10.6 Injection Scorer Field Scope: Partially Fixed

Historical hardcode: the injection scorer checked only `"amount"` field for suspicious characters. CHANGELOG M-03 expanded to fields ending in `_id`, `_key`, `_token`, `_ref`, `_number`, `_code`, `_account`, `_address`. Policies with sensitive fields outside this naming convention remain under-screened at Layer 3. The fix is partial: a policy with a field named `destination_routing_code` but spelled `routing` is not covered.

### 10.7 Pickle in Process Mode: Risk (if HMAC key compromised)

`injection_scorer.py` uses `pickle.loads()` after HMAC verification. If the HMAC key is compromised, this is an RCE vector. The HMAC seal is the only barrier. This is noted in `reality.md` under security gaps. HMAC key compromise is a prerequisite — but HMAC key compromise is not a far-fetched scenario in shared-key IPC architectures.

### 10.8 Benchmark Version Mismatch

All benchmark results (`benchmarks/results/`) were collected under v0.8.0, not v1.0.0. The 1.0.0 release includes multiple performance-relevant changes (BUG-06 audit log bounded growth, Kafka poll fix, LlamaIndex coroutine fix). The reported benchmark numbers (P50 5.235ms, 81.3 avg RPS on consumer laptop) are real measurements but do not represent the current release on server hardware.

### 10.9 Policy Author Skill Dependency

The system enforces exactly what the policy author encodes. `PolicyAuditor` finds unreferenced fields but cannot verify that the encoded invariants correctly capture the intended policy. A policy with all fields referenced but wrong threshold values silently enforces wrong constraints. There is no formal policy correctness verification beyond syntactic well-formedness.

### 10.10 Hypothesis Test Gap: Injection Scorer Score Bounds

`reality.md` §3.1 documents: no Hypothesis property-tests verify that the injection scorer's additive float-math heuristics produce scores monotonically bounded within `[0.0, 1.0]` across the full input space. This is a coverage gap for a security-critical component.

---

## 11. What Would Make It Superior

**Table 5: Gap Prioritization**

| Gap | Severity | Evidence | Impact | What Would Close It |
|---|---|---|---|---|
| AGPL-3.0 license | Critical | `reality.md`; all competitors Apache-2.0/MIT | Blocks all commercial adoption | Dual-license (AGPL + commercial) or re-license under Apache-2.0 |
| LLM consensus layer CI coverage | High | All injection tests use stub translators; no real LLM CI runs | Primary anti-injection defence unvalidated | Add CI job with real API keys; or mock at HTTP boundary with adversarial payloads; or add property tests for extraction schema compliance |
| No NLP validators | High | Guardrails AI comparison; no `detect_pii`, `toxic_language` in codebase | Cannot protect against text-content policy violations | Integrate HuggingFace pipeline, spaCy, or cloud NLP APIs as optional validators |
| Merkle archive encryption | High | `audit/archiver.py` source comment; CHANGELOG L-02 | Compliance failure for SOC2/PCI DSS/HIPAA deployments without external encryption | Add `encryption_key` parameter to `MerkleArchiver`; AES-256-GCM per-file encryption at write time |
| ProvenanceChain key persistence | High | `provenance.py` `os.urandom(32)` per-process | Cross-restart audit chain breaks | Accept key as constructor parameter; document `AwsKmsKeyProvider` as the recommended store |
| Benchmark on current version and server hardware | Medium | `benchmarks/results/` dated v0.8.0; consumer laptop | All published latency numbers are outdated and hardware-specific | Re-run on v1.0.0 on EC2 c5.8xlarge or equivalent; publish with hardware spec |
| Injection scorer score bounds test | Medium | `reality.md` §3.1 gap note | Score > 1.0 or < 0.0 could miscalibrate the threshold | Add Hypothesis property test: `st.text()` input → score in `[0.0, 1.0]` |
| Injection scorer field scope | Medium | CHANGELOG M-03 partial fix | Sensitive fields outside naming convention under-screened | Replace field-name heuristic with field-declaration annotation (`sensitive=True`) |
| Process mode adversarial crash test | Medium | DECISIONS.md §4 architectural claim; no SIGSEGV test | Crash isolation claim unverified | Add subprocess test that sends SIGABRT to a worker and verifies host receives `Decision.error()` |
| Pickle in process mode (HMAC key compromise) | Medium | `reality.md` gap; `injection_scorer.py` | RCE if HMAC key compromised | Replace pickle with JSON + schema validation for IPC payloads; remove pickle entirely from process-boundary code |
| `pramanix doctor` coverage for LLM translator misconfiguration | Low | CHANGELOG check #10, #11 added; no translator check | Silent no-op if translator configured but API key absent | Add check #12: translator configured → at least one API key present |
| No property test for `ShadowEvaluator` divergence completeness | Low | Architectural claim in source | Shadow eval may miss divergences | Hypothesis test: same inputs to live and shadow policy → divergence recorded if outputs differ |

### 11.1 The Three Changes That Would Most Increase Real-World Adoption

1. **Dual licensing.** Technical quality is not the adoption bottleneck. AGPL-3.0 is. A commercial license tier with a free-tier for research/open-source would immediately unblock enterprise evaluation.
2. **Real LLM CI coverage for injection defence.** The strongest anti-injection claim requires real validation. A $5–10/month CI budget for actual LLM API calls would provide evidence that the Layer 4 defence works as designed.
3. **NLP validator integration.** The absence of PII and toxicity validators means Pramanix must be combined with another library for text-content policies. Adding `detect_pii` and `toxic_language` primitives backed by a lightweight model would eliminate the most common reason to choose Guardrails AI instead.

### 11.2 What Would Constitute Formal Category Leadership

- Published third-party security audit of the adversarial test suite and injection defence chain.
- Benchmark results on server hardware for v1.0.0 (not v0.8.0 on a consumer laptop).
- Production deployment reference at ≥1 named enterprise customer.
- Property-verified injection scorer score bounds.
- Merkle archive encryption built-in (not operator-responsibility).

None of these require architectural changes. All are achievable without breaking existing APIs.

---

## 12. Final Verdict

### 12.1 A. Correctness

**Strong.** Z3 correctness guarantee is real for well-formed inputs. Exact Decimal arithmetic eliminates float drift. Two-phase attribution is deterministic. `Decision.__post_init__` enforces `allowed=True ↔ status=SAFE` structurally. Property-based tests via Hypothesis cover 10 DSL properties. No known correctness defects.

**Limitation:** Correctness is over the policy-as-written. A wrong policy enforces wrong constraints. No formal policy correctness verification beyond static analysis of field coverage.

### 12.2 B. Safety

**Production-grade.** Dual structural fail-closed enforcement. All 6 pipeline stages proven fail-closed against 9 exception types. `ALLOW_WITH_AUDIT` deprecated and aliased to `BLOCK_ALL`. Fast path can only BLOCK. Signing failure produces `Decision.error()`, not an unsigned decision. Timing oracle protection implemented and tested (statistical, not cryptographic).

### 12.3 C. Security

**Strong with documented gaps.** JWT algorithm confusion patched (CVE-2015-9235 family; BUG-10). Algorithm validation before signature computation. `nbf` enforcement added (BUG-11). Empty `sub` rejected (BUG-12). HMAC IPC tamper detection proven. No `eval`/`exec`/`ast.parse` anywhere in the transpiler. Pydantic strict mode prevents schema bypass.

**Gaps:** Pickle in process-mode IPC (RCE if HMAC key compromised). Merkle archive plaintext (compliance gap). LLM consensus Layer 4 untested in CI (injection validation gap). ProvenanceChain key not persisted (audit continuity gap).

### 12.4 D. Performance

**Unverified for current version.** All benchmarks (P50 5.235ms latency, 81.3 avg RPS at 1M scale) are from v0.8.0 on a consumer laptop (Intel Core, 15.63 GB RAM). The v1.0.0 latency target of 5.0ms P50 was **missed** at v0.8.0 (actual: 5.235ms P50). Multiple 1.0.0 fixes affect performance-relevant paths. No v1.0.0 benchmark exists.

Configurable thresholds via `PRAMANIX_PERF_P50_MS` etc. (R6) indicate the team is aware of environment-dependent variance. The benchmark infrastructure is real and re-runnable — the gap is a missing re-run, not a missing capability.

### 12.5 E. Reliability

**Strong on primary axis; medium on secondary axes.** Z3 timeout → `Decision(status=TIMEOUT)`. Worker crash → `Decision.error()`. Circuit breaker with `ISOLATED` state for chronic pressure. AdaptiveConcurrencyLimiter with load-shedding. `ResolverRegistry.clear_cache()` unconditional in `finally`. Kafka interceptor transient-error `continue` bug fixed (BUG-08). LlamaIndex cross-event-loop crash fixed (BUG-13).

**Medium:** Process-mode crash isolation is architectural, not adversarially tested. ProvenanceChain key loss on restart. Sweeper `stop()` required for clean `InMemoryApprovalWorkflow` shutdown (added in BUG-04).

### 12.6 F. Evidence Quality

**High for core path; low for injection Layer 4 and benchmarks.**

Core path (fail-closed, Z3 isolation, Pydantic boundary, HMAC tamper): proven with real tests, no mocks on critical paths.

Injection Layer 4 (LLM consensus): stub-backed. The tests are correctly designed — they isolate the Z3+governance layer from LLM parsing — but the claimed defence against sophisticated injection is not validated with real LLMs.

Benchmarks: real measurements on real hardware, but outdated version and non-production hardware.

Integration tests: real containers (`requires_docker`), may skip in CI without Docker.

### 12.7 G. Usability

**Good DSL ergonomics; steep onboarding for advanced features.** `E(balance) - E(amount) >= 0` is readable. `@guard` decorator and `Guard.verify()` are clean API surfaces. `pramanix doctor` provides actionable diagnostics. 14 working examples cover all major use cases.

**Friction points:** AGPL-3.0 triggers legal review before any evaluation. LLM translator requires API key configuration before the natural-language policy authoring path works. `async-process` mode requires policy classes to be defined at module level (not closures or lambdas — documented in `DECISIONS.md §5`). Z3 glibc dependency blocks Alpine-based Docker images without custom builds.

### 12.8 H. Competitive Position

Pramanix occupies a narrow but real lane: **deterministic, formally verified, tamper-evident enforcement of arithmetic and boolean invariants over typed agentic tool calls**. No named competitor provides SMT-based formal completeness with per-invariant attribution, a signed audit chain, and 9 framework integrations in a single library.

The lane narrows further: most real-world LLM safety requirements involve NLP-level content constraints (PII, toxicity, off-topic) that Pramanix cannot address. For those use cases, Guardrails AI or NeMo are more complete. Pramanix's natural target is the subset of agentic use cases where the action being gated is a structured tool call with numeric/boolean parameters and a clear formal specification — financial transactions, clinical access decisions, infrastructure mutations.

Within that lane, for that use case, the technical quality is genuinely high. The gap between current state and category leadership is primarily licensing, LLM consensus CI coverage, and NLP validator absence — not core architecture.

---

*This document was produced by systematic review of source code, tests, benchmarks, and documentation. All claims are attributed to a specific file, test, or documented gap. Claims labelled `documented-only`, `stub-backed`, `real-partial`, or `beta` should not be cited as production evidence without corresponding real test coverage.*
