# PRAMANIX SDK — Principal Engineering Remediation & Elevation Plan

**From Beta to Best-in-Class: A Phase-Gated Engineering Master Plan**

- **Document Version:** 1.0
- **SDK Target:** v1.1 → v2.0 GA
- **Audience:** Principal Engineers, Staff Engineers, LLM Code Agents
- **License:** Proprietary — Pramanix Commercial + AGPL-3.0 Open Core
- **Owner:** Viraj Jain | github.com/virajjain1011/Pramanix

---

## §0 — How to Use This Document

This document is the single authoritative source of truth for all engineering work on the Pramanix SDK post-v1.0.

| Reader Type | How to Use |
|---|---|
| Human Principal Engineer | Read §0–§2 for context. Navigate to the Phase relevant to your sprint. Each phase is self-contained with: Problem, Root Cause, Architecture Decision, Implementation Plan, Test Gate. |
| LLM Code Agent (Claude Code, etc.) | Read §0 entirely. Receive a phase ID (e.g. `Phase B-1`). Locate that section. Follow Implementation Steps exactly in order. Do not proceed until the Test Gate passes. Never mark a phase complete without running the gate command. |
| Code Reviewer / Architect | Use §1 (Gap Severity Matrix) and §3 (Architecture Decisions) as review anchors. Every PR must cite the Phase ID it addresses. |
| Enterprise Customer / Auditor | §1 maps gaps to your compliance concern. §4–§10 contain remediations relevant to HIPAA, SOX, Basel III, and BSA/AML postures. |

> **RULE:** Every phase has exactly one gate condition. The gate must pass before any subsequent phase begins. No exceptions. No partial completions.

> **RULE:** All implementation steps within a phase are numbered and sequential. An LLM agent must execute them in order. Parallelism is only permitted where explicitly noted with `[PARALLEL OK]`.

> **RULE:** The test baseline is **1,821 tests**. Every phase gate requires: (a) all new tests pass, (b) zero regressions from 1,821 baseline, (c) coverage >= 95%.

---

## §1 — Current State Assessment

### 1.1 — What Is Already Best-in-Class (Do Not Break)

The following capabilities represent genuine, differentiated, category-leading engineering. Every subsequent phase must preserve these properties unconditionally.

| Capability | Why It Is Non-Negotiable |
|---|---|
| Formal SMT-backed decisions (Z3) | No other Python guardrail SDK uses Z3. Every ALLOW is a mathematical theorem. This is the entire product thesis. |
| Fail-safe contract: `verify()` never raises | Every exception path → `Decision(allowed=False)`. Breaking this collapses the safety model. |
| Dual-model consensus for NLP extraction | Two independent LLMs must agree character-for-character before any field reaches Z3. |
| Sealed execution tokens (TOCTOU mitigation) | Cryptographically binds a verification to a specific action at a specific time. Unique in the field. |
| Merkle + Ed25519 audit chain | Tamper-evident decision log. Required for regulatory defensibility. |
| SLSA Level 3 CI/CD | SBOM + Sigstore provenance. Supply chain integrity exceeds most SDKs. |
| 38 production-grade primitives | Battle-tested constraints for finance, healthcare, RBAC, infra, time, and anti-fraud domains. |
| 1,821 tests (706 adversarial) | STRIDE T1–T7 coverage. Hypothesis property-based. Adversarial injection vectors. |

### 1.2 — Gap Severity Matrix

All gaps identified in the independent architecture review are classified by severity, blast radius, and remediation complexity. Phases in §3–§10 map 1:1 to these rows.

| Gap ID | Gap Description | Severity | Blast Radius | Phase |
|---|---|---|---|---|
| G-01 | No exponentiation / polynomial constraints in DSL | HIGH | Finance, ML policy | A-1 |
| G-02 | No modulo / bitwise arithmetic in DSL | MEDIUM | Even-lot checks, bit-flags | A-1 |
| G-03 | String fields: equality & is_in only — no regex/prefix/length | HIGH | Text-heavy policies | A-2 |
| G-04 | No quantifiers (forall/exists) in DSL | HIGH | Basket policies, collections | A-3 |
| G-05 | No array/list field type | HIGH | Basket trades, multi-item actions | A-3 |
| G-06 | No native datetime arithmetic — caller must pre-compute | MEDIUM | Time-window policies | A-4 |
| G-07 | No nested Pydantic models in policy fields | HIGH | Complex state schemas | B-1 |
| G-08 | No dynamic field declarations (runtime schema) | MEDIUM | Multi-tenant policies | B-2 |
| G-09 | No cross-policy constraint sharing / composition | MEDIUM | Policy reuse, DRY | B-3 |
| G-10 | Policy versioning is manual (plain string, no semver) | MEDIUM | Migration, rollback | B-4 |
| G-11 | Alpine Linux not supported (glibc vs musl) | MEDIUM | Docker / K8s deployments | C-1 |
| G-12 | Z3 context overhead: fresh context per call, no AST caching | HIGH | Throughput at scale | C-2 |
| G-13 | Worker ProcessPoolExecutor: pickling constraints | MEDIUM | Process mode correctness | C-3 |
| G-14 | AdaptiveCircuitBreaker is async-only; sync callers must wrap | MEDIUM | Sync service adoption | C-4 |
| G-15 | No distributed circuit breaker / metric aggregation | HIGH | Multi-replica deployments | C-5 |
| G-16 | Consensus check uses exact JSON string equality (brittle) | **CRITICAL** | NLP extraction reliability | D-1 |
| G-17 | Only 3 LLM backends (OpenAI, Anthropic, Ollama) | MEDIUM | Ecosystem breadth | D-2 |
| G-18 | Input truncated at 512 chars silently | HIGH | Complex multi-step intents | D-3 |
| G-19 | Injection scoring uses fixed coefficients — no calibration | HIGH | False positive rate | D-4 |
| G-20 | Redis required for distributed token verification | MEDIUM | Small/serverless deployments | E-1 |
| G-21 | Merkle anchor grows without bound — no pruning/archival | MEDIUM | Long-running systems | E-2 |
| G-22 | Ed25519 key management is manual (no KMS/HSM) | **CRITICAL** | Enterprise security posture | E-3 |
| G-23 | Audit log to stdout only — no Kafka/S3/SIEM sink | HIGH | Production observability | E-4 |
| G-24 | Only 4 framework integrations (FastAPI, LangChain, LlamaIndex, AutoGen) | HIGH | Ecosystem reach | F-1 |
| G-25 | @guard decorator is async-only — TypeError on sync functions | HIGH | Adoption in sync codebases | F-2 |
| G-26 | No gRPC / Kafka / non-HTTP transport interceptors | MEDIUM | Microservice adoption | F-3 |
| G-27 | No Kubernetes admission webhook controller | MEDIUM | K8s-native enforcement | F-4 |
| G-28 | Not on PyPI — install-from-source only | **CRITICAL** | Adoption, distribution | G-1 |
| G-29 | No policy dry-run / simulate CLI command | HIGH | Developer experience | G-2 |
| G-30 | No visual policy editor or JSON schema export | MEDIUM | Non-developer adoption | G-3 |

---

## §2 — Architecture Principles for All Remediation Work

Every engineer (human or LLM) working on Pramanix remediation MUST internalize and enforce these principles. They are not guidelines — they are invariants.

- **P-01: Fail-safe is axiomatic.** Any code path that could theoretically produce `Decision(allowed=True)` from an error state is a P0 defect. Fail-safe takes precedence over performance, usability, and feature completeness.
- **P-02: Z3 is never bypassed.** The `IntentExtractionCache` caches LLM extraction results only. Z3 still runs on every call. Any optimization that removes Z3 from the critical path violates the product contract and must be rejected.
- **P-03: No fabricated metrics.** No benchmark, coverage number, or performance claim may appear in any document without a corresponding reproducible test or measurement artifact. Fabricated data is a trust violation.
- **P-04: Closed-loop discipline.** Every disclaimer in a README must be backed by a failing test that enforces the limitation. Comment + enforcing test = closed loop. Comment alone = open loop = defect.
- **P-05: Frozen dataclasses are sacred.** Use `dataclasses.replace()` — never `object.__setattr__()` — to respect the immutability contract of `Decision` and related objects.
- **P-06: Canonical hash is unredacted.** OTel field redaction applies to spans only. The SHA-256 canonical hash always uses raw (unredacted) field values. Redacting the hash input creates non-injective audit records.
- **P-07: Ed25519 keys survive restart.** Historical audit validity requires that signing keys outlive any single process. Key rotation must be explicit, versioned, and backward-compatible.
- **P-08: Windows compatibility is not optional.** `freeze_support()`, module-level `worker_entry`, PowerShell-compatible commands, cp1252-safe output. Windows-specific regressions are P1 defects.
- **P-09: Benchmark honesty is enforced.** Pilot results (N < 1M decisions) must be labeled as pilots. Extrapolations are prohibited. Every performance claim cites the exact test harness command used to produce it.
- **P-10: Phase gate before merge.** No phase is merged to main without its gate condition passing in CI. Gate failures block the merge — they are not warnings.

---

## §3 — Phase Overview Map

All remediation is organized into 7 tracks (A–G), each subdivided into focused phases. Each phase is atomic and independently mergeable.

| Track | Theme | Phases | SDK Version Target | Priority |
|---|---|---|---|---|
| A | DSL Expressiveness | A-1 through A-4 | v1.1 | HIGH → CRITICAL |
| B | Policy Authoring & Schema | B-1 through B-4 | v1.2 | MEDIUM → HIGH |
| C | Concurrency & Deployment | C-1 through C-5 | v1.1 & v1.3 | HIGH |
| D | NLP / Translator Layer | D-1 through D-4 | v1.1 | CRITICAL → HIGH |
| E | Identity & Audit | E-1 through E-4 | v1.2 | CRITICAL → HIGH |
| F | Ecosystem Integrations | F-1 through F-4 | v1.2 & v1.3 | HIGH → MEDIUM |
| G | Developer Experience | G-1 through G-3 | v1.1 (G-1 blocks all others) | CRITICAL |

> **SEQUENCING NOTE:** G-1 (PyPI publication) and D-1 (consensus robustness fix) are prerequisites for all other public-facing work. They must be completed first regardless of track ordering.

### Recommended Sprint Sequencing (2-week sprints)

| Sprint | Phases | Rationale |
|---|---|---|
| Sprint 1 | G-1, D-1, G-2 | Unlock distribution + fix highest-risk NLP bug + ship CLI |
| Sprint 2 | A-1, A-2, C-4, C-5 | DSL arithmetic + string extensions + sync support + distributed metrics |
| Sprint 3 | E-3, E-4, D-4, D-3 | KMS integration + SIEM sinks + injection calibration + input size fix |
| Sprint 4 | A-3, A-4, B-1, F-1 | Quantifiers + datetime + nested models + new integrations |
| Sprint 5 | B-2, B-3, B-4, F-2, F-3 | Dynamic fields + cross-policy + versioning + sync decorator + gRPC |
| Sprint 6 | C-1, C-2, C-3, E-1, E-2 | Docker/musl + Z3 AST cache spike + pickling + Redis alt + Merkle pruning |
| Sprint 7 | D-2, F-4, G-3, C-5 hardening | New LLM backends + K8s webhook + policy editor + distributed CB |

---

## TRACK A — DSL Expressiveness | Phases A-1 through A-4

> The DSL is the product's core interface. Every gap here reduces the class of safety policies that can be expressed. Fixes must be additive — no breaking changes to existing expression syntax.

---

### Phase A-1 — Polynomial & Modulo Arithmetic in DSL

**Severity:** HIGH | **Effort:** 3 days | **Gaps closed:** G-01, G-02

#### A-1.1 — Problem

The `**` (exponentiation) operator is explicitly banned. The `%` (modulo) operator is undocumented and unsupported. This blocks compound-interest constraints, quadratic risk limits, even-lot checks, and bit-flag permission masks.

#### A-1.2 — Root Cause

Z3's QF_NRA (non-linear real arithmetic) can handle polynomials but defaults to a slower decision procedure. The original design chose to ban exponentiation to keep all queries in the faster QF_LRA (linear real arithmetic) fragment. Modulo was simply never implemented.

#### A-1.3 — Architecture Decision

- Introduce a new `ConstraintComplexity` enum: `LINEAR` (default), `POLYNOMIAL`, `MODULAR`.
- `Policy.invariants()` that contain `**` or `%` are automatically classified by the Transpiler.
- The Solver selects the Z3 tactic based on complexity: QF_LRA for LINEAR, QF_NRA for POLYNOMIAL, QF_BVLIA for MODULAR.
- Timeout budget per complexity class: LINEAR 200ms (current), POLYNOMIAL 2000ms, MODULAR 500ms. Independently configurable.
- Fail-safe remains unchanged: TIMEOUT or UNKNOWN → BLOCK.

#### A-1.4 — Implementation Steps (execute in order)

1. In `expressions.py`, add `__pow__` to `ExpressionNode`: `return ExpressionNode(NodeType.POW, [self, _wrap(other)])`. Add `POW` to `NodeType` enum. Remove the `NotImplementedError` that currently raises for `**`.
2. Add `NodeType.MOD` and `ExpressionNode.__mod__`: `return ExpressionNode(NodeType.MOD, [self, _wrap(other)])`.
3. In `transpiler.py`, add POW case: compile via explicit multiplication unrolling up to degree 4. Degree > 4 or non-integer exponent: raise `PolicyCompilationError`.
4. Add MOD case in `transpiler.py`: for `IntSort` fields, use z3's native mod. For `RealSort` fields, raise `PolicyCompilationError` at compile time with a clear message.
5. In `solver.py`, detect `ConstraintComplexity` from the compiled invariant set before creating the Solver. Set tactic accordingly: `z3.Tactic('qfnra')` for POLYNOMIAL.
6. Add `PRAMANIX_POLYNOMIAL_TIMEOUT_MS` and `PRAMANIX_MODULAR_TIMEOUT_MS` to `GuardConfig` with defaults `2000` and `500`.
7. Update `primitives/fintech.py` to remove the docstring note `'Modulo arithmetic is not supported.'`

#### A-1.5 — Tests to Add After Each Step

- `test_expressions.py`: `test_pow_expression_compiles()`, `test_mod_expression_compiles()`, `test_pow_on_real_field()`, `test_mod_on_real_raises_compile_time_error()`.
- `test_transpiler.py`: `test_pow_transpiles_to_z3()`, `test_mod_transpiles_to_z3_intmod()`.
- `test_solver.py`: `test_polynomial_policy_uses_qfnra_tactic()`, `test_polynomial_timeout_config()`.
- Hypothesis test: given any two `Decimal` fields `a, b` with `b > 0`, verify `Guard.verify()` with constraint `(a % b < b)` never raises and always returns ALLOW.

#### A-1.6 — Gate Condition

```
pytest tests/unit/test_expressions.py tests/unit/test_transpiler.py tests/unit/test_solver.py -k 'pow or mod'
# ALL PASS. pytest --tb=short — zero regressions from 1,821 baseline.
```

---

### Phase A-2 — String Field Extensions: Regex, Prefix, Suffix, Length

**Severity:** HIGH | **Effort:** 4 days | **Gaps closed:** G-03

#### A-2.1 — Problem

String fields support only equality (`==`) and `is_in()`. Policies that need to check string prefixes (e.g. SWIFT BIC codes), suffixes, lengths, or pattern matching (IBAN, account number format) cannot be expressed.

#### A-2.2 — Architecture Decision

- Z3 sequence theory (SeqSort) supports: `z3.PrefixOf`, `z3.SuffixOf`, `z3.Contains`, `z3.Length`, and `z3.InRe` (regex via `z3.Re`).
- Extend `ExpressionNode` with string-specific methods that compile to these Z3 primitives.
- Regex support limited to RE-expressible patterns (no backreferences, no lookahead). Validate at compile time.
- String operations are only valid on `String`-sort fields. Applying to `Real`/`Int`/`Bool` raises `PolicyCompilationError` at `Guard.__init__` time.

#### A-2.3 — New DSL Methods

```python
E(cls.account_id).starts_with('GB')                             # z3.PrefixOf
E(cls.account_id).ends_with('0000')                             # z3.SuffixOf
E(cls.account_id).contains('SWIFT')                             # z3.Contains
E(cls.account_id).length_between(10, 34)                        # z3.Length
E(cls.account_id).matches_re(r'[A-Z]{4}[A-Z]{2}[0-9A-Z]{2}')  # z3.InRe
```

#### A-2.4 — Implementation Steps

1. Add `starts_with`, `ends_with`, `contains`, `length_between`, `matches_re` to `ExpressionNode`. Each returns a `ConstraintExpr` with a new `NodeType` (`PREFIX_OF`, `SUFFIX_OF`, `CONTAINS`, `LENGTH_BETWEEN`, `REGEX_MATCH`).
2. In `transpiler.py`, add compilation cases for each `NodeType` using z3 sequence operations.
3. For `REGEX_MATCH`: parse Python regex at compile time. Reject unsupported features. Translate to `z3.Re(...)` using `z3.Union`, `z3.Concat`, `z3.Star`, `z3.Range` primitives.
4. Update the `Field` docstring to document which DSL methods are valid for which Z3 sort.
5. Add `StringEnumField` helper that creates a `String` Field pre-configured with an `is_in` constraint from an `Enum` class.

#### A-2.5 — Gate Condition

```
pytest -k 'string_ext'
# A Policy with starts_with, ends_with, length_between, and matches_re
# must compile and Guard.verify() must return ALLOW/BLOCK correctly.
```

---

### Phase A-3 — Quantifiers & Array Field Type

**Severity:** HIGH | **Effort:** 6 days | **Gaps closed:** G-04, G-05

#### A-3.1 — Problem

Policies over collections — "all line items in a basket must be non-negative", "at least one counterparty must be on the approved list" — cannot be expressed without manually unrolling N-element arrays into N separate fields.

#### A-3.2 — Architecture Decision

- Introduce `ArrayField(element_type, z3_sort, max_length)` as a new field descriptor. Arrays projected to Z3 using bounded unrolling up to `max_length`.
- Add `ForAll(field, lambda_constraint)` and `Exists(field, lambda_constraint)` DSL constructs that compile to Z3 quantifier-free formulas via bounded unrolling.
- `max_length` is a compile-time constant. This preserves decidability and linear complexity.
- At runtime, if actual array length exceeds `max_length`, the solver returns BLOCK immediately (fail-safe).

#### A-3.3 — New DSL Syntax

```python
amounts = ArrayField('amounts', Decimal, z3_sort='Real', max_length=50)

# In invariants:
ForAll(cls.amounts, lambda amt: E(amt) >= Decimal('0')).named('all_amounts_non_negative')
Exists(cls.recipients, lambda r: E(r).is_in(cls.approved_list)).named('approved_recipient')
```

#### A-3.4 — Implementation Steps

1. Add `ArrayField` to `expressions.py`. Generates N Z3 variables (`field_0`, `field_1`, ..., `field_N-1`) at compile time.
2. Add `ForAll` and `Exists` to `expressions.py` as functions taking an `ArrayField` and a callable returning a `ConstraintExpr`.
3. In `transpiler.py`: `ForAll` → `z3.And(*[predicate(field_i) for i in range(max_length)])`, `Exists` → `z3.Or(*[...])`.
4. In `validator.py`: `if len(values[field]) > max_length: return Decision(allowed=False, reason='array_overflow')`.
5. Add `ArrayField` serialization support to the `model_dump()` pipeline for IPC boundary crossing.

#### A-3.5 — Gate Condition

```
pytest -k 'array_field or quantifier'
# BasketTradePolicy with ForAll(amounts, lambda a: E(a) >= 0)
# must ALLOW all-positive basket and BLOCK any-negative basket.
# Hypothesis test with random arrays up to max_length must produce no exceptions.
```

---

### Phase A-4 — Native Datetime Arithmetic in DSL

**Severity:** MEDIUM | **Effort:** 3 days | **Gaps closed:** G-06

#### A-4.1 — Problem

Time-based constraints require callers to pre-compute Unix timestamps and pass them as numeric fields. This leaks implementation details into calling code and makes policies harder to read and audit.

#### A-4.2 — Architecture Decision

- Add `DatetimeField(name)` as a `Field` variant that accepts Python `datetime` objects.
- At serialization time, `DatetimeField` values are converted to `Z3 IntSort` (Unix epoch seconds). Keeps Z3 arithmetic linear and fast.
- Add DSL helpers: `E(cls.trade_time).within_seconds(3600)`, `E(cls.trade_time).is_business_hours()`, `E(cls.expiry).is_before(cls.settlement)`.
- All datetime arithmetic is performed in UTC. Non-UTC input raises `PolicyCompilationError` at `Guard.__init__` time.

#### A-4.3 — Gate Condition

```
# A TradeWindowPolicy with DatetimeField and within_seconds(3600)
# must correctly ALLOW requests within the window and BLOCK requests outside it
# without the caller pre-computing any timestamp.
```

---

## TRACK B — Policy Authoring & Schema | Phases B-1 through B-4

---

### Phase B-1 — Nested Pydantic Models in Policy Fields

**Severity:** HIGH | **Effort:** 5 days | **Gaps closed:** G-07

#### B-1.1 — Problem

`serialization.py` explicitly blocks nested `BaseModel` instances. This forces callers to flatten all state into scalar fields, which is untenable for real-world domain models with natural hierarchies (`Account -> Position -> Instrument`).

#### B-1.2 — Architecture Decision

- Implement recursive `model_dump_z3()` that traverses nested Pydantic models and produces a flat dict of dotted-path keys: `'account.position.amount' -> Decimal`.
- Introduce nested field access in the DSL via `E(cls.account.position.amount)` using Python descriptor chaining that resolves to the dotted-path key at compile time.
- Z3 variable names use the dotted path as the identifier. Transparent to the solver.
- Circular reference detection at compile time. `max_nesting_depth` config (default: 5).

#### B-1.3 — Gate Condition

```
# A Policy with nested Account -> Position -> Instrument model must compile and verify.
# E(cls.account.position.amount) must produce the same Z3 result
# as E(cls.amount) with a flat schema.
```

---

### Phase B-2 — Dynamic Field Declarations (Runtime Schema)

**Severity:** MEDIUM | **Effort:** 4 days | **Gaps closed:** G-08

#### B-2.1 — Problem

Policies with tenant-specific field sets require a separate `Policy` subclass per tenant. At scale (1000+ tenants) this is unmanageable.

#### B-2.2 — Architecture Decision

- Add `Policy.from_config(fields: dict, invariants: list)` classmethod as a factory for dynamically constructed policies.
- Dynamic policies are fully compiled at construction time — not per-request. Factory returns a sealed `Policy` class.
- Invariants expressed as lambda functions: `lambda f: (E(f['balance']) - E(f['amount']) >= 0).named('funds_check')`.
- Dynamic Policy instances cached by field schema hash. Identical schemas reuse the same compiled Policy class.

#### B-2.3 — Gate Condition

```
pytest -k 'dynamic_policy'
# Policy.from_config({'balance': ('Real', Decimal), 'amount': ('Real', Decimal)}, invariants=[...])
# must produce a valid, verifiable policy.
# 100 different tenant configs must compile without error in < 1s total.
```

---

### Phase B-3 — Cross-Policy Constraint Sharing

**Severity:** MEDIUM | **Effort:** 3 days | **Gaps closed:** G-09

#### B-3.1 — Problem

Common invariants (non-negative balance, non-suspended account) are duplicated across every policy. There is no mechanism to define a shared invariant library.

#### B-3.2 — Architecture Decision

- Add `@invariant_mixin` decorator to `ConstraintExpr` functions. Mixin functions called with the receiving Policy's field set, return `list[ConstraintExpr]`.
- Policy classes can compose mixins: `class TradePolicy(Policy, mixins=[AccountSafetyMixin, RiskLimitMixin])`.
- Mixin field requirements validated at compile time. Missing required fields raise `PolicyCompilationError` listing which mixin requires which field.

#### B-3.3 — Gate Condition

```
pytest -k 'invariant_mixin'
# AccountSafetyMixin must compose into two different Policy classes without duplication.
# Removing a required field must raise PolicyCompilationError at Guard.__init__ time,
# not at verify() time.
```

---

### Phase B-4 — Semantic Policy Versioning & Migration

**Severity:** MEDIUM | **Effort:** 3 days | **Gaps closed:** G-10

#### B-4.1 — Architecture Decision

- Replace `Meta.version` plain string with `Meta.semver: tuple[int, int, int]` validated at compile time.
- Add `PolicyMigration(from_version, to_version, field_renames, removed_fields)` declarative migration record.
- `Guard.verify()` checks `state_version` against policy semver. Stale schema → `Decision(allowed=False, reason='schema_version_mismatch')`.
- CLI command: `pramanix policy migrate --from 1.0.0 --to 1.1.0 --spec policy_migration.json`.

#### B-4.4 — Gate Condition

```
pytest -k 'policy_versioning'
# State dict with old schema version must return BLOCK with reason='schema_version_mismatch'.
# Migration spec must correctly rename fields.
```

---

## TRACK C — Concurrency & Deployment | Phases C-1 through C-5

---

### Phase C-1 — Alpine Linux Compatibility (musl libc)

**Severity:** MEDIUM | **Effort:** 2 days | **Gaps closed:** G-11

#### C-1.1 — Problem

`z3-solver` 4.16.0 ships glibc-compiled wheels. Alpine Linux (musl libc) causes segfaults and 3–10x slowdowns.

#### C-1.2 — Architecture Decision

- Maintain the current CI ban on Alpine images. This is correct and must not be removed.
- Add a runtime startup check in `guard.py` that detects musl libc (`/lib/ld-musl-*.so.1`) and raises `PramanixConfigurationError` before the first solve attempt.
- Provide a `Dockerfile.slim` variant using `python:3.13-slim-bookworm` with comments explaining why Alpine is banned.

#### C-1.3 — Gate Condition

```
# On Alpine container: PramanixConfigurationError raised at import time.
# On Debian container: import succeeds.
# CI must validate both.
```

---

### Phase C-2 — Z3 Expression Tree Caching (Spike)

**Severity:** HIGH | **Effort:** 2 days (spike only) | **Gaps closed:** G-12 (decision)

#### C-2.1 — Background

A previous spike concluded that expression tree caching saves ~0.3ms against an 8ms P50. This phase re-evaluates that decision with specific scope: caching Z3 AST at the policy level when the policy schema has not changed between calls.

#### C-2.2 — Spike Protocol

1. Implement `InvariantASTCache`: a dict keyed by `(policy_class_id, schema_hash)` storing pre-built Z3 formulas (serialized as S-expressions).
2. On each `verify()` call: check cache. If hit, deserialize and inject concrete field values. If miss, compile from scratch and populate cache.
3. Benchmark with 10,000 sequential calls to the same policy on the same schema. Measure P50, P95, P99 latency with and without cache.
4. Benchmark with 10,000 calls across 100 different policy schemas (cache thrash scenario).
5. Document result in `performance.md`.

**Decision rule:**
- Speedup > 20% on P50 AND no regression on cache-thrash → IMPLEMENT
- Speedup < 20% OR cache-thrash regression → REVERT and DOCUMENT

#### C-2.3 — Gate Condition

```
# performance.md must have a new "AST Cache Spike" section with exact benchmark numbers
# and a documented go/no-go decision. The decision is binding.
```

---

### Phase C-3 — ProcessPoolExecutor Pickling Safety

**Severity:** MEDIUM | **Effort:** 3 days | **Gaps closed:** G-13

#### C-3.1 — Problem

The pickling constraint for process mode is partially documented but not enforced at the API layer. A caller can pass a non-picklable object and receive a cryptic `PicklingError`.

#### C-3.2 — Architecture Decision

- Add pre-flight picklability check in `Guard.verify()` when `execution_mode='process'`: attempt `pickle.dumps(intent_dict)`. If it fails, return `Decision(allowed=False, reason='unpicklable_intent', remediation='Call model_dump() on your intent before passing to verify().')`.
- Add `Guard.assert_process_safe(intent)` diagnostic method listing which fields are not picklable.
- Update all integration adapters (LangChain, AutoGen) to call `model_dump()` before dispatching.

#### C-3.3 — Gate Condition

```
pytest -k 'process_pickle'
# Non-picklable object in process mode must return Decision(allowed=False, reason='unpicklable_intent').
# PicklingError must never propagate to the caller.
```

---

### Phase C-4 — Synchronous Circuit Breaker Interface

**Severity:** MEDIUM | **Effort:** 2 days | **Gaps closed:** G-14

#### C-4.1 — Problem

`AdaptiveCircuitBreaker.verify_async()` is the only public interface. Sync callers must wrap it with `asyncio.run()`, which fails inside existing event loops.

#### C-4.2 — Architecture Decision

- Add `AdaptiveCircuitBreaker.verify_sync(intent, state)` as a blocking wrapper using a dedicated thread-executor.
- If called from within a running asyncio event loop: raise `PramanixConfigurationError` directing the caller to use `verify_async()`.
- Document clearly: `verify_sync()` is for sync codebases only. New async code should always use `verify_async()`.

#### C-4.5 — Gate Condition

```
pytest -k 'circuit_breaker_sync'
# verify_sync from synchronous function returns valid Decision.
# verify_sync from inside asyncio loop raises PramanixConfigurationError.
```

---

### Phase C-5 — Distributed Circuit Breaker State (Multi-Replica)

**Severity:** HIGH | **Effort:** 5 days | **Gaps closed:** G-15

#### C-5.1 — Problem

In a 10-replica Kubernetes deployment, each pod has independent circuit breaker state. A downstream overload affecting 3 pods will not trip the circuit breaker on the other 7. The safety model degrades silently at scale.

#### C-5.2 — Architecture Decision

- Add `DistributedCircuitBreaker` as an optional drop-in replacement for `AdaptiveCircuitBreaker`.
- Backend interface: `DistributedStateBackend` with two implementations: `RedisDistributedBackend` (production) and `InMemoryDistributedBackend` (single-process testing).
- State synchronized: OPEN/HALF_OPEN/CLOSED status, failure_count, last_failure_time, success_count. Sync interval: configurable, default 1 second.
- Aggregation: if ANY replica is OPEN, all replicas report OPEN. Failure counts are summed. Conservative (fail-safe).
- Prometheus metrics emit aggregate (cross-replica) values in addition to per-replica values.

#### C-5.3 — Gate Condition

```
pytest -k 'distributed_cb'
# Simulate 3 replicas. Trip the breaker on replica 1.
# Within 2 sync intervals, replicas 2 and 3 must also report OPEN.
# InMemoryDistributedBackend must pass all the same tests.
```

---

## TRACK D — NLP / Translator Layer | Phases D-1 through D-4

---

### Phase D-1 — Consensus Check Robustness ⚠️ CRITICAL — DO FIRST

**Severity:** CRITICAL | **Effort:** 2 days | **Gaps closed:** G-16

#### D-1.1 — Problem

The dual-model consensus check uses exact JSON string equality:
```python
json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
```
This fails on semantically identical values that differ in float vs Decimal representation (`'500'` vs `'500.0'` vs `'5.0E+2'`). Causes spurious `ExtractionMismatchError` and blocks legitimate requests.

#### D-1.2 — Root Cause

Two different LLMs may represent the same number differently in JSON. `json.dumps` converts `Decimal('500')` to `'500'` on one model and `'500.0'` on another. String equality fails despite semantic equivalence.

#### D-1.3 — Architecture Decision

- Replace string equality consensus with semantic field-by-field comparison.
- Numeric fields: `Decimal(str(a)) == Decimal(str(b))` after normalization.
- String fields: `a.strip().casefold() == b.strip().casefold()` (configurable per-field via `FieldComparisonMode` enum).
- Boolean fields: `bool(a) == bool(b)`.
- Disagreement report: report which specific fields disagree and their respective values.
- Consensus strictness configurable: `STRICT` (current), `SEMANTIC` (new default), `NUMERIC_ONLY`.

#### D-1.4 — Implementation Steps

1. Replace the `json.dumps` equality check in `redundant.py` with a `_semantic_equal(a: dict, b: dict, schema: PolicySchema) -> tuple[bool, list[str]]` function.
2. `_semantic_equal` iterates over all keys in both dicts. For each key, apply the field-appropriate comparison. Collect disagreeing field names.
3. If any field disagrees: raise `ExtractionMismatchError` with `disagreeing_fields` list.
4. Add `ConsensusStrictness` enum to `GuardConfig` with `SEMANTIC` as default.
5. Update structured log schema: add `consensus_fields_checked`, `consensus_fields_agreed`, `consensus_fields_disagreed` to the translator log line.

#### D-1.5 — Gate Condition

```
pytest -k 'consensus_semantic'
# '500' vs '500.0' must produce AGREE.
# '500' vs '600' must produce DISAGREE.
# ALL PASS. Zero regressions.
```

---

### Phase D-2 — Additional LLM Backends

**Severity:** MEDIUM | **Effort:** 4 days | **Gaps closed:** G-17

#### D-2.1 — Architecture Decision

- Add `GeminiTranslator` (google-generativeai), `CohereTranslator` (cohere), `MistralTranslator` (mistralai).
- All new backends must implement the existing `Translator` Protocol exactly. No new methods.
- Add `LlamaCppTranslator` for local GGUF models via `llama-cpp-python`. Enables air-gapped enterprise deployments.
- Each backend is an optional dependency. Import failures raise `PramanixConfigurationError` with the `pip install` command.
- `RedundantTranslator` must work with any mix of backends.

#### D-2.2 — Gate Condition

```
# Integration tests with mock HTTP responses must pass for Gemini, Cohere, and Mistral.
# LlamaCppTranslator must pass with a local model fixture.
# RedundantTranslator(GeminiTranslator(...), OllamaTranslator(...)) must work.
```

---

### Phase D-3 — Input Size: Beyond 512 Characters

**Severity:** HIGH | **Effort:** 2 days | **Gaps closed:** G-18

#### D-3.1 — Problem

`sanitise_user_input()` silently truncates at 512 characters. Multi-step agent instructions are silently cut, causing incorrect field extraction without any error to the caller.

#### D-3.2 — Architecture Decision

- Remove the silent truncation. Replace with a configurable limit that raises `InputTooLongError` when exceeded: `PRAMANIX_MAX_INPUT_CHARS` (default: 4096).
- Add chunked extraction mode: for inputs > 4096 chars, split on sentence boundaries, extract from each chunk, and merge field values using the consensus logic. If values conflict across chunks: block.
- Add `InputTooLongError` to the exception hierarchy.

#### D-3.3 — Gate Condition

```
pytest -k 'input_size'
# An input of 600 chars with default config raises InputTooLongError.
# An input of 600 chars with max_input_chars=1000 succeeds.
# No silent truncation in any code path.
```

---

### Phase D-4 — Injection Score Calibration

**Severity:** HIGH | **Effort:** 5 days | **Gaps closed:** G-19

#### D-4.1 — Problem

The injection confidence score uses fixed additive coefficients (`+0.60`, `+0.20`, etc.) with no per-deployment calibration. In financial applications with high-entropy inputs (cryptocurrency addresses, SWIFT codes), the false positive rate is unacceptably high.

#### D-4.2 — Architecture Decision

- Add `InjectionScorer` Protocol with two implementations: `BuiltinScorer` (current) and `CalibratedScorer`.
- `CalibratedScorer` accepts a calibration dataset of `(input_text, is_injection: bool)` pairs. Fits a logistic regression model.
- Add `pramanix calibrate-injection --dataset ./calibration.jsonl --output ./scorer.pkl` CLI command.
- Persist the calibrated scorer as a pickle file loaded by `GuardConfig`. Falls back to `BuiltinScorer` if none provided.
- Document: calibration requires >= 1000 labeled examples per deployment domain.

#### D-4.3 — Gate Condition

```
pytest -k 'injection_calibration'
# CalibratedScorer trained on a 200-example fixture dataset must achieve >= 85% accuracy.
# pramanix calibrate-injection CLI command must produce a valid scorer.pkl.
```

---

## TRACK E — Identity & Audit | Phases E-1 through E-4

---

### Phase E-1 — Redis-Free Token Verification Backends

**Severity:** MEDIUM | **Effort:** 3 days | **Gaps closed:** G-20

#### E-1.1 — Problem

`RedisExecutionTokenVerifier` requires Redis 5+. Small deployments, serverless environments, and test setups cannot use it without running Redis.

#### E-1.2 — Architecture Decision

- Add `InMemoryExecutionTokenVerifier` for single-process deployments (development, testing, small production).
- Add `SQLiteExecutionTokenVerifier` for small production deployments. WAL-mode SQLite, thread-safe.
- Add `PostgresExecutionTokenVerifier` for deployments already running Postgres. Uses advisory locking for atomicity.
- All four backends implement the `ExecutionTokenVerifier` Protocol identically. Switching requires only a config change.

#### E-1.3 — Gate Condition

```
pytest -k 'token_verifier'
# All four backends must pass the same compliance test suite.
# A token used once must be rejected on second use.
# A token must expire correctly.
```

---

### Phase E-2 — Merkle Anchor Pruning & Archival

**Severity:** MEDIUM | **Effort:** 3 days | **Gaps closed:** G-21

#### E-2.1 — Problem

`PersistentMerkleAnchor` grows without bound. After 1 year of 100 RPS operation, the anchor file exceeds 50GB.

#### E-2.2 — Architecture Decision

- Add `MerkleArchiver` that: (1) flushes a time-bounded segment to an archive file (`.merkle.archive.YYYYMMDD`), (2) computes and stores the root hash of the archived segment, (3) replaces archived entries with a single checkpoint entry.
- Archived segments are cryptographically verifiable: `pramanix audit verify --archive ./archive-2025-01.merkle`.
- `PRAMANIX_MERKLE_SEGMENT_DAYS` (default: 30) controls archival frequency.
- `PRAMANIX_MERKLE_MAX_ACTIVE_ENTRIES` (default: 100,000) triggers automatic archival.

#### E-2.3 — Gate Condition

```
# A chain of 200,000 entries must archive correctly, leaving <= 100,000 active entries.
# pramanix audit verify on the archived segment must succeed.
# Root hash of the archived segment must match the checkpoint entry in the active chain.
```

---

### Phase E-3 — KMS / HSM Integration for Ed25519 Keys ⚠️ CRITICAL

**Severity:** CRITICAL | **Effort:** 7 days | **Gaps closed:** G-22

#### E-3.1 — Problem

Ed25519 key management is entirely manual. For institutional clients (banking, healthcare, sovereign funds), enterprise security policy mandates HSM or cloud KMS for all signing keys.

#### E-3.2 — Architecture Decision

- Add `KeyProvider` Protocol: `load_private_key()`, `load_public_key()`, `rotate_key()`, `key_version()`.
- Implement `FileKeyProvider` (current behavior, now explicit) for backward compatibility.
- Implement `AwsKmsKeyProvider` using boto3. Signs using KMS Sign API.
- Implement `AzureKeyVaultKeyProvider` using azure-keyvault-keys.
- Implement `GcpKmsKeyProvider` using google-cloud-kms.
- Implement `HashiCorpVaultKeyProvider` using hvac.
- All KMS providers implement automatic key rotation. Historical signatures remain verifiable with the old public key (key version embedded in signature metadata).

#### E-3.3 — Gate Condition

```
pytest -k 'kms_provider'
# With mocked AWS KMS backend, PramanixSigner must produce valid signatures.
# PramanixVerifier must verify them.
# Key rotation must not invalidate historical signatures.
```

---

### Phase E-4 — Structured Audit Sinks (Kafka, S3, SIEM)

**Severity:** HIGH | **Effort:** 5 days | **Gaps closed:** G-23

#### E-4.1 — Problem

Audit logs go to structlog stdout only. Enterprise customers want native Kafka, S3, and SIEM (Splunk, Datadog) sinks.

#### E-4.2 — Architecture Decision

- Add `AuditSink` Protocol: `emit(decision: SignedDecision) -> None`.
- Implement `KafkaAuditSink` (confluent-kafka), `S3AuditSink` (boto3), `SplunkHecAuditSink` (HTTP Event Collector), `DatadogAuditSink` (datadog-api-client), and `StdoutAuditSink` (current default).
- `GuardConfig` accepts a list of sinks. All sinks receive every decision. Sink failures are logged but **never** propagate to the caller.
- Add buffer + retry for async sinks: bounded queue (default: 10,000) with configurable flush interval. Queue overflow: emit `pramanix_audit_sink_overflow_total` metric.

#### E-4.3 — Gate Condition

```
pytest -k 'audit_sink'
# KafkaAuditSink must emit to a mock Kafka topic.
# S3AuditSink must upload to a mock S3 bucket.
# Sink failure must not affect the Decision returned to the caller.
```

---

## TRACK F — Ecosystem Integrations | Phases F-1 through F-4

---

### Phase F-1 — New Framework Integrations

**Severity:** HIGH | **Effort:** 6 days | **Gaps closed:** G-24

#### F-1.1 — Scope

Add production-grade integration adapters for CrewAI, DSPy, Haystack, Semantic Kernel, and Pydantic AI.

#### F-1.2 — Architecture Decision

- Each adapter follows the same pattern as the existing LangChain adapter.
- All adapters must implement both sync and async variants.
- `CrewAI` adapter: `PramanixTool(BaseTool)` that verifies the tool's input before execution.
- `DSPy` adapter: `PramanixModule(dspy.Module)` that wraps a `dspy.Predict` call with pre-verification.
- `Pydantic AI` adapter: `PramanixValidator` integrating with Pydantic AI's tool validation hooks.
- Each adapter ships with a minimum 5 integration tests using mocked LLM responses.

#### F-1.3 — Gate Condition

```
pytest -k 'integration'
# Each adapter: (1) constructs, (2) calls with valid intent → ALLOW,
# (3) calls with invalid intent → BLOCK.
# ALL 5 adapters pass. Existing LangChain/AutoGen tests still pass.
```

---

### Phase F-2 — Sync @guard Decorator

**Severity:** HIGH | **Effort:** 2 days | **Gaps closed:** G-25

#### F-2.1 — Problem

The `@guard` decorator raises `TypeError` when applied to synchronous functions. This blocks adoption in Django views, Flask endpoints, and Celery tasks.

#### F-2.2 — Architecture Decision

- Detect at decoration time via `asyncio.iscoroutinefunction`. If async: existing behavior. If sync: wrap using the C-4 sync interface.
- The decorator signature is identical for sync and async functions — no API change.
- Add `@guard(execution_mode='sync')` as an explicit override.

#### F-2.3 — Gate Condition

```
pytest -k 'sync_decorator'
# @guard on sync function works. TypeError not raised for any sync function.
# Existing async decorator tests still pass.
```

---

### Phase F-3 — gRPC Interceptor & Kafka Consumer Guard

**Severity:** MEDIUM | **Effort:** 5 days | **Gaps closed:** G-26

#### F-3.1 — Architecture Decision

- `PramanixGrpcInterceptor(grpc.ServerInterceptor)`: extracts gRPC request payload, calls `Guard.verify()`, returns `PERMISSION_DENIED` on BLOCK.
- `PramanixKafkaConsumerGuard`: middleware wrapper for `confluent-kafka` `Consumer.poll()`. Blocked messages routed to a dead-letter topic (configurable).
- Both adapters ship with proto fixture files and Docker Compose configs for local testing.

#### F-3.2 — Gate Condition

```
pytest -k 'grpc or kafka_guard'
# gRPC interceptor must BLOCK non-compliant request with PERMISSION_DENIED.
# Kafka guard must route blocked message to DLQ.
```

---

### Phase F-4 — Kubernetes Admission Webhook Controller

**Severity:** MEDIUM | **Effort:** 6 days | **Gaps closed:** G-27

#### F-4.1 — Architecture Decision

- `PramanixAdmissionWebhook`: a FastAPI service implementing the Kubernetes `ValidatingAdmissionWebhook` interface.
- Receives `AdmissionReview` requests, extracts resource spec, constructs Guard intent, calls `Guard.verify()`, returns ALLOW or DENY.
- Packaged as a Helm chart with TLS certificate provisioning (cert-manager) and RBAC manifests.

#### F-4.2 — Gate Condition

```
# In a kind (Kubernetes in Docker) cluster:
# Non-compliant Pod admission request must be DENIED.
# Compliant Pod must be ALLOWED.
# Helm chart install must succeed without errors.
pytest -k 'k8s_webhook'
```

---

## TRACK G — Developer Experience | Phases G-1 through G-3

---

### Phase G-1 — PyPI Publication ⚠️ CRITICAL — Blocks All External Adoption

**Severity:** CRITICAL | **Effort:** 3 days | **Gaps closed:** G-28

#### G-1.1 — Problem

v0.9.0 and v1.0 are install-from-source only. `pip install pramanix` returns a package not found error. This is the single largest adoption blocker. Enterprise evaluation teams will not install from GitHub source in production.

#### G-1.2 — Architecture Decision

- Publish `pramanix` to PyPI under the existing AGPL-3.0 + Commercial dual license.
- CI/CD: GitHub Actions workflow publishes to PyPI on every version tag using OIDC trusted publishing (no stored API key). SLSA Level 3 and Sigstore provenance already in place.
- Release checklist: (1) Update `pyproject.toml` version. (2) Update CHANGELOG. (3) Run full test suite. (4) Tag the commit. (5) CI publishes automatically.

#### G-1.3 — Implementation Steps

1. Create PyPI account and register `'pramanix'` package name.
2. Add PyPI trusted publisher to the GitHub Actions OIDC configuration.
3. Create `.github/workflows/publish.yml`: trigger on tags matching `v*`, run tests, `poetry build`, upload with twine using OIDC.
4. Add README badge: `![PyPI version](https://img.shields.io/pypi/v/pramanix)`.
5. Publish v1.0.0 to PyPI. Verify `pip install pramanix==1.0.0` in a clean virtualenv.

#### G-1.4 — Gate Condition

```
pip install pramanix  # in a clean Python 3.13 virtualenv
python -c "from pramanix import Guard; print('OK')"
# Installed version matches the git tag.
# PyPI page shows the correct README and AGPL-3.0 license.
```

---

### Phase G-2 — Policy Dry-Run / Simulate CLI Command

**Severity:** HIGH | **Effort:** 4 days | **Gaps closed:** G-29

#### G-2.1 — Problem

There is no way to test a policy against sample data without writing Python code.

#### G-2.2 — Implementation

```bash
pramanix simulate --policy my_policy.py:TradePolicy --input sample.json
pramanix simulate --policy my_policy.py:TradePolicy --input batch.jsonl --output results.jsonl
pramanix simulate --policy my_policy.py:TradePolicy --fuzz 1000  # Hypothesis-powered random inputs
```

Output format: for each input, print ALLOW/BLOCK, violated invariants, and the proof/counterexample. Batch mode produces a summary: N ALLOW, M BLOCK, K ERRORS.

#### G-2.3 — Implementation Steps

1. Add `simulate` subcommand to `cli.py` using Click.
2. Policy loading: `importlib.import_module` the module path, `getattr` the class name, instantiate `Guard` with the policy.
3. Input loading: JSON (single dict), JSONL (one dict per line), or CSV (headers become field names).
4. Fuzz mode: use Hypothesis strategies inferred from the policy's field types. Report any inputs that cause Python exceptions (these are policy bugs, not Z3 BLOCK decisions).
5. Output: colorized terminal output for single inputs. JSONL for batch. Prometheus metrics emitted during batch run.

#### G-2.4 — Gate Condition

```
pytest -k 'cli_simulate'
pramanix simulate \
  --policy tests/fixtures/trade_policy.py:TradePolicy \
  --input tests/fixtures/sample_trade.json
# Must print ALLOW or BLOCK correctly.
# --fuzz 100 must complete without Python exceptions.
```

---

### Phase G-3 — Policy JSON Schema Export & Web Validator

**Severity:** MEDIUM | **Effort:** 5 days | **Gaps closed:** G-30

#### G-3.1 — Implementation

- Add `pramanix schema export --policy my_policy.py:TradePolicy --output schema.json` CLI command.
- Schema format: JSON Schema draft 2020-12 with `x-pramanix-z3-sort` extensions for type metadata.
- The exported schema can be used with any JSON Schema validator to pre-validate intent dicts before calling `Guard.verify()`.
- Stretch goal: `pramanix web-ui` command that launches a local FastAPI server at `localhost:8080` with a Swagger UI interface for testing policies via browser.

#### G-3.2 — Gate Condition

```
pytest -k 'schema_export'
pramanix schema export \
  --policy tests/fixtures/trade_policy.py:TradePolicy \
  --output /tmp/schema.json
# Produces valid JSON Schema.
# Sample intent dict validates against it correctly.
```

---

## §11 — LLM Agent Working Instructions

This section is specifically for LLM code agents executing phases from this document. **Read it completely before beginning any implementation work.**

### 11.1 — Pre-Flight Protocol

Before executing any phase, perform these steps in order:

1. Read this document's §0 in full.
2. Read the relevant phase section completely before writing any code.
3. Read the current state of the files you will modify: `guard.py`, `expressions.py`, `transpiler.py`, `solver.py`, `worker.py`, `redundant.py`, `cli.py` as applicable.
4. Run `pytest --tb=short > /tmp/baseline.txt 2>&1` to capture the current baseline. Verify it shows >= 1,821 passing tests before proceeding.
5. Create a git branch: `git checkout -b phase-{ID}` (e.g. `phase-d1`).

### 11.2 — Implementation Protocol

- Execute implementation steps in the numbered order given in the phase. Do not reorder or parallelize unless the phase explicitly states `[PARALLEL OK]`.
- After each step, run the test command listed in "Tests to Add After Each Step" before proceeding to the next step.
- All new code must include type annotations (Python 3.13 style: `list[str]` not `List[str]`).
- All new public functions and classes must have docstrings (Google style: Args, Returns, Raises).
- All new environment variables must be added to `GuardConfig` with sensible defaults. Never read `os.environ` directly outside `GuardConfig`.
- All new exception types must be added to `exceptions.py` and exported from `__init__.py`.
- All new configuration options must be documented in `deployment.md` under the Environment Variables section.

### 11.3 — Gate Verification Protocol

1. Run the exact gate command from the phase's Gate Condition section.
2. Run the full test suite: `pytest --tb=short -q 2>&1 | tail -20`.
3. Verify test count is >= 1,821 (baseline) + (new tests in this phase).
4. Run coverage: `pytest --cov=pramanix --cov-report=term-missing -q 2>&1 | grep TOTAL`. Verify >= 95%.
5. Only when all four checks pass: `git commit -m 'Phase {ID}: {title} [gate: PASS]'`.

### 11.4 — Hard Stops

Stop immediately and report to the human engineer if you encounter any of the following:

- Any exception path that could return `Decision(allowed=True)` — this is a P0 safety defect.
- A test that requires modifying the existing 1,821 baseline tests to pass — this indicates a breaking change.
- A change to the `Decision` dataclass fields or serialization format — this breaks the audit trail.
- A change to the canonical hash computation — this invalidates historical signatures.
- Any performance regression > 10% on the benchmark suite.
- A Windows-specific failure (`freeze_support`, pickling, encoding) — fix it before committing, not after.

### 11.5 — Code Quality Standards (Non-Negotiable)

| Standard | Requirement |
|---|---|
| Type annotations | 100% of new public functions. `mypy --strict` must pass. |
| Docstrings | Every new public class and function. Format: Google style (Args, Returns, Raises). |
| Error messages | Every exception message must include: what went wrong, what the caller can do, and the relevant config variable if applicable. |
| Test coverage | Every new code path must have at least one positive test (correct behavior) and one negative test (failure behavior). |
| Windows compat | No bash-specific syntax. No `os.system()`. Use subprocess with explicit argument lists. No non-ASCII print characters. |
| Decimal precision | All monetary amounts use `Decimal`. Never `float`. Float-to-Z3 conversion must use `as_integer_ratio()`, not `float()`. |
| Fail-safe | Every new `try/except` block that catches `Exception` must log with structlog and return `Decision(allowed=False)`. |

### 11.6 — Phase Reporting Format

After each phase gate passes, output this block:

```
PHASE {ID} COMPLETE
─────────────────────────────────────────
Gaps closed:     {G-XX, G-YY}
New tests added: {N}
Total tests:     {N} (baseline was 1,821)
Coverage:        {X}%
Gate command:    {exact command that passed}
Branch:          phase-{id}
Commit:          {git commit hash}
Next phase:      {next phase ID and title}
─────────────────────────────────────────
```

If a gate FAILS:

```
PHASE {ID} GATE FAILED
─────────────────────────────────────────
Failure:     {test name and error}
Root cause:  {your diagnosis}
Fix applied: {what you changed}
Retrying gate...
─────────────────────────────────────────
```

---

## §12 — Post-Remediation Competitive Position

Upon completion of all phases, the following competitive gaps will be closed:

| Competitor | Their Current Edge | Post-Remediation Status |
|---|---|---|
| Guardrails AI | On PyPI, large community, extensive GUI, many validators | Closed: PyPI published (G-1), simulate CLI (G-2), web UI (G-3). Pramanix adds formal proofs Guardrails can never match. |
| NeMo Guardrails (NVIDIA) | Colang DSL for multi-turn dialogue-level flow control | Partially closed: Pramanix is per-call by design. Session-scoped policies (Track B) close the gap for stateful workflows. |
| LlamaGuard (Meta) | Fine-tuned LLM classifier for subjective content moderation | Not contested: targets fuzzy content. Pramanix targets arithmetic correctness. Complementary, not competitive. |
| Rebuff | Purpose-built injection detection with crowd-sourced patterns | Closed: D-4 (CalibratedScorer) + D-1 (semantic consensus) closes the injection detection quality gap. |
| Open Policy Agent (OPA) | Mature, K8s-native, Rego more expressive for RBAC/ABAC | Partially closed: F-4 (K8s admission webhook) makes Pramanix K8s-native. Pramanix's SMT proofs remain unmatched for arithmetic safety. |

### 12.1 — The Permanent Moat (Unreachable by Competitors)

These properties cannot be replicated without rebuilding from scratch:

- **Formal SMT-backed ALLOW:** Every approval is a mathematical theorem. No probabilistic classifier can make this claim.
- **Sealed execution tokens with TOCTOU mitigation:** Unique in the field. Competitors have not identified this attack vector.
- **Merkle + Ed25519 cryptographic audit chain:** No other Python guardrail library ships this. Required for HIPAA, SOX, Basel III audit defensibility.
- **Fail-safe as architectural invariant:** `verify()` cannot raise. Competitors' error handling is probabilistic. Pramanix's is provable.

---

> **FINAL NOTE:** The architecture is already production-grade. The distribution is not. **G-1 (PyPI) is the single highest-leverage action available. Ship it first. Everything else is optimization.**

---

*Pramanix SDK — Principal Engineering Remediation & Elevation Plan | v1.0*
*Owner: Viraj Jain | Confidential & Proprietary*