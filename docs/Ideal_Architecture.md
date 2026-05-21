# Pramanix — Ideal Architecture Vision
### A Principal-Senior Software Architect's Blueprint

**Author context:** This document is written from the position of a principal-level
software architect who has read every line of the current codebase, the PROOF_DOSSIER,
ARCHITECTURE_NOTES, flaws.md, CHANGELOG, MIGRATION, PUBLIC_API, and THESIS — and who
has also worked with or against LangChain, LangGraph, LlamaIndex, NeMo Guardrails, and
Guardrails AI in production environments. Every recommendation below is grounded in what
the code actually does today, not in what the marketing narrative claims.

---

## Part 0 — Ground Rules for This Document

**Rule 1.** No aspirational language that does not connect to a concrete engineering
decision. "World-class" means nothing. "Replace every bare `except Exception: pass`
in `guard.py` with a named counter increment and a WARNING log" means something.

**Rule 2.** The ideal version of Pramanix is not a bigger version of Pramanix. It is
a *sharper* version with a *broader platform reach*. Those two directions pull against
each other and must be managed explicitly.

**Rule 3.** The six-product framing in the ideal document (Core, Safety, Flow, Memory,
Cloud, Studio) is correct in spirit but wrong in sequencing. You cannot build Flow
before you have proven Safety. You cannot build Studio before Flow is stable. Sequence
matters more than ambition.

**Rule 4.** Every existing open item in the flaws.md elimination blueprint is a
pre-condition for the next phase of growth. Zero open items is not a stretch goal.
It is the admission ticket.

---

## Part 1 — Honest Assessment of Current State as Starting Point

Before designing the ideal future, a principal architect must be precise about what
the foundation actually is.

### What is genuinely strong (build on these)

**The Z3 core is production-grade.** Two-phase solving (shared solver for SAT,
per-invariant attribution for UNSAT) is the correct design. Exact Decimal arithmetic
via `as_integer_ratio()` → `z3.RatVal()` is the right approach for financial invariants.
Thread-local Z3 contexts are correctly managed. The fail-closed contract enforced at two
independent structural levels (`guard.py` outermost try/except + `Decision.__post_init__`
raising on `allowed=True` with `status != SAFE`) is architecturally sound and
adversarially tested. This is the strongest part of the system and must be preserved
with zero compromise.

**The audit chain design is correct.** Ed25519/RS256/ES256 signing, Merkle anchoring,
canonical SHA-256 decision hashing with `orjson OPT_SORT_KEYS`, and a self-contained
offline verifier are all correct choices. The provenance model (`ProvenanceChain` with
HMAC-SHA256 hash-linking) is a genuine differentiator. No competitor offers this.

**The test discipline is exceptional.** 4,118 tests, 98.26% branch coverage, 166 skips
that are all justified (Docker-gated or optional-dep-gated), 0 failures, Hypothesis
property tests for core arithmetic paths, adversarial suite with real threat vectors.
For a v1.0 solo project this is remarkable. This culture must be protected aggressively
as the codebase grows.

**The flaws.md self-audit is itself an asset.** The document exists, is brutally honest,
and is maintained. This is rarer and more valuable than most architects acknowledge.
Any team that does not produce this kind of document about their own system is flying
blind.

### What is genuinely weak (fix before building on top)

**The open items in flaws.md are not minor cleanup.** They include:
- Z3 trust boundary violation (patching `z3.Solver` instead of injecting a SolverProtocol)
- No `SolverProtocol` abstraction — the Z3 library is a concrete dependency, not an
  injected interface, which means any test that needs to simulate solver failure must
  patch the C-library binding directly. This is a design flaw in the test architecture,
  not a test flaw.
- No injectable clock in `execution_token.py` (9 direct `time.time()` call sites)
- No concurrent-mutation integration test for the circuit breaker lock after the
  `@functools.cached_property` fix
- `re2` fallback to stdlib `re` still executes the vulnerable path; a SecurityWarning
  is now emitted but the security-posture degradation still occurs
- `hypothesis.assume()` exclusions in `test_sanitise_properties.py` leave the
  sanitizer's most adversarially relevant inputs (empty, single-char, injection-prefix,
  overlong) unexercised by property tests
- Benchmarks are v0.8.0 on a consumer laptop. The v1.0.0 number does not exist.
- Layer 4 LLM consensus is never exercised in CI with real LLMs. This is the most
  important anti-injection claim and the least validated component.
- The `_emit_field_seen_metric()` silent swallow (`except Exception: pass`) is still open
  as of flaws.md §4.16.
- 4 stub integrations (CrewAI, DSPy, Haystack, Semantic Kernel) ship real-looking class
  names with no functional test coverage.

**The AGPL-3.0 license is not a technical problem but it is the most important problem.**
Nothing else on this list matters for enterprise adoption until this is resolved. Apache-2.0
or a dual-license (AGPL-3.0 for open-source, commercial for enterprise) is the minimum
viable licensing strategy. A principal architect must say this clearly: the technical
quality is already competitive enough for enterprise use. The license is the only reason
enterprise legal teams will reject it before architecture review starts.

---

## Part 2 — The Correct Mental Model for Pramanix's Role

The ideal document describes Pramanix as "the market's default decision-control plane
for AI systems." This framing is correct but must be made concrete.

A decision-control plane is not an LLM orchestration framework. It is not a retrieval
stack. It is not a dialogue manager. It sits between the LLM's output and the real world's
state mutation, and it answers exactly one question with mathematical precision:

**"Is this specific proposed action consistent with all stated invariants against the
current verified state, and is there a signed, replayable proof of that decision?"**

LangChain answers: "How do I chain LLM calls together?"
LangGraph answers: "How do I manage state across a multi-step agent graph?"
LlamaIndex answers: "How do I retrieve and synthesize information?"
NeMo answers: "How do I keep conversational AI on-topic and safe?"
Guardrails AI answers: "How do I validate LLM outputs against schemas and content rules?"
Pramanix answers: **"Was this action formally proven safe before it was allowed to execute,
and can I prove that to a regulator?"**

These are not competing answers to the same question. They are answers to different
questions. The ideal Pramanix is not a bigger version of any of those frameworks. It is
the governance layer that wraps around all of them.

**The strategic insight:** Every one of those frameworks produces actions. None of them
formally proves those actions are safe. Pramanix is the layer that closes that gap. The
ideal Pramanix is not trying to be LangChain. It is trying to be the thing that makes
LangChain safe enough to use in a regulated environment.

This reframing changes the competitive analysis entirely. Pramanix does not need to match
LangGraph's orchestration depth. It needs to prove that LangGraph workflows can be
governed. It does not need to match LlamaIndex's retrieval ergonomics. It needs to prove
that LlamaIndex RAG outputs can be checked before they cause side effects.

---

## Part 3 — The Platform Architecture (Phased, Realistic, Sequenced)

### Phase 0 — Zero Debt (Before Any Growth)
**Duration: 3–4 months. Non-negotiable prerequisite.**

This phase produces no new features. It closes every open item in flaws.md and
establishes the engineering foundation that every subsequent phase depends on.

#### 0.1 SolverProtocol Injection

Extract `SolverProtocol` from `solver.py`:

```python
class SolverProtocol(Protocol):
    def solve(
        self,
        intent_data: dict[str, Any],
        state_data: dict[str, Any],
        timeout_ms: int,
    ) -> SolveResult: ...
```

Inject it into `Guard` via `GuardConfig.solver`. The default is the real Z3 solver.
Tests inject a `FailingSolverStub` that implements the protocol. No test ever patches
`z3.Solver` again. This is not optional — it is the prerequisite for all distributed
and edge deployment scenarios in later phases.

#### 0.2 ClockProtocol Injection

Extract a `_Clock` protocol with a single `now() -> float` method. Inject it into
`ExecutionToken`, `RedisExecutionTokenVerifier`, `PostgresExecutionTokenVerifier`,
and `SQLiteExecutionTokenVerifier` via their constructors. The default is `time.time`.
Tests inject a `FakeClock` with controllable time. This closes all 9 direct `time.time()`
call sites without an injection mechanism.

#### 0.3 re2 Hard Boundary in Hardened Mode

Add a `GuardConfig.require_re2: bool = False` field. When `True`, if `re2` is not
available, `Guard.__init__` raises `ConfigurationError` rather than falling back.
Deployments that care about ReDoS safety set this flag. The existing fallback behavior
is preserved for backward compatibility but is now explicitly opt-in, not silent.

#### 0.4 Concurrent-Mutation Integration Test for Circuit Breaker

Implement `test_circuit_breaker_lock_linearizability.py`:
200 concurrent asyncio coroutines all attempt state transitions on the same
`AdaptiveCircuitBreaker` instance simultaneously using `asyncio.Barrier` (Python 3.11+).
Assert that the final state count is exactly 200 with no concurrent write corruption.
This validates the `@functools.cached_property` lock fix under real concurrency.

#### 0.5 Hypothesis Sanitizer Coverage

Remove `assume(len(s) >= 10)`, `assume(len(s) <= 512)`, `assume(len(s) > 0)`, and
`assume(s.strip())` from `test_sanitise_properties.py`. Replace them with explicit
deterministic edge-case tests for empty string, single character, injection-prefix
string, whitespace-only, and boundary-length inputs. Add property test for
"every injection-prefix string is blocked or flagged before reaching Z3."

#### 0.6 `_emit_field_seen_metric()` Fix

Replace the silent `except Exception: pass` at `guard.py` line ~250 with:
```python
except Exception as _exc:
    _log.warning(
        "field_seen metric emit failed: %s",
        type(_exc).__name__,
        exc_info=_exc,
    )
```
This is a three-line change. The fact that it is still open is a signal about
prioritization discipline, not technical difficulty.

#### 0.7 Live LLM CI Integration

Add a nightly CI job (separate from the main suite) that runs the injection adversarial
tests against real LLM API endpoints using containerized Ollama with a known-bad model
(e.g., a fine-tuned model that is adversarially susceptible). The test suite must
document its adversarial failure rate. "Our injection tests only pass with stub
translators" is not an acceptable claim for a security library.

#### 0.8 License Decision

This is the most important non-engineering task in Phase 0. Make the decision:
- Apache-2.0 full re-license (simplest; loses copyleft protection)
- Dual license: AGPL-3.0 for open source, commercial for enterprise use
  (Business Source License pattern, common in database and developer-tool companies)
- Keep AGPL-3.0 and accept that Fortune-500 enterprises will not use it commercially
  (this is a valid strategic choice but must be made explicitly, not by default)

A principal architect recommends the dual-license approach: Apache-2.0 for any project
with fewer than N users or below an annual revenue threshold, commercial for enterprises
above that threshold. This is the approach taken by HashiCorp (before BSL), Elastic,
and Redis Labs. It preserves community adoption while creating a commercial revenue path.

#### 0.9 Server-Class Benchmarks

Re-run all benchmarks on v1.0.0 on a standardized CI environment (minimum: 8 vCPU,
32 GB RAM, SSD storage, Linux). Publish P50/P95/P99 latency, throughput under concurrent
load, cold-start times, and memory growth per 100K decisions. Retire the v0.8.0 consumer
laptop numbers from all public documentation. Publish the benchmark script so results
are reproducible by anyone.

#### 0.10 Remove or Productize the Stub Integrations

The four stub integrations (CrewAI, DSPy, Haystack, Semantic Kernel) must either be
completed with real test coverage or removed from the public API. Shipping class names
that look functional but have no validated behavior against real framework versions is
a trust liability. The decision is: build it or cut it. Keeping stubs is not a third
option.

**Phase 0 exit criteria:** All 36 elimination blueprint items closed. Zero `# type: ignore`
suppression that is not documented with an explicit architectural justification comment.
Zero bare `except Exception: pass` in production source. Live LLM adversarial CI passing.
License decision made and implemented. Server-class benchmark published.

---

### Phase 1 — The Governance Core (The Real Foundation)
**Duration: 4–6 months. Builds on Phase 0.**

Phase 1 is about making the core engine not just correct but *composable* — so that
it can be embedded inside LangChain, LangGraph, LlamaIndex, NeMo, and Guardrails AI
workflows without ceremony.

#### 1.1 The Guard-as-Middleware Pattern

Every major AI framework has a middleware or hook system:
- LangChain: `BaseCallbackHandler`, `@tool` decorator
- LangGraph: node pre/post hooks, state reducers
- LlamaIndex: `BaseQueryPipeline` stages, `BasePostprocessor`
- AutoGen: `ConversableAgent` message interceptors

Pramanix must provide a first-class adapter for each that requires zero knowledge of
Pramanix internals. The pattern is:

```python
# LangGraph integration — one line
graph = StateGraph(AgentState)
graph.add_node("transfer", pramanix.langraph.guarded(transfer_fn, policy=TransferPolicy))

# LlamaIndex integration — one line
engine = pramanix.llamaindex.guarded(VectorStoreIndex.from_documents(docs), policy=AccessPolicy)

# AutoGen integration — one line
agent = pramanix.autogen.guarded(AssistantAgent("banker"), policy=BankingPolicy)
```

These are not stub classes. Each one is a production-grade, fully-tested adapter that
intercepts the framework's action dispatch, runs `Guard.verify()`, and either allows
execution or raises the framework's native error type with the Decision object attached.

The implementation philosophy: write the adapter test first against the real framework,
then write the adapter. No stubs, no fakes.

#### 1.2 Policy Registry and Distribution

Currently, a Guard must be instantiated with a Policy class reference. In a distributed
system with multiple services and hundreds of agents, this is operationally fragile:
policy changes require redeployment, there is no central visibility into which policy
version is running where, and policy drift between replicas is only detectable if
`expected_policy_hash` is configured.

The ideal architecture introduces a **PolicyRegistry** — a versioned, content-addressed
store for compiled policy artifacts:

```
┌─────────────────────────────────────────────────────────────┐
│  PolicyRegistry                                              │
│  - policy_name → (semver, policy_hash, compiled_artifact)   │
│  - drift detection: alerts when running hash ≠ registry hash │
│  - hot reload: Guard polls registry; applies new version     │
│    via shadow evaluation before promoting                    │
│  - audit: every policy version change is a signed record    │
└─────────────────────────────────────────────────────────────┘
```

The PolicyRegistry is a thin service, not a database. It stores and serves compiled
`PolicyIR` artifacts (from the existing IR compiler). It does not store Python source.
It does not execute code. It is content-addressed: the key is the SHA-256 of the
compiled artifact. This means the registry is append-only and tamper-evident by design.

Implementation: start with a file-based registry (`~/.pramanix/registry/`), then add
an HTTP server as an optional extra (`pip install pramanix[registry]`), then add
Redis-backed and S3-backed storage. The protocol is the same at every layer.

#### 1.3 Policy Linter and Semantic Verifier

The current `PolicyAuditor` does static field-coverage analysis. That is useful but
insufficient. The ideal linter answers questions that engineers actually have:

- "Which inputs can reach the ALLOW branch?" → Counterexample generation via Z3 model
- "Is this invariant ever satisfiable?" → Z3 sat check with no concrete values
- "If I change this threshold, which existing test cases change outcome?" → Differential
  analysis using the shadow evaluator
- "Does this policy correctly encode what the compliance document says?" → This is the
  hard one; it requires semantic verification that no automated tool can fully answer,
  but the linter can surface likely encoding errors (e.g., `>=` vs `>` at boundary values,
  missing field coverage)

The linter is a CLI command (`pramanix lint --policy my_policy.py`) that produces a
human-readable report with specific, actionable feedback. It runs in under 1 second for
any policy with fewer than 50 invariants.

#### 1.4 Execution Token as First-Class API

The execution token system exists (HMAC-SHA256, single-use, TOCTOU gap closure) but is
not prominently positioned. In Phase 1, it becomes a mandatory part of the governance
story:

```python
# The complete safe execution pattern — Pramanix enforces this
decision = await guard.verify(intent, state)
token = signer.mint(decision, ttl_seconds=30)

# Later, at execution boundary:
if not verifier.consume(token, expected_state_version=state.state_version):
    raise ExecutionTokenExpiredError("State changed or token replayed")

await actually_execute(intent)
```

This pattern is documented prominently, tested with realistic race conditions, and
has reference implementations for FastAPI, LangChain, and LangGraph.

#### 1.5 Trace and Replay Infrastructure

Every `Decision` is already signed and hashable. Phase 1 adds **trace capture and
replay** — the ability to record a sequence of decisions during a workflow execution
and replay them later to verify behavior:

```python
with pramanix.trace.capture(guard, "workflow_run_20260521") as trace:
    decision_1 = await guard.verify(intent_1, state_1)
    decision_2 = await guard.verify(intent_2, state_2)
    # ...

# Later, in a different environment:
replay = pramanix.trace.replay("workflow_run_20260521", guard)
assert replay.all_decisions_match()  # Deterministic verification
```

This is only possible because Pramanix decisions are deterministic given the same
inputs. It is a uniquely Pramanix capability. No competitor can offer this because no
competitor has deterministic, signed, replayable decision objects.

**Phase 1 exit criteria:** All major framework adapters (LangChain, LangGraph, LlamaIndex,
AutoGen) are production-tested against real framework versions. PolicyRegistry is functional
with file-based and HTTP-based backends. Policy linter is in the CLI. Execution token
pattern is prominently documented with reference implementations. Trace/replay works for
the banking and healthcare examples.

---

### Phase 2 — The Safety Layer (Production-Grade Text and Multimodal Safety)
**Duration: 4–6 months. Builds on Phase 1.**

Phase 2 is where Pramanix closes the gap with NeMo Guardrails and Guardrails AI on
content safety. But it does so in a way that is architecturally distinct: Pramanix
does not replace NeMo or Guardrails AI. It *wraps* them as audit-signed, policy-governed
components.

#### 2.1 SafetyValidator Protocol

Introduce a `SafetyValidator` protocol that makes any text safety check a first-class
Pramanix component:

```python
class SafetyValidator(Protocol):
    name: str

    def validate(self, text: str) -> SafetyResult: ...
    # SafetyResult: passed: bool, reason: str | None, confidence: float
```

Built-in implementations:
- `PIIValidator` — wraps the existing `PIIDetector` (promote from beta to stable)
- `ToxicityValidator` — wraps the existing `ToxicityScorer` (promote from beta to stable)
- `SemanticSimilarityValidator` — wraps the existing `SemanticSimilarityGuard`
- `RegexValidator` — deterministic pattern matching (no model dependency)
- `SchemaValidator` — JSON schema validation of LLM output (no model dependency)

External adapters (through explicit integration packages):
- `NeMoValidator` — wraps NeMo Guardrails rail checks
- `GuardrailsValidator` — wraps Guardrails AI validators
- `OpenAIModerationValidator` — wraps the OpenAI moderation endpoint

The critical design decision: **SafetyValidator results feed into Guard.verify() as
additional policy fields, not as a separate system.** A validator that fails produces
a Decision with `allowed=False` and `violated_invariants=["pii_detected"]`. This means
safety validation failures are signed, audited, and replayable — exactly like arithmetic
violations. Guardrails AI cannot say this. NeMo cannot say this.

#### 2.2 Adversarial Validation in CI

Layer 4 LLM consensus must be validated in CI. The implementation:

1. Containerized Ollama instance with two different model families (e.g., Llama-3 and
   Mistral) running locally in the CI environment.
2. Adversarial test suite that generates injection-attempt inputs and verifies that
   the dual-model consensus correctly blocks them.
3. Quarterly "adversarial benchmark" that measures the consensus mechanism's success
   rate against a fixed library of known injection techniques.

This is the most important gap in the current codebase from a security credibility
standpoint. No other item in Phase 2 matters as much as closing this.

#### 2.3 Response Validation (Not Just Request Validation)

The current system validates *requests* (intent + state). Phase 2 adds *response*
validation — checking that an LLM's output is consistent with policy before it is
presented to a user or used as input to the next step:

```python
response_guard = Guard(ResponsePolicy)
decision = await response_guard.verify(
    intent=ResponseIntent(text=llm_output),
    state=ConversationState(topic=current_topic, user_role=user_role),
)
```

This closes the gap with Guardrails AI's output validation capabilities while maintaining
Pramanix's unique property: the validation decision is signed, audited, and attributable.

#### 2.4 Multimodal Support (Scoped)

For image inputs, the validation is not visual content analysis (that is a different
problem). It is metadata validation: image dimensions, file size, format, source
provenance. These are typed fields that Z3 can reason about exactly. Pramanix does not
compete with image safety classifiers. It governs the *policy* around image inputs.

**Phase 2 exit criteria:** NLP validators promoted from beta to stable with full
adversarial test coverage. Live LLM adversarial CI running and publishing results.
Response validation integrated into the LangChain and LangGraph adapters. SafetyValidator
adapters for NeMo and Guardrails AI published and tested.

---

### Phase 3 — The Developer Experience Layer
**Duration: 3–4 months. Builds on Phase 2.**

The audit is explicit: policy authoring skill is a friction point. Phase 3 eliminates
that friction without compromising the formal guarantees.

#### 3.1 Natural Language to Verified Policy

The existing `NaturalPolicyCompiler` (Phase 2 of the THESIS) is the right foundation.
Phase 3 makes it production-grade:

1. The LLM generates a `PolicyIR` JSON object using Structured Outputs. The schema is
   the Pydantic model; the LLM does not write code.
2. The `PolicyCompiler` validates the IR against the declared `Policy.fields()`. Unknown
   fields, sort mismatches, and operator errors are caught before any Z3 formula is
   constructed.
3. The `Decompiler` generates a structured English audit report from the compiled
   constraints. This report is presented to the policy author for review before deployment.
4. The `MetaVerifier` checks semantic consistency between the compiled invariants and
   the original English description. Threshold mismatches and operator transpositions
   are flagged.

The policy author's workflow:
```
Write English → see compiled constraints → inspect counterexamples →
approve → deploy (with CISO sign-off PDF attached)
```

No Z3 knowledge required at any point.

#### 3.2 Policy Templates

A library of policy templates for common domains, available as:
```bash
pramanix template banking/transfer
pramanix template healthcare/phi-access
pramanix template infra/scaling-guard
pramanix template fintech/kyc-gate
```

Each template generates a complete, working policy with:
- Field declarations with correct Z3 sorts
- Invariants with `.named()` and `.explain()` populated
- Example intent and state models
- Unit tests that demonstrate SAT and UNSAT paths
- Compliance mapping for the relevant regulatory framework

Templates are not code generation. They are documented starting points that engineers
adapt. The goal is to reduce time-to-first-working-policy from hours to minutes.

#### 3.3 IDE Integration

A Language Server Protocol (LSP) server for Pramanix policy files:
- Autocomplete for `Field` declarations, `E()` expressions, and invariant methods
- Real-time linting: shows which invariants are satisfiable with example inputs
- Counterexample display: hover over an invariant to see an input that violates it
- Coverage display: shows which fields are not covered by any invariant

The LSP server reuses the existing `PolicyAuditor` and extends it with the Z3 model
extraction from the linter. It is a separate package (`pip install pramanix-lsp`).

#### 3.4 CLI Trace Explorer

```bash
pramanix trace list
pramanix trace show <trace_id>
pramanix trace replay <trace_id> --policy new_policy.py
pramanix trace diff <trace_id_1> <trace_id_2>
```

The trace explorer makes the signed, replayable decision architecture visible and useful
to engineers during development and debugging. It is the DX complement to the compliance
audit trail.

**Phase 3 exit criteria:** Natural language policy authoring works for banking, healthcare,
and infrastructure templates. IDE plugin published and installable in VS Code and PyCharm.
CLI trace explorer functional with the banking and healthcare examples. Policy templates
cover the 7 domains in the existing primitives library.

---

### Phase 4 — The Managed Platform
**Duration: 6+ months. Builds on Phase 3.**

Phase 4 is the business layer. It is not engineering-first. It is enterprise-adoption-first.
A principal architect is honest about this: Phase 4 is where Pramanix stops being a
library and starts being a product that enterprises buy.

#### 4.1 Policy Control Plane (SaaS)

A hosted service that provides:
- Policy registry (versioned, signed, content-addressed)
- Fleet visibility: which services are running which policy version
- Drift detection: alerts when a running policy hash does not match the registered version
- Decision audit explorer: search, filter, and export signed decisions
- Compliance report generation: maps decisions to regulatory citations and produces
  audit-ready PDF packages
- Policy promotion workflow: shadow evaluation → canary → full rollout

The control plane is not a new architecture. It is the existing CLI tools wrapped in
a web UI and a REST API. The decision infrastructure is already there (`DecisionSigner`,
`MerkleAnchor`, `ComplianceOracle`, `ShadowEvaluator`, `PolicyDiff`). Phase 4 makes
them visible and operable without CLI access.

#### 4.2 Benchmark Fleet

A public benchmark service that:
- Runs the Pramanix benchmark suite against standardized hardware on every release
- Publishes P50/P95/P99 latency, throughput, and memory numbers
- Compares against the previous release for regression detection
- Makes results available via a public URL (`benchmarks.pramanix.dev`)

This directly addresses the benchmark freshness gap in the current state.

#### 4.3 Enterprise Support and SLAs

A commercial tier with:
- SLA guarantees on the core library's API stability
- Security disclosure process with 90-day responsible disclosure
- Named support engineers for enterprise customers
- Quarterly architecture reviews for enterprise deployments
- Migration support for major version upgrades

This requires an organizational decision (a company or a foundation), not just an
engineering decision. A principal architect names this explicitly: you cannot have
enterprise SLAs without an entity that can be held to them.

---

## Part 4 — Engineering Standards That Must Not Move

Regardless of phase, these standards are non-negotiable. Any feature that does not
meet them does not ship.

### Standard 1: The Fail-Closed Contract Is Absolute

`Guard.verify()` never raises. `Decision(allowed=True)` only when `status=SAFE`.
`Decision.__post_init__` enforces this structurally. No new feature, integration,
or safety validator can weaken this. If a new component introduces a code path where
an error produces `allowed=True`, it does not merge.

The enforcement mechanism: every new component that participates in the Guard pipeline
must have an adversarial test that injects a failure and verifies `allowed=False` is
returned. This is not optional. It is gated in CI.

### Standard 2: Every Public API That Can Fail Has Observable Failure

No `except Exception: pass` in production source. Every swallowed exception either:
- Increments a named Prometheus counter and emits a structured WARNING log, or
- Emits a `SecurityWarning` (for security-posture degradations), or
- Raises to the caller with a typed exception from the `PramanixError` hierarchy

The enforcement mechanism: a `grep -rn "except Exception: pass"` lint check in CI that
fails the build if it finds any matches in `src/pramanix/`.

### Standard 3: No Stub Integration Ships as a Production Symbol

If an integration class is not tested against the real framework with real framework
objects, it is not exported from `pramanix.integrations`. It may exist in `pramanix.beta`
or `pramanix.experimental` with an explicit stability warning. It does not appear in
`__all__`. It does not appear in the README without a beta label.

### Standard 4: Security-Kernel Tests Use Protocol Injection, Not C-Library Patching

No test patches `z3.Solver`. No test patches `pramanix.guard.solve`. All solver failure
scenarios use the `SolverProtocol` injection mechanism (from Phase 0). This is enforced
by a CI check that scans test files for `patch("z3.Solver"` and `patch("pramanix.guard.solve"`.

### Standard 5: Every Benchmark Is Reproducible

Every performance claim in public documentation links to:
1. The exact hardware specification (vCPU, RAM, storage, OS, kernel version)
2. The exact software versions (Python, Z3, Pydantic, OS packages)
3. The exact benchmark script (committed in the `benchmarks/` directory)
4. The raw output file (committed in `benchmarks/results/`)

Claims without this provenance are removed from documentation.

### Standard 6: Hypothesis Tests Have Justified Deadlines

Every Hypothesis test has either:
- A `deadline=timedelta(seconds=N)` with a justification comment, or
- No deadline suppression (meaning the default Hypothesis deadline applies)

`deadline=None` is banned. `suppress_health_check` requires a benchmark comment showing
the measured strategy latency. This is enforced by a lint check.

### Standard 7: The Z3 License Dependency Is Managed

Z3 is MIT-licensed. This is compatible with Apache-2.0. If the license changes to
dual-license or commercial, the Z3 dependency does not create a conflict. Document this
explicitly in the license metadata and SBOM. Any additional dependency added in future
phases must pass a license compatibility check before merging.

---

## Part 5 — What This Is Not (And Why That Matters)

The ideal document suggests building "Pramanix Flow" (competitive with LangGraph) and
"Pramanix Memory" (competitive with LlamaIndex). A principal architect must push back
on this directly.

**Do not build an orchestration framework.** LangGraph has years of development, a large
community, and deep integration with the LangChain ecosystem. Building a competing
orchestration framework from a starting point of a v1.0 governance library is not a
viable strategy. The correct move is to be the best governance layer *for* LangGraph,
not a replacement of it.

**Do not build a retrieval stack.** LlamaIndex has a mature, battle-tested retrieval
pipeline with deep community support and extensive integrations. Building a competing
RAG framework is not the right use of Pramanix's engineering resources. The correct move
is to make LlamaIndex workflows governable — to wrap LlamaIndex's retrieval pipeline in
Pramanix's policy enforcement so that data access is checked, signed, and audited.

**Do not build a dialogue management system.** NeMo Guardrails is the right tool for
conversational AI safety. Pramanix's `SafetyValidator` adapters should wrap NeMo, not
replace it.

**The correct abstraction:** Pramanix is the governance layer. Every other framework is
a component that can be governed. This is a stronger strategic position than trying to
replicate the functionality of mature frameworks. It is also a position that no existing
player can easily replicate because it requires the formal correctness foundation that
only Pramanix has.

---

## Part 6 — The Latency Architecture (Real Numbers, Real Decisions)

The ideal document mentions "very very less latency than other giants." A principal
architect must be precise about what this means and how to achieve it.

### Current state

The only published benchmarks are v0.8.0 on a consumer laptop. P50: 5.235ms. This missed
the 5.0ms target. These numbers are not usable for comparison against LangChain or
LangGraph. The first task is getting real numbers.

### The latency composition for a Pramanix verification call

```
Component                          Typical    P95     Notes
──────────────────────────────────────────────────────────
Pydantic strict-mode validation    0.2ms      0.5ms   Fixed cost
resolver.resolve_all()             0–10ms     15ms    Dominated by DB latency
model_dump() serialization         0.1ms      0.2ms   Fixed cost
Thread/process dispatch            0.05ms     0.2ms   async-thread only
Z3 context setup                   0ms        0ms     Thread-local, cached
Z3 formula construction            0.5ms      1.5ms   Depends on policy complexity
Z3 check()                         2–8ms      20ms    Dominant term
Decision construction + signing    0.2ms      0.5ms   Fixed cost
Prometheus/OTel                    0.1ms      0.2ms   Fire-and-forget
──────────────────────────────────────────────────────────
Total (no resolver, cached solver) 3–9ms      22ms    Typical production path
Total (with DB resolver)           5–25ms     40ms    Realistic production path
```

The Z3 check is the dominant term. It cannot be eliminated. But it can be bounded:
- `solver_timeout_ms=5000` is the default. For simple policies (4–6 arithmetic
  invariants), Z3 returns in under 10ms on any modern server. The timeout is a ceiling,
  not an expectation.
- `solver_rlimit=10_000_000` prevents logic-bomb DoS. This is correct.
- Pre-compilation of the expression tree at Guard construction time (already implemented
  in `InvariantASTCache`) eliminates repeated transpilation.

### Latency improvements that are achievable

**Hot-path caching for proven-safe branches.** For policies where Z3 can prove that
a particular combination of field values is always safe (e.g., `amount == 0` is always
safe regardless of other state), add a hash-keyed cache of proven-safe input tuples.
First hit pays the full Z3 cost. Cache hits pay zero Z3 cost. The cache is policy-version-
keyed: a policy change invalidates the entire cache. This is safe because:
- Cache entries are only created on `sat` results
- The cache is keyed on the full input tuple, not a subset
- The policy hash is included in the cache key

This is analogous to query plan caching in a database. It is not a correctness risk.
It is a latency optimization for repeated similar inputs.

**Solver context pooling.** Currently, each worker gets one thread-local Z3 context
that is created once and never destroyed. This is correct for correctness. For latency,
the question is whether the shared-solver-for-SAT phase (Phase 1 of the two-phase solve)
can be further optimized by pre-asserting the concrete value equalities at solver
construction time. This requires benchmarking to determine if it produces measurable
improvement before implementing.

**Zero-copy fast path.** The O(1) Python pre-screen (`fast_path.py`) can short-circuit
the full Z3 pipeline for obvious violations (e.g., negative amount, frozen account).
This is already implemented. The optimization is to move more invariants into the fast
path for deployments where the policy author can guarantee monotonicity of the fast-path
rules. This requires an explicit API: `GuardConfig(fast_path_rules=[...])` already exists.

**The comparison to LangChain and LangGraph:** These frameworks do not run a formal
solver. Their "latency" is dominated by LLM inference time (50ms–2000ms per call).
Pramanix's 5–15ms verification overhead is negligible in a workflow where the LLM
call costs 500ms. The latency comparison is not meaningful in isolation. The meaningful
metric is "governance overhead as a percentage of total workflow latency." For any
workflow involving an LLM, Pramanix's overhead is under 3% in typical cases.

The latency story for enterprise is not "we are faster than LangGraph." It is "we add
less than 15ms to any LLM workflow and you get formal proof, a signed audit record,
and regulatory compliance evidence in return."

---

## Part 7 — The Competitive Position in One Paragraph

Pramanix's real competitive position — stated precisely, not aspirationally — is this:

For any AI system that executes actions with real-world consequences in a regulated
environment, Pramanix is the only layer that can formally prove that those actions
were authorized, produce a cryptographically signed and tamper-evident record of that
authorization, attribute any violation to a specific named invariant, and do all of
this in under 15ms of governance overhead on top of any existing framework (LangChain,
LangGraph, LlamaIndex, AutoGen, NeMo). No other library in the market does all five
of these simultaneously. The AGPL-3.0 license must change for this position to be
commercially accessible, but the technical differentiation is real, validated, and
genuinely hard to replicate.

That is the sentence that should be on the front page of the website, in the pitch deck,
and in the architecture review for every enterprise customer. Everything in this blueprint
is engineering in service of making that sentence provably true at scale.

---

## Part 8 — Execution Sequencing Summary

```
Phase 0 (3–4 months)   Zero Debt
  ├── SolverProtocol injection
  ├── ClockProtocol injection
  ├── re2 hard-fail mode
  ├── Concurrent-mutation CB test
  ├── Hypothesis sanitizer coverage
  ├── _emit_field_seen_metric fix
  ├── Live LLM adversarial CI
  ├── License decision + implementation
  ├── Server-class benchmarks published
  └── Stub integrations: complete or remove

Phase 1 (4–6 months)   Governance Core
  ├── Guard-as-middleware for LC, LG, LlIdx, AutoGen
  ├── PolicyRegistry (file → HTTP → Redis/S3)
  ├── Policy linter + semantic verifier
  ├── Execution token as first-class pattern
  └── Trace and replay infrastructure

Phase 2 (4–6 months)   Safety Layer
  ├── SafetyValidator protocol + built-in validators (stable)
  ├── Live LLM adversarial CI (quarterly benchmarks)
  ├── Response validation
  ├── NeMo + Guardrails AI adapters
  └── Multimodal metadata governance

Phase 3 (3–4 months)   Developer Experience
  ├── NL → verified policy (production-grade)
  ├── Policy templates (7 domains)
  ├── LSP server (VS Code + PyCharm)
  └── CLI trace explorer

Phase 4 (6+ months)    Managed Platform
  ├── Policy control plane (SaaS)
  ├── Benchmark fleet (public, continuous)
  └── Enterprise support + SLAs (requires org/company)
```

**Total realistic timeline to full platform:** 20–26 months from Phase 0 start,
assuming a team of 3–5 engineers with the right background (one Z3/formal methods,
one backend/distributed systems, one DX/tooling, one ML/safety, one enterprise/growth).

A solo architect cannot execute all of this. The prerequisite for Phase 1 and beyond
is assembling a team. Phase 0 is the last thing that can be done solo without
sacrificing quality.

---

## Closing Note

The current version of Pramanix — despite its open items, its AGPL license, its consumer
laptop benchmarks, and its stub integrations — contains something that is genuinely rare
in the AI tooling ecosystem: a formally correct, adversarially tested, cryptographically
signed enforcement layer with a real audit trail. That is not common. That is worth
building on.

The path from here to the ideal version is not a rewrite. It is a disciplined sequence
of: close the debt, extend the reach, build the platform. In that order. Nothing in
Part 2 or Part 3 or Part 4 is possible without Part 0 completed correctly.

The mission is not to out-feature LangChain. It is to be the layer that makes
LangChain safe enough to use when the stakes are real. That mission is achievable,
differentiated, and defensible. Build toward it one phase at a time.