# Pramanix Pre-PyPI Hardening and Elite Launch Strategy

**Document type:** Architecture-first launch-readiness strategy  
**Audience:** Founder, CTO, engineering team  
**Repository state:** v1.0.0 tag, not yet published to PyPI  
**Evidence standard:** Code is authoritative. Every claim in this document is backed by specific file, line, or test evidence from the repository. Where code and documentation disagree, code governs.  
**Audit date:** 2026-05-04

---

## 1. Executive Verdict

**Do not push to PyPI today.**

Not because the core is weak — it is not. The Z3 enforcement kernel, the HMAC-sealed IPC boundary, the two-phase attribution strategy, and the adversarially-verified fail-closed guarantee are genuinely elite engineering. Nothing in the open-source AI safety ecosystem matches the formal correctness of the core verification pipeline.

But a PyPI publication is a public commitment. Once users install `pramanix==1.0.0`, every architectural decision becomes a migration burden. Every broken claim becomes a credibility debt. Every RCE vector in the default install becomes a CVE against your name.

**What blocks publication today:**

1. `CalibratedScorer.load()` calls `pickle.load(f)` at `injection_scorer.py:260` with no integrity check. This is a confirmed RCE vector in a security SDK. Enterprise security teams will reject on this finding alone.

2. The six governance subsystems — IFC, Privilege, Oversight, Memory, Lifecycle, Provenance — are implemented as standalone libraries with no coupling into `Guard.verify()`. A developer who installs and configures all six, then calls `guard.verify()`, receives no governance enforcement unless they manually wire every subsystem. This is security theater by composition failure.

3. Python 3.13 is the only supported version. The enterprise Python install base is 3.11 and 3.12. A library that cannot be installed by 80% of its target audience has an adoption rate of zero.

4. The project is not on PyPI. `pip install pramanix` fails. This is the absolute prerequisite for everything else in this document.

**What is already elite:**

The verification kernel (`guard.py`, `solver.py`, `transpiler.py`, `decision.py`, `worker.py`) is a 5/5 engineering artifact. The two-phase Z3 solve strategy with per-invariant attribution via single-`assert_and_track` solvers eliminates the minimum-core ambiguity that breaks most Z3-based tools. The HMAC IPC boundary with a non-picklable ephemeral key (`worker.py:213`) prevents worker process forgery. The `Decision.__post_init__` invariant enforces `allowed=True ↔ status=SAFE` immutably. The adversarial test suite (`test_fail_safe_invariant.py`) proves fail-closed behavior against 11 exception types including `MemoryError` and `SystemExit`. None of this needs architectural rethinking. It needs protection, not replacement.

**The gap:** A Ferrari engine bolted to an incomplete chassis. The kernel is production-worthy. The platform around it — governance, persistence, cloud integrations, adapter validation, packaging — is 60–70% complete and the remaining 30–40% is where the credibility risk lives.

**Minimum launch bar before any PyPI publication:**

- P0 security fixes complete (CalibratedScorer HMAC, FlowRule label-matching correctness)
- Python 3.11+ compatibility validated in CI matrix
- Governance subsystems wired into Guard via `GuardConfig.governance` composition primitive
- At least one durable oversight backend (Redis) implemented and tested
- All five unvalidated adapters (CrewAI, DSPy, Haystack, PydanticAI, SemanticKernel) tested against real installed frameworks in CI
- Coverage-padding test files replaced with scenario-driven tests
- PyPI trusted publishing workflow configured and smoke-tested
- `LAUNCH_CLAIMS.md` published stating exactly what is guaranteed and what is not

**Launch posture:** "Formal action authorization primitive for structured AI agent systems. Production kernel. Beta governance platform."

---

## 2. Strategic Positioning

### What Category Pramanix Is Actually In

Pramanix is not an AI orchestration framework. It is not an LLM output validator. It is not a conversational safety filter. It is a **formal action authorization layer** — a pre-execution enforcement gate that produces a cryptographically-anchored, mathematically-proven binary decision (ALLOW with proof, BLOCK with counterexample) about whether a structured AI agent action satisfies a formal policy.

This is a distinct category with no current open-source competitor backed by a sound SMT solver. That statement is both the opportunity and the risk.

### LangChain and LlamaIndex: Embedding Targets, Not Competitors

LangChain (80,000+ GitHub stars, $35M+ funding, multi-year head start) is an agent orchestration and chain-composition framework. LlamaIndex is a RAG data-ingestion framework. Neither does formal verification. Neither produces mathematical proofs of policy satisfaction. Neither has a fail-closed guarantee verifiable from code.

The correct relationship is embedding: Pramanix becomes the enforcement primitive that every serious LangChain or LlamaIndex agent deployment installs to govern its tool calls. The `PramanixGuardedTool` adapter for LangChain and the `PramanixFunctionTool` adapter for LlamaIndex already encode this relationship correctly. The framing is:

> "LangChain orchestrates your agents. Pramanix proves their actions are safe."

Trying to compete with LangChain on ecosystem breadth is a category error and a three-year losing race. The correct goal is to become the standard enforcement primitive that LangChain deployments depend on — the way OpenTelemetry became the standard instrumentation layer without replacing any application framework.

### Guardrails AI: Adjacent Domain, Partial Overlap

Guardrails AI (9,000+ GitHub stars, PyPI-published, growing community) validates LLM outputs — detecting PII, toxicity, format violations, hallucinations in generated text. Pramanix authorizes structured agent actions — proving that a declared intent satisfies formal policy invariants before execution.

The overlap: both intercept AI system behavior to prevent harm. The non-overlap: Guardrails AI validates what the LLM said; Pramanix validates what the agent is about to do. Guardrails AI operates on free-form text output; Pramanix operates on structured intent dicts against formal policies. Guardrails AI uses probabilistic ML validators; Pramanix uses Z3 formal proof with counterexample attribution.

Pramanix wins on: formal correctness guarantees, violation attribution, fail-closed provability, structured action enforcement.  
Pramanix loses on: PyPI availability (currently zero), output content validation (zero capability), ecosystem breadth, non-programmer usability.

The competitive claim Pramanix can make honestly: for structured action authorization (financial transactions, infrastructure mutations, data access decisions), Z3-backed formal verification produces stronger guarantees than probabilistic validators. This is not a claim Guardrails AI can rebut because it is mathematically true.

### NeMo Guardrails: Different Domain, Irrelevant for Core Claims

NVIDIA NeMo Guardrails (GPU-accelerated, enterprise NVIDIA stack, Colang language) controls conversational AI behavior — topic control, dialog flow, factual grounding in LLM conversations. It cannot produce a formal proof of policy satisfaction. Pramanix cannot evaluate conversation context or detect hallucinations in free text.

For structured action authorization, NeMo is irrelevant. For conversational AI safety, Pramanix is irrelevant. The competitive positioning should acknowledge NeMo in adjacent space without claiming direct competition.

### The Category-Creation Burden

Having no direct open-source competitor in Z3-backed formal action authorization is a double-edged position:

**Opportunity:** Pramanix can define the category. The vocabulary (formal action authorization, policy invariant, violation attribution, fail-closed guarantee) can become Pramanix's vocabulary. First-mover advantage in defining what "formal AI safety" means at the action level.

**Risk:** No competitor means no validated market demand. No comparable product means no established buyer education. Enterprises accustomed to probabilistic validators will need to be convinced that formal verification is worth the added complexity and the Z3 dependency. Category creation is expensive — it requires case studies, developer education, benchmarks against familiar alternatives, and patience.

**Market entry strategy:** Do not announce a category. Demonstrate a capability. Ship to three fintech teams, publish real benchmark data, document a real production deployment, then let the market name the category after the fact.

---

## 3. Current-State Architecture Assessment

### Elite Kernel (Production-Worthy)

The verification pipeline from `guard.verify()` through `Decision` is production-plausible for controlled deployments:

| Module | Lines | Assessment |
|---|---|---|
| `guard.py` | ~1,354 | Orchestration logic; disciplined 12-step pipeline; fail-closed at all boundaries |
| `policy.py` | ~703 | Clean DSL base; `ConstraintExpr.__bool__` catches accidental Python boolean ops at load time |
| `expressions.py` | ~1,052 | NamedTuple AST; zero Z3 imports; correct isolation |
| `transpiler.py` | ~884 | DSL → Z3 lowering; no `eval`/`exec`/`ast.parse`; correct boundary |
| `solver.py` | ~430 | Two-phase strategy; per-context instantiation; rlimit + wall-clock timeout |
| `worker.py` | ~832 | HMAC-sealed IPC (`_RESULT_SEAL_KEY` at line 213); warmup with 8 Z3 patterns including forced UNSAT |
| `decision.py` | ~677 | Frozen dataclass; `__post_init__` enforces `allowed=True ↔ status=SAFE`; 7-field canonical hash |
| `fast_path.py` | ~214 | O(1) pre-screen; can only BLOCK, never ALLOW (line 8-12 contract); 0% false positive design |

**Structural strength:** The transpiler-to-Z3 boundary is correctly isolated. No Z3 objects cross the process boundary. The HMAC seal uses `hmac.compare_digest` (constant-time). Worker warmup forces a UNSAT solve and refuses to serve if Z3 returns wrong result — preventing silent solver corruption.

**One structural risk:** `verify_async()` (line 824) and `_verify_core()` (line 449) are separate code trees, currently ~155 lines vs ~331 lines respectively. The research pass confirms the semver check is present in both paths (lines 593-627 and 937-974 respectively). However, maintaining two parallel trees is a structural maintenance risk — any future step added to one path must be manually replicated in the other. This is not a current bug; it is a future divergence trap.

### Platform Layer (Functional, Incomplete)

| Component | Status | Gap |
|---|---|---|
| `circuit_breaker.py` | Solid | Distributed CB uses fakeredis in unit tests; real Redis tested in integration suite |
| `execution_token.py` | Strong | Redis (SETNX), SQLite (WAL+UNIQUE), Postgres (testcontainers) real; InMemory warns in multi-worker |
| `audit_sink.py` | Functional | KafkaAuditSink bounded queue (10,000); overflow silently drops decisions (`audit_sink.py` line 218-225) |
| `key_provider.py` | Faith-based | All four cloud KMS providers tested with injected stubs; no real IAM path tested |
| `crypto.py` | Real | Ed25519 signing with PyCA; `key_id = SHA-256[:16]` of public key PEM |
| `audit/` (merkle, signer, verifier) | Real | Second-preimage protection in Merkle; `iat` removed from signed payload (replay risk — documented) |

### Governance Subsystems (Implemented, Uncoupled)

All six beta subsystems contain real, non-trivial code. None contain `pass`-only methods. None are coupled to `Guard.verify()`.

| Subsystem | Module | Gap | Severity |
|---|---|---|---|
| IFC | `ifc/flow_policy.py`, `ifc/enforcer.py` | No Guard coupling; FlowRule label exact-match (not glob for labels) | HIGH |
| Privilege | `privilege/scope.py` | No Guard coupling | HIGH |
| Oversight | `oversight/workflow.py` | No Guard coupling; HMAC key per-process (line 491: `os.urandom(32)`), lost on restart | HIGH |
| Memory | `memory/store.py` | No Guard coupling; `list.pop(0)` at line 200 (O(n) eviction) | MEDIUM |
| Lifecycle | `lifecycle/diff.py` | No Guard coupling; `ShadowEvaluator` O(n) eviction | MEDIUM |
| Provenance | `provenance.py` | No Guard coupling; `verify_integrity()` skips prev_hash for first post-eviction record | MEDIUM |

### Adapters and Integrations (Breadth Real, Depth Varies)

| Adapter | Framework tested | Verdict |
|---|---|---|
| FastAPI/Starlette | Real `TestClient` | Production-validated |
| LangChain | Real `langchain-core` objects | Production-validated |
| LlamaIndex | Real `llama-index-core` | Integration-tested |
| AutoGen | Real `pyautogen` | Integration-tested |
| CrewAI | No real `crewai` in CI | Implemented, unvalidated |
| DSPy | No real `dspy-ai` in CI | Implemented, unvalidated |
| Haystack | No real `haystack-ai` in CI | Implemented, unvalidated |
| PydanticAI | No real `pydantic-ai` in CI | Implemented, unvalidated |
| SemanticKernel | No real `semantic-kernel` in CI | Implemented, unvalidated |
| gRPC interceptor | No real `grpcio` in CI | Implemented, synthetic stubs |
| Kafka consumer | Stub unit + testcontainers integration | Mixed |

### Operational Tooling (Solid)

`pramanix doctor`, `pramanix simulate`, `pramanix verify-proof` are implemented and strongly tested. The CLI is a genuine production debugging asset. Release checklist, Dockerfiles, Trivy security scan in CI, and license scan are present. The 9-stage CI pipeline (`ci.yml`) is real and meaningful.

### Packaging Reality

- `pyproject.toml` version: `1.0.0`; Python: `>=3.13,<4.0`
- PyPI classifier: `"Development Status :: 5 - Production/Stable"` — incorrect given beta subsystems
- CI coverage gate: `--cov-fail-under=95` (not 98% as `pyproject.toml` specifies — discrepancy)
- `integrations/*.py` excluded from coverage: `omit = ["src/pramanix/integrations/*.py"]`
- No `dist/` directory; no `publish.yml` workflow configured for trusted publishing
- Hard non-optional dependencies: `z3-solver`, `pydantic`, `structlog`, `orjson`, `prometheus-client`
- `prometheus-client` registers counters at module import (`guard_config.py` lines 109-140) but gracefully handles `ImportError` — the hard dependency means the package is always installed, but the registry code only runs if the import succeeds

---

## 4. Launch Blockers

The following issues must be resolved before any PyPI publication. Each is categorized by severity and includes the minimum acceptable fix and acceptance criteria.

---

### LB-1: CalibratedScorer Pickle RCE

**Severity:** CRITICAL — blocks launch  
**File:** `src/pramanix/translator/injection_scorer.py:260`  
**Evidence:**
```python
instance._pipeline = pickle.load(f)  # — trusted model file
```
The comment says "trusted model file." The code enforces nothing. An attacker who can write to the scorer file path (shared storage, S3 bucket with misconfigured ACL, NFS mount) gets arbitrary code execution when `CalibratedScorer.load()` is called. In a security SDK, an unenforced pickle load is not a documentation problem — it is a pre-auth RCE vector that enterprise security teams will find in their first dependency audit.

**Why this blocks launch:** Any CVE filed against `pramanix` for unenforced pickle deserialization will be cited in every competitor comparison, every HackerNews thread, and every enterprise procurement conversation. This cannot be present in a 1.0.0 release of a security library.

**Required fix:**
```python
@classmethod
def load(cls, path: str | Path, *, hmac_key: bytes) -> "CalibratedScorer":
    path = Path(path)
    raw = path.read_bytes()
    # Verify HMAC-SHA256 integrity before deserializing
    sig_path = path.with_suffix(path.suffix + ".sig")
    expected_tag = sig_path.read_bytes()
    actual_tag = hmac.new(hmac_key, raw, hashlib.sha256).digest()
    if not hmac.compare_digest(actual_tag, expected_tag):
        raise IntegrityError(
            f"CalibratedScorer file '{path}' failed HMAC-SHA256 integrity check. "
            "Do not load scorer files from untrusted sources."
        )
    instance = cls.__new__(cls)
    instance._pipeline = pickle.loads(raw)  # noqa: S301 — integrity verified above
    return instance
```

Add a companion `save()` classmethod that writes both the `.pkl` and the `.pkl.sig` file atomically.

**Acceptance criteria:**
- `CalibratedScorer.load()` requires `hmac_key` parameter; raises `IntegrityError` on mismatch
- `CalibratedScorer.save()` writes `.pkl` + `.pkl.sig` atomically
- `test_injection_calibration.py` includes: tampered file raises `IntegrityError`; correct file loads; missing sig file raises `FileNotFoundError`
- Bandit/Ruff `S301` suppression comment added with inline justification
- `KNOWN_GAPS.md` updated to mark this gap as resolved

---

### LB-2: FlowRule Label Matching Precision

**Severity:** HIGH — blocks launch  
**File:** `src/pramanix/ifc/flow_policy.py:49-71`  
**Evidence:**
```python
def matches(self, data_label, sink_label, source_component, sink_component) -> bool:
    if data_label != self.source_label: return False
    if sink_label != self.sink_label: return False
    ...
```
Labels (`data_label`, `sink_label`) use exact equality. The docstring describes "glob-style component name pattern" for components, but this only applies to `source_component` / `sink_component` — not to the data label or sink label fields. A user writing `FlowRule(source_label="PUBLIC.*", sink_label="SECRET")` expecting to match any PUBLIC-prefixed label will get silent pass-through for all non-exact matches.

This is a semantic security gap. IFC policies that use prefix patterns on labels provide zero enforcement.

**Required fix:** Either implement `fnmatch.fnmatch()` for `data_label` and `sink_label` fields, or rename the parameters and update the docstring to be unambiguous that labels require exact string equality. Implementing glob is the correct fix for a security primitive:

```python
import fnmatch

def matches(self, data_label: str, sink_label: str,
            source_component: str | None, sink_component: str | None) -> bool:
    if not fnmatch.fnmatch(data_label, self.source_label):
        return False
    if not fnmatch.fnmatch(sink_label, self.sink_label):
        return False
    if self.source_component is not None:
        if not fnmatch.fnmatch(source_component or "", self.source_component):
            return False
    if self.sink_component is not None:
        if not fnmatch.fnmatch(sink_component or "", self.sink_component):
            return False
    return True
```

**Acceptance criteria:**
- `FlowRule("PUBLIC.*", "SECRET").matches("PUBLIC.api", "SECRET", None, None)` → `True`
- `FlowRule("PUBLIC", "SECRET").matches("PUBLIC.api", "SECRET", None, None)` → `False`
- Existing exact-match tests remain passing
- New test file `test_flow_rule_glob.py` with 12 parametrized cases covering: exact match, prefix wildcard, suffix wildcard, nested path, no-match, empty label

---

### LB-3: Python 3.13-Only Constraint

**Severity:** CRITICAL — blocks launch  
**File:** `pyproject.toml:38`  
**Evidence:** `python = ">=3.13,<4.0"`

Python 3.13 was released October 2024. As of mid-2026, the enterprise Python install base is primarily 3.11 (security support through 2027-10) and 3.12 (security support through 2028-10). Requiring 3.13 excludes every enterprise that hasn't upgraded, every managed cloud Python runtime on an LTS image, and every CI matrix that hasn't added 3.13 yet.

No technical reason within the codebase requires 3.13. The `pyproject.toml` requirement is a declaration, not a constraint forced by code. Z3, Pydantic v2, and all core dependencies support 3.11+.

**Required fix:**
1. Lower `python = ">=3.11,<4.0"` in `pyproject.toml`
2. Add Python 3.11 and 3.12 to CI matrix alongside 3.13
3. Run full test suite on all three versions
4. Replace any 3.13-only syntax (`match` statements without `case`, `ExceptionGroup`, etc.) with backward-compatible equivalents — or explicitly document and test which features require 3.13 with conditional imports

**Acceptance criteria:**
- `pip install pramanix` succeeds on Python 3.11.x, 3.12.x, 3.13.x
- Full unit test suite passes on all three versions in CI
- No `SyntaxError` or `ImportError` on Python 3.11

---

### LB-4: Governance Subsystems Have No Guard Coupling

**Severity:** HIGH — blocks launch (or must be explicitly scoped out of 1.0 claims)  
**Files:** `ifc/enforcer.py`, `privilege/scope.py`, `oversight/workflow.py`, `memory/store.py`, `lifecycle/diff.py`, `provenance.py`  
**Evidence:** No call to any governance subsystem method exists in `guard.py`. No `GuardConfig` field accepts governance policy objects.

A developer who reads the README, installs `pramanix`, configures IFC policies, and calls `guard.verify()` receives no IFC enforcement unless they manually call `flow_enforcer.gate()` after receiving an ALLOW. There is no composition primitive. There is no configuration path. There is no error if governance is configured but not wired.

If security requires a developer to remember to call a function, it is not security infrastructure — it is a security library. The distinction matters enormously for enterprise buyers.

**Two acceptable paths to launch:**

**Path A (recommended):** Implement the composition primitive before 1.0.0 (see Section 7 for design). Mark governance subsystems as `beta` in all documentation but couple them structurally into `Guard` so misconfiguration is impossible to miss.

**Path B:** Explicitly scope governance subsystems out of 1.0 claims. Label them as standalone beta libraries. Remove all marketing language that implies they are enforced by default. Publish `KNOWN_GAPS.md` gap G-1 through G-4 prominently. Ship 1.0.0 as "formal verification kernel only" and announce 1.1.0 as "governance coupling release."

Path B is lower technical risk for the launch date. Path A produces a stronger product. This document recommends Path A with a realistic 60-day implementation window before launch.

**Acceptance criteria for Path A:**
- `GuardConfig` accepts optional `governance` field of type `GovernanceConfig`
- `guard.verify()` automatically calls coupled governance checks on ALLOW decisions
- Misconfigured governance (policy set but not wired) raises `ConfigurationError` at Guard construction
- Integration test: Guard + IFC + Privilege coupled in single test verifying automatic enforcement

---

### LB-5: Decision Hash Has No Algorithm Version

**Severity:** MEDIUM — blocks launch for regulated industry claims  
**File:** `src/pramanix/decision.py:286-316`  
**Evidence:** `_compute_hash()` produces SHA-256 of 7 canonical fields. No version identifier is embedded in the `Decision` object. If the hash computation changes between Pramanix versions (e.g., adding `policy_fingerprint` to the canonical fields), every existing signed decision in every audit trail and Merkle archive becomes unverifiable against the new code.

For financial institutions, healthcare providers, or any regulated industry building compliance audit trails on Pramanix, this is a forward-incompatibility trap with no migration path.

**Required fix:** Add `hash_alg: str = "sha256-v1"` field to `Decision`. Include `hash_alg` in the canonical serialization so it is part of the signed payload. Define a version upgrade protocol (v1 → v2) in the CHANGELOG. `PramanixVerifier.verify_decision()` must check `hash_alg` and use the appropriate computation.

**Acceptance criteria:**
- `Decision.hash_alg` field present and defaults to `"sha256-v1"`
- `_compute_hash()` includes `hash_alg` in canonical bytes
- `PramanixVerifier.verify_decision()` reads `hash_alg` to select computation
- Test: Decision with `hash_alg="sha256-v1"` verifies correctly; unknown `hash_alg` raises `UnsupportedAlgorithmError`

---

### LB-6: Policy Fingerprint Omits python_type

**Severity:** MEDIUM  
**File:** `src/pramanix/guard_pipeline.py:194-226`  
**Evidence:** `_compute_policy_fingerprint()` hashes: policy name, version, invariant labels, field names, and field z3_types. It does NOT hash `python_type`. Two policies with identical names, field names, and z3_types but different Python types (`int` vs `Decimal`, both mapped to `"Real"`) produce identical fingerprints. Policy fingerprints are embedded in `ExecutionToken` — tokens issued under one type mapping remain valid for a different mapping.

**Required fix:** Add `f.python_type.__qualname__` to the canonical field hash string. This is a one-line fix with significant correctness implications.

**Acceptance criteria:**
- `Field("amount", int, "Real")` and `Field("amount", Decimal, "Real")` produce different fingerprints
- Existing tests still pass (fingerprint values will change — update test fixtures)

---

### LB-7: Coverage Gate Discrepancy

**Severity:** MEDIUM (honesty/credibility issue)  
**Evidence:** `pyproject.toml:359`: `fail_under = 98`. CI workflow: `--cov-fail-under=95`. These diverge by 3 percentage points. Additionally, `integrations/*.py` is excluded from coverage (`omit` in pyproject.toml), meaning adapter code has zero mandatory coverage contribution.

**Required fix:** Align the two values. Either raise CI to 98% (requires removing coverage-padding files and replacing with real tests), or lower `pyproject.toml` to 95% and explicitly document the delta. Removing the `integrations/*.py` exclusion from `omit` requires ensuring real framework tests count toward the gate.

**Acceptance criteria:**
- `pyproject.toml:fail_under` matches CI `--cov-fail-under` exactly
- Or: documented explanation in `KNOWN_GAPS.md` for why they differ

---

### LB-8: Coverage-Padding Test Files

**Severity:** MEDIUM (test suite integrity)  
**Files identified:**
```
tests/unit/test_coverage_boost.py
tests/unit/test_coverage_boost2.py
tests/unit/test_coverage_gaps.py
tests/unit/test_coverage_gaps_final.py
tests/unit/test_coverage_final_push.py
tests/unit/test_coverage_final_push2.py
```
These files exist to satisfy a coverage metric, not to verify behavior. They inflate the coverage number without proportionally increasing confidence in correctness. For a security SDK where the coverage metric is cited as evidence of quality, this is a credibility liability.

**Required fix:** Audit each file. Identify tests that genuinely verify meaningful behavior — keep those and move them to appropriately named files. Delete tests that only exercise trivial paths (e.g., `__repr__` calls, single-line property accessors). Replace the deleted coverage with 3–5 scenario-driven tests per gap area. Accept a coverage drop to 93–95% honest coverage rather than 98% padded coverage.

**Acceptance criteria:**
- Zero files named `test_coverage_*` in the test suite
- Coverage gate passes at 93%+ with only scenario-driven tests
- Net test count may decrease; scenario coverage should increase

---

### LB-9: Five Adapters Untested Against Real Frameworks

**Severity:** HIGH for launch credibility  
**Files:** `integrations/crewai.py`, `integrations/dspy.py`, `integrations/haystack.py`, `integrations/pydantic_ai.py`, `integrations/semantic_kernel.py`

These adapters are fully implemented but never exercised against real installed framework objects in CI. CrewAI, DSPy, and PydanticAI all have rapid API evolution. SemanticKernel has broken its own API multiple times between 1.x minor versions. The current adapters were written against specific versions and may already be broken.

**Required fix:** Add CI jobs that install each framework and run a minimal integration smoke test:
```yaml
- name: Test CrewAI adapter
  run: |
    pip install pramanix[crewai] crewai>=0.55
    python -c "from pramanix.integrations.crewai import PramanixCrewAITool; ..."
```

**Acceptance criteria:**
- Each of the five adapters has a real-framework smoke test in CI
- Smoke tests exercise: import, construction, a ALLOW path, a BLOCK path
- Tests run on a matrix of framework versions (current + N-1 minor)

---

### LB-10: PyPI Packaging Not Configured

**Severity:** CRITICAL — blocks launch by definition  
**Evidence:** No `dist/` directory. No configured trusted publishing workflow in `.github/workflows/publish.yml` (a `publish.yml` file exists but its content needs verification). No documented wheel smoke test against a clean virtual environment.

**Required fix:** Configure PyPI trusted publishing (OIDC-based, no stored API key). Add wheel/sdist smoke test to CI that installs the built artifact into a fresh virtual environment and imports the package. Validate `python -c "import pramanix; print(pramanix.__version__)"` succeeds.

**Acceptance criteria:**
- `poetry build` produces `.tar.gz` and `.whl` artifacts without errors
- Wheel installs cleanly on Python 3.11, 3.12, 3.13
- `import pramanix` succeeds in a clean environment with only mandatory deps installed
- OIDC trusted publishing configured for PyPI
- Test PyPI publication succeeds as pre-launch validation

---

## 5. Architecture Hardening Plan

### 5.1 Guard Core: Unify the Sync/Async Pipeline

**Problem:** Two code trees (`_verify_core()` at line 449, `verify_async()` at line 824) implement the same 12-step pipeline. Both currently contain the semver check, but maintaining parallel trees is the leading source of future divergence bugs.

**Hardened design:**

Extract a shared `_pipeline_steps` protocol that both sync and async paths execute. The async path differs only in how it dispatches the Z3 solve (via `ThreadPoolExecutor.submit()` or `ProcessPoolExecutor.submit()`). All other steps — validation, fast-path, resolver population, pipeline checks, signing, audit emission — are identical and should share code:

```python
# New module: guard_pipeline_steps.py

@dataclass(frozen=True)
class PipelineContext:
    intent: dict[str, Any]
    state: dict[str, Any]
    policy_cls: type[Policy]
    config: GuardConfig
    token: ExecutionToken | None

def step_validate(ctx: PipelineContext) -> dict[str, Any] | Decision:
    """Pydantic strict validation. Returns validated dict or error Decision."""
    ...

def step_fast_path(ctx: PipelineContext, values: dict) -> Decision | None:
    """O(1) pre-screen. Returns blocking Decision or None to continue."""
    ...

def step_resolve_fields(ctx: PipelineContext) -> dict[str, Any]:
    """Run ContextVar resolvers before worker dispatch."""
    ...

# ... etc for all 12 steps

async def _async_solve_step(ctx: PipelineContext, values: dict) -> Decision:
    """Only this step differs: dispatches to async worker."""
    ...

def _sync_solve_step(ctx: PipelineContext, values: dict) -> Decision:
    """Dispatches to synchronous worker."""
    ...
```

`guard.py` reduces to: build `PipelineContext`, execute shared steps in order, branch only at the solve step.

**Acceptance criteria:**
- `verify()` and `verify_async()` share all non-solve steps via shared functions
- Adding a new pipeline step requires editing one place only
- All existing tests pass without modification
- New test: verify `verify()` and `verify_async()` produce identical results for identical inputs

### 5.2 Decision Identity Versioning

**Problem:** `Decision.decision_hash` is computed as `SHA-256(7 canonical fields)` with no version identifier. Future changes to the canonical field set silently break all stored signed decisions.

**Hardened design:** Add `hash_alg: str` field to `Decision` dataclass with default `"sha256-v1"`. The canonical bytes include `hash_alg` as the first field. `PramanixVerifier` reads `hash_alg` and routes to the correct computation. Define a migration protocol for upgrading decision archives.

```python
HASH_ALGORITHMS: dict[str, Callable[[Decision], bytes]] = {
    "sha256-v1": _compute_hash_v1,
    # "sha256-v2": _compute_hash_v2,  # add when canonical fields change
}
```

### 5.3 Observability Decoupling

**Problem:** Prometheus counters are initialized at module import in `guard_config.py` (lines 109-140). `prometheus-client` is a hard non-optional dependency in `pyproject.toml`. This means every `import pramanix` registers metrics in the global Prometheus registry, regardless of whether the user wants metrics.

**Hardened design:**

1. Move `prometheus-client` to optional extras: `pramanix[metrics]`
2. In `guard_config.py`, wrap all metric initialization in `try: import prometheus_client except ImportError: prometheus_client = None`
3. All metric increment calls become no-ops when `prometheus_client is None`
4. Document: Prometheus metrics are available with `pip install pramanix[metrics]`

This is the same pattern already used for OTel (`_OTEL_AVAILABLE` flag in `guard_pipeline.py`). Apply it consistently to Prometheus.

Similarly, move `orjson` to optional. The stdlib fallback already exists in `decision.py`. Make the fallback the guaranteed path; `orjson` becomes an optional performance enhancement:

```python
# decision.py — guaranteed stdlib path, orjson as optimization
try:
    from orjson import dumps as _json_dumps
    def _canonical_json(obj: dict) -> bytes:
        return _json_dumps(obj, option=OPT_SORT_KEYS)
except ImportError:
    import json
    def _canonical_json(obj: dict) -> bytes:
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
```

**Acceptance criteria:**
- `pip install pramanix` (no extras) produces zero Prometheus metrics in global registry
- `pip install pramanix[metrics]` enables Prometheus metrics
- `import pramanix` does not fail if `prometheus-client` is not installed
- `decision_hash` computation produces identical results with and without `orjson`

### 5.4 Policy Fingerprint Completeness

**Problem:** `_compute_policy_fingerprint()` omits `python_type` from the hash. Two policies with different Python types but same Z3 type share a fingerprint.

**Fix:** Add `f.python_type.__qualname__` to field canonical string. This is a one-line change with correct behavior. Document in CHANGELOG that fingerprint values change in this release (existing `ExecutionToken`s will be invalidated — expected and acceptable).

### 5.5 Governance Composition Architecture

See Section 7 for the full governance coupling design. The architectural principle here: governance enforcement must be impossible to misconfigure silently. `GuardConfig` should be the single composition point. A developer who configures a governance policy without wiring it should get a `ConfigurationError` at `Guard.__init__` time, not silent pass-through at runtime.

### 5.6 Failure Domain Isolation

**Current state:** Audit sink exceptions are caught and logged; they cannot affect decisions. This is correct. Resolver exceptions are caught per-resolver; missing resolvers log warnings and continue. OTel span failures are suppressed. These are all correct patterns.

**Gap:** `GuardViolationError.__init__` accesses `decision.status` at construction time. If a malformed `Decision` without a `status` attribute is passed (possible in adversarial process-mode scenarios), the exception constructor itself raises `AttributeError`, which propagates unexpectedly from a context where `GuardViolationError` was expected.

**Fix:** Add `getattr(decision, "status", SolverStatus.UNSAFE)` defensive access in `GuardViolationError.__init__`.

### 5.7 Configuration Ergonomics

**Current state:** `GuardConfig` is a frozen dataclass — immutable after construction, validated at construction time. This is correct design. All env vars read at construction time. No runtime reconfiguration race conditions.

**Gap:** `GuardConfig` currently has no `governance` field accepting governance policy objects. Adding this is the key composition primitive (see Section 7). The field should be `Optional[GovernanceConfig]` with default `None` for backward compatibility.

---

## 6. Security Tightening Plan

### 6.1 Deserialization Risk

**LB-1 covers the primary issue.** Secondary instances:

- `MerkleArchiver` reads `.merkle.archive.*` files without integrity verification on read. An attacker who modifies archive files after write will cause `verify_archive()` to produce incorrect results. Fix: HMAC-sign the archive file on write; verify on read. Document that archive files must be stored in write-protected storage for production.

- Worker receives `(policy_cls, values_dict, timeout_ms)` via pickle across the process boundary. `values_dict` is Pydantic-validated before dispatch — values are primitive Python types. `policy_cls` is a class reference (module path + classname). A compromised worker cannot forge the class reference; it can only receive what the host sends. This is acceptable — the HMAC seal protects the result, not the input.

### 6.2 Signing and Replay Protection

**Current state:** `DecisionSigner` (`audit/signer.py`) uses HMAC-SHA256 with `iat` removed from the signed payload. This means replays of historical `SignedDecision` objects are indistinguishable from fresh decisions by timestamp alone.

**Fix:** Add `jti` (JWT ID) nonce — a random UUID included in the signed payload. Verification checks that `jti` has not been seen before (requires a short-TTL Redis set or in-memory seen-set). This converts at-most-once token verification semantics to at-most-once signing semantics.

Alternatively: document explicitly that `DecisionSigner` provides integrity guarantees (was not tampered) but not freshness guarantees (was not replayed). For deployments requiring replay protection, use `ExecutionToken` (which already provides this via SETNX). This is an acceptable scope boundary if documented clearly.

### 6.3 Cryptographic Boundary Clarity

The coexistence of two signing systems (`DecisionSigner`/HMAC-SHA256 and `PramanixSigner`/Ed25519) is a documented dual-system design. The distinction must be made prominent in documentation:

| System | Algorithm | Key type | Freshness | Replay protection |
|---|---|---|---|---|
| `DecisionSigner` | HMAC-SHA256 | Symmetric shared secret | No (iat removed) | No (without jti) |
| `PramanixSigner` | Ed25519 | Asymmetric keypair | Via key rotation | Via key ID tracking |

Deployments should choose one. The default should be Ed25519 for any regulated-industry use case.

### 6.4 HashiCorp Vault KeyError

**File:** `key_provider.py:634`  
**Issue:** `resp["data"]["data"][self._field]` — if `_field` does not exist, raw `KeyError` propagates outside the try/except block at line 627.

**Fix:**
```python
try:
    value = resp["data"]["data"][self._field]
except KeyError:
    raise ConfigurationError(
        f"HashiCorp Vault secret at '{self._path}' does not contain field '{self._field}'. "
        f"Available fields: {list(resp.get('data', {}).get('data', {}).keys())}"
    ) from None
```

### 6.5 Audit Sink Delivery Guarantees

**Current state:** `KafkaAuditSink` drops decisions on queue overflow (line 218-225). This is at-most-once delivery. For regulated deployments, decisions must reach the audit trail. Dropping them silently is a compliance failure.

**Fix options (in order of implementation cost):**

1. **Minimal (immediate):** Expose `overflow_policy` enum: `DROP` (current), `BLOCK_CALLER` (backpressure), `DEAD_LETTER_QUEUE`. Default remains `DROP` for backward compatibility but document it prominently.

2. **Full (v1.1):** Implement Kafka transactions for exactly-once delivery. This requires `confluent-kafka` transactional producer mode.

3. **Alternative:** Make the queue size configurable and default to a much larger value (100,000+) with documented overflow behavior.

**Acceptance criteria:** `overflow_policy` parameter documented; overflow counter metric visible in `pramanix_audit_sink_overflow_total`; operational runbook in docs for overflow alert response.

### 6.6 Secret Handling at Import Time

`guard_config.py` reads environment variables at `GuardConfig.__init__` time, not at module import time. This is correct — no secrets are captured into module-level variables. The `_redact_secrets_processor` runs as the first structlog processor before any renderer. Confirmed strong.

One gap: `DatadogAuditSink` scrubs error response bodies, which "may contain API key." The scrubbing is post-hoc — the API key may have already been logged by an upstream handler. Verify that Datadog sink does not log the raw response body before scrubbing.

### 6.7 Import-Time Side Effects

After moving `prometheus-client` to optional and applying the `_PROMETHEUS_AVAILABLE` pattern:

**Remaining mandatory import-time side effects:**
- `structlog` configuration — acceptable; structlog initialization is idempotent
- `z3.Context` creation — lazy (only when solver used); acceptable
- `_RESULT_SEAL_KEY = _EphemeralKey(secrets.token_bytes(32))` — at `worker.py` module load; acceptable; this is intentional and documented

No remaining global-state pollution from mandatory imports after the `prometheus-client` and `orjson` moves.

---

## 7. Governance and Enforcement Completion Plan

### 7.1 The Core Problem Statement

The six governance subsystems are real, non-trivial Python libraries. They are not stubs. But they are libraries — meaning callers must explicitly invoke them. For a governance framework to provide security guarantees, governance must be infrastructure: automatic, mandatory when configured, impossible to forget.

The gap is architectural, not implementational. The fix requires a composition primitive at the `GuardConfig` layer and an enforcement hook inside `guard.verify()`.

### 7.2 Proposed Composition Design

Define a `GovernanceConfig` dataclass that `GuardConfig` accepts as an optional field:

```python
@dataclass(frozen=True)
class GovernanceConfig:
    # Information Flow Control
    ifc_policy: FlowPolicy | None = None
    ifc_enforcer: FlowEnforcer | None = None

    # Privilege Separation
    privilege_manifest: CapabilityManifest | None = None
    privilege_enforcer: ScopeEnforcer | None = None

    # Human Oversight
    oversight_workflow: ApprovalWorkflow | None = None
    oversight_required_for: frozenset[str] = frozenset()
    # ^ set of invariant labels that require human approval when allowed

    # Provenance
    provenance_chain: ProvenanceChain | None = None

    # Memory
    memory_store: SecureMemoryStore | None = None

    def __post_init__(self) -> None:
        # Validate consistency: if enforcer provided, policy must also be provided
        if self.ifc_enforcer is not None and self.ifc_policy is None:
            raise ConfigurationError(
                "GovernanceConfig: ifc_enforcer provided without ifc_policy. "
                "Provide ifc_policy or remove ifc_enforcer."
            )
        # ... similar checks for privilege
```

`GuardConfig` adds:
```python
governance: GovernanceConfig | None = None
```

### 7.3 Enforcement Hook in guard.verify()

After the Z3 solve produces an ALLOW decision, before signing and audit emission, `guard.verify()` calls `_apply_governance()`:

```python
def _apply_governance(
    self,
    decision: Decision,
    intent: dict,
    state: dict,
) -> Decision:
    """
    Apply configured governance subsystems to an ALLOW decision.
    Any governance failure converts the ALLOW to a BLOCK.
    All governance failures are fail-closed.
    """
    if self._config.governance is None:
        return decision

    gov = self._config.governance

    # IFC enforcement
    if gov.ifc_enforcer is not None:
        try:
            gov.ifc_enforcer.gate(
                data_label=intent.get("_data_label", ""),
                sink_label=intent.get("_sink_label", ""),
                source_component=intent.get("_source_component"),
                sink_component=intent.get("_sink_component"),
            )
        except FlowViolationError as e:
            return Decision.block(
                allowed=False,
                violated_invariants=("ifc_flow_violation",),
                explanation=str(e),
                ...
            )
        except Exception:
            return Decision.error(allowed=False, explanation="IFC enforcement error")

    # Privilege enforcement
    if gov.privilege_enforcer is not None:
        try:
            gov.privilege_enforcer.enforce(
                tool=intent.get("_tool_name", ""),
                scope=intent.get("_requested_scope", ExecutionScope.NONE),
                approved_by=intent.get("_approved_by", []),
            )
        except PrivilegeEscalationError as e:
            return Decision.block(allowed=False, ...)
        except Exception:
            return Decision.error(allowed=False, explanation="Privilege enforcement error")

    # Oversight requirement check
    if gov.oversight_required_for:
        violated = set(decision.violated_invariants or [])
        # For ALLOW decisions, check if any allowed-but-flagged invariants require approval
        # This is for "high-risk ALLOW" scenarios
        if gov.oversight_required_for.intersection(intent.get("_risk_labels", set())):
            if gov.oversight_workflow is not None:
                try:
                    gov.oversight_workflow.request_approval(decision)
                except OversightRequiredError:
                    # Expected: decision requires human approval
                    return Decision.block(
                        allowed=False,
                        explanation="Human oversight required for this action",
                        ...
                    )

    # Provenance recording
    if gov.provenance_chain is not None:
        try:
            gov.provenance_chain.append(ProvenanceRecord.from_decision(decision))
        except Exception:
            # Provenance failure is logged but does not block the decision
            # (provenance is observability, not enforcement)
            logger.warning("Provenance recording failed", exc_info=True)

    return decision
```

### 7.4 What Remains Beta

The following governance capabilities should remain explicitly `beta` in v1.0:

- `ShadowEvaluator` (policy lifecycle) — requires synchronous wrapping for async use
- `PolicyDiff` (lifecycle diff) — operational tooling, not enforcement
- `MemoryStore` integration into Guard — memory-scoped access control requires a different intent model extension; not ready for automatic coupling

### 7.5 Durable Oversight Backend

`InMemoryApprovalWorkflow` generates its HMAC key at `oversight/workflow.py:491` (`os.urandom(32)`). Process restart invalidates all historical record verification. This is unacceptable for regulated industries.

**Minimum viable durable backend:**

```python
class RedisApprovalWorkflow(ApprovalWorkflow):
    """
    Durable approval workflow backed by Redis.
    HMAC key stored in Redis (or fetched from KMS).
    Records serialized to Redis hashes with TTL.
    """
    def __init__(
        self,
        redis_client: redis.Redis,
        hmac_key_source: KeyProvider,  # fetch from KMS, not os.urandom
        record_ttl_days: int = 365,
    ) -> None: ...
```

**Acceptance criteria:**
- `RedisApprovalWorkflow` implemented and tested with `fakeredis` unit tests + real Redis integration test
- `InMemoryApprovalWorkflow` docstring clearly states: "Not suitable for regulated production deployments. Use RedisApprovalWorkflow for persistence."

### 7.6 O(n) Eviction Fix

Three modules use `list.pop(0)` for O(n) FIFO eviction:

- `memory/store.py:200`
- `provenance.py` (ProvenanceChain.append)
- `lifecycle/diff.py` (ShadowEvaluator)

**Fix:** Replace all with `collections.deque(maxlen=N)`. This is a mechanical change with identical semantics and O(1) eviction:

```python
from collections import deque

# Before
self._entries: list[MemoryEntry] = []
# ... 
if len(self._entries) > self._max_entries:
    self._entries.pop(0)
self._entries.append(entry)

# After
self._entries: deque[MemoryEntry] = deque(maxlen=self._max_entries)
# ... 
self._entries.append(entry)  # deque handles eviction automatically
```

---

## 8. Test and Verification Strategy Upgrade

### 8.1 Current Test Landscape

| Category | Current state | Signal quality |
|---|---|---|
| Core verification (Z3, policy, transpiler, solver) | Real Z3, Hypothesis property tests, adversarial suite | HIGH |
| Worker/HMAC/IPC | Real thread/process pool, real HMAC | HIGH |
| Decision/crypto/audit | Real Ed25519, real SHA-256, real Merkle | HIGH |
| FastAPI/LangChain adapters | Real framework objects | HIGH |
| LlamaIndex/AutoGen | Real framework objects | MEDIUM-HIGH |
| Execution tokens (SQLite, Postgres) | Real SQLite WAL; real Postgres via testcontainers | HIGH |
| Redis (token, circuit breaker) | `fakeredis` unit; real Redis in integration | MEDIUM-HIGH |
| Kafka/S3 audit sinks | Stub unit; real testcontainers integration | HIGH (integration) |
| CrewAI/DSPy/Haystack/PydanticAI/SK | No real framework | LOW |
| Cloud KMS | Injected fake clients | LOW |
| Governance subsystems (unit) | Real Python logic | MEDIUM |
| Governance + Guard coupling | **Not tested** | NONE |
| async-process mode on Windows | **Not tested** | NONE |
| Coverage-padding files | Trivial path exercises | NOISE |

### 8.2 Test Gaps to Close Before Launch

**G1: Governance coupling integration tests**  
New file: `tests/integration/test_governance_coupling.py`  
Tests: Guard + GovernanceConfig(ifc) auto-enforces on ALLOW; Guard + GovernanceConfig(privilege) blocks escalation; oversight required → BLOCK returned; governance error → fail-closed BLOCK.

**G2: Real-framework adapter smoke tests**  
New CI jobs: one per adapter (CrewAI, DSPy, Haystack, PydanticAI, SemanticKernel).  
Each job: `pip install pramanix[adapter]`; import and construct adapter; exercise ALLOW path and BLOCK path; verify decision structure.

**G3: Windows CI for async-process mode**  
Add `windows-latest` runner to CI matrix. Run: `tests/unit/test_worker.py` and `tests/unit/test_process_pickle.py` and a new `test_async_process_windows.py` that exercises policy-defined-at-module-level with spawn semantics.

**G4: Decision hash versioning tests**  
New tests in `test_decision.py`: hash_alg field present; hash_alg included in canonical bytes; PramanixVerifier routes by hash_alg; unknown hash_alg raises UnsupportedAlgorithmError.

**G5: CalibratedScorer HMAC integrity tests**  
New tests: tampered file raises IntegrityError; correct file loads; missing sig file raises FileNotFoundError; save+load round-trip succeeds.

**G6: FlowRule glob matching tests**  
New `tests/unit/test_flow_rule_glob.py`: 12 parametrized cases covering exact match, prefix wildcard, no-match, nested path, component patterns.

**G7: Install smoke tests**  
New CI stage: build wheel, install into clean venv, `python -c "import pramanix; assert pramanix.__version__ == '1.0.0'"`, verify no import errors on Python 3.11/3.12/3.13.

### 8.3 Removing Coverage Theater

**Procedure:**
1. Run each `test_coverage_*` file in isolation; record which source lines are newly covered
2. For lines that cover meaningful behavior: extract test into the appropriate named test file
3. For lines that cover trivial paths (`__repr__`, `str()`, single-line property): delete without replacement
4. Re-run coverage; accept the new (honest) number
5. If coverage drops below 90%: identify the genuinely uncovered meaningful code and write scenario tests for it

**Target:** 93%+ honest coverage after purge. Do not re-inflate with new padding.

### 8.4 Release Test Matrix

The following matrix must pass before any PyPI publication:

| Test suite | Python 3.11 | Python 3.12 | Python 3.13 | Linux | macOS | Windows |
|---|---|---|---|---|---|---|
| Unit (core) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Unit (governance) | ✓ | ✓ | ✓ | ✓ | — | — |
| Integration (testcontainers) | — | — | ✓ | ✓ | — | — |
| Adapter smoke (all 9) | — | — | ✓ | ✓ | — | — |
| async-process mode | — | — | ✓ | ✓ | — | ✓ |
| Install smoke | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Adversarial suite | — | — | ✓ | ✓ | — | — |
| Governance coupling | — | — | ✓ | ✓ | — | — |

---

## 9. Packaging, Compatibility, and PyPI Readiness

### 9.1 Python Version Strategy

**Immediate action:** Lower `pyproject.toml` to `python = ">=3.11,<4.0"`. Add Python 3.11 and 3.12 to CI matrix. Audit for any 3.13-only syntax.

**Long-term policy:** Support N and N-1 Python minor versions within their security support window. Drop a Python version only when it exits security support AND a new minor version covers >80% of the install base.

| Python version | Security support ends | Pramanix support status |
|---|---|---|
| 3.11 | 2027-10 | Must support for 1.0 |
| 3.12 | 2028-10 | Must support for 1.0 |
| 3.13 | 2029-10 | Current development version |
| 3.14+ | — | Add when stable |

### 9.2 Dependency Restructure

**Mandatory (always installed):**

| Package | Justification | Action |
|---|---|---|
| `z3-solver ^4.12` | Core functionality; cannot be optional | Keep mandatory |
| `pydantic ^2.5` | Field validation and model schema | Keep mandatory |
| `structlog ^23.2` | Structured logging throughout | Keep mandatory |

**Move to optional:**

| Package | Current | Target extra | Justification |
|---|---|---|---|
| `prometheus-client ^0.19` | Hard | `[metrics]` | Side effect at import; not all users need metrics |
| `orjson >=3.9` | Hard | `[performance]` | Stdlib fallback exists; orjson is optimization |

**Updated extras layout:**

```toml
[tool.poetry.extras]
# Core optional functionality
metrics    = ["prometheus-client"]
performance = ["orjson"]
otel       = ["opentelemetry-sdk", "opentelemetry-exporter-otlp-proto-grpc"]
crypto     = ["cryptography"]

# Identity and tokens
identity   = ["redis"]
postgres   = ["asyncpg"]

# Translator (LLM extraction)
translator = ["httpx", "openai", "anthropic", "tenacity"]

# Framework adapters
fastapi    = ["fastapi", "starlette", "httpx"]
langchain  = ["langchain-core"]
llamaindex = ["llama-index-core"]
autogen    = ["pyautogen"]
crewai     = ["crewai"]
dspy       = ["dspy-ai"]
haystack   = ["haystack-ai"]
pydantic-ai = ["pydantic-ai"]
semantic-kernel = ["semantic-kernel"]

# Cloud key providers
aws        = ["boto3"]
azure      = ["azure-keyvault-secrets", "azure-identity"]
gcp        = ["google-cloud-secret-manager"]
vault      = ["hvac"]

# Audit sinks
kafka      = ["confluent-kafka"]
s3         = ["boto3"]
datadog    = ["datadog-api-client"]

# Governance persistence
governance = ["redis"]

# Everything
all = [...]
```

### 9.3 Binary Dependency Policy

`z3-solver` is a binary dependency (C++ extension). `orjson` (after moving to optional) is a Rust binary. `confluent-kafka` is a librdkafka wrapper. `cryptography` is a Rust/C binary.

**Policy:** All binary dependencies must:
1. Publish pre-built wheels for Linux (x86_64, aarch64), macOS (x86_64, arm64), and Windows (x86_64) for all supported Python versions
2. Be verifiable via `pip install --only-binary :all: pramanix` without compilation
3. Be pinned to ranges that exclude known vulnerable versions (enforced by Trivy)

### 9.4 Semantic Versioning Policy

| Increment | When |
|---|---|
| Patch (1.0.x) | Bug fixes, security patches, documentation corrections |
| Minor (1.x.0) | New features, new beta subsystems, new adapters — backward-compatible |
| Major (x.0.0) | Breaking API changes; `decision_hash` algorithm version bump; policy DSL breaking changes |

**Stability tiers at 1.0.0:**

| Tier | Modules | Stability guarantee |
|---|---|---|
| Stable | `guard`, `policy`, `expressions`, `transpiler`, `solver`, `worker`, `decision`, `fast_path` | No breaking changes without major version |
| Stable | `execution_token`, `circuit_breaker`, `crypto`, `audit`, `audit_sink`, `key_provider`, `primitives` | No breaking changes without major version |
| Beta | `translator`, `integrations`, `ifc`, `privilege`, `oversight`, `memory`, `lifecycle`, `provenance` | May change in minor versions; migration notes provided |
| Experimental | `CalibratedScorer`, `ShadowEvaluator`, `ComplianceReport` | May change in any version |

### 9.5 PyPI Trusted Publishing Configuration

Configure GitHub Actions OIDC-based trusted publishing:

```yaml
# .github/workflows/publish.yml
name: Publish to PyPI
on:
  release:
    types: [published]

permissions:
  id-token: write  # Required for OIDC

jobs:
  publish:
    runs-on: ubuntu-latest
    environment: pypi-publish
    steps:
      - uses: actions/checkout@v4
      - name: Build
        run: poetry build
      - name: Verify wheel
        run: |
          pip install dist/*.whl --only-binary :all:
          python -c "import pramanix; assert pramanix.__version__ == '${{ github.ref_name }}'"
      - name: Publish
        uses: pypa/gh-action-pypi-publish@release/v1
```

No stored API keys. No password secrets. OIDC-only. This is the current best practice for PyPI security.

---

## 10. Developer Experience Tightening

### 10.1 First-Run Experience

A new developer should be able to write a working policy and get a verified decision in under 5 minutes. The current quickstart in the README is functionally correct after the DSL method name corrections, but the path from installation to first decision has friction:

1. `pip install pramanix` fails (not on PyPI)
2. Installation from source is documented but not obvious
3. Cloud provider imports are not re-exported from top-level (`AwsKmsKeyProvider` requires `from pramanix.key_provider import ...`)
4. `async-process` mode requires policies to be defined at module level — not documented prominently

**Minimum viable quickstart experience:**
```python
# pip install pramanix (after PyPI publication)
from pramanix import Guard, Policy, Field, E

class FinancialPolicy(Policy):
    amount  = Field("amount",  float, "Real")
    balance = Field("balance", float, "Real")

    @classmethod
    def invariants(cls):
        return [
            (E(cls.amount) > 0).named("positive_amount"),
            (E(cls.amount) <= E(cls.balance)).named("sufficient_balance"),
        ]

guard = Guard(FinancialPolicy)
decision = guard.verify(
    intent={"amount": 100.0},
    state={"balance": 500.0},
)
print(decision.allowed)          # True
print(decision.status.value)     # "SAFE"
print(decision.decision_hash)    # SHA-256 fingerprint
```

This must work exactly as shown, in a clean virtual environment, with no additional configuration. Test this as a CI artifact.

### 10.2 Error Message Quality Audit

Audit all `ConfigurationError`, `PolicyCompilationError`, `InvariantLabelError`, `FieldTypeError`, and `GuardViolationError` messages for:
- Does the message name the specific field/invariant/file that caused the error?
- Does the message explain what to do to fix it?
- Is the message reproducible without inspecting source code?

Known improvement areas:
- `HashiCorpVaultKeyProvider` `KeyError` (see LB fix above)
- `Field()` positional argument order — error message should say "Did you swap python_type and z3_sort?"
- `async-process` mode `PicklingError` — intercept and re-raise with "Policies used with async-process mode must be defined at module level (not inside functions or closures)"

### 10.3 Policy Template Library

Create `src/pramanix/templates/` with ready-to-use policy templates:

```
templates/
  finance/
    transfer_policy.py      # amount, balance, daily_limit constraints
    payment_policy.py       # merchant category, amount, card limits
  healthcare/
    medication_policy.py    # dosage, frequency, contraindications
    access_policy.py        # RBAC for patient record access
  infrastructure/
    deployment_policy.py    # replicas, resource limits, environment gates
    access_policy.py        # SSH, RDP, database access controls
  rbac/
    role_policy.py          # role-based permission invariants
```

Each template includes: the Policy class, usage example, customization guide, and the formal invariants with human-readable explanations.

### 10.4 CLI Completeness

`pramanix doctor` is well-implemented. Add:
- `pramanix init --template finance` — scaffold a working Policy file from a template
- `pramanix validate policy.py` — import and compile a policy file, report all errors
- `pramanix benchmark policy.py --n 1000` — run a latency benchmark against a user-supplied policy

### 10.5 Footgun Removal

| Footgun | Fix |
|---|---|
| `Field("name", python_type, z3_sort)` — swapping 2/3 detected only at Guard construction | Add keyword-only parameter enforcement or clear error message |
| `AwsKmsKeyProvider` not importable from top-level | Re-export from `pramanix.__init__` or document explicitly with `from pramanix.key_provider import ...` |
| `is_business_hours()` weekday encoding (0=Thursday, not Monday) | Add explicit docstring example: "Note: epoch day 0 = 1970-01-01 (Thursday). Use `weekday=0` for Thursday behavior." |
| `Meta` inner class silently dropped in subclasses | Use MRO traversal: `next((vars(c)["Meta"] for c in type(cls).__mro__ if "Meta" in vars(c)), None)` |
| `async-process` mode silently fails for closures | Intercept `PicklingError` and re-raise with actionable message |

---

## 11. Documentation Program

### 11.1 Required Before Launch

| Document | Status | Required action |
|---|---|---|
| `README.md` | Updated (DSL names corrected) | Add installation instructions for PyPI; add quickstart that works |
| `docs/ARCHITECTURE_NOTES.md` | Accurate | Add governance coupling section; update with composition primitive |
| `docs/PUBLIC_API.md` | Accurate (cleaned) | Add `GovernanceConfig`; add `hash_alg` field; add `RedisApprovalWorkflow` |
| `docs/KNOWN_GAPS.md` | Present and honest | Update as gaps are closed |
| `docs/THREAT_MODEL.md` | Missing | Create: STRIDE analysis, trust boundaries, attack surfaces, residual risks |
| `docs/SECURITY_MODEL.md` | Missing | Create: what is guaranteed, what is not, how to verify claims |
| `docs/QUICKSTART.md` | Missing | Create: 5-minute working example, zero-to-decision guide |
| `docs/PRODUCTION_DEPLOYMENT.md` | Missing | Create: Redis token store, circuit breaker config, audit sink config, monitoring setup |
| `docs/GOVERNANCE_GUIDE.md` | Missing | Create: IFC, Privilege, Oversight configuration; GovernanceConfig composition |
| `docs/BENCHMARK_METHODOLOGY.md` | Missing | Create: how benchmarks are run, what they measure, limitations |
| `LAUNCH_CLAIMS.md` | Missing | Create: explicit list of what Pramanix guarantees and what it does not (see Section 14) |

### 11.2 Required by v1.1 (Post-Launch)

| Document | Notes |
|---|---|
| `docs/ADAPTER_GUIDE.md` | Per-adapter integration guide with real examples |
| `docs/POLICY_TEMPLATES.md` | Template library documentation |
| `docs/CLOUD_KMS_GUIDE.md` | Production configuration for AWS/Azure/GCP/Vault |
| `docs/MIGRATION.md` | v0.x → v1.0 migration guide |
| `docs/CONTRIBUTING.md` | Community contribution protocol |

### 11.3 Documentation Truthfulness Standards

Every statement in public documentation must be verifiable from code. The following statements are currently misleading and must be corrected or removed:

- Any implication that the governance subsystems are automatically enforced by `guard.verify()` — not true until coupling is implemented
- `"Development Status :: 5 - Production/Stable"` in PyPI classifiers — change to `4 - Beta` until governance coupling and cloud KMS real testing are complete
- Any benchmark claim that does not include the `"passed": false` context for P50 (5.235ms vs 5ms target)

### 11.4 Changelog and ADR Policy

`docs/CHANGELOG.md` is currently accurate and honest. Maintain it. Continue the pattern of `[Unreleased]` section in CHANGELOG with `Fixed`, `Added`, `Changed`, `Deprecated`, `Removed`, `Security` subsections per Keep a Changelog convention.

ADRs in `docs/DECISIONS.md` with rejected alternatives documented are a genuine asset. Mandate new ADRs for: governance coupling design, decision hash versioning, Python version strategy, dependency structure changes.

---

## 12. Performance and Scale Plan

### 12.1 What the Existing Benchmark Evidence Proves

| Evidence | Source | What it proves |
|---|---|---|
| P50=5.235ms, P95=6.361ms, P99=7.109ms | `benchmarks/results/latency_results.json` | API-mode latency at N=2,000 iterations on one machine |
| "passed": false | Same file | P50 just above 5ms target — margin is thin |
| 100M decisions, 18 workers, 150ms solver timeout | `run_finance_20260322_052731/run_meta.json` | Kernel can sustain high decision volume on local hardware |
| Nightly benchmark job | `ci.yml` | P99 < 15ms gate runs daily — CI environment performance unknown |

**What the evidence does NOT prove:**

- Performance under concurrent load with multiple different active policies
- Performance under LRU cache contention with many policy fingerprints
- Audit sink pipeline performance under high decision volume
- Multi-replica coordination performance (Redis pubsub latency)
- Governance subsystem performance impact when coupled to Guard
- Performance on cloud VMs (CI uses GitHub-hosted runners)

### 12.2 Pre-Launch Performance Requirements

**Latency:** The 5ms P50 target must be verifiable in a reproducible environment. Either:
- Achieve P50 < 5ms reliably (requires profiling the hot path and optimizing), or
- Change the published target to 6ms (honest), or
- Publish latency targets per-mode: `sync < 6ms P50`, `async-thread < 8ms P50`

**Throughput:** Document the 100M decision benchmark methodology:
- Hardware spec
- Policy complexity (single fintech policy vs mixed policy set)
- Worker configuration
- Solver timeout setting

**Scale claims:** Do not publish throughput claims based on the local 100M benchmark without a cloud-environment reproduction. Run the benchmark on a standard cloud VM (e.g., AWS c5.4xlarge) and publish that result.

### 12.3 Audit Sink Scale

KafkaAuditSink at 10,000-entry queue with at-most-once delivery is unsuitable for high-throughput regulated deployments. Before publishing throughput claims:

- Measure decisions-per-second at which the queue saturates
- Publish the saturation threshold as an operational limit
- Document overflow behavior prominently
- Provide operational runbook: "If `pramanix_audit_sink_overflow_total` counter is nonzero, your audit delivery rate is below your decision rate."

### 12.4 Governance Coupling Performance Impact

When governance subsystems are coupled into `guard.verify()`, each ALLOW decision incurs additional synchronous calls (IFC gate, privilege check, provenance append). Measure and publish this overhead before launch. Target: governance coupling adds < 2ms to ALLOW decision latency in sync mode.

---

## 13. Competitive Readiness Plan

### 13.1 Guardrails AI: Honest Comparison

| Dimension | Pramanix | Guardrails AI | Winner |
|---|---|---|---|
| Structured action authorization | Z3 formal proof with attribution | Probabilistic validators | **Pramanix** |
| Violation attribution | Per-invariant with counterexample | Generic rejection message | **Pramanix** |
| Fail-closed provability | Adversarially tested, code-verifiable | Probabilistic best-effort | **Pramanix** |
| LLM output content validation | Zero capability | Hub of 50+ validators | **Guardrails AI** |
| PyPI availability | Not published | Published and installable | **Guardrails AI** |
| Non-programmer usability | DSL only | Python API + GUI options | **Guardrails AI** |
| Production deployments | None documented | Thousands | **Guardrails AI** |
| Documentation breadth | Solid but incomplete | Comprehensive | **Guardrails AI** |

**What Pramanix needs before public comparison is credible:**
- PyPI publication with clean install
- At least one documented real production deployment
- Performance data in a cloud environment
- Governance subsystems coupled and enforced

**After those requirements are met:** Pramanix wins on formal correctness for structured action authorization. Position against Guardrails AI with: "For structured AI agent action authorization, formal Z3 proof produces stronger guarantees than probabilistic validators. Every Pramanix BLOCK comes with a counterexample. Every Pramanix ALLOW comes with a mathematical proof."

### 13.2 NeMo Guardrails: Different Domain

NeMo addresses conversational AI safety (dialog flow, topic control, factual grounding). Pramanix addresses structured action authorization. Direct comparison is misleading to buyers.

**Correct framing:** "NeMo controls what your LLM says. Pramanix controls what your agent does." These are complementary. A production AI system that generates responses (NeMo's domain) and also takes actions (Pramanix's domain) can use both.

Do not compete with NeMo. Build an integration: `PramanixNeMoGuard` that uses NeMo for conversation safety and Pramanix for action authorization in the same agent system.

### 13.3 LangChain/LlamaIndex: Ecosystem Targets

**Positioning:** "Pramanix is the formal enforcement primitive that production LangChain and LlamaIndex deployments use to govern agent tool calls."

**Required for credibility:** Real case study showing a LangChain agent deployment where `PramanixGuardedTool` prevented a harmful action that a probability-based guard would have missed. Publish this as a technical blog post with reproducible code.

### 13.4 Category Claim

Pramanix's unique competitive position: **No open-source SDK backed by a sound SMT solver exists for formal AI agent action authorization.**

This is the claim to own. It is technically true. It requires no competitor disparagement. It invites technical evaluation. It establishes a category. Use it consistently.

---

## 14. Public Claim Boundaries

### Safe to Claim at Launch

- "Formal action authorization primitive for structured AI agent systems"
- "Every ALLOW decision comes with a Z3-derived mathematical proof that all policy invariants are satisfied"
- "Every BLOCK decision comes with a complete attribution of which invariants were violated and why"
- "Fail-closed by design: every error path returns BLOCK, never ALLOW, verified by adversarial test suite"
- "HMAC-sealed worker IPC prevents compromised worker processes from forging ALLOW decisions"
- "Deterministic: given identical inputs and timeout, produces identical decisions"
- "Real testcontainers infrastructure: Kafka, Postgres, Redis, and LocalStack S3 exercised in CI"
- "No MagicMock in test logic: all test infrastructure uses real protocol implementations"
- "Timing oracle mitigation: min_response_ms pad applied identically to ALLOW and BLOCK"
- "Merkle second-preimage protection in audit trail (Bitcoin CVE-2012 mitigation applied)"

### Safe to Claim with Qualification

- "Production-ready kernel for sync and async-thread modes on Linux" *(qualify: async-process on Windows is untested in CI)*
- "P99 latency under 15ms at N=2,000" *(qualify: on specific hardware; P50 is 5.235ms just above 5ms target)*
- "Integrations for LangChain, FastAPI, LlamaIndex, AutoGen" *(qualify: real test coverage; CrewAI/DSPy/Haystack/PydanticAI/SK are implemented but not CI-validated against real frameworks)*
- "AWS, Azure, GCP, and HashiCorp Vault key providers" *(qualify: tested with injected stubs; real IAM paths not validated)*
- "Governance subsystems for IFC, Privilege, Oversight, Memory, Lifecycle, Provenance" *(qualify: beta; require explicit developer coupling until v1.1 governance release)*

### Not Safe to Claim at Launch

- "Enterprise-ready" — requires real production deployments, real cloud KMS validation, SLA definitions, multi-environment CI
- "Production-ready governance" — governance subsystems are libraries, not enforced infrastructure, until coupling is implemented
- "Guaranteed audit delivery" — KafkaAuditSink drops decisions on queue overflow
- "Complete framework adapter coverage" — five adapters unvalidated against real frameworks
- "98% test coverage" — actual gate is 95%; coverage includes padding files
- "Cross-platform" — Windows async-process mode untested
- "98% behavioral coverage" — coverage metric is inflated by coverage-padding files

---

## 15. 90-Day Execution Plan

### Phase 0: Launch Blockers (Days 1–21)

**Objective:** Resolve all CRITICAL and HIGH blockers. Nothing else before these are done.

| Workstream | Task | Files affected | Definition of done |
|---|---|---|---|
| Security | CalibratedScorer HMAC (LB-1) | `injection_scorer.py` | HMAC-verify before pickle.load; test coverage |
| Security | FlowRule glob matching (LB-2) | `ifc/flow_policy.py` | fnmatch implementation; 12 test cases |
| Packaging | Python 3.11+ compatibility (LB-3) | `pyproject.toml`, CI matrix | Full test suite on 3.11, 3.12, 3.13 |
| Security | HashiCorp Vault KeyError (S-3) | `key_provider.py` | ConfigurationError with field name |
| Core | Decision hash versioning (LB-5) | `decision.py`, `crypto.py` | `hash_alg` field; PramanixVerifier routes by alg |
| Core | Policy fingerprint python_type (LB-6) | `guard_pipeline.py` | python_type in fingerprint hash |
| Deps | Move prometheus-client to optional (5.3) | `pyproject.toml`, `guard_config.py` | Zero import-time side effects without extra |
| Deps | Move orjson to optional (5.3) | `pyproject.toml`, `decision.py` | Stdlib fallback is guaranteed path |
| Tests | Remove coverage-padding files (LB-8) | 6 `test_coverage_*` files | Zero files named `test_coverage_*` |
| Tests | Align coverage gate (LB-7) | `pyproject.toml`, `ci.yml` | Single consistent gate value |

**Acceptance test for Phase 0:** Zero CRITICAL or HIGH blockers open. `bandit -r src/pramanix` reports zero HIGH findings. `pip install pramanix` succeeds on Python 3.11 in a clean venv.

---

### Phase 1: Platform Coupling (Days 22–50)

**Objective:** Transform governance subsystems from libraries into enforced infrastructure. Validate all adapters.

| Workstream | Task | Files affected | Definition of done |
|---|---|---|---|
| Governance | `GovernanceConfig` dataclass | New file `governance_config.py` | Dataclass with all 6 subsystem fields; `__post_init__` validation |
| Governance | `GuardConfig.governance` field | `guard_config.py` | Optional `GovernanceConfig` field |
| Governance | `_apply_governance()` in guard | `guard.py` | Called on all ALLOW decisions; fail-closed on governance errors |
| Governance | Governance coupling integration tests | New `test_governance_coupling.py` | 5+ tests covering IFC, privilege, oversight, provenance, fail-closed |
| Governance | O(n) eviction fix | `memory/store.py`, `provenance.py`, `lifecycle/diff.py` | `collections.deque` replaces `list.pop(0)` |
| Governance | `RedisApprovalWorkflow` | `oversight/workflow.py` or new file | Durable oversight backend with real Redis integration test |
| Adapters | Real-framework CI for 5 adapters | `.github/workflows/ci.yml`, adapter files | Each adapter has smoke test against real framework version |
| Adapters | Windows CI for async-process | `.github/workflows/ci.yml` | `test_worker.py` passes on `windows-latest` |
| Pipeline | Unify sync/async pipeline | `guard.py` | Shared `_pipeline_steps` functions; two trees merged to one |

**Acceptance test for Phase 1:** Governance coupling integration test passes with real Guard + IFC + Privilege enforcement. All 9 adapters have CI-validated smoke tests. Async-process mode passes on Windows runner.

---

### Phase 2: Production Hardening and Documentation (Days 51–75)

**Objective:** Harden operational layer, write required documentation, reach launch-ready state.

| Workstream | Task | Files affected | Definition of done |
|---|---|---|---|
| Packaging | Python 3.11/3.12/3.13 full matrix | `pyproject.toml`, CI | All three versions in CI matrix; full test suite passes on all |
| Packaging | PyPI trusted publishing setup | `.github/workflows/publish.yml` | OIDC-configured; test PyPI publish succeeds |
| Packaging | Wheel/sdist smoke test CI stage | `ci.yml` | Install artifact; import check on all three Python versions |
| Packaging | `pyproject.toml` classifier fix | `pyproject.toml` | `Development Status :: 4 - Beta` |
| Performance | Cloud-environment latency benchmark | `benchmarks/` | P50/P95/P99 published from AWS/GCP VM |
| Performance | Governance coupling latency measurement | New benchmark | <2ms overhead documented |
| Observability | `KafkaAuditSink.overflow_policy` | `audit_sink.py` | Configurable DROP/BACKPRESSURE/DLQ |
| Docs | `docs/THREAT_MODEL.md` | New file | STRIDE analysis; trust boundaries; residual risks |
| Docs | `docs/SECURITY_MODEL.md` | New file | Guarantees and non-guarantees |
| Docs | `docs/QUICKSTART.md` | New file | Zero-to-decision in 5 minutes; tested as CI artifact |
| Docs | `docs/PRODUCTION_DEPLOYMENT.md` | New file | Redis, circuit breaker, audit sinks, monitoring |
| Docs | `docs/GOVERNANCE_GUIDE.md` | New file | GovernanceConfig composition guide |
| Docs | `LAUNCH_CLAIMS.md` | New file | Section 14 claims table |
| Tests | Release test matrix | CI | Full matrix from Section 8.4 passes |
| CLI | Policy template scaffolding | `cli.py`, `templates/` | `pramanix init --template finance` works |

**Acceptance test for Phase 2:** Full release test matrix green. All required documentation complete and reviewed. `pramanix doctor` returns clean bill of health on a production-configuration environment.

---

### Phase 3: PyPI Launch (Days 76–90)

**Objective:** Ship v1.0.0 to PyPI with correct positioning and honest documentation.

| Task | Definition of done |
|---|---|
| Tag `v1.0.0` | Git tag signed; `__version__ == "1.0.0"` |
| Publish to PyPI (test) | `pip install -i https://test.pypi.org/simple/ pramanix` succeeds |
| Publish to PyPI (production) | `pip install pramanix` succeeds; import works; version correct |
| GitHub Release | Release notes written; wheel/sdist attached; CHANGELOG entry complete |
| README update | PyPI badge, install command, quickstart link |
| Announcement draft | Technical blog post: "What Pramanix is and what it is not" — positions against Guardrails AI and NeMo without overclaiming |
| Monitoring | `pramanix_decisions_total` Prometheus metric visible in `[metrics]` install |

**Acceptance test for Phase 3:** `pip install pramanix` works globally. Quickstart guide produces a working decision in under 5 minutes. `LAUNCH_CLAIMS.md` is accurate.

---

## 16. 12–18 Month Category Plan

### Month 1–3: Foundation (PyPI + Community Seed)

- PyPI v1.0.0 published (Phase 3 above)
- GitHub Discussions enabled; first-responder process defined
- First three adopters (fintech teams, ideally) identified and onboarded
- Technical blog post: "Formal action authorization: why probabilistic guards fail for financial transactions"
- First public case study: anonymized if necessary; must show a real BLOCK on a real harmful action

### Month 3–6: Governance Release (v1.1.0)

- Governance coupling (GovernanceConfig) promoted from beta to stable
- RedisApprovalWorkflow published with documentation
- Five adapter integrations all validated and CI-tested
- Cloud KMS staging integration tests for at least AWS
- Python 3.11/3.12/3.13 all confirmed green
- Policy template library published: finance, healthcare, infrastructure, RBAC

### Month 6–9: Ecosystem Integration (v1.2.0)

- `pramanix[langchain]` documented as first-class integration
- `pramanix[llamaindex]` documented as first-class integration
- Adapter compatibility matrix published (supported framework versions)
- Contribution model: policy primitives can be contributed by community
- Benchmark published from three different cloud environments with methodology document
- Security audit by external firm (even a small firm) — publish the report

### Month 9–12: Enterprise Features (v1.3.0)

- Kafka exactly-once delivery audit sink
- Multi-cloud KMS real staging tests (AWS at minimum)
- Distributed circuit breaker with Redis cluster support
- Policy hot-reload without Guard restart (lifecycle coupling)
- SLA definition: P99 < 15ms in `async-thread` mode on c5.2xlarge class hardware
- Compliance report generation (PDF) from audit trail
- Enterprise support offering defined (even if just a GitHub issues SLA initially)

### Month 12–18: Market Credibility

| Milestone | Target |
|---|---|
| PyPI monthly downloads | 10,000+ |
| GitHub stars | 1,000+ |
| Real production deployments documented | 5+ |
| Framework adapters CI-validated | All 9 |
| Cloud KMS real-tested | AWS, Azure |
| Python version support | 3.11, 3.12, 3.13, 3.14 |
| External security audit | Published |
| Community validators/templates | 20+ templates |

**Realistic Guardrails AI parity target:** 18 months post-PyPI for download volume and community breadth. Technical capability in the formal action authorization domain: already ahead. The gap to close is operational (cloud integrations, production deployments, community).

---

## 17. Final Recommendation

**Do not push to PyPI today.**

The kernel is ready. The platform is not. Publishing a v1.0.0 with a CalibratedScorer RCE vector, uncoupled governance subsystems, and Python 3.13-only support would guarantee negative press on HackerNews, a CVE within six months, and adoption numbers of zero from enterprise teams whose procurement process requires passing a basic dependency audit.

**The minimum launch bar:**

1. CalibratedScorer HMAC integrity enforced
2. FlowRule label matching fixed (fnmatch or exact-match documented unambiguously)
3. Python 3.11+ compatibility validated in CI
4. GovernanceConfig composition primitive implemented with basic coupling in Guard
5. All five unvalidated adapters smoke-tested against real frameworks in CI
6. Decision hash algorithm version field added
7. `prometheus-client` moved to optional
8. Coverage-padding files removed
9. PyPI trusted publishing configured
10. `LAUNCH_CLAIMS.md` published listing exact guarantees

**Estimated time to minimum launch bar:** 75 days of focused engineering on the hardening roadmap above.

**Launch posture:** "Formal action authorization kernel for structured AI agent systems. Production-grade verification engine. Beta governance platform. Use it when you need mathematical proof that an agent action is safe, not statistical confidence."

**One-sentence positioning:**

> Pramanix is the formal action authorization primitive for AI agents — the only open-source SDK that produces a Z3-backed mathematical proof for every ALLOW decision and a complete invariant counterexample for every BLOCK.

That sentence is technically true, competitively differentiated, and honest about scope. Every other claim must be a footnote to it.

---

*This document is a living artifact. Update it as launch blockers are closed, as competitive landscape evolves, and as real production deployments generate evidence. Code is authoritative. Reread the source before making any public claim.*
