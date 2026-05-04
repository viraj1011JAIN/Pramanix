# Pramanix: Elite Architectural Roadmap to 100/100

**Classification:** Brutally honest. Evidence-first. Code over aspiration.
**Basis:** FORENSIC_AUDIT.md (2026-05-04), ARCHITECTURE_NOTES.md, KNOWN_GAPS.md, DECISIONS.md, README.md
**Standard:** Every claim in this document is traceable to a specific file, function, or measurable gap. Vague advice is a defect in this document, not a feature.

---

## 0. Honest Starting Position

The forensic audit gave Pramanix a **weighted average of 3.1/5** across 15 dimensions. The audit's single-sentence verdict: *"A genuine formal verification kernel wrapped in an architecturally sound but operationally incomplete platform not yet ready for enterprise production deployment."*

That is accurate. Accept it. The following dimension-by-dimension scores are the real baseline. Disagreeing with them requires pointing at code that contradicts the audit evidence.

| Dimension | Audit Score | Target | Gap |
|---|---|---|---|
| Architecture cohesion | 4/5 | 5/5 | verify_async duplication; governance isolation |
| Core verification correctness | 5/5 | 5/5 | **Already at ceiling** |
| Policy DSL quality | 4/5 | 5/5 | Meta inheritance; weekday encoding; Field arg traps |
| Fail-closed guarantee | 5/5 | 5/5 | **Already at ceiling** |
| Test rigor (core) | 4/5 | 5/5 | 8 coverage-padding files; no Windows CI |
| Test rigor (integrations) | 2/5 | 5/5 | 5 adapters unvalidated against real frameworks |
| Security maturity | 3/5 | 5/5 | Pickle RCE; FlowRule glob mismatch; cloud KMS unstaged |
| Cryptographic auditability | 3/5 | 5/5 | iat=0; oversight HMAC lost on restart; eviction gap |
| Governance depth | 2/5 | 5/5 | 6 subsystems isolated; all in-memory; no Guard coupling |
| Observability | 3/5 | 5/5 | Benchmark not in CI; no distributed tracing |
| Enterprise integration maturity | 2/5 | 5/5 | 5/9 adapters untested; cloud fake-backed; not on PyPI |
| Scalability readiness | 3/5 | 5/5 | O(n) eviction; async-process Windows gap |
| Operational readiness | 2/5 | 5/5 | Not on PyPI; no real KMS; no production deployments |
| Developer experience | 3/5 | 5/5 | Field arg traps; two-signing-system confusion |
| Ecosystem competitiveness | 2/5 | 5/5 | Not on PyPI; no community; no output validation; no conversation safety |
| **Output Validation Engine** | **0/5** | **5/5** | **Does not exist. Guardrails AI's core moat.** |
| **Multi-turn Conversation Safety** | **0/5** | **5/5** | **Does not exist. NeMo's core moat.** |

The last two rows are the most important. They are capabilities that both major competitors ship as core products, and Pramanix has **zero implementation** of either. Fixing the audit's P0/P1 list gets Pramanix to 3.8/5. Closing those two gaps is what closes the remaining distance to 5/5.

---

## 1. The Competitor Gap: What Guardrails AI and NeMo Actually Ship

### 1.1 Guardrails AI

Guardrails AI's core capability is not guardrails around action intent. It is **structured output validation with a fix/retry loop**. The LLM writes text; Guardrails intercepts the output, validates it against a schema or set of validators, and if it fails, either rewrites the output (using the LLM itself) or hard-blocks. This includes:

- **JSON schema coercion:** LLM output is parsed, validated against a Pydantic or JSON schema, and coerced or repaired when it fails
- **Guardrails Hub:** A community marketplace of 50+ reusable validators (no-toxic-language, no-secrets-in-code, detect-PII, regex-match, valid-sql, etc.)
- **Streaming validation:** Validators run on partial LLM output as it streams, not just on the complete response
- **Multi-rail composition:** Multiple validators run in sequence; each can pass, fix, or block
- **On-fail actions:** `noop`, `fix`, `reask`, `exception`, `filter` — different actions on validator failure
- **Direct LLM wrapping:** `guard.parse(llm_output)` or `guard(openai_client, ...)` — integrates at the LLM call boundary, not the action boundary

**What Pramanix has in this space:** Nothing. `guard.verify()` validates intent and state before an action. It does not validate LLM output. It has no schema repair. It has no streaming. It has no validator hub.

This is not a roadmap gap. It is a product gap. Pramanix and Guardrails AI are currently solving different problems. To compete in the same market, Pramanix needs to bridge this.

### 1.2 NeMo Guardrails

NeMo's core capability is **multi-turn conversation flow control via a domain-specific language (Colang)**. It operates as a dialog manager, tracking conversation state across turns and enforcing rails on both what the system can say and what topics it will engage with. Specifically:

- **Input rails:** Check user input before it reaches the LLM (topic filters, jailbreak detection)
- **Output rails:** Check LLM output before it reaches the user (fact-checking, sensitive content)
- **Dialog rails:** Control conversation flow (topic drift prevention, safe messaging for self-harm)
- **Colang language:** Declarative conversation flow definitions — NeMo compiles these to a state machine
- **Knowledge base integration:** Rails can query a knowledge base to enforce factual accuracy
- **Action server:** Custom actions (Python functions) callable from Colang rules
- **State tracking across turns:** Full conversation history available to rails

**What Pramanix has in this space:** Nothing. Pramanix's `Guard.verify()` is single-turn — it evaluates one intent against one state. It has no memory of prior turns (beyond the opt-in `SecureMemoryStore` beta, which has no pipeline coupling). It has no dialog flow language.

### 1.3 Where Pramanix Leads

Do not underestimate the genuine technical moat Pramanix holds. Both competitors lack:

- **Formal SMT-based proofs:** Guardrails validators are heuristic. NeMo's Colang is pattern-matching. Neither can prove `balance - amount >= min_reserve` — they can only check it with Python conditions that have no completeness guarantee.
- **Complete violation attribution:** Guardrails tells you "validator failed." Pramanix tells you exactly which invariant failed with a Z3-generated counterexample. This is categorically different for regulated industries.
- **HMAC-sealed IPC:** No competitor has tamper-evident worker process results.
- **Ed25519 Merkle audit trails:** No competitor produces cryptographically verifiable decision chains for regulatory inspection.
- **Timing side-channel mitigation:** No competitor applies timing pads to prevent oracle attacks.

The strategic position is: Pramanix's kernel is demonstrably superior for structured action enforcement in regulated industries. The market gap is that it cannot do output validation or conversation safety at all. The roadmap must close both while not abandoning the kernel advantage.

---

## 2. The Roadmap

Ten sequential phases. Each phase has explicit gate conditions that must pass before the next phase begins. Estimates are calendar weeks for a single engineer working full-time on the item. They are not padded.

---

### Phase 0: Surgical Fixes (2 weeks) — Must happen before anything else

**Gate condition:** Every item in this phase merged to main. Zero regressions in existing 3,550-test suite. CI green.

These are bugs confirmed by the forensic audit that create either security vulnerabilities or silent correctness failures. None require architectural decisions — they have exactly one correct fix.

#### 0-A: Pickle RCE in CalibratedScorer (`injection_scorer.py:CalibratedScorer.load()`)

**What's broken:** `pickle.load(f)` with no integrity check over the file bytes. A compromised scorer file on disk produces arbitrary code execution when loaded.

**Exact fix:**
```python
import hmac, hashlib

def load(cls, path: Path, hmac_key: bytes) -> "CalibratedScorer":
    raw = path.read_bytes()
    expected_tag = path.with_suffix(".hmac").read_bytes()
    actual_tag = hmac.new(hmac_key, raw, hashlib.sha256).digest()
    if not hmac.compare_digest(actual_tag, expected_tag):
        raise IntegrityError(f"HMAC mismatch for scorer file {path}")
    return pickle.loads(raw)

def save(self, path: Path, hmac_key: bytes) -> None:
    raw = pickle.dumps(self)
    path.write_bytes(raw)
    path.with_suffix(".hmac").write_bytes(
        hmac.new(hmac_key, raw, hashlib.sha256).digest()
    )
```

`pramanix calibrate-injection` CLI must be updated to generate the `.hmac` sidecar. The HMAC key must be injected via env var `PRAMANIX_SCORER_HMAC_KEY`, not hardcoded.

**Test requirement:** `test_calibrated_scorer_tamper_detection.py` — verify that a byte flip in the scorer file raises `IntegrityError`, not arbitrary code execution. This is an adversarial test, not a unit test.

#### 0-B: FlowRule glob mismatch (`ifc/flow_policy.py:FlowRule.matches()`)

**What's broken:** Docstring says "glob-style pattern matching." Implementation is exact string equality. A flow policy rule `source="PUBLIC*"` never matches `source="PUBLIC_DATA"` — silent IFC bypass.

**Exact fix:**
```python
from fnmatch import fnmatch

def matches(self, source_label: str, dest_label: str) -> bool:
    return fnmatch(source_label, self.source) and fnmatch(dest_label, self.dest)
```

**Test requirement:** Parametric test covering: exact match (backward compat), wildcard source, wildcard dest, wildcard both, no match. Verify the old exact-equality tests are updated, not deleted (they should still pass because `fnmatch("PUBLIC", "PUBLIC")` is True).

#### 0-C: Interceptors `__init__.py` declares names it does not import

**What's broken:** `from pramanix.interceptors import PramanixGrpcInterceptor` raises `ImportError` at runtime.

**Exact fix:**
```python
# pramanix/interceptors/__init__.py
from .grpc import PramanixGrpcInterceptor
from .kafka import PramanixKafkaConsumer

__all__ = ["PramanixGrpcInterceptor", "PramanixKafkaConsumer"]
```

These imports must be gated: wrap in `try/except ImportError` and raise a `ConfigurationError` with install instructions if grpcio or confluent-kafka is not installed.

**Test requirement:** One test that does `from pramanix.interceptors import PramanixGrpcInterceptor` in a CI environment where grpcio is installed. This test should be in the `extras-smoke` CI stage.

#### 0-D: `verify_async()` behavioral divergence from `verify()` (M-02 and future)

**What's broken:** `verify_async()` reimplements the 12-step pipeline independently. M-02 (missing semver check) already diverged. Two codepaths will continue to diverge independently.

**Exact fix:** Extract a shared `_verify_core(self, intent, state, *, _async_context=False)` method containing all 12 steps, where async-specific behavior (e.g., awaiting coroutines) is handled via a dispatch table. Both `verify()` and `verify_async()` become thin wrappers:

```python
def verify(self, intent, state):
    return self._run_sync(self._verify_core(intent, state, mode="sync"))

async def verify_async(self, intent, state):
    return await self._run_async(self._verify_core(intent, state, mode="async"))
```

The core cannot call `await` directly — it must yield async steps to the async wrapper. The implementation strategy is: `_verify_core` is a generator that yields `Step(label, fn_or_coro)` objects; the sync and async runners consume the steps differently.

**Test requirement:** Parametric test that calls `verify()` and `verify_async()` on the same input and asserts the `Decision` objects are field-for-field identical for every decision status (SAFE, UNSAFE, TIMEOUT, VALIDATION_FAILURE, ERROR). This prevents future M-02-class divergences.

#### 0-E: Policy fingerprint omits `python_type` (`guard.py:_compute_policy_fingerprint()`)

**What's broken:** Two `Field` definitions with the same name and z3_sort but different `python_type` (e.g., `int` vs `Decimal`) produce the same policy fingerprint. They are semantically different policies — type coercion rules differ at Pydantic validation time.

**Exact fix:** Include `f"{field.name}:{field.python_type.__qualname__}:{field.z3_sort}"` in the SHA-256 input for each field.

**Test requirement:** Assert that `Guard(PolicyWithIntField)._policy_hash != Guard(PolicyWithDecimalField)._policy_hash` where both policies have identical names and z3_sorts.

#### 0-F: `Meta` inner class non-inheritable (`policy.py`)

**What's broken:** `vars(cls).get("Meta")` returns `None` for subclasses that do not re-declare `Meta` but expect to inherit it from a parent policy.

**Exact fix:**
```python
@classmethod
def _get_meta(cls):
    for klass in type(cls).__mro__:
        if "Meta" in vars(klass):
            return vars(klass)["Meta"]
    return None
```

Replace all `vars(cls).get("Meta")` with `cls._get_meta()` throughout `policy.py`, `guard.py`, and `guard_config.py`.

**Test requirement:** `class ChildPolicy(ParentPolicyWithMeta): pass` — assert `Guard(ChildPolicy)._meta.version` equals `ParentPolicyWithMeta.Meta.version`.

---

### Phase 1: Architecture Hardening (5 weeks)

**Gate condition:** All six beta subsystems (IFC, Privilege, Oversight, Memory, Lifecycle, Provenance) have at minimum one integration test exercising their coupling with `Guard.verify()`. O(n) eviction bugs eliminated. ProvenanceChain integrity gap closed. Oversight HMAC key survives restart in the durable backend.

#### 1-A: Governance Subsystem Guard Coupling

**What's broken:** IFC, Privilege, Oversight are fully implemented but have **zero coupling with Guard**. A developer who forgets to call `FlowEnforcer.gate()` or `ScopeEnforcer.enforce()` silently bypasses all governance. This is the architectural equivalent of having airbags that only deploy when the driver manually presses a button.

**Design prescription:**

Add first-class composition points in `GuardConfig`:

```python
@dataclasses.dataclass(frozen=True)
class GuardConfig:
    # ... existing fields ...
    ifc_policy: FlowPolicy | None = None          # NEW
    privilege_scope: ExecutionScope | None = None  # NEW
    oversight_workflow: ApprovalWorkflow | None = None  # NEW (protocol)
```

Modify the `_verify_core` pipeline (from Phase 0-D) to insert governance steps after Z3 decides ALLOW:

```
Step 11 (new): IFC enforcement — if ifc_policy set, call FlowEnforcer(ifc_policy).gate(
                   source=decision.context.get("trust_label"),
                   dest=config.ifc_policy.dest_label
               ) — BLOCK if denied
Step 12 (new): Privilege enforcement — if privilege_scope set, call
               ScopeEnforcer(privilege_scope).enforce(intent.get("tool"))
               — BLOCK if not in scope
Step 13 (new): Oversight gate — if oversight_workflow set, check
               workflow.has_approval(decision_id) — raise OversightRequiredError if not
```

**Critical invariant:** Governance steps run **after** Z3 ALLOW, not in parallel. A Z3 BLOCK short-circuits before governance steps. A governance BLOCK produces `Decision.block(allowed=False, status=GOVERNANCE_BLOCKED)` — a new status value. This is added to `SolverStatus`.

**Integration test requirement:** Test where Z3 would ALLOW but IFC policy blocks — assert `decision.allowed is False` and `decision.status == SolverStatus.GOVERNANCE_BLOCKED`. Test where Z3 ALLOWs and IFC allows but oversight approval is missing — assert `OversightRequiredError` is raised (this is one of the cases where Guard raises, intentionally, for the oversight gate specifically).

#### 1-B: Persistent Oversight Backend (`DurableApprovalWorkflow`)

**What's broken:** `InMemoryApprovalWorkflow` loses all pending approvals on process restart. Oversight records are unverifiable after restart because the HMAC key is ephemeral.

**Design prescription:**

Define a `DurableApprovalWorkflow` protocol and ship a Redis reference implementation:

```python
class RedisApprovalWorkflow:
    """Implements ApprovalWorkflow with Redis-backed persistence."""

    def __init__(self, redis_client, signing_key: bytes, ttl_seconds: int = 86400):
        # signing_key must be injected from KeyProvider, not generated ephemerally
        ...

    async def request_approval(self, action, requester_id) -> ApprovalRequest:
        # Store in Redis with TTL, sign with persistent key
        ...

    async def has_approval(self, request_id) -> bool:
        # Verify HMAC of stored record, return True if approved and unexpired
        ...
```

The HMAC signing key for oversight records must come from a `KeyProvider` (any of: AWS KMS, Vault, environment-injected). It cannot be generated ephemerally. This closes the restart-breaks-historical-records gap (P1-7 in the audit).

**Test requirement:** `test_durable_oversight_restart.py` — create approval, simulate process restart by re-instantiating `RedisApprovalWorkflow` with same Redis and same key, verify `has_approval()` returns True and HMAC validates. Use real Redis via testcontainers.

#### 1-C: ProvenanceChain Eviction Checkpoint (`provenance.py`)

**What's broken:** When `ProvenanceChain` evicts the oldest record due to `maxlen`, `verify_integrity()` has a silent gap: the first retained record's `prev_hash` points to an evicted record that no longer exists. An attacker who knows the eviction boundary could insert a record there without detection.

**Design prescription:**

Before eviction, emit a signed checkpoint record:

```python
@dataclasses.dataclass(frozen=True)
class ProvenanceRecord:
    # ... existing fields ...
    is_eviction_checkpoint: bool = False
    eviction_count: int = 0  # How many records were evicted before this checkpoint

def _maybe_evict(self) -> None:
    if len(self._chain) >= self._maxlen:
        evicted = self._chain.popleft()
        checkpoint = ProvenanceRecord(
            agent_id="__system__",
            action="__eviction_checkpoint__",
            inputs={"evicted_count": 1, "evicted_hash": evicted.record_hash},
            decision_id="__checkpoint__",
            timestamp=time.time(),
            prev_hash=evicted.record_hash,
            is_eviction_checkpoint=True,
        )
        # Sign the checkpoint with the same HMAC key used for normal records
        self._chain.appendleft(signed_checkpoint)
```

`verify_integrity()` treats checkpoint records as trust anchors: when it encounters `is_eviction_checkpoint=True`, it accepts the chain's continuity at that point rather than requiring the evicted record.

#### 1-D: O(n) Eviction Replacement

**What's broken:** `list.pop(0)` in `ScopedMemoryPartition.write()`, `ProvenanceChain.append()`, and `ShadowEvaluator`. These are O(n) under sustained write volume. At 1,000 records, eviction costs 1,000 pointer shifts per write.

**Exact fix:** Replace `list` with `collections.deque(maxlen=max_entries)` in all three locations. `deque.appendleft()` and `deque.popleft()` are O(1). No behavioral difference for callers.

This is three one-line changes. Do them all in a single commit. Add a `test_memory_eviction_performance.py` that writes 100,000 entries to a `ScopedMemoryPartition(maxlen=1000)` and asserts completion in under 1 second.

#### 1-E: HashiCorp Vault `KeyError` to `ConfigurationError`

**What's broken:** `resp["data"]["data"][self._field]` raises bare `KeyError` when the field is missing from the Vault secret. The error message is `KeyError: 'field_name'` with no context.

**Exact fix:**
```python
try:
    return resp["data"]["data"][self._field]
except KeyError:
    available = list(resp.get("data", {}).get("data", {}).keys())
    raise ConfigurationError(
        f"Vault secret at '{self._mount_path}/{self._secret_path}' does not contain "
        f"field '{self._field}'. Available fields: {available}"
    ) from None
```

---

### Phase 2: Release Engineering (3 weeks)

**Gate condition:** `pip install pramanix` works from PyPI. `pip install pramanix` works with Python 3.11, 3.12, 3.13. CI matrix runs on ubuntu-latest and windows-latest. Coverage gate is a single number. Coverage-padding files are removed from default test run.

#### 2-A: PyPI Publication

**What's broken:** `pip install pramanix` fails. Zero adoption is possible without this. This is the single largest adoption blocker in the entire codebase.

**Actions:**
1. Change `pyproject.toml` classifier to `"Development Status :: 4 - Beta"` (P1-3 fix).
2. Move `prometheus-client` to optional extra `[metrics]` (P1-1 fix).
3. Move `orjson` to optional with stdlib fallback path (P1-2 fix).
4. Add `scikit-learn = {version = ">=1.3", optional = true}` to `[sklearn]` extra (KNOWN_GAPS §10 fix).
5. Implement OIDC-based PyPI trusted publishing in `.github/workflows/publish.yml`.
6. Implement Sigstore signing of release artifacts via `sigstore sign dist/*.whl dist/*.tar.gz`.
7. Publish. Verify `pip install pramanix` from PyPI installs cleanly with Python 3.13.

#### 2-B: Python 3.11 and 3.12 Compatibility

**What's broken:** `python = ">=3.13,<4.0"` excludes every enterprise running Python 3.11 or 3.12. This is not a theoretical concern — Python 3.11 was the LTS version for most of 2023-2024. Many regulated institutions have 2-3 year upgrade cycles.

**Actions:**
1. Change `pyproject.toml` to `python = ">=3.11,<4.0"`.
2. Identify all Python 3.13-only syntax: `type` keyword aliases, improved error messages, `tomllib` changes, `asyncio` API changes. Replace each with backward-compatible equivalents.
3. Add `python-version: ["3.11", "3.12", "3.13"]` matrix to all CI jobs.
4. Run the full 3,550-test suite on all three versions. Fix any failures.

Known risk area: `tomllib` is stdlib in 3.11+ so no change needed. The `type X = Y` syntax (3.12+) must be replaced with `TypeAlias`. Check `expressions.py` and `policy.py` for any usage.

#### 2-C: Windows CI for async-process mode

**What's broken:** `execution_mode="async-process"` has no CI coverage on Windows. The development platform is Windows 11. Silent correctness issues are possible.

**Actions:**
1. Add `os: [ubuntu-latest, windows-latest]` to the CI matrix.
2. On Windows, specifically run: worker tests, HMAC IPC tests, async-process policy verification tests, PPID watchdog tests.
3. Fix any Windows-specific failures (expected issues: spawn vs fork semantics, path separators in policy module resolution, PPID polling on Windows).

#### 2-D: Coverage Gate Alignment and Padding Removal

**What's broken:**
- `pyproject.toml` says `fail_under=98`. CI says `--cov-fail-under=95`. These disagree.
- 8 files named `test_coverage_boost*`, `test_coverage_gaps*`, `test_coverage_final_push*` inflate the metric.

**Actions:**
1. Move the 8 padding files to `tests/coverage_artifacts/` and add that directory to `[tool.pytest.ini_options] testpaths` exclusion.
2. Do NOT delete them — some may test real behavior. Audit each: keep tests that assert real behavior, delete tests that are `assert True` or coverage-only one-liners.
3. Set `fail_under=92` in `pyproject.toml` and `--cov-fail-under=92` in CI. The number will drop when padding is removed — that is expected and honest. Set a target of 95% for Phase 6 once real integration tests are added.
4. Remove `integrations/*.py` from the coverage exclusion list (P2-6 fix). Integration tests counting toward the gate prevents future exclusion drift.

---

### Phase 3: Output Validation Engine (10 weeks)

**Gate condition:** `guard.validate_output(llm_output, schema=MySchema)` works end-to-end. At least 10 built-in validators are shipped. Streaming validation works with `async for token in guard.validate_stream(...)`. Validator SDK allows community validators to be installed as Python packages.

This phase closes the largest single gap between Pramanix and Guardrails AI. It is also Pramanix's strongest opportunity to differentiate: output validation backed by Z3 formal verification is categorically different from heuristic validators.

#### 3-A: Core Output Validation Architecture

**Design principle:** Output validation must integrate with the Z3 engine for structured outputs, and fall back to rule-based validators for unstructured text. The two-tier architecture:

```
LLM output
    │
    ├─ Structured output path (JSON, Pydantic model, dataclass)
    │    ├─ Parse against declared schema
    │    ├─ If parse fails → attempt repair via LLM reask (configurable)
    │    ├─ If repair fails → OutputValidationError
    │    └─ If parse succeeds → run Z3 invariant validation via existing Guard.verify()
    │         └─ Produces same Decision object as action validation
    │
    └─ Unstructured text path (free text, markdown, code)
         ├─ Run registered text validators in pipeline
         ├─ Each validator returns: PASS | FAIL(reason) | FIX(repaired_text)
         └─ On FAIL: configurable on-fail action (block | reask | fix | filter | noop)
```

**New API surface:**

```python
class OutputGuard:
    """Validates and optionally repairs LLM output against a schema and validator pipeline."""

    def __init__(
        self,
        schema: type[BaseModel] | None = None,
        policy: type[Policy] | None = None,  # For Z3 invariant validation on structured output
        validators: list[OutputValidator] = (),
        on_fail: OnFailAction = OnFailAction.BLOCK,
        max_reask_attempts: int = 2,
        reask_llm_client: Any | None = None,
    ): ...

    def validate(self, output: str) -> OutputDecision: ...
    async def validate_async(self, output: str) -> OutputDecision: ...
    async def validate_stream(
        self, token_stream: AsyncIterator[str]
    ) -> AsyncIterator[StreamValidationEvent]: ...
```

`OutputDecision` is a new frozen dataclass parallel to `Decision`:

```python
@dataclasses.dataclass(frozen=True)
class OutputDecision:
    raw_output: str
    validated_output: str | None  # None if blocked; repaired output if fixed
    allowed: bool
    status: OutputValidationStatus  # VALID | INVALID | REPAIRED | SCHEMA_MISMATCH | BLOCKED
    validator_results: tuple[ValidatorResult, ...]
    z3_decision: Decision | None  # Populated if structured schema + Policy provided
    output_hash: str  # SHA-256 of validated_output for audit
    signed: SignedOutputDecision | None
```

#### 3-B: Built-in Validator Library (Minimum 10 validators for parity)

Each validator is a class implementing `OutputValidator` protocol:

```python
class OutputValidator(Protocol):
    name: str
    on_fail: OnFailAction

    def validate(self, output: str, metadata: dict) -> ValidatorResult: ...
```

**Required validators for v1.0 parity:**

| Validator | What it checks | On-fail action |
|---|---|---|
| `NoSecretsValidator` | Regex + entropy scan for API keys, tokens, passwords | `block` |
| `NoPIIValidator` | Email, phone, SSN, credit card patterns | `filter` or `block` |
| `ValidJSONValidator` | Parses as JSON; reports parse error | `reask` |
| `ValidSQLValidator` | Parses as SQL via `sqlglot`; checks for injection patterns | `block` |
| `SentimentValidator` | Sentiment threshold; configurable min/max | `block` |
| `ToxicityValidator` | Profanity/toxicity word list; configurable lists | `filter` |
| `FactualConsistencyValidator` | Cross-checks claims against a provided context | `reask` |
| `LengthValidator` | Output within min/max character or token bounds | `fix` (truncate) |
| `SchemaValidator` | Validates against JSON Schema (not just Pydantic) | `reask` |
| `RegexMatchValidator` | Output matches (or does not match) a pattern | configurable |

**Z3-backed validators (differentiator):** For structured outputs where a `Policy` is provided:

| Validator | What it checks | Z3 backing |
|---|---|---|
| `NumericInvariantsValidator` | Financial invariants on extracted numeric fields | Full Z3 proof |
| `ThresholdRangeValidator` | Output values within declared safe ranges | Z3 range check |
| `CompositeInvariantValidator` | Arbitrary multi-field invariants | Full Z3 policy |

These Z3-backed validators are Pramanix's moat. No other output validation SDK can claim formally proven output invariants.

#### 3-C: Streaming Validation

**Design:** Streaming validation is inherently partial — you cannot validate a JSON object until it is complete. The streaming validator must buffer tokens until a complete validation unit is available.

```python
class StreamValidationBuffer:
    """Accumulates streaming tokens and emits validation events at boundaries."""

    def __init__(self, validators: list[OutputValidator], buffer_strategy: BufferStrategy):
        # BufferStrategy: SENTENCE | JSON_COMPLETE | PARAGRAPH | FIXED_TOKENS
        ...

    async def feed(self, token: str) -> list[StreamValidationEvent]:
        """Feed one token. May return zero or more validation events."""
        ...

    async def flush(self) -> list[StreamValidationEvent]:
        """Called when stream ends. Validates any remaining buffer."""
        ...
```

`StreamValidationEvent` is a discriminated union:
- `TokenEvent(token)` — safe token to forward to the user
- `BlockEvent(reason, buffered_tokens)` — stop stream; do not forward buffered tokens
- `FilterEvent(safe_replacement)` — replace blocked content with `safe_replacement`

**Test requirement:** Stream a 10,000-token JSON object from a fake LLM. Assert that `ValidJSONValidator` defers validation until the `}` token, then validates the complete object. Assert that a `NoSecretsValidator` with `SENTENCE` buffer strategy blocks on the sentence containing a secret.

#### 3-D: Reask Loop

**What this is:** When a validator's `on_fail` is `REASK`, the output guard sends the original LLM output + the validation failure reason back to the LLM and asks it to regenerate. This requires an LLM client.

```python
class ReaskLoop:
    def __init__(self, llm_client, max_attempts: int):
        ...

    async def execute(
        self,
        original_prompt: str,
        failed_output: str,
        failure_reason: str,
        reask_template: str = DEFAULT_REASK_TEMPLATE,
    ) -> str:
        """Returns repaired output or raises ReaskExhaustedError after max_attempts."""
        ...
```

The reask template must be auditable — every reask call is recorded in `OutputDecision.reask_history`.

---

### Phase 4: Multi-Turn Conversation Safety (10 weeks)

**Gate condition:** A multi-turn conversation can be tracked across calls. Topic rails can be defined declaratively and enforced on both input and output. Conversation history is available to policies. NeMo's core use cases can be replicated with Pramanix's API.

This is the most architecturally novel phase. Pramanix must build something equivalent to NeMo's dialog state machine, but expressed in terms of Z3 policies rather than Colang. This is also the phase where Pramanix's formal verification advantage is strongest.

#### 4-A: Conversation Context Model

**Design prescription:** A `Conversation` is a stateful object that accumulates turns and makes conversation history available to `Guard.verify()` calls.

```python
@dataclasses.dataclass
class Turn:
    turn_id: str
    role: Literal["user", "assistant", "system"]
    content: str
    timestamp: float
    decision: Decision | None  # The Guard decision for this turn, if verified
    metadata: dict[str, Any]

class Conversation:
    """Stateful multi-turn conversation with attached Guard instances."""

    def __init__(
        self,
        conversation_id: str,
        input_guard: Guard | None = None,     # Validates user input
        output_guard: OutputGuard | None = None,  # Validates LLM output
        dialog_rails: list[DialogRail] = (),   # Multi-turn conversation rules
        history_backend: ConversationHistoryBackend = InMemoryHistoryBackend(),
        max_history_turns: int = 50,
    ): ...

    async def add_user_turn(self, content: str) -> TurnDecision:
        """Validate user input against input_guard and dialog_rails. Returns TurnDecision."""
        ...

    async def add_assistant_turn(self, content: str) -> TurnDecision:
        """Validate assistant output against output_guard and dialog_rails."""
        ...

    def get_context_for_policy(self) -> dict[str, Any]:
        """Returns conversation history as a dict suitable for Policy.verify() state input."""
        # Includes: turn_count, user_topics, assistant_topics, prior_decisions, etc.
        ...
```

#### 4-B: Dialog Rail DSL

**Design prescription:** Dialog rails are conversation-level rules that span multiple turns. They are expressed in Pramanix's existing Policy DSL where possible, with conversation-specific extensions.

```python
class DialogRail:
    """Base class for multi-turn conversation constraints."""

    @classmethod
    def on_turn_start(cls, conversation: Conversation, turn: Turn) -> RailDecision: ...
    @classmethod
    def on_turn_end(cls, conversation: Conversation, turn: Turn) -> RailDecision: ...

class TopicBoundaryRail(DialogRail):
    """Prevents conversation from drifting to disallowed topics."""
    allowed_topics: frozenset[str]
    blocked_topics: frozenset[str]
    topic_classifier: TopicClassifier  # Protocol: classify(text) -> str

class RateLimitRail(DialogRail):
    """Limits how many times a topic or action can appear in N turns."""
    target: str  # What to count (topic, intent_type, etc.)
    max_count: int
    window_turns: int

class EscalationRail(DialogRail):
    """Triggers human escalation when conversation reaches defined states."""
    trigger_conditions: list[Callable[[Conversation], bool]]
    escalation_action: Callable[[Conversation], Awaitable[None]]

class SafeMessagingRail(DialogRail):
    """Enforces safe messaging guidelines (e.g., for mental health, suicide prevention)."""
    domain: Literal["suicide", "self_harm", "eating_disorders", "substance_abuse"]
    # Pre-built rule sets; not configurable by default for safety
```

#### 4-C: Z3-Backed Conversation Invariants

**This is the core differentiator over NeMo.** NeMo's Colang is pattern-matching. Pramanix can express conversation invariants as formal Z3 policies:

```python
class ConversationPolicy(Policy):
    """Policy that operates on conversation-level fields."""

    turn_count = Field("turn_count", int, "Int")
    user_message_count = Field("user_message_count", int, "Int")
    prior_violation_count = Field("prior_violation_count", int, "Int")
    sentiment_score = Field("sentiment_score", float, "Real")

    @classmethod
    def invariants(cls):
        return [
            # Block after 3 prior violations in same session
            (E(cls.prior_violation_count) < 3).named("session_violation_limit"),
            # Escalate if sentiment drops below -0.7 for 3+ consecutive turns
            # (expressed as a compound state check)
            (E(cls.sentiment_score) > -0.7).named("sentiment_floor"),
        ]
```

`Conversation.add_user_turn()` automatically computes conversation-level fields from history and passes them to `Guard.verify()` alongside the turn-level intent and state.

#### 4-D: Durable Conversation History Backend

`InMemoryHistoryBackend` is for development only. Ship two production backends:

```python
class RedisHistoryBackend(ConversationHistoryBackend):
    """Redis-backed conversation history. Each turn serialized as JSON."""
    # TTL per conversation (default: 24 hours)
    # Turn data signed with Ed25519 for tamper detection
    ...

class PostgresHistoryBackend(ConversationHistoryBackend):
    """Postgres-backed conversation history. Full ACID guarantees."""
    # Suitable for regulated industries requiring audit trail of full conversation
    ...
```

**Test requirement:** `test_conversation_multi_turn.py` — 20-turn conversation where turn 15 triggers a `TopicBoundaryRail` violation, assert that turns 1-14 are recoverable from Redis, turn 15 produces `TurnDecision(allowed=False)`, and turns 16+ are still trackable.

---

### Phase 5: Agent Tools Hardening (6 weeks)

**Gate condition:** Privilege scope is automatically enforced when Guard is configured with `privilege_scope`. TOCTOU gap in execution tokens is closable with a one-call API. Tool manifests can be declared and validated with Z3 invariants. The `@guard` decorator works with all three execution backends.

#### 5-A: Privilege Scope Auto-Enforcement via Guard

From Phase 1-A, `GuardConfig(privilege_scope=scope)` wires `ScopeEnforcer` into the Guard pipeline. This phase validates the complete tool capability flow:

```
Agent declares intent: {"tool": "file_write", "path": "/etc/passwd"}
Guard.verify():
    1. Z3 checks: path invariants, permission bounds
    2. [if privilege_scope set] ScopeEnforcer checks: is "file_write" in scope?
    3. [if ifc_policy set] FlowEnforcer checks: does trust label allow this write?
    4. [if oversight_workflow set] Oversight checks: does this require human approval?
```

#### 5-B: Tool Manifest DSL

**Design prescription:** An agent should declare its tool capabilities as a machine-verifiable manifest that Pramanix can validate at startup:

```python
class ToolManifest:
    """Declares what tools an agent is allowed to invoke and their invariants."""

    tools: dict[str, ToolSpec]

    def validate(self) -> None:
        """Raises PolicyCompilationError if any tool spec is invalid."""
        ...

    def as_privilege_scope(self) -> ExecutionScope:
        """Converts to an ExecutionScope for ScopeEnforcer integration."""
        ...

@dataclasses.dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    policy: type[Policy]  # Z3 policy that must hold for invocations of this tool
    rate_limit: RateLimit | None = None
    requires_oversight: bool = False
    allowed_trust_levels: frozenset[str] = frozenset({"PUBLIC"})
```

**Usage:**

```python
manifest = ToolManifest(tools={
    "file_read": ToolSpec(
        name="file_read",
        policy=FileReadPolicy,
        allowed_trust_levels={"PUBLIC", "INTERNAL"},
    ),
    "database_write": ToolSpec(
        name="database_write",
        policy=DatabaseWritePolicy,
        requires_oversight=True,
        allowed_trust_levels={"INTERNAL", "CONFIDENTIAL"},
    ),
})

guard = Guard(
    manifest.tools["database_write"].policy,
    config=GuardConfig(
        privilege_scope=manifest.as_privilege_scope(),
        oversight_workflow=redis_workflow,
    )
)
```

#### 5-C: TOCTOU Gap — One-Call API

**What's broken:** The execution token system requires the caller to: (1) verify the decision, (2) mint a token, (3) pass the token to the executor, (4) have the executor consume the token. This is a four-step protocol with documentation explaining the gap — the gap only closes if the caller follows all four steps in the right order.

**Design prescription:** Add a `Guard.verify_and_execute()` method that encapsulates the entire protocol:

```python
async def verify_and_execute(
    self,
    intent: dict,
    state: dict,
    action: Callable[[], Awaitable[T]],
    *,
    token_verifier: ExecutionTokenVerifier,
) -> tuple[Decision, T | None]:
    """
    Atomically: verify intent, mint a single-use token, execute action.
    The action is only called if verify() returns allowed=True.
    The token is consumed before action execution, closing the TOCTOU window.
    Returns (decision, action_result). action_result is None if blocked.
    """
    decision = await self.verify_async(intent, state)
    if not decision.allowed:
        return decision, None

    token = ExecutionToken.mint(decision.decision_id, token_verifier)
    # Token consumption and action execution happen in the same atomic operation
    async with token_verifier.consume_transaction(token) as consumed:
        if not consumed:
            return decision.error("token_already_consumed"), None
        result = await action()
    return decision, result
```

This API makes the TOCTOU-safe path the default path. The multi-step protocol remains available for callers who need it, but the one-call API eliminates the footgun for most use cases.

---

### Phase 6: Enterprise Hardening (8 weeks)

**Gate condition:** At least one cloud KMS provider (AWS recommended) is tested against real IAM in a staging environment. `rotate_key()` is implemented for AWS KMS and HashiCorp Vault. Audit sink overflow drops zero decisions silently. K8s webhook is tested against a real Kind cluster in CI. `pramanix doctor` Redis check is unconditional.

#### 6-A: Cloud KMS Staging Integration Tests

**What's broken:** All four cloud KMS providers are fake-backed. Real IAM paths, key rotation, regional failover are untested.

**Actions:**
1. Add `test_aws_kms_staging.py` marked `@pytest.mark.staging` (skipped in default CI, runs in a dedicated staging CI job with real AWS credentials injected via GitHub OIDC).
2. Test: key creation, signing, verification, key rotation, IAM permission error (wrong role), network timeout, key version mismatch.
3. Implement `rotate_key()` for `AwsKmsKeyProvider` and `HashiCorpVaultKeyProvider` (currently `NotImplementedError` in both).
4. Repeat for GCP Secret Manager and Azure Key Vault in subsequent sprints.

#### 6-B: Audit Sink Zero-Loss Guarantee

**What's broken:** `KafkaAuditSink` overflows at 10,000 entries and silently drops decisions. A transient Kafka outage = silent audit loss. For regulated industries, this is unacceptable.

**Design prescription:**

Implement a two-tier sink architecture:

```
Primary sink (Kafka/S3/Splunk/DD)
    │
    └─ On failure / overflow → Local fallback sink (SQLite WAL-mode)
           │
           └─ Background reconciler thread: replays SQLite to primary when available
```

`LocalFallbackSink` uses SQLite in WAL mode (already present in the codebase for token verification). It never drops decisions. The background reconciler drains SQLite to the primary sink on recovery.

**API addition:**

```python
@dataclasses.dataclass
class KafkaAuditSink:
    # ... existing fields ...
    fallback_sink: AuditSink | None = None  # NEW — called on overflow/error
    overflow_strategy: Literal["drop", "fallback", "raise"] = "fallback"  # NEW
```

**Test requirement:** `test_audit_sink_no_loss.py` — simulate Kafka broker down, emit 10,000 decisions, assert all 10,000 appear in the SQLite fallback, bring Kafka back up, assert all 10,000 are reconciled to Kafka within 60 seconds.

#### 6-C: Kubernetes Admission Webhook End-to-End

**What's broken:** K8s webhook is unit-tested against synthetic payloads. TLS certificate handling, webhook registration, and the actual K8s API server payload format are untested.

**Actions:**
1. Add a `tests/e2e/test_k8s_webhook.py` that starts a Kind cluster via `pytest-kind`, deploys the webhook, and sends real `AdmissionReview` requests.
2. Test: ALLOW decision (valid pod spec), BLOCK decision (policy violation), TLS certificate rotation, webhook timeout handling.
3. This CI job should run nightly, not on every PR (Kind startup is ~2 minutes).

#### 6-D: Python 3.11 Lower Bound — Enterprise Adoption

This is from Phase 2 but operationally affects enterprise. Validate that all Pramanix features work correctly on the Python versions used by major cloud providers' managed runtimes:
- AWS Lambda Python 3.11 runtime
- Google Cloud Functions Python 3.11 runtime
- Azure Functions Python 3.11 runtime

Add a CI job that runs `pramanix doctor` in a Lambda-like environment (restricted imports, no `fork`, limited temp directory).

#### 6-E: `pramanix doctor` Unconditional Redis Check

**What's broken:** Doctor skips the Redis check if `PRAMANIX_REDIS_URL` is not set, even if Redis-backed components are configured.

**Fix:** If any of `RedisExecutionTokenVerifier`, `RedisDistributedBackend`, or `RedisApprovalWorkflow` is instantiated (detectable via `GuardConfig` introspection), the doctor must require `PRAMANIX_REDIS_URL` to be set and must attempt a real `PING` before declaring the environment healthy.

---

### Phase 7: Integration Ecosystem (8 weeks)

**Gate condition:** All 9 framework adapters have CI jobs that install the real framework and run at least one end-to-end test. gRPC interceptor is tested against real grpcio. `interceptors/__init__.py` imports are functional. All adapters updated to current framework API versions.

#### 7-A: Real Framework CI Tests (5 adapters)

For each of CrewAI, DSPy, Haystack, PydanticAI, SemanticKernel:

1. Add `extras-{framework}` CI job that: installs framework, runs `tests/integration/test_{framework}_adapter.py`.
2. Each integration test must: instantiate a real agent/module, attach the Pramanix adapter, run one ALLOW and one BLOCK scenario, assert the decision is propagated correctly.
3. Pin framework versions in `pyproject.toml` optional extras and update them via Renovate/Dependabot.

**gRPC interceptor specific:** The `handler._replace(**replace_kwargs)` call assumes `HandlerCallDetails` is a NamedTuple. Pin to grpcio ≥ 1.60 and verify this assumption; add a version check at interceptor construction time.

#### 7-B: New Integrations for Competitive Parity

Guardrails AI integrates natively with OpenAI, Anthropic, Google, Cohere, Hugging Face. Pramanix must ship adapters for the LLM clients most used by enterprise customers:

1. **OpenAI client adapter:** Wrap `openai.Client.chat.completions.create()` — validate input before calling, validate output after. Works with both `OutputGuard` (from Phase 3) and `Guard`.
2. **Anthropic client adapter:** Same pattern for `anthropic.Anthropic().messages.create()`.
3. **LiteLLM adapter:** LiteLLM is a proxy for 100+ providers — one Pramanix adapter covers all of them.

These adapters are the bridge between Phase 3 (output validation) and the LLM clients that generate the output.

#### 7-C: MCP (Model Context Protocol) Server

The MCP protocol is becoming the standard interface for AI agent tool invocation. Pramanix should expose a Guard-as-MCP-server capability:

```python
class PramanixMCPServer:
    """Exposes a Guard instance as an MCP server that validates tool calls."""

    def __init__(self, guards: dict[str, Guard], host: str = "localhost", port: int = 8080):
        ...

    async def start(self) -> None:
        """Starts the MCP server. Tool calls to registered guards are intercepted."""
        ...
```

An AI agent (Claude, GPT-4, etc.) configured to use this MCP server will have every tool call formally verified before execution. This is a market positioning move — it positions Pramanix as infrastructure for Claude, GPT, and any MCP-compatible agent.

---

### Phase 8: Performance Engineering (6 weeks)

**Gate condition:** P50 < 3ms in sync mode on the CI hardware. Benchmark self-reports `"passed": true`. Benchmark runs in nightly CI and artifacts are stored. Memory stability test passes 24-hour soak.

#### 8-A: Hot Path Profiling

**What's broken:** P50 = 5.235ms against a 5ms target. Benchmark self-reports `"passed": false`. The margin is thin and will vary by OS scheduling.

**Actions:**
1. Profile `Guard.verify()` hot path using `cProfile` + `pstats` on a representative policy (10 invariants, mix of arithmetic and string).
2. Expected bottlenecks: Z3 solver startup per call (if context not cached), Pydantic strict-mode validation overhead, `ResolverRegistry.clear_cache()` every call, structlog serialization.
3. The Z3 solver context is already cached via `InvariantASTCache` — verify this is actually being hit on every call and not being recreated.
4. Move structlog emission off the critical path: buffer log records in a `queue.SimpleQueue` and drain in a background thread. This removes serialization from the hot path.

#### 8-B: Concurrent Z3 Solves per Worker Process

**The opportunity:** Z3 releases the Python GIL during `solver.check()`. In `async-process` mode, each worker runs one Z3 solve at a time. But since GIL is released, multiple Z3 solves can run concurrently within a single process.

**Design prescription:**

Modify the worker process to run a thread pool for Z3 solves:

```python
# Inside worker process:
_Z3_THREAD_POOL = concurrent.futures.ThreadPoolExecutor(
    max_workers=os.cpu_count() or 4,
    thread_name_prefix="z3-solve",
)

def _solve_concurrent(policy_cls, values_dict, timeout_ms):
    """Submit to thread pool; GIL is released during solver.check()."""
    future = _Z3_THREAD_POOL.submit(_solve_inner, policy_cls, values_dict, timeout_ms)
    return future.result(timeout=timeout_ms / 1000)
```

This allows a 4-core worker process to run 4 concurrent Z3 solves. With 4 worker processes, throughput increases from 4 concurrent solves to 16.

**Expected throughput gain:** 3-4x under sustained concurrent load. The GIL release during `solver.check()` has been confirmed in the existing architecture decisions. This is not speculative.

#### 8-C: Benchmark as First-Class CI Artifact

**What's broken:** The benchmark runs locally and results are committed to the repo. Reproducibility is unknown. The nightly benchmark job exists but result archival strategy is not specified.

**Actions:**
1. The nightly CI benchmark job must: run the full latency benchmark, produce `results/latency_results_{date}.json`, upload as a GitHub Actions artifact, post a PR comment if P50 regresses by > 10% vs the rolling 7-day baseline.
2. The benchmark gate must change from `P99 < 15ms` to `P50 < 3ms AND P99 < 8ms` after Phase 8-A optimizations.
3. Store the last 90 days of benchmark results for trend analysis.

#### 8-D: Policy Compilation Time Optimization

**The problem:** Guard construction calls `transpiler.compile_policy()` which pre-walks the expression tree. For policies with 50+ invariants (not unusual in fintech/healthcare), this can be slow at startup.

**Actions:**
1. Profile `Guard.__init__` time for a 50-invariant policy.
2. If > 100ms, implement `compile_policy()` result caching at the class level (not instance level) — same policy class instantiated multiple times shares the compiled AST.
3. Cache key: `(policy_cls.__qualname__, policy_hash)` — invalidated when policy changes.

---

### Phase 9: DX and Ecosystem (Ongoing from Phase 2)

**Gate condition:** A developer can install, write their first policy, and call `guard.verify()` in under 10 minutes. A developer searching PyPI for "AI guardrails" finds Pramanix. The policy authoring experience has IDE completions and type safety for all common operations.

#### 9-A: Field Type Safety Improvements

**What's broken:** `Field("name", python_type, z3_sort)` — swapping positions 2 and 3 fails at Guard construction, not at policy definition. IDEs cannot catch this.

**Design prescription:**

```python
# Current (error-prone):
amount = Field("amount", Decimal, "Real")

# New (keyword-only, IDE-completable):
amount = Field(name="amount", python_type=Decimal, z3_sort="Real")
# OR via type-inferred factory:
amount = DecimalField("amount")     # → Field(name="amount", python_type=Decimal, z3_sort="Real")
amount = IntegerField("amount")     # → Field(name="amount", python_type=int, z3_sort="Int")
amount = StringField("amount")      # → Field(name="amount", python_type=str, z3_sort="String")
amount = BooleanField("amount")     # → Field(name="amount", python_type=bool, z3_sort="Bool")
```

Positional-arg form remains supported for backward compatibility. Add `DeprecationWarning` to positional arg usage. This is a DX improvement that prevents the most common new-user mistake.

#### 9-B: Two-Signing-System Documentation and Rationalization

**What's broken:** `DecisionSigner` (HMAC-SHA256) and `PramanixSigner` (Ed25519) both exist, both sign `decision_hash`, both are exported. The tradeoff is underdocumented.

**Actions:**
1. Add a `SIGNING_GUIDE.md` that explains: use `PramanixSigner` (Ed25519) for regulated-industry compliance (third-party verifiable), use `DecisionSigner` (HMAC) only for internal integrity checks where you control both sides.
2. Add a `pramanix doctor --check-signing-config` that warns if both signers are configured simultaneously (redundant) or if no signer is configured in `PRAMANIX_ENV=production`.
3. In the long run (v2.0), deprecate `DecisionSigner` — Ed25519 is strictly more capable. Asymmetric signing is always preferable for an audit trail because the verifier does not need the private key.

#### 9-C: `is_business_hours()` Weekday Encoding Fix

**What's broken:** `epoch//86400 % 7` where `0 = Thursday` (Unix epoch = 1970-01-01 = Thursday). A developer expecting `0 = Monday` writes silent day-of-week bugs.

**Fix:**

```python
def is_business_hours(
    field: Field,
    *,
    start_hour: int = 9,
    end_hour: int = 17,
    timezone: str = "UTC",  # Add explicit timezone support
    business_days: frozenset[int] = frozenset({0, 1, 2, 3, 4}),  # 0=Monday, ISO weekday
) -> ConstraintExpr:
    """
    Returns a ConstraintExpr that is True if the field value (Unix epoch seconds)
    falls within business hours.

    business_days uses ISO weekday convention: 0=Monday, 1=Tuesday, ..., 6=Sunday.
    The default {0,1,2,3,4} corresponds to Monday–Friday.
    """
    # Internal: convert ISO weekday to epoch-based weekday
    # epoch//86400 % 7: 0=Thursday. To get ISO weekday from epoch day:
    # iso_weekday = (epoch_day + 3) % 7  [because Thursday=0 and ISO Thursday=3]
```

This is a breaking change to the API signature but not to existing behavior (the default matches Monday-Friday even with the corrected encoding). Add to `MIGRATION.md`.

#### 9-D: Cloud Provider Re-exports

**What's broken:** `from pramanix import AwsKmsKeyProvider` fails. Must use `from pramanix.key_provider import AwsKmsKeyProvider`.

**Fix:** Add to `pramanix/__init__.py`:

```python
from .key_provider import (
    AwsKmsKeyProvider,
    AzureKeyVaultKeyProvider,
    GcpKmsKeyProvider,
    HashiCorpVaultKeyProvider,
)
```

Gate each import behind `try/except ImportError` with the correct extra name in the error message.

#### 9-E: Policy Hub (Community Validator/Policy Library)

**What this is:** A mechanism for the community to publish reusable `Policy` classes and `OutputValidator` implementations as standalone Python packages. Analogous to Guardrails Hub.

**Design prescription:**

Define a `pramanix-hub` CLI extension:

```
pramanix hub install pramanix-fintech-policies
pramanix hub install pramanix-healthcare-validators
pramanix hub list --category=fintech
pramanix hub publish ./my_policy_package/
```

Policies in the hub are just Python packages with a `pyproject.toml` declaring:
```toml
[tool.pramanix]
hub_category = "fintech"
hub_policies = ["pramanix_fintech.TransferPolicy", "pramanix_fintech.WirePolicy"]
```

`pramanix hub install` does `pip install` and registers the policy in a local `~/.pramanix/hub/registry.json`.

This is a community flywheel, not an engineering task. The technical cost is low (it's a thin wrapper around pip). The strategic value is high — a hub makes Pramanix sticky and creates ecosystem lock-in through policy reuse.

---

### Phase 10: v2.0 Distributed Architecture (Long-Term)

**Target:** Pramanix Guard as a standalone microservice. Multiple agents sharing one Guard instance over gRPC/HTTP. Distributed policy evaluation. Multi-agent topology safety.

This phase is architectural future planning, not near-term execution. The current in-process Guard architecture is correct for single-service deployments. The v2.0 architecture enables platform-level deployment where Pramanix is itself a service.

#### 10-A: Guard-as-a-Service

```
Agent 1 ──┐
Agent 2 ──┤──→ PramanixService (gRPC) ──→ PolicyEngine (Z3 cluster)
Agent 3 ──┘                                      │
                                           AuditStore (Kafka → S3)
```

The `PramanixGrpcInterceptor` (already implemented, weakly tested) becomes the client-side transport. The server is a new `PramanixService` with:
- Stateless verification workers (same Z3 engine, same HMAC IPC)
- Policy registry (policies are uploaded to the service, not compiled in the client)
- Centralized audit trail
- Service-level circuit breaker

#### 10-B: Multi-Agent Topology Safety

When multiple AI agents interact with each other (agent A calls agent B, which calls agent C), information flow between agents must be controlled. The IFC subsystem (already implemented) is the natural mechanism — but it currently operates on trust labels, not agent identities.

**Extension:** `AgentIdentityLabel` — a signed JWT identifying the calling agent. IFC `FlowRule` entries can reference agent identities:

```python
FlowRule(source="agent:financial-analyst", dest="agent:trade-executor", action=ALLOW)
FlowRule(source="agent:*", dest="agent:core-banking", action=DENY)
```

This allows Pramanix to enforce information flow in multi-agent pipelines, not just between data trust levels.

---

## 3. Cross-Cutting Concerns

### 3.1 What Must Not Change

The following properties are the core technical moat. They must not be weakened by any phase of this roadmap:

1. `Guard.verify()` never raises. The new `Conversation.add_user_turn()` raises — by design, for the oversight gate. This is acceptable. Guard itself must never raise.
2. `Decision(allowed=True)` only when `status=SAFE`. The new `OutputDecision` must enforce the same invariant: `OutputDecision(allowed=True)` only when `status=VALID` or `status=REPAIRED`.
3. HMAC-sealed IPC in async-process mode. Never loosen this.
4. Timing pad applied to both ALLOW and BLOCK. Any new fast path must also apply the timing pad.
5. Fail-closed: every error path produces `allowed=False`. Every new error handler must follow this.

### 3.2 The Test Discipline Problem

The 8 coverage-padding files are a symptom, not the disease. The disease is coverage-as-a-KPI. Coverage measures which lines were executed, not whether the behavior is correct. A policy that `return True` always achieves 100% coverage.

**Structural fix:** Rename the CI coverage gate to `behavioral_confidence_gate`. The metric it measures changes from line coverage to:
- Lines covered by tests that also assert a specific output (not just "no exception raised")
- Tests that cover at least one ALLOW path and one BLOCK path for each policy
- Tests that exercise at least one adversarial input per security-critical code path

This is not a tooling change — it is a discipline change enforced in code review.

### 3.3 Benchmark Honesty

The forensic audit found that the benchmark `self-reports "passed": false`. This must be fixed before any benchmark result is published in documentation, marketing material, or a README.

**Rule:** A benchmark that reports `"passed": false` must not appear in any published artifact. Either fix the performance (Phase 8) or change the target to one that is actually met. Publishing a failed benchmark result as evidence of performance capability is a defect in documentation, not a caveat.

### 3.4 AGPL Dual-License as Adoption Strategy

The AGPL license is correctly chosen for the monetization strategy: regulated institutions cannot ship AGPL code without a commercial license. This is the wedge. But AGPL also creates a friction for adoption in open-source projects and startups.

**Recommendation:** Keep AGPL for the core SDK. License the `primitives/` module (pre-built policies) under MIT or Apache-2.0. This makes the policy library freely adoptable, drives adoption, and creates inbound leads for the commercial license (because any institution that adopts the primitives at scale will need the commercial license for compliance reasons).

---

## 4. Execution Priority Matrix

The following table sequences work by impact-to-effort ratio. This is the order in which phases should be executed within each sprint cycle.

| Priority | Item | Phase | Effort (weeks) | Impact | Blocker? |
|---|---|---|---|---|---|
| P0 | Fix Pickle RCE | 0-A | 0.5 | CRITICAL security | Yes — blocks PyPI |
| P0 | Fix FlowRule glob | 0-B | 0.5 | CRITICAL correctness | Yes — IFC is silent |
| P0 | Fix interceptors import | 0-C | 0.1 | HIGH usability | Yes — docs are wrong |
| P0 | Unify verify_async | 0-D | 2 | HIGH correctness | Yes — divergence inevitable |
| P0 | Fix policy fingerprint | 0-E | 0.5 | HIGH correctness | No |
| P0 | Fix Meta inheritance | 0-F | 0.5 | HIGH correctness | No |
| P1 | PyPI publication | 2-A | 1 | CRITICAL adoption | Yes — zero installs without this |
| P1 | Python 3.11/3.12 support | 2-B | 2 | HIGH adoption | No |
| P1 | Governance Guard coupling | 1-A | 3 | HIGH architecture | No |
| P1 | Durable oversight backend | 1-B | 2 | HIGH enterprise | No |
| P1 | O(n) eviction fix | 1-D | 0.2 | MEDIUM performance | No |
| P2 | Windows CI | 2-C | 1 | HIGH correctness | No |
| P2 | Coverage alignment | 2-D | 1 | MEDIUM honesty | No |
| P2 | Output validation engine | 3 | 10 | CRITICAL competitive | No — highest strategic value |
| P2 | Multi-turn conversation safety | 4 | 10 | CRITICAL competitive | No — highest strategic value |
| P3 | Agent tools hardening | 5 | 6 | HIGH DX | No |
| P3 | Performance optimization | 8 | 6 | HIGH reliability | No |
| P3 | Real framework CI tests | 7-A | 4 | HIGH correctness | No |
| P4 | Cloud KMS staging tests | 6-A | 3 | HIGH enterprise | No |
| P4 | Audit sink zero-loss | 6-B | 3 | HIGH enterprise | No |
| P4 | K8s webhook e2e | 6-C | 2 | MEDIUM enterprise | No |
| P5 | New integrations (OpenAI, Anthropic) | 7-B | 3 | HIGH adoption | No |
| P5 | MCP server | 7-C | 3 | HIGH positioning | No |
| P5 | Policy Hub | 9-E | 4 | HIGH ecosystem | No |
| Ongoing | DX improvements | 9-A/B/C/D | 2 | MEDIUM adoption | No |

---

## 5. Honest Assessment of Time to 100/100

The audit verdict was: *"approximately 18–24 months of focused engineering from being a competitive enterprise platform."*

With this roadmap and one engineer executing full-time:

- **Phases 0-2 (Fixes + Release):** 10 weeks → Pramanix reaches ~4.2/5 average and is publicly installable
- **Phases 3-4 (Output Validation + Conversation Safety):** 20 more weeks → Pramanix reaches ~4.6/5 average and closes the Guardrails/NeMo capability gap
- **Phases 5-8 (Hardening + Performance):** 26 more weeks → Pramanix reaches ~4.9/5 and is enterprise-deployable
- **Phase 9 (Ecosystem):** Ongoing → Pramanix reaches 5/5 as community adoption grows

**Total: ~56 weeks** from today to a defensible 100/100 across all dimensions.

The 18-24 month audit estimate is accurate. This roadmap does not compress it — it structures it. The work is real.

The good news: Phases 0-2 (the foundation) take 10 weeks and unlock everything else. The core kernel is already 5/5. The remaining distance is platform work, not fundamental re-architecture. That is a much better position than starting from zero.

---

## 6. Final Technical Verdict

**The kernel is genuinely elite.** Two-phase Z3 with per-invariant attribution, HMAC-sealed IPC, Ed25519 Merkle audit trails, adversarially-verified fail-closed guarantee — this is technically superior to every comparable open-source guardrail. This is not flattery; it is a technical finding verifiable from the code.

**The platform is not.** Six beta subsystems with no Guard coupling, five adapters untested against real frameworks, cloud KMS entirely faith-based, no PyPI release, no output validation, no conversation safety, P50 benchmark self-reporting failure.

**The gap is closable.** Unlike the kernel — which required genuine formal verification expertise — the platform gaps are engineering work, not research. Real framework CI tests are four weeks of CI configuration. O(n) eviction is three one-line changes. The interceptors import is one line. The output validation engine is ten weeks of design and implementation from a strong foundation.

**The strategic path is clear:** Fix the P0 bugs, publish to PyPI, build the output validation engine, build the conversation safety layer. In that order. Everything else is optimization.

The question is execution velocity, not direction.

---

*End of roadmap. All findings traceable to FORENSIC_AUDIT.md, ARCHITECTURE_NOTES.md, KNOWN_GAPS.md, DECISIONS.md. Code is authoritative.*