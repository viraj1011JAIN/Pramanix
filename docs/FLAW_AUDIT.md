# PRAMANIX COMPLETE FLAW AUDIT

Every Crack, Gap, Fake, Stub, Mock, Silent Swallow, and Drawback — Source-Verified · Line-Cited · No Sugar-Coating

> **Methodology**: Direct grep scans + full file reads of every `.py`, `.yml`, `.toml`,
> and Dockerfile in the repository.
>
> **Prior agent audit verdict**: "The codebase is forensically clean with no flaws."
> **This audit verdict**: 342 confirmed findings across tests, source, CI, and architecture.
>
> **Last verified**: 2026-06-04 (five-pass exhaustive deep audit, 342 total findings, all 112 production files read)
>
> **FIX STATUS (2026-06-05)**: 85+ flaws fixed across 5 commit waves. See **PART 16** (appended) for full fix log.
> Critical (🔴) production bugs: **ALL FIXED**. Supply chain RCE (#304-309): **ALL PINNED TO SHA**.
> Remaining open: 3 architectural deferrals requiring full persistence-layer redesign (#29, #261, #263).

---

## Severity Legend

| Symbol | Meaning |
| ------ | ------- |
| 🔴 CRITICAL | Breaks a documented guarantee or hides production bugs |
| 🟠 HIGH | Significant gap with observable production impact |
| 🟡 MEDIUM | Structural problem or silent degradation |
| 🔵 LOW | Minor inconsistency, cosmetic, or edge-case only |

---

# PART 1 — TEST SUITE FLAWS

## 1.1 Mocks and Fakes

### 🟠 #6 — 147 `monkeypatch.setattr` Calls Across 31 Test Files

| File | Count | Impact |
| ---- | ----- | ------ |
| `test_cli_simulate.py` | 20+ | CLI tested with patched `Guard.verify()` — not real guard |
| `test_worker_dark_paths.py` | 8 | `os.getpid`, `os.kill`, `os.getppid` replaced with lambdas |
| `test_guard_dark_paths.py` | 4 | Internal guard methods replaced |
| Others | 115+ | Various real functions replaced |

Real OS signal delivery, real process inspection, and real timer behavior are never exercised.

---

### 🟠 #7 — Private Attribute Mutations — White-Box Hacks

Direct mutation of private attributes to force states unreachable by API:

| File | Line | Mutation |
| ---- | ---- | -------- |
| `test_audit_sink_full_coverage.py` | 137 | `_sink_mod._OVERFLOW_COUNTER = original` (resets module-level global) |
| `test_translator_anthropic.py` | 53, 58 | `assert t._api_key == "sk-test"` (testing private field) |
| `test_translator.py` | 601 | `assert t._api_key == _OPENAI_TEST_KEY` |
| `test_circuit_breaker_and_guard_paths.py` | 1332 | `p._secret_name = "key"` |
| `test_interceptors_real.py` | 146-149 | `consumer._dlq_topic`, `consumer._dlq_pending`, etc. |

---

### 🟠 #8 — Azure/GCP/Vault Key Providers Tested Only Against Duck-Typed Stubs

`test_kms_provider.py`, `test_circuit_breaker_and_guard_paths.py`, `test_misc_coverage_gaps.py` use `_FakeSecretClient`, `_FakeSecretsManagerClient`, `_FakeHvacModule`. None implement real SDK error models, retry behavior, or authentication flow. Rotation behavior for Azure, GCP, and Vault has never been tested against real cloud APIs.

---

### 🟠 #9 — `test_translator.py` — 1,140 Lines, Zero Real API Calls

Every translator unit test uses inline protocol fakes (`_RecordingTranslator`, inline `FakeTranslator` class). No real LLM call, no real JSON parsing stress, no real retry logic tested. Tests verify orchestration plumbing, not LLM integration behavior.

---

### 🟠 #10 — `deadline=None` Disabled on ALL Property Tests

Every Hypothesis property test uses `deadline=None`. A 10× performance regression in Z3 solving would not be caught by any property test. This affects:
- `test_dsl_and_transpiler_properties.py` — 15+ `@settings(deadline=None)`
- `test_fintech_primitive_properties.py` — 10+ `@settings(deadline=None)`
- `test_serialization_roundtrip.py`, `test_injection_scorer_property.py`, `test_consensus_semantic.py`, `test_decision_hash.py`

---

### 🟠 #11 — `suppress_health_check=[HealthCheck.too_slow]` Masks Performance Regressions

**Files**: `tests/unit/test_sanitise_properties.py:143`, `tests/unit/test_decision_hash.py:122`

Hypothesis `too_slow` health checks catch functions running significantly slower than expected. Suppressing them means sanitizer and hash computation performance regressions go undetected in property tests.

---

### 🟡 #12 — `assume(peak >= current)` in Fintech Properties — Abnormal Regime Never Explored

**File**: `tests/property/test_fintech_primitive_properties.py:215`
```python
assume(peak >= current)
```
The max-drawdown test never explores `current > peak` (possible data integrity error). This edge case produces undefined policy behavior but is excluded from property exploration.

---

### 🟡 #13 — `sys.modules` Manipulation Without Automatic Restore

**File**: `tests/unit/test_translator_and_interceptor_paths.py:677-678, 810-811`
```python
if "pramanix.interceptors.grpc" in sys.modules:
    del sys.modules["pramanix.interceptors.grpc"]
```
Bare `del sys.modules[...]` without a `try/finally` restore. If the test fails mid-way, `sys.modules` remains polluted for the session.

---

# PART 2 — PRODUCTION SOURCE FLAWS

## 2.1 Silent Signing Failures — All Three Signers Return `""` on ANY Exception

### 🟠 #17 — `integrations/langgraph.py:59-60` — Prometheus Metrics Setup Failure at DEBUG

```python
except Exception as _e:
    _log.debug("pramanix.integrations.langgraph: metrics setup failed: %s", _e)
```
LangGraph node-level latency and verdict metrics are silently disabled without any operator warning. Production deployments monitoring LangGraph guard decisions via Prometheus receive no data and no alert.

---

### 🟠 #18 — `integrations/semantic_kernel.py:104-106` — Guard Errors Swallowed Into JSON Response

```python
except Exception as exc:
    _log.error("pramanix.sk.guard_error: %s", exc, exc_info=True)
    return json.dumps({"error": "Guard error — action blocked", "allowed": False})
```
Guard policy violations (`GuardViolationError`) and infrastructure failures (Z3 crash, OOM) both return the same JSON string `{"allowed": False}`. Callers cannot distinguish a policy violation from a guard infrastructure failure — both look identical to the Semantic Kernel caller.

---

### 🟠 #19 — `execution_token.py:936-940` — `consumed_count()` Fails Open, Returns `0`

```python
except Exception as _e:
    # fail-open for monitoring: return 0 so callers don't crash
    # LOG at WARNING so operators know the quota/rate-limit count is unreliable
```
If Redis SCAN fails, `consumed_count()` returns `0`. Any rate-limiting or quota logic based on `consumed_count()` is silently bypassed during Redis failures. The comment says "fail-open" — this is intentional but dangerous.

---

### 🟡 #20 — `execution_token.py:1071` — `asyncio.run()` Fallback in "Test Mode"

```python
if self._loop is None:
    return asyncio.run(coro)   # test mode fallback
```
`asyncio.run()` raises `RuntimeError: This event loop is already running` if called from within an async context. If `PostgresExecutionTokenVerifier` is instantiated without providing `loop` (e.g., in an async FastAPI handler), the first call crashes with a confusing `RuntimeError`. The "test mode" comment doesn't protect against accidental production misconfiguration.

---

### 🟡 #21 — `provenance.py` — Invalid `PRAMANIX_PROVENANCE_KEY` Falls Through to Ephemeral Key

**File**: `src/pramanix/provenance.py:107-112`
```python
except ValueError as exc:
    _log.warning("provenance: invalid PRAMANIX_PROVENANCE_KEY value (%s) — falling back to ephemeral key", exc)
```
If an operator sets `PRAMANIX_PROVENANCE_KEY` to an invalid hex string (typo, truncation), Pramanix silently falls back to a random ephemeral key. The WARNING is easy to miss. The ProvenanceChain then uses a key the operator did NOT intend, and cross-process chain verification silently fails. Should raise `ConfigurationError` in production mode.

---

### 🟡 #22 — `key_provider.py` — `RuntimeError` From Cloud Providers, Not Typed Exceptions

Cloud key providers raise untyped `RuntimeError` on infrastructure failure:
- `AwsKmsKeyProvider._refresh_cache()` — `key_provider.py:369-373` → `RuntimeError`
- `AzureKeyVaultKeyProvider._refresh_cache()` — `key_provider.py:483-487` → `RuntimeError`
- `GcpKmsKeyProvider._refresh_cache()` — `key_provider.py:605-609` → `RuntimeError`

Callers expecting `ConfigurationError` or typed Pramanix exceptions receive `RuntimeError` — standard Python error type with no Pramanix context. Makes `except PramanixError` guards miss these failures.

---

### 🟡 #23 — `mesh/authenticator.py:510-513` — JWKS Thundering Herd on Refresh Failure

```python
try:
    fresh_keys = self._fetch_jwks()
except Exception:
    with self._jwks_lock:
        self._jwks_fetching = False   # ← resets the "in progress" flag
    raise
```
If `_fetch_jwks()` fails, `_jwks_fetching` is reset to `False`. On the next request, all concurrent callers see stale cache and all try to refresh simultaneously. No backoff, no jitter, no "failed recently" flag. Under high concurrency after a JWKS endpoint failure, this creates a thundering herd of retry requests.

---

### 🟡 #24 — `mesh/authenticator.py:548` — Synchronous `httpx.get()` in JWKS Fetch

```python
response = httpx.get(
    self._jwks_uri,
    timeout=httpx.Timeout(connect=self._connect_timeout, read=self._read_timeout, ...),
    ...
)
```
`httpx.get()` is synchronous. In async contexts (FastAPI, pytest-asyncio), `_get_cached_jwks_keys()` is called via `asyncio.to_thread()` — which offloads to a thread pool. This is correct but undocumented. Developers who call `authenticate_and_bind()` (sync variant) directly from async code will block the event loop. No warning in docs or code.

---

### 🟡 #25 — `integrations/crewai.py:175-178` — Guard Error and Policy Violation Indistinguishable

```python
except Exception as exc:
    _log.error("pramanix.crewai.guard_error: %s", exc, exc_info=True)
    return f"{_SAFE_FAILURE_PREFIX} Guard error during verification. ..."
```
`GuardViolationError` (policy blocked the action) and `Exception` (infrastructure failure) return the same string prefix to CrewAI. A Z3 crash and a legitimate policy block are identical from the CrewAI caller's perspective.

---

### 🟡 #26 — `audit/merkle.py:228` — Atexit Flush Silently Suppressed

```python
with contextlib.suppress(OSError, RuntimeError):
    anchor.flush()
```
If the Merkle anchor fails to flush on process exit (disk full, NFS timeout, file descriptor exhaustion), the last batch of decisions is **silently lost** with no log entry. Decisions that happened after the last successful flush are not in any durable audit log. The `atexit` context makes logging unreliable, but `sys.stderr.write()` would at least surface the error.

---

### 🔵 #27 — `guard_pipeline.py` — WARNING Logs Don't Include Policy Invariant Label

**File**: `src/pramanix/guard_pipeline.py:94-98, 123-127, 158-161`
```python
except Exception as _exc:
    _log.warning(
        "guard_pipeline: daily-limit safety check received non-numeric value "
        "(daily_limit=%r, daily_spent=%r) — applying safe-default DENY",
        ...
    )
```
When a semantic pipeline check receives a non-numeric value and applies safe-default DENY, the WARNING log includes the field values but not the policy name or invariant label. Operators cannot trace which specific guard instance or policy triggered this from the log alone.

---

## 2.3 Global Mutable State

### 🟡 #28 — 5 Module-Level Mutable Globals — Unsafe Under Free-Threaded Python 3.13

| Variable | File | Type | Risk |
| -------- | ---- | ---- | ---- |
| `_PROVENANCE_KEY` | `provenance.py:58` | `bytes \| None` | Double-checked locking but `os.environ.get()` not thread-safe under `--disable-gil` |
| `_signing_failure_counter` | `audit/signer.py:41` | Prometheus Counter | Lazy init with `global` |
| `_signing_failure_counter` | `crypto.py:69` | Prometheus Counter | Separate from signer.py — two different globals with same purpose |
| `_PARSE_FAILURE_COUNTER` | `fast_path.py:50` | Prometheus Counter | Lazy init with `global` |
| `_OVERFLOW_COUNTER`, `_SEND_ERROR_COUNTER` | `audit_sink.py:172-173` | Prometheus Counters | `global` with lock but `_prom_factory` injection race |

**Note**: `_signing_failure_counter` is defined independently in both `audit/signer.py` AND `crypto.py` — two separate module-level globals tracking the same metric. If both modules are imported, two independent failure counters exist but only one increments at a time.

---

## 2.4 Architectural Gaps

### 🟠 #31 — `ShadowEvaluator` — Unbounded Memory With `max_history=None`

**File**: `src/pramanix/lifecycle/diff.py:298`
```python
self._results: deque[ShadowResult] = deque(maxlen=max_history)
```
`deque(maxlen=None)` is an unbounded deque. If `ShadowEvaluator(max_history=None)` is called (or the default is relied on in a long-running process), results accumulate indefinitely. No flush-to-metrics, no flush-to-file, no eviction callback. Memory grows until OOM.

---

### 🟠 #32 — `DistributedCircuitBreaker` Class Docstring Lies About Default Behavior

**File**: `src/pramanix/circuit_breaker.py:622-634`
```python
"""...
backend: Distributed state backend.  Defaults to
         InMemoryDistributedBackend (single-process testing).
"""
```
The code at line 646 raises `ConfigurationError` if `backend=None`. The docstring is the opposite of true. Any operator who reads the docstring will provide no backend and immediately hit `ConfigurationError`.

---

### 🟠 #33 — Merkle Archive Plaintext by Default — No Warning in Production Mode

`MerkleArchiver` writes plaintext (zstd-compressed) archives by default. `EncryptedArchiveWriter` (AES-256-GCM) exists but requires `PRAMANIX_MERKLE_ARCHIVE_KEY`. When `PRAMANIX_ENV=production` and no archive key is set, no warning is emitted. HIPAA/PCI regulated deployments have unencrypted audit logs by default.

---

### 🟠 #34 — Merkle Tree In-Memory Only — Inclusion Proofs Break After Restart

`PersistentMerkleAnchor` stores the current root hash to disk but the actual leaf tree is in-memory. After process restart: root hash exists on disk but no leaves exist in memory. `verify(proof)` always fails because the required leaf hashes are gone. The "tamper-evident append-only log" claim breaks across process boundaries.

---

### 🟠 #35 — `SemanticSimilarityGuard` Name Misleads — Uses TF-IDF, Not Embeddings

**File**: `src/pramanix/nlp/validators.py`

`SemanticSimilarityGuard` implies vector embedding similarity (sentence-transformers style). It uses `TfidfVectorizer` (bag-of-words term frequency) with cosine similarity. TF-IDF has no semantic understanding — paraphrased injection attacks ("move funds" vs "transfer money") have near-zero cosine similarity under TF-IDF if words don't overlap. This is a **lexical overlap guard**, not a semantic similarity guard.

---

### 🟠 #36 — `ToxicityScorer` Name Misleads — Keyword Density Ratio, Not ML

**File**: `src/pramanix/nlp/validators.py`

`ToxicityScorer` performs keyword density matching against 58 stems. Despite the name implying an ML-backed toxicity model, it's a bag-of-words ratio counter. Fails against leetspeak, Unicode homoglyphs, foreign-language content, and semantic paraphrasing.

---

### 🟠 #37 — Healthcare Primitives — No Clinical Validation

**File**: `src/pramanix/primitives/healthcare.py`

`DosageGradientCheck` (Joint Commission NPSG 03.06.01) and `PediatricDoseBound` (FDA PREA weight-based dosing) encode clinically critical constraints. Any Z3 formulation error could contribute to patient harm. No clinical informatician, pharmacist, or patient safety organization has reviewed these primitives.

---

### 🟡 #38 — Privilege Gate Silently Skipped When `"tool"` Key Absent

**File**: `src/pramanix/guard.py` — `_apply_governance_gates()`
```python
_tool = str(intent_values.get("tool") or intent_values.get("_tool") or "")
if _tool:
    ...privilege check...
# else: silently skipped
```
If neither `"tool"` nor `"_tool"` key exists in intent, the entire privilege check is skipped without error or warning. Agents using `"action"`, `"function"`, `"command"`, or any other key name for their tool identifier bypass `ExecutionScope` enforcement entirely.

---

### 🟡 #39 — `PolicyDiff` Structural-Only — Semantically Equivalent Invariants Show as "Changed"

**File**: `src/pramanix/lifecycle/diff.py`

Two invariants expressing `amount <= balance` with labels `"balance_check"` vs `"suf_balance"` appear as fully changed. Two invariants with the same label but different expressions appear unchanged. No Z3 semantic equivalence checking. `PolicyDiff` is misleading for policy evolution audits.

---

### 🟡 #40 — YAML DSL Is Undocumented Subset — `ForAll`/`Exists`/`DatetimeField` Silently Fail

**File**: `src/pramanix/natural_policy/yaml_loader.py`

The YAML policy loader's safe AST visitor handles only 9 node types. Complex constructs (`ForAll`, `Exists`, `DatetimeField`, `NestedField`, `abs()`) are not reliably supported. There is no documented compatibility matrix. Operators get cryptic `PolicySyntaxError` without knowing which constructs are unsupported.

---

### 🟡 #41 — `z3-solver ^4.12` — No Cross-Version Compatibility Test

`pyproject.toml` allows any z3-solver 4.x minor. Z3 API behavior changed between 4.12 and 4.16. No automated test verifies transpiler semantics are stable across Z3 minor upgrades.

---

### 🟡 #42 — `NaturalPolicyCompiler` MetaVerifier Threshold Unvalidated

No test verifies the `MetaVerifier` semantic distance threshold catches real hallucinations. Without real-LLM CI testing, the threshold is an untested hyperparameter.

---

### 🟡 #43 — `ResolverRegistry` Not Safe Under Python 3.13 Free-Threaded

**File**: `src/pramanix/resolvers.py`

Module-level singleton dict with no lock around `register()`. In Python 3.13 `--disable-gil` mode, concurrent registrations corrupt the registry.

---

### 🟡 #44 — `integrations/haystack.py` Has Fail-Open Mode for Guard Errors

**File**: `src/pramanix/integrations/haystack.py:67,79`
```python
block_on_error: bool = True   # default is correct
```
The `block_on_error=False` mode causes guard infrastructure errors (Z3 crash, OOM, network error) to silently allow the request through. An operator who sets `block_on_error=False` for performance reasons inadvertently creates a fail-open behavior for guard failures.

---

### 🟡 #45 — Worker Warmup Uses 8 Hardcoded Patterns — Policy-Specific JIT Paths Still Cold-Start

**File**: `src/pramanix/worker.py:397-479`

Worker warmup runs 8 generic Z3 patterns. Policies using string-theory constraints, non-linear arithmetic, or array quantifiers will still cold-start on the first real request because the warmup doesn't trigger those JIT paths.

---

### 🔵 #46 — `security = ["google-re2"]` Extra Is Redundant

`google-re2 = ">=1.0"` is a required dependency at `pyproject.toml:49` (not `optional=true`). The `[security]` extra just re-lists it. Operators who see `[security]` think it enables something new, but RE2 is already always installed.

---

### 🔵 #47 — Two Independent `_signing_failure_counter` Globals for the Same Metric

`src/pramanix/audit/signer.py:41` and `src/pramanix/crypto.py:69` each define their own module-level `_signing_failure_counter` global. Both try to register `pramanix_signing_failure_total`. If `audit/signer.py` registers first, `crypto.py`'s registration either returns the same counter (if using the idempotent helper) or raises a collision error. Having two independent globals for the same metric is a maintenance hazard.

---

# PART 3 — CI/CD PIPELINE FLAWS

### 🟠 #48 — `continue-on-error: true` on Trivy SARIF Upload

**File**: `.github/workflows/ci.yml:418`
```yaml
- name: Upload Trivy SARIF report
  continue-on-error: true
```
If SARIF upload fails, CI reports green. Security findings may not appear in the GitHub Security tab. The Trivy scan itself does fail on CVEs, but the visibility artifact is silently lost.

---

### 🟠 #49 — Python 3.11/3.12 Claimed in Classifiers, Never CI-Tested

`pyproject.toml` declares classifiers for 3.11, 3.12, 3.13. CI matrix: 3.13 only. The `_Z3_CTX_CREATE_LOCK` fix was documented as triggered by Python 3.13 GC behavior — 3.11/3.12 compatibility untested.

---

### 🟠 #50 — CI Benchmark Gate Is a Microbenchmark — Sustained Load P99 Exceeds Gate

CI nightly gate: P99 < 15ms (20 warm sequential calls). Real sustained-load benchmark: P99 = 30.5ms at ~81 RPS, P99.99 ≈ 270ms spike. CI reports green while real production load exceeds the stated target by 2×.

---

### 🟡 #51 — Integration Test Coverage Not Included in 98% Measurement

The `coverage` job runs only `tests/unit tests/adversarial tests/property tests/benchmarks`. Integration test results are never submitted to Codecov. Code paths exercised only by integration tests (real Postgres, real Vault, real Redis) are invisible to the 98% gate.

---

# PART 4 — CONFIGURATION AND PACKAGING FLAWS

### 🟡 #52 — `_inc_signing_failure` in Both `audit/signer.py` and `crypto.py` — Duplicate Implementation

Both files define an `_increment_signing_failure_counter()` function that tries to register and increment the same `pramanix_signing_failure_total` counter. Two independent implementations doing the same thing with separate lazy-init logic is a maintenance hazard.

---

### 🔵 #53 — `setup.cfg` — Stale Config File Contains Only `[mypy]` Compat

`setup.cfg` with a lone `[mypy]` section confuses some IDE and tool versions that read both `setup.cfg` and `pyproject.toml`. Not a functional bug but unnecessary complexity.

---

### 🔵 #54 — `test_api_contract.py:24` Stale Comment Says "9 SolverStatus Members"

```python
# 2. SolverStatus — exact 9 members, wire values, iteration order.
```
The actual `_EXPECTED_SOLVER_STATUS_ORDERED` snapshot has 10 entries (added `GOVERNANCE_BLOCKED`). Comment drifted and was never updated.

---

# PART 5 — DOCUMENTATION FLAWS

### 🟡 #55 — `DistributedCircuitBreaker` Docstring Says "Defaults to InMemoryDistributedBackend" — False

**File**: `src/pramanix/circuit_breaker.py:622-634`

Docstring says it defaults to `InMemoryDistributedBackend`. Code raises `ConfigurationError` if `backend=None`. Active lie in documentation.

---

### 🟡 #56 — `redundant.py` Module Warning Not Propagated to Top-Level `__all__`

**File**: `src/pramanix/translator/redundant.py:8`
```python
.. warning:: **EXPERIMENTAL** — stability level ``"experimental"``.
```
This module is marked experimental in its own docstring but `RedundantTranslator` and `extract_with_consensus` are exported in `pramanix.__all__` without any stability annotation. Users relying on `import pramanix; pramanix.RedundantTranslator` see no indication that this is experimental.

---

### 🔵 #57 — `RELEASE_READINESS.md:A4` Still Says "9 members" in an Evidence Column

**File**: `docs/RELEASE_READINESS.md`
```
| A4 | SolverStatus has 10 members | ✅ | ... test comment says "9" — stale...
```
The evidence column notes the stale comment but the description was updated to "10 members" in the last audit session. Minor remaining inconsistency in the notes.

---

# PART 6 — REMAINING EDGE-CASE FLAWS

### 🟡 #58 — `execution_token.py:903-912` — `False` Return Conflates Two Different Failure Modes

`RedisExecutionTokenVerifier.consume()` returns `False` for both:
1. Token already consumed (legitimate denial)
2. Redis connectivity error (infrastructure failure)

The ERROR log distinguishes them, but the API contract (`bool` return) does not. Callers who check only the return value cannot distinguish "replay attack blocked" from "Redis is down."

---

### 🟡 #59 — `key_provider.py:543-545, 657-660` — `except Exception: raise` Hides Version Rollback Logic

**File**: `src/pramanix/key_provider.py:543-545`
```python
except Exception:
    self._secret_version = _pinned  # restore on failure
    raise
```
While the version rollback is correct, the bare `except Exception:` catches ALL exceptions including `SystemExit` and `KeyboardInterrupt`. The version will be restored before propagating these signals, which may cause confusion in shutdown scenarios.

---

### 🟡 #60 — `helpers/compliance.py` — `ComplianceReporter` PDF Generation Undocumented for Real Usage

**File**: `src/pramanix/helpers/compliance.py`

`ComplianceReporter` generates PDF compliance reports via `fpdf2`. No examples, no test of the actual PDF output format, no documentation of what a compliant report looks like to an auditor. The `pramanix report` CLI subcommand exists but its output has never been reviewed by a compliance professional.

---

### 🟡 #61 — `integrations/fastapi.py:171` — Overly Broad `except Exception` for Intent Validation

```python
except Exception as exc:
    _log.warning("pramanix.fastapi.intent_validation_error: %s", exc, exc_info=True)
    return JSONResponse(status_code=422, content={"detail": "Intent validation failed."})
```
`except Exception` catches Pydantic `ValidationError` (expected) AND `MemoryError`, `RecursionError`, etc. (unexpected). All produce the same 422 response. Infrastructure failures in validation are indistinguishable from schema violations.

---

### 🟡 #62 — `integrations/llamaindex.py:211` — Same Overly Broad Exception for Intent Validation

```python
except Exception as exc:
    return ToolOutput(content=f"Pramanix: invalid input: {exc}", ...)
```
Same issue — `MemoryError` and Pydantic `ValidationError` both produce "invalid input" ToolOutput. Infrastructure failures masked as input errors.

---

### 🔵 #63 — `_inc_send_error_metric()` Logs at DEBUG vs WARNING Inconsistency

`_increment_overflow_counter()` logs at WARNING on failure.
`_increment_send_error_metric()` logs at DEBUG on failure.
These two increment helpers in the same file use different log levels for equivalent failure modes, creating an inconsistent observability surface.

---

### 🔵 #64 — `key_provider.py` — `_ALLOWED_KEY_SIZES` Not Checked at Construction for `AzureKeyVaultKeyProvider`

Azure and GCP key providers cache keys but don't validate key length at cache-refresh time. A Vault returning a 16-byte key (too short for Ed25519) would be cached and later fail at signing time with a cryptography library error rather than a clear `ConfigurationError` at refresh time.

---

### 🔵 #65 — `ci.yml` — No Explicit Python 3.11/3.12 `pyproject.toml` Classifier Verification

CI declares Python 3.13 only but `pyproject.toml` lists 3.11, 3.12, 3.13 classifiers. No CI gate verifies that the declared classifiers match tested versions. PyPI will show "Python 3.11 Compatible" for a package that was never tested on 3.11.

---

### 🔵 #66 — `natural_policy/verifier.py` — MetaVerifier Semantic Distance Threshold Has No Bounds

`MetaVerifier` accepts a `semantic_threshold` parameter with no validation bounds. Passing `semantic_threshold=0.0` disables all semantic checking (everything passes). Passing `semantic_threshold=1.0` rejects everything. Neither extreme emits a warning.

---

### 🔵 #67 — `helpers/policy_auditor.py` — Static Coverage Analysis Has No Integration Test

`PolicyAuditor` performs static field coverage analysis on policies. It has unit tests but no integration test verifying it produces correct output on a realistic multi-mixin policy with inherited invariants. The auditor's invariant-label collection logic may miss inherited labels.

---

# SUMMARY TABLE

| # | Severity | Category | File | Finding |
| - | -------- | -------- | ---- | ------- |
| 6 | 🟠 | Mock | 31 test files | 147 `monkeypatch.setattr` replacing real functions |
| 7 | 🟠 | Fake | Multiple test files | Private attribute mutations bypassing API |
| 8 | 🟠 | Fake | `test_kms_provider.py` etc. | Azure/GCP/Vault tested against duck-typed stubs only |
| 9 | 🟠 | Fake | `test_translator.py` | 1,140 lines, zero real API calls |
| 10 | 🟠 | Test | All property test files | `deadline=None` on every property test |
| 11 | 🟠 | Test | `test_sanitise_properties.py` | `suppress_health_check=[HealthCheck.too_slow]` |
| 12 | 🟡 | Test | `test_fintech_primitive_properties.py:215` | `assume(peak >= current)` — abnormal regime excluded |
| 13 | 🟡 | Test | `test_translator_and_interceptor_paths.py:677` | `del sys.modules[...]` without restore |
| 17 | 🟠 | Silent | `audit_sink.py:247` | Send error metric failure logged at DEBUG only |
| 18 | 🟠 | Silent | `integrations/langgraph.py:59-60` | Prometheus metrics setup failure at DEBUG only |
| 19 | 🟠 | Silent | `integrations/semantic_kernel.py:104` | Guard errors and policy violations indistinguishable to caller |
| 20 | 🟠 | Design | `execution_token.py:936-940` | `consumed_count()` fails open — returns 0 on Redis error |
| 21 | 🟡 | Design | `execution_token.py:1071` | `asyncio.run()` fallback crashes if called from async context |
| 22 | 🟡 | Design | `provenance.py:107-112` | Invalid `PRAMANIX_PROVENANCE_KEY` silently falls to ephemeral |
| 23 | 🟡 | Design | `key_provider.py:369,483,605` | Cloud providers raise `RuntimeError` not typed Pramanix exceptions |
| 24 | 🟡 | Design | `mesh/authenticator.py:510-513` | JWKS thundering herd on refresh failure — no backoff |
| 25 | 🟡 | Design | `mesh/authenticator.py:548` | Synchronous `httpx.get()` blocks event loop in async context |
| 26 | 🟡 | Design | `integrations/crewai.py:175` | Guard error and policy violation indistinguishable in CrewAI |
| 27 | 🟡 | Design | `audit/merkle.py:228` | Atexit flush silently suppressed — last batch of decisions lost on failure |
| 28 | 🔵 | Design | `guard_pipeline.py:94-98` | WARNING logs don't include policy name/invariant label |
| 31 | 🔴 | Arch | `oversight/workflow.py` | No persistent `ApprovalWorkflow` — SOC2 CC6.3 cannot be satisfied |
| 32 | 🟠 | Arch | `lifecycle/diff.py:298` | `ShadowEvaluator` with `max_history=None` — unbounded memory |
| 33 | 🟠 | Arch | `circuit_breaker.py:622` | Stale docstring lies about `backend` default behavior |
| 34 | 🟠 | Arch | `audit/archiver.py` | Merkle archive plaintext default — no production warning |
| 35 | 🟠 | Arch | `audit/merkle.py` | Merkle inclusion proofs break after process restart |
| 36 | 🟠 | Arch | `nlp/validators.py` | `SemanticSimilarityGuard` uses TF-IDF not embeddings — name misleads |
| 37 | 🟠 | Arch | `nlp/validators.py` | `ToxicityScorer` is keyword density ratio — name misleads |
| 38 | 🟠 | Arch | `primitives/healthcare.py` | Clinically critical constraints not clinically validated |
| 39 | 🟡 | Arch | `guard.py:_apply_governance_gates` | Privilege gate silently skipped if no `"tool"` key |
| 40 | 🟡 | Arch | `lifecycle/diff.py` | `PolicyDiff` structural-only — semantically equivalent = "changed" |
| 41 | 🟡 | Arch | `natural_policy/yaml_loader.py` | YAML DSL undocumented subset — `ForAll`/`Exists` silently unsupported |
| 42 | 🟡 | Arch | `pyproject.toml:47` | `z3-solver ^4.12` — no cross-minor-version compatibility test |
| 43 | 🟡 | Arch | `natural_policy/compiler.py` | `MetaVerifier` threshold unvalidated hyperparameter |
| 44 | 🟡 | Arch | `resolvers.py` | `ResolverRegistry` unsafe under Python 3.13 `--disable-gil` |
| 45 | 🟡 | Arch | `integrations/haystack.py:79` | `block_on_error=False` is fail-open for guard infrastructure errors |
| 46 | 🟡 | Arch | `worker.py:397-479` | Worker warmup hardcoded 8 patterns — policy-specific paths cold-start |
| 47 | 🔵 | Config | `pyproject.toml:124` | `security = ["google-re2"]` extra is redundant — RE2 always installed |
| 48 | 🟠 | CI | `ci.yml:418` | `continue-on-error: true` on Trivy SARIF upload — silent failure |
| 49 | 🟠 | CI | `ci.yml` matrix | Python 3.11/3.12 claimed but never CI-tested |
| 50 | 🟠 | CI | `ci.yml` benchmark | Microbenchmark P99=3.3ms; real sustained P99=30.5ms — gates different things |
| 51 | 🟡 | CI | `ci.yml` coverage | Integration tests excluded from 98% coverage measurement |
| 52 | 🟡 | Config | `audit/signer.py`, `crypto.py` | Duplicate `_inc_signing_failure` implementation in two modules |
| 53 | 🔵 | Config | `setup.cfg` | Stale file with only `[mypy]` compat — potential tool confusion |
| 54 | 🔵 | Docs | `test_api_contract.py:24` | Stale comment says "9 SolverStatus members" — actual is 10 |
| 55 | 🟡 | Docs | `circuit_breaker.py:622` | Docstring says "defaults to InMemoryDistributedBackend" — false |
| 56 | 🟡 | Docs | `translator/redundant.py:8` | "EXPERIMENTAL" warning not visible in `pramanix.__all__` |
| 57 | 🔵 | Docs | `RELEASE_READINESS.md` | Minor note inconsistency in A4 evidence column |
| 58 | 🟡 | API | `execution_token.py:903-912` | `False` return conflates "already consumed" and "Redis down" |
| 59 | 🟡 | Design | `key_provider.py:543-545` | `except Exception:` catches `SystemExit` during version rollback |
| 60 | 🟡 | Design | `helpers/compliance.py` | PDF compliance reports never reviewed by compliance professional |
| 61 | 🟡 | Design | `integrations/fastapi.py:171` | `except Exception` conflates schema errors and infrastructure failures |
| 62 | 🟡 | Design | `integrations/llamaindex.py:211` | Same broad catch makes MemoryError look like invalid input |
| 63 | 🔵 | Design | `audit_sink.py` | Overflow counter uses WARNING; send-error counter uses DEBUG — inconsistent |
| 64 | 🔵 | Design | `key_provider.py` | Short keys from Azure/GCP Vault not validated at cache-refresh time |
| 65 | 🔵 | CI | `ci.yml` | No CI gate verifies classifier versions match tested Python versions |
| 66 | 🔵 | Design | `natural_policy/verifier.py` | `MetaVerifier` threshold has no bounds — `0.0` disables all checks silently |
| 67 | 🔵 | Test | `helpers/policy_auditor.py` | Static coverage analysis has no integration test |

---

## FALSE CLAIMS IN PRIOR AUDITS

| Prior Claim | Reality |
| ----------- | ------- |
| "Zero `unittest.mock.patch`/`MagicMock`/`AsyncMock` in the test suite" | **FALSE** — 21 files use these |
| "No `__new__()` constructor bypasses" | **FALSE** — Found in 7 test files |
| "The codebase is forensically clean with no flaws" | **FALSE** — 67 confirmed findings |
| "All exception handlers are justified and logged" | **FALSE** — `_inc_send_error_metric` at DEBUG; signing returns `""` |
| "DistributedCircuitBreaker docstring is current" | **FALSE** — Stale, says opposite of actual behavior |
| "`SemanticSimilarityGuard` uses semantic embeddings" | **MISLEADING** — Uses TF-IDF bag-of-words |
| "`ToxicityScorer` is an ML toxicity scorer" | **MISLEADING** — Keyword density ratio |
| "No silent signing failures" | **FALSE** — All three signers return `""` on any exception |

---

## PART 7 — DEEP AUDIT: SECOND PASS (2026-06-04)

> Second-pass full read of transpiler, solver, policy, guard, worker, audit, circuit_breaker,
> execution_token, primitives, integrations, oversight, mesh, lifecycle, and natural_policy modules.
> Findings #68–#116 are new; #73 was investigated and found non-buggy (Merkle padding is consistent).

---

## 7.1 Transpiler / Solver / Policy — Logic Errors

### 🟠 #74 — `execution_token.py:903-916` — `False` Return on Redis Error vs. Replay Cannot Be Distinguished by Callers

**File**: `src/pramanix/execution_token.py:903-916`

`RedisExecutionTokenVerifier.consume()` returns `False` for both "token already consumed" and "Redis connectivity error." The docstring explicitly warns callers must not fall back to in-memory on Redis failure, but the return type is just `bool`. A caller implementing retry-on-transient-failure would retry a Redis error (correct) but would also retry a replay (wrong — token is gone). The API contract is violated: operators cannot implement safe retry logic without re-reading ERROR logs to distinguish the two cases.

---

### 🟠 #75 — `transpiler.py:577-583` — `_PowOp(exp=0)` Returns the Variable, Not Constant 1

**File**: `src/pramanix/transpiler.py:577-583`
```python
result: z3.ArithRef = z_base
for _ in range(e - 1):
    result = cast("z3.ArithRef", result * z_base)
return cast("z3.ExprRef", result)
```
`exp=0` → `range(-1)` → zero iterations → returns `z_base` instead of `z3.IntVal(1)`. `x**0` silently becomes `x` in the Z3 formula. `expressions.py` is documented to enforce `n ≤ 4` but NOT `n ≥ 1`. If that lower bound is ever weakened (or if a policy is crafted via YAML DSL that bypasses expressions.py), `x**0` produces a semantically wrong constraint without any error.

---

### 🟠 #76 — `solver.py` — Free Variables from Missing Fields Can Produce Spurious `sat`

**File**: `src/pramanix/solver.py:354-356`

Bindings for missing fields are never added to the solver. Z3 will freely assign any value to an unconstrained variable and return `sat`. The field-presence pre-check in `_verify_core` should catch this case, but the check only validates top-level policy field names — expanded array element names (`amounts_0`, `amounts_1`) are added by `_preprocess_invariants` and are not in the original `_compiled_meta` field list. If an invariant references `amounts_0` but the user does not provide `amounts`, that array element gets a free Z3 variable and a spurious `sat` result is possible.

---

### 🟠 #77 — `policy.py:554-555` — `_DYNAMIC_POLICY_CACHE` LRU Eviction Causes Repeated Class Allocation for Identical Schemas

**File**: `src/pramanix/policy.py:554-555`

`from_config` caches dynamic policy classes keyed by `(fields_key, tuple(invariants))` — invariant function objects by identity. When an entry is evicted from the 256-slot LRU, the lambda functions it holds are freed. The next call with the same schema creates NEW lambdas (new identity), gets a cache miss, and creates a new class. For multi-tenant workloads cycling through many schema configurations, this creates unbounded class allocation and Python type-system pressure within the LRU window.

---

### 🟠 #78 — `guard.py:1357-1359` — `mode="sync"` Path in `verify_async` Does Not Apply `min_response_ms` Timing Pad

**File**: `src/pramanix/guard.py:1357-1359`

For `execution_mode="sync"`, `verify_async` calls `asyncio.to_thread(self.verify, ...)` and returns directly without going through the `_timed()` helper that applies `min_response_ms`. The synchronous `verify()` applies its own timing pad. But when called via `asyncio.to_thread`, the thread runs timing-padded and returns after the pad, while `_timed()` on the async side is NOT called. If `min_response_ms` in the async config differs from the sync pad, or if `_timed` does something beyond padding (e.g., emitting metrics), that behaviour is missing on the sync-mode async path. An observer can distinguish sync-mode calls from thread-mode calls by response time distribution.

---

### 🟠 #79 — `guard.py:1519-1531` — `CancelledError` Inside `_timed()` Called From `except` Block Silently Skips Audit Sink Emission

**File**: `src/pramanix/guard.py:1519-1531`

`_timed()` calls `await asyncio.sleep(_left)` which raises `asyncio.CancelledError` on task cancellation. `CancelledError` is a `BaseException`, not caught by `except Exception`. If cancellation occurs while `_timed()` is executing inside one of the `except` handlers (e.g., `except ValidationError`), the `CancelledError` propagates out of the entire `try/except/finally` block. The `finally` block runs (`_resolver_registry.clear_cache()`), but `_emit_to_sinks` — which is called INSIDE `_timed()` — never executes. The audit trail has a gap: the decision was computed but never logged.

---

### 🟠 #80 — `integrations/langchain.py:149-157` — Hardcoded 30-Second Timeout in `_run()` Ignores GuardConfig `solver_timeout_ms`

**File**: `src/pramanix/integrations/langchain.py:149-157`
```python
return str(future.result(timeout=30))
```
The sync `_run()` path blocks the calling thread for up to 30 seconds regardless of `GuardConfig.solver_timeout_ms`. A guard with `solver_timeout_ms=1000` (1 second) will still block for 30 seconds on the timeout path. The timeout is hardcoded and not configurable.

---

### 🟠 #81 — `worker.py:981-986` — Worker Warmup Awaits All Slots Sequentially — Blocks `Guard.__init__` for Up to `N×30s`

**File**: `src/pramanix/worker.py:981-986`

`_run_warmup()` awaits each warmup future with `fut.result(timeout=30.0)` in a sequential loop. With `max_workers=8`, Guard construction can block for up to 240 seconds if warmup stalls. Cloud environments with strict health-check startup deadlines will timeout and restart the service. Warmup should be submitted fire-and-forget or awaited with a total (not per-slot) timeout.

---

### 🟠 #84 — `primitives/fintech.py:169-204` — `WashSaleDetection` Uses Fixed 86,400-Second Windows, Not Calendar Days

**File**: `src/pramanix/primitives/fintech.py:169-204`

IRC § 1091 uses calendar days. `30 * 86_400` seconds is not always 30 calendar days: DST transitions and timezone ambiguity mean the same calendar day pair can be either inside or outside the 30 × 86400-second window depending on timezone. The primitive's regulatory mapping to IRC § 1091 implies calendar-day compliance that the UTC-epoch implementation does not provide.

---

### 🟠 #85 — `translator/redundant.py:429-431` — Non-Critical Extra Fields Injected by Compromised Model Flow Into Decision Record Unchecked

**File**: `src/pramanix/translator/redundant.py:429-431`

In `lenient` mode with `critical_fields` specified, extra fields injected by one model that are not in `critical_fields` are logged but NOT blocked. They flow into `intent_dump` in the `Decision` record with attacker-controlled values. While Z3 ignores extra keys in `values`, the audit trail logs these tampered fields as if they were verified intent.

---

### 🟠 #86 — `mesh/authenticator.py:481-519` — JWKS Cold Cache Allows Concurrent Duplicate Fetches Despite Documentation Claiming Prevention

**File**: `src/pramanix/mesh/authenticator.py:481-519`

The comment says "Prevents concurrent threads from issuing duplicate JWKS fetches." This is only true when stale keys exist. On cold start (no keys), `self._jwks_fetching=True and self._jwks_cache.keys==[]` evaluates as `True and []` = `False`, so both Thread A and Thread B proceed to fetch. The comment is false for the cold-start case. Additionally, no backoff is applied after a failed fetch — the `_jwks_fetching` flag is reset to `False` and all subsequent requests retry immediately (already noted as thundering herd in #24, but the cold-start aspect is a distinct and separately undocumented issue).

---

### 🟠 #87 — `mesh/authenticator.py:547-548` — No Guard Against Direct `authenticate_and_bind()` Call From Async Context

**File**: `src/pramanix/mesh/authenticator.py:547-548`

The async variant `authenticate_and_bind_async` offloads the synchronous JWKS HTTP fetch to a thread. But if a developer calls `authenticate_and_bind` (sync) directly from a coroutine, it blocks the event loop. There is no runtime guard (no `asyncio.get_running_loop()` check) in `authenticate_and_bind` to reject or warn on async misuse. The only protection is documentation, which is insufficient.

---

### 🟠 #88 — `lifecycle/diff.py:330-366` — `ShadowEvaluator.record()` Docstring Claims "Non-Blocking" — False for Synchronous Path

**File**: `src/pramanix/lifecycle/diff.py:330-366`

The docstring says "Shadow evaluation is non-blocking — shadow verify() runs after the live decision is produced so it can never delay the caller." This is false. `record()` calls `self._shadow.verify()` synchronously on the calling thread. A slow shadow policy (500ms Z3 solve) blocks the caller for 500ms after the live decision. Only `arecord()` is genuinely non-blocking. The "non-blocking" claim in the sync variant's docstring is a lie.

---

## 7.3 Cache / Memory / Threading Issues

### 🟡 #89 — `transpiler.py:883-884` — `InvariantASTCache` Keyed on `id(policy_cls)` — Stale Entry on GC + ID Reuse

**File**: `src/pramanix/transpiler.py:883-884`
```python
_cache: ClassVar[dict[tuple[int, str], list[InvariantMeta]]] = {}
```
Cache key is `(id(policy_cls), schema_hash)`. Python reuses object IDs after GC. A dynamic policy class evicted from `_DYNAMIC_POLICY_CACHE` and GC'd can have its `id()` reused by a different new class. The new class gets a stale cache hit with the evicted class's compiled metadata, using wrong invariants silently for all subsequent verifications through that Guard.

---

### 🟡 #90 — `transpiler.py:881-885` — `import threading` at Class Body Level — Import-Time Side Effect and Namespace Pollution

**File**: `src/pramanix/transpiler.py:881-885`
```python
class InvariantASTCache:
    import threading as _threading
```
This executes `import threading` at class definition time (module import), creating a threading lock at class body scope. It exposes `_threading` as a class attribute, polluting the `InvariantASTCache` namespace.

---

### 🟡 #91 — `transpiler.py:897-910` — `InvariantASTCache.get()` Uses O(N) `deque.remove()` on Every Cache Hit

**File**: `src/pramanix/transpiler.py:897-910`
```python
cls._access_order.remove(key)  # O(N) scan under _lock
cls._access_order.append(key)
```
With `_max_size=512`, every cache hit performs an O(512) linear scan under `_lock`. Under high-throughput (thousands of req/s), this creates O(N) lock contention per request. A proper LRU should use `OrderedDict.move_to_end()` (O(1)) instead.

---

### 🟡 #92 — `policy.py:554-555` — Dynamic Policy Class Names Collide on Hash Collision

**File**: `src/pramanix/policy.py:554-555`
```python
schema_hash = abs(hash(fields_key)) % 10**8
class_name = f"_DynamicPolicy_{schema_hash:08d}"
```
At most 100 million distinct class names. Hash collisions produce two policies with the same class name, creating confusing logs and stack traces in incident response.

---

### 🟡 #93 — `guard.py:560-563` — `policy.invariants()` Called Twice During `Guard.__init__` — Mixin Side Effects Execute Twice

**File**: `src/pramanix/guard.py:560-563`

`policy.invariants()` is called once in `policy.validate()` and again to build `_inv_labels`. For policies with mixin functions, mixin evaluation runs twice. If any mixin has side effects (DB query, network call), they execute twice per Guard construction.

---

### 🟡 #94 — `guard.py:546-556` — `_InvariantASTCache` Keyed on Field Schema Only — Invariant Changes With Same Fields Get Stale Cache

**File**: `src/pramanix/guard.py:546-556`

`_schema_hash` covers only `export_json_schema()` (field declarations). If a policy class is monkey-patched (e.g., mixins are added after first compilation), the field schema is unchanged but `invariants()` returns different constraints. The cache returns the stale compiled metadata — wrong invariants are used silently.

---

### 🟡 #95 — `guard.py:1147-1153` — `policy.invariants()` Called on Every `verify()` — Expression Tree Rebuilt Every Request

**File**: `src/pramanix/guard.py:1147-1153`

`policy.invariants()` is not cached at the Guard level. Every `verify()` call recreates the expression tree and re-runs `_preprocess_invariants` and `analyze_string_promotions`. For high-throughput deployments, this creates garbage pressure from repeated expression object instantiation.

---

### 🟡 #96 — `worker.py:998-1018` — Recycled Worker Pool Not Warmed Up — First Requests Hit Cold Z3

**File**: `src/pramanix/worker.py:998-1018`

`_recycle()` creates a new `ThreadPoolExecutor`/`ProcessPoolExecutor` but does NOT call `_run_warmup()`. The new workers have cold Z3 JIT, causing a latency spike on the first requests after every recycle. Only the initial `spawn()` call runs warmup.

---

### 🟡 #97 — `audit/signer.py:210+` — `DecisionSigner._canonicalize` Signs Only 7 of 17 Decision Fields — 10 Fields Are Unsigned

**File**: `src/pramanix/audit/signer.py:210+`

`_canonicalize` hardcodes 7 fields: `decision_id`, `allowed`, `explanation`, `policy_hash`, `solver_time_ms`, `status`, `violated_invariants`. The Decision wire format now has 17 keys. The unsigned 10 include `intent_dump`, `state_dump`, `error_domain`, `stack_trace_hash`, and others. An attacker who can tamper with the unsigned fields gets a valid HMAC signature over the 7-field subset while audit logs contain tampered intent/state data. The signature gives a false sense of integrity for the full decision record.

---

## 7.4 Resource Leaks and Lifecycle Issues

### 🟡 #98 — `execution_token.py:564-566` — `SQLiteExecutionTokenVerifier.close()` Not Idempotent — Double-Close Raises Exception

**File**: `src/pramanix/execution_token.py:564-566`

`close()` calls `self._conn.close()` — SQLite raises `ProgrammingError` if called twice. If `close()` is called after an already-closed connection (e.g., from a `finally` block that runs after an earlier explicit `close()`), the exception propagates. No idempotency guard.

---

### 🟡 #99 — `execution_token.py:1044-1047` — `PostgresExecutionTokenVerifier` Leaks Background Thread + Event Loop on Construction Failure

**File**: `src/pramanix/execution_token.py:1044-1047`

If `asyncpg.create_pool()` fails during `__init__`, the background event loop thread (`self._loop_thread`) is already started and continues running indefinitely. No `self._loop.stop()` is called in the error path. Each failed construction leaks one daemon thread and one `asyncio` event loop.

---

### 🟡 #100 — `circuit_breaker.py:808` — `DistributedCircuitBreaker.reset()` Calls Synchronous `backend.clear()` — Non-Existent on `RedisDistributedBackend`

**File**: `src/pramanix/circuit_breaker.py:808`
```python
self._backend.clear(self._config.namespace)
```
`RedisDistributedBackend` has no synchronous `clear()` method. Calling `reset()` on a Redis-backed `DistributedCircuitBreaker` raises `AttributeError`. Meanwhile, `self._local_state` has been set to `CLOSED`, leaving the local replica in an inconsistent state while all other replicas still see the old distributed state.

---

### 🟡 #101 — `primitives/fintech.py:225-234` — `Decimal * ExpressionNode` Multiplication Depends on Unverified `__rmul__` Implementation

**File**: `src/pramanix/primitives/fintech.py:225-234`

`E(collateral_value) * (Decimal("1") - haircut_pct)` and similar constant-multiplication patterns in `MaxDrawdown`, `MarginRequirement`, etc., rely on `ExpressionNode.__rmul__` being implemented. If `__rmul__` is absent, Python falls back to `Decimal.__mul__(ExpressionNode)` which returns `NotImplemented` and raises `TypeError` — silently breaking policy construction for all constant-multiplication primitives.

---

### 🟡 #102 — `natural_policy/yaml_loader.py:85-86` — `_ast.Not` in `_ALLOWED_NODES` But Never Handled as a Standalone Node

**File**: `src/pramanix/natural_policy/yaml_loader.py`

`_ast.Not` is a child of `_ast.UnaryOp`, not a standalone expression node. Including it in `_ALLOWED_NODES` without a handler for standalone `_ast.Not` means it can pass the allowlist gate and reach the unhandled fallback, producing a confusing `PolicySyntaxError` rather than a meaningful error about unsupported `not` expressions.

---

### 🟡 #103 — `lifecycle/diff.py` — `ShadowResult` Holds Mutable References to Live `intent`/`state` Dicts

**File**: `src/pramanix/lifecycle/diff.py`

`ShadowResult` stores references to `intent` and `state` dicts without deep-copying them. If the caller mutates these dicts after `record()` returns, the stored `ShadowResult` history is corrupted. In async or multi-threaded Guard usage, concurrent mutations create data races in the shadow history.

---

### 🟡 #104 — `helpers/compliance.py:117-133` — `intent_dump["amount"]` Defaults to `"0"` — All Non-Amount Policies Classified by Wrong Baseline

**File**: `src/pramanix/helpers/compliance.py:117-133`

`_classify_severity` uses `intent_dump.get("amount", "0")`. For policies with no `amount` field (RBAC, infrastructure), the baseline `"0"` is used, silently misclassifying all such decisions by the amount-based rule path.

---

### 🟡 #105 — `guard.py:1293-1300` — Oversized Request Rejections Not Counted in `_decisions_total` Prometheus Metric

**File**: `src/pramanix/guard.py:1293-1300`

The `max_input_bytes` size check at lines 952-989 returns BEFORE the `try` block that contains the `finally` clause emitting metrics. Oversized rejections are never counted in `_decisions_total` or observed in `_decision_latency`. Monitoring dashboards have a blind spot for all size-rejected requests.

---

## 7.5 Integration and API Contract Issues

### 🟡 #106 — `integrations/autogen.py:125-139` — `_guarded(**kwargs)` Raises `TypeError` on Positional Arguments — Not Caught as Structured Rejection

**File**: `src/pramanix/integrations/autogen.py:125-139`

`_guarded` accepts only `**kwargs`. If AutoGen calls the decorated tool with positional arguments, Python raises `TypeError` at the call site before the function body executes. This is NOT caught by the internal `try/except` around intent validation, so the error propagates as an uncaught `TypeError` rather than a structured rejection string. The decorator's documented contract ("all exceptions from validation are caught") is false for positional misuse.

---

### 🟡 #107 — `integrations/langchain.py:132-147` — `ThreadPoolExecutor(max_workers=1)` Per Tool Instance Serializes Concurrent Agent Calls

**File**: `src/pramanix/integrations/langchain.py:132-147`

Each `PramanixGuardedTool` instance creates its own single-threaded executor. With 10 tools in an agent, 10 threads are created at construction time. More critically, concurrent invocations of the same tool are serialized by the `max_workers=1` constraint — the second concurrent call waits for the first to complete, creating unintended serialization in parallel agent workflows.

---

## 7.6 Primitive Logic Errors

### 🔵 #108 — `primitives/finance.py:55-70` and `primitives/fintech.py:108` — `NonNegativeBalance` and `SufficientBalance` Duplicate the Same Constraint With Different Labels

Both encode `balance - amount >= 0` with labels `"non_negative_balance"` and `"sufficient_balance"`. A policy importing both adds redundant Z3 work and misleads compliance reporters into treating them as distinct requirements.

---

### 🔵 #109 — `guard.py:1688-1694` — `parse_and_verify` Default Model Tuple Hardcodes Specific Deprecated-Prone Model Names

**File**: `src/pramanix/guard.py:1688-1694`

```python
models: tuple[str, str] = ("gpt-4o", "claude-opus-4-7"),
```

Model names are time-sensitive. When OpenAI or Anthropic deprecates these model IDs, all deployments relying on the default will fail with API errors or silently use successor models with different semantics.

---

### 🔵 #110 — `primitives/rbac.py:40-57` — Docstring Example Shows `Field("role", str, "Int")` — Incorrect Typing That Causes Runtime `FieldTypeError`

**File**: `src/pramanix/primitives/rbac.py`

The docstring example declares `python_type=str` with `z3_type="Int"`. Passing a string role value (e.g., `"doctor"`) to an Int-sorted field raises `FieldTypeError`. The correct pattern is `Field("role", int, "Int")`. Users copying the example hit a runtime error.

---

### 🔵 #111 — `guard.py:592-638` — Redacted Decision's `decision_hash` Computed Over Real Fields, Not Redacted Fields — External Verifiers Always Fail

**File**: `src/pramanix/guard.py:592-638`

When `redact_violations=True` and `signer=None`, `decision_hash` is computed from the full unredacted fields, then `explanation` and `violated_invariants` are replaced. The returned decision shows redacted fields with a hash that does not match them. External verifiers who recompute `decision_hash` from the visible record always get a mismatch.

---

### 🔵 #112 — `translator/redundant.py:455-464` — Post-Consensus Injection Scorer Runs on Original Unsanitised `text`, Not on LLM-Sent `sanitised_text`

**File**: `src/pramanix/translator/redundant.py:455-464`

The injection scorer runs on the original `text`, while the LLM received `sanitised_text`. Injections removed by NFKC normalisation produce false positives in the scorer (blocking legitimate requests) while the sanitised text sent to the LLM was already safe. The security pipeline operates on two different versions of the same input.

---

### 🔵 #113 — `primitives/fintech.py:395-423` — `MarginRequirement` Accepts `min_margin_pct=0` — Zero Margin Is a No-Op Constraint

**File**: `src/pramanix/primitives/fintech.py:395-423`

`min_margin_pct=0` produces `equity >= 0` — a trivially-satisfied constraint that never blocks. No validation that `min_margin_pct > 0`. An operator who sets zero margin (e.g., by mistake or as a test value) gets a silent no-op.

---

### 🔵 #114 — `oversight/workflow.py:477-519` — `InMemoryApprovalWorkflow` Background Sweeper Thread Has No Public `stop()` API — Test Suite Leaks Threads

**File**: `src/pramanix/oversight/workflow.py:477-519`

The sweeper thread is started as `daemon=True` in `__init__` with no public `stop()` or `shutdown()` method. Test suites that create many `InMemoryApprovalWorkflow` instances (per-test fixture) leak one sweeper thread per test until process exit.

---

### 🔵 #115 — `execution_token.py:327-333` — `ExecutionTokenVerifier` Emits `WARNING` Log on Every Instantiation — Log Noise in Correct Single-Process Deployments

**File**: `src/pramanix/execution_token.py:327-333`

The WARNING about "in-memory only" fires even in correctly-configured single-process deployments. Users of `InMemoryExecutionTokenVerifier` (the explicit in-memory subclass) receive both this WARNING and the subclass's `UserWarning` — double-warning on legitimate usage, degrading log signal quality.

---

### 🔵 #116 — `worker.py:625-645` — `_unseal_decision` Nonce `compare_digest` Raises `TypeError` on `bytes` vs `str` Mismatch — Not Caught as `ValueError`

**File**: `src/pramanix/worker.py:625-645`

`hmac.compare_digest(sealed.get("_n", ""), expected_nonce)` requires both arguments to be the same type. If `sealed["_n"]` is `bytes` (e.g., from a msgpack-encoded backend), `compare_digest(bytes, str)` raises `TypeError`. The `TypeError` is not caught by `except (ValueError, KeyError)` handlers in the call chain, producing a confusing error message instead of the clear "Decision replay detected" message.

---

## UPDATED SUMMARY TABLE (Findings #68–#116)

| # | Severity | Category | File | Finding |
| - | -------- | -------- | ---- | ------- |
| 74 | 🟠 | API | `execution_token.py:903` | `False` return conflates Redis error with replay — callers cannot implement safe retry |
| 75 | 🟠 | Logic | `transpiler.py:577-583` | `_PowOp(exp=0)` returns variable instead of constant 1 |
| 76 | 🟠 | Logic | `solver.py:354-356` | Missing array element bindings → free Z3 variables → spurious `sat` |
| 77 | 🟠 | Memory | `policy.py:554-555` | Dynamic policy LRU eviction causes class allocation per identical schema |
| 78 | 🟠 | Timing | `guard.py:1357-1359` | `mode="sync"` in `verify_async` skips `min_response_ms` timing pad |
| 79 | 🟠 | Audit | `guard.py:1519-1531` | `CancelledError` in `_timed()` during except handler skips `_emit_to_sinks` |
| 80 | 🟠 | Design | `integrations/langchain.py:149` | Hardcoded 30s timeout ignores `GuardConfig.solver_timeout_ms` |
| 81 | 🟠 | Design | `worker.py:981-986` | Warmup awaits slots sequentially — blocks `Guard.__init__` up to N×30s |
| 84 | 🟠 | Compliance | `primitives/fintech.py:169` | `WashSaleDetection` uses seconds, not calendar days — IRC §1091 gap |
| 85 | 🟠 | Security | `translator/redundant.py:429` | Non-critical extra injected fields flow into audit `intent_dump` unchecked |
| 86 | 🟠 | Design | `mesh/authenticator.py:481` | JWKS cold-cache thundering herd — comment claims prevention, is false |
| 87 | 🟠 | Design | `mesh/authenticator.py:547` | No guard against `authenticate_and_bind()` called from async context |
| 88 | 🟠 | Docs | `lifecycle/diff.py:330` | `record()` docstring claims "non-blocking" — false, runs synchronously |
| 89 | 🟡 | Cache | `transpiler.py:883` | `InvariantASTCache` keyed on `id()` — stale cache hit on GC+ID reuse |
| 90 | 🟡 | Style | `transpiler.py:881` | `import threading` at class body level — import-time side effect |
| 91 | 🟡 | Perf | `transpiler.py:897` | `deque.remove()` is O(N) under lock per cache hit — LRU should use `OrderedDict` |
| 92 | 🟡 | Observ | `policy.py:554` | Dynamic policy class names collide on hash collision — confusing logs |
| 93 | 🟡 | Perf | `guard.py:560` | `policy.invariants()` called twice in `Guard.__init__` — mixin side effects run twice |
| 94 | 🟡 | Cache | `guard.py:546` | `_InvariantASTCache` hash covers fields only — invariant mutations use stale cache |
| 95 | 🟡 | Perf | `guard.py:1147` | `policy.invariants()` called every `verify()` — expression tree rebuilt each request |
| 96 | 🟡 | Perf | `worker.py:998` | Recycled worker pool not warmed up — first requests hit cold Z3 after recycle |
| 97 | 🟡 | Security | `audit/signer.py:210` | `_canonicalize` signs only 7 of 17 Decision fields — 10 unsigned including `intent_dump` |
| 98 | 🟡 | Design | `execution_token.py:564` | `SQLiteExecutionTokenVerifier.close()` not idempotent — double-close raises |
| 99 | 🟡 | Leak | `execution_token.py:1044` | `PostgresExecutionTokenVerifier` leaks thread+event loop on construction failure |
| 100 | 🟡 | Design | `circuit_breaker.py:808` | `reset()` calls synchronous `backend.clear()` — non-existent on `RedisDistributedBackend` |
| 101 | 🟡 | Logic | `primitives/fintech.py:225` | `Decimal * ExpressionNode` depends on unverified `__rmul__` — silent `TypeError` |
| 102 | 🟡 | Design | `natural_policy/yaml_loader.py` | `_ast.Not` in allowlist but never handled — passes gate, hits unhandled fallback |
| 103 | 🟡 | Race | `lifecycle/diff.py` | `ShadowResult` stores mutable dict references — concurrent mutation corrupts history |
| 104 | 🟡 | Logic | `helpers/compliance.py:117` | Non-amount policies classified with `"0"` amount baseline |
| 105 | 🟡 | Observ | `guard.py:1293` | Oversized request rejections not counted in `_decisions_total` Prometheus metric |
| 106 | 🟡 | Design | `integrations/autogen.py:125` | `_guarded(**kwargs)` raises `TypeError` on positional args — not caught as structured rejection |
| 107 | 🟡 | Perf | `integrations/langchain.py:132` | `ThreadPoolExecutor(max_workers=1)` per tool — serializes concurrent agent calls |
| 108 | 🔵 | Design | `primitives/finance.py:55` | `NonNegativeBalance` and `SufficientBalance` duplicate same constraint — redundant Z3 work |
| 109 | 🔵 | Design | `guard.py:1688` | Default model tuple hardcodes `"claude-opus-4-7"` — will break on deprecation |
| 110 | 🔵 | Docs | `primitives/rbac.py:40` | Docstring example `Field("role", str, "Int")` causes `FieldTypeError` at runtime |
| 111 | 🔵 | Design | `guard.py:592` | Redacted decision's `decision_hash` computed over unredacted fields — verifiers always fail |
| 112 | 🔵 | Design | `translator/redundant.py:455` | Injection scorer runs on original `text`, LLM received `sanitised_text` — inconsistency |
| 113 | 🔵 | Design | `primitives/fintech.py:395` | `MarginRequirement(min_margin_pct=0)` produces trivially-satisfied no-op constraint |
| 114 | 🔵 | Leak | `oversight/workflow.py:477` | `InMemoryApprovalWorkflow` sweeper thread leaks in test suites — no `stop()` API |
| 115 | 🔵 | Observ | `execution_token.py:327` | `ExecutionTokenVerifier` emits WARNING on every instantiation — log noise in valid deployments |
| 116 | 🔵 | Design | `worker.py:625` | `compare_digest(bytes, str)` raises `TypeError` — not caught as `ValueError` |

---

*116 total findings (67 original + 49 new from second-pass deep audit).*
*Second pass methodology: full file reads of transpiler.py, solver.py, policy.py, guard.py, worker.py,*
*audit/signer.py, circuit_breaker.py, execution_token.py, primitives/\*, integrations/\*,*
*oversight/workflow.py, lifecycle/diff.py, mesh/authenticator.py, natural_policy/yaml_loader.py.*
*2026-06-04.*

---

## PART 8 — INTEGRATIONS DEEP AUDIT (Third Pass, 2026-06-04)

> Full adversarial read of every integration: fastapi, llamaindex, dspy, pydantic_ai,
> semantic_kernel, haystack, crewai, autogen, langgraph, agent_orchestration.
> Angles: fail-open, timing oracles, event loop starvation, audit gaps, guard crash propagation.

### 🟠 #122 — `integrations/dspy.py:150-151` — `intent_builder`/`state_provider` Exceptions Leak Policy Field Shapes

No `try/except` around `intent_builder(**kwargs)` or `state_provider()`. `KeyError`/`TypeError` from the builder reveals the policy's expected field names to the attacker — allowing schema probing without triggering Z3 verification.

---

### 🟠 #123 — `integrations/pydantic_ai.py:160-162` — `guard_tool` Passes `intent={}` When No `intent` Kwarg Present — Vacuous-Truth Fail-Open

```python
intent: dict[str, Any] = kwargs.get("intent", {})
```

PydanticAI tools receive domain-specific kwargs, not a magic `intent=` key. Every `@validator.guard_tool`-decorated function that omits `intent=` sends `{}` to the guard. Policies with conditional invariants on optional fields may vacuously ALLOW an empty intent dict.

---

### 🟠 #124 — `integrations/crewai.py:153-155` — `_arun` Calls Synchronous `guard.verify()` on the Async Event Loop — Event Loop Starvation DoS

```python
async def _arun(self, **tool_input: Any) -> str:
    return self._execute(tool_input)   # ← calls sync guard.verify()
```

Blocks the entire async event loop for Z3 solve duration (potentially hundreds of ms). Must call `verify_async` instead.

---

### 🟠 #125 — `integrations/llamaindex.py:507-513` — New `ThreadPoolExecutor` Per `call()` Invocation — Thread Exhaustion Under Load

```python
with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
    future = pool.submit(lambda: asyncio.run(self.acall(input, **kwargs)))
```

`PramanixQueryEngineTool.call()` allocates and tears down a thread executor on every invocation. Under agent-loop load, exhausts OS thread handles. Must use a shared lifecycle-managed executor.

---

### 🟠 #126 — `integrations/haystack.py:121,176` — State Fetched Once Before Item Loop — TOCTOU on Mutable State Across Batch

State is captured once for the entire document batch and reused for all items. A policy enforcing `balance >= amount` receives the same starting balance for every document — a full batch can collectively exhaust the balance while every individual check passes the same stale state.

---

### 🟠 #128 — `integrations/agent_orchestration.py:225,239` — `_enter_times` Dict Overwritten by Concurrent Same-Node Calls, Unbounded, Leaks on Missed Exits

Keyed by `node_id` (string). Concurrent executions of the same node (parallel LangGraph branches) overwrite each other's timestamps — incorrect latency metrics. If `on_node_enter` fires without a matching `on_node_exit`, the entry is never cleaned — unbounded memory growth in long-running agents.

---

### 🟡 #129 — `integrations/semantic_kernel.py:108-114` — `redact_violations` Not Respected — Full Policy Internals Always Exposed to SK Planner

```python
return json.dumps({
    "explanation": decision.explanation,
    "violated_invariants": list(decision.violated_invariants),
})
```

`fastapi.py` checks `self._redact_violations` before exposing these fields. The SK plugin has no such check — every BLOCK exposes the exact invariant names and explanation strings to the LLM planner, enabling binary-search policy probing.

---

### 🟡 #130 — `integrations/fastapi.py:283-286` — Positional Arg Extraction Passes Non-Dict `intent` to Guard Without Type Check

```python
if intent is None and len(args) >= 1:
    intent = args[0]
```

If `args[0]` is a FastAPI `Request` or `Depends()` object, it is passed as `intent` to `verify_async`. Needs `isinstance(intent, dict)` guard.

---

### 🟡 #131 — `integrations/llamaindex.py:244-249` — `decision.status` Enum in `raw_output` Not Serialized — Latent JSON Crash

```python
"status": decision.status,     # ← SolverStatus enum, not str
```

When LlamaIndex serializes `raw_output` to JSON for the LLM context, raises `TypeError: Object of type SolverStatus is not JSON serializable`. Fix: `decision.status.value`.

---

### 🟡 #132 — `integrations/autogen.py:129-131` — `strict=True` Rejects AutoGen v0.4 Framework-Injected Kwargs — Silent Fail-Closed for All v0.4 Users

```python
intent = intent_schema.model_validate(kwargs, strict=True).model_dump()
```

AutoGen v0.4 injects `ctx`, `tool_call_id`, `_run_id` into tool kwargs. With `strict=True`, Pydantic rejects every call. Every legitimate v0.4 tool call returns a rejection string.

---

### 🟡 #133 — `integrations/pydantic_ai.py:109,131` — Guard Infrastructure Exception Propagates as Non-`GuardViolationError` — Bypasses Callers' Handler

`check()` and `check_async()` have no `try/except`. Infrastructure failures bypass `except GuardViolationError:` in caller code, potentially allowing the tool to proceed.

---

### 🟡 #134 — `integrations/haystack.py:215-219` — `@component` Registration Failure Swallowed — Component Appears Initialized But Cannot Be Used in Pipeline

```python
except Exception as exc:
    _log.warning("Haystack @component registration failed: %s", exc, exc_info=True)
```

`__init__` succeeds; failure discovered only when connecting to a pipeline at runtime. Should raise `ConfigurationError` at initialization.

---

### 🟡 #135 — `integrations/crewai.py:187-196` — `ConfigurationError` Raised Inside Agent Loop on ALLOW with No `underlying_fn` — Crashes CrewAI

`_run()` and `_arun()` have no `try/except` for `ConfigurationError`. It propagates as an unhandled exception out of the CrewAI tool, potentially causing infinite retry storms.

---

### 🔵 #137 — `integrations/llamaindex.py:160-162` — `max_workers=1` Hardcoded in `PramanixFunctionTool` Executor

Not configurable. Concurrent `call()` invocations queue on a single thread.

---

### 🔵 #138 — `integrations/dspy.py:162-164` — Custom `__call__` Bypasses DSPy `Module.__call__` Bookkeeping — Calls Invisible to Optimizer

```python
def __call__(self, **kwargs: Any) -> Any:
    return self.forward(**kwargs)   # ← bypasses DSPy Module.__call__
```

DSPy tracing and assertion mechanisms observe calls through `Module.__call__`, not direct `forward`. Guard-gated calls become invisible to DSPy's optimizer.

---

### 🔵 #139 — `integrations/pydantic_ai.py:106-108` — `state_fn()` Exception Propagates as Non-`GuardViolationError`

`self._state_fn()` called inline with no protection. Database/network failures escape `except GuardViolationError:` handlers.

---

### 🔵 #140 — `integrations/fastapi.py:142-147` — Content-Type Check Uses Substring `in` — Malformed Types Pass Gate

```python
if "application/json" not in content_type:
```

`text/html; application/json`, `x-application/json` all pass. Fix: `content_type.split(";")[0].strip().lower() != "application/json"`.

---

### 🔵 #141 — `integrations/agent_orchestration.py:357` — `AutoGenGuardAdapter` Hardcodes `state={}` — State-Dependent Policies Always See Empty State

```python
decision = self._guard.verify(intent=intent, state={})
```

Policies enforcing `balance >= amount` or `permissions contain role` receive empty state — vacuously pass or fail. `LangGraphGuardAdapter` correctly extracts state; `AutoGenGuardAdapter` does not.

---

### 🔵 #142 — `integrations/haystack.py:128-132` — `block_on_error=False` Allowed Items Audit-Invisible in Return Value

Error-allowed items flow into `allowed_docs` indistinguishably from policy-allowed items. No separate output key, no per-item tag. Operators cannot determine which items bypassed the guard due to errors.

---

### 🔵 #143 — `integrations/langgraph.py:297` — `PramanixLangGraphNode` Has `bypass_on_timeout=True` Default; `PramanixLangGraphEdge` Has No Parameter — Undocumented Asymmetry

The same policy class used in Node vs. Edge context has different timeout behavior. Operators who migrate from Edge to Node silently gain fail-open on timeout with no documentation warning.

---

## PART 9 — CORE INFRASTRUCTURE DEEP AUDIT (Third Pass, 2026-06-04)

> Full adversarial read of: crypto.py, fast_path.py, decision.py, expressions.py,
> ifc/labels.py, ifc/flow_policy.py, ifc/enforcer.py, guard_pipeline.py, provenance.py, resolvers.py.

### 🟠 #146 — `fast_path.py:112,190` — `intent.get(field) or state.get(field)` — Zero Values (`0`, `0.0`, `Decimal("0")`) Fall Through to State Field

```python
val = intent.get(field_name) or state.get(field_name)
```

`0`, `0.0`, `Decimal("0")`, and `False` are falsy. `intent={"amount": 0}` causes the `or` to fall through to `state.get("amount")`, evaluating state's value instead of intent's zero. The `negative_amount` and `exceeds_hard_cap` fast-path rules see the wrong value — a zero-amount intent bypasses these checks entirely.

---

### 🟠 #147 — `fast_path.py:48-69` — Prometheus Counter Registration Failure Silently Swallowed — No Operator Warning

```python
except Exception:
    _PARSE_FAILURE_COUNTER = False
```

On Prometheus registration failure (e.g. name collision), `_PARSE_FAILURE_COUNTER` is set to `False` with no log at WARNING or ERROR. Parse failures (malformed numeric input reaching Z3) go completely undetected in production. Compare `crypto.py` which logs a warning on the same pattern.

---

### 🟡 #152 — `crypto.py:391-411` — Timing Side-Channel: `InvalidSignature` vs `ValueError` Path Have Different Execution Times

`_b64url_decode(invalid_base64)` raises `binascii.Error` (→ `ValueError`). `_b64url_decode(valid_base64_but_wrong_ed25519_sig)` reaches `public_key.verify()` (→ `InvalidSignature`). These two failure modes have measurably different execution times, leaking whether an attacker's forged signature was well-formed base64url or not — a minor timing oracle on signature format.

---

### 🟡 #153 — `expressions.py:679-680` — `is_business_hours` Uses `/` (Real Division) on Int-Sorted DatetimeField — Z3 Real/Int Type Mismatch

```python
hour = (self / 3600) % 24
```

`DatetimeField` is `z3_type="Int"`. Python's `/` operator on Z3 `IntRef` produces a `Real`. Subsequent `% 24` (integer modulo) applied to a `Real` in Z3 either produces a `TranspileError` or incorrect results. `is_business_hours()` silently produces wrong business-hours constraints for all time-based policies.

---

### 🟡 #154 — `expressions.py:641` — `within_seconds(0)` Silently Blocks All Requests

```python
if not isinstance(duration, int) or isinstance(duration, bool) or duration < 0:
    raise PolicyCompilationError(...)
```

`duration=0` passes. The resulting constraint `0 <= (now - field) <= 0` requires the field to equal the exact current second — practically never true. All requests are silently blocked. Should be rejected with a clear error.

---

### 🟡 #155 — `guard_pipeline.py:87-91` — Full-Balance Drain Check Bypassed by Negative `minimum_reserve`

```python
if minimum_reserve == Decimal("0") and amount == balance:
    raise SemanticPolicyViolation("Full balance transfer requires secondary human approval.")
```

A `minimum_reserve` of `-0.01` (attacker-controlled state or misconfiguration) evaluates `minimum_reserve == Decimal("0")` as `False`, completely skipping the full-balance drain guard. The preceding reserve check becomes `balance - amount < -0.01`, effectively allowing a full drain.

---

### 🟡 #156 — `decision.py:780-834` — `from_dict` Accepts Arbitrary `decision_hash` Without Validation — Enables Audit Log Forgery

```python
decision_hash=str(d.get("decision_hash", "")),
```

Restored verbatim from wire. Consumers who call `Decision.from_dict(d).allowed` without then calling `verifier.verify_decision(decision)` silently trust a forged hash. A forged `{"allowed": True, "decision_hash": "anything"}` in the audit log appears legitimate to any consumer that doesn't verify.

---

### 🟡 #157 — `resolvers.py:99-111` — `_resolvers` Dict Unprotected — Data Race Under Free-Threaded Python 3.13

`register()` and `resolve()` both access `self._resolvers` without any lock. The `if name in self._resolvers: ... self._resolvers[name] = resolver` sequence is not atomic — concurrent `register` + `resolve` is a TOCTOU under free-threaded Python.

---

### 🟡 #158 — `ifc/labels.py:42-61` — UNTRUSTED at Top of Lattice (Value=5) — Semantically Inverted vs Standard IFC Models

In standard Denning-style IFC, UNTRUSTED data has the lowest integrity value. Here UNTRUSTED=5 (highest value) means it is "more restricted" than REGULATED=4. This places user prompts above PCI-regulated data in the ordering. `downgrade(UNTRUSTED → REGULATED)` is semantically valid (higher value to lower value) but means "this user input is now PCI-regulated data" — the opposite of the intended sanitization semantic.

---

### 🔵 #159 — `crypto.py:246` — `key_id` Truncated to 64 Bits — Birthday Collision Risk

```python
self._key_id = hashlib.sha256(self._public_pem).hexdigest()[:16]
```

16 hex chars = 8 bytes = 64-bit entropy. Two different Ed25519 public keys with the same `key_id` cause the wrong key to be used for verification (returns `False` silently instead of `True`). Standard for key IDs is 128 bits (32 hex chars).

---

### 🔵 #160 — `provenance.py:135` — `os.urandom(32)` Instead of `secrets.token_bytes(32)` — Minor Idiom Inconsistency

`secrets.token_bytes` is already imported at line 39 and is the Python-idiomatic equivalent for cryptographic purposes. `os.urandom` is also secure but inconsistent with the file's own imports.

---

### 🔵 #161 — `fast_path.py:168-177` — `account_frozen` Misses Integer Values > 1 — Non-Standard Frozen Flags Bypass Check

```python
if val is True or str(val).lower() in ("true", "1", "yes"):
```

Integer `2` (or any truthy non-bool, non-"1", non-"yes" value) does not match — account with `is_frozen=2` is not detected as frozen.

---

### 🔵 #162 — `expressions.py:962-963` — `__and__`/`__or__` Accepts Non-`ConstraintExpr` Right Operand Silently

No runtime type check. `ArithmeticExpr & ArithmeticExpr` creates `_BoolOp("and", (arith, arith))` — a non-boolean Z3 expression. Transpiler raises at solve time rather than at policy-definition time, violating the fail-fast-at-compilation design principle.

---

## PART 10 — AUDIT MODULE, KEY PROVIDER, EXECUTION TOKEN (Third Pass, 2026-06-04)

> Full adversarial read of: audit/merkle.py, audit_sink.py, audit/archiver.py, key_provider.py, execution_token.py.
> Angles: Merkle forgery, archive key TOCTOU, silent data loss in sinks, token replay, key exfiltration.

### 🟠 #165 — `audit/archiver.py:305-324` — `ArchiveKeySet.rotate()` Is a Two-Lock TOCTOU — Concurrent Rotations Can Promote the Wrong Key

```python
def rotate(self, new_key_id: str, new_key: bytes) -> str:
    self.add(new_key_id, new_key)   # lock #1: add, then release
    with self._lock:                # lock #2: promote
        old_id = self._active_key_id
        self._active_key_id = new_key_id
    return old_id
```

Between lock #1 and lock #2, another thread can call `rotate()` with a different key. Thread A's `old_id` return value references the key that Thread B just promoted — caller A schedules cleanup of the still-active key, causing archive decryption failure.

---

### 🟠 #166 — `audit/archiver.py:271-279` — `ArchiveKeySet.add()` Silently Overwrites an Existing Key on `key_id` Collision — Permanent Archive Decryption Loss

```python
"""Add *key* under *key_id*. Overwrites silently if the ID already exists."""
self._keys[key_id] = key
```

If a misconfiguration or rotation race calls `add("key-2026-01", new_bytes)` after `add("key-2026-01", old_bytes)`, old key bytes are silently discarded. Historical archives encrypted with `old_bytes` become permanently unreadable.

---

### 🟠 #167 — `audit/archiver.py:757-817` — `_archive_segment()` Called Under `self._lock` While Invoking User-Supplied `_writer` (File I/O, KMS Calls) — Lock Held During Arbitrary I/O

`_archive_segment()` is invoked from `add()` while `self._lock` is held. The `_writer` performs synchronous file I/O with fsync, or calls KMS for key material (`EncryptedArchiveWriter`), or executes arbitrary user code. This holds the lock for the full I/O duration, blocking all concurrent `add()`, `archive()`, and `root()` calls. A reentrant `_writer` that calls back into `MerkleArchiver` deadlocks.

---

### 🟠 #168 — `audit/archiver.py:771-772` — Same-Date Archive Filename — Second Archival Batch Overwrites First on Same Calendar Day

```python
archive_date = time.strftime("%Y%m%d", time.gmtime(to_archive[0].ts))
archive_path = self._base_path / f".merkle.archive.{archive_date}"
```

Multiple `_archive_segment()` calls on the same day produce the same path. The second call silently destroys the first archive via `os.replace()`. **Systematic data loss for all archival batches after the first on any given day.**

---

### 🟠 #169 — `audit/merkle.py:64-71` — `MerkleProof.verify()` Never Validates `leaf_hash` Against the Original `decision_id`

```python
def verify(self) -> bool:
    current = self.leaf_hash   # ← trusted from caller; never re-derived
    for sibling, direction in self.proof_path:
        ...
    return current == self.root_hash
```

An auditor with a deserialized `MerkleProof` where `leaf_hash` has been replaced sees `verify() → True` if the `proof_path` was re-generated to match. The proof does not bind to a specific `decision_id` unless the auditor independently recomputes `SHA256(\x00 || decision_id)` and asserts it equals `self.leaf_hash`. No API helper enforces this.

---

### 🟡 #173 — `audit/archiver.py:744-753` — `_build_root([])` Raises `IndexError` on Empty Leaf List

```python
def _build_root(leaf_hashes: list[str]) -> str:
    level = leaf_hashes[:]
    while len(level) > 1:
        ...
    return level[0]   # IndexError if empty
```

A crafted archive with a valid header but no leaf lines passes the `if not leaf_hashes: return False` guard in `verify_archive()`. A subsequent call to `_build_root` with an empty list (from a different code path) raises `IndexError` rather than returning a clear error.

---

### 🟡 #174 — `audit_sink.py:492-502` — S3 Sink `close()`: `_worker_thread.join(timeout=5.0)` Timeout Not Checked — Pool Shutdown Races With Still-Running Worker

```python
self._worker_thread.join(timeout=5.0)   # ← not checked if join timed out
self._pool.shutdown(wait=True, cancel_futures=False)
```

If the worker is still running after 5 seconds (slow S3), it continues submitting futures to a shutting-down pool → `RuntimeError: cannot schedule new futures after shutdown`. Decisions in-flight at shutdown are lost.

---

### 🟡 #175 — `audit_sink.py:321-349` — Kafka Sink `_queue_depth` Can Undercount Permanently on `BaseException` Between Increment and `produce()`

`_queue_depth` is incremented outside the lock before `produce()`. A `KeyboardInterrupt` or `SystemExit` between increment and the `except Exception:` decrement leaves the depth permanently inflated. Subsequent `emit()` calls believe the queue is full and drop decisions when it is not.

---

### 🟡 #176 — `key_provider.py:382` — Ed25519 Private Key PEM Cached as Immutable `bytes` — Cannot Be Zeroed From Heap

All cloud providers (`AwsKmsKeyProvider`, `AzureKeyVaultKeyProvider`, `GcpKmsKeyProvider`, `HashiCorpVaultKeyProvider`) cache raw private key PEM as `self._cached_pem: bytes`. Python `bytes` objects are immutable — cannot be zeroed. They persist on the heap for up to 300 seconds (TTL) plus GC lag. A process heap dump, `gc.get_objects()` call from a compromised extension, or crash dump yields the signing key.

---

### 🟡 #177 — `key_provider.py:533-545` — `AzureKeyVaultKeyProvider.rotate_key()` Holds `_cache_lock` During Network I/O — All Signing Operations Block During Key Vault Calls

```python
with self._cache_lock:
    ...
    self._refresh_cache()   # ← httpx network call under lock
```

`private_key_pem()` acquires `_cache_lock` on every `Guard.verify()`. Under key rotation, the lock is held for the full duration of the Key Vault HTTP request (potentially 10–30s under load). Same bug in `GcpKmsKeyProvider.rotate_key()` and `HashiCorpVaultKeyProvider.rotate_key()`.

---

### 🟡 #178 — `key_provider.py:191-199` — `EnvKeyProvider.private_key_pem()` Creates New `bytes` Object Per Call — Unbounded Heap Accumulation of Key Material

```python
def private_key_pem(self) -> bytes:
    pem = os.environ.get(self._env_var, "")
    return pem.encode()   # new bytes on every call
```

Called on every `Guard.verify()`. High-throughput guard creates hundreds of dangling PEM copies on the heap per second. No validation that the PEM is valid at construction time.

---

### 🟡 #179 — `execution_token.py:205-206` — Minimum HMAC Key Size Is 16 Bytes — Below NIST SP 800-107 Recommendation of 32 Bytes

```python
if len(secret_key) < 16:
    raise ValueError("secret_key must be at least 16 bytes.")
```

Docstring says "at least 32 bytes recommended" but enforcement is 16 bytes. A developer trusting the enforced minimum deploys a key with only 128-bit HMAC security. Should enforce 32-byte minimum.

---

### 🟡 #180 — `execution_token.py:392` — Expiry Check Uses `time.time()` (Wall Clock) — NTP Clock Rollback Enables Replay of Recently-Expired Tokens

```python
if token.is_expired():     # ← calls time.time() by default
```

NTP manipulation or VM migration clock skew allows a recently-expired token (e.g., 5 seconds past expiry) to appear valid after a clock rollback. The `ExecutionTokenVerifier` injects a custom `_clock` for testing but `consume()` calls `token.is_expired()` without passing it, making clock injection incomplete for tests as well.

---

### 🟡 #181 — `execution_token.py:629-642` — SQLite `consume()`: Eviction DELETE and Token INSERT Are Two Separate Commits — Replay Window on Crash

```python
self._evict_expired()   # DELETE + COMMIT (transaction #1)
...
self._conn.commit()     # INSERT (transaction #2)
```

A crash between commit #1 and commit #2 removes expired entries but never records the token as consumed. On restart, the token can be consumed again — **single-execution guarantee violated**. Both operations must be in a single transaction.

---

### 🟡 #182 — `execution_token.py:903-916` — `RedisExecutionTokenVerifier.consume()` Returns `False` on Redis Failure — Programmatically Indistinguishable From "Already Consumed"

Noted in prior audit (#74) at API level. The deeper issue: a caller implementing "retry on transient failure" cannot distinguish `False` from a replay vs. `False` from Redis down. Should raise a typed `RedisUnavailableError` on connection failure.

---

### 🟡 #183 — `execution_token.py:335-340` — O(N) Eviction Scan Inside `_lock` on Every `consume()` — DoS Amplifier

```python
expired = [tid for tid, exp in self._consumed.items() if exp < now]
```

Called under `self._lock` on every `consume()`. With 300s TTL at 10k req/s, `_consumed` accumulates ~300k entries. O(N) scan blocks all concurrent `consume()` calls during eviction.

---

### 🟡 #184 — `execution_token.py:1061-1072` — `PostgresExecutionTokenVerifier._run()` Creates New Event Loop Per Call When `_loop=None` — asyncpg Pool Exhaustion

```python
if self._loop is None:
    return asyncio.run(coro)   # new loop per call
```

Under pool-injection mode, each call creates a temporary event loop. asyncpg pool connections opened on temporary loops are never properly returned to the pool. Pool exhaustion under load.

---

### 🟡 #185 — `execution_token.py:711-716` — `consume_within()` Creates Table Without WAL Mode or `expires_at` Index — Full Table Scans on Eviction

```python
conn.execute("CREATE TABLE IF NOT EXISTS consumed_tokens (...)")
# missing: PRAGMA journal_mode=WAL
# missing: CREATE INDEX IF NOT EXISTS idx_expires ON consumed_tokens(expires_at)
```

Inconsistent with `_init_db()` which sets WAL and creates the index. Callers using `consume_within()` on fresh databases get full-table-scan eviction.

---

### 🔵 #186 — `audit/merkle.py:123-127` — Padding Node Hash Indistinguishable From Internal Nodes — Same `\x01` Prefix Used

Padding nodes use `SHA256(\x01 || last_leaf)` — the same prefix as internal nodes. Proofs containing padding node siblings are structurally ambiguous (though not directly exploitable given correct domain separation of leaf `\x00` vs internal `\x01` prefixes).

---

### 🔵 #187 — `audit_sink.py` — `SplunkHecAuditSink` and `DatadogAuditSink` Expose No `overflow_count` Property — API Inconsistency

`KafkaAuditSink` and `S3AuditSink` have `overflow_count` properties. `SplunkHecAuditSink` and `DatadogAuditSink` track overflow internally but expose no programmatic count. Monitoring assertions can only be written against some sinks, not all.

---

### 🔵 #188 — `key_provider.py:268-299` — `FileKeyProvider.rotate_key()` Does Not `chmod 0600` New Key File — Permissions Depend on `mkstemp` Default and umask

`tempfile.mkstemp()` defaults to `0o600` on POSIX but this is umask-dependent. Explicit `os.chmod(tmp_path, 0o600)` before `os.replace` is required to guarantee restrictive permissions independent of umask.

---

### 🔵 #189 — `key_provider.py:369-373` — Cloud Provider Errors Log Full ARN / Secret Name / KMS Key ID in RuntimeError Messages — Infrastructure Topology Disclosure

All four cloud providers embed the full resource identifier (`secret_arn`, vault URL + secret name, GCP project ID + secret ID + version) in `RuntimeError` messages that flow to application logs. Attackers with log access harvest cloud infrastructure topology.

---

### 🔵 #190 — `key_provider.py` (all) — No Key Revocation Mechanism — Compromised Key Active for Full 300-Second Cache TTL

`KeyProvider` defines `rotate_key()` but no `revoke_key()` or `invalidate_cache()`. A known-compromised key continues to mint valid tokens for up to 300 seconds after the operator rotates it at the cloud provider level.

---

### 🔵 #191 — `execution_token.py:265` — `intent_dump` Serialized via `default=str` in HMAC Body — Non-JSON-Native Types Coerced, Semantic Binding Is Lossy

```python
json.dumps(..., default=str)
```

Non-JSON-native `intent_dump` values are silently converted to their `str()` representation. Two structurally different objects with the same `str()` output produce the same HMAC body — the token no longer uniquely binds to the semantic intent that was verified.

---

### 🔵 #192 — `execution_token.py:147-149` — `is_expired()` Uses `time.time()` by Default But `consume()` Doesn't Pass `self._clock` — Injected Clock Incomplete

```python
if token.is_expired():   # should be: token.is_expired(clock=self._clock)
```

Tests that inject a custom clock into the verifier still see wall time for the expiry check, causing test non-determinism and clock-injection being incomplete.

---

## UPDATED SUMMARY TABLE (Findings #118–#192)

| # | Severity | Category | File | Finding |
| - | -------- | -------- | ---- | ------- |
| 122 | 🟠 | Design | `integrations/dspy.py:150` | `intent_builder`/`state_provider` exceptions leak policy field shapes |
| 123 | 🟠 | Security | `integrations/pydantic_ai.py:160` | `guard_tool` sends `intent={}` — vacuous-truth fail-open |
| 124 | 🟠 | DoS | `integrations/crewai.py:153` | `_arun` calls sync guard on event loop — starvation |
| 125 | 🟠 | Perf | `integrations/llamaindex.py:507` | New `ThreadPoolExecutor` per `call()` — thread exhaustion |
| 126 | 🟠 | TOCTOU | `integrations/haystack.py:121` | State fetched once per batch — TOCTOU on mutable state |
| 128 | 🟠 | Race | `integrations/agent_orchestration.py:225` | `_enter_times` overwritten on parallel same-node calls; unbounded |
| 129 | 🟡 | Security | `integrations/semantic_kernel.py:108` | `redact_violations` ignored — full policy internals exposed to LLM planner |
| 130 | 🟡 | Design | `integrations/fastapi.py:283` | Positional arg extraction passes non-dict `intent` without type check |
| 131 | 🟡 | Bug | `integrations/llamaindex.py:244` | `decision.status` enum in `raw_output` — latent JSON crash |
| 132 | 🟡 | Design | `integrations/autogen.py:129` | `strict=True` rejects AutoGen v0.4 framework-injected kwargs |
| 133 | 🟡 | Design | `integrations/pydantic_ai.py:109` | Guard infrastructure exception bypasses `GuardViolationError` handler |
| 134 | 🟡 | Design | `integrations/haystack.py:215` | `@component` registration failure swallowed — silent misconfiguration |
| 135 | 🟡 | Design | `integrations/crewai.py:187` | `ConfigurationError` raised in agent loop on ALLOW + no `underlying_fn` |
| 137 | 🔵 | Perf | `integrations/llamaindex.py:160` | `max_workers=1` hardcoded |
| 138 | 🔵 | Design | `integrations/dspy.py:162` | Custom `__call__` bypasses DSPy `Module.__call__` bookkeeping |
| 139 | 🔵 | Design | `integrations/pydantic_ai.py:106` | `state_fn()` exception propagates as non-`GuardViolationError` |
| 140 | 🔵 | Security | `integrations/fastapi.py:142` | Content-Type check uses substring `in` |
| 141 | 🔵 | Design | `integrations/agent_orchestration.py:357` | `AutoGenGuardAdapter` hardcodes `state={}` |
| 142 | 🔵 | Audit | `integrations/haystack.py:128` | `block_on_error=False` items audit-invisible |
| 143 | 🔵 | Design | `integrations/langgraph.py:297` | Node `bypass_on_timeout=True` default vs Edge with no parameter — undocumented asymmetry |
| 146 | 🟠 | Logic | `fast_path.py:112,190` | `or` short-circuit — zero-value intent bypasses fast-path rules |
| 147 | 🟠 | Observ | `fast_path.py:48-69` | Prometheus counter failure swallowed silently |
| 152 | 🟡 | Timing | `crypto.py:391` | Timing side-channel: base64url decode error vs InvalidSignature |
| 153 | 🟡 | Logic | `expressions.py:679` | `is_business_hours` uses `/` (Real) on Int-sorted field — Z3 type mismatch |
| 154 | 🟡 | Design | `expressions.py:641` | `within_seconds(0)` silently blocks all requests |
| 155 | 🟡 | Security | `guard_pipeline.py:87` | Full-balance drain bypass via negative `minimum_reserve` |
| 156 | 🟡 | Security | `decision.py:780` | `from_dict` accepts arbitrary `decision_hash` without validation |
| 157 | 🟡 | Race | `resolvers.py:99` | `_resolvers` dict unprotected — data race under free-threaded Python |
| 158 | 🟡 | Design | `ifc/labels.py:42` | UNTRUSTED at top of lattice — semantically inverted vs standard IFC |
| 159 | 🔵 | Security | `crypto.py:246` | `key_id` truncated to 64 bits |
| 160 | 🔵 | Style | `provenance.py:135` | `os.urandom` vs `secrets.token_bytes` idiom inconsistency |
| 161 | 🔵 | Logic | `fast_path.py:168` | `account_frozen` misses integer values > 1 |
| 162 | 🔵 | Design | `expressions.py:962` | `__and__`/`__or__` accepts non-`ConstraintExpr` silently |
| 165 | 🟠 | Race | `audit/archiver.py:305` | `ArchiveKeySet.rotate()` two-lock TOCTOU — wrong key promoted |
| 166 | 🟠 | Design | `audit/archiver.py:271` | `ArchiveKeySet.add()` silently overwrites key — permanent archive loss |
| 167 | 🟠 | Design | `audit/archiver.py:757` | `_archive_segment()` runs user `_writer` under `self._lock` — deadlock risk |
| 168 | 🟠 | Design | `audit/archiver.py:771` | Same-date archive filename collision — second batch overwrites first |
| 169 | 🟠 | Security | `audit/merkle.py:64` | `MerkleProof.verify()` never validates `leaf_hash` vs `decision_id` |
| 173 | 🟡 | Design | `audit/archiver.py:827` | `_build_root([])` raises `IndexError` — empty archive unhandled |
| 174 | 🟡 | Design | `audit_sink.py:492` | S3 close(): join timeout not checked — pool shutdown races with worker |
| 175 | 🟡 | Design | `audit_sink.py:321` | Kafka `_queue_depth` can undercount on `BaseException` |
| 176 | 🟡 | Security | `key_provider.py:382` | Ed25519 PEM cached as immutable bytes — unzeroable from heap |
| 177 | 🟡 | Design | `key_provider.py:533` | Network I/O under cache lock in Azure/GCP/Vault `rotate_key()` |
| 178 | 🟡 | Security | `key_provider.py:191` | `EnvKeyProvider` creates fresh PEM bytes per call — unbounded heap |
| 179 | 🟡 | Security | `execution_token.py:205` | HMAC key minimum 16 bytes — below NIST 32-byte recommendation |
| 180 | 🟡 | Security | `execution_token.py:392` | Expiry check uses wall clock — NTP rollback enables token replay |
| 181 | 🟡 | Security | `execution_token.py:629` | SQLite eviction + INSERT two separate commits — replay window on crash |
| 182 | 🟡 | API | `execution_token.py:903` | Redis failure returns `False` — indistinguishable from "already consumed" |
| 183 | 🟡 | Perf | `execution_token.py:335` | O(N) eviction scan under `_lock` on every `consume()` — DoS amplifier |
| 184 | 🟡 | Design | `execution_token.py:1070` | `asyncio.run()` per call in pool-injection mode — asyncpg pool exhaustion |
| 185 | 🟡 | Design | `execution_token.py:711` | `consume_within()` creates table without WAL mode or `expires_at` index |
| 186 | 🔵 | Design | `audit/merkle.py:123` | Padding node uses `\x01` prefix — indistinguishable from internal nodes |
| 187 | 🔵 | API | `audit_sink.py:559` | Splunk/Datadog expose no `overflow_count` property — API inconsistency |
| 188 | 🔵 | Security | `key_provider.py:268` | `FileKeyProvider.rotate_key()` no explicit `chmod 0600` |
| 189 | 🔵 | Info | `key_provider.py:369` | Cloud provider errors log full ARN/key path — infrastructure topology disclosure |
| 190 | 🔵 | Design | `key_provider.py` (all) | No key revocation mechanism — compromised key active for full 300s TTL |
| 191 | 🔵 | Design | `execution_token.py:265` | `intent_dump` coerced via `default=str` — semantic binding is lossy |
| 192 | 🔵 | Design | `execution_token.py:392` | `is_expired()` uses wall clock even when verifier has injected clock |

---

## PART 11 — CLI, NATURAL POLICY, NLP, PRIMITIVES, MESH DEEP AUDIT (Third Pass, 2026-06-04)

> Full adversarial read of: cli.py, natural_policy/compiler.py, natural_policy/yaml_loader.py,
> helpers/policy_auditor.py, helpers/compliance.py, primitives/infra.py, primitives/roles.py,
> primitives/time.py, nlp/validators.py, mesh/authenticator.py.
> Angles: RCE via --policy flag, prompt injection, YAML DoS, JWT algorithm confusion, SSRF,
> role confusion, universal temporal bypass via caller-controlled state.

### 🟠 #197 — `natural_policy/yaml_loader.py:397-398,495` — `_build_policy_class` Accepts `__dunder__` Names — Namespace Collision, Pickle Gadget Risk

```python
if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", policy_name):
    raise PolicySyntaxError(...)
policy_cls = type(policy_name, (Policy,), class_attrs)
```
Regex allows `__reduce__`, `__init__`, and other dunder names. A class named `__reduce__` fed into pickling-related code paths is indistinguishable from the real method. Also allows shadowing `Guard`, `Policy`, `Decision`, `Field` and Python builtins (`list`, `dict`, `type`).

---

### 🟠 #198 — `cli.py:779-788` — `audit verify` Recomputes Hash From Attacker-Controlled Record Fields — Extra Fields Bypass Authentication

```python
canonical = _build_decision_canonical(
    allowed=bool(record.get("allowed", False)),
    explanation=str(record.get("explanation", "")),
    intent_dump=record.get("intent_dump") or {},
    ...
)
```
`_build_decision_canonical` hashes only 7–9 fields. Additional fields present in the audit record (`metadata`, `error_domain`, `stack_trace_hash`, `policy_name`) are NOT authenticated. An attacker can inject these fields with arbitrary values; they appear in `--json` output as verified data while being completely outside the canonical hash.

---

### 🟠 #199 — `primitives/infra.py:145-151` — `BlastRadiusCheck` Vacuously True When `total_instances=0`; `max_blast_pct` Accepts `0` and Values > 1

```python
(E(affected_instances) <= max_blast_pct * E(total_instances))
```
`total_instances=0` → constraint becomes `affected <= 0`. An attacker injecting `state={"total_instances": 0}` causes all non-zero deployments to be blocked (DoS), or trivially ALLOWs zero-affected deployments. `max_blast_pct=0` produces `affected <= 0` (always blocks any deployment); `max_blast_pct=1.5` allows 150% of fleet to be affected. Neither is validated at primitive construction time.

---

### 🟠 #200 — `primitives/infra.py:180-188` — `CircuitBreakerState` Case-Sensitive — `"open"` Bypasses OPEN Check

```python
(E(circuit_state) != "OPEN")
```
Z3 String theory performs byte-exact comparison. `"open"`, `"Open"`, `"OPEN "` (trailing space), or Unicode homoglyphs all bypass the guard and allow requests to flow to a tripped downstream service. Any external system (Redis, Kubernetes annotation, API response) using lowercase or mixed-case circuit state triggers silent fail-open.

---

### 🟠 #201 — `primitives/time.py:99-114` — `NotExpired` Accepts Caller-Controlled `now_ts` Field — Setting `now_ts=0` Bypasses All Expiry Checks

```python
def NotExpired(expiry_ts: Field, now_ts: Field) -> ConstraintExpr:
    return (E(expiry_ts) > E(now_ts))
```
`now_ts` is a `Field` populated from caller-supplied intent/state. Setting `state={"now_ts": 0}` makes `expiry_ts > 0` true for any positive expiry — all tokens and certificates appear permanently valid. There is no mechanism to mark fields as "policy-managed, not caller-editable."

---

### 🟠 #202 — `primitives/time.py:43-96` — `WithinTimeWindow`, `Before`, `After` Accept Caller-Controlled Bound Fields — Universal Temporal Bypass

Same root cause as #201. `window_start`, `window_end`, `cutoff` are all `Field` objects from caller-supplied state. Setting `window_start=0, window_end=9999999999` makes any timestamp pass any window check. **All temporal enforcement is universally bypassable by a caller who controls the `state` dict.**

---

### 🟠 #203 — `mesh/authenticator.py:548-557` — `_fetch_jwks` Has No Certificate Pinning — JWKS MITM Enables Full JWT-SVID Forgery

```python
response = httpx.get(self._jwks_uri, ...)
```
Standard TLS CA verification only — no certificate pinning. A BGP hijack, DNS poisoning, or rogue CA can serve a JWKS with the attacker's public keys. All tokens signed by the attacker's private key then pass `verify_svid()`, granting full agent identity impersonation for the cache TTL window (default 600s).

---

### 🟠 #204 — `mesh/authenticator.py:506-519` — `_jwks_fetching` Not Cleared on `BaseException` — Permanent JWKS Cache Staleness

```python
except Exception:
    with self._jwks_lock:
        self._jwks_fetching = False
    raise
```
`KeyboardInterrupt` and `SystemExit` are `BaseException` subclasses — not caught here. After a `SIGINT` during JWKS fetch, `_jwks_fetching` remains `True` permanently. All subsequent threads serve stale cached keys forever. Rotated signing keys are never picked up.

---

### 🟠 #205 — `mesh/authenticator.py:976-978` — No-`kid` JWT Fallback Tries All Keys — Key Substitution Attack When JWKS Is Compromised

When a JWT has no `kid` header, key selection falls back to any key matching the algorithm. An attacker who can add a JWK to the JWKS (via MITM as in #203) injects a second key with no `kid`. Their forged token — signed with their private key — is tried as a candidate and passes verification. Combined with #203, this is a complete end-to-end JWT-SVID forgery path.

---

### 🟠 #206 — `helpers/compliance.py:118-133` — Severity Classification Driven by Attacker-Controlled `intent_dump["amount"]` — Severity Downgrade Attack

```python
amount_str = str(intent_dump.get("amount", "0"))
amount = Decimal(amount_str)
if amount >= Decimal("100000"):
    return "CRITICAL_PREVENTION"
```
`intent_dump["amount"]` comes from the caller-supplied intent. An attacker submitting a $200,000 sanctions-screen violation with `intent={"amount": "0"}` receives `HIGH` classification instead of `CRITICAL_PREVENTION`, reducing the urgency of SAR filing and audit review. Severity must be driven by `violated_invariants`, not user-supplied field values.

---

### 🟠 #207 — `nlp/validators.py:534-539` — `ToxicityScorer` Keyword Fallback Bypassed by Unicode Homoglyphs, Zero-Width Chars, Multi-Token Phrases

```python
tokens = _normalise(text).split()
toxic_count = sum(1 for t in tokens if t.strip(".,!?;:'\"") in self._words)
```
`"kіll"` (Cyrillic і) is not normalised to ASCII `"kill"` by NFKC. Zero-width spaces (`​`) are not stripped. Multi-word phrases (`"camel jockey"`) are in the frozenset but split into two non-matching tokens. Leet-speak (`"k1ll"`) bypasses entirely. All result in false-negative toxicity detection.

---

### 🟠 #208 — `nlp/validators.py:237` — `PIIDetector` Credit Card Regex Overly Broad — Matches Phone Numbers, SSNs, Timestamps — High False-Positive Rate

```python
("credit_card", _re_engine.compile(r"\b(?:\d[ -]?){13,19}\b")),
```
Any 13–19 digit sequence with optional spaces/dashes matches — including phone numbers, SSNs, NAICS codes, and numerical timestamps. High false-positive rate in financial/medical text overwhelms downstream PII handling.

---

### 🟡 #209 — `cli.py:1443-1444` — `--policy-var` Silently Ignored for YAML/TOML — No Warning Emitted

When `--policy-var SomeClass --policy banking.yaml` is passed, `policy_var` is silently ignored for YAML/TOML files. No warning is emitted. A user believes they are testing class `SomeClass` when they are testing the first policy in the file — silent test misconfiguration in CI.

---

### 🟡 #210 — `natural_policy/compiler.py:594-642` — `compile_from_schema` Bypasses LLM Entirely — No Provenance Check on Schema Origin

Any `NaturalPolicySchema` object is accepted without signature or hash verification. The CLI `compile-policy` command calls this path directly. An attacker with write access to the policy store crafts a schema that compiles to arbitrary Z3 constraints, bypassing the CISO's English-language policy intent without a LLM trace.

---

### 🟡 #211 — `natural_policy/compiler.py:583` — `_validate_schema` Embeds 200 Chars of Policy Text in Error Messages — Sensitive Policy Intent Leak

```python
raise ExtractionFailureError(
    f"...Original policy: {original_english[:200]!r}"
)
```
Policy text may contain financial thresholds, internal system names, or PII. This leaks into exception messages that flow to Sentry-style error trackers or API error responses.

---

### 🟡 #212 — `natural_policy/yaml_loader.py:267-274` — `not bool_field` Silently Compiled to `field.is_false()` for Non-Bool Fields — Logic Inversion

```python
if isinstance(operand, ExpressionNode):
    return operand.is_false()
```
`not amount` (Real field) compiles to `amount == 0` (Z3's interpretation of `.is_false()` on Real). A policy author intending "block if amount is non-zero" gets the opposite — `amount == 0` blocks only zero-amount transfers. No type check before calling `.is_false()` on non-Bool fields.

---

### 🟡 #213 — `natural_policy/yaml_loader.py:471-473` — `explain` Template Strings Not Validated — Format String Introspection Risk

```python
constraint = constraint.explain(explain)
```
`explain` values containing `{__class__.__mro__}` or `{x.__init__.__globals__[SECRET]}` are not filtered at load time. If the template is rendered via Python `str.format_map(intent_dump)` with user-controlled intent data, this is a format string information disclosure. At minimum, undefined `{field_name}` placeholders cause `KeyError` at explain-rendering time.

---

### 🟡 #214 — `primitives/infra.py:209-217` — `ProdDeployApproval` Accepts `required_approvers=0` — No Approval Required

```python
(E(deployment_approved).is_true() & (E(approver_count) >= required_approvers))
```
No validation that `required_approvers >= 1`. `required_approvers=0` produces `approver_count >= 0`, trivially satisfied — zero approvals required for production deployment. Should raise `ValueError` at construction time.

---

### 🟡 #215 — `primitives/infra.py:238-244` — `ReplicaBudget(min=10, max=5)` Produces Unsatisfiable Constraint — All Requests Silently Blocked

```python
(E(requested_replicas) >= min_replicas) & (E(requested_replicas) <= max_replicas)
```
If `min_replicas > max_replicas`, the constraint is unsatisfiable — Z3 returns `unsat` for all inputs, every request is blocked with no error. No validation of ordering at construction time.

---

### 🟡 #216 — `primitives/roles.py:75,99` — `HIPAARole.BREAK_GLASS=99` and `EnterpriseRole.SUPERUSER=99` Share the Same Integer — Cross-Namespace Role Confusion

A policy that mixes role namespaces (using `EnterpriseRole.SUPERUSER` in a HIPAA policy) grants `BREAK_GLASS` PHI emergency override access to any `SUPERUSER`-privileged principal. Z3 sees only integer `99` — no type-level namespace separation. In healthcare deployments this is a HIPAA violation.

---

### 🟡 #217 — `mesh/authenticator.py:718-719` — `_validate_temporal_claims` Accepts `exp` as Float — `exp=9.9e99` Produces Token That Never Expires

```python
exp_int = int(exp)
```
`int(9.9e99)` is a valid but enormous Python integer. `now > exp_int + skew` is always `False` for any plausible `now`. A JWT with `exp = 9.9e99` is permanently valid. Should reject non-integer or out-of-range `exp` values.

---

### 🟡 #218 — `mesh/authenticator.py:1044-1046` — `_jwk_to_public_key` Does Not Validate RSA Key Size — Accepts 512-Bit Keys

```python
return rsa.RSAPublicNumbers(e=e, n=n).public_key(default_backend())
```
No minimum modulus size check. A JWKS served (via MITM) with a 512-bit RSA key allows the attacker to factor the modulus and sign arbitrary JWT-SVIDs. Should enforce `n.bit_length() >= 2048`.

---

### 🟡 #219 — `nlp/validators.py:692` — `SemanticSimilarityGuard._tokenise` Calls `_re_engine.split()` When `_re_engine=None` — `AttributeError` at Init Time

```python
return frozenset(_re_engine.split(r"\W+", norm)) - {""}
```
`_re_engine` is `None` when RE2 is not installed and sentence-transformers is also absent (the Jaccard fallback path). `None.split(...)` raises `AttributeError` at `SemanticSimilarityGuard.__init__` time. `PIIDetector` correctly calls `_require_re2()` to produce a clear `ConfigurationError`; `SemanticSimilarityGuard` does not.

---

### 🟡 #220 — `nlp/validators.py:1002-1010` — `URLValidator` Does Not Check IPv4/IPv6 Private Ranges — SSRF via IP Literal

```python
host = (parsed.hostname or "").lower()
for bd in self.blocked_domains:
    if host == bd.lower() or host.endswith(f".{bd.lower()}"):
        return False, ...
```
`urlparse("https://127.0.0.1/admin").hostname` returns `"127.0.0.1"`. Domain suffix matching never fires on IP literals. `https://[::1]/admin` (IPv6 loopback) and `https://10.0.0.1/internal` (RFC 1918) are not blocked unless explicitly in `blocked_domains`. An SSRF attack using IP literals bypasses the domain blocklist.

---

### 🟡 #221 — `mesh/authenticator.py:114-119` — SPIFFE URI Regex Allows Single-Character Trust Domains and Consecutive Dots

```python
r"(?P<trust_domain>[A-Za-z0-9][A-Za-z0-9\-\.]{0,253})"
```
`spiffe://a/path` (single-char trust domain) and `spiffe://foo..bar/path` (consecutive dots) both pass. These are invalid DNS names per RFC 1035 and invalid SPIFFE trust domains per the spec. Malformed URIs accepted as valid identities can cause trust-domain confusion.

---

### 🟡 #222 — `nlp/validators.py:1211-1213` — `ProfanityDetector` Uses Stdlib `re` — `extra_words` Without Length Limit Enables ReDoS

```python
re.compile(r"(?<!\w)" + re.escape(w) + r"(?!\w)", flags)
```
Stdlib `re` (not RE2) is used. Long `extra_words` entries combined with adversarial near-miss input text can trigger backtracking. No length limit on `extra_words` entries.

---

### 🟡 #223 — `natural_policy/yaml_loader.py:241-247` — `_ast.Constant` Bool/Int Ambiguity — `amount == True` Compiles to `amount == 1` for Real Fields

`bool` is a subclass of `int`. `isinstance(True, int)` is `True`. `amount == True` on a Real field is compiled as `amount == 1` by `_Literal`. The semantic intent ("amount equals True") is silently transformed to a numeric check with no type error.

---

### 🟡 #224 — `helpers/compliance.py:347-351` — `ComplianceReport` Embeds Unvalidated Invariant Names in Regulatory Reference Output — Injection Into Audit PDF

```python
refs.append(f"Internal policy rule: {rule}")
```
If `rule` contains embedded newlines, quotes, or regulatory-citation-like text (possible if invariant names come from attacker-controlled YAML policy), the compliance report's `regulatory_refs` section is polluted with attacker-controlled strings that appear in the PDF submitted to regulators.

---

### 🟡 #225 — `helpers/policy_auditor.py:249-333` — `boundary_examples()` Returns Exact Z3 Witness Values — Full Policy Threshold Disclosure

`boundary_examples()` returns the exact amounts, balances, and field values that sit on the ALLOW/BLOCK boundary of every invariant. If exposed via an API or logged, this gives an attacker a complete map of every policy threshold — enabling structuring attacks (maximising impact while staying just within each constraint).

---

### 🟡 #226 — `primitives/time.py` — No Maximum Epoch Value Guard — Year 2038 / Far-Future Timestamp Overflow

All time primitives accept unbounded `Int` Z3 fields. No validation that caller-supplied timestamps fall within a plausible range (`[0, 4102444800]`). On 32-bit systems, `int(time.time())` wraps negative after 2038, making `expiry_ts > negative_now` trivially true — bypassing all expiry checks.

---

### 🔵 #227 — `cli.py:984,988` — `--policy-var` Silently Ignored for YAML/TOML — Misleads Users in Automated Testing

When `--policy-var SomeClass --policy banking.yaml` is used, `policy_var` is silently dropped. No warning. A CI pipeline that tests `SomeClass` by this argument silently tests the wrong policy.

*(Note: same root as #209 — distinct symptom documented for CI tooling impact.)*

---

### 🔵 #228 — `cli.py:889` — `_suggest_fixes` Picks First Numeric Intent Field — Irrelevant Fields Produce Misleading Fix Suggestions

```python
intent_key = next((key for key in numeric_intent), None)
```
If `intent={"timestamp": 9999, "amount": 75000}`, the fix suggestion recommends raising `max_daily_limit` to `9999` instead of `75000`. Low direct risk but erodes trust in the tool's guidance.

---

### 🔵 #229 — `helpers/compliance.py:213-216` — PDF Uses `cp1252` Encoding — Non-Latin Characters Silently Corrupted in Regulatory PDFs

```python
pdf.core_fonts_encoding = "cp1252"
```
Policy names or explanations containing Japanese, Arabic, Cyrillic, or emoji are silently dropped or replaced with `?` in the PDF. No error is raised. Regulatory PDFs submitted with corrupted text are invalid.

---

### 🔵 #230 — `primitives/roles.py:51-99` — Role Integer Constants Are Mutable Class Attributes — Privilege Escalation via Monkey-Patching

```python
class HIPAARole:
    CLINICIAN: int = 1
    BREAK_GLASS: int = 99
```
Plain class-level attributes with no `Final` annotation or `__slots__`. Any code can write `HIPAARole.BREAK_GLASS = 1` — silently granting all clinicians emergency PHI access. Should use `enum.IntEnum`.

---

### 🔵 #231 — `mesh/authenticator.py:384-385` — `token_preview=token[:16]` Exposes Raw JWT Bytes in Error Logs

```python
token_preview=token[:16],
```
The first 16 characters of a JWT expose the beginning of the base64url-encoded header. Should use `hashlib.sha256(token.encode()).hexdigest()[:16]` as a safe correlation handle.

---

### 🔵 #232 — `nlp/validators.py:922-925` — `DateValidator` Treats Naive Datetimes as UTC — Silent 8-Hour Error for UTC+8 Callers

```python
if dt.tzinfo is None:
    dt = dt.replace(tzinfo=UTC)
```
Naive datetime strings are silently assumed to be UTC. Callers in non-UTC timezones providing local time strings get incorrect `not_before`/`not_after` validation with up to 14-hour discrepancy.

---

### 🟠 #234 — **ARCHITECTURAL** — `CircuitBreakerState` + Caller-Controlled State = Fail-Open Circuit Bypass

A specific instance of #233. The circuit breaker state (`OPEN`/`CLOSED`/`HALF-OPEN`) is stored in Redis and injected via `state`. A caller controlling `state` injects `circuit_state="CLOSED"` when the actual circuit is `OPEN`, bypassing downstream service protection entirely. This is distinct from the case-sensitivity bypass in #200 — it is about the trust model, not the string comparison.

---

## FINAL SUMMARY TABLE (Findings #193–#234)

| # | Severity | Category | File | Finding |
| - | -------- | -------- | ---- | ------- |
| 197 | 🟠 | Security | `natural_policy/yaml_loader.py:397` | `_build_policy_class` accepts `__dunder__` names — namespace collision |
| 198 | 🟠 | Security | `cli.py:779` | `audit verify` extra record fields bypass authentication — unsigned fields appear verified |
| 199 | 🟠 | Logic | `primitives/infra.py:145` | `BlastRadiusCheck` vacuous truth on `total_instances=0`; unchecked `max_blast_pct` |
| 200 | 🟠 | Security | `primitives/infra.py:180` | `CircuitBreakerState` case-sensitive — `"open"` bypasses OPEN check |
| 201 | 🟠 | Security | `primitives/time.py:99` | `NotExpired` accepts caller-controlled `now_ts=0` — universal expiry bypass |
| 202 | 🟠 | Security | `primitives/time.py:43` | `WithinTimeWindow`/`Before`/`After` all accept caller-controlled bounds |
| 203 | 🟠 | Security | `mesh/authenticator.py:548` | `_fetch_jwks` no certificate pinning — MITM enables full JWT-SVID forgery |
| 204 | 🟠 | Design | `mesh/authenticator.py:506` | `_jwks_fetching` not cleared on `BaseException` — permanent cache staleness |
| 205 | 🟠 | Security | `mesh/authenticator.py:976` | No-`kid` JWT fallback tries all keys — key substitution attack |
| 206 | 🟠 | Security | `helpers/compliance.py:118` | Severity driven by attacker-controlled `amount` field — downgrade attack |
| 207 | 🟠 | Security | `nlp/validators.py:534` | `ToxicityScorer` bypassed by Unicode homoglyphs, zero-width chars, multi-token phrases |
| 208 | 🟠 | Design | `nlp/validators.py:237` | `PIIDetector` credit card regex overly broad — high false-positive rate |
| 209 | 🟡 | Design | `cli.py:984` | `--policy-var` silently ignored for YAML/TOML — no warning emitted |
| 210 | 🟡 | Security | `natural_policy/compiler.py:594` | `compile_from_schema` bypasses LLM provenance — no schema origin check |
| 211 | 🟡 | Info | `natural_policy/compiler.py:583` | Validation error embeds 200 chars of policy text — sensitive intent leak |
| 212 | 🟡 | Logic | `natural_policy/yaml_loader.py:267` | `not non_bool_field` silently compiles to `field == 0` — logic inversion |
| 213 | 🟡 | Security | `natural_policy/yaml_loader.py:471` | `explain` template strings not validated — format string introspection risk |
| 214 | 🟡 | Logic | `primitives/infra.py:209` | `ProdDeployApproval` accepts `required_approvers=0` — no approval required |
| 215 | 🟡 | Logic | `primitives/infra.py:238` | `ReplicaBudget(min>max)` produces unsatisfiable constraint — all requests blocked |
| 216 | 🟡 | Security | `primitives/roles.py:75,99` | `HIPAARole.BREAK_GLASS` and `EnterpriseRole.SUPERUSER` share integer `99` — role confusion |
| 217 | 🟡 | Security | `mesh/authenticator.py:718` | `exp` as float `9.9e99` produces never-expiring token |
| 218 | 🟡 | Security | `mesh/authenticator.py:1044` | `_jwk_to_public_key` accepts 512-bit RSA keys — factorable modulus |
| 219 | 🟡 | Bug | `nlp/validators.py:692` | `SemanticSimilarityGuard._tokenise` calls `None.split()` when RE2 absent |
| 220 | 🟡 | Security | `nlp/validators.py:1002` | `URLValidator` no IPv4/IPv6 private-range check — SSRF via IP literal |
| 221 | 🟡 | Security | `mesh/authenticator.py:114` | SPIFFE URI regex allows single-char trust domains and consecutive dots |
| 222 | 🟡 | DoS | `nlp/validators.py:1211` | `ProfanityDetector` uses stdlib `re` — ReDoS via long `extra_words` entries |
| 223 | 🟡 | Logic | `natural_policy/yaml_loader.py:241` | `amount == True` compiles to `amount == 1` — bool/int ambiguity |
| 224 | 🟡 | Security | `helpers/compliance.py:347` | Compliance report embeds unvalidated invariant names — injection into regulatory PDF |
| 225 | 🟡 | Security | `helpers/policy_auditor.py:249` | `boundary_examples()` returns exact policy thresholds — full threshold disclosure |
| 226 | 🟡 | Logic | `primitives/time.py` | No maximum epoch guard — far-future timestamps bypass expiry; 2038 overflow |
| 227 | 🔵 | Design | `cli.py:984` | `--policy-var` ignored for YAML — misleads automated CI testing |
| 228 | 🔵 | Design | `cli.py:889` | `_suggest_fixes` picks first numeric field — irrelevant fields produce misleading guidance |
| 229 | 🔵 | Design | `helpers/compliance.py:213` | PDF uses `cp1252` — non-Latin characters silently corrupted in regulatory PDFs |
| 230 | 🔵 | Security | `primitives/roles.py:51` | Role integer constants are mutable class attributes — privilege escalation via patch |
| 231 | 🔵 | Info | `mesh/authenticator.py:384` | `token_preview=token[:16]` exposes raw JWT bytes in error logs |
| 232 | 🔵 | Logic | `nlp/validators.py:922` | `DateValidator` treats naive datetimes as UTC — 14-hour error for non-UTC callers |
| 234 | 🟠 | **ARCH** | `guard.py` + `circuit_breaker.py` | `CircuitBreakerState` + caller `state` = fail-open circuit bypass |

---

## PART 12 — TRANSLATOR DEEP AUDIT (Fourth Pass, 2026-06-04)

> Full adversarial read of all 7 translator implementations plus redundant.py tail.
> All 7 files: anthropic.py, cohere.py, gemini.py, mistral.py, ollama.py, openai_compat.py, llamacpp.py.
> Also: bedrock.py, vertexai.py, json.py, prompt.py, sanitise.py, injection\_filter.py.
> Angles: prompt injection, SSRF, API key exposure, retry-on-auth-error, race conditions.

### 🟠 #235 — All Translators — Model Name Logged Verbatim — Log Injection via Attacker-Controlled `model` Parameter

**Files**: `anthropic.py:129`, `openai_compat.py:147`, `cohere.py:159`, `gemini.py:222`, `mistral.py:172`, `ollama.py:148`, `llamacpp.py:154`

```python
raise LLMTimeoutError(
    f"Anthropic model '{self.model}' unreachable after {attempts} attempt(s): {exc}",
)
```

`self.model` is fully caller-controlled and never validated. A model name containing `\n`, `\r`, or ANSI escape sequences lands verbatim in log aggregators (Splunk, Datadog, CloudWatch), enabling log injection and SIEM query bypass. This is systemic across every translator that embeds `self.model` in exception strings.

---

### 🟠 #236 — `anthropic.py:136`, `openai_compat.py:147` — Raw API Error Body in Exception Messages — Account Metadata / Quota Leak to Third-Party Log Aggregators

```python
raise ExtractionFailureError(
    f"[{self.model}] Anthropic API error {exc.status_code}: {exc.message}"
)
```

`exc.message` is the raw Anthropic/OpenAI API error response. On 401/403 errors these responses sometimes include account tier, quota details, or partial key information. Embedding `exc.message` propagates it to Sentry, Datadog, and any other error aggregator the application uses.

---

### 🟡 #244 — `gemini.py:258-260` — Multi-Tenant API Key Race: Lock Released Before HTTP Call

```python
with _GEMINI_CONFIGURE_LOCK:
    genai.configure(api_key=self._api_key)   # Thread A sets KEY_A
    model_client = genai.GenerativeModel(...)
# Lock released HERE
# Thread B sets KEY_B via configure()
# Thread A calls generate_content — may use KEY_B in some SDK versions
```

`_GEMINI_CONFIGURE_LOCK` is released before the actual API call. In SDK versions that read the global key at call time rather than at model construction time, Thread A's request is billed to Thread B's API key. In multi-tenant deployments, this is a cross-tenant billing and data leakage issue.

---

### 🟡 #245 — `cohere.py:94` — Retry on HTTP 429 Without Respecting `Retry-After` Header

`TooManyRequestsError` (HTTP 429) is included in `_retryable`. The retry delay is `1→2→4s` — far shorter than the `Retry-After` header value (often 60s+). Three rapid retries on a rate-limited request produce three additional 429s, accelerating quota exhaustion and potentially triggering temporary account suspension.

---

### 🟡 #246 — `mistral.py:131-136` — Retry on Auth Failure: `SDKError` Is Base Class for ALL Mistral Errors Including 401/403

`SDKError` covers all Mistral SDK errors. The retry loop retries authentication failures (401/403) three times with backoff before giving up. Auth errors are not transient — retrying them wastes API budget and delays failure signals.

---

### 🟡 #248 — `_json.py:92-94` — Raw LLM Response Snippet (300 chars) in Exception Messages — PII Propagation to Error Aggregators

```python
raise ExtractionFailureError(
    f"...Raw response (first 300 chars): {raw[:300]!r}"
)
```

If the LLM echoes PII from the user's prompt in its response before producing invalid JSON, those 300 characters propagate through the exception to Sentry, Datadog, and any other error aggregator without redaction.

---

### 🟡 #249 — `bedrock.py:276-313` — Full Response Body in Exception Messages

```python
f"[{self.model}] Bedrock returned an empty response body: {body}"
f"[{self.model}] Bedrock Converse returned empty content: {response}"
```

`body` and `response` are the full parsed JSON response dicts from Bedrock. These may contain metadata fields, request IDs, quota details, or reflected user input. Should be logged at DEBUG with keys only.

---

### 🟡 #250 — `redundant.py:455` — Injection Scorer Uses Pre-Sanitised `text` — Unicode Homoglyph High-Entropy Check Bypassed

The injection scorer's high-entropy token check runs on original `text`, not `sanitised_text`. Full-width base64 characters (`Ａ`, `Ｂ` etc.) don't match `[A-Za-z0-9+/]{20,}` in the original text, bypassing the entropy check even though the sanitised version would be normal ASCII base64.

---

### 🟡 #252 — `bedrock.py:230-238` — Llama 2 Chat Format Applied to Llama 3 Models — System Prompt Exposed as User Content

`_build_llama_payload` uses `<s>[INST] <<SYS>>...` (Llama 2 format). Bedrock-hosted Llama 3 models (`meta.llama3-*`) use `<|begin_of_text|><|start_header_id|>system<|end_header_id|>...`. The Llama 2 format applied to Llama 3 causes the system prompt to be treated as user content — the model never sees it as authoritative system instructions, and the attacker can potentially extract the schema by asking the model to "repeat the user message."

---

### 🔵 #253 — `llamacpp.py:97-112` — `self._llm` Never Assigned After Cache Hit — Dead Code on Fast Path

```python
if self._llm is not None:
    return self._llm    # ← dead: self._llm is never set
```

`_get_llm` reads `self._llm` on every call but never assigns it after the first cache population. The fast-path check is permanently dead code, causing every call to acquire `_MODEL_CACHE_LOCK` unnecessarily.

---

### 🔵 #254 — `cohere.py:190-230` — `asyncio.run()` in `__del__` Can Propagate `SystemExit`/`KeyboardInterrupt` During Shutdown

`__del__` calls `asyncio.run(self.aclose())`. `asyncio.run()` can propagate `SystemExit` and `KeyboardInterrupt` (`BaseException` subclasses) which are not caught by `except Exception`. During Python interpreter shutdown, `asyncio` module may be partially torn down, causing `AttributeError: module 'asyncio' has no attribute 'run'`.

---

### 🔵 #255 — `redundant.py:347` — 512-Char Input Limit Only Enforced in Consensus Path — Individual Translators Accept Unlimited Input

`sanitise_user_input` is called only in `extract_with_consensus`. Callers who use `AnthropicTranslator.extract()` directly bypass the 512-char limit entirely, enabling long-prompt injection and context manipulation attacks.

---

### 🔵 #256 — `injection_filter.py:174` — `m.group()` Embedded in `InjectionBlockedError` Message — Log Injection via Matched Text

```python
return (True, f"... matched={m.group()!r}")
```

The matched text from the user's input is embedded in the rejection message. User-controlled matched content containing `\n`, ANSI escapes, or fake log-line patterns propagates into `InjectionBlockedError` strings which are then logged.

---

### 🔵 #257 — `redundant.py:314-324` — Entry-Point Scorer Loaded Without Signature Verification — Malicious Package Can Register Scorer

```python
_scorer_fn = _ep.load()
```

`importlib.metadata.entry_points()` returns all `pramanix.injection_scorers` entry-points from all installed packages. A malicious package that registers a matching entry-point name executes arbitrary code when `_scorer_fn = _ep.load()` is called. No signature verification, no hash pinning.

---

### 🔵 #258 — `_sanitise.py:147` — `findall()` Match Results Embedded in Warnings — Log Injection via Injection Pattern Matches

```python
warnings.append(f"injection_patterns_detected: {matches}")
```

`matches` from `findall()` contains user-controlled matched strings. When forwarded to the scorer and logged, attacker-controlled content appears verbatim in warning messages.

---

## SUMMARY TABLE (Findings #235–#258)

| # | Severity | Category | File | Finding |
| - | -------- | -------- | ---- | ------- |
| 235 | 🟠 | Security | All translators | Model name in exception strings — log injection |
| 236 | 🟠 | Info | `anthropic.py:136`, `openai_compat.py:147` | Raw API error body in exceptions — account metadata leak |
| 244 | 🟡 | Race | `gemini.py:258` | Multi-tenant API key race in legacy `genai.configure()` path |
| 245 | 🟡 | Design | `cohere.py:94` | Retry on HTTP 429 without `Retry-After` — quota exhaustion |
| 246 | 🟡 | Design | `mistral.py:131` | Retry on auth failure (SDKError base includes 401/403) |
| 248 | 🟡 | Info | `_json.py:92` | Raw LLM response snippet (300 chars) in exceptions — PII leak |
| 249 | 🟡 | Info | `bedrock.py:276,313` | Full Bedrock response body in exception messages |
| 250 | 🟡 | Logic | `redundant.py:455` | Scorer runs on pre-sanitised text — homoglyph entropy check bypassed |
| 252 | 🟡 | Security | `bedrock.py:230` | Llama 2 format on Llama 3 models — system prompt exposed as user content |
| 253 | 🔵 | Perf | `llamacpp.py:97` | `self._llm` never assigned — dead code on fast path, lock on every call |
| 254 | 🔵 | Design | `cohere.py:190` | `asyncio.run()` in `__del__` — `SystemExit` propagation during shutdown |
| 255 | 🔵 | Design | `redundant.py:347` | 512-char limit bypassed when individual translators called directly |
| 256 | 🔵 | Security | `injection_filter.py:174` | `m.group()` in rejection message — log injection |
| 257 | 🔵 | Supply chain | `redundant.py:314` | Entry-point scorer loaded without signature verification |
| 258 | 🔵 | Security | `_sanitise.py:147` | `findall()` matches in warnings — log injection |

---

## PART 13 — GUARD, WORKER, CIRCUIT BREAKER DEEP AUDIT (Fourth Pass, 2026-06-04)

> Full read of guard.py lines 600–1674, worker.py lines 600–1018, circuit_breaker.py full 1340 lines.
> Angles: async path TOCTOU, verify\_stream bypass, process-mode audit gap, fire-and-forget Redis clear,
> HALF\_OPEN race, shed-limiter leak, ISOLATED thundering herd on TTL expiry.

### 🟠 #259 — `guard.py:952-989` — `max_input_bytes` Check Uses `default=str` Coercion — Large Nested Objects Pass Size Check, Cause Downstream Memory Exhaustion

```python
_payload_size = len(
    _json_size.dumps({"i": _raw_intent, "s": _raw_state}, default=str).encode()
)
```

`default=str` coerces any non-JSON-serializable object to its `str()` representation (e.g., an object address like `<MyObj at 0x7f...>`). A deeply nested custom object with a 10-char `str()` but 10 MB of actual data passes the byte check, then arrives at the Z3 solver as an enormous in-memory structure. The size check fires on the pre-coercion compact representation, not on the actual allocation the solver receives.

---

### 🟠 #260 — `guard.py:686-700` — Action Authorized Before Audit Sink Records the Decision — Audit Gap on Sink Failure

```python
decision = self._sign_decision(self._verify_core(intent, state))
...
time.sleep(_left)          # timing pad
self._emit_to_sinks(decision)   # audit AFTER timing pad
return decision                 # caller already has authorized decision
```

The decision is returned to the caller after the timing pad but before `_emit_to_sinks` completes. If a sink raises or hangs, the action has already been authorized with no durable audit record. In a financial system, the transfer executes but no audit log entry exists.

---

### 🟠 #261 — `guard.py:2007-2035` — `verify_stream` Bypasses Signing, Audit Sinks, Governance Gates, Timing Pad, and Input Size Check

`verify_stream` calls `_parse_and_verify_buffer` which calls `_verify_core` directly. Every governance gate (`_apply_governance_gates`), signing (`_sign_decision`), sink emission (`_emit_to_sinks`), timing pad, and `max_input_bytes` check is bypassed. The buffer grows to `max_tokens` strings with no per-token byte cap — `max_tokens=4096` × 1 MB/token = 4 GB heap allocation. IFC gates, privilege gates, and oversight workflow are never applied to streaming decisions.

---

### 🟠 #263 — `circuit_breaker.py:711-781` — `DistributedCircuitBreaker` Has No HALF\_OPEN State — Thundering-Herd Restart When Redis TTL Expires

The `DistributedCircuitBreaker` has no HALF\_OPEN probing. When the Redis key expires after TTL (default 300s), `get_state` returns default CLOSED. All replicas simultaneously admit traffic without any single-probe safety valve. If the underlying system is still under pressure, all replicas simultaneously hammer it and immediately re-trip to OPEN, entering an exponential failure-count inflation cycle (see #83).

---

### 🟠 #265 — `circuit_breaker.py:804-808` — `DistributedCircuitBreaker.reset()` Fire-and-Forgets Redis Clear — ISOLATED Persists Across Process Restart

```python
def reset(self) -> None:
    self._local_state = CircuitState.CLOSED
    self._backend.clear(self._config.namespace)   # schedules background task
```

When called from async context, `backend.clear()` schedules `_async_clear` as a fire-and-forget `asyncio.ensure_future` task. If the process restarts before the task executes, the Redis key retains `ISOLATED`. On restart all replicas immediately read ISOLATED and block all traffic — the system is unrecoverable via `reset()` without manually deleting the Redis key.

---

### 🟠 #266 — `guard.py:1532-1536` — Resolver Cache Cleared Between Steps 1–4 and Worker Dispatch — Cross-Request Contamination Window

```python
        finally:
            _resolver_registry.clear_cache()    # clears at step 4
    # Steps 5-6: dispatch to worker pool starts HERE
    pool = self._pool
```

The `finally` block clears `_resolver_registry` after Steps 1–4 but before the worker dispatch. If `_resolver_registry` uses the async Task as an isolation key and another concurrent Task's resolver state is stored in the same key space, clearing it mid-flight contaminates the other request. Two concurrent `verify_async` calls can see each other's resolved field values.

---

### 🟡 #268 — `worker.py:999-1023` — New Executor Goes Live Before Warmup — Real Requests Hit Cold-Start Z3 Workers During Recycle

The new executor is installed under `self._lock` at line 1010, making it immediately visible to concurrent `submit_solve` calls. Warmup runs after the lock is released — real requests race against warmup and hit cold Z3 JIT, causing latency spikes that increment `_consecutive_pressure` on the circuit breaker, potentially tripping it open during normal recycling.

---

### 🟡 #269 — `circuit_breaker.py:342-353` — HALF\_OPEN Double-Probe Race: `_probing=False` Cleared Before `_record_solve` — Second Probe Can Fire on Already-Failed Circuit

```python
    finally:
        if is_probe:
            async with self._lock:
                self._probing = False     # step A
solve_ms = (time.monotonic() - t0) * 1000
async with self._lock:
    self._record_solve(solve_ms)          # step B (transitions OPEN/CLOSED)
```

Between step A (`_probing=False`) and step B (`_record_solve`), another coroutine can enter `verify_async`, see `HALF_OPEN` + `_probing=False`, claim the probe slot (`_probing=True`), and begin probing. The first probe's `_record_solve` then transitions to OPEN/ISOLATED while the second probe is already in flight. Two probes run simultaneously on a circuit that should allow exactly one.

---

### 🟡 #270 — `circuit_breaker.py:739-779` — Distributed Failure Count Never Reset After Push — Delta Accumulates Across Syncs (Existing #83 Root Cause Detail)

`_local_failure_count` is reset to `agg.failure_count` on `_sync_state`, not to 0. On the next pressure event, the replica pushes `delta_failures=self._local_failure_count` (which equals global count + local delta). Redis merges `existing + delta = 2×global + local`. With N replicas each syncing and pushing, counts grow O(N²) per pressure event.

---

### 🟡 #272 — `circuit_breaker.py:339-351` — HALF\_OPEN Permanently Stuck If `_record_solve` Never Reached After Exception

If `self._guard.verify_async()` raises an unhandled exception (bypassing Guard's catch-all, e.g. `asyncio.CancelledError`), the `finally` clears `_probing=False` but `_record_solve` on line 351 is never called. The breaker stays in `HALF_OPEN` forever with `_probing=False`, allowing infinite sequential probes that never resolve the state.

---

### 🔵 #274 — `guard.py:1991-2003` — `verify_stream` No Per-Token Byte Cap — Quadratic Memory on Large Tokens

```python
buffer += token    # O(n) string copies, no byte limit
```

`max_tokens` counts strings, not bytes. Each token can be arbitrarily large. `buffer += token` creates a new string on every iteration — O(n) total allocations. An adversary sending `max_tokens=4096` tokens of 1 MB each produces a 4 GB buffer.

---

### 🔵 #275 — `worker.py:648-682` — Unbounded Drain-Thread Accumulation Under High-Frequency Recycling

Each `_recycle()` call starts a new daemon drain thread calling `executor.shutdown(wait=True)`. Under sustained load with `max_decisions_per_worker=10_000` at high RPS, recycling fires frequently, creating O(rate / max_decisions_per_worker) daemon threads per second, each living for `grace_s=10` seconds.

---

### 🟡 #287 — `exceptions.py:175` — `pramanix.ValidationError` Name Collides With `pydantic.ValidationError` — Callers Catch the Wrong Exception

```python
class ValidationError(GuardError):
    """Wraps pydantic.ValidationError..."""
```

The same name at the same API level causes `from pramanix import ValidationError` to be shadowed by `from pydantic import ValidationError` in the same scope, or vice versa. A caller with `except pydantic.ValidationError` never catches the Pramanix-wrapped version — Guard validation failures propagate uncaught.

---

### 🟡 #290 — `governance_config.py:61-94` — Governance Fields Typed `Any | None` — Wrong Types Silently Accepted Until Deep Attributeerror

```python
ifc_policy: Any | None = field(default=None)
capability_manifest: Any | None = field(default=None)
```

Passing `capability_manifest="wrong"` (string instead of `CapabilityManifest`) raises no error at construction. The `AttributeError` surfaces deep inside `_apply_governance_gates`, where it is caught by the fail-safe and becomes a BLOCK. Debugging is opaque — no indication at configuration time that the wrong type was passed.

---

### 🟡 #291 — `audit/verifier.py:62` — Key Length Checked in Characters, Not Bytes — Semantic Mismatch in Minimum Entropy Guarantee

```python
if len(raw) < self._MIN_KEY_LENGTH:   # len() counts Unicode code points
```

A key of 32 multi-byte Unicode characters (e.g., 32 emoji = 128 bytes) passes with `len=32`, providing much more entropy than intended minimum. Conversely, the docstring says "at least 32 characters" but HMAC security depends on entropy in bytes. The check conflates character count with byte entropy.

---

### 🔵 #297 — `natural_policy/verifier.py:213-219` — Only First Operator Checked in Compound Expressions — Second Operator in AND Constraints Not Verified

```python
m = re.search(r"(>=|<=|>|<|==|!=)", reconstructed)   # finds only FIRST
```

For `amount >= 0 AND amount <= 50000`, only `>=` is extracted. The LLM annotation "amount must not exceed 50000" correctly describes `<=` but not `>=`. The MetaVerifier finds no synonym match for `>=` in the annotation and raises a false-positive verification failure — or in the inverse case, a false-negative for a hallucinated second constraint.

---

### 🔵 #298 — `compliance/oracle.py:272-285` — `register_mapping` Without Lock Around the `framework` Check — TOCTOU on Concurrent Registrations

```python
if mapping.framework is not framework:   # check outside lock
    ...
with self._lock:
    self._registry[framework].append(mapping)   # append inside lock
```

Between the framework check and the lock acquisition, another thread can unregister or change the framework entry. Low probability but present under concurrent multi-module registration at startup.

---

### 🔵 #301 — `exceptions.py:464-491` — `FlowViolationError` Typed `object` for IFC Label Fields — No Type Safety at Definition Site

```python
def __init__(self, message: str, *, source_label: object = None, ...):
```

`object` type annotations prevent mypy from type-checking calls. Passing a string where a `TrustLabel` is expected silently produces nonsense in the error message with no diagnostic.

---

### 🔵 #302 — `helpers/serialization.py:68-125` — `flatten_model` Exported in Submodule but Not in `pramanix.__all__` — Inconsistent Public Surface

`flatten_model` produces `PolicyCompilationError` messages including the model type name and full field path. It is reachable via `from pramanix.helpers.serialization import flatten_model` but has no stability annotation in the top-level namespace.

---

### 🟠 #310 — `requirements/production.txt` Is Empty — `pip install --require-hashes` Docker Build Installs Nothing

```dockerfile
RUN pip install --require-hashes --no-cache-dir -r /tmp/requirements.txt
```

`requirements/production.txt` contains only comments — zero actual package entries. `pip install --require-hashes -r empty-file` succeeds but installs nothing. The SLSA Level 3 supply-chain integrity guarantee (hash-pinned installation) is not enforced. The production image may be relying on a different installation mechanism while falsely appearing to use `--require-hashes`.

---

### 🟠 #311 — `src/pramanix/compiler.py:997` — `assert` for Compiler Invariant — Stripped by `-O` — Wrong Z3 Constraint Silently Generated

```python
assert not isinstance(rhs_val, list)
return self._compile_scalar_comparison(cond, lhs_field, lhs_node, label, rhs_val)
```

`assert` is silently eliminated by `python -O` or `PYTHONOPTIMIZE=1`. When stripped, `_compile_scalar_comparison` receives a `list` as `rhs_val`, producing an incorrect Z3 constraint — potentially an always-satisfiable one that makes the guard ALLOW a prohibited action. The ruff config globally silences `S101` across `src/`, preventing automated detection.

---

### 🟠 #312 — `src/pramanix/execution_token.py:1089` — `assert self._loop_thread is not None` — Stripped by `-O` — `AttributeError` Leaks Background Thread on Shutdown

```python
assert self._loop_thread is not None
self._loop_thread.join(timeout=10.0)
```

When stripped, `None.join(timeout=10.0)` raises `AttributeError`, aborting clean shutdown of the Postgres token replay store. The background event loop thread and database connection pool are leaked on every pod restart in production with `-O` optimization.

---

### 🟠 #313 — `pyproject.toml:407` — Global `filterwarnings = ["ignore:GuardConfig:UserWarning"]` Silences Production-Mode Security Warnings in ALL 4701 Tests

```ini
filterwarnings = [
    "ignore:GuardConfig:UserWarning",
```

`GuardConfig` emits `UserWarning` when production-unsafe configurations are detected (`signer=None`, empty `audit_sinks`, InMemory sinks in production). This global filter suppresses those warnings across all tests. Tests that verify production warning emission may be passing vacuously. If a future change breaks the production warning, no test will catch it.

---

### 🟠 #314 — `Dockerfile.slim` — Runs as Root, No HEALTHCHECK, Editable Install, Unpinned Base Digest

```dockerfile
FROM python:3.13-slim-bookworm
RUN pip install --no-cache-dir -e ".[all]"
CMD ["python", "-m", "pramanix"]
# no USER directive, no HEALTHCHECK
```

Unlike `Dockerfile.production` (which enforces UID 10001 and health checks), `Dockerfile.slim` runs as root with an editable install. A container escape or dependency compromise gives root access to the host kernel. An attacker who can write to `/app/src/pramanix/` modifies live production code without a redeploy. No label marking it as dev-only.

---

### 🟠 #315 — `.github/workflows/ci.yml:800` — `ollama/ollama:latest` Service Container — Unpinned Docker Image in CI

```yaml
services:
  ollama:
    image: ollama/ollama:latest
```

`latest` is not pinned to a digest. A compromised or backdoored Ollama image silently executes as a service container with network access to the GitHub Actions runner. A malicious container can reach runner metadata APIs and exfiltrate `GITHUB_TOKEN`.

---

### 🟠 #316 — No `SECURITY.md` — No Responsible Disclosure Policy — Vulnerability Reporting Undefined

No `SECURITY.md` at repository root. For a security-focused library with `Topic :: Security` classifier, the absence of any responsible disclosure policy means: researchers who find bugs have no documented channel; vulnerabilities may be publicly disclosed without a coordinated window; enterprise users see this as a supply-chain risk signal.

---

### 🟠 #317 — `pyproject.toml:297` — `S101` (assert-used) Globally Silenced for All `src/` Code — Production `assert` Statements Not Detected by Linter

```toml
"S101",    # assert used — acceptable in tests and warmup
```

This `ignore` covers all of `src/`, not just tests. Production security-critical `assert` statements (#311, #312) pass `ruff` checks undetected. The justification comment is incorrect — the ignore should be scoped to `tests/` only.

---

### 🟡 #318 — `tests/integration/conftest.py:127,152`, `tests/unit/conftest.py:60` — Alpine Containers in Python Conftest Bypass the Alpine-Ban CI Gate

```python
with PostgresContainer("postgres:16-alpine") as pg:
with RedisContainer("redis:7-alpine") as redis:
```

The `alpine-ban` CI gate scans `Dockerfile*` and `docker-compose*` but not Python source files. These Alpine service containers are invisible to the gate, creating a conceptual inconsistency: future contributors may see Alpine as "acceptable" from test code and apply it to a Dockerfile.

---

### 🟡 #319 — `.github/workflows/release.yml:220` — `sigstore/gh-action-sigstore-python@v3` — Mutable Tag in Release Signing Step

```yaml
uses: sigstore/gh-action-sigstore-python@v3
```

A compromised Sigstore action could sign artifacts with a different key, produce fraudulent `.sigstore.json` bundles, or exfiltrate the OIDC token used for both PyPI and Sigstore signing.

---

### 🟡 #320 — `pyproject.toml` Dev Dependencies Use `>=` With No Upper Bound — Dependency Confusion Attack Surface

```toml
boto3 = ">=1.34"
cohere = ">=5.0"
google-generativeai = ">=0.7"
```

A supply chain attack publishing `boto3==9.0.0` is auto-resolved. In CI with AWS integration tests, this executes with `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` available.

---

### 🟡 #321 — `pyproject.toml:396` — `addopts = "--ignore=tests/perf"` — Performance-Critical Code Paths Excluded From 98% Coverage Gate

```ini
addopts = "--ignore=tests/perf"
```

`tests/perf` is permanently ignored by default pytest and excluded from the coverage job. Hot paths in `fast_path.py`, `worker.py`, and solver dispatch may achieve 98% coverage without any perf-path coverage. Performance regressions in these paths go undetected.

---

### 🟡 #322 — Dual Publish Workflows (`release.yml` + `publish.yml`) Both Trigger on Same Tag — Race Condition, Divergent SLSA Artifacts

Both workflows trigger on `push` of `v[0-9]+.[0-9]+.[0-9]+` tags and both run `pypa/gh-action-pypi-publish`. If `publish.yml` wins the race, the release has no SBOM and no Sigstore signatures — the SLSA Level 3 guarantees are void. The two workflows use different Poetry versions (`latest` vs `1.8.3`), potentially producing different wheel hashes for the same source.

---

### 🟡 #323 — `ci.yml` (8 locations) — `poetry config virtualenvs.create false` — System Python Pollution Across Concurrent CI Jobs

All CI jobs install into the system Python interpreter. Concurrent jobs that install different extras can produce nondeterministic dependency resolutions. The SAST job's `pip-audit` scans a Python environment that subsequent concurrent jobs may modify — the scan result is not representative of the final deployed environment.

---

### 🟡 #324 — `tests/integration/conftest.py:160` — Hardcoded Vault Root Token in Version Control

```python
_VAULT_ROOT_TOKEN = "pramanix-test-root-token"
```

A known, version-controlled root token. Secret scanning tools ingesting this repo flag it as a potential leaked credential, creating false-positive noise that desensitises the team to real leaks.

---

### 🟡 #325 — `.github/dependabot.yml:4` — `package-ecosystem: "pip"` Used for a Poetry Project — `poetry.lock` Never Updated by Dependabot

```yaml
- package-ecosystem: "pip"
  directory: "/"
```

Dependabot's `pip` ecosystem reads `pyproject.toml` version constraints but does not understand `poetry.lock`. Dependabot PRs widen constraints in `pyproject.toml` but never update `poetry.lock` — the actual pinned dependency versions are never bumped automatically. Security patches to locked transitive dependencies are silently missed. Fix: use `package-ecosystem: "poetry"`.

---

### 🟡 #326 — `tests/integration/conftest.py:231` — `AZURE_CLIENT_SECRET` Variable Name in pytest Skip Reason — CI Artifact XML Leaks Expected Secret Name

```python
reason=(
    "Azure live tests require AZURE_KEYVAULT_URL, AZURE_TENANT_ID, "
    "AZURE_CLIENT_ID, AZURE_CLIENT_SECRET to be set"
)
```

pytest skip reasons appear in JUnit XML reports uploaded as CI artifacts. An attacker who reads artifact XML knows exactly which Azure credential variables are expected, reducing credential-harvesting search space.

---

### 🔵 #327 — `release.yml:64`, `publish.yml:85-86` — `${{ github.ref_name }}` Unquoted in Shell — Latent Injection if Tag Pattern Expands

`github.ref_name` is expanded at the workflow level before the shell runs it, unquoted. Current tag pattern `v[0-9]+.[0-9]+.[0-9]+` is safe. If future tag patterns include non-alphanumeric characters (e.g., release candidates `v1.0.0-rc.1`), shell injection becomes possible. Pin the pattern and add quoting.

---

### 🔵 #328 — `setup.cfg` — Conflicting `pycodestyle` Configuration Alongside `ruff`

```ini
[pycodestyle]
ignore = E221,E226,W503,W504
```

`pycodestyle` is a legacy tool; `ruff` handles all E/W rules. IDE plugins running `pycodestyle` see different rules from `ruff check`, allowing code style patterns that `ruff` would flag to slip through.

---

### 🔵 #329 — `Dockerfile.dev` — Root-Owned Binaries After `USER 10001` Drop

```dockerfile
RUN pip install ...   # as root
USER 10001
ENTRYPOINT ["python", "-m", "pytest"]
```

Tool binaries in `/usr/local/bin` remain root-owned after the USER drop. Processes requiring write access to those directories (e.g., a pip self-update triggered by a test) fail with permission errors under UID 10001.

---

### 🔵 #330 — `tests/integration/test_zero_trust_identity.py:136` — Module-Level `SECRET = "zero-trust-jwt-signing-secret-minimum-32-chars"` Triggers Secret Scanners

```python
SECRET = "zero-trust-jwt-signing-secret-minimum-32-chars"
```

Secret scanning tools (truffleHog, git-secrets, GitHub push protection) flag this as a potential credential leak. Creates alert fatigue that desensitises the team to real leaks.

---

### 🔵 #331 — `pyproject.toml:327` — `S301` (Unsafe Deserialization) Globally Silenced in All Integration Tests

```toml
"tests/integration/*.py" = ["T20", "TCH", "E402", "S106", "S105", "S108", "S301"]
```

`S301` (unsafe `pickle` deserialization) is silenced across all integration tests. A future test that accidentally uses `pickle.loads()` on untrusted data is never flagged by the linter. Should be scoped to `test_serialization.py` only.

---

### 🔵 #332 — No `.github/CODEOWNERS` — CI Workflow Changes Have No Mandatory Reviewer

Without CODEOWNERS, modifications to `.github/workflows/*.yml` (including adding `pull_request_target` triggers, weakening `permissions:`, or adding new unpinned third-party actions) require no designated security reviewer. A contributor with write access to a branch can introduce supply chain vulnerabilities without mandatory review.

---

## FINAL SUMMARY TABLE (Findings #304–#332)

| # | Severity | Category | File | Finding |
| - | -------- | -------- | ---- | ------- |
| 310 | 🟠 | Security | `requirements/production.txt` | File is empty — `--require-hashes` Docker build installs nothing |
| 311 | 🟠 | Security | `compiler.py:997` | `assert` for compiler invariant — stripped by `-O` — wrong Z3 constraint silently generated |
| 312 | 🟠 | Security | `execution_token.py:1089` | `assert` on loop thread — stripped by `-O` — AttributeError on shutdown leaks thread |
| 313 | 🟠 | Security | `pyproject.toml:407` | Global `ignore:GuardConfig:UserWarning` silences production-mode warnings in all tests |
| 314 | 🟠 | Security | `Dockerfile.slim` | Runs as root, no HEALTHCHECK, editable install, unpinned base |
| 315 | 🟠 | Supply chain | `ci.yml:800` | `ollama/ollama:latest` unpinned service container — runner compromise risk |
| 316 | 🟠 | Security | (absent) | No `SECURITY.md` — no responsible disclosure policy |
| 317 | 🟠 | Security | `pyproject.toml:297` | `S101` globally silenced in `src/` — production `assert` not detected by linter |
| 318 | 🟡 | Design | `conftest.py:127,152` | Alpine containers in Python conftest bypass alpine-ban CI gate |
| 319 | 🟡 | Supply chain | `release.yml:220` | `sigstore-python@v3` mutable in release signing step |
| 320 | 🟡 | Supply chain | `pyproject.toml` dev deps | `>=` unbounded dev dependencies — dependency confusion attack surface |
| 321 | 🟡 | Coverage | `pyproject.toml:396` | `--ignore=tests/perf` — perf-critical paths excluded from 98% coverage gate |
| 322 | 🟡 | Design | `release.yml` + `publish.yml` | Dual publish workflows — race condition, divergent SLSA artifacts |
| 323 | 🟡 | Design | `ci.yml` (8 locations) | `virtualenvs.create false` — system Python pollution across concurrent CI jobs |
| 324 | 🟡 | Security | `integration/conftest.py:160` | Hardcoded Vault root token in version control |
| 325 | 🟡 | Security | `.github/dependabot.yml:4` | `pip` ecosystem for Poetry project — `poetry.lock` never updated by Dependabot |
| 326 | 🟡 | Privacy | `integration/conftest.py:231` | `AZURE_CLIENT_SECRET` in skip reason — appears in CI artifact XML |
| 327 | 🔵 | Security | `release.yml:64` | `github.ref_name` unquoted — latent shell injection on future tag pattern expansion |
| 328 | 🔵 | Design | `setup.cfg` | Conflicting `pycodestyle` config alongside ruff |
| 329 | 🔵 | Design | `Dockerfile.dev:119` | Root-owned binaries after `USER 10001` drop |
| 330 | 🔵 | Security | `test_zero_trust_identity.py:136` | `SECRET =` module-level constant triggers secret scanners — alert fatigue |
| 331 | 🔵 | Security | `pyproject.toml:327` | `S301` silenced globally in integration tests — pickle misuse undetected |
| 332 | 🔵 | Security | (absent) | No `CODEOWNERS` — CI workflow changes have no mandatory reviewer |

---

*332 total confirmed findings across all five passes.*
*Coverage: all 112 production source files, all translator implementations, all integrations,*
*all primitive modules, all audit/crypto/execution-token modules, all CLI commands,*
*natural\_policy compiler and verifier, compliance oracle, identity/memory/privilege modules,*
*helpers, exceptions hierarchy, public API surface, full CI/CD pipeline, all Dockerfiles,*
*pyproject.toml, dependabot.yml, test conftest files, supply chain action pins.*
*2026-06-04 — Fourth-pass bounty-hunter audit.*

---

## PART 16 — FINAL GAP-FILL: ALL REMAINING FILES (Fifth Pass, 2026-06-04)

> Complete glob of all 112 production source files. Read every file not previously covered:
> k8s/webhook.py, compiler.py (top-level), interceptors/grpc.py, interceptors/kafka.py,
> translator/base.py, translator/injection\_scorer.py, testing.py, validator.py,
> logging\_helpers.py, \_platform.py, primitives/common.py, helpers/type\_mapping.py,
> tests/helpers/solver\_stubs.py, tests/helpers/real\_protocols.py, audit/signer.py (confirmed).
> audit/signer.py \_canonicalize confirmed: signs exactly 7 of 17 Decision fields — as documented in #97.

### 🟠 #334 — `k8s/webhook.py:119` — Sync `guard.verify()` in Async FastAPI Endpoint — Event Loop Blocked During Z3 Solve

```python
async def validate(body: dict[str, Any] = ...) -> ...:
    decision = guard.verify(intent=intent, state=state)   # SYNCHRONOUS
```

The K8s admission webhook is an `async def` FastAPI handler. Calling synchronous `guard.verify()` blocks the event loop for the full Z3 solve duration. Under admission traffic all webhook requests queue behind each other. Must use `await guard.verify_async(...)`.

---

### 🟠 #335 — `k8s/webhook.py:150-155` — Full Policy Internals in K8s AdmissionReview Rejection Message — Permanent Disclosure in `kubectl describe` and Cluster Audit Logs

```python
violated = ", ".join(decision.violated_invariants or [])
message = (
    f"Pramanix guard blocked admission. Violated: [{violated}]. "
    f"Reason: {decision.explanation or 'policy violation'}"
)
```

K8s admission rejection messages are stored in `kubectl describe pod`, cluster Events, and immutable audit logs. The full `violated_invariants` and `decision.explanation` are disclosed to any K8s user who can read pod events — regardless of `GuardConfig.redact_violations`.

---

### 🟠 #336 — `compiler.py:606` — No Depth Limit on Nested `Rule.conditions` — Deep Nesting Causes `RecursionError` DoS at Guard Initialization

```python
conditions: list[Condition | Rule] = _PF(..., min_length=1)  # no max depth
```

`_compile_rule` recurses into nested `Rule` subtrees. A JSON policy with 1000+ nested levels exhausts Python's recursion limit at compile time. Since `PolicyCompiler.compile()` is called during `Guard.__init__()`, this crashes the service at startup before handling any requests.

---

### 🟡 #337 — `k8s/webhook.py` — No mTLS Validation of Kubernetes API Server Certificate — Any Pod Reaching Port 8443 Can Submit Arbitrary AdmissionReview Payloads

The webhook code does not validate that the caller is the legitimate Kubernetes API server (no client certificate check, no shared token, no IP allowlist). Any process reachable on the webhook port (e.g., a compromised pod via ClusterIP) can submit arbitrary `AdmissionReview` bodies and probe the policy.

---

### 🟡 #338 — `interceptors/grpc.py:134-140` — Full Policy Internals in gRPC Status Message — No `redact_violations` Check

```python
context.abort(
    interceptor._denied_code,
    f"Pramanix guard blocked RPC. Violated: [{violated}]. Reason: {decision.explanation}",
)
```

`violated_invariants` and `decision.explanation` are sent to the gRPC caller verbatim, regardless of `GuardConfig.redact_violations`.

---

### 🟡 #339 — `interceptors/kafka.py:162-171` — Full Policy Internals in DLQ Message Headers — Readable by Any DLQ Consumer

```python
headers = [("x-pramanix-block-reason", reason.encode())]
# reason = f"blocked: [{violated}] {decision.explanation or ''}"
```

`violated_invariants` and `decision.explanation` embedded in `x-pramanix-block-reason` Kafka header of every dead-lettered message. Any DLQ consumer, administrator, or log aggregator receives full policy internals with no `redact_violations` check.

---

### 🟡 #340 — `helpers/type_mapping.py:49-53` — Z3 Sort Objects Created at Module Import Time — Invalid Under Multiple Z3 Contexts

```python
_TYPE_MAP: list[tuple[type, z3.SortRef]] = [
    (bool, z3.BoolSort()),   # created at import time, default context
    (int, z3.IntSort()),
    ...
]
```

Module-level Z3 sort objects are tied to the default Z3 context. Any code path creating a new `z3.Context()` will find these cached sorts invalid, raising `Z3Exception` during policy compilation.

---

### 🔵 #341 — `primitives/common.py:69` — `FieldMustEqual` Label Generation Fails on Non-Identifier Values

```python
label = f"field_{field_obj.name}_must_equal_{value}"
```

`value = "PENDING REVIEW"` → label `"field_status_must_equal_PENDING REVIEW"` fails `^[a-z][a-z0-9_]*$` at runtime, raising `PolicyCompilationError` from a primitive that should have been validated at construction time.

---

### 🔵 #342 — `_platform.py:63-99` — `check_platform()` Skips ctypes Musl Heuristic — Edge Cases Missed

`check_platform()` → `_check_musl()` only checks `/lib/ld-musl-*.so.1` glob. The more comprehensive `is_musl()` adds a second heuristic: `ctypes.CDLL("libc.so.6")` failure → musl confirmed. If the glob path is absent but libc.so.6 fails to load (unusual Alpine configuration), `check_platform()` misses it and Z3 loads on musl, causing documented segfaults and 3–10× slowdowns.

---

## PART 16 SUMMARY (Findings #333–#342)

| # | Severity | Category | File | Finding |
| - | -------- | -------- | ---- | ------- |
| 334 | 🟠 | Perf | `k8s/webhook.py:119` | Sync `guard.verify()` in async endpoint — event loop blocked |
| 335 | 🟠 | Security | `k8s/webhook.py:150` | Policy internals in K8s AdmissionReview — permanent in kubectl + audit logs |
| 336 | 🟠 | DoS | `compiler.py:606` | No depth limit on nested Rule.conditions — RecursionError DoS at Guard init |
| 337 | 🟡 | Security | `k8s/webhook.py` | No mTLS validation — any pod can submit arbitrary AdmissionReview |
| 338 | 🟡 | Security | `interceptors/grpc.py:134` | Policy internals in gRPC status — no redact\_violations check |
| 339 | 🟡 | Security | `interceptors/kafka.py:162` | Policy internals in DLQ headers — readable by any DLQ consumer |
| 340 | 🟡 | Design | `helpers/type_mapping.py:49` | Z3 sorts at module import time — invalid under multiple contexts |
| 341 | 🔵 | Design | `primitives/common.py:69` | `FieldMustEqual` label generation fails on non-identifier values |
| 342 | 🔵 | Design | `_platform.py:63` | `check_platform()` misses ctypes musl heuristic |

---

## AUDIT COMPLETE — DEFINITIVE FINAL VERDICT

**342 total confirmed findings. All 112 production source files read in full.**

**Files confirmed covered in all 5 passes:**
All modules in: audit/, compliance/, helpers/, identity/, ifc/, integrations/, interceptors/,
k8s/, lifecycle/, memory/, mesh/, natural\_policy/, nlp/, oversight/, primitives/, privilege/,
translator/ (all 10 files including bedrock, vertexai, base), plus all top-level modules,
all test helpers, full CI/CD pipeline, all Dockerfiles.

**Confirmed clean** (grep-verified across all of `src/`): no `os.system`, no `subprocess shell=True`,
no `pickle.loads`, no `yaml.load` without Loader, no `random` for security, no `md5`/`sha1` for security,
no `verify=False`, no hardcoded secrets.

---

## PART 17 — CIRCUIT_BREAKER FIX LOG (2026-06-05, Sixth Wave)

> Fixed all HIGH-severity flaws in `circuit_breaker.py`.
> All fixes are production-level: no mocks, no stubs, no monkey-patches.
> Full test coverage added for every fix.

### ✅ FIXED — #55 — `DistributedCircuitBreaker` Docstring Lie About Default Backend

Updated class docstring to clearly state `backend` is **required** (raises
`ConfigurationError` if omitted).  Corrected the `Usage::` example to always
pass an explicit backend.  Previous text said "Defaults to InMemoryDistributedBackend"
which was the opposite of the code behaviour.

### ✅ FIXED — #263 — No HALF_OPEN State in `DistributedCircuitBreaker` (Thundering Herd)

Implemented distributed HALF_OPEN probing:
- Added `open_at_epoch: float` field to `_DistributedState` — wall-clock Unix
  epoch stored in Redis so all replicas can independently compute recovery
  elapsed time without sharing a monotonic clock baseline.
- Added `try_claim_probe(namespace) -> bool` to both backends: atomic `SET NX`
  in Redis, thread-safe `_probe_holders` dict in InMemory.
- Added `release_probe(namespace)` and `force_reset_state(namespace)` to both
  backends.  `force_reset_state` deletes the state Hash and the probe token
  key atomically (`DEL key, probe_key`), bypassing the conservative merge
  that prevents CLOSED from overwriting OPEN in a normal `set_state`.
- Updated `verify_async` to check `open_at_epoch` vs `time.time()` and attempt
  `try_claim_probe`.  Exactly one replica probes; all others return OPEN.
- On probe success: `force_reset_state` → CLOSED across all replicas.
- On probe abort (CancelledError): `release_probe` + push OPEN in finally.

### ✅ FIXED — #265 — `DistributedCircuitBreaker.reset()` Fire-and-Forget in Async

Added `reset_async()` method that **awaits** `force_reset_state` before returning.
`reset()` in sync context now runs `asyncio.run(reset_async())` (blocking, safe).
`reset()` in async context still schedules a task but emits a WARNING directing
callers to `reset_async()` and stores a task reference to prevent GC discard.

### ✅ FIXED — #269 — HALF_OPEN Double-Probe Race in `AdaptiveCircuitBreaker`

Root cause: `_probing = False` was cleared in one `async with self._lock` block
inside `finally`, then `_record_solve` ran in a separate `async with self._lock`
acquisition.  Between the two acquisitions, another coroutine could see
`HALF_OPEN + _probing=False` and claim a second probe slot.

Fix: merged both operations into a **single lock acquisition** in the `finally`
block.  For normal probe completion, `_record_solve` clears `_probing` atomically
with the state transition — no window exists for a second probe to enter.

### ✅ FIXED — #270 — Distributed Failure Count Inflation

Root cause: `_sync_state` set `self._local_failure_count = agg.failure_count`
(the cumulative total across all replicas).  One local pressure event then made
`_local_failure_count = aggregate + 1 >= threshold`, tripping OPEN immediately
once the global aggregate reached threshold — O(N²) inflation per sync cycle.

Fix: `_sync_state` now resets `self._local_failure_count = 0`.  Each replica
tracks only NEW failures since the last sync; `delta_failures=1` is pushed to
the backend on threshold trip, preserving correct aggregate accumulation.

### ✅ FIXED — #272 — HALF_OPEN Permanently Stuck After `CancelledError`

Root cause: `_record_solve` was placed after the `try/finally` block and was
unreachable on `CancelledError`.  The `finally` cleared `_probing=False` but
left state as `HALF_OPEN`, allowing infinite sequential probes that never
resolved the state machine.

Fix: all probe state management (clearing `_probing`, state transition) is now
inside the single `finally` lock acquisition.  On `CancelledError` with
`_exc_raised=True` and state `HALF_OPEN`, the finally block explicitly increments
`_open_episodes` and transitions to OPEN or ISOLATED.

---

## PART 18 — SEVENTH WAVE FIX LOG (2026-06-05)

> Seventh fix wave — production-level fixes for 7 confirmed open HIGH/MEDIUM flaws.
> All fixes use real implementations — no mocks, stubs, or monkeypatching.
> ruff clean + mypy strict 0 errors across all modified files.

### ✅ FIXED — #161 — `fast_path.py:account_frozen` — Integer > 1 Frozen Flags Not Caught

`account_frozen(field_name)` previously used `str(val).lower() in ("true", "1", "yes")`.
Integer values like `2`, `3` (multi-level freeze codes) returned `None` (not frozen).
Fixed: explicit type dispatch — `bool`, `int`, `float`, `Decimal` all checked against `!= 0`;
strings checked against an explicit "not frozen" frozenset. Any truthy value not in the
"not frozen" set is treated as frozen.

### ✅ FIXED — #311 — `compiler.py:1026` — `assert` Stripped by `-O` — Wrong Z3 Constraint Silently Generated

`assert not isinstance(rhs_val, list)` before `_compile_scalar_comparison` was eliminated
by `python -O`, silently passing a list to a scalar comparison and producing an incorrect
Z3 constraint that could make the guard spuriously ALLOW. Replaced with a proper
`if isinstance(...): raise PolicyCompilationError(...)` that cannot be stripped.

Also fixed two related pre-existing `list` → `list[Any]` type annotation gaps in the same
file (mypy `[type-arg]` errors at lines 618, 630).

### ✅ FIXED — #312 — `execution_token.py:1148` — `assert self._loop_thread is not None` Stripped by `-O`

`assert self._loop_thread is not None` before `self._loop_thread.join()` was eliminated
by `python -O`, causing `AttributeError: 'NoneType' has no attribute 'join'` on every
pod restart, silently leaking the background event loop thread and asyncpg connection pool.
Replaced with an explicit `if self._loop_thread is None: log.error(...); return`.

### ✅ FIXED — #317 — `pyproject.toml` — `S101` (assert-used) Globally Silenced in `src/`

`"S101"` was in the global ruff `ignore` list, preventing detection of `assert` statements
in all production source. Moved to per-file-ignores for `tests/unit/`, `tests/integration/`,
and `tests/adversarial/` only. Running `ruff check src/pramanix/ --select S101` now surfaces
all production assertions for inspection and replacement.

Found and fixed 2 additional `assert` statements in production source that the now-enabled
rule revealed (`audit/archiver.py:749`, `integrations/langgraph.py:189`).

### ✅ FIXED — #334 — `k8s/webhook.py:119` — Sync `guard.verify()` in Async FastAPI Handler

The Kubernetes admission webhook `validate()` was an `async def` FastAPI handler that called
synchronous `guard.verify()`, blocking the entire event loop for the full Z3 solve duration.
Under admission traffic, all concurrent webhook requests queued behind each other, triggering
Kubernetes webhook timeout retries. Fixed by replacing with `await guard.verify_async(...)`.

### ✅ FIXED — #335 — `k8s/webhook.py:150-155` — Policy Internals Disclosed Permanently in K8s Audit Log

The rejection `AdmissionReview.status.message` previously embedded `violated_invariants`
and `decision.explanation`, both of which are stored permanently in `kubectl describe pod`,
cluster Events, and the immutable Kubernetes audit log — visible to any kubectl user
regardless of RBAC and unredactable after the fact. The rejection message now contains only
`decision_id` (for correlation with the Pramanix audit sink). Operators who need violation
details must read the Pramanix structured logs or audit sink.

---

## PART 19 — EIGHTH WAVE FIX LOG (2026-06-05)

> Eighth fix wave — production-level fixes for 8 remaining open HIGH flaws.
> All fixes use real implementations — no mocks, stubs, or monkeypatching.

### ✅ FIXED — #33 — Merkle Archive Plaintext by Default — No Warning in Production Mode

`MerkleArchiver.__init__` now raises `ConfigurationError` when:
- `PRAMANIX_ENV=production`, AND
- no `archive_writer` is supplied, AND
- `PRAMANIX_MERKLE_ARCHIVE_KEY` is not set, AND
- `PRAMANIX_MERKLE_ARCHIVE_PLAINTEXT_OK=true` is not set.

Previous behaviour: only emitted a `log.warning()` regardless of environment.
New behaviour: raises `ConfigurationError` at startup in production — fail fast
rather than silently writing unencrypted audit data to disk.

### ✅ FIXED — #35 — `SemanticSimilarityGuard` Name Misleads (TF-IDF → Jaccard → now accurately documented)

Added `LexicalOverlapGuard` as the canonical correctly-named alias (accurate:
the default backend uses Jaccard word-overlap, not semantic embeddings).
Added `KeywordDensityScorer` as the canonical alias for `ToxicityScorer`
(accurate: keyword density ratio, not an ML model).
Both original names (`SemanticSimilarityGuard`, `ToxicityScorer`) are preserved
for backward compatibility. New code should use the accurate names.
Both are exported from `pramanix.nlp.validators`.

### ✅ FIXED — #48 — CI `continue-on-error: true` on Trivy SARIF Upload

Removed `continue-on-error: true` from the `Upload Trivy SARIF report` step in
`.github/workflows/ci.yml`.  When SARIF upload fails, CI now fails so operators
know that vulnerability findings are not visible in the GitHub Security tab.

### ✅ FIXED — #85 — Redundant Translator Lenient Mode — Non-Critical Fields Flow into Audit Unchecked

In `lenient` mode with explicit `critical_fields`, `extract_with_consensus` now
filters the returned intent dict:
- Only includes fields declared in `intent_schema.model_fields` (strips extras)
- For non-critical fields: only includes them if BOTH models agree on the value
- Excludes fields where only model A has a value (attacker-controlled via model A)
  and logs a WARNING with the list of excluded fields
This prevents injection through non-critical fields even when the attacker
controls model A's output for those fields.

### ✅ FIXED — #87 — `authenticate_and_bind()` No Guard Against Async Context

Added `asyncio.get_running_loop()` check at the start of
`MeshAuthenticator.authenticate_and_bind()`.  When called from within a running
event loop, emits `RuntimeWarning` directing the caller to use
`authenticate_and_bind_async()` instead.  Previously there was no detection or
warning — developers would silently block the event loop during JWKS HTTP fetches.

### ✅ FIXED — #313 — Global `filterwarnings` Silences Production-Mode Warnings in ALL Tests

Replaced `"ignore:GuardConfig:UserWarning"` (which silenced ALL GuardConfig
`UserWarning` globally across all 4701 tests) with precise filters targeting
only the InMemory component advisories that are expected/harmless in tests:
- `"ignore:InMemoryDistributedBackend is for testing only:UserWarning"`
- `"ignore:InMemoryAuditSink is for testing only:UserWarning"`
- `"ignore:InMemoryExecutionTokenVerifier is for testing only:UserWarning"`
- `"ignore:InMemoryApprovalWorkflow is for testing only:UserWarning"`
GuardConfig production-mode signer/sink warnings are now visible in tests,
allowing tests to verify that these warnings fire correctly.

### ✅ FIXED — #314 — `Dockerfile.slim` Runs as Root, No HEALTHCHECK

- Added `groupadd`/`useradd pramanix` (UID 10001, matching Dockerfile.production)
- Added `USER 10001` directive
- Added `HEALTHCHECK` with 30s interval and 10s timeout
- Added `LABEL` marking image as development-only
- Added prominent `⚠ DEVELOPMENT / EVALUATION USE ONLY` header

### ✅ FIXED — #316 — No `SECURITY.md` — No Responsible Disclosure Policy

Created `SECURITY.md` at repository root with:
- Supported versions table
- Coordinated disclosure process (email + 90-day window)
- In-scope and out-of-scope vulnerability types specific to Pramanix
- Response SLA (48h ack, 5-day triage, 10-day patch timeline)
- Bug bounty statement (no paid program, named credit in release notes)

---

## CONFIRMED CLEAN (Explicitly Verified)

- `os.system(` — none in `src/`
- `subprocess.* shell=True` — none in `src/`
- `pickle.loads(` — none in `src/`
- `yaml.load(` without Loader — none in `src/`
- `import random` / `random.` for security — none (all use `secrets.`)
- `hashlib.md5` / `hashlib.sha1` for security — none
- `verify=False` in HTTP clients — none in `src/`
- Hardcoded secrets (`sk-`, `api_key = "literal"`) — none in `src/`

---