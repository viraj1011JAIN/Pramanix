# Changelog

All notable changes to Pramanix are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **R1 — `DecisionVerifier` field alignment (active regression):** `VerificationResult.policy` renamed to `policy_hash`; the verifier now reads `payload["policy_hash"]` — the correct key written by `DecisionSigner._canonicalize()`. The old key `"policy"` never existed in the signed payload and always resolved to `""`. `issued_at` is documented as always `0` — `iat` was removed from the signed payload in the N6 determinism fix (it is not embedded in the JWS body; the value is available in `SignedDecision.issued_at` outside the HMAC boundary). CLI `verify-proof` JSON output updated from `"policy"` key to `"policy_hash"`; epoch timestamp display removed from text output.
- **R2 — `GuardConfig(otel_enabled=True)` silent no-op:** Added `_OTEL_AVAILABLE` tracking flag to the OpenTelemetry `try/except` import block (mirrors the existing `_PROM_AVAILABLE` flag). A `UserWarning` is now emitted in `__post_init__` when `otel_enabled=True` but `opentelemetry-sdk` is not installed, guiding users to `pip install 'pramanix[otel]'`.
- **R3 — `MerkleAnchor._build_root` recursion limit:** Replaced the recursive implementation with an iterative `while len(level) > 1:` loop. The recursive version would hit Python's default 1,000-frame call stack limit for production logs with more than ~1,000 decisions. The iterative version handles arbitrarily large batches with O(1) stack depth.

### Added

- `tests/unit/test_production_fixes_r1_r3.py` — 25 regression tests covering all three fixes: `VerificationResult` field round-trips (`policy_hash`, `issued_at=0`), OTel availability warning (patched `_OTEL_AVAILABLE`), and Merkle root correctness + large-batch stability (1,500 and 5,000 decision batches).
- **HMAC IPC integrity tests** (`tests/unit/test_worker_dark_paths.py`): 12 new tests covering the full `_EphemeralKey` / `_worker_solve_sealed` / `_unseal_decision` contract — repr redaction, pickle prevention, tampered tag detection, tampered payload detection, missing envelope keys, wrong seal key, and end-to-end `WorkerPool` HMAC failure returning `Decision.error(allowed=False)`.
- **Property-based tests for DSL and transpiler** (`tests/property/test_dsl_and_transpiler_properties.py`): 13 test groups (~500–1,000 Hypothesis examples each) covering commutativity, monotonicity, conjunction/disjunction semantics, negation complement, real/integer comparison agreement with Python decimal, set-membership exactness, bool field isolation, `named()` label preservation, empty invariant list is always SAT, and full violated-invariant attribution.
- **CLI verify-proof test suite** (`tests/unit/test_verify_proof_cli.py`): 50 new tests covering all branches of `_cmd_verify_proof` and `_cmd_audit`: token argument / stdin / whitespace / missing-key paths; valid/invalid/tampered token human and JSON output; `--fail-fast` on malformed JSON, missing-sig, and invalid-sig; directory-as-key-path error handling; empty log file.
- **`MIGRATION.md`**: step-by-step upgrade guide covering v0.7.x → v0.8.x → v0.9.x breaking changes (`VerificationResult.policy_hash`, `issued_at=0`, new `GuardConfig` fields and validations, OTel warning, HMAC process-mode IPC) and planned v1.0 stability contracts.
- **`docs/incident_response.md`**: operational playbook for P0–P3 incidents — false ALLOW, audit log tampering, elevated timeout rate, circuit breaker ISOLATED state, policy drift, HMAC seal violations, key rotation procedure, and structured log queries.
- **Legal disclaimers** added to regulatory primitive modules:
  - `src/pramanix/primitives/fintech.py`: BSA/AML, OFAC, PSD2, Reg. T primitives — not compliance advice.
  - `src/pramanix/primitives/healthcare.py`: HIPAA, Joint Commission, AAP/FDA primitives — not medical or clinical advice.
  - `src/pramanix/primitives/finance.py`: financial constraint primitives — not financial or compliance advice.
- **`GuardConfig.injection_threshold`** field (default `0.5`, env var `PRAMANIX_INJECTION_THRESHOLD`): configures the post-consensus injection confidence threshold in `RedundantTranslator`. Previously hardcoded; now operator-tunable and validated in `__post_init__` (must be in `(0.0, 1.0]`).
- **Digest-pinned base image** in `Dockerfile.production`: both builder and runner stages now reference `python:3.13-slim-bookworm` by SHA-256 multi-arch manifest digest, satisfying SLSA Level 3 supply chain integrity requirements.
- **`.github/dependabot.yml`**: automated weekly dependency update PRs for pip (runtime, security, and dev-tool groups) and GitHub Actions.

### Changed

- Claims/evidence alignment pass started for production-readiness hardening:
  - Added `docs/claims-matrix.md` with verification status (`verified`, `partially verified`, `unverified`, `wording too strong`) for key public claims.
  - `Guard.parse_and_verify()` now forwards `GuardConfig.injection_threshold` into dual-model consensus extraction instead of relying on extractor defaults.
  - README status contract corrected to match implemented API (`VALIDATION_FAILURE`, no `INJECTION_BLOCKED` status row).
- README: SLSA level corrected from Level 2 to Level 3 (matching `release.yml` job name and v0.5 CHANGELOG); supply chain section rewritten with SLSA requirements table and attestation details.
- `guard_config._resolver_registry` is now an alias for `pramanix.resolvers.resolver_registry` (the module-level singleton) instead of a private `ResolverRegistry()` instance. This was a silent bug: Guard's `clear_cache()` was operating on a different registry object than the one users registered resolvers into.
- **API contract lock (Phase 1.2 — complete rewrite)**: `tests/unit/test_api_contract.py` — 6 test classes (v0.9.0 snapshot) covering every dimension of the public surface:
  - `TestAllExportsLock` (6 tests): exact frozenset of 43 names in `pramanix.__all__`; checks list type, count, additions, removals, attribute reachability, and no private names.
  - `TestDirectImportSurface` (10 tests): verifies `from pramanix import X` works for every high-visibility name.
  - `TestSolverStatusLock` (8 tests): exact 9 members, wire values, iteration order, StrEnum identity contract.
  - `TestDecisionToDictLock` (17 tests): exact 13-key schema, per-field type semantics, cross-field invariants, hash determinism.
  - `TestDecisionFactories` (12 tests): all 6 factory methods, frozen invariant.
  - `TestGuardConfigFieldLock` (12 tests): exact 20 fields, 18 locked defaults, injection threshold range.
- `docs/api-compatibility.md`: comprehensive semver rules document (9 sections).
- **CI wheel/sdist install smoke gate (Phase 4.1)**: new `wheel-smoke` CI job inserted between `coverage` and `trivy` in `.github/workflows/ci.yml`.

### Security hardening (this release)

- HMAC IPC seal for async-process mode: worker results are now signed with an ephemeral `_EphemeralKey` and verified by `_unseal_decision` before being trusted. Prevents a compromised worker process from forging `allowed=True` results across the process boundary.
- `_EphemeralKey.__reduce__` raises `TypeError` on pickle — prevents accidental serialisation of the IPC key to disk or via `multiprocessing.Queue`.
- Legal disclaimers on regulatory primitives reduce liability exposure for deployments in regulated industries.

## [0.9.0] - 2026-04-16

### Added

- **15 Phase 12 hardening measures (H01-H15)** -- all fully unit-tested (`tests/unit/test_hardening.py`)
- **`ExecutionToken` / `ExecutionTokenSigner` / `ExecutionTokenVerifier`** (`src/pramanix/execution_token.py`) -- HMAC-SHA256 single-use intent binding token with configurable TTL (default 30 s). Prevents TOCTOU replay attacks (H01). `RedisExecutionTokenVerifier` provides distributed single-use enforcement via Redis SETNX.
- **`GuardConfig.solver_rlimit`** (default 10,000,000) -- Z3 elementary operation cap per solve call. Prevents non-linear logic bombs that stay within wall-clock timeout (H08). Env var: `PRAMANIX_SOLVER_RLIMIT`.
- **`GuardConfig.max_input_bytes`** (default 65,536 = 64 KiB) -- serialized intent + state payload size cap checked before Z3 is invoked. Prevents big-data DoS (H06). Env var: `PRAMANIX_MAX_INPUT_BYTES`.
- **`GuardConfig.min_response_ms`** (default 0.0, disabled) -- minimum wall-clock time before `verify()` returns, padding short decisions to prevent timing side-channel attacks (H13).
- **`GuardConfig.redact_violations`** (default False) -- replaces `explanation` and `violated_invariants` in BLOCK decisions returned to callers with a generic message. `decision_hash` is computed over real fields before redaction, preserving server-side audit integrity (H04).
- **`GuardConfig.expected_policy_hash`** (default None) -- SHA-256 fingerprint of the compiled policy. `Guard.__init__` raises `ConfigurationError` if the running policy does not match, detecting silent policy drift in distributed deployments (H09).
- **PPID watchdog daemon thread** (H02) -- spawned worker processes check `os.getppid()` every 5 seconds and call `os._exit(0)` if the parent is dead. Prevents zombie Z3 subprocesses.
- **Per-call `z3.Context()` thread safety** (H07) -- explicitly documented and tested. Every solver call creates and destroys its own Z3 context, preventing cross-thread context contamination.
- **`PersistentMerkleAnchor`** (H05) -- Merkle anchor with checkpoint callbacks to durable storage, preventing Merkle root loss on process crash.
- **`policy_hash` in `Decision.to_dict()`** (H14) -- embeds the policy fingerprint in the serialized decision, enabling audit tools to identify which policy version was active.
- **Fail-closed signing** (H15) -- any exception during Ed25519 signing produces `Decision.error(allowed=False)`, never an unsigned decision that bypasses audit.
- **Complete documentation suite** (`docs/`) -- 9 finalized documents:
  - `architecture.md` -- Two-phase model, worker lifecycle, Z3 context isolation, TOCTOU prevention, H01-H15
  - `security.md` -- 7-threat model, H01-H15 hardening table, cryptographic audit trail, key management, probabilistic failure analysis
  - `performance.md` -- Phase 4 benchmarks, 100M finance run results, latency budget, tuning guide
  - `policy_authoring.md` -- Complete DSL reference, 30 production rules, primitives quick reference, multi-policy composition
  - `primitives.md` -- All 38 primitives with SAT/UNSAT examples and regulatory citations
  - `integrations.md` -- FastAPI, LangChain, LlamaIndex, AutoGen guides
  - `compliance.md` -- HIPAA, BSA/AML, OFAC, SOC2, PCI DSS patterns with policy examples
  - `deployment.md` -- Docker, Kubernetes manifests, health probes, Phase 12 env vars
  - `why_smt_wins.md` -- Technical manifesto: probabilistic failure analysis, Z3 proof walkthrough, audit trail
- **Multi-worker benchmark infrastructure** (`benchmarks/`) -- 5-domain (finance, banking, fintech, healthcare, infra) orchestrator with rolling hash chain, Merkle anchoring, per-worker P99 and RSS tracking. Finance pilot run (1,002 decisions, 3 workers): 247 RPS, max P99 54.5 ms, 0 timeouts, 0 errors. Full-scale runs in progress.

### Changed

- **`GuardConfig`** -- 5 new hardening fields: `solver_rlimit`, `max_input_bytes`, `min_response_ms`, `redact_violations`, `expected_policy_hash`.
- **`Guard.__init__()`** -- validates `expected_policy_hash` against compiled policy fingerprint on construction.
- **`Guard.verify()`** -- applies `max_input_bytes` check before dispatching to worker, `min_response_ms` pad before returning.
- **`performance.md`** updated: "100M Finance Domain Benchmark" section renamed to "Multi-Worker Finance Pilot Run" and projection table removed -- the 1,002-decision pilot run does not constitute a 100M benchmark.

### Security

- H01: ExecutionToken prevents TOCTOU replay attacks with HMAC+TTL+single-use enforcement.
- H02: PPID watchdog prevents orphaned Z3 subprocess resource leaks after host crash.
- H03: 8-pattern Z3 warmup eliminates cold-start JIT spike (verified to eliminate 50-200 ms first-request latency).
- H04: `redact_violations` prevents oracle attacks where callers learn exact violated invariants.
- H06: `max_input_bytes` = 64 KiB cap prevents big-data DoS attacks that exploit Z3 memory limits.
- H07: Per-call `z3.Context()` prevents non-deterministic cross-thread Z3 corruption.
- H08: `solver_rlimit` = 10M operations prevents logic-bomb DoS within wall-clock timeout window.
- H09: `expected_policy_hash` detects silent policy drift across distributed deployments.
- H10: Structured JSON logging via structlog neutralizes log injection (ANSI escapes, newlines encoded as JSON).
- H13: `min_response_ms` padding makes timing side-channel attacks statistically infeasible.

## [0.8.0] - 2026-03-17

### Added

- **Cryptographic Decision Hashing** (`src/pramanix/decision.py`) — every `Decision` now
  carries a deterministic `decision_hash` (SHA-256 via orjson canonical bytes) over
  `allowed`, `explanation`, `intent_dump`, `policy`, `state_dump`, `status`, and
  `violated_invariants`. Hash is content-addressable; `decision_id` excluded by design.
- **`intent_dump` / `state_dump` fields on `Decision`** — raw Python dicts capturing the
  resolved intent and state values at verification time. Serialised via `_make_json_safe()`
  (Decimal→str, preserving precision) at hash-computation and `to_dict()` boundaries.
- **Ed25519 signing (`src/pramanix/crypto.py`)** — `PramanixSigner` / `PramanixVerifier`
  using the `cryptography` library. `PramanixSigner.generate()` creates an ephemeral keypair;
  production keys loaded from `PRAMANIX_SIGNING_KEY_PEM` env var or explicit PEM. Key rotation
  tracked via `key_id` (SHA-256[:16] of public PEM). `verify()` / `verify_decision()` never
  raise — return `False` on any failure.
- **Guard signing integration** (`src/pramanix/guard.py`) — `GuardConfig.signer` optional
  field; when set, `Guard.verify()` attaches `signature` and `public_key_id` to the returned
  Decision via `dataclasses.replace()` (immutable, mypy-clean).
- **Audit CLI subcommand** (`pramanix audit verify`) — verifies JSONL audit logs line by line.
  Status labels: `[VALID]`, `[TAMPERED]`, `[INVALID_SIG]`, `[MISSING_SIG]`, `[ERROR]`.
  Exit codes: 0 = all valid, 1 = any failure, 2 = usage error. Supports `--json`, `--fail-fast`.
- **`ComplianceReporter` / `ComplianceReport`** (`src/pramanix/helpers/compliance.py`) —
  maps Z3 unsat-core labels to structured compliance reports with 30+ regulatory citations
  (BSA/AML, OFAC/SDN, IRC §1091, HIPAA, Basel III, SOX, SRE SLAs). Severity classification:
  `CRITICAL_PREVENTION` / `HIGH` / `MEDIUM`. `to_json()` produces audit-ready JSON;
  `to_pdf()` returns UTF-8 structured text (real PDF output planned for Phase 12).

### Changed

- `Decision.safe()` and `Decision.unsafe()` factory methods accept optional `intent_dump`
  and `state_dump` kwargs, wired from `Guard._verify_core()`.
- `Decision.to_dict()` now includes `intent_dump`, `state_dump`, and `decision_hash`.
- `GuardConfig` gains optional `signer: PramanixSigner | None` field (default `None`).

### New extras

- `cryptography` extra (`pip install pramanix[crypto]`) — required for `PramanixSigner` /
  `PramanixVerifier`. Included in the `all` extra.

## [0.7.0] - 2026-03-15

### Added

- **Expression Tree Pre-compilation** (`src/pramanix/transpiler.py`) — `compile_policy()`
  walks the DSL expression tree once at `Guard.__init__()` time and caches `InvariantMeta`
  (label, field refs, tree fingerprint) as pure Python objects. Field-presence pre-checks at
  request time are O(n_fields) dict lookups; the full tree-walk is never repeated per request.
- **`InvariantMeta` dataclass** — frozen, hashable metadata cache entry with `label`,
  `explain_template`, `field_refs: frozenset[str]`, `tree_repr`, and `has_literal`. Validated
  at construction; raises `PolicyCompilationError` on empty label or missing field references.
- **Intent Extraction Cache** (`src/pramanix/translator/_cache.py`) — LRU + optional Redis
  cache for NLP extraction results. Disabled by default (`PRAMANIX_INTENT_CACHE_ENABLED=true`
  required). SHA-256 / NFKC-normalized cache keys prevent timing oracles and Unicode collision.
  Z3 and Pydantic **always** run on cache hits — cache stores only the raw extracted dict.
- **Semantic Fast-Path** (`src/pramanix/fast_path.py`) — pure-Python O(1) pre-screening before
  Z3 invocation. Rules can only BLOCK, never ALLOW. Ships five built-in factory rules:
  `negative_amount`, `zero_or_negative_balance`, `account_frozen`, `exceeds_hard_cap`,
  `amount_exceeds_balance`. Enabled via `GuardConfig(fast_path_enabled=True, fast_path_rules=...)`.
- **Adaptive Load Shedding** (`src/pramanix/worker.py`) — `AdaptiveConcurrencyLimiter` uses
  dual-condition shedding: saturation% AND P99 latency (60 s sliding window, ≥10 samples).
  Shed decisions return `Decision.rate_limited()` — always `allowed=False`, status
  `SolverStatus.RATE_LIMITED`. `WorkerPool` exposes `latency_threshold_ms` / `worker_pct`.
- **`Decision.rate_limited()` factory** and `SolverStatus.RATE_LIMITED` enum value —
  fail-safe shed result included in `_BLOCKED_STATUSES`.
- **Publishable benchmarks** (`benchmarks/`) — machine-readable JSON P50/P95/P99 latency
  benchmark and tracemalloc-based memory stability benchmark.
- **Performance test suite** (`tests/perf/`) — gate tests for P50 API latency, fast-path
  sub-millisecond timing, and compiled-metadata correctness.
- **Phase 10 unit tests** — `test_expression_cache.py` (22 tests), `test_intent_cache.py`
  (extended with full Redis mock coverage, exception paths, TTL), `test_fast_path.py`
  (35 tests), `test_load_shedding.py` (20 tests).

### Changed

- **`GuardConfig`** — added `fast_path_enabled`, `fast_path_rules`, `shed_latency_threshold_ms`,
  `shed_worker_pct` fields; all env-var configurable.
- **`Guard.__init__()`** — calls `compile_policy()` and initialises `FastPathEvaluator` once at
  construction; `verify()` performs field-presence pre-check and fast-path screen before Z3.
- **Zero mypy errors** — all `type-arg`, `no-any-return`, `unused-ignore`, and `assignment`
  errors across 12 source files resolved; 0 mypy errors on `--ignore-missing-imports`.
- **Version bumped to `0.7.0`**.

### Security

- Shed decisions (`Decision.rate_limited()`) are always `allowed=False` — load shedding
  can never produce an ALLOW response. Verified by `test_load_shedding.py`.
- Fast-path rules can only BLOCK, never ALLOW — only Z3 can produce `allowed=True`.
  Exception in any fast-path rule falls through to Z3 (safe degradation).
- Intent cache stores only the raw extracted dict — not a Decision, not allow/block status.
  State is **never** part of the cache key; same input with different state still invokes Z3.

## [0.6.0] - 2026-03-15

### Added

- **Cryptographic Decision Proofs** (`src/pramanix/audit/`) — every `Decision` can
  be signed with HMAC-SHA256 (JWS compact serialization, stdlib-only). `DecisionSigner`
  reads from `PRAMANIX_SIGNING_KEY` env var; `sign()` never raises. `DecisionVerifier`
  provides offline audit via constant-time `hmac.compare_digest`. `MerkleAnchor` chains
  multiple decisions into a tamper-evident tree with per-decision proof paths.
- **`pramanix verify-proof` CLI** — offline cryptographic proof verification with
  `--stdin`, `--key`, and `--json` flags. Exit codes: 0=valid, 1=invalid/error, 2=usage.
- **Zero-Trust JWT Identity Layer** (`src/pramanix/identity/`) — `JWTIdentityLinker`
  verifies HMAC-SHA256 JWT signatures *before* decoding any claims, then loads state
  exclusively via the verified `sub` claim. Caller-provided request body state is
  always ignored. `RedisStateLoader` keys on `{prefix}{sub}` with `Decimal`-safe JSON
  parsing and required `state_version` field validation.
- **Adaptive Circuit Breaker** (`src/pramanix/circuit_breaker.py`) — four-state
  machine (CLOSED → OPEN → HALF_OPEN → CLOSED; ISOLATED after configurable open
  episodes) wraps any `Guard` to shed Z3 solver pressure while keeping the system
  responsive. Emits Prometheus metrics (`pramanix_circuit_state`,
  `pramanix_circuit_pressure_events_total`) when `prometheus-client` is installed.
- **`X-Pramanix-Proof` response header** — FastAPI middleware attaches a signed JWS
  token to every ALLOW and BLOCK response when `PRAMANIX_SIGNING_KEY` is set.
- **Live framework integration tests** — all 8 `sys.modules` mocking stubs replaced
  with real FastAPI + httpx + LangChain + LlamaIndex integrations guarded by
  `pytest.importorskip`. Zero mocked framework imports.

### Changed

- **`PramanixGuardedTool` (LangChain)** — fixed Pydantic v2 `PydanticUserError`
  caused by `ConfigDict` import inside the class body. Module-level
  `_PRAMANIX_MODEL_CONFIG` alias now correctly sets `arbitrary_types_allowed=True`
  without polluting the class namespace. Private guard state stored via
  `object.__setattr__`/`object.__getattribute__` with `_pramanix_` prefix.
- **`format_block_feedback` security fix** — removed `_format_intent_values` helper
  that leaked raw field values into LLM feedback strings, enabling binary-search
  policy probing attacks. Feedback now contains only `decision_id`, `violated_invariant`
  label names, and the policy `explanation` string.
- **Version bumped to `0.6.0`**.

### Security

- Block feedback no longer includes raw intent or state field values in any integration
  (LangChain, AutoGen, LlamaIndex, FastAPI). Verified by dedicated
  `tests/unit/test_feedback_security.py` and `TestMiddlewareBlock` suite.
- JWT signatures are verified *before* any claim is trusted or decoded — prevents
  algorithm-confusion and claim-injection attacks.
- `PRAMANIX_SIGNING_KEY` minimum length enforced at 32 characters; keys below this
  threshold silently produce `None` from `DecisionSigner.sign()` rather than raising,
  maintaining fail-safe behaviour.

## [0.5.0] - 2026-03-14

### Added

- **SLSA Level 3 release pipeline** — OIDC-based PyPI publish, Sigstore artifact signing,
  CycloneDX SBOM generation, and cryptographic provenance on every tag push.
- **Iron Gate CI pipeline** — six-job chain (SAST → Alpine-ban → Lint → Test → Coverage →
  License) enforcing zero-CVE deps, 95 % branch coverage, and allowlist-only licenses.
- **`.dockerignore`** — excludes `.git`, `tests/`, `docs/`, `*.md`, `__pycache__`,
  `.mypy_cache`, and `.venv` to keep the build context lean and the image surface minimal.
- **`Dockerfile.dev`** — local-only development image extending the production runner;
  adds `poetry`, dev dependencies, and test tooling; never deployed to production.
- **`deploy/k8s/deployment.yaml`** — HA Kubernetes Deployment (replicas: 2) with
  hardened pod/container securityContexts, live/readiness probes, and graceful shutdown.
- **`deploy/k8s/hpa.yaml`** — HorizontalPodAutoscaler targeting 70 % CPU utilisation
  (min 2, max 10 replicas) with 300 s scale-down stabilisation to prevent Z3 worker
  pool thrash.
- **`deploy/k8s/networkpolicy.yaml`** — Default-deny NetworkPolicy allowing only port
  8000 ingress and explicit egress to DNS, PyPI, and LLM endpoints; blocks cloud-metadata
  SSRF endpoint 169.254.169.254.
- **`deploy/k8s/configmap.yaml`** — All `PRAMANIX_*` environment variables with
  documented defaults; `PRAMANIX_TRANSLATOR_ENABLED=false` enforced at cluster level.
- **Trivy hardening documentation** in `docs/deployment.md` — Accepted LOW/MEDIUM
  findings with rationale; CRITICAL/HIGH gate must be zero on every build.

### Changed

- **Python 3.10 support dropped** — EOL December 2026; matrix now `3.11`, `3.12`.
  `pyproject.toml` minimum bumped to `>=3.11`. `mypy` and `ruff` targets updated.
- **Version Development Status** promoted from `3 - Alpha` to `4 - Beta`.
- **`codecov.yml`** coverage delta threshold set to `0.5 %` — PRs failing this check
  must either add tests or explicitly justify the regression.
- **`README.md`** CI badge updated to live GitHub Actions workflow badge
  (previously a static shields.io graphic).

### Security

- Supply-chain hardening: all release artifacts signed with Sigstore `cosign`;
  SBOM attached in CycloneDX JSON format to every GitHub Release.
- Pipeline never stores `PYPI_API_TOKEN`; PyPI publish uses GitHub OIDC trusted
  publishing exclusively.
- Container image: `trivy image --exit-code 1 --severity CRITICAL,HIGH` must pass
  on every release build (0 CRITICAL, 0 HIGH policy).

---

## [0.4.0] - 2026-03-13

### Added

- **Translator subsystem** (`src/pramanix/translator/`) -- LLM-based intent extraction. Four backends: `OllamaTranslator` (local), `OpenAICompatTranslator`, `AnthropicTranslator`, `RedundantTranslator` (dual-model consensus). `PRAMANIX_TRANSLATOR_ENABLED=false` is the default -- opt-in only.
- **Five-Layer Defence pipeline** (`pramanix_hardened.py`, `pramanix_llm_hardened.py`) -- complete neuro-symbolic hardening: input sanitisation, dual-model consensus, injection scoring, semantic gateway, Z3 verification.
- **Input sanitisation** (`sanitise_user_input()`) -- Unicode NFKC normalisation, 512-character hard truncation, C0 control-character strip, 30+ injection pattern scan.
- **Injection confidence scoring** (`injection_confidence_score()`) -- additive risk model with 6 weighted signals. Score >= 0.5 produces `InjectionBlockedError` before Z3.
- **Dual-model consensus** (`RedundantTranslator`) -- two independent LLM backends called concurrently via `asyncio.gather`. Canonical JSON equality check (sort_keys=True). Any mismatch blocks with `ExtractionMismatchError`.
- **Semantic post-consensus gateway** -- fast pure-Python business rules (minimum reserve, daily limit, full-drain check) before Z3.
- **Fail-closed human approval gateway** (`_FailClosedApprovalGateway`) -- full-drain transfers always BLOCK unless a `HumanApprovalBackend` is explicitly wired.
- **Adversarial test suite** (`tests/adversarial/`) -- OWASP A01/A02 injection vectors, field overflow, ID injection, TOCTOU, 50+ tests.
- **Per-currency injection scoring** -- sub-penny thresholds per currency (JPY=1, KWD=0.001, BTC=0.0001, default=0.01).
- **Red-flag telemetry** (`pramanix_telemetry.py`) -- three 300-second rolling counters: `injection_spikes`, `consensus_mismatches`, `z3_timeouts`. `StructuredLogEmitter` writes newline-delimited JSON.

### Changed

- `Guard.verify()` gains optional LLM extraction path when `translator_enabled=True`.
- `GuardConfig` gains `translator_enabled` field (default False).
- Spawn (not fork) enforced for subprocess workers -- fork silently inherits Z3 heap state.

### Security

- HMAC-SHA256 IPC seal (`_worker_solve_sealed` / `_unseal_decision`) -- prevents forged `allowed=True` from compromised worker subprocess.
- `_EphemeralKey` HMAC key -- `secrets.token_bytes(32)`, cannot be pickled (`__reduce__` raises `TypeError`), repr returns `<EphemeralKey: redacted>`.
- Blind ID resolution -- LLM never sees real account identifiers; host resolves labels to IDs after extraction.

---

## [0.3.0] - 2026-03-12

### Added

- **`ResolverRegistry`** (`src/pramanix/resolvers.py`) -- async field resolver cache with thread-local isolation. Resolvers run on the event loop before dispatching to Z3 workers.
- **Prometheus metrics** -- `pramanix_decisions_total` (counter by policy+status), `pramanix_decision_latency_seconds` (histogram), `pramanix_solver_timeouts_total`, `pramanix_validation_failures_total`. Enabled via `PRAMANIX_METRICS_ENABLED=true`.
- **OpenTelemetry spans** -- `pramanix.guard.verify` span with `policy`, `allowed`, `status`, `latency_ms` attributes. Enabled via `PRAMANIX_OTEL_ENABLED=true`. No-op when otel package not installed.
- **Structured JSON logging** (`structlog`) -- secret-key redaction processor runs first (keys matching `secret|api_key|token|hmac|password|credential` replaced with `<redacted>`). ISO timestamp, stack info, Unicode decoder.
- **Property-based tests** (`tests/property/`) -- Hypothesis strategies for FinTech primitives (30+ generated test cases per strategy).
- **Memory stability benchmarks** -- tracemalloc-based RSS growth tracking across worker recycle boundaries.
- **`ContextVar` isolation** -- per-request context isolation prevents concurrent-request state contamination in thread-mode workers.

### Changed

- `GuardConfig` gains `metrics_enabled`, `otel_enabled`, `log_level` fields.
- Telemetry is optional -- Prometheus and OTel gracefully degrade when their packages are not installed (zero overhead).

---

## [0.2.0] - 2026-03-11

### Added

- **`async-thread` execution mode** -- `ThreadPoolExecutor` worker pool. Z3 runs in background threads without blocking the event loop.
- **`async-process` execution mode** -- `ProcessPoolExecutor` with spawn start method. Z3 runs in isolated subprocesses; no Z3 objects cross the process boundary.
- **`WorkerPool`** (`src/pramanix/worker.py`) -- lifecycle management: spawn, warmup, recycle (at `max_decisions_per_worker`). Old executor handed to daemon background thread for clean shutdown.
- **Worker warmup** -- dummy Z3 solve per worker slot on startup. Uses private `z3.Context()`. Eliminates 50-200 ms cold-start JIT spike.
- **Worker recycling** -- after `max_decisions_per_worker=10000` decisions, entire executor replaced. Caps Z3 heap accumulation to < 50 MiB per worker.
- **`@guard` decorator** (`src/pramanix/decorator.py`) -- wraps any sync or async function with Guard.verify(). Raises `GuardViolationError` on BLOCK.
- **Primitives library** (`src/pramanix/primitives/`) -- 18 pre-built constraints:
  - Finance (6): NonNegativeBalance, UnderDailyLimit, UnderSingleTxLimit, RiskScoreBelow, SecureBalance, MinimumReserve
  - RBAC (3): RoleMustBeIn, ConsentRequired, DepartmentMustBeIn
  - Infrastructure (4): MinReplicas, MaxReplicas, WithinCPUBudget, WithinMemoryBudget
  - Time (4): WithinTimeWindow, After, Before, NotExpired
  - Common (1): NotSuspended
- **`model_dump()` before process boundary** -- Pydantic models serialized to plain dicts before crossing subprocess boundary; never pickled.

### Changed

- `GuardConfig` gains `execution_mode`, `max_workers`, `max_decisions_per_worker`, `worker_warmup` fields.
- `Guard.__init__()` creates worker pool; `Guard.verify()` is now async-capable.

### Security

- Spawn (not fork) for subprocess workers -- fork silently inherits Z3 internal state.
- `max_decisions_per_worker` default = 10,000 -- hard cap on worker lifetime to prevent unbounded RSS growth.

---

## [0.1.0] - 2026-03-10

### Added

- **Core DSL** (`src/pramanix/expressions.py`) -- `Field` descriptor, `E()` expression builder, `ExpressionNode` with full arithmetic and comparison operator overloading, `ConstraintExpr` with boolean composition (`&`, `|`, `~`).
- **`ConstraintExpr.__bool__` guard** -- raises `PolicyCompilationError` when Python `and`/`or` is accidentally used instead of `&`/`|`. Catches this class of bug at policy compilation time.
- **`ConstraintExpr.is_in()`** -- expands to OR of equality constraints for enum-style fields. Raises `PolicyCompilationError` on empty list.
- **`Policy` base class** (`src/pramanix/policy.py`) -- `Field` descriptors, `invariants()` classmethod, `class Meta` with `version`, `intent_model`, `state_model`. Compile-time validation: all invariants named, no duplicate names, no empty invariants list.
- **`Transpiler`** (`src/pramanix/transpiler.py`) -- DSL expression tree to Z3 AST conversion. `Decimal` via `as_integer_ratio()` (exact rational), `bool` via `z3.BoolVal`, `int` via `z3.IntVal`. Zero `ast.parse()`, zero `eval()`, zero `exec()`.
- **`Solver`** (`src/pramanix/solver.py`) -- Z3 wrapper with `solver.set("timeout", ms)`, `assert_and_track` per invariant (per-invariant solver instances for exact violation attribution), unsat core extraction, `del solver` after every decision.
- **`SolverStatus` enum** -- SAFE, UNSAFE, TIMEOUT, UNKNOWN, CONFIG_ERROR, VALIDATION_FAILURE, EXTRACTION_FAILURE, EXTRACTION_MISMATCH, RATE_LIMITED.
- **`Decision`** (`src/pramanix/decision.py`) -- frozen dataclass: `allowed`, `status`, `violated_invariants`, `explanation`, `metadata`, `solver_time_ms`, `decision_id` (UUID4). Factory methods: `safe()`, `unsafe()`, `timeout()`, `error()`. All error factories enforce `allowed=False`.
- **`Guard`** (`src/pramanix/guard.py`) -- sync `verify()` entrypoint. Fail-safe contract: every exception returns `Decision.error(allowed=False)`, never propagates.
- **`GuardConfig`** (`src/pramanix/guard.py`) -- frozen dataclass with `PRAMANIX_*` env var bindings. `solver_timeout_ms` default 5,000 ms.
- **Exception hierarchy** (`src/pramanix/exceptions.py`) -- 15+ exception types: `PramanixError`, `PolicyCompilationError`, `IntentValidationError`, `StateValidationError`, `SolverTimeoutError`, `SolverUnknownError`, `SolverContextError`, `ResolverNotFoundError`, `ResolverExecutionError`, `ExtractionFailureError`, `ExtractionMismatchError`, `InjectionBlockedError`, `SemanticPolicyViolation`, `GuardViolationError`, `WorkerError`, `ConfigurationError`.
- **Unit test suite** (`tests/unit/`) -- > 200 tests, 95%+ branch coverage.
- **`BankingPolicy` reference implementation** (`examples/banking_example.py`) -- 4 invariants, SAT + UNSAT paths, full quickstart.

### Security

- Fail-safe contract: `Guard.verify()` never raises. Any exception path (including bugs in user-defined `invariants()`) returns `Decision.error(allowed=False)`.
- `allowed=True` is generated only when Z3 returns `sat` for all invariants. No other code path produces it.
- Per-invariant solver instances -- Z3's `unsat_core()` minimum-core issue bypassed; every violated invariant is always reported.

---

## [0.0.0] - 2026-03-09

### Added

- **Transpiler spike** (`transpiler_spike.py`) -- standalone proof-of-concept (302 lines). Proves Z3 SMT solver integration: `E()` + `Field` lazy AST, `Decimal` exact rational arithmetic via `as_integer_ratio()`, per-invariant solver instances for exact violation attribution.
- **53 unit tests** (`tests/unit/test_transpiler_spike.py`) -- 5 gate tests + 48 additional.
- **Gate test results** -- all 5 pass: SAT (normal tx), UNSAT single (overdraft), UNSAT multi (overdraft+frozen), SAT boundary exact (0 >= 0), UNSAT boundary breach.

### Security

- **Critical finding documented:** Z3's `unsat_core()` returns a minimal subset, not all violated invariants. Per-invariant solver instances (one `assert_and_track` per solver) required for complete attribution. Fast-path shared solver for overall SAT/UNSAT; per-invariant solvers only on UNSAT path.
- **Exact arithmetic confirmed:** `Decimal("100.01").as_integer_ratio()` = `(10001, 100)`. Z3 `RealVal(10001) / RealVal(100)` = exact `10001/100`. No IEEE 754 values ever reach Z3.

---

<!-- Future major release -->
<!-- ## [1.0.0] - TBD -->
<!-- API contract locked. No breaking changes until v2.0. SLSA Level 3 provenance. -->
