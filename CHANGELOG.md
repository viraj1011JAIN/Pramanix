# Changelog

All notable changes to Pramanix are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

<!-- ────────────────────────────────────────────────────────────────────────
  Future versions will follow this structure:

  ## [0.1.0] - YYYY-MM-DD
  ### Added
  - Core DSL: Policy, Field, E(), ExpressionNode, ConstraintExpr
  - Transpiler: DSL expression tree → Z3 AST (zero AST parsing)
  - Solver: Z3 wrapper with timeout, assert_and_track, unsat_core()
  - Guard: sync verify(), GuardConfig
  - Decision: frozen dataclass with all factory methods
  - BankingPolicy reference implementation
  - Unit tests (>95% coverage)

  ## [0.2.0] - YYYY-MM-DD
  ### Added
  - async-thread and async-process execution modes
  - WorkerPool: spawn, warmup, recycle lifecycle
  - @guard decorator
  - Primitives: finance, rbac, infra, time, common

  ## [0.3.0] - YYYY-MM-DD
  ### Added
  - ResolverRegistry: async + sync, per-decision cache
  - Telemetry: Prometheus metrics, OTel spans, structured JSON logs
  - Property-based tests (Hypothesis)
  - Performance benchmarks and memory stability tests

  ## [0.4.0] - YYYY-MM-DD
  ### Added
  - Translator subsystem: Ollama, OpenAI-compat, RedundantTranslator
  - Adversarial test suite
  - ExtractionMismatch detection

  ## [1.0.0] - YYYY-MM-DD
  ### Changed
  - API stabilized. No breaking changes guaranteed until v2.0.
  ### Added
  - Full documentation suite
  - PyPI release with signed provenance
───────────────────────────────────────────────────────────────────────── -->
