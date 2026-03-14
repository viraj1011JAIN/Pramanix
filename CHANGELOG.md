# Changelog

All notable changes to Pramanix are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
