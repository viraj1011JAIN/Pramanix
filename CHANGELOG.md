# Changelog

All notable changes to Pramanix are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Project scaffolding: directory structure, pyproject.toml, CI pipeline
- AGPL-3.0 license

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
