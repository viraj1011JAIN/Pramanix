# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""
Pramanix: Deterministic Neuro-Symbolic Guardrails for Autonomous AI Agents.

Public API contract — these are the ONLY names that are considered stable.
All other internal modules may change without notice.
"""

__version__ = "1.0.0"

# Module stability contract — which public surfaces are safe to build on.
# "stable"       — public API, semver-protected; no breaking changes without a major bump.
# "beta"         — available but may change in minor versions with a deprecation notice.
# "experimental" — subject to change without notice; not for production use.
__stability__: dict[str, str] = {
    "core": "stable",           # Guard, Policy, Field, E, Decision, GuardConfig
    "audit": "stable",          # DecisionSigner, DecisionVerifier, MerkleAnchor
    "crypto": "stable",         # PramanixSigner, PramanixVerifier
    "circuit_breaker": "stable",
    "execution_token": "stable",
    "key_provider": "stable",   # PemKeyProvider, EnvKeyProvider, FileKeyProvider, cloud providers
    "compliance": "stable",     # ComplianceReporter, ComplianceReport, to_pdf()
    "audit_sinks": "stable",    # KafkaAuditSink, S3AuditSink, SplunkHecAuditSink, DatadogAuditSink
    "worker": "stable",         # async-process execution backend
    "primitives": "stable",     # fintech, healthcare, finance, rbac, time, infra
    "translator": "beta",       # LLM translation stack (httpx/openai/anthropic)
    "integrations": "beta",     # LangChain, LlamaIndex, AutoGen, FastAPI adapters
    "fast_path": "beta",        # fast-path cache (GuardConfig.fast_path_enabled)
}

# ── Phase 2 (v0.1) public surface ─────────────────────────────────────────────

from pramanix.audit import DecisionSigner, DecisionVerifier, MerkleAnchor, MerkleArchiver, PersistentMerkleAnchor
from pramanix.audit_sink import (
    AuditSink,
    DatadogAuditSink,
    InMemoryAuditSink,
    KafkaAuditSink,
    S3AuditSink,
    SplunkHecAuditSink,
    StdoutAuditSink,
)
from pramanix.circuit_breaker import (
    AdaptiveCircuitBreaker,
    CircuitBreakerConfig,
    DistributedCircuitBreaker,
    InMemoryDistributedBackend,
    RedisDistributedBackend,
)
from pramanix.crypto import PramanixSigner, PramanixVerifier
from pramanix.decision import Decision, SolverStatus
from pramanix.decorator import guard
from pramanix.exceptions import (
    ConfigurationError,
    ExtractionFailureError,
    ExtractionMismatchError,
    FieldTypeError,
    GuardError,
    GuardViolationError,
    InjectionBlockedError,
    InputTooLongError,
    InvariantLabelError,
    LLMTimeoutError,
    PolicyCompilationError,
    PolicyError,
    PramanixError,
    SemanticPolicyViolation,
    SolverError,
    SolverTimeoutError,
    StateValidationError,
    TranspileError,
    ValidationError,
    WorkerError,
)
from pramanix.execution_token import (
    ExecutionToken,
    ExecutionTokenSigner,
    ExecutionTokenVerifier,
    InMemoryExecutionTokenVerifier,
    PostgresExecutionTokenVerifier,
    RedisExecutionTokenVerifier,
    SQLiteExecutionTokenVerifier,
)
from pramanix.expressions import (
    ArrayField,
    ConstraintExpr,
    DatetimeField,
    E,
    Exists,
    Field,
    ForAll,
    NestedField,
)
from pramanix.guard import Guard, GuardConfig
from pramanix.helpers.compliance import ComplianceReport, ComplianceReporter
from pramanix.helpers.policy_auditor import PolicyAuditor
from pramanix.helpers.string_enum import StringEnumField
from pramanix.identity import JWTIdentityLinker
from pramanix.key_provider import (
    EnvKeyProvider,
    FileKeyProvider,
    KeyProvider,
    PemKeyProvider,
)
from pramanix.migration import PolicyMigration
from pramanix.policy import Policy, invariant_mixin, model_dump_z3
from pramanix.translator.injection_scorer import BuiltinScorer, CalibratedScorer, InjectionScorer
from pramanix.transpiler import InvariantASTCache
from pramanix.resolvers import ResolverRegistry
from pramanix.translator.redundant import ConsensusStrictness

__all__ = [
    # Phase 9 — Pillar 4: Adaptive circuit breaker
    "AdaptiveCircuitBreaker",
    "CircuitBreakerConfig",
    # C-5: Distributed circuit breaker
    "DistributedCircuitBreaker",
    "InMemoryDistributedBackend",
    "RedisDistributedBackend",
    # E-4: Audit sinks
    "AuditSink",
    "DatadogAuditSink",
    "InMemoryAuditSink",
    "KafkaAuditSink",
    "S3AuditSink",
    "SplunkHecAuditSink",
    "StdoutAuditSink",
    # E-3: KMS/HSM key providers
    "KeyProvider",
    "PemKeyProvider",
    "EnvKeyProvider",
    "FileKeyProvider",
    # A-3: Array field quantifiers
    "ArrayField",
    # A-4: Datetime field
    "DatetimeField",
    # B-1: Nested model descriptor chaining
    "NestedField",
    "ComplianceReport",
    # Phase 11 — Pillar 4: Compliance reporter
    "ComplianceReporter",
    # Limitations overrides: static policy coverage analysis
    "PolicyAuditor",
    # Limitations overrides: string→int enum helper
    "StringEnumField",
    "ConfigurationError",
    "ConstraintExpr",
    # Core result
    "Decision",
    # Phase 9 — Pillar 1: Cryptographic audit
    "DecisionSigner",
    "DecisionVerifier",
    "E",
    "Exists",
    # Phase 12 — Hardening: sealed execution token (TOCTOU gap)
    "ExecutionToken",
    "ExecutionTokenSigner",
    "ExecutionTokenVerifier",
    # E-1: Redis-free token backends
    "InMemoryExecutionTokenVerifier",
    "PostgresExecutionTokenVerifier",
    "SQLiteExecutionTokenVerifier",
    # Exceptions — translator (Phase 4)
    "ExtractionFailureError",
    "ExtractionMismatchError",
    # Phase D-3 — input length guard
    "InputTooLongError",
    # DSL
    "Field",
    "FieldTypeError",
    "ForAll",
    # Guard
    "Guard",
    "GuardConfig",
    "GuardError",
    "GuardViolationError",
    "InjectionBlockedError",
    "InvariantLabelError",
    # Phase 9 — Pillar 3: Zero-trust identity
    "JWTIdentityLinker",
    "LLMTimeoutError",
    "MerkleAnchor",
    # E-2: Merkle pruning and archival
    "MerkleArchiver",
    # Phase 12 — Hardening: persistent Merkle anchoring
    "PersistentMerkleAnchor",
    # Policy
    "Policy",
    "PolicyMigration",
    "invariant_mixin",
    "model_dump_z3",
    # C-2: Invariant AST cache
    "InvariantASTCache",
    # D-4: Injection scorer
    "InjectionScorer",
    "BuiltinScorer",
    "CalibratedScorer",
    "PolicyCompilationError",
    "PolicyError",
    # Exceptions — core
    "PramanixError",
    # Phase 11 — Pillar 2: Ed25519 cryptographic signing
    "PramanixSigner",
    "PramanixVerifier",
    # Phase 13 — Enterprise: distributed Redis token store
    "RedisExecutionTokenVerifier",
    # Resolver cache (data-bleed guard) — singleton excluded intentionally:
    # interact with the registry through Guard configuration, not directly.
    "ResolverRegistry",
    # Exceptions — hardening (Phase 4)
    "SemanticPolicyViolation",
    "SolverError",
    "SolverStatus",
    "SolverTimeoutError",
    "StateValidationError",
    "TranspileError",
    "ValidationError",
    "WorkerError",
    # Decorator
    "guard",
    # Phase D-1 — Consensus strictness control
    "ConsensusStrictness",
]
