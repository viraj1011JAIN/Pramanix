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

from pramanix.audit import (
    DecisionSigner,
    DecisionVerifier,
    MerkleAnchor,
    MerkleArchiver,
    PersistentMerkleAnchor,
)
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
from pramanix.resolvers import ResolverRegistry
from pramanix.translator.injection_scorer import BuiltinScorer, CalibratedScorer, InjectionScorer
from pramanix.translator.redundant import ConsensusStrictness
from pramanix.transpiler import InvariantASTCache

__all__ = [
    # Phase 9 — Pillar 4: Adaptive circuit breaker
    "AdaptiveCircuitBreaker",
    # A-3: Array field quantifiers
    "ArrayField",
    # E-4: Audit sinks
    "AuditSink",
    "BuiltinScorer",
    "CalibratedScorer",
    "CircuitBreakerConfig",
    "ComplianceReport",
    # Phase 11 — Pillar 4: Compliance reporter
    "ComplianceReporter",
    "ConfigurationError",
    # Phase D-1 — Consensus strictness control
    "ConsensusStrictness",
    "ConstraintExpr",
    "DatadogAuditSink",
    # A-4: Datetime field
    "DatetimeField",
    # Core result
    "Decision",
    # Phase 9 — Pillar 1: Cryptographic audit
    "DecisionSigner",
    "DecisionVerifier",
    # C-5: Distributed circuit breaker
    "DistributedCircuitBreaker",
    "E",
    "EnvKeyProvider",
    # Phase 12 — Hardening: sealed execution token (TOCTOU gap)
    "ExecutionToken",
    "ExecutionTokenSigner",
    "ExecutionTokenVerifier",
    "Exists",
    # Exceptions — translator (Phase 4)
    "ExtractionFailureError",
    "ExtractionMismatchError",
    # DSL
    "Field",
    "FieldTypeError",
    "FileKeyProvider",
    "ForAll",
    # Guard
    "Guard",
    "GuardConfig",
    "GuardError",
    "GuardViolationError",
    "InMemoryAuditSink",
    "InMemoryDistributedBackend",
    # E-1: Redis-free token backends
    "InMemoryExecutionTokenVerifier",
    "InjectionBlockedError",
    # D-4: Injection scorer
    "InjectionScorer",
    # Phase D-3 — input length guard
    "InputTooLongError",
    # C-2: Invariant AST cache
    "InvariantASTCache",
    "InvariantLabelError",
    # Phase 9 — Pillar 3: Zero-trust identity
    "JWTIdentityLinker",
    "KafkaAuditSink",
    # E-3: KMS/HSM key providers
    "KeyProvider",
    "LLMTimeoutError",
    "MerkleAnchor",
    # E-2: Merkle pruning and archival
    "MerkleArchiver",
    # B-1: Nested model descriptor chaining
    "NestedField",
    "PemKeyProvider",
    # Phase 12 — Hardening: persistent Merkle anchoring
    "PersistentMerkleAnchor",
    # Policy
    "Policy",
    # Limitations overrides: static policy coverage analysis
    "PolicyAuditor",
    "PolicyCompilationError",
    "PolicyError",
    "PolicyMigration",
    "PostgresExecutionTokenVerifier",
    # Exceptions — core
    "PramanixError",
    # Phase 11 — Pillar 2: Ed25519 cryptographic signing
    "PramanixSigner",
    "PramanixVerifier",
    "RedisDistributedBackend",
    # Phase 13 — Enterprise: distributed Redis token store
    "RedisExecutionTokenVerifier",
    # Resolver cache (data-bleed guard) — singleton excluded intentionally:
    # interact with the registry through Guard configuration, not directly.
    "ResolverRegistry",
    "S3AuditSink",
    "SQLiteExecutionTokenVerifier",
    # Exceptions — hardening (Phase 4)
    "SemanticPolicyViolation",
    "SolverError",
    "SolverStatus",
    "SolverTimeoutError",
    "SplunkHecAuditSink",
    "StateValidationError",
    "StdoutAuditSink",
    # Limitations overrides: string→int enum helper
    "StringEnumField",
    "TranspileError",
    "ValidationError",
    "WorkerError",
    # Decorator
    "guard",
    "invariant_mixin",
    "model_dump_z3",
]
