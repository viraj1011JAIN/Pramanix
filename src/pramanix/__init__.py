# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""
Pramanix: Deterministic Neuro-Symbolic Guardrails for Autonomous AI Agents.

Public API contract — these are the ONLY names that are considered stable.
All other internal modules may change without notice.
"""

__version__ = "0.9.0"

# ── Phase 2 (v0.1) public surface ─────────────────────────────────────────────

from pramanix.audit import DecisionSigner, DecisionVerifier, MerkleAnchor, PersistentMerkleAnchor
from pramanix.circuit_breaker import AdaptiveCircuitBreaker, CircuitBreakerConfig
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
    RedisExecutionTokenVerifier,
)
from pramanix.expressions import ConstraintExpr, E, Field
from pramanix.guard import Guard, GuardConfig
from pramanix.helpers.compliance import ComplianceReport, ComplianceReporter
from pramanix.identity import JWTIdentityLinker
from pramanix.policy import Policy
from pramanix.resolvers import ResolverRegistry

__all__ = [
    # Phase 9 — Pillar 4: Adaptive circuit breaker
    "AdaptiveCircuitBreaker",
    "CircuitBreakerConfig",
    "ComplianceReport",
    # Phase 11 — Pillar 4: Compliance reporter
    "ComplianceReporter",
    "ConfigurationError",
    "ConstraintExpr",
    # Core result
    "Decision",
    # Phase 9 — Pillar 1: Cryptographic audit
    "DecisionSigner",
    "DecisionVerifier",
    "E",
    # Phase 12 — Hardening: sealed execution token (TOCTOU gap)
    "ExecutionToken",
    "ExecutionTokenSigner",
    "ExecutionTokenVerifier",
    # Exceptions — translator (Phase 4)
    "ExtractionFailureError",
    "ExtractionMismatchError",
    # DSL
    "Field",
    "FieldTypeError",
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
    # Phase 12 — Hardening: persistent Merkle anchoring
    "PersistentMerkleAnchor",
    # Policy
    "Policy",
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
]
