# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""
Pramanix: Deterministic Neuro-Symbolic Guardrails for Autonomous AI Agents.

Public API contract — these are the ONLY names that are considered stable.
All other internal modules may change without notice.
"""

__version__ = "0.2.0"

# ── Phase 2 (v0.1) public surface ─────────────────────────────────────────────

from pramanix.decision import Decision, SolverStatus
from pramanix.decorator import guard
from pramanix.exceptions import (
    ConfigurationError,
    FieldTypeError,
    GuardError,
    GuardViolationError,
    InvariantLabelError,
    PolicyCompilationError,
    PolicyError,
    PramanixError,
    SolverError,
    SolverTimeoutError,
    StateValidationError,
    TranspileError,
    ValidationError,
    WorkerError,
)
from pramanix.expressions import ConstraintExpr, E, Field
from pramanix.guard import Guard, GuardConfig
from pramanix.policy import Policy

__all__ = [
    # Core result
    "Decision",
    "SolverStatus",
    # DSL
    "Field",
    "E",
    "ConstraintExpr",
    # Policy
    "Policy",
    # Guard
    "Guard",
    "GuardConfig",
    # Decorator
    "guard",
    # Exceptions
    "PramanixError",
    "PolicyError",
    "PolicyCompilationError",
    "InvariantLabelError",
    "FieldTypeError",
    "TranspileError",
    "GuardError",
    "ValidationError",
    "StateValidationError",
    "SolverTimeoutError",
    "SolverError",
    "WorkerError",
    "GuardViolationError",
    "ConfigurationError",
]
