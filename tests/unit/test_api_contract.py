# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""API contract lock tests — Phase 1.2.

THESE TESTS ARE INTENTIONALLY BRITTLE.

They encode the exact public API surface at v0.9.0 as immutable snapshots.
When a test here fails on a branch, it is NOT a test bug — it means the
public API changed and the change requires ALL THREE of:

  (a) An explicit snapshot update in this file, AND
  (b) A CHANGELOG.md entry in the correct semver category (MAJOR/MINOR/PATCH),
      AND
  (c) If MAJOR: version bump in pyproject.toml + src/pramanix/__init__.py.

Do NOT update the snapshots without completing all three steps.

Contracts locked at v0.9.0:

  1. pramanix.__all__            — exact set of 43 exported names.
  2. SolverStatus                — exact 9 members, wire values, iteration order.
  3. Decision.to_dict()          — exact 13-key schema + per-field type semantics.
  4. GuardConfig field names     — exact 29 fields, all-defaults constructor, frozen.
  5. GuardConfig default values  — operational defaults that callers depend on.
  6. Direct import surface       — high-visibility names importable from `pramanix`.
  7. Decision factory methods    — all factory class-methods exist, correct status.

See docs/api-compatibility.md for the full semver policy and update procedure.
"""

from __future__ import annotations

import dataclasses
import re
import uuid
from typing import Any

import pytest

import pramanix
from pramanix.decision import _BLOCKED_STATUSES, Decision, SolverStatus
from pramanix.governance_config import GovernanceConfig
from pramanix.guard_config import GuardConfig

# ============================================================================
# 1.  pramanix.__all__ — exact export set
# ============================================================================
#
# Order of __all__ is NOT part of the public contract (Python `import *` does
# not depend on order). A frozenset snapshot is therefore correct and
# intentional.  Additions are MINOR; removals/renames are MAJOR.
#
# To update: add/remove the name from _EXPECTED_ALL below and document the
# change in CHANGELOG.md under the appropriate semver category.
# ============================================================================

_EXPECTED_ALL: frozenset[str] = frozenset(
    {
        # Circuit breaker (Phase 9)
        "AdaptiveCircuitBreaker",
        "CircuitBreakerConfig",
        # Compliance (Phase 11)
        "ComplianceReport",
        "ComplianceReporter",
        # Exceptions — core
        "ConfigurationError",
        "FieldTypeError",
        "GuardError",
        "GuardViolationError",
        "InvariantLabelError",
        "LLMTimeoutError",
        "PolicyCompilationError",
        "PolicyError",
        "PramanixError",
        "SemanticPolicyViolation",
        "SolverError",
        "SolverTimeoutError",
        "StateValidationError",
        "TranspileError",
        "ValidationError",
        "WorkerError",
        # Exceptions — translator (Phase 4)
        "ExtractionFailureError",
        "ExtractionMismatchError",
        "InjectionBlockedError",
        # New security exceptions (v1.0.0+)
        "FlowViolationError",
        "MemoryViolationError",
        "OversightRequiredError",
        "PrivilegeEscalationError",
        "ProvenanceError",
        # DSL expressions
        "ArrayField",
        "ConstraintExpr",
        "DatetimeField",
        "E",
        "Exists",
        "Field",
        "ForAll",
        "NestedField",
        # Core result types
        "Decision",
        "SolverStatus",
        # Audit / crypto (Phase 9 + 11)
        "DecisionSigner",
        "DecisionVerifier",
        "MerkleAnchor",
        "PersistentMerkleAnchor",
        "PramanixSigner",
        "PramanixVerifier",
        # Execution tokens (Phase 12)
        "ExecutionToken",
        "ExecutionTokenSigner",
        "ExecutionTokenVerifier",
        "RedisExecutionTokenVerifier",
        # Guard
        "Guard",
        "GuardConfig",
        # Identity (Phase 9)
        "JWTIdentityLinker",
        # Limitations overrides (v0.9.0)
        "PolicyAuditor",
        "StringEnumField",
        # C-5: distributed circuit breaker (v1.0.0)
        "DistributedCircuitBreaker",
        "InMemoryDistributedBackend",
        # E-4: audit sinks (v1.0.0)
        "AuditSink",
        "InMemoryAuditSink",
        "StdoutAuditSink",
        # E-3: KMS/HSM key providers (v1.0.0)
        "KeyProvider",
        "PemKeyProvider",
        "EnvKeyProvider",
        "FileKeyProvider",
        # D-1: consensus strictness enum (v1.0.0)
        "ConsensusStrictness",
        # D-3: input size guard (v1.0.0)
        "InputTooLongError",
        # Policy
        "Policy",
        # Resolvers
        "ResolverRegistry",
        # Decorator
        "guard",
        # Execution token verifiers (v1.0.0)
        "InMemoryExecutionTokenVerifier",
        "PostgresExecutionTokenVerifier",
        "SQLiteExecutionTokenVerifier",
        # Audit sinks (v1.0.0 additions)
        "DatadogAuditSink",
        "KafkaAuditSink",
        "S3AuditSink",
        "SplunkHecAuditSink",
        # Merkle archiver (v1.0.0)
        "MerkleArchiver",
        # Injection scoring (v1.0.0)
        "BuiltinScorer",
        "CalibratedScorer",
        "InjectionScorer",
        # Distributed circuit breaker backend (v1.0.0)
        "RedisDistributedBackend",
        # Policy migration / versioning (v1.0.0)
        "PolicyMigration",
        # AST cache (v1.0.0)
        "InvariantASTCache",
        # Utility helpers (v1.0.0)
        "invariant_mixin",
        "model_dump_z3",
        # Fast-path rules (v1.0.0)
        "FastPathRule",
        "SemanticFastPath",
        # Integrations — beta (v1.0.0)
        "HaystackGuardedComponent",
        "PramanixCrewAITool",
        "PramanixFunctionTool",
        "PramanixGuardedModule",
        "PramanixGuardedTool",
        "PramanixPydanticAIValidator",
        "PramanixQueryEngineTool",
        "PramanixSemanticKernelPlugin",
        "PramanixToolCallback",
        # Identity (v1.0.0)
        "IdentityClaims",
        "JWTExpiredError",
        "JWTVerificationError",
        # State loading (v1.0.0)
        "RedisStateLoader",
        "StateLoadError",
        "StateLoader",
        # Resolver / migration errors (v1.0.0)
        "MigrationError",
        "ResolverConflictError",
        # IFC — information-flow control (v1.0.0+)
        "ClassifiedData",
        "FlowDecision",
        "FlowEnforcer",
        "FlowPolicy",
        "FlowRule",
        "TrustLabel",
        # Privilege separation (v1.0.0+)
        "CapabilityManifest",
        "ExecutionContext",
        "ExecutionScope",
        "ScopeEnforcer",
        "ToolCapability",
        # Human oversight (v1.0.0+)
        "ApprovalDecision",
        "ApprovalRequest",
        "ApprovalStatus",
        "EscalationQueue",
        "InMemoryApprovalWorkflow",
        "OversightRecord",
        # Memory security (v1.0.0+)
        "MemoryEntry",
        "ScopedMemoryPartition",
        "SecureMemoryStore",
        # Policy lifecycle (v1.0.0+)
        "FieldChange",
        "InvariantChange",
        "PolicyDiff",
        "ShadowEvaluator",
        "ShadowResult",
        # Provenance / chain-of-custody (v1.0.0+)
        "ProvenanceChain",
        "ProvenanceRecord",
        # Governance config bundle (v1.0.0+)
        "GovernanceConfig",
    }
)


class TestAllExportsLock:
    """Contract: pramanix.__all__ exact set must not change silently."""

    def test_all_is_defined_as_list(self) -> None:
        """__all__ must exist and be a list (PEP 8 / import-star contract)."""
        assert hasattr(pramanix, "__all__"), "pramanix.__all__ must be defined"
        assert isinstance(
            pramanix.__all__, list
        ), f"pramanix.__all__ must be a list, got {type(pramanix.__all__).__name__}"

    def test_exact_count(self) -> None:
        """Exact count catches accidental duplicates inserted into __all__."""
        assert len(pramanix.__all__) == len(_EXPECTED_ALL), (
            f"pramanix.__all__ has {len(pramanix.__all__)} entries, "
            f"expected {len(_EXPECTED_ALL)}. "
            "Check for duplicate entries or a mismatch with _EXPECTED_ALL."
        )

    def test_no_unexpected_additions(self) -> None:
        """Additions to __all__ are MINOR-version events and must be explicit."""
        actual = frozenset(pramanix.__all__)
        unexpected = actual - _EXPECTED_ALL
        assert not unexpected, (
            f"New name(s) added to pramanix.__all__ without updating the contract snapshot:\n"
            f"  {sorted(unexpected)}\n"
            "If intentional: add to _EXPECTED_ALL here, add CHANGELOG.md entry (MINOR)."
        )

    def test_no_unexpected_removals(self) -> None:
        """Removals from __all__ are MAJOR-version breaking changes."""
        actual = frozenset(pramanix.__all__)
        missing = _EXPECTED_ALL - actual
        assert not missing, (
            f"Name(s) removed from pramanix.__all__ without updating the contract snapshot:\n"
            f"  {sorted(missing)}\n"
            "Removing a public export is a semver MAJOR breaking change.\n"
            "If intentional: update _EXPECTED_ALL, bump major version, add CHANGELOG.md entry."
        )

    def test_all_names_are_importable_as_attributes(self) -> None:
        """Every name in __all__ must be reachable as `pramanix.<name>`."""
        not_importable = [name for name in pramanix.__all__ if not hasattr(pramanix, name)]
        assert not not_importable, (
            f"Name(s) in pramanix.__all__ missing as package attributes:\n"
            f"  {not_importable}\n"
            "A name in __all__ that is not an attribute will break `from pramanix import X`."
        )

    def test_no_private_names_in_all(self) -> None:
        """No underscore-prefixed name belongs in the public API."""
        private = [n for n in pramanix.__all__ if n.startswith("_")]
        assert not private, f"Private name(s) found in pramanix.__all__: {private!r}"

    def test_all_entries_are_strings(self) -> None:
        assert all(
            isinstance(n, str) for n in pramanix.__all__
        ), "Every entry in pramanix.__all__ must be a str"


# ============================================================================
# 2.  Direct import surface — high-visibility names
# ============================================================================
#
# Verifies that the core types can be imported directly from `pramanix`
# (not just via __all__). These names appear in every user's first line of
# code and must never silently become un-importable.
# ============================================================================


class TestDirectImportSurface:
    """Contract: core public names must be importable via `from pramanix import X`."""

    def test_guard_importable(self) -> None:
        from pramanix import Guard

        assert Guard is pramanix.Guard

    def test_guard_config_importable(self) -> None:
        from pramanix import GuardConfig

        assert GuardConfig is pramanix.GuardConfig

    def test_policy_importable(self) -> None:
        from pramanix import Policy

        assert Policy is pramanix.Policy

    def test_field_importable(self) -> None:
        from pramanix import Field

        assert Field is pramanix.Field

    def test_e_importable(self) -> None:
        from pramanix import E

        assert E is pramanix.E

    def test_decision_importable(self) -> None:
        from pramanix import Decision

        assert Decision is pramanix.Decision

    def test_solver_status_importable(self) -> None:
        from pramanix import SolverStatus

        assert SolverStatus is pramanix.SolverStatus

    def test_pramanix_error_importable(self) -> None:
        from pramanix import PramanixError

        assert issubclass(PramanixError, Exception)

    def test_guard_violation_error_is_pramanix_error(self) -> None:
        from pramanix import GuardViolationError, PramanixError

        assert issubclass(GuardViolationError, PramanixError)

    def test_configuration_error_is_pramanix_error(self) -> None:
        from pramanix import ConfigurationError, PramanixError

        assert issubclass(ConfigurationError, PramanixError)


# ============================================================================
# 3.  SolverStatus — member names, wire values, and iteration order
# ============================================================================
#
# Wire values (.value strings) appear in:
#   - Decision.to_dict()["status"]
#   - JSON audit logs written to persistent storage
#   - CLI `pramanix audit verify` comparisons
# Changing a wire value silently corrupts ALL existing audit records.
#
# Iteration order is the documented enumeration order (Python enum preserves
# insertion order). Reordering is a MINOR change; names/values are MAJOR.
#
# To update: change _EXPECTED_SOLVER_STATUS_ORDERED, add CHANGELOG.md entry.
# ============================================================================

# Ordered tuple — iteration order is locked.
# Reordering requires a MINOR bump (non-breaking, but visible in for-loops
# and documentation that lists members in source order).
_EXPECTED_SOLVER_STATUS_ORDERED: tuple[tuple[str, str], ...] = (
    ("SAFE", "safe"),
    ("UNSAFE", "unsafe"),
    ("TIMEOUT", "timeout"),
    ("ERROR", "error"),
    ("STALE_STATE", "stale_state"),
    ("VALIDATION_FAILURE", "validation_failure"),
    ("RATE_LIMITED", "rate_limited"),
    ("CONSENSUS_FAILURE", "consensus_failure"),
    ("CACHE_HIT", "cache_hit"),
    # Phase 1-A: post-Z3 governance gate (MINOR bump)
    ("GOVERNANCE_BLOCKED", "governance_blocked"),
)

# Derived dict — used for per-member value assertions (order-independent).
_EXPECTED_SOLVER_STATUS: dict[str, str] = dict(_EXPECTED_SOLVER_STATUS_ORDERED)


class TestSolverStatusLock:
    """Contract: SolverStatus members, wire values, and order must not change silently."""

    def test_exact_member_count(self) -> None:
        actual_count = sum(1 for _ in SolverStatus)
        expected_count = len(_EXPECTED_SOLVER_STATUS_ORDERED)
        assert actual_count == expected_count, (
            f"SolverStatus has {actual_count} members, expected {expected_count}. "
            "Update _EXPECTED_SOLVER_STATUS_ORDERED and classify the new/removed member."
        )

    def test_no_unexpected_members(self) -> None:
        """New members require explicit snapshot update and classification."""
        actual_names = {m.name for m in SolverStatus}
        unexpected = actual_names - set(_EXPECTED_SOLVER_STATUS)
        assert not unexpected, (
            f"New SolverStatus member(s) without snapshot update:\n  {sorted(unexpected)}\n"
            "Add to _EXPECTED_SOLVER_STATUS_ORDERED and classify in decision.py "
            "(_BLOCKED_STATUSES / SAFE-only / OBSERVABILITY)."
        )

    def test_no_missing_members(self) -> None:
        """Removing a member is MAJOR — callers may hold references to the removed name."""
        actual_names = {m.name for m in SolverStatus}
        missing = set(_EXPECTED_SOLVER_STATUS) - actual_names
        assert not missing, (
            f"SolverStatus member(s) removed:\n  {sorted(missing)}\n"
            "Removing an enum member is a semver MAJOR breaking change."
        )

    def test_wire_values_unchanged(self) -> None:
        """Wire values appear in persistent audit logs — any change corrupts stored records."""
        actual = {m.name: m.value for m in SolverStatus}
        mismatches = [
            f"  {name}: expected {exp!r}, got {actual[name]!r}"
            for name, exp in _EXPECTED_SOLVER_STATUS.items()
            if name in actual and actual[name] != exp
        ]
        assert not mismatches, (
            "SolverStatus wire value(s) changed (MAJOR — corrupts audit logs):\n"
            + "\n".join(mismatches)
        )

    def test_iteration_order_locked(self) -> None:
        """Enum declaration order is part of the documented public interface."""
        actual_order = tuple((m.name, m.value) for m in SolverStatus)
        assert actual_order == _EXPECTED_SOLVER_STATUS_ORDERED, (
            "SolverStatus iteration order changed (MINOR change — must be explicit).\n"
            f"  Expected: {_EXPECTED_SOLVER_STATUS_ORDERED}\n"
            f"  Got:      {actual_order}\n"
            "Update _EXPECTED_SOLVER_STATUS_ORDERED and add CHANGELOG.md entry."
        )

    def test_all_values_are_str(self) -> None:
        """SolverStatus inherits from StrEnum — every .value must be a plain str."""
        non_str = [(m.name, type(m.value)) for m in SolverStatus if not isinstance(m.value, str)]
        assert not non_str, f"SolverStatus member(s) with non-str .value: {non_str!r}"

    def test_every_member_equals_its_value_string(self) -> None:
        """StrEnum members must compare equal to their .value string."""
        for member in SolverStatus:
            assert member == member.value, (
                f"SolverStatus.{member.name} != {member.value!r}. "
                "The StrEnum identity contract is broken."
            )

    def test_safe_is_sole_non_blocked_non_observability(self) -> None:
        """Architectural invariant: the allowed=True path flows through SAFE only."""
        non_blocked_non_safe = [
            m for m in SolverStatus if m is not SolverStatus.SAFE and m not in _BLOCKED_STATUSES
        ]
        assert non_blocked_non_safe == [SolverStatus.CACHE_HIT], (
            f"Unexpected unclassified SolverStatus member(s): {non_blocked_non_safe!r}.\n"
            "Every new member must be placed in _BLOCKED_STATUSES OR explicitly\n"
            "listed as OBSERVABILITY-only in decision.py."
        )

    def test_blocked_statuses_are_subset_of_solver_status(self) -> None:
        """_BLOCKED_STATUSES must only reference members that actually exist."""
        unknown = _BLOCKED_STATUSES - set(SolverStatus)
        assert not unknown, f"_BLOCKED_STATUSES references non-existent members: {unknown!r}"


# ============================================================================
# 4.  Decision.to_dict() — wire schema key set and per-field type semantics
# ============================================================================
#
# Decision.to_dict() is the canonical wire format for:
#   - Audit log persistence
#   - CLI `pramanix audit verify` command
#   - Any downstream consumer that deserialises a Decision
#
# Key set: adding a key is MINOR; removing/renaming is MAJOR.
# Value types: changing a type is MAJOR (corrupts deserialisation code).
#
# Fields NOT locked for specific content (only type/presence):
#   - metadata:      dict — caller-supplied; content varies per policy
#   - intent_dump:   dict — runtime intent data
#   - state_dump:    dict — runtime state data
#   - explanation:   str  — human-readable; wording may change in patches
#
# To update: change _EXPECTED_DECISION_KEYS or the per-field type tests,
#            add CHANGELOG.md entry with semver category.
# ============================================================================

_EXPECTED_DECISION_KEYS: frozenset[str] = frozenset(
    {
        "decision_id",
        "allowed",
        "status",
        "violated_invariants",
        "explanation",
        "solver_time_ms",
        "metadata",
        "intent_dump",
        "state_dump",
        "decision_hash",
        "signature",
        "public_key_id",
        "policy_hash",
        # P0: hash algorithm version field (v1.0.0+)
        "hash_alg",
    }
)


@pytest.fixture(scope="module")
def _safe_decision() -> Decision:
    return Decision.safe(metadata={"policy": "contract-test"})


@pytest.fixture(scope="module")
def _unsafe_decision() -> Decision:
    return Decision.unsafe(
        violated_invariants=("amount_exceeds_balance",),
        explanation="Amount exceeds balance",
        metadata={"policy": "contract-test"},
    )


class TestDecisionToDictLock:
    """Contract: Decision.to_dict() wire schema and field types must not change silently."""

    # â"€â"€ key set â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    def test_exact_key_count(self, _safe_decision: Decision) -> None:
        actual_keys = frozenset(_safe_decision.to_dict())
        assert len(actual_keys) == len(_EXPECTED_DECISION_KEYS), (
            f"Decision.to_dict() has {len(actual_keys)} keys, expected "
            f"{len(_EXPECTED_DECISION_KEYS)}.\n"
            f"  Actual:   {sorted(actual_keys)}\n"
            f"  Expected: {sorted(_EXPECTED_DECISION_KEYS)}"
        )

    def test_no_unexpected_keys(self, _safe_decision: Decision) -> None:
        unexpected = frozenset(_safe_decision.to_dict()) - _EXPECTED_DECISION_KEYS
        assert not unexpected, (
            f"New key(s) in Decision.to_dict() without snapshot update: {sorted(unexpected)!r}.\n"
            "Add to _EXPECTED_DECISION_KEYS and document in CHANGELOG.md (MINOR)."
        )

    def test_no_missing_keys(self, _safe_decision: Decision) -> None:
        missing = _EXPECTED_DECISION_KEYS - frozenset(_safe_decision.to_dict())
        assert not missing, (
            f"Key(s) removed from Decision.to_dict(): {sorted(missing)!r}.\n"
            "Removing a wire field is a semver MAJOR breaking change."
        )

    # â"€â"€ per-field type semantics â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    def test_decision_id_is_uuid4_str(self, _safe_decision: Decision) -> None:
        """decision_id is used as a distributed trace key — must be UUID4 string."""
        d = _safe_decision.to_dict()
        assert (
            isinstance(d["decision_id"], str) and d["decision_id"]
        ), "decision_id must be a non-empty str"
        try:
            parsed = uuid.UUID(d["decision_id"])
        except ValueError:
            pytest.fail(f"decision_id {d['decision_id']!r} is not a valid UUID string")
        assert parsed.version == 4, f"decision_id must be UUID4, got version {parsed.version}"

    def test_allowed_is_exactly_bool(self, _safe_decision: Decision) -> None:
        """allowed must be bool, not int — `type(x) is bool` is stricter than isinstance."""
        d = _safe_decision.to_dict()
        assert (
            type(d["allowed"]) is bool
        ), f"allowed must be exactly bool (not int subclass), got {type(d['allowed'])}"

    def test_status_is_str_and_known_wire_value(self, _safe_decision: Decision) -> None:
        """status must be the plain str wire value, not a SolverStatus instance."""
        d = _safe_decision.to_dict()
        assert isinstance(
            d["status"], str
        ), f"status must be plain str (not SolverStatus enum), got {type(d['status'])}"
        known_values = set(_EXPECTED_SOLVER_STATUS.values())
        assert d["status"] in known_values, (
            f"status {d['status']!r} is not a known SolverStatus wire value. "
            f"Known: {sorted(known_values)!r}"
        )

    def test_violated_invariants_is_list_of_str(self, _safe_decision: Decision) -> None:
        d = _safe_decision.to_dict()
        assert isinstance(
            d["violated_invariants"], list
        ), f"violated_invariants must be list, got {type(d['violated_invariants'])}"
        for item in d["violated_invariants"]:
            assert isinstance(
                item, str
            ), f"violated_invariants must be list[str], found item of type {type(item)!r}"

    def test_explanation_is_str(self, _safe_decision: Decision) -> None:
        d = _safe_decision.to_dict()
        assert isinstance(
            d["explanation"], str
        ), f"explanation must be str, got {type(d['explanation'])}"

    def test_solver_time_ms_is_non_negative_numeric(self, _safe_decision: Decision) -> None:
        d = _safe_decision.to_dict()
        assert isinstance(
            d["solver_time_ms"], int | float
        ), f"solver_time_ms must be numeric, got {type(d['solver_time_ms'])}"
        assert d["solver_time_ms"] >= 0, f"solver_time_ms must be >= 0, got {d['solver_time_ms']}"

    def test_metadata_is_dict(self, _safe_decision: Decision) -> None:
        assert isinstance(_safe_decision.to_dict()["metadata"], dict)

    def test_intent_dump_is_dict(self, _safe_decision: Decision) -> None:
        assert isinstance(_safe_decision.to_dict()["intent_dump"], dict)

    def test_state_dump_is_dict(self, _safe_decision: Decision) -> None:
        assert isinstance(_safe_decision.to_dict()["state_dump"], dict)

    def test_decision_hash_is_64_char_lowercase_hex(self, _safe_decision: Decision) -> None:
        """decision_hash is SHA-256 — 64 lowercase hex chars."""
        d = _safe_decision.to_dict()
        assert isinstance(
            d["decision_hash"], str
        ), f"decision_hash must be str, got {type(d['decision_hash'])}"
        assert (
            len(d["decision_hash"]) == 64
        ), f"decision_hash must be 64 hex chars (SHA-256), got {len(d['decision_hash'])}"
        assert re.fullmatch(
            r"[0-9a-f]{64}", d["decision_hash"]
        ), f"decision_hash must be lowercase hex: {d['decision_hash']!r}"

    def test_signature_is_str_or_none_not_bytes(self, _safe_decision: Decision) -> None:
        """signature must be str | None — bytes breaks JSON serialisation."""
        d = _safe_decision.to_dict()
        assert d["signature"] is None or isinstance(
            d["signature"], str
        ), f"signature must be str | None (not bytes), got {type(d['signature'])}"

    def test_public_key_id_is_str_or_none(self, _safe_decision: Decision) -> None:
        d = _safe_decision.to_dict()
        assert d["public_key_id"] is None or isinstance(
            d["public_key_id"], str
        ), f"public_key_id must be str | None, got {type(d['public_key_id'])}"

    def test_policy_hash_is_str_or_none(self, _safe_decision: Decision) -> None:
        d = _safe_decision.to_dict()
        assert d["policy_hash"] is None or isinstance(
            d["policy_hash"], str
        ), f"policy_hash must be str | None, got {type(d['policy_hash'])}"

    # â"€â"€ cross-field invariants â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    def test_safe_decision_allowed_true_status_safe(self, _safe_decision: Decision) -> None:
        d = _safe_decision.to_dict()
        assert d["allowed"] is True
        assert d["status"] == "safe"

    def test_unsafe_decision_allowed_false_status_unsafe(self, _unsafe_decision: Decision) -> None:
        d = _unsafe_decision.to_dict()
        assert d["allowed"] is False
        assert d["status"] == "unsafe"

    def test_unsafe_violated_invariants_populated(self, _unsafe_decision: Decision) -> None:
        d = _unsafe_decision.to_dict()
        assert d["violated_invariants"] == ["amount_exceeds_balance"]

    def test_decision_hash_is_deterministic(self, _safe_decision: Decision) -> None:
        """Same Decision must produce the same hash on every to_dict() call."""
        assert (
            _safe_decision.to_dict()["decision_hash"] == _safe_decision.to_dict()["decision_hash"]
        ), "Decision.to_dict()['decision_hash'] is not deterministic"


# ============================================================================
# 5.  Decision factory methods — existence and status contract
# ============================================================================
#
# Factory methods are the canonical way to construct Decisions.
# Their existence and return-status are part of the public contract.
# ============================================================================


class TestDecisionFactories:
    """Contract: all factory class-methods must exist and return the correct status."""

    def test_safe_factory_exists(self) -> None:
        assert callable(getattr(Decision, "safe", None)), "Decision.safe() must exist"

    def test_unsafe_factory_exists(self) -> None:
        assert callable(getattr(Decision, "unsafe", None)), "Decision.unsafe() must exist"

    def test_error_factory_exists(self) -> None:
        assert callable(getattr(Decision, "error", None)), "Decision.error() must exist"

    def test_timeout_factory_exists(self) -> None:
        assert callable(getattr(Decision, "timeout", None)), "Decision.timeout() must exist"

    def test_stale_state_factory_exists(self) -> None:
        assert callable(getattr(Decision, "stale_state", None)), "Decision.stale_state() must exist"

    def test_validation_failure_factory_exists(self) -> None:
        assert callable(
            getattr(Decision, "validation_failure", None)
        ), "Decision.validation_failure() must exist"

    def test_safe_returns_allowed_true_and_safe_status(self) -> None:
        d = Decision.safe()
        assert d.allowed is True
        assert d.status is SolverStatus.SAFE

    def test_unsafe_returns_allowed_false_and_unsafe_status(self) -> None:
        d = Decision.unsafe(violated_invariants=("x",))
        assert d.allowed is False
        assert d.status is SolverStatus.UNSAFE

    def test_error_returns_allowed_false_and_error_status(self) -> None:
        d = Decision.error(reason="test error")
        assert d.allowed is False
        assert d.status is SolverStatus.ERROR

    def test_timeout_returns_allowed_false_and_timeout_status(self) -> None:
        d = Decision.timeout(label="amount_check", timeout_ms=5000)
        assert d.allowed is False
        assert d.status is SolverStatus.TIMEOUT

    def test_stale_state_returns_allowed_false_and_stale_status(self) -> None:
        d = Decision.stale_state(expected="v2", actual="v1")
        assert d.allowed is False
        assert d.status is SolverStatus.STALE_STATE

    def test_validation_failure_returns_allowed_false(self) -> None:
        d = Decision.validation_failure(reason="bad input")
        assert d.allowed is False
        assert d.status is SolverStatus.VALIDATION_FAILURE

    def test_decision_is_frozen(self) -> None:
        """Decision must be immutable — callers rely on this for thread safety."""
        d = Decision.safe()
        with pytest.raises(AttributeError):
            d.allowed = False  # type: ignore[misc]


# ============================================================================
# 6.  GuardConfig — field names, stable defaults, and immutability
# ============================================================================
#
# GuardConfig fields are part of the public API: callers write
# GuardConfig(field=value) and depend on keyword argument names being stable.
#
# FIELD NAMES:    removing/renaming is MAJOR.  Adding with a default is MINOR.
# DEFAULT VALUES: the values below are part of the operational contract.
#   Changing a default silently changes behaviour for every caller that relied
#   on the default.  Treat as MINOR if the new default is strictly safer,
#   MAJOR otherwise.
#
# Fields intentionally NOT locked for default value (operational tuning —
# may be tightened across patch releases without a version bump):
#   - shed_latency_threshold_ms
#   - shed_worker_pct
#
# To update: change _EXPECTED_GUARDCONFIG_FIELDS or _EXPECTED_GUARDCONFIG_DEFAULTS,
#            add CHANGELOG.md entry with semver category.
# ============================================================================

_EXPECTED_GUARDCONFIG_FIELDS: frozenset[str] = frozenset(
    {
        "execution_mode",
        "solver_timeout_ms",
        "max_workers",
        "max_decisions_per_worker",
        "worker_warmup",
        "log_level",
        "metrics_enabled",
        "otel_enabled",
        "translator_enabled",
        "fast_path_enabled",
        "fast_path_rules",
        "shed_latency_threshold_ms",
        "shed_worker_pct",
        "signer",
        "solver_rlimit",
        "max_input_bytes",
        "min_response_ms",
        "redact_violations",
        "expected_policy_hash",
        "injection_threshold",
        # D-1: consensus strictness (v1.0.0)
        "consensus_strictness",
        # D-3: input size guard (v1.0.0)
        "max_input_chars",
        # D-4: custom injection scorer path (v1.0.0)
        "injection_scorer_path",
        # E-4: audit sinks (v1.0.0)
        "audit_sinks",
        # translator circuit breaker config (v1.0.0)
        "translator_circuit_breaker_config",
        # Phase 1-B: GovernanceConfig bundle (replaces 4 flat fields) (v1.0.0+)
        "governance",
        "memory_store",
    }
)

# Locked default values.  Fields marked (*) encode a safety/security guarantee:
# changing them requires explicit security review in the PR.
_EXPECTED_GUARDCONFIG_DEFAULTS: dict[str, Any] = {
    "execution_mode": "sync",
    "solver_timeout_ms": 5_000,  # (*) Z3 solver timeout
    "max_workers": 4,
    "max_decisions_per_worker": 10_000,
    "worker_warmup": True,
    "log_level": "INFO",
    "metrics_enabled": False,
    "otel_enabled": False,
    "translator_enabled": False,
    "fast_path_enabled": False,
    "fast_path_rules": (),
    "signer": None,
    "solver_rlimit": 10_000_000,  # (*) anti-DoS resource limit
    "max_input_bytes": 65_536,  # (*) 64 KiB input cap
    "min_response_ms": 0.0,
    "redact_violations": False,
    "expected_policy_hash": None,
    "injection_threshold": 0.5,  # (*) injection confidence gate
    "max_input_chars": 512,  # (*) input character cap
    "injection_scorer_path": None,
    "consensus_strictness": "semantic",
    "audit_sinks": (),
    "translator_circuit_breaker_config": None,
    # Phase 1-B: GovernanceConfig bundle (replaces 4 flat fields) (v1.0.0+)
    "governance": None,
    "memory_store": None,
}


class TestGuardConfigFieldLock:
    """Contract: GuardConfig field names, defaults, and immutability must not change silently."""

    def _actual_fields(self) -> frozenset[str]:
        return frozenset(f.name for f in dataclasses.fields(GuardConfig))

    def test_exact_field_count(self) -> None:
        actual = len(self._actual_fields())
        expected = len(_EXPECTED_GUARDCONFIG_FIELDS)
        assert actual == expected, (
            f"GuardConfig has {actual} fields, expected {expected}. "
            "Update _EXPECTED_GUARDCONFIG_FIELDS."
        )

    def test_no_unexpected_fields(self) -> None:
        """New fields added without snapshot update — additions are MINOR."""
        unexpected = self._actual_fields() - _EXPECTED_GUARDCONFIG_FIELDS
        assert not unexpected, (
            f"New GuardConfig field(s) without snapshot update:\n  {sorted(unexpected)}\n"
            "Add to _EXPECTED_GUARDCONFIG_FIELDS (and _EXPECTED_GUARDCONFIG_DEFAULTS if "
            "the default is contractually stable). Document in CHANGELOG.md (MINOR)."
        )

    def test_no_missing_fields(self) -> None:
        """Removed/renamed fields are MAJOR — callers pass them as kwargs."""
        missing = _EXPECTED_GUARDCONFIG_FIELDS - self._actual_fields()
        assert not missing, (
            f"GuardConfig field(s) missing:\n  {sorted(missing)}\n"
            "Removing or renaming a GuardConfig field is a semver MAJOR breaking change."
        )

    def test_zero_arg_constructor_works(self) -> None:
        """GuardConfig() with no arguments must succeed — all fields have defaults."""
        cfg = GuardConfig()  # must not raise
        assert cfg is not None

    def test_all_fields_have_defaults(self) -> None:
        fields_without_defaults = [
            f.name
            for f in dataclasses.fields(GuardConfig)
            if (
                f.default is dataclasses.MISSING  # type: ignore[misc]
                and f.default_factory is dataclasses.MISSING  # type: ignore[misc]
            )
        ]
        assert not fields_without_defaults, (
            f"GuardConfig field(s) without defaults: {fields_without_defaults!r}. "
            "All fields must have defaults so GuardConfig() is callable with no arguments."
        )

    def test_default_values_are_stable(self) -> None:
        """Locked defaults must not change silently."""
        cfg = GuardConfig()
        mismatches = [
            f"  {name}: expected {expected!r}, got {getattr(cfg, name)!r}"
            for name, expected in _EXPECTED_GUARDCONFIG_DEFAULTS.items()
            if hasattr(cfg, name) and getattr(cfg, name) != expected
        ]
        assert not mismatches, (
            "GuardConfig default value(s) changed without snapshot update.\n"
            "Changing a default is MINOR (if safer) or MAJOR (if less safe).\n"
            "Update _EXPECTED_GUARDCONFIG_DEFAULTS and add a CHANGELOG.md entry.\n"
            + "\n".join(mismatches)
        )

    def test_guard_config_is_frozen(self) -> None:
        """GuardConfig must remain immutable (frozen=True) — mutable config is a hazard."""
        cfg = GuardConfig()
        with pytest.raises(AttributeError):  # FrozenInstanceError (3.11+) subclasses AttributeError
            cfg.execution_mode = "async-thread"  # type: ignore[misc]

    @pytest.mark.parametrize("mode", ["sync", "async-thread", "async-process"])
    def test_valid_execution_modes_accepted(self, mode: str) -> None:
        GuardConfig(execution_mode=mode)  # must not raise

    def test_invalid_execution_mode_raises_configuration_error(self) -> None:
        from pramanix import ConfigurationError

        with pytest.raises(ConfigurationError):
            GuardConfig(execution_mode="batch")  # not a valid mode

    @pytest.mark.parametrize("threshold", [0.1, 0.5, 1.0])
    def test_injection_threshold_valid_values_accepted(self, threshold: float) -> None:
        GuardConfig(injection_threshold=threshold)  # must not raise

    @pytest.mark.parametrize("threshold", [0.0, -0.1, 1.1, 2.0])
    def test_injection_threshold_out_of_range_raises(self, threshold: float) -> None:
        from pramanix import ConfigurationError

        with pytest.raises(ConfigurationError):
            GuardConfig(injection_threshold=threshold)


# ── GovernanceConfig contract ─────────────────────────────────────────────────


class TestGovernanceConfigLock:
    """Contract: GovernanceConfig structure, validation, and immutability."""

    def test_all_defaults_none(self) -> None:
        """GovernanceConfig() with no arguments must succeed and all fields must default None."""
        gov = GovernanceConfig()
        assert gov.ifc_policy is None
        assert gov.capability_manifest is None
        assert gov.execution_scope is None
        assert gov.oversight_workflow is None

    def test_is_frozen(self) -> None:
        """GovernanceConfig must remain immutable (frozen=True)."""
        gov = GovernanceConfig()
        with pytest.raises(AttributeError):
            gov.ifc_policy = object()  # type: ignore[misc]

    def test_execution_scope_without_manifest_raises(self) -> None:
        """execution_scope requires capability_manifest — cross-validation in __post_init__."""
        from pramanix.exceptions import ConfigurationError

        sentinel = object()  # stand-in for an ExecutionScope value
        with pytest.raises(
            ConfigurationError, match="execution_scope requires capability_manifest"
        ):
            GovernanceConfig(execution_scope=sentinel)

    def test_execution_scope_with_manifest_accepted(self) -> None:
        """execution_scope + capability_manifest together must not raise."""
        manifest_stub = object()
        scope_stub = object()
        gov = GovernanceConfig(capability_manifest=manifest_stub, execution_scope=scope_stub)
        assert gov.capability_manifest is manifest_stub
        assert gov.execution_scope is scope_stub

    def test_guard_config_accepts_governance_bundle(self) -> None:
        """GuardConfig(governance=GovernanceConfig()) must construct without error."""
        gov = GovernanceConfig()
        cfg = GuardConfig(governance=gov)
        assert cfg.governance is gov

    def test_guard_config_governance_default_none(self) -> None:
        """GuardConfig().governance defaults to None — all governance gates disabled."""
        assert GuardConfig().governance is None
