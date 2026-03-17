# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Unit tests for pramanix.decision — Decision dataclass and SolverStatus.

Coverage targets:
- SolverStatus enum: all six members, str-subclass semantics
- Every factory classmethod: safe, unsafe, timeout, error, stale_state,
  validation_failure
- Cross-field invariant enforcement in __post_init__
- Immutability (frozen dataclass)
- to_dict() serialisation contract
- decision_id uniqueness and UUID4 validity
- metadata isolation between instances
"""
from __future__ import annotations

import dataclasses
import json
import uuid

import pytest

from pramanix.decision import Decision, SolverStatus

# ── Compatibility: FrozenInstanceError added in Python 3.11 ──────────────────
try:
    from dataclasses import FrozenInstanceError  # type: ignore[attr-defined,unused-ignore]
except ImportError:
    FrozenInstanceError = AttributeError  # type: ignore[assignment, misc]


# ═══════════════════════════════════════════════════════════════════════════════
# SolverStatus
# ═══════════════════════════════════════════════════════════════════════════════


class TestSolverStatus:
    """SolverStatus must be a str-subclass enum with eight well-defined members."""

    def test_member_count(self) -> None:
        assert len(SolverStatus) == 8

    @pytest.mark.parametrize(
        ("member", "expected_value"),
        [
            (SolverStatus.SAFE, "safe"),
            (SolverStatus.UNSAFE, "unsafe"),
            (SolverStatus.TIMEOUT, "timeout"),
            (SolverStatus.ERROR, "error"),
            (SolverStatus.STALE_STATE, "stale_state"),
            (SolverStatus.VALIDATION_FAILURE, "validation_failure"),
        ],
    )
    def test_member_values(self, member: SolverStatus, expected_value: str) -> None:
        assert member.value == expected_value

    def test_is_str_subclass(self) -> None:
        """SolverStatus inherits str so it JSON-serialises without a custom encoder."""
        for status in SolverStatus:
            assert isinstance(status, str), f"{status!r} is not a str"

    def test_str_comparison(self) -> None:
        assert SolverStatus.SAFE.value == "safe"
        assert SolverStatus.UNSAFE.value == "unsafe"

    def test_json_serialisable_directly(self) -> None:
        payload = {"status": SolverStatus.SAFE}
        serialised = json.dumps(payload)
        assert "safe" in serialised

    def test_by_value_lookup(self) -> None:
        assert SolverStatus("safe") is SolverStatus.SAFE
        assert SolverStatus("unsafe") is SolverStatus.UNSAFE

    def test_all_members_accessible(self) -> None:
        """Access by name should work for all eight members."""
        names = {
            "SAFE",
            "UNSAFE",
            "TIMEOUT",
            "ERROR",
            "STALE_STATE",
            "VALIDATION_FAILURE",
            "RATE_LIMITED",
            "CACHE_HIT",
        }
        assert {m.name for m in SolverStatus} == names


# ═══════════════════════════════════════════════════════════════════════════════
# Decision.safe()
# ═══════════════════════════════════════════════════════════════════════════════


class TestDecisionSafe:
    """Factory: Decision.safe() — the only path to allowed=True."""

    def test_allowed_true(self) -> None:
        assert Decision.safe().allowed is True

    def test_status_safe(self) -> None:
        assert Decision.safe().status is SolverStatus.SAFE

    def test_no_violated_invariants(self) -> None:
        assert Decision.safe().violated_invariants == ()

    def test_explanation_empty(self) -> None:
        assert Decision.safe().explanation == ""

    def test_solver_time_default_zero(self) -> None:
        assert Decision.safe().solver_time_ms == 0.0

    def test_solver_time_passthrough(self) -> None:
        d = Decision.safe(solver_time_ms=12.5)
        assert d.solver_time_ms == pytest.approx(12.5)

    def test_metadata_default_empty_dict(self) -> None:
        assert Decision.safe().metadata == {}

    def test_metadata_passthrough(self) -> None:
        d = Decision.safe(metadata={"trace_id": "abc123"})
        assert d.metadata["trace_id"] == "abc123"

    def test_metadata_is_defensive_copy(self) -> None:
        """Mutating the original dict must not affect the stored metadata."""
        original: dict[str, str] = {"k": "v"}
        d = Decision.safe(metadata=original)
        original["k"] = "mutated"
        assert d.metadata["k"] == "v"

    def test_decision_id_is_valid_uuid4(self) -> None:
        d = Decision.safe()
        parsed = uuid.UUID(d.decision_id, version=4)
        assert str(parsed) == d.decision_id

    def test_decision_id_unique_per_call(self) -> None:
        ids = {Decision.safe().decision_id for _ in range(20)}
        assert len(ids) == 20


# ═══════════════════════════════════════════════════════════════════════════════
# Decision.unsafe()
# ═══════════════════════════════════════════════════════════════════════════════


class TestDecisionUnsafe:
    """Factory: Decision.unsafe() — violated invariants path."""

    def test_allowed_false(self) -> None:
        assert Decision.unsafe().allowed is False

    def test_status_unsafe(self) -> None:
        assert Decision.unsafe().status is SolverStatus.UNSAFE

    def test_violated_invariants_stored(self) -> None:
        d = Decision.unsafe(violated_invariants=("a", "b"))
        assert d.violated_invariants == ("a", "b")

    def test_violated_invariants_default_empty(self) -> None:
        assert Decision.unsafe().violated_invariants == ()

    def test_explicit_explanation_stored(self) -> None:
        d = Decision.unsafe(explanation="Custom reason.")
        assert d.explanation == "Custom reason."

    def test_auto_explanation_from_invariant_labels(self) -> None:
        d = Decision.unsafe(violated_invariants=("non_negative_balance",))
        assert "non_negative_balance" in d.explanation

    def test_explicit_explanation_overrides_auto(self) -> None:
        d = Decision.unsafe(
            violated_invariants=("x",),
            explanation="Override message.",
        )
        assert d.explanation == "Override message."

    def test_no_violations_no_auto_explanation(self) -> None:
        """When violated_invariants=() and no explanation, explanation stays ''."""
        d = Decision.unsafe()
        assert d.explanation == ""

    def test_solver_time_passthrough(self) -> None:
        d = Decision.unsafe(solver_time_ms=7.3)
        assert d.solver_time_ms == pytest.approx(7.3)

    def test_metadata_passthrough(self) -> None:
        d = Decision.unsafe(metadata={"policy": "BankingPolicy"})
        assert d.metadata["policy"] == "BankingPolicy"

    @pytest.mark.parametrize(
        "labels",
        [
            ("non_negative_balance",),
            ("a", "b"),
            ("x", "y", "z"),
        ],
    )
    def test_multiple_labels_all_stored(self, labels: tuple[str, ...]) -> None:
        d = Decision.unsafe(violated_invariants=labels)
        for label in labels:
            assert label in d.violated_invariants


# ═══════════════════════════════════════════════════════════════════════════════
# Decision.timeout()
# ═══════════════════════════════════════════════════════════════════════════════


class TestDecisionTimeout:
    """Factory: Decision.timeout() — Z3 solver exceeded the time budget."""

    def test_allowed_false(self) -> None:
        assert Decision.timeout(label="lbl", timeout_ms=5_000).allowed is False

    def test_status_timeout(self) -> None:
        d = Decision.timeout(label="lbl", timeout_ms=5_000)
        assert d.status is SolverStatus.TIMEOUT

    def test_label_in_violated_invariants(self) -> None:
        d = Decision.timeout(label="non_negative_balance", timeout_ms=100)
        assert "non_negative_balance" in d.violated_invariants

    @pytest.mark.parametrize("timeout_ms", [1, 50, 100, 5_000, 10_000])
    def test_explanation_contains_timeout_ms(self, timeout_ms: int) -> None:
        d = Decision.timeout(label="inv", timeout_ms=timeout_ms)
        assert str(timeout_ms) in d.explanation

    def test_explanation_contains_label(self) -> None:
        d = Decision.timeout(label="within_daily_limit", timeout_ms=50)
        assert "within_daily_limit" in d.explanation

    def test_metadata_passthrough(self) -> None:
        d = Decision.timeout(label="x", timeout_ms=10, metadata={"source": "fast_path"})
        assert d.metadata["source"] == "fast_path"


# ═══════════════════════════════════════════════════════════════════════════════
# Decision.error()
# ═══════════════════════════════════════════════════════════════════════════════


class TestDecisionError:
    """Factory: Decision.error() — unexpected internal error (fail-safe)."""

    def test_allowed_false(self) -> None:
        assert Decision.error().allowed is False

    def test_status_error(self) -> None:
        assert Decision.error().status is SolverStatus.ERROR

    def test_default_explanation_non_empty(self) -> None:
        assert Decision.error().explanation != ""

    def test_custom_reason_stored(self) -> None:
        d = Decision.error(reason="Z3 segfault simulation")
        assert d.explanation == "Z3 segfault simulation"

    def test_no_violated_invariants(self) -> None:
        assert Decision.error().violated_invariants == ()

    def test_solver_time_zero(self) -> None:
        assert Decision.error().solver_time_ms == 0.0

    def test_metadata_passthrough(self) -> None:
        d = Decision.error(metadata={"exc_type": "RuntimeError"})
        assert d.metadata["exc_type"] == "RuntimeError"


# ═══════════════════════════════════════════════════════════════════════════════
# Decision.stale_state()
# ═══════════════════════════════════════════════════════════════════════════════


class TestDecisionStaleState:
    """Factory: Decision.stale_state() — state_version mismatch."""

    def test_allowed_false(self) -> None:
        assert Decision.stale_state(expected="1.0", actual="0.9").allowed is False

    def test_status_stale_state(self) -> None:
        d = Decision.stale_state(expected="1.0", actual="0.9")
        assert d.status is SolverStatus.STALE_STATE

    def test_no_violated_invariants(self) -> None:
        d = Decision.stale_state(expected="1.0", actual="0.9")
        assert d.violated_invariants == ()

    def test_explanation_contains_expected_version(self) -> None:
        d = Decision.stale_state(expected="2.0", actual="1.5")
        assert "2.0" in d.explanation

    def test_explanation_contains_actual_version(self) -> None:
        d = Decision.stale_state(expected="2.0", actual="1.5")
        assert "1.5" in d.explanation

    def test_metadata_passthrough(self) -> None:
        d = Decision.stale_state(expected="1.0", actual="0.9", metadata={"retry": True})
        assert d.metadata["retry"] is True

    @pytest.mark.parametrize(
        ("expected", "actual"),
        [
            ("1.0", "0.9"),
            ("2.0", "1.0"),
            ("v3", "v2"),
        ],
    )
    def test_both_versions_in_explanation(self, expected: str, actual: str) -> None:
        d = Decision.stale_state(expected=expected, actual=actual)
        assert expected in d.explanation
        assert actual in d.explanation


# ═══════════════════════════════════════════════════════════════════════════════
# Decision.validation_failure()
# ═══════════════════════════════════════════════════════════════════════════════


class TestDecisionValidationFailure:
    """Factory: Decision.validation_failure() — Pydantic strict-mode rejection."""

    def test_allowed_false(self) -> None:
        assert Decision.validation_failure(reason="bad").allowed is False

    def test_status_validation_failure(self) -> None:
        d = Decision.validation_failure(reason="bad")
        assert d.status is SolverStatus.VALIDATION_FAILURE

    def test_reason_stored_as_explanation(self) -> None:
        d = Decision.validation_failure(reason="field 'amount' must be Decimal")
        assert d.explanation == "field 'amount' must be Decimal"

    def test_no_violated_invariants(self) -> None:
        assert Decision.validation_failure(reason="bad").violated_invariants == ()

    def test_solver_time_zero(self) -> None:
        assert Decision.validation_failure(reason="x").solver_time_ms == 0.0

    def test_metadata_passthrough(self) -> None:
        d = Decision.validation_failure(reason="x", metadata={"field": "amount"})
        assert d.metadata["field"] == "amount"


# ═══════════════════════════════════════════════════════════════════════════════
# Cross-field invariant: allowed ↔ status
# ═══════════════════════════════════════════════════════════════════════════════


class TestCrossFieldInvariant:
    """__post_init__ must enforce allowed=True ↔ status=SAFE."""

    @pytest.mark.parametrize(
        "status",
        [
            SolverStatus.UNSAFE,
            SolverStatus.TIMEOUT,
            SolverStatus.ERROR,
            SolverStatus.STALE_STATE,
            SolverStatus.VALIDATION_FAILURE,
        ],
    )
    def test_allowed_true_with_non_safe_status_raises(self, status: SolverStatus) -> None:
        with pytest.raises(ValueError, match="status=SAFE"):
            Decision(allowed=True, status=status)

    def test_allowed_false_with_safe_status_raises(self) -> None:
        with pytest.raises(ValueError, match="inconsistent"):
            Decision(allowed=False, status=SolverStatus.SAFE)

    def test_allowed_true_with_safe_status_ok(self) -> None:
        d = Decision(allowed=True, status=SolverStatus.SAFE)
        assert d.allowed is True

    @pytest.mark.parametrize(
        "status",
        [
            SolverStatus.UNSAFE,
            SolverStatus.TIMEOUT,
            SolverStatus.ERROR,
            SolverStatus.STALE_STATE,
            SolverStatus.VALIDATION_FAILURE,
        ],
    )
    def test_allowed_false_with_blocked_status_ok(self, status: SolverStatus) -> None:
        d = Decision(allowed=False, status=status)
        assert d.allowed is False


# ═══════════════════════════════════════════════════════════════════════════════
# Immutability (frozen dataclass)
# ═══════════════════════════════════════════════════════════════════════════════


class TestImmutability:
    """Frozen dataclass — no field may be reassigned after construction."""

    def test_cannot_reassign_allowed(self) -> None:
        d = Decision.safe()
        with pytest.raises((FrozenInstanceError, AttributeError, TypeError)):
            d.allowed = False  # type: ignore[misc]

    def test_cannot_reassign_status(self) -> None:
        d = Decision.safe()
        with pytest.raises((FrozenInstanceError, AttributeError, TypeError)):
            d.status = SolverStatus.ERROR  # type: ignore[misc]

    def test_cannot_reassign_violated_invariants(self) -> None:
        d = Decision.unsafe(violated_invariants=("a",))
        with pytest.raises((FrozenInstanceError, AttributeError, TypeError)):
            d.violated_invariants = ()  # type: ignore[misc]

    def test_cannot_reassign_explanation(self) -> None:
        d = Decision.error(reason="x")
        with pytest.raises((FrozenInstanceError, AttributeError, TypeError)):
            d.explanation = "y"  # type: ignore[misc]

    def test_cannot_reassign_decision_id(self) -> None:
        d = Decision.safe()
        with pytest.raises((FrozenInstanceError, AttributeError, TypeError)):
            d.decision_id = "00000000-0000-0000-0000-000000000000"  # type: ignore[misc]

    def test_metadata_isolates_between_instances(self) -> None:
        d1 = Decision.safe()
        d2 = Decision.safe()
        assert d1.metadata is not d2.metadata

    def test_frozen_instance_error_is_attribute_error_subclass(self) -> None:
        assert issubclass(FrozenInstanceError, AttributeError)


# ═══════════════════════════════════════════════════════════════════════════════
# to_dict() serialisation
# ═══════════════════════════════════════════════════════════════════════════════

_EXPECTED_KEYS = frozenset(
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
    }
)


class TestToDict:
    """to_dict() must return a JSON-serialisable dict with the full schema."""

    def test_returns_dict(self) -> None:
        assert isinstance(Decision.safe().to_dict(), dict)

    def test_all_keys_present(self) -> None:
        assert set(Decision.safe().to_dict().keys()) == _EXPECTED_KEYS

    def test_status_is_string(self) -> None:
        d = Decision.safe().to_dict()
        assert isinstance(d["status"], str)
        assert d["status"] == "safe"

    def test_violated_invariants_is_list(self) -> None:
        d = Decision.unsafe(violated_invariants=("a", "b")).to_dict()
        assert isinstance(d["violated_invariants"], list)
        assert d["violated_invariants"] == ["a", "b"]

    def test_allowed_is_bool(self) -> None:
        ds = Decision.safe().to_dict()
        du = Decision.unsafe().to_dict()
        assert ds["allowed"] is True
        assert du["allowed"] is False

    def test_round_trip_preserves_values(self) -> None:
        original = Decision.unsafe(
            violated_invariants=("non_negative_balance",),
            explanation="Overdraft",
            solver_time_ms=3.14,
            metadata={"policy": "BankingPolicy"},
        )
        d = original.to_dict()
        assert d["allowed"] is False
        assert d["status"] == "unsafe"
        assert d["explanation"] == "Overdraft"
        assert d["solver_time_ms"] == pytest.approx(3.14)
        assert d["decision_id"] == original.decision_id
        assert d["metadata"]["policy"] == "BankingPolicy"

    def test_fully_json_serialisable(self) -> None:
        d = Decision.unsafe(
            violated_invariants=("x",),
            explanation="violated",
            metadata={"key": "value"},
        )
        serialised = json.dumps(d.to_dict())
        assert "violated" in serialised
        assert "unsafe" in serialised

    @pytest.mark.parametrize(
        "factory_result",
        [
            Decision.safe(solver_time_ms=1.0),
            Decision.unsafe(violated_invariants=("a",), explanation="msg"),
            Decision.timeout(label="lbl", timeout_ms=50),
            Decision.error(reason="boom"),
            Decision.stale_state(expected="1.0", actual="0.9"),
            Decision.validation_failure(reason="bad field"),
        ],
    )
    def test_all_factories_produce_json_serialisable_dicts(self, factory_result: Decision) -> None:
        d = factory_result.to_dict()
        json.dumps(d)  # Must not raise

    def test_dataclasses_asdict_compatible(self) -> None:
        d = Decision.safe()
        as_dict = dataclasses.asdict(d)
        assert as_dict["allowed"] is True


# ═══════════════════════════════════════════════════════════════════════════════
# decision_id uniqueness
# ═══════════════════════════════════════════════════════════════════════════════


class TestDecisionId:
    """decision_id must be a valid UUID4 string, unique per call."""

    @pytest.mark.parametrize(
        "decision",
        [
            Decision.safe(),
            Decision.unsafe(),
            Decision.timeout(label="l", timeout_ms=1),
            Decision.error(),
            Decision.stale_state(expected="1", actual="0"),
            Decision.validation_failure(reason="x"),
        ],
    )
    def test_is_valid_uuid4(self, decision: Decision) -> None:
        parsed = uuid.UUID(decision.decision_id, version=4)
        assert str(parsed) == decision.decision_id

    def test_100_ids_are_unique(self) -> None:
        ids = {Decision.safe().decision_id for _ in range(100)}
        assert len(ids) == 100
