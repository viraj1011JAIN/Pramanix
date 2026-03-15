# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Adversarial tests — fail-safe invariant: every exception path → Decision(allowed=False).

Security requirement (CTO Phase 7 brief):
    The most important test you will ever write.  Every exception path in
    ``Guard.verify()`` must produce ``Decision(allowed=False)``.  If even one
    path returns ``True`` or propagates a raw exception to the caller, the SDK
    fails its core security contract.

    "If you can't break it, the banks can't trust it." — Phase 7 CTO brief.

Coverage targets — all 6 pipeline stages in ``Guard.verify()``:

    Stage 1 — Intent validation:
        • ``pydantic.ValidationError`` during ``validate_intent()``
        • ``StateValidationError`` raised by the validator

    Stage 2 — State validation:
        • ``pydantic.ValidationError`` during ``validate_state()``

    Stage 3 — model_dump() / safe_dump():
        • Generic ``RuntimeError`` during serialization

    Stage 4 — Version check / conflicting keys:
        • ``ValueError`` from conflicting intent/state keys

    Stage 5 — Z3 solve:
        • ``SolverTimeoutError`` (Z3 budget exhausted)
        • ``z3.Z3Exception`` from the solver
        • ``MemoryError`` in the transpiler
        • Generic ``Exception`` from ``invariants()`` override

    Catch-all:
        • Bare ``Exception`` from outside the typed catch blocks

Golden rules verified by every test in this module:
    1.  ``decision.allowed is False``         — NEVER True
    2.  ``decision`` is a ``Decision``        — NEVER a raw exception
    3.  No exception propagates to the caller — NEVER raises

This file targets 100% branch coverage of ``guard.py``'s exception handlers.
"""
from __future__ import annotations

from decimal import Decimal
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest
import z3 as _z3
from pydantic import BaseModel
from pydantic import Field as PydanticField

from pramanix import E, Field, Guard, GuardConfig, Policy
from pramanix.decision import Decision, SolverStatus
from pramanix.exceptions import (
    SolverTimeoutError,
    StateValidationError,
    TranspileError,
    ValidationError,
)

if TYPE_CHECKING:
    from pramanix.expressions import ConstraintExpr

# ── Shared infrastructure ────────────────────────────────────────────────────


class _TestIntent(BaseModel):
    amount: Decimal = PydanticField(gt=0, le=Decimal("1_000_000"))


class _TestState(BaseModel):
    state_version: str
    balance: Decimal


class _StablePolicy(Policy):
    """A fully-valid policy used as the baseline for injection tests."""

    class Meta:
        version = "1.0"
        intent_model = _TestIntent
        state_model = _TestState

    balance = Field("balance", Decimal, "Real")
    amount = Field("amount", Decimal, "Real")

    @classmethod
    def invariants(cls) -> list[ConstraintExpr]:
        return [(E(cls.balance) - E(cls.amount) >= Decimal("0")).named("non_negative_balance")]


_VALID_INTENT = {"amount": Decimal("100.00")}
_VALID_STATE = {"balance": Decimal("1000.00"), "state_version": "1.0"}


def _make_guard() -> Guard:
    return Guard(_StablePolicy, GuardConfig(execution_mode="sync"))


def _assert_fail_safe(decision: object, context: str) -> None:
    """Common assertion: result must be a Decision with allowed=False."""
    assert isinstance(
        decision, Decision
    ), f"{context}: expected Decision, got {type(decision).__name__}"
    assert decision.allowed is False, (
        f"{context}: expected allowed=False, got allowed=True. "
        "CRITICAL: Guard.verify() returned True on an error path — SECURITY VIOLATION."
    )


# ── Stage 1: Intent Validation Failures ──────────────────────────────────────


class TestStage1IntentValidation:
    """Inject failures at the Pydantic intent-validation stage."""

    def test_intent_validation_error_returns_false(self) -> None:
        """Pydantic ValidationError during validate_intent → Decision(VALIDATION_FAILURE)."""
        guard = _make_guard()
        decision = guard.verify(
            intent={"amount": Decimal("-1.00")},  # violates gt=0
            state=_VALID_STATE,
        )
        _assert_fail_safe(decision, "intent gt=0 violation")
        assert decision.status is SolverStatus.VALIDATION_FAILURE

    def test_intent_type_error_returns_false(self) -> None:
        """Wrong type for Decimal field in strict mode → blocked."""
        guard = _make_guard()
        decision = guard.verify(
            intent={"amount": "not-a-number"},  # type: str, not Decimal
            state=_VALID_STATE,
        )
        _assert_fail_safe(decision, "intent type mismatch")
        assert decision.status is SolverStatus.VALIDATION_FAILURE

    def test_intent_missing_required_field_returns_false(self) -> None:
        """Missing required field in intent → VALIDATION_FAILURE."""
        guard = _make_guard()
        decision = guard.verify(
            intent={},  # empty — 'amount' is required
            state=_VALID_STATE,
        )
        _assert_fail_safe(decision, "intent missing field")
        assert decision.status is SolverStatus.VALIDATION_FAILURE

    def test_validate_intent_raises_pramanix_validation_error(self) -> None:
        """Force pramanix.ValidationError in validate_intent — caught and wrapped."""
        guard = _make_guard()
        with patch(
            "pramanix.guard.validate_intent",
            side_effect=ValidationError("mock intent validation failure"),
        ):
            decision = guard.verify(intent=_VALID_INTENT, state=_VALID_STATE)
        _assert_fail_safe(decision, "patched ValidationError in validate_intent")
        assert decision.status is SolverStatus.VALIDATION_FAILURE

    def test_validate_intent_raises_state_validation_error(self) -> None:
        """StateValidationError from validate_intent → VALIDATION_FAILURE."""
        guard = _make_guard()
        with patch(
            "pramanix.guard.validate_intent",
            side_effect=StateValidationError("patched state error"),
        ):
            decision = guard.verify(intent=_VALID_INTENT, state=_VALID_STATE)
        _assert_fail_safe(decision, "patched StateValidationError in validate_intent")
        assert decision.status is SolverStatus.VALIDATION_FAILURE


# ── Stage 2: State Validation Failures ───────────────────────────────────────


class TestStage2StateValidation:
    """Inject failures at the Pydantic state-validation stage."""

    def test_state_validation_error_returns_false(self) -> None:
        """Wrong type in state model → VALIDATION_FAILURE."""
        guard = _make_guard()
        decision = guard.verify(
            intent=_VALID_INTENT,
            state={"balance": "not-a-decimal", "state_version": "1.0"},
        )
        _assert_fail_safe(decision, "state type mismatch")
        assert decision.status is SolverStatus.VALIDATION_FAILURE

    def test_state_missing_state_version_returns_false(self) -> None:
        """Missing state_version in state model → VALIDATION_FAILURE."""
        guard = _make_guard()
        decision = guard.verify(
            intent=_VALID_INTENT,
            state={"balance": Decimal("1000.00")},  # no state_version
        )
        _assert_fail_safe(decision, "state missing state_version")
        # Could be VALIDATION_FAILURE (Pydantic) or caught by step-4 guard,
        # but MUST be False.

    def test_validate_state_raises_pramanix_validation_error(self) -> None:
        """Force ValidationError in validate_state — caught by handler."""
        guard = _make_guard()
        with patch(
            "pramanix.guard.validate_state",
            side_effect=ValidationError("mock state validation failure"),
        ):
            decision = guard.verify(intent=_VALID_INTENT, state=_VALID_STATE)
        _assert_fail_safe(decision, "patched ValidationError in validate_state")
        assert decision.status is SolverStatus.VALIDATION_FAILURE


# ── Stage 4: Version check / conflicting keys ─────────────────────────────────


class TestStage4VersionAndKeyConflict:
    """Inject failures at the version check and key-collision stages."""

    def test_version_mismatch_returns_stale_state(self) -> None:
        """state_version != Policy.Meta.version → STALE_STATE (allowed=False)."""
        guard = _make_guard()
        decision = guard.verify(
            intent=_VALID_INTENT,
            state={"balance": Decimal("1000.00"), "state_version": "99.0"},
        )
        _assert_fail_safe(decision, "state_version mismatch")
        assert decision.status is SolverStatus.STALE_STATE

    def test_conflicting_intent_state_keys_returns_error(self) -> None:
        """Intent and state sharing a key key → ValueError → Decision.error(False)."""

        # No Pydantic models: raw dict mode, where key conflict is possible.
        class _RawPolicy(Policy):
            class Meta:
                version = None  # disable version check

            balance = Field("balance", Decimal, "Real")
            amount = Field("amount", Decimal, "Real")

            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [(E(cls.balance) >= Decimal("0")).named("non_negative")]

        guard = Guard(_RawPolicy)
        # 'balance' appears in BOTH intent and state — conflict!
        decision = guard.verify(
            intent={"amount": Decimal("100"), "balance": Decimal("50")},
            state={"balance": Decimal("1000")},
        )
        _assert_fail_safe(decision, "conflicting keys ValueError")
        assert decision.status is SolverStatus.ERROR


# ── Stage 5: Solver Failures ─────────────────────────────────────────────────


class TestStage5SolverFailures:
    """Inject failures at the Z3 solver stage."""

    def test_solver_timeout_error_returns_timeout_decision(self) -> None:
        """SolverTimeoutError from solver → Decision.timeout (allowed=False)."""
        guard = _make_guard()
        with patch(
            "pramanix.guard.solve",
            side_effect=SolverTimeoutError(label="non_negative_balance", timeout_ms=5000),
        ):
            decision = guard.verify(intent=_VALID_INTENT, state=_VALID_STATE)
        _assert_fail_safe(decision, "patched SolverTimeoutError")
        assert decision.status is SolverStatus.TIMEOUT

    def test_z3_exception_in_solver_returns_error(self) -> None:
        """z3.Z3Exception from solver → caught as generic Exception → Decision.error."""
        guard = _make_guard()
        with patch(
            "pramanix.guard.solve",
            side_effect=_z3.Z3Exception("synthetic Z3 context error"),
        ):
            decision = guard.verify(intent=_VALID_INTENT, state=_VALID_STATE)
        _assert_fail_safe(decision, "patched Z3Exception")
        assert decision.status is SolverStatus.ERROR

    def test_memory_error_in_transpiler_returns_error(self) -> None:
        """MemoryError during transpile (Z3 may OOM on huge formulas) → Decision.error."""
        guard = _make_guard()
        with patch(
            "pramanix.guard.solve",
            side_effect=MemoryError("Z3 out of memory — formula too large"),
        ):
            decision = guard.verify(intent=_VALID_INTENT, state=_VALID_STATE)
        _assert_fail_safe(decision, "patched MemoryError in transpiler")
        assert decision.status is SolverStatus.ERROR

    def test_transpile_error_from_invariants_returns_error(self) -> None:
        """TranspileError raised from invariants() → PramanixError handler → Decision.error."""
        guard = _make_guard()
        with patch(
            "pramanix.guard.solve",
            side_effect=TranspileError("deliberate transpile crash"),
        ):
            decision = guard.verify(intent=_VALID_INTENT, state=_VALID_STATE)
        _assert_fail_safe(decision, "patched TranspileError")
        assert decision.status is SolverStatus.ERROR

    def test_invariants_raises_runtime_error_returns_error(self) -> None:
        """RuntimeError from user-defined invariants() → catch-all → Decision.error(False)."""
        guard = _make_guard()
        with patch(
            "pramanix.guard.solve",
            side_effect=RuntimeError("Deliberate crash in invariants()"),
        ):
            decision = guard.verify(intent=_VALID_INTENT, state=_VALID_STATE)
        _assert_fail_safe(decision, "patched RuntimeError in solve")
        assert decision.status is SolverStatus.ERROR

    def test_keyboard_interrupt_is_not_suppressed(self) -> None:
        """KeyboardInterrupt must propagate — it should never be swallowed by
        Guard.verify().  This confirms the bare-except is *not* used."""
        guard = _make_guard()
        # Guard's catch-all uses `except Exception` — KeyboardInterrupt is
        # NOT a subclass of Exception, so it will propagate correctly.
        with patch(
            "pramanix.guard.solve",
            side_effect=KeyboardInterrupt,
        ), pytest.raises(KeyboardInterrupt):
            guard.verify(intent=_VALID_INTENT, state=_VALID_STATE)


# ── Catch-all: Generic Exception ─────────────────────────────────────────────


class TestCatchAllExceptionPath:
    """Verify the broad ``except Exception`` catch at the bottom of verify()."""

    def test_arbitrary_exception_returns_error_decision(self) -> None:
        """Any unexpected exception derived from Exception → Decision.error."""
        guard = _make_guard()

        class _WeirdError(Exception):
            pass

        with patch("pramanix.guard.solve", side_effect=_WeirdError("Unexpected!")):
            decision = guard.verify(intent=_VALID_INTENT, state=_VALID_STATE)
        _assert_fail_safe(decision, "arbitrary Exception subclass")
        assert decision.status is SolverStatus.ERROR

    def test_os_error_in_solve_returns_error_decision(self) -> None:
        """OSError (unexpected I/O during Z3) → Decision.error."""
        guard = _make_guard()
        with patch(
            "pramanix.guard.solve",
            side_effect=OSError("File descriptor issue during Z3 init"),
        ):
            decision = guard.verify(intent=_VALID_INTENT, state=_VALID_STATE)
        _assert_fail_safe(decision, "OSError in solve")
        assert decision.status is SolverStatus.ERROR


# ── Composite: inject at each stage in sequence ───────────────────────────────


class TestAllStagesSequential:
    """Run one injected failure per pipeline stage in a single parametrised sweep.

    This provides a single-glance CI report showing all stages are covered.
    """

    @pytest.mark.parametrize(
        "patch_target,side_effect_cls,exc_args,expected_status",
        [
            (
                "pramanix.guard.validate_intent",
                ValidationError,
                ("intent stage",),
                SolverStatus.VALIDATION_FAILURE,
            ),
            (
                "pramanix.guard.validate_state",
                ValidationError,
                ("state stage",),
                SolverStatus.VALIDATION_FAILURE,
            ),
            (
                "pramanix.guard.solve",
                SolverTimeoutError,
                (),
                SolverStatus.TIMEOUT,
            ),
            (
                "pramanix.guard.solve",
                RuntimeError,
                ("solver crash",),
                SolverStatus.ERROR,
            ),
        ],
        ids=["validate_intent", "validate_state", "solver_timeout", "solver_crash"],
    )
    def test_stage_injection(
        self,
        patch_target: str,
        side_effect_cls: type,
        exc_args: tuple,
        expected_status: SolverStatus,
    ) -> None:
        """Each stage injection must produce Decision(allowed=False)."""
        guard = _make_guard()

        if side_effect_cls is SolverTimeoutError:
            exc = SolverTimeoutError(label="non_negative_balance", timeout_ms=5000)
        else:
            exc = side_effect_cls(*exc_args)

        with patch(patch_target, side_effect=exc):
            decision = guard.verify(intent=_VALID_INTENT, state=_VALID_STATE)

        _assert_fail_safe(decision, f"stage injection: {patch_target}")
        assert decision.status is expected_status


# ── Golden rule: allowed=True is NEVER returned from error handlers ──────────


class TestGoldenRuleAllowedNeverTrue:
    """Exhaustive parametric proof that no error handler ever returns allowed=True."""

    @pytest.mark.parametrize(
        "exception",
        [
            ValidationError("x"),
            StateValidationError("x"),
            SolverTimeoutError(label="lbl", timeout_ms=1000),
            TranspileError("x"),
            RuntimeError("x"),
            MemoryError("x"),
            OSError("x"),
            ValueError("x"),
            AttributeError("x"),
            ImportError("x"),
            _z3.Z3Exception("x"),
        ],
        ids=[
            "ValidationError",
            "StateValidationError",
            "SolverTimeoutError",
            "TranspileError",
            "RuntimeError",
            "MemoryError",
            "OSError",
            "ValueError",
            "AttributeError",
            "ImportError",
            "Z3Exception",
        ],
    )
    def test_no_error_type_returns_allowed_true(self, exception: Exception) -> None:
        """Guard.verify() must return Decision(allowed=False) for EVERY exception type."""
        guard = _make_guard()
        with patch("pramanix.guard.solve", side_effect=exception):
            decision = guard.verify(intent=_VALID_INTENT, state=_VALID_STATE)

        assert isinstance(decision, Decision), (
            f"Exception {type(exception).__name__} caused verify() to propagate instead of "
            "returning a Decision."
        )
        assert decision.allowed is False, (
            f"CRITICAL SECURITY VIOLATION: {type(exception).__name__} produced "
            f"Decision(allowed=True). Every error path must return allowed=False."
        )
