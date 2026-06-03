# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Adversarial tests — fail-safe invariant.

Every exception path in Guard.verify() must produce Decision(allowed=False).

Security requirement (CTO Phase 7 brief):
    The most important test you will ever write.  Every exception path in
    ``Guard.verify()`` must produce ``Decision(allowed=False)``.  If even
    one path returns ``True`` or propagates a raw exception to the caller,
    the SDK fails its core security contract.

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

import pytest
import z3 as _z3
from pydantic import BaseModel
from pydantic import Field as PydanticField

import pramanix.guard as _guard_mod
from pramanix import E, Field, Guard, GuardConfig, Policy
from pramanix.decision import Decision, SolverStatus
from pramanix.exceptions import (
    SolverTimeoutError,
    StateValidationError,
    TranspileError,
    ValidationError,
)
from tests.helpers.solver_stubs import RaisingSolverStub, TimeoutSolverStub

if TYPE_CHECKING:
    from pramanix.expressions import ConstraintExpr

# ── Shared infrastructure ─────────────────────────────────────────────────


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
        return [
            (E(cls.balance) - E(cls.amount) >= Decimal("0")).named(
                "non_negative_balance"
            )
        ]


_VALID_INTENT = {"amount": Decimal("100.00")}
_VALID_STATE = {"balance": Decimal("1000.00"), "state_version": "1.0"}


def _make_guard() -> Guard:
    return Guard(_StablePolicy, GuardConfig(execution_mode="sync"))


def _assert_fail_safe(decision: object, context: str) -> None:
    """Common assertion: result must be a Decision with allowed=False."""
    assert isinstance(decision, Decision), (
        f"{context}: expected Decision, got {type(decision).__name__}"
    )
    assert decision.allowed is False, (
        f"{context}: expected allowed=False, got allowed=True. "
        "CRITICAL: Guard.verify() returned True on an error path "
        "— SECURITY VIOLATION."
    )


# ── Stage 1: Intent Validation Failures ──────────────────────────────────


class TestStage1IntentValidation:
    """Inject failures at the Pydantic intent-validation stage."""

    def test_intent_validation_error_returns_false(self) -> None:
        """Pydantic ValidationError → Decision(VALIDATION_FAILURE)."""
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
            intent={"amount": "not-a-number"},  # str, not Decimal
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

    def test_validate_intent_raises_pramanix_validation_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """pramanix.ValidationError in validate_intent — caught and wrapped."""
        guard = _make_guard()

        def _raise(*a, **kw):
            raise ValidationError("intent validation failure")

        monkeypatch.setattr(_guard_mod, "validate_intent", _raise)
        decision = guard.verify(intent=_VALID_INTENT, state=_VALID_STATE)
        _assert_fail_safe(
            decision, "patched ValidationError in validate_intent"
        )
        assert decision.status is SolverStatus.VALIDATION_FAILURE

    def test_validate_intent_raises_state_validation_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """StateValidationError from validate_intent → VALIDATION_FAILURE."""
        guard = _make_guard()

        def _raise(*a, **kw):
            raise StateValidationError("patched state error")

        monkeypatch.setattr(_guard_mod, "validate_intent", _raise)
        decision = guard.verify(intent=_VALID_INTENT, state=_VALID_STATE)
        _assert_fail_safe(
            decision, "patched StateValidationError in validate_intent"
        )
        assert decision.status is SolverStatus.VALIDATION_FAILURE


# ── Stage 2: State Validation Failures ───────────────────────────────────


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
        """Missing state_version in state model → blocked."""
        guard = _make_guard()
        decision = guard.verify(
            intent=_VALID_INTENT,
            state={"balance": Decimal("1000.00")},  # no state_version
        )
        _assert_fail_safe(decision, "state missing state_version")
        # Could be VALIDATION_FAILURE (Pydantic) or caught by step-4 guard,
        # but MUST be False.

    def test_validate_state_raises_pramanix_validation_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Force ValidationError in validate_state — caught by handler."""
        guard = _make_guard()

        def _raise(*a, **kw):
            raise ValidationError("mock state validation failure")

        monkeypatch.setattr(_guard_mod, "validate_state", _raise)
        decision = guard.verify(intent=_VALID_INTENT, state=_VALID_STATE)
        _assert_fail_safe(
            decision, "patched ValidationError in validate_state"
        )
        assert decision.status is SolverStatus.VALIDATION_FAILURE


# ── Stage 3: Serialization failure (safe_dump / model_dump) ──────────────


class TestStage3SerializationFailure:
    """Inject failures at the model_dump() / safe_dump() stage.

    This stage runs *after* Pydantic validation succeeds but *before* values
    reach the Z3 solver.  A RuntimeError here must still produce
    Decision(allowed=False) — never a raw exception to the caller.
    """

    def test_safe_dump_raises_on_intent_returns_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """RuntimeError in flatten_model() on intent → ERROR (fail-safe)."""
        guard = _make_guard()

        def _raise(*a, **kw):
            raise RuntimeError("model_dump() failed — circular reference")

        monkeypatch.setattr(_guard_mod, "flatten_model", _raise)
        intent_model = _TestIntent(amount=Decimal("100.00"))
        state_model = _TestState(
            balance=Decimal("1000.00"), state_version="1.0"
        )
        decision = guard.verify(intent=intent_model, state=state_model)
        _assert_fail_safe(decision, "flatten_model RuntimeError on intent")
        assert decision.status is SolverStatus.ERROR

    def test_safe_dump_raises_on_state_returns_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """RuntimeError in flatten_model() on state → ERROR (fail-safe).

        Patches flatten_model to succeed on the first call (intent) and
        raise on the second call (state), isolating that path.
        """
        guard = _make_guard()
        _call_count = {"n": 0}

        def _side_effect(obj):
            _call_count["n"] += 1
            if _call_count["n"] == 2:
                raise RuntimeError(
                    "model_dump() failed on state — unexpected attribute"
                )
            from pramanix.helpers.serialization import flatten_model as _real

            return _real(obj)

        monkeypatch.setattr(_guard_mod, "flatten_model", _side_effect)
        intent_model = _TestIntent(amount=Decimal("100.00"))
        state_model = _TestState(
            balance=Decimal("1000.00"), state_version="1.0"
        )
        decision = guard.verify(intent=intent_model, state=state_model)
        _assert_fail_safe(decision, "flatten_model RuntimeError on state")
        assert decision.status is SolverStatus.ERROR


# ── Stage 4: Version check / conflicting keys ─────────────────────────────


class TestStage4VersionAndKeyConflict:
    """Inject failures at the version check and key-collision stages."""

    def test_version_mismatch_returns_stale_state(self) -> None:
        """state_version != Policy.Meta.version → STALE_STATE."""
        guard = _make_guard()
        decision = guard.verify(
            intent=_VALID_INTENT,
            state={
                "balance": Decimal("1000.00"),
                "state_version": "99.0",
            },
        )
        _assert_fail_safe(decision, "state_version mismatch")
        assert decision.status is SolverStatus.STALE_STATE

    def test_conflicting_intent_state_keys_returns_error(self) -> None:
        """Intent and state share a key → ValueError → Decision.error."""

        class _RawPolicy(Policy):
            class Meta:
                version = None  # disable version check

            balance = Field("balance", Decimal, "Real")
            amount = Field("amount", Decimal, "Real")

            @classmethod
            def invariants(cls) -> list[ConstraintExpr]:
                return [
                    (E(cls.balance) >= Decimal("0")).named("non_negative")
                ]

        guard = Guard(_RawPolicy)
        # 'balance' appears in BOTH intent and state — conflict!
        decision = guard.verify(
            intent={"amount": Decimal("100"), "balance": Decimal("50")},
            state={"balance": Decimal("1000")},
        )
        _assert_fail_safe(decision, "conflicting keys ValueError")
        assert decision.status is SolverStatus.ERROR


# ── Stage 5: Solver Failures ──────────────────────────────────────────────


class TestStage5SolverFailures:
    """Inject failures at the Z3 solver stage via solver_factory."""

    def test_solver_timeout_error_returns_timeout_decision(self) -> None:
        """z3.unknown → SolverTimeoutError → timeout decision."""
        guard = Guard(
            _StablePolicy,
            GuardConfig(
                execution_mode="sync",
                solver_factory=lambda ctx: TimeoutSolverStub(),
            ),
        )
        decision = guard.verify(intent=_VALID_INTENT, state=_VALID_STATE)
        _assert_fail_safe(decision, "TimeoutSolverStub")
        assert decision.status is SolverStatus.TIMEOUT

    def test_z3_exception_in_solver_returns_error(self) -> None:
        """z3.Z3Exception from check() → Decision.error."""
        guard = Guard(
            _StablePolicy,
            GuardConfig(
                execution_mode="sync",
                solver_factory=lambda ctx: RaisingSolverStub(
                    _z3.Z3Exception("synthetic Z3 context error")
                ),
            ),
        )
        decision = guard.verify(intent=_VALID_INTENT, state=_VALID_STATE)
        _assert_fail_safe(decision, "RaisingSolverStub(Z3Exception)")
        assert decision.status is SolverStatus.ERROR

    def test_memory_error_in_solver_returns_error(self) -> None:
        """MemoryError from check() → Decision.error."""
        guard = Guard(
            _StablePolicy,
            GuardConfig(
                execution_mode="sync",
                solver_factory=lambda ctx: RaisingSolverStub(
                    MemoryError("Z3 out of memory — formula too large")
                ),
            ),
        )
        decision = guard.verify(intent=_VALID_INTENT, state=_VALID_STATE)
        _assert_fail_safe(decision, "RaisingSolverStub(MemoryError)")
        assert decision.status is SolverStatus.ERROR

    def test_transpile_error_from_solver_returns_error(self) -> None:
        """TranspileError from check() → Decision.error."""
        guard = Guard(
            _StablePolicy,
            GuardConfig(
                execution_mode="sync",
                solver_factory=lambda ctx: RaisingSolverStub(
                    TranspileError("deliberate transpile crash")
                ),
            ),
        )
        decision = guard.verify(intent=_VALID_INTENT, state=_VALID_STATE)
        _assert_fail_safe(decision, "RaisingSolverStub(TranspileError)")
        assert decision.status is SolverStatus.ERROR

    def test_invariants_raises_runtime_error_returns_error(self) -> None:
        """RuntimeError from check() → catch-all → Decision.error."""
        guard = Guard(
            _StablePolicy,
            GuardConfig(
                execution_mode="sync",
                solver_factory=lambda ctx: RaisingSolverStub(
                    RuntimeError("deliberate crash in solver")
                ),
            ),
        )
        decision = guard.verify(intent=_VALID_INTENT, state=_VALID_STATE)
        _assert_fail_safe(decision, "RaisingSolverStub(RuntimeError)")
        assert decision.status is SolverStatus.ERROR

    def test_keyboard_interrupt_is_not_suppressed(self) -> None:
        """KeyboardInterrupt propagates — Guard uses except Exception.

        Guard's ``except Exception`` does not catch ``KeyboardInterrupt``
        (a BaseException subclass), confirming no bare-except is used.
        """
        guard = Guard(
            _StablePolicy,
            GuardConfig(
                execution_mode="sync",
                solver_factory=lambda ctx: RaisingSolverStub(
                    KeyboardInterrupt()
                ),
            ),
        )
        with pytest.raises(KeyboardInterrupt):
            guard.verify(intent=_VALID_INTENT, state=_VALID_STATE)


# ── Catch-all: Generic Exception ──────────────────────────────────────────


class TestCatchAllExceptionPath:
    """Verify the broad ``except Exception`` catch at bottom of verify()."""

    def test_arbitrary_exception_returns_error_decision(self) -> None:
        """Any unexpected Exception subclass → Decision.error."""

        class _WeirdError(Exception):
            pass

        guard = Guard(
            _StablePolicy,
            GuardConfig(
                execution_mode="sync",
                solver_factory=lambda ctx: RaisingSolverStub(
                    _WeirdError("Unexpected!")
                ),
            ),
        )
        decision = guard.verify(intent=_VALID_INTENT, state=_VALID_STATE)
        _assert_fail_safe(decision, "arbitrary Exception subclass")
        assert decision.status is SolverStatus.ERROR

    def test_os_error_in_solve_returns_error_decision(self) -> None:
        """OSError (unexpected I/O during Z3) → Decision.error."""
        guard = Guard(
            _StablePolicy,
            GuardConfig(
                execution_mode="sync",
                solver_factory=lambda ctx: RaisingSolverStub(
                    OSError("File descriptor issue during Z3 init")
                ),
            ),
        )
        decision = guard.verify(intent=_VALID_INTENT, state=_VALID_STATE)
        _assert_fail_safe(decision, "OSError in solve")
        assert decision.status is SolverStatus.ERROR


# ── Composite: inject at each pre-Z3 stage in sequence ───────────────────


class TestAllStagesSequential:
    """One injected failure per pre-Z3 stage in a parametrised sweep.

    Provides a single-glance CI view of pre-Z3 stage coverage.
    Z3 solver stages are covered exhaustively by TestStage5SolverFailures.
    """

    @pytest.mark.parametrize(
        "attr_name,exc,expected_status",
        [
            (
                "validate_intent",
                ValidationError("intent stage"),
                SolverStatus.VALIDATION_FAILURE,
            ),
            (
                "validate_state",
                ValidationError("state stage"),
                SolverStatus.VALIDATION_FAILURE,
            ),
        ],
        ids=["validate_intent", "validate_state"],
    )
    def test_stage_injection(
        self,
        monkeypatch: pytest.MonkeyPatch,
        attr_name: str,
        exc: Exception,
        expected_status: SolverStatus,
    ) -> None:
        """Each pre-Z3 stage injection must produce Decision(allowed=False)."""
        guard = _make_guard()

        def _raise(*a, **kw):
            raise exc

        monkeypatch.setattr(_guard_mod, attr_name, _raise)
        decision = guard.verify(intent=_VALID_INTENT, state=_VALID_STATE)
        _assert_fail_safe(decision, f"stage injection: {attr_name}")
        assert decision.status is expected_status


# ── Golden rule: allowed=True is NEVER returned from error handlers ───────


class TestGoldenRuleAllowedNeverTrue:
    """Exhaustive proof that no error handler ever returns allowed=True."""

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
    def test_no_error_type_returns_allowed_true(
        self, exception: Exception
    ) -> None:
        """Decision(allowed=False) for EVERY exception type from solver."""
        guard = Guard(
            _StablePolicy,
            GuardConfig(
                execution_mode="sync",
                solver_factory=lambda ctx: RaisingSolverStub(exception),
            ),
        )
        decision = guard.verify(intent=_VALID_INTENT, state=_VALID_STATE)
        assert isinstance(decision, Decision), (
            f"Exception {type(exception).__name__} caused verify() to "
            "propagate instead of returning a Decision."
        )
        assert decision.allowed is False, (
            f"CRITICAL SECURITY VIOLATION: {type(exception).__name__} "
            "produced Decision(allowed=True). Every error path must "
            "return allowed=False."
        )
