# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Adversarial tests — T3: Pydantic strict-mode boundary enforcement.

Security threat: T3 — Schema bypass via Pydantic coercion.

Pydantic v2 performs implicit type coercions in *lax* mode:
    * ``"100"`` → ``int(100)``   (string → numeric)
    * ``{"amount": 5}`` → ``Decimal("5")``   (int → Decimal)
    * Extra fields are silently ignored when ``model_config["extra"]`` is
      unset.

An attacker who knows the Pydantic schema can supply a payload like::

    {"amount": "DROP TABLE accounts"}

If this were allowed to reach the solver as a string, Z3 would raise
``z3.exceptions.Z3Exception`` — which the guard catches and converts to
``Decision.error(allowed=False)``.  BUT the attacker could also loop the
coercion path to find a value that passes Z3 numerics incorrectly, just
by exploiting the fact that a string "0" coerces to Decimal("0").

Mitigation under test:
    ``validate_intent()`` and ``validate_state()`` call
    ``model.model_validate(raw, strict=True)``, which disables all implicit
    coercions.  Extra fields cause a Pydantic ``ValidationError``.

    See ``src/pramanix/validator.py`` and ``docs/security.md §T3``.

Tests cover:
    • Strict numeric boundary: ``"100"`` (str) for Decimal field → rejected.
    • Strict bool boundary: ``1`` (int) for bool field → rejected.
    • Extra field injection → rejected.
    • Missing required field → rejected.
    • Correct types pass.
    • State model without ``state_version`` → StateValidationError.
    • State model with ``state_version`` wrong type → StateValidationError.
    • Correct state payload passes.
    • Nested model as value → rejected (not a valid Decimal/bool).
    • None for non-optional field → rejected.
    • Guard-level rejection: extra fields in intent dict passed to Guard
      (end-to-end test through Guard.verify()).
    • Guard-level rejection: string amount through Guard.verify().
"""
from __future__ import annotations

from decimal import Decimal
from typing import Any, ClassVar

import pytest
from pydantic import BaseModel, ConfigDict

from pramanix import E, Field, Policy
from pramanix.decision import Decision, SolverStatus
from pramanix.exceptions import StateValidationError, ValidationError
from pramanix.guard import Guard, GuardConfig
from pramanix.validator import validate_intent, validate_state

# ── Pydantic models for tests ─────────────────────────────────────────────────


class _TransferIntent(BaseModel):
    """Intent model: amount must be a well-typed Decimal."""

    model_config = ConfigDict(strict=True, extra="forbid")

    amount: Decimal


class _AccountState(BaseModel):
    """Full state model with required state_version."""

    model_config = ConfigDict(strict=True, extra="forbid")

    state_version: str
    balance: Decimal
    is_frozen: bool


class _StateMissingVersion(BaseModel):
    """State model that forgot to declare state_version — policy author bug."""

    model_config = ConfigDict(strict=True)

    balance: Decimal


class _StateVersionWrongType(BaseModel):
    """State model where state_version is int — policy author bug."""

    model_config = ConfigDict(strict=True)

    state_version: int  # wrong! should be str
    balance: Decimal


# ── validate_intent strict tests ──────────────────────────────────────────────


class TestIntentStrictMode:
    """validate_intent() must reject all coercion attempts."""

    def test_correct_decimal_passes(self) -> None:
        result = validate_intent(_TransferIntent, {"amount": Decimal("100")})
        assert result.amount == Decimal("100")

    def test_string_decimal_rejected(self) -> None:
        """T3 core: ``"100"`` (string) must not coerce to Decimal."""
        with pytest.raises(ValidationError):
            validate_intent(_TransferIntent, {"amount": "100"})

    def test_int_decimal_rejected(self) -> None:
        """``100`` (int) must not silently coerce to Decimal("100") in strict mode."""
        with pytest.raises(ValidationError):
            validate_intent(_TransferIntent, {"amount": 100})

    def test_float_decimal_rejected(self) -> None:
        """Float precision trap: ``3.14`` (float) must not coerce to Decimal."""
        with pytest.raises(ValidationError):
            validate_intent(_TransferIntent, {"amount": 3.14})

    def test_extra_field_rejected(self) -> None:
        """T3: additional field not in schema → rejected (extra='forbid')."""
        with pytest.raises(ValidationError):
            validate_intent(
                _TransferIntent,
                {"amount": Decimal("100"), "injected": "DROP TABLE"},
            )

    def test_missing_required_field_rejected(self) -> None:
        """Missing ``amount`` field → ValidationError."""
        with pytest.raises(ValidationError):
            validate_intent(_TransferIntent, {})

    def test_none_for_required_field_rejected(self) -> None:
        """``None`` for non-optional Decimal → ValidationError."""
        with pytest.raises(ValidationError):
            validate_intent(_TransferIntent, {"amount": None})

    def test_dict_as_field_value_rejected(self) -> None:
        """Nested dict where Decimal expected → ValidationError."""
        with pytest.raises(ValidationError):
            validate_intent(_TransferIntent, {"amount": {"value": 100}})

    def test_list_as_field_value_rejected(self) -> None:
        """List where Decimal expected → ValidationError."""
        with pytest.raises(ValidationError):
            validate_intent(_TransferIntent, {"amount": [100, 200]})


# ── validate_state strict tests ───────────────────────────────────────────────


class TestStateStrictMode:
    """validate_state() must reject coercions and enforce state_version."""

    _VALID_STATE: ClassVar[dict[str, object]] = {
        "state_version": "1.0",
        "balance": Decimal("500"),
        "is_frozen": False,
    }

    def test_correct_state_passes(self) -> None:
        result = validate_state(_AccountState, self._VALID_STATE)
        assert result.state_version == "1.0"
        assert result.balance == Decimal("500")
        assert result.is_frozen is False

    def test_string_balance_rejected(self) -> None:
        with pytest.raises(ValidationError):
            validate_state(
                _AccountState,
                {**self._VALID_STATE, "balance": "500"},
            )

    def test_int_bool_rejected(self) -> None:
        """``1`` (int) must not coerce to ``True`` in strict mode for bool field."""
        with pytest.raises(ValidationError):
            validate_state(
                _AccountState,
                {**self._VALID_STATE, "is_frozen": 1},
            )

    def test_extra_field_rejected(self) -> None:
        with pytest.raises(ValidationError):
            validate_state(
                _AccountState,
                {**self._VALID_STATE, "evil_field": "INJECTED"},
            )

    def test_missing_state_version_in_data_rejected(self) -> None:
        """state_version exists in model but missing from data → ValidationError."""
        with pytest.raises(ValidationError):
            validate_state(
                _AccountState,
                {"balance": Decimal("500"), "is_frozen": False},
            )

    def test_model_missing_state_version_field_raises(self) -> None:
        """Policy bug: model without state_version → StateValidationError."""
        with pytest.raises(StateValidationError, match="missing the required"):
            validate_state(_StateMissingVersion, {"balance": Decimal("500")})

    def test_model_state_version_wrong_type_raises(self) -> None:
        """Policy bug: state_version declared as int → StateValidationError."""
        with pytest.raises(StateValidationError, match="must be annotated as"):
            validate_state(_StateVersionWrongType, {"state_version": 1, "balance": Decimal("5")})


# ── Guard end-to-end strict enforcement tests ─────────────────────────────────


class _BoundaryPolicy(Policy):
    """Minimal banking policy for boundary tests."""

    class Meta:
        version = "1.0"
        intent_model = _TransferIntent
        state_model = _AccountState

    balance = Field("balance", Decimal, "Real")
    amount = Field("amount", Decimal, "Real")

    @classmethod
    def invariants(cls):  # type: ignore[override]
        return [(E(cls.balance) - E(cls.amount) >= Decimal("0")).named("non_negative")]


_GUARD = Guard(_BoundaryPolicy, GuardConfig(execution_mode="sync"))


class TestGuardEndToEndBoundary:
    """
    Guard.verify() must reject coerced inputs before reaching Z3.
    These tests verify the full pipeline — intent will never arrive at the
    solver if it fails Pydantic strict validation.
    """

    def test_valid_intent_and_state_passes(self) -> None:
        decision = _GUARD.verify(
            intent={"amount": Decimal("100")},
            state={"state_version": "1.0", "balance": Decimal("500"), "is_frozen": False},
        )
        assert isinstance(decision, Decision)
        assert decision.allowed is True

    def test_string_amount_rejected_before_solver(self) -> None:
        """T3 end-to-end: string amount never reaches Z3."""
        decision = _GUARD.verify(
            intent={"amount": "100"},  # type: ignore[arg-type]
            state={"state_version": "1.0", "balance": Decimal("500"), "is_frozen": False},
        )
        assert isinstance(decision, Decision)
        assert decision.allowed is False
        assert decision.status in (
            SolverStatus.VALIDATION_FAILURE,
            SolverStatus.ERROR,
        )

    def test_extra_intent_field_rejected_before_solver(self) -> None:
        """T3 end-to-end: extra field in intent dict is blocked."""
        decision = _GUARD.verify(
            intent={"amount": Decimal("100"), "sql_injection": "'; DROP TABLE --"},
            state={"state_version": "1.0", "balance": Decimal("500"), "is_frozen": False},
        )
        assert isinstance(decision, Decision)
        assert decision.allowed is False

    def test_extra_state_field_rejected_before_solver(self) -> None:
        """T3 end-to-end: extra field in state dict is blocked."""
        decision = _GUARD.verify(
            intent={"amount": Decimal("100")},
            state={
                "state_version": "1.0",
                "balance": Decimal("500"),
                "is_frozen": False,
                "override_allow": True,  # attacker injection
            },
        )
        assert isinstance(decision, Decision)
        assert decision.allowed is False

    def test_int_amount_rejected_before_solver(self) -> None:
        """Plain int (not Decimal) for amount → rejected in strict mode."""
        decision = _GUARD.verify(
            intent={"amount": 100},  # type: ignore[arg-type]
            state={"state_version": "1.0", "balance": Decimal("500"), "is_frozen": False},
        )
        assert isinstance(decision, Decision)
        assert decision.allowed is False

    @pytest.mark.parametrize(
        "bad_amount",
        [
            "100",  # string
            100,  # int
            100.0,  # float
            None,  # null
            [],  # list
            {},  # dict
            False,  # bool (common coercion trap)
        ],
    )
    def test_all_non_decimal_amounts_rejected(self, bad_amount: Any) -> None:
        """Parametric sweep: every non-Decimal type for amount is rejected."""
        decision = _GUARD.verify(
            intent={"amount": bad_amount},  # type: ignore[arg-type]
            state={"state_version": "1.0", "balance": Decimal("500"), "is_frozen": False},
        )
        assert isinstance(decision, Decision)
        assert decision.allowed is False, (
            f"Guard returned allowed=True for amount type {type(bad_amount).__name__!r} "
            f"with value {bad_amount!r} — strict mode coercion bypass!"
        )
