# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Unit tests for pramanix.validator — validate_intent() and validate_state().

Coverage targets:
- validate_intent: valid dict → model instance, invalid type → ValidationError,
  missing fields → ValidationError, pydantic exc wrapped (not propagated)
- validate_state: valid dict → model instance, missing state_version field
  in model schema → StateValidationError (compile-time check), wrong annotation
  type → StateValidationError, bad data → ValidationError, strict-mode
  rejection of implicit coercions (string → int)
- Both functions use strict=True: no implicit coercions accepted
"""
from __future__ import annotations

from decimal import Decimal

import pytest
from pydantic import BaseModel

from pramanix.exceptions import StateValidationError, ValidationError
from pramanix.validator import validate_intent, validate_state

# ── Models used throughout ────────────────────────────────────────────────────


class _SimpleIntent(BaseModel):
    amount: Decimal
    currency: str


class _FullState(BaseModel):
    state_version: str
    balance: Decimal
    is_frozen: bool


class _StateWithoutVersionField(BaseModel):
    """Missing the required state_version field."""

    balance: Decimal
    is_frozen: bool


class _StateWithWrongVersionType(BaseModel):
    """state_version declared as int, not str."""

    state_version: int  # wrong: must be str
    balance: Decimal


# ── Valid inputs ──────────────────────────────────────────────────────────────

_VALID_INTENT_DATA: dict[str, object] = {
    "amount": Decimal("500.00"),
    "currency": "USD",
}

_VALID_STATE_DATA: dict[str, object] = {
    "state_version": "1.0",
    "balance": Decimal("1000.00"),
    "is_frozen": False,
}


# ═══════════════════════════════════════════════════════════════════════════════
# validate_intent()
# ═══════════════════════════════════════════════════════════════════════════════


class TestValidateIntent:
    def test_valid_data_returns_model_instance(self) -> None:
        result = validate_intent(_SimpleIntent, _VALID_INTENT_DATA)
        assert isinstance(result, _SimpleIntent)

    def test_model_fields_populated_correctly(self) -> None:
        result = validate_intent(_SimpleIntent, _VALID_INTENT_DATA)
        assert isinstance(result, _SimpleIntent)
        assert result.amount == Decimal("500.00")
        assert result.currency == "USD"

    def test_string_for_decimal_raises_validation_error(self) -> None:
        """Strict mode: string '500' cannot coerce to Decimal."""
        with pytest.raises(ValidationError):
            validate_intent(_SimpleIntent, {"amount": "500", "currency": "USD"})

    def test_int_for_decimal_raises_validation_error(self) -> None:
        """Strict mode: int 500 cannot coerce to Decimal."""
        with pytest.raises(ValidationError):
            validate_intent(_SimpleIntent, {"amount": 500, "currency": "USD"})

    def test_missing_required_field_raises_validation_error(self) -> None:
        with pytest.raises(ValidationError):
            validate_intent(_SimpleIntent, {"amount": Decimal("100")})

    def test_extra_fields_ignored_by_pydantic(self) -> None:
        """Pydantic's default is to ignore extra fields; must not raise."""
        data = {**_VALID_INTENT_DATA, "extra_field": "ignored"}
        result = validate_intent(_SimpleIntent, data)
        assert isinstance(result, _SimpleIntent)

    def test_empty_dict_raises_validation_error(self) -> None:
        with pytest.raises(ValidationError):
            validate_intent(_SimpleIntent, {})

    def test_pydantic_validation_error_not_propagated(self) -> None:
        """pydantic.ValidationError must be wrapped, never escape as raw pydantic exc."""
        import pydantic

        with pytest.raises(ValidationError):
            try:
                validate_intent(_SimpleIntent, {"amount": "bad", "currency": "USD"})
            except pydantic.ValidationError:
                pytest.fail("Raw pydantic.ValidationError escaped validate_intent()")

    def test_validation_error_is_pramanix_error(self) -> None:
        from pramanix.exceptions import PramanixError

        with pytest.raises(PramanixError):
            validate_intent(_SimpleIntent, {"amount": "bad", "currency": "USD"})

    def test_validation_error_wraps_cause(self) -> None:
        """The __cause__ attribute should reference the original pydantic error."""
        import pydantic

        try:
            validate_intent(_SimpleIntent, {"amount": "bad", "currency": "USD"})
        except ValidationError as err:
            assert isinstance(err.__cause__, pydantic.ValidationError)
        else:
            pytest.fail("ValidationError not raised")


# ═══════════════════════════════════════════════════════════════════════════════
# validate_state()
# ═══════════════════════════════════════════════════════════════════════════════


class TestValidateState:
    def test_valid_data_returns_model_instance(self) -> None:
        result = validate_state(_FullState, _VALID_STATE_DATA)
        assert isinstance(result, _FullState)

    def test_model_fields_populated_correctly(self) -> None:
        result = validate_state(_FullState, _VALID_STATE_DATA)
        assert isinstance(result, _FullState)
        assert result.state_version == "1.0"
        assert result.balance == Decimal("1000.00")
        assert result.is_frozen is False

    def test_model_without_state_version_field_raises_state_validation_error(self) -> None:
        """Compile-time check: the model schema must declare state_version: str."""
        with pytest.raises(StateValidationError):
            validate_state(_StateWithoutVersionField, {"balance": Decimal("100"), "is_frozen": False})

    def test_model_with_wrong_version_type_raises_state_validation_error(self) -> None:
        """state_version must be annotated as str, not int or anything else."""
        with pytest.raises(StateValidationError):
            validate_state(
                _StateWithWrongVersionType,
                {"state_version": 1, "balance": Decimal("100")},
            )

    def test_missing_state_version_value_in_data_raises_validation_error(self) -> None:
        """Model has the field, but data doesn't supply it → Pydantic rejection."""
        data = {"balance": Decimal("1000"), "is_frozen": False}
        with pytest.raises(ValidationError):
            validate_state(_FullState, data)

    def test_wrong_type_for_balance_raises_validation_error(self) -> None:
        data = {**_VALID_STATE_DATA, "balance": "not-a-decimal"}
        with pytest.raises(ValidationError):
            validate_state(_FullState, data)

    def test_strict_mode_rejects_string_for_bool(self) -> None:
        data = {**_VALID_STATE_DATA, "is_frozen": "false"}
        with pytest.raises(ValidationError):
            validate_state(_FullState, data)

    def test_strict_mode_rejects_int_for_bool(self) -> None:
        """Strict mode does NOT coerce 0/1 to bool."""
        data = {**_VALID_STATE_DATA, "is_frozen": 0}
        with pytest.raises(ValidationError):
            validate_state(_FullState, data)

    def test_empty_dict_raises_validation_error(self) -> None:
        with pytest.raises(ValidationError):
            validate_state(_FullState, {})

    def test_pydantic_error_wrapped_not_propagated(self) -> None:
        import pydantic

        with pytest.raises(ValidationError):
            try:
                validate_state(_FullState, {"state_version": "1.0", "balance": "bad", "is_frozen": False})
            except pydantic.ValidationError:
                pytest.fail("Raw pydantic.ValidationError escaped validate_state()")

    def test_state_validation_error_message_mentions_field_name(self) -> None:
        try:
            validate_state(_StateWithoutVersionField, {"balance": Decimal("100"), "is_frozen": False})
        except StateValidationError as err:
            assert "state_version" in str(err)
        else:
            pytest.fail("StateValidationError not raised")

    def test_extra_fields_in_data_are_ignored(self) -> None:
        data = {**_VALID_STATE_DATA, "extra_key": "ignored"}
        result = validate_state(_FullState, data)
        assert isinstance(result, _FullState)
