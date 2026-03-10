# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Pydantic v2 validation layer for intent and state data.

This module is the *only* place where raw caller-supplied dicts are converted
to typed Pydantic model instances.  All validation runs in **strict mode** so
that implicit type coercions (e.g. ``"123"`` → ``int``) are rejected — the
caller is responsible for sending well-typed data.

Public API
----------
* :func:`validate_intent` — validate raw dict against an intent model
* :func:`validate_state`  — validate raw dict against a state model; also
  asserts that ``state_version: str`` is declared in the model schema

Design notes
------------
* Pydantic ``ValidationError`` is **never** propagated to callers.  It is
  caught and re-raised as :exc:`~pramanix.exceptions.ValidationError` so that
  callers never need to depend on ``pydantic`` just to catch errors.
* :exc:`~pramanix.exceptions.StateValidationError` is raised (not
  :exc:`~pramanix.exceptions.ValidationError`) when the *model itself* lacks
  the required ``state_version`` field — this is a policy definition error,
  not a data error.
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel
from pydantic import ValidationError as _PydanticValidationError

from pramanix.exceptions import StateValidationError, ValidationError

__all__ = ["validate_intent", "validate_state"]

# The field name that every state model must declare.
_STATE_VERSION_FIELD: str = "state_version"


# ── Intent validation ──────────────────────────────────────────────────────────


def validate_intent(
    intent_model: type[BaseModel],
    raw_data: dict[str, Any],
) -> BaseModel:
    """Validate *raw_data* against *intent_model* in Pydantic strict mode.

    Args:
        intent_model: A :class:`pydantic.BaseModel` subclass describing the
            expected structure of the intent payload.
        raw_data:     The raw input dict from the caller.

    Returns:
        A fully-validated *intent_model* instance.

    Raises:
        ValidationError: If *raw_data* does not conform to *intent_model*.
            Wraps the original :class:`pydantic.ValidationError` as
            ``__cause__``.
    """
    try:
        return intent_model.model_validate(raw_data, strict=True)
    except _PydanticValidationError as exc:
        raise ValidationError(
            f"Intent validation failed for {intent_model.__name__}: {exc}"
        ) from exc


# ── State validation ───────────────────────────────────────────────────────────


def validate_state(
    state_model: type[BaseModel],
    raw_data: dict[str, Any],
) -> BaseModel:
    """Validate *raw_data* against *state_model* in Pydantic strict mode.

    In addition to standard field validation, this function asserts that
    *state_model* declares a ``state_version: str`` field.  This is a
    **compile-time check** on the model definition, not the data.

    Args:
        state_model: A :class:`pydantic.BaseModel` subclass describing the
            expected structure of the state payload.  Must declare
            ``state_version: str``.
        raw_data:    The raw input dict from the caller.

    Returns:
        A fully-validated *state_model* instance.

    Raises:
        StateValidationError: If *state_model* does not declare
            ``state_version``.
        ValidationError:      If *raw_data* does not conform to *state_model*
            (including a missing ``state_version`` value in the data).
            Wraps the original :class:`pydantic.ValidationError` as
            ``__cause__``.
    """
    # ── Check that the model declares state_version ────────────────────────────
    if _STATE_VERSION_FIELD not in state_model.model_fields:
        raise StateValidationError(
            f"{state_model.__name__} is missing the required "
            f"'{_STATE_VERSION_FIELD}: str' field. "
            "Every state model must declare this field for version pinning.",
        )
    field_annotation = state_model.model_fields[_STATE_VERSION_FIELD].annotation
    if field_annotation is not str:
        raise StateValidationError(
            f"{state_model.__name__}.{_STATE_VERSION_FIELD} must be annotated as "
            f"'str', got '{field_annotation}'. "
            "Every state model must declare this field as 'str' for version pinning.",
        )

    # ── Run Pydantic validation in strict mode ─────────────────────────────────
    try:
        return state_model.model_validate(raw_data, strict=True)
    except _PydanticValidationError as exc:
        raise ValidationError(
            f"State validation failed for {state_model.__name__}: {exc}"
        ) from exc
