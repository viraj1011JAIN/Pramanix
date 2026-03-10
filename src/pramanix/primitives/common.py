# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""General-purpose common constraint primitives.

Example::

    from pramanix.primitives.common import NotSuspended, StatusMustBe

    class TransferPolicy(Policy):
        is_suspended = Field("is_suspended", bool, "Bool")
        status       = Field("status",       int,  "Int")  # 1=active, 2=frozen, 3=closed

        @classmethod
        def invariants(cls):
            return [
                NotSuspended(cls.is_suspended),
                StatusMustBe(cls.status, 1),  # must be active
            ]
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from pramanix.expressions import E

if TYPE_CHECKING:
    from pramanix.expressions import ConstraintExpr, Field

__all__ = [
    "NotSuspended",
    "StatusMustBe",
    "FieldMustEqual",
]


def NotSuspended(is_suspended: Field) -> ConstraintExpr:
    """Enforce that the entity is not suspended.

    DSL: ``(E(is_suspended) == False)``

    Args:
        is_suspended: Bool-sorted field; ``True`` means the entity is suspended.
    """
    return (
        (E(is_suspended) == False)  # noqa: E712
        .named("not_suspended")
        .explain(
            "Action blocked: the entity is suspended (is_suspended={is_suspended})."
        )
    )


def StatusMustBe(status: Field, expected_value: Any) -> ConstraintExpr:
    """Enforce that a status field equals a specific expected value.

    DSL: ``(E(status) == expected_value)``

    The invariant label encodes the expected value so violations identify
    *which* status was required.

    Args:
        status:         Field representing the entity's status code.
        expected_value: The required status value (must be compatible with
                        the field's Z3 sort).
    """
    label = f"status_must_be_{expected_value}"
    return cast(
        "ConstraintExpr",
        (
            (E(status) == expected_value)
            .named(label)
            .explain(
                f"Status mismatch: status ({{status}}) != expected {expected_value}."
            )
        ),
    )


def FieldMustEqual(field_obj: Field, value: Any) -> ConstraintExpr:
    """Enforce that a generic field equals a specific value.

    DSL: ``(E(field_obj) == value)``

    A more general form of :func:`StatusMustBe`.  The invariant label encodes
    both the field name and the required value.

    Args:
        field_obj: Any :class:`~pramanix.expressions.Field`.
        value:     The required value (must be compatible with the field's sort).
    """
    label = f"field_{field_obj.name}_must_equal_{value}"
    return cast(
        "ConstraintExpr",
        (
            (E(field_obj) == value)
            .named(label)
            .explain(
                f"{{{field_obj.name}}} must equal {value}; got {{{field_obj.name}}}."
            )
        ),
    )
