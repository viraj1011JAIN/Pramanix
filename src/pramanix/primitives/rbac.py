# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""RBAC (Role-Based Access Control) constraint primitives.

Example::

    from pramanix.primitives.rbac import RoleMustBeIn, ConsentRequired

    class PHIPolicy(Policy):
        role    = Field("role",    str,  "Int")   # encoded as int
        consent = Field("consent", bool, "Bool")

        @classmethod
        def invariants(cls):
            return [
                RoleMustBeIn(cls.role, [1, 2, 3]),   # doctor=1, nurse=2, admin=3
                ConsentRequired(cls.consent),
            ]
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from pramanix.expressions import E

if TYPE_CHECKING:
    from pramanix.expressions import ConstraintExpr, Field

__all__ = [
    "ConsentRequired",
    "DepartmentMustBeIn",
    "RoleMustBeIn",
]


def RoleMustBeIn(role: Field, allowed_roles: list[Any]) -> ConstraintExpr:
    """Enforce that the requester's role is in the set of allowed roles.

    DSL: ``E(role).is_in(allowed_roles)``

    Because Z3 works with concrete sorts, roles must be encoded as integers
    (or another declared type) — not raw strings.

    Args:
        role:          Field representing the requester's role (e.g., Int-sorted).
        allowed_roles: List of allowed role values (must match the field's sort).
    """
    return (
        E(role)
        .is_in(allowed_roles)
        .named("role_must_be_in_allowed_set")
        .explain("Access denied: role ({role}) is not in the set of allowed roles.")
    )


def ConsentRequired(consent: Field) -> ConstraintExpr:
    """Enforce that explicit consent has been granted.

    DSL: ``(E(consent) == True)``

    Args:
        consent: Bool-sorted field; ``True`` means consent was granted.
    """
    return (
        (E(consent) == True)  # noqa: E712
        .named("consent_required")
        .explain("Access denied: explicit user consent is required ({consent}=False).")
    )


def DepartmentMustBeIn(department: Field, allowed_departments: list[Any]) -> ConstraintExpr:
    """Enforce that the requester's department is in the allowed set.

    DSL: ``E(department).is_in(allowed_departments)``

    Args:
        department:          Field representing the deparment (Int/Bool-sorted).
        allowed_departments: List of allowed department values.
    """
    return (
        E(department)
        .is_in(allowed_departments)
        .named("department_must_be_in_allowed_set")
        .explain(
            "Access denied: department ({department}) is not in the " "set of allowed departments."
        )
    )
