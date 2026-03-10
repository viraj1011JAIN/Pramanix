# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Python type → Z3 sort mapping for the Pramanix DSL.

This module centralises the compile-time mapping from Python ``type`` objects
to Z3 ``SortRef`` instances.  It is called during policy compilation to
validate that every :class:`~pramanix.expressions.Field` declaration uses a
supported Python type.

Supported mappings
------------------
+-------------------+------------------+
| Python type       | Z3 sort          |
+===================+==================+
| ``bool``          | ``BoolSort``     |
+-------------------+------------------+
| ``int``           | ``IntSort``      |
+-------------------+------------------+
| ``float``         | ``RealSort``     |
+-------------------+------------------+
| ``Decimal``       | ``RealSort``     |
+-------------------+------------------+

Any other type (``str``, ``list``, ``dict``, nested models, etc.) raises
:exc:`~pramanix.exceptions.PolicyCompilationError` at compile time so
authoring errors surface before any request is ever processed.

Design note: ``bool`` must be checked **before** ``int`` because ``bool``
is a subclass of ``int`` in Python.
"""
from __future__ import annotations

from decimal import Decimal

import z3

from pramanix.exceptions import PolicyCompilationError

__all__ = ["python_type_to_z3_sort"]

# ── Mapping table ─────────────────────────────────────────────────────────────

# Order matters: bool before int (bool is a subclass of int).
_TYPE_MAP: list[tuple[type, z3.SortRef]] = [
    (bool, z3.BoolSort()),
    (int, z3.IntSort()),
    (float, z3.RealSort()),
    (Decimal, z3.RealSort()),
]


# ── Public API ────────────────────────────────────────────────────────────────


def python_type_to_z3_sort(
    python_type: type,
    z3_type_hint: str | None = None,
) -> z3.SortRef:
    """Map *python_type* to the corresponding Z3 :class:`~z3.SortRef`.

    Args:
        python_type:  The Python ``type`` object declared on a
            :class:`~pramanix.expressions.Field`.
        z3_type_hint: Optional Z3 sort name already declared on the
            ``Field`` (e.g. ``"Real"``, ``"Int"``, ``"Bool"``).  When
            provided, the returned sort is validated to be consistent
            with the type hint; an inconsistency raises
            :exc:`~pramanix.exceptions.PolicyCompilationError`.

    Returns:
        The Z3 sort corresponding to *python_type*.

    Raises:
        PolicyCompilationError: If *python_type* is not one of the
            supported types, or if *z3_type_hint* is inconsistent with
            the resolved sort.
    """
    resolved: z3.SortRef | None = None

    for py_type, sort in _TYPE_MAP:
        if python_type is py_type:
            resolved = sort
            break

    if resolved is None:
        raise PolicyCompilationError(
            f"Unsupported Python type for Z3: {python_type!r}. "
            "Supported types are: bool, int, float, Decimal. "
            "Use str, list, dict, or nested models only in non-Z3 contexts."
        )

    # ── Optional consistency check with z3_type_hint ──────────────────────────
    if z3_type_hint is not None:
        expected_name = resolved.name()
        if z3_type_hint != expected_name:
            raise PolicyCompilationError(
                f"Type mismatch: python_type={python_type!r} maps to Z3 sort "
                f"'{expected_name}', but z3_type_hint='{z3_type_hint}' was declared. "
                "Fix the Field declaration to use a consistent z3_type."
            )

    return resolved
