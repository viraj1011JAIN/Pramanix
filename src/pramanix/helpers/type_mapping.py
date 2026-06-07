# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
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

# Z3 sort objects are created lazily inside python_type_to_z3_sort() rather than
# at module import time.  Module-level sort instances are tied to the default Z3
# context; any code path that creates a new z3.Context() (e.g. process-pool
# workers, test fixtures with context isolation) would find cached sorts invalid,
# raising Z3Exception during policy compilation (#340 fix).

# Order matters: bool before int (bool is a subclass of int in Python).
_TYPE_NAME_MAP: list[tuple[type, str]] = [
    (bool, "Bool"),
    (int, "Int"),
    (float, "Real"),
    (Decimal, "Real"),
]


def _sort_for_name(name: str) -> z3.SortRef:
    """Return the Z3 sort for *name*, created in the current context."""
    if name == "Bool":
        return z3.BoolSort()
    if name == "Int":
        return z3.IntSort()
    if name == "Real":
        return z3.RealSort()
    raise PolicyCompilationError(f"Unknown Z3 sort name: {name!r}")  # unreachable


# ── Public API ────────────────────────────────────────────────────────────────


def python_type_to_z3_sort(
    python_type: type,
    z3_type_hint: str | None = None,
) -> z3.SortRef:
    """Map *python_type* to the corresponding Z3 :class:`~z3.SortRef`.

    Z3 sort objects are created fresh on every call so they are valid in the
    calling thread's active Z3 context.  This avoids ``Z3Exception`` when
    running in a process-pool worker or a test fixture that creates a new
    ``z3.Context()`` (#340 fix — do not cache sorts at module import time).

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
    sort_name: str | None = None

    for py_type, name in _TYPE_NAME_MAP:
        if python_type is py_type:
            sort_name = name
            break

    if sort_name is None:
        raise PolicyCompilationError(
            f"Unsupported Python type for Z3: {python_type!r}. "
            "Supported types are: bool, int, float, Decimal. "
            "Use str, list, dict, or nested models only in non-Z3 contexts."
        )

    # ── Optional consistency check with z3_type_hint ──────────────────────────
    if z3_type_hint is not None and z3_type_hint != sort_name:
        raise PolicyCompilationError(
            f"Type mismatch: python_type={python_type!r} maps to Z3 sort "
            f"'{sort_name}', but z3_type_hint='{z3_type_hint}' was declared. "
            "Fix the Field declaration to use a consistent z3_type."
        )

    return _sort_for_name(sort_name)
